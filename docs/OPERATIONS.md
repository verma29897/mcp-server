# Operations

Running the server: what it emits, what to alert on, and what to do when
something breaks.

---

## Endpoints

| Path | Purpose | Auth |
|---|---|---|
| `GET /` | endpoint directory; also served on any unknown path | none |
| `POST/GET/DELETE {MCP_HTTP_PATH}` | the MCP endpoint | per `MCP_AUTH_MODE` |
| `GET /healthz` | liveness — process only, touches nothing | none |
| `GET /readyz` | readiness — checks the backend | none |
| `GET {MCP_METRICS_PATH}` | Prometheus metrics | optional `MCP_METRICS_TOKEN` |

**Liveness and readiness are not the same probe, and using one for both causes
outages.** A liveness probe that checks the backend gets the pod restarted
during a backend outage — which fixes nothing, and removes the capacity that
could still have served the requests that do not need the backend. `/healthz`
therefore touches nothing; `/readyz` is what takes a replica out of the load
balancer.

The root serves a small JSON directory of these paths, and so does any unknown
path. It exists because the first thing anyone does after starting the server is
open its address in a browser, and a bare `404 page not found` followed by a
cryptic `400` from `/mcp` is a wall rather than directions. It names paths only:
whether authentication is on, which backend is in use and what the default
tenant is are all withheld, because those help someone decide whether this host
is worth attacking.

Keep the operational endpoints off the public internet.

---

## Logs

JSON to **stderr**, always. Under stdio, stdout carries the JSON-RPC stream and
a stray byte on it breaks the session; under HTTP it makes no difference, so
there is one rule rather than a transport-dependent one that could be got wrong.

Every line carries `service` and `version`.

### Application log

```json
{"time":"2026-09-03T10:15:04.812Z","level":"DEBUG","msg":"mcp request completed",
 "service":"company-mcp-server","version":"1.0.0",
 "method":"tools/call","feature":"get_customer","duration_ms":12,
 "session_id":"01J...","request_id":"9f2c...","trace_id":"4bf9...","outcome":"success"}
```

Request lines are `DEBUG` on success, `INFO` for an in-band tool error, `WARN`
for a protocol error. Set `LOG_LEVEL=debug` to see per-request lines in
production; the volume is one line per MCP method.

**Arguments are never logged.** The middleware reads only routing fields — a
tool name, a resource URI. If you need to know what a call contained, you need
the client's own log, and that is deliberate.

### Audit log

Tagged `"log_type":"audit"`. Route it to its own index with its own retention.

```json
{"time":"...","level":"INFO","msg":"audit","log_type":"audit",
 "action":"customer.read","result":"success",
 "principal":"user-42","tenant":"acme","auth_mode":"oauth",
 "client_id":"claude-desktop","issuer":"https://idp.example/",
 "request_id":"9f2c...","session_id":"01J...","trace_id":"4bf9...",
 "method":"tools/call","feature":"get_customer","duration_ms":12}
```

Actions: `auth.success`, `auth.failure`, `authz.denied`, `ratelimit.exceeded`,
`customer.read`, `customer.search`, `customer.orders.read`, `customer.update`,
`customer.delete`, `notification.send`, `resource.read`, `prompt.render`.

Successes are `INFO`; denials and failures are `WARN`, so an alert can find them
without parsing the body.

Routing example (Loki):

```yaml
- match:
    selector: '{app="mcp-server"} |= "log_type" | json | log_type="audit"'
    stages:
      - labels: { action: "", result: "", tenant: "" }
```

### Correlation

`request_id` ties every line about one request together, including the single
line — the classified failure log — where the internal cause exists. That is the
line to look for when a client reports a redacted error: the client saw
`BACKEND_ERROR: the backend could not complete the get_customer operation`, and
the log has the connection failure behind it under the same `request_id`.

`X-Request-Id` from the caller is honoured (sanitised and length-bounded) and
echoed on the response, so a trace survives the hop from the gateway.

---

## Tracing

W3C Trace Context (`traceparent`, `tracestate`) is parsed from inbound requests,
carried on every log and audit record as `trace_id`, and injected into every
backend call. A trace started at your gateway continues through this server and
into the customer API.

This is deliberately the header rather than an SDK. The wire format is what
every tracing system consumes — including every OpenTelemetry SDK — so an
operator who wants full OTel spans wraps the HTTP handler and the backend
transport with `otelhttp` and gets them, with the same trace ids, without this
server depending on a tracing vendor. A server handling customer data has a good
reason to keep its dependency surface small.

Never put customer data in a span attribute. The identifiers already on the
records are enough to correlate.

---

## Metrics

Prometheus text format at `MCP_METRICS_PATH`.

| Metric | Type | Labels |
|---|---|---|
| `mcp_requests_total` | counter | `method`, `outcome` |
| `mcp_request_duration_seconds` | histogram | `method` |
| `mcp_tool_calls_total` | counter | `tool`, `outcome` |
| `mcp_tool_duration_seconds` | histogram | `tool` |
| `mcp_resource_reads_total` | counter | `resource`, `outcome` |
| `mcp_prompt_renders_total` | counter | `prompt`, `outcome` |
| `mcp_errors_total` | counter | `code`, `feature` |
| `mcp_auth_failures_total` | counter | `reason` |
| `mcp_authz_denials_total` | counter | `scope`, `feature` |
| `mcp_rate_limited_total` | counter | `scope_kind` |
| `mcp_backend_requests_total` | counter | `operation`, `outcome` |
| `mcp_backend_duration_seconds` | histogram | `operation` |
| `mcp_backend_retries_total` | counter | `operation` |
| `mcp_active_sessions` | gauge | — |
| `mcp_http_requests_total` | counter | `path`, `status` |
| `mcp_response_bytes` | histogram | `feature` |
| `mcp_idempotent_replays_total` | counter | `operation` |
| `mcp_uptime_seconds` | gauge | — |

**Cardinality is bounded by construction.** Every label value comes from a
closed set defined in the repository — a registered tool name, a domain error
code, an MCP method — never from a request argument. Resource URIs are collapsed
onto their template (`customer://{id}`), because a per-customer label would
create one time series per customer, which is how a metrics backend is brought
down by ordinary use.

### Alerts

```yaml
groups:
  - name: mcp-server
    rules:
      - alert: MCPHighErrorRate
        expr: |
          sum(rate(mcp_requests_total{outcome="error"}[5m]))
            / sum(rate(mcp_requests_total[5m])) > 0.05
        for: 10m
        annotations:
          summary: "over 5% of MCP requests are failing"

      - alert: MCPBackendDegraded
        expr: |
          sum(rate(mcp_backend_requests_total{outcome=~"BACKEND_ERROR|TIMEOUT"}[5m]))
            / sum(rate(mcp_backend_requests_total[5m])) > 0.1
        for: 5m

      - alert: MCPCircuitOpen
        expr: mcp_backend_circuit_state > 0
        for: 2m
        annotations:
          summary: "the backend circuit breaker is not closed"

      # A spike here is either a misconfigured client or credential stuffing.
      - alert: MCPAuthFailureSpike
        expr: sum(rate(mcp_auth_failures_total[5m])) > 1
        for: 5m

      # A caller repeatedly attempting what it may not do. Investigate before
      # widening a grant: the client may be doing something it should not.
      - alert: MCPAuthzDenialSpike
        expr: sum(rate(mcp_authz_denials_total[5m])) > 0.5
        for: 10m

      # Almost always an agent loop.
      - alert: MCPRateLimitSustained
        expr: sum(rate(mcp_rate_limited_total[5m])) > 1
        for: 15m

      - alert: MCPLatencyP99
        expr: |
          histogram_quantile(0.99,
            sum(rate(mcp_request_duration_seconds_bucket[5m])) by (le)) > 2
        for: 10m

      - alert: MCPNoTraffic
        expr: sum(rate(mcp_requests_total[10m])) == 0
        for: 15m
```

### Useful queries

```promql
# p50 / p95 / p99 by tool
histogram_quantile(0.95, sum(rate(mcp_tool_duration_seconds_bucket[5m])) by (le, tool))

# which tools are being denied, and to whom
sum by (feature, scope) (rate(mcp_authz_denials_total[1h]))

# how close responses run to the size cap
histogram_quantile(0.99, sum(rate(mcp_response_bytes_bucket[1h])) by (le, feature))

# retries as a share of backend calls — a rising ratio means upstream trouble
sum(rate(mcp_backend_retries_total[5m])) / sum(rate(mcp_backend_requests_total[5m]))
```

---

## Failure modes

| Symptom | Cause | Behaviour | Action |
|---|---|---|---|
| Every tool returns `BACKEND_ERROR` | backend unreachable | `/readyz` fails, replica leaves the LB; circuit opens after 5 consecutive faults | check the backend and `BACKEND_BASE_URL`; the cause is in the log under the client's `request_id` |
| `TIMEOUT` under load | `BACKEND_TIMEOUT` too low, or upstream latency | retried if idempotent, with jittered backoff | raise the timeout or fix upstream; check `mcp_backend_duration_seconds` |
| `mcp_backend_circuit_state > 0` | breaker open | requests fail fast without touching the backend | leave it — it is protecting the backend; it probes and closes on its own |
| `RATE_LIMITED` in bursts | agent loop | in-band error the model can see | check `mcp_rate_limited_total{scope_kind}` for which layer; raise the budget only after ruling out a loop |
| `401` on every request | wrong token, or clock skew beyond 60s | rejected at the HTTP boundary | check `mcp_auth_failures_total{reason}` and the `auth.failure` audit records |
| `403` on one tool | missing scope | in-band `FORBIDDEN` | check the `authz.denied` audit record for the scope; grant it deliberately or leave it |
| `CONFLICT` on update | concurrent writer | the write is refused, not applied | the client re-reads and retries; this is working as designed |
| Nothing listening on the port | `MCP_TRANSPORT=stdio`; stdio opens no socket | the startup line reports `transport=stdio` and omits every `http_*` field | set `MCP_TRANSPORT=http` |
| Sessions drop behind a LB | no sticky sessions | | `MCP_HTTP_STATELESS=true` |
| Requests hang, no events | a proxy is buffering SSE | | disable buffering, or `MCP_HTTP_JSON_RESPONSE=true` |
| Pagination fails at random | replicas with different cursor secrets | cursors fail to verify | set one `CURSOR_SECRET` everywhere |
| Duplicate messages after a retry | multi-replica in-process idempotency | | sticky sessions or a shared store |
| Tool result refused as too large | over `MAX_TOOL_RESPONSE_BYTES` | in-band error naming the limit | the model should narrow the call; raise the cap only deliberately |
| `413` on a request | over `MCP_HTTP_MAX_REQUEST_BYTES` | | usually an oversized notification body; the schema caps it at 4000 characters |
| Panic in a handler | a defect | recovered; the session survives; trace goes to the log | the stack trace is in the log under `panic recovered in MCP handler` |
| Startup fails with a config error | invalid combination | | the message names the variable; `-check-config` reproduces it |

---

## Measured performance

From `make bench` on a 13th-gen Core i5-1335U laptop, `-benchtime 200x`. These
are a shape, not a specification — measure your own hardware.

| Operation | ns/op | allocs/op |
|---|---|---|
| Service `GetCustomer` (no protocol) | ~430 | 0 |
| `get_customer` end to end, in-memory transport | ~720,000 | 530 |
| `search_customers` end to end | ~1,190,000 | 955 |
| `update_customer` end to end | ~685,000 | 585 |
| `customer://{id}/summary` read | ~780,000 | 655 |
| `tools/list` | ~3,370,000 | 3,470 |
| Concurrent clients (parallel) | ~1,024,000 | 637 |
| Pagination walk (service) | ~43,000 | 94 |
| Notification send + replay | ~21,000 | 28 |

Reading these:

- **The business logic is not the cost.** 430ns for a service call against
  720µs end to end means essentially all of it is JSON-RPC framing and schema
  validation, in the SDK.
- **`tools/list` is the expensive one**, because it re-marshals six tool schemas
  each time. Clients call it once per session, so this is fine — but it is the
  first thing to look at if a client polls it.
- **With a real backend, the backend dominates.** `BenchmarkBackendLatency`
  shows 1ms of upstream latency producing ~1.12ms per call: about 120µs of
  overhead on top.
- **Sizing.** A replica with 1 CPU handles on the order of 1,000 simple tool
  calls per second against an in-memory backend; against a 10ms backend, in-flight
  concurrency rather than CPU is the limit. Memory is a few tens of MiB plus
  rate-limit and idempotency state.

---

## Routine tasks

**Rotate the backend token.** Update the secret, restart replicas one at a time.
Readiness gates each one, so a bad token stops the rollout instead of taking the
service down.

**Rotate the cursor secret.** In-flight cursors stop verifying and clients
restart their listing — a `INVALID_ARGUMENT` naming the cursor, not an outage.
Do it in a quiet window.

**Rotate OAuth signing keys.** Publish the new key in the JWKS *before* issuing
tokens with it. An unknown `kid` triggers a refresh; no restart needed.

**Upgrade the Go toolchain.** Pinned in `go.mod` and the Dockerfile. Most of
what `govulncheck` reports against this server is standard library, so treat a
toolchain bump as a security update: `make vuln` before and after.

**Upgrade the MCP SDK.** Re-read `go doc github.com/modelcontextprotocol/go-sdk/mcp`
rather than trusting older examples, run the full suite, and re-verify the
transport-level controls with the Inspector — DNS-rebinding and cross-origin
protection are SDK behaviour and are not covered by a test here.
