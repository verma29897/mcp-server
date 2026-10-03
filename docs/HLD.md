# High-Level Design

Company MCP Server — Go, official MCP SDK (`github.com/modelcontextprotocol/go-sdk` v1.7.0)

---

## 1. Purpose

Expose company customer and order data to any MCP-capable client as a governed
set of **tools**, **resources** and **prompts**, without the client needing any
knowledge of the backend systems behind it, and without the server needing any
knowledge of which model is on the other end.

The MCP layer is the product. The backend integration is deliberately thin and
replaceable: it exists to prove the layering, not to be the focus.

Two constraints shape everything below:

- **The caller is a model, and its output is untrusted input.** A model does not
  make mistakes the way a UI does. It retries in loops, it reads attacker-chosen
  text as though it were instruction, and it will call whatever it is told to
  call. Every control here assumes that.
- **The server is model-agnostic.** No provider SDK, no per-model branch, no
  prompt-completion call. Model selection happens outside, and this server could
  not behave differently per provider if it wanted to.

---

## 2. Context

```
        Claude Desktop   claude.ai   OpenAI-based agent   Gemini-based agent
        MCP Inspector    custom clients    any MCP client library
                    │
                    │  MCP (JSON-RPC 2.0) over stdio or Streamable HTTP
                    ▼
        ┌───────────────────────────────────────────────────┐
        │  OFFICIAL GO MCP SDK                              │
        │  framing · sessions · schema validation · capabilities
        └───────────────────────┬───────────────────────────┘
                                │
        ┌───────────────────────▼───────────────────────────┐
        │  MCP ADAPTER   internal/mcp                       │
        │  middleware: recovery · correlate · observe ·     │
        │              authenticate · throttle · authorize ·│
        │              audit                                │
        │  registration · error encoding · transports       │
        └───────────────────────┬───────────────────────────┘
                                │  plain Go values, domain errors
        ┌───────────────────────▼───────────────────────────┐
        │  APPLICATION   internal/services                  │
        │  authorization (again) · tenancy · validation ·   │
        │  pagination · idempotency · concurrency control   │
        └───────────────────────┬───────────────────────────┘
                                │  domain types, explicit tenant
        ┌───────────────────────▼───────────────────────────┐
        │  BACKEND   internal/backend                       │
        │  memory │ HTTP + retry · backoff · circuit breaker│
        └───────────────────────┬───────────────────────────┘
                                ▼
                       REST API / database

  Supporting, used by several layers, importing none of them:
    internal/domain   types, classified errors, PII classification
    internal/authz    principal, scopes, policy
    internal/authn    credential verification (static, JWT/JWKS)
    internal/audit    the security event stream
    internal/observability  correlation, trace context, metrics
    internal/ratelimit · internal/idempotency · internal/paging
```

---

## 3. Layering

| Layer | Packages | Imports the MCP SDK? | Imports the backend? |
|---|---|---|---|
| Adapter | `internal/mcp`, `internal/tools/*`, `internal/resources`, `internal/prompts` | yes | no |
| Application | `internal/services` | **no** | through an interface only |
| Data access | `internal/backend` | no | yes |
| Vocabulary | `internal/domain`, `internal/authz` | no | no |
| Supporting | `internal/authn`, `internal/audit`, `internal/observability`, `internal/ratelimit`, `internal/idempotency`, `internal/paging` | no | no |

Three rules, all enforced by the import graph:

1. **`internal/services` never imports the MCP SDK.** Business rules are
   testable without a protocol, and would be equally valid behind a REST handler
   or a CLI.
2. **`internal/backend` never imports `internal/services`.** The shared
   vocabulary lives in `internal/domain`, so both layers speak it without a
   cycle.
3. **`internal/authz` imports neither the SDK nor `net/http`.** An authorization
   decision is a property of the caller and the operation, not of the protocol
   that carried the request. That is what lets the same rules be enforced in the
   MCP middleware, re-enforced in the service layer, and unit-tested with
   neither.

`internal/tools/customer` depends on the SDK only for tool *metadata* types —
descriptors and annotations. It contains no protocol plumbing and no business
rules.

---

## 4. Request flow

```
MCP client
    │  tools/call {name, arguments}
    ▼
SDK server
    │
    ▼  ── receiving middleware, in order ───────────────────────────────
    │  recovery      a panic below becomes an error, not a dead process
    │  correlate     request id + W3C trace context onto the context
    │  observe       metrics and one structured log line
    │  authenticate  verified token claims → authz.Principal on the ctx
    │  throttle      rate limit, by IP / principal / tenant / tool
    │  authorize     scope + tenant gate; list filtering
    │  audit         records the attempt and its outcome
    ▼ ───────────────────────────────────────────────────────────────────
SDK validates arguments against the tool's input JSON Schema
    │   (invalid arguments are rejected here; the handler never runs)
    ▼
adapt() in internal/mcp/tools.go   →  (ctx, typed input)
    ▼
Handler in internal/tools/customer   shape input, one service call, shape output
    ▼
Service in internal/services
    │   authorize again · resolve tenant · validate · clamp · decode cursor
    │   · idempotency · optimistic lock
    ▼
Backend in internal/backend
    │   explicit tenant · retry (idempotent only) · circuit breaker
    │   · ctx propagated to the HTTP call
    ▼
domain.Customer  or  *domain.Error
    ▼
adapt()  success → size check → StructuredContent (+ JSON text block)
         failure → toolError() → CallToolResult{IsError: true}
    ▼
MCP client
```

**Why the middleware order is what it is.** Authenticate before throttle, so a
limit can be per-principal rather than only per-address. Throttle before
authorize, so a caller cannot use denied requests as a free probe of what it may
do. Authorize before audit, so a denial is recorded with its reason.

---

## 5. Security model

The whole design rests on one property:

> **Every security decision is made server-side, from a cryptographically
> verified credential, before a handler runs. Nothing a model emits reaches an
> authorization decision.**

```
   UNTRUSTED                              │  TRUSTED
   model output · tool arguments          │  verified token
   prompt text · customer names & emails  │  authz policy
   order data · resource contents         │  principal's tenant
   client self-description                │  operator configuration
   ───────── data ───────────────────────►│  never crosses into a decision
```

Seven layers, each failing closed on its own: TLS/gateway, authentication, rate
limiting, authorization, tenant isolation, input validation, output control.
Full treatment in [SECURITY.md](SECURITY.md); threat-by-threat mapping in
[THREAT-MODEL.md](THREAT-MODEL.md).

### Authorization

Six scopes named after operations rather than tools, so a tool rename cannot
silently widen a grant. One policy table (`internal/authz/policy.go`), enforced
twice — once in middleware as the gate, once in the service layer as what still
holds if some future caller reaches the service another way.

A feature may require more than one scope: the customer summary needs both
`customer:read` and `customer:orders:read`, because it combines a record with
its order roll-up and a single-scope policy would have made it a way around the
orders boundary. An unmapped feature is denied, not allowed.

### Tenancy

The tenant is an **explicit parameter** on every backend method that touches
customer data. Not from the context, and not from a request field. An implicit
tenant is a tenant a new method can forget, and the failure mode of forgetting
is one customer reading another's data.

Cross-tenant access is reported as `NOT_FOUND`, byte-identical to a genuine
miss, because the difference between "not yours" and "does not exist" turns the
endpoint into an existence oracle over the customer base.

---

## 6. Capability model

| Capability | Count | Purpose |
|---|---|---|
| Tools | 6 | Actions the model may take |
| Resources | 1 static + 3 templates | Read-only context a client attaches |
| Prompts | 2 | User-invoked interaction templates |
| Completions | prompt arguments | Value pickers for closed argument sets |

Capabilities are **inferred by the SDK** from what is registered. There is no
separate declaration that could drift.

Listings are filtered per principal, so a client sees only what it may use. That
is usability, not enforcement: calling a hidden feature anyway still fails.

### Tools, by behaviour class

| Tool | Class | `readOnly` | `destructive` | `idempotent` | `openWorld` | Scope |
|---|---|:-:|:-:|:-:|:-:|---|
| `get_customer` | READ_ONLY | ✅ | ❌ | ✅ | ❌ | `customer:read` |
| `search_customers` | READ_ONLY | ✅ | ❌ | ✅ | ❌ | `customer:search` |
| `list_customer_orders` | READ_ONLY | ✅ | ❌ | ✅ | ❌ | `customer:orders:read` |
| `update_customer` | MUTATING | ❌ | ❌ | ✅ | ❌ | `customer:update` |
| `delete_customer` | DESTRUCTIVE | ❌ | **✅** | ✅ | ❌ | `customer:delete` |
| `send_customer_notification` | EXTERNAL_SIDE_EFFECT | ❌ | ❌ | **❌** | **✅** | `notification:send` |

Each dangerous tool carries guard rails beyond the annotation and the scope:

- `delete_customer` requires `confirm: true`, checked server-side, plus an
  optional `expected_version` so a record that changed after a human approved it
  is refused rather than deleted.
- `send_customer_notification` has a stricter rate limit, supports idempotency
  keys, refuses control characters in a subject (header injection), is never
  retried automatically, and is paired with a drafting prompt so text is
  reviewed before it is sent.

---

## 7. Transport model

```
                 MCP Server (registered once)
                     │
             ┌───────┴───────┐
           stdio           HTTP
             │               │
             ▼               ▼
        Local client     Remote clients
```

Registration completes in `mcp.New()` **before** a transport is selected, so the
same server object is served either way, with the same authorization.
`tests/integration/transport_test.go` asserts it directly: one client over
stdio, another over Streamable HTTP, feature sets compared.

| | stdio | Streamable HTTP |
|---|---|---|
| Sessions per process | one | many, concurrent |
| Authentication | OS process boundary | static bearer or OAuth/JWT |
| Authorization | `MCP_LOCAL_SCOPES` | per-token scopes |
| Tenancy | configured default | per-token tenant claim |
| Correlation | generated ids | caller's `X-Request-Id` / `traceparent` |
| Lifecycle end | stdin EOF or signal | signal → drain → close |
| Scale-out | n/a | stateless mode, shared cursor secret |

---

## 8. Error model

MCP has two failure channels, and the design uses both deliberately.

| | Tool error | Protocol error |
|---|---|---|
| Wire shape | `CallToolResult{IsError: true}` | JSON-RPC `error` |
| Model sees it | **yes** — it can explain and self-correct | no |
| Used for | every `tools/call` failure, including denials | `resources/read`, `prompts/get`, unknown method |

Nine classifications: `INVALID_ARGUMENT`, `NOT_FOUND`, `UNAUTHORIZED`,
`FORBIDDEN`, `CONFLICT`, `TIMEOUT`, `RATE_LIMITED`, `BACKEND_ERROR`,
`INTERNAL_ERROR`.

Authorization denials and rate-limit rejections on `tools/call` are returned
**in band**, so the model can see why and adjust. A JSON-RPC error is invisible
to it, and a model that cannot see why a call failed simply tries again.

**Redaction is structural, not a review habit.** `domain.Error.Error()` prints
only the classification and a safe message; the internal cause is reachable
solely through `Unwrap()`/`Detail()`, which only the logger calls. Reaching a
secret requires calling a different method, so it cannot happen by accident.

---

## 9. Cross-cutting concerns

| Concern | Where | How |
|---|---|---|
| Cancellation | every layer | `context.Context` from the SDK request to the backend HTTP call |
| Panic containment | `internal/mcp/middleware.go` | recovered, stack to the log, session survives |
| Correlation | `internal/observability` | request id + W3C trace context, injected into backend calls |
| Metrics | `internal/observability` | Prometheus text format; label values from closed sets only |
| Audit | `internal/audit` | separate stream, tagged for routing; identifiers only, never content |
| Secrets | `internal/config` | `Redacted()` reports `set`/`unset`, never values |
| Input safety | `internal/services` | id shape validated before any URL or query; path segments percent-encoded anyway |
| Result size | adapter + resources | byte caps, refused rather than truncated |
| Backend resilience | `internal/backend` | timeouts, jittered backoff, circuit breaker; retries only where safe |
| Replay safety | `internal/idempotency` | keys for side-effecting calls |
| Lost updates | `internal/domain` + backend | optional version preconditions |

---

## 10. Deployment shapes

**Local (stdio).** A client spawns the binary; one process, one session, no
network surface. Least privilege comes from `MCP_LOCAL_SCOPES`.

**Remote (Streamable HTTP).**

```
AI platform / enterprise client
    │ HTTPS
    ▼
WAF / API gateway        TLS · volumetric protection · optional introspection
    │
    ▼
Load balancer            /readyz drives membership
    │
    ▼
MCP server × N           MCP_HTTP_STATELESS=true, shared CURSOR_SECRET
    │
    ▼
Customer backend API     X-Tenant-Id enforced upstream too
```

Three things remain per-process and are documented as such: rate-limit buckets,
idempotency records and metric counters. See [DEPLOYMENT.md](DEPLOYMENT.md).

---

## 11. Design decisions

| Decision | Rationale | Trade-off accepted |
|---|---|---|
| The official SDK owns all protocol work | Spec compliance, framing, sessions and schema validation are not this project's problem | Bound to the SDK's release cadence |
| Schemas inferred from Go types, then patched | Schema and handler cannot drift; enums stay a single source of truth | Constraints need a patch function, not just a tag |
| Handlers take `(ctx, In) (Out, error)` | Tool logic is unit-testable with no server, transport or client | One small adapter layer to maintain |
| Authorization enforced twice | The middleware is the gate; the service check survives a handler wired up another way | Two places to update when the policy changes |
| Tenant as an explicit backend parameter | A tenant that must be passed cannot be forgotten | Wider interface; more churn on a signature change |
| Cross-tenant reported as `NOT_FOUND` | Distinguishing it turns the tool into an existence oracle | An operator debugging a real permission problem has to read the audit log |
| Denials returned in band on `tools/call` | The model must see why, or it retries blind | Slightly unusual: a "failure" arrives as a successful RPC |
| Domain errors carry a safe message plus a hidden cause | Redaction cannot be forgotten at a call site | Callers must use `Detail()` for logs |
| Prometheus text written directly, no client library | The format is the contract every scraper consumes; a server handling customer data has good reason to keep its dependency surface small | ~40 lines to maintain; no exemplars or native histograms |
| W3C trace context, no tracing SDK | The header is what every tracing system consumes, OpenTelemetry included; an operator who wants spans wraps the handler | No spans out of the box |
| In-memory idempotency and rate limiting | Correct for one replica, and the interface admits a shared implementation | Multi-replica caveats, logged as startup warnings |
| In-memory backend is the default | The server runs and is Inspector-testable with zero setup | The default is not a real data source |
| Toolchain version pinned in `go.mod` and the Dockerfile | Most vulnerabilities reported against a server like this one are in the standard library | A toolchain bump is a reviewed change, not automatic |
