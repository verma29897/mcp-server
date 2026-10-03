# Deployment

Production configuration for the Streamable HTTP transport. For a local stdio
deployment (Claude Desktop, the Inspector), see the README — most of this
document does not apply, because the OS process boundary replaces the network
one.

---

## Architecture

```
   AI platform / enterprise client
              │ HTTPS
              ▼
   ┌──────────────────────────────┐
   │ WAF / API gateway            │   TLS termination
   │                              │   volumetric protection
   │                              │   optional OAuth introspection
   └──────────────┬───────────────┘
                  │ HTTP/1.1, SSE pass-through
                  ▼
   ┌──────────────────────────────┐
   │ Load balancer                │   /readyz drives membership
   └──────────────┬───────────────┘
                  │
      ┌───────────┼───────────┐
      ▼           ▼           ▼
   ┌──────┐   ┌──────┐   ┌──────┐
   │ MCP  │   │ MCP  │   │ MCP  │      MCP_HTTP_STATELESS=true
   │ x N  │   │      │   │      │      shared CURSOR_SECRET
   └──┬───┘   └──┬───┘   └──┬───┘
      └──────────┼──────────┘
                 ▼
        ┌─────────────────┐
        │ Customer API    │   X-Tenant-Id on every call
        └────────┬────────┘
                 ▼
            ┌─────────┐
            │Database │
            └─────────┘

  Sideways:  stderr JSON logs → aggregator (audit stream routed separately)
             /metrics → Prometheus
             traceparent → tracing backend
```

The MCP server holds no durable state. Everything it needs per request comes
from the token and the backend.

---

## Required configuration

```bash
# Transport
MCP_TRANSPORT=http
MCP_HTTP_ADDR=:8080
MCP_HTTP_PATH=/mcp
MCP_HTTP_STATELESS=true            # more than one replica

# Authentication — pick one
MCP_AUTH_MODE=oauth
MCP_OAUTH_ISSUER=https://idp.example.com/
MCP_OAUTH_AUDIENCE=https://mcp.example.com/mcp
MCP_OAUTH_JWKS_URL=https://idp.example.com/.well-known/jwks.json
MCP_OAUTH_RESOURCE_METADATA_URL=https://mcp.example.com/.well-known/oauth-protected-resource

# Tenancy (requires oauth)
TENANCY_ENABLED=true
MCP_OAUTH_TENANT_CLAIM=tenant_id

# Backend
BACKEND_MODE=http
BACKEND_BASE_URL=https://api.internal.example.com/v1

# Behind a proxy that overwrites X-Forwarded-For
MCP_HTTP_TRUST_PROXY=true

# Observability
LOG_LEVEL=info
LOG_FORMAT=json
METRICS_ENABLED=true
AUDIT_ENABLED=true
```

### Secrets

From a secret manager, never from a file in the image or the repository.

The server reads a `.env` when one is present, but it **cannot override the
environment** — the file only fills gaps. That makes an accidental `.env` in an
image harmless rather than dangerous, and it means the values below must still
be injected as real environment variables. Pass `-env-file ""` in production if
you would rather the feature were not there at all.


| Variable | Purpose | Rotation |
|---|---|---|
| `BACKEND_API_TOKEN` | authenticates this server to the customer API | as your API policy requires |
| `CURSOR_SECRET` | signs pagination cursors; **identical across replicas** | rotating invalidates in-flight cursors; clients restart their listing |
| `MCP_HTTP_BEARER_TOKEN` | static mode only | rolling restart |
| `MCP_OAUTH_HMAC_SECRET` | HS256 mode only; prefer JWKS | — |
| `MCP_METRICS_TOKEN` | optional, guards `/metrics` | any time |

`CURSOR_SECRET` is the one that is easy to get wrong. Leave it unset with
several replicas and each mints its own random key, so a cursor issued by one
replica fails on another — pagination breaks at random rather than failing
cleanly. Startup refuses this combination when `MCP_HTTP_STATELESS=true`.

---

## Validate before you deploy

```bash
mcp-server -check-config
```

Prints the redacted configuration, every warning, and exits non-zero on an
invalid combination. Run it in your pipeline against the real environment.

Startup **fails** on: an invalid transport or backend mode; `BACKEND_MODE=http`
without a base URL; `MCP_AUTH_MODE=oauth` without an issuer or audience;
`MCP_AUTH_MODE=static` with a token under 16 characters; `TENANCY_ENABLED=true`
without OAuth; `MCP_HTTP_STATELESS=true` without a cursor secret; unauthenticated
HTTP without `MCP_ALLOW_INSECURE_HTTP=true`.

Startup **warns** on: unauthenticated HTTP; static auth (single identity for
every caller); rate limiting disabled; audit disabled; `X-Forwarded-For` trusted;
in-memory idempotency with multiple replicas; tenancy disabled; the in-memory
backend; a plain-http backend URL.

---

## Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-server
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate: { maxUnavailable: 0, maxSurge: 1 }
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
        seccompProfile: { type: RuntimeDefault }
      containers:
        - name: mcp-server
          image: company-mcp-server:1.0.0
          imagePullPolicy: IfNotPresent
          ports:
            - { name: http, containerPort: 8080 }
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            privileged: false
            capabilities:
              drop: ["ALL"]
          env:
            - { name: MCP_TRANSPORT,      value: "http" }
            - { name: MCP_HTTP_STATELESS, value: "true" }
            - { name: MCP_AUTH_MODE,      value: "oauth" }
            - { name: TENANCY_ENABLED,    value: "true" }
            - { name: BACKEND_MODE,       value: "http" }
            - name: BACKEND_API_TOKEN
              valueFrom: { secretKeyRef: { name: mcp-secrets, key: backend-api-token } }
            - name: CURSOR_SECRET
              valueFrom: { secretKeyRef: { name: mcp-secrets, key: cursor-secret } }
          envFrom:
            - configMapRef: { name: mcp-config }
          resources:
            requests: { cpu: 100m, memory: 64Mi }
            limits:   { cpu: "1",  memory: 256Mi }

          # Liveness must not depend on the backend. A probe that fails during a
          # backend outage restarts the pod, which fixes nothing and removes the
          # capacity that could still serve.
          livenessProbe:
            httpGet: { path: /healthz, port: http }
            initialDelaySeconds: 3
            periodSeconds: 10
            failureThreshold: 3

          # Readiness does check it, so an unhealthy replica leaves the load
          # balancer instead of answering every request with an error.
          readinessProbe:
            httpGet: { path: /readyz, port: http }
            initialDelaySeconds: 2
            periodSeconds: 5
            failureThreshold: 2

          startupProbe:
            httpGet: { path: /healthz, port: http }
            failureThreshold: 30
            periodSeconds: 2

      # Comfortably longer than MCP_HTTP_SHUTDOWN_TIMEOUT (15s), so a drain
      # completes rather than being SIGKILLed halfway.
      terminationGracePeriodSeconds: 45
```

Scraping:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: mcp-server
spec:
  selector:
    matchLabels: { app: mcp-server }
  endpoints:
    - port: http
      path: /metrics
      interval: 30s
```

---

## nginx

```nginx
upstream mcp_backend {
    server 10.0.1.10:8080;
    server 10.0.1.11:8080;
    server 10.0.1.12:8080;
    keepalive 32;
}

server {
    listen 443 ssl;
    http2 on;
    server_name mcp.example.com;

    ssl_certificate     /etc/ssl/certs/mcp.crt;
    ssl_certificate_key /etc/ssl/private/mcp.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    client_max_body_size 4m;      # match MCP_HTTP_MAX_REQUEST_BYTES

    location /mcp {
        proxy_pass         http://mcp_backend;

        # HTTP/1.1 upstream: SSE needs it, and HTTP/2 to the origin buys
        # nothing here.
        proxy_http_version 1.1;
        proxy_set_header   Connection "";

        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        # Overwritten, not appended: a client-supplied value must not survive,
        # or MCP_HTTP_TRUST_PROXY becomes a way to forge a source address.
        proxy_set_header   X-Forwarded-For   $remote_addr;
        proxy_set_header   X-Forwarded-Proto $scheme;

        # Required for SSE. With buffering on, the stream is held in nginx and
        # the client sees a hang rather than events.
        proxy_buffering    off;
        proxy_cache        off;
        chunked_transfer_encoding on;

        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    # Operational endpoints stay inside the network.
    location ~ ^/(healthz|readyz|metrics)$ {
        allow 10.0.0.0/8;
        deny  all;
        proxy_pass http://mcp_backend;
    }
}
```

If your proxy cannot be persuaded to pass SSE through, set
`MCP_HTTP_JSON_RESPONSE=true`. Requests still work; server-initiated messages
are lost.

---

## Scaling

`MCP_HTTP_STATELESS=true` removes server-side session state, so any replica can
serve any request and no sticky sessions are needed. Three things stay
per-process, and each has a consequence:

| State | Consequence of N replicas | What to do |
|---|---|---|
| Rate-limit buckets | roughly N times the configured rate | divide the limits by N, or enforce at the gateway |
| Idempotency records | a retry landing elsewhere sends a second message | sticky sessions, or a shared `idempotency.Store` |
| Metric counters | per-replica series | aggregate in Prometheus (they are labelled per instance) |

### A shared idempotency store

`idempotency.Store` is a three-method interface designed to be implemented
against Redis:

```go
type Store interface {
    Begin(ctx context.Context, key, fingerprint string) (*Record, error)
    Commit(ctx context.Context, key string, payload []byte) error
    Abort(ctx context.Context, key string)
}
```

`Begin` must be atomic — `SET key value NX EX ttl` — or two replicas can both
believe they won and both send. The in-process implementation and its tests
(`TestConcurrentBeginElectsOneWinner`) define the contract to satisfy.

---

## Graceful shutdown

On `SIGTERM` or `SIGINT`:

1. the listener stops accepting new connections;
2. in-flight requests get `MCP_HTTP_SHUTDOWN_TIMEOUT` (default 15s) to finish;
3. open MCP sessions are closed;
4. the backend client releases its connections.

Set `terminationGracePeriodSeconds` comfortably above the shutdown timeout, or
the drain is cut short by `SIGKILL`. A second `SIGINT` during shutdown kills the
process immediately — signal interception is released after the first.

---

## Backend contract

`BACKEND_MODE=http` expects:

| Method | Path | Request | Response |
|---|---|---|---|
| `GET` | `/healthz` | | 2xx |
| `GET` | `/customers/{id}` | | `Customer` |
| `GET` | `/customers?q=&status=&tier=&limit=&after=` | | `{"items":[Customer],"next_after":"..."}` |
| `GET` | `/customers/{id}/orders?limit=&after=` | | `{"items":[Order],"next_after":"..."}` |
| `PATCH` | `/customers/{id}` | sparse `CustomerPatch` | `Customer` |
| `DELETE` | `/customers/{id}?expected_version=` | | 2xx |
| `POST` | `/customers/{id}/notifications` | `Notification` | `Receipt` |

Headers sent on every call:

| Header | Meaning |
|---|---|
| `Authorization: Bearer $BACKEND_API_TOKEN` | authenticates this server |
| `X-Tenant-Id` | the caller's tenant — **scope your queries by it** |
| `X-Request-Id`, `traceparent`, `tracestate` | correlation |
| `Idempotency-Key` | on a notification, when the caller supplied one |

**Enforce the tenant upstream too.** This server filters returned rows by tenant
as a safety net, but a backend that ignores `X-Tenant-Id` leaves that net as the
only thing between two customers.

Status mapping:

| Upstream | Becomes | Retried? |
|---|---|---|
| 404 | `NOT_FOUND` | no |
| 401 | `UNAUTHORIZED` | no |
| 403 | `FORBIDDEN` | no |
| 409 / 412 | `CONFLICT` | no |
| 429 | `RATE_LIMITED` (with `Retry-After`) | yes, if idempotent |
| 408 / 504 | `TIMEOUT` | yes, if idempotent |
| 400 / 422 | `INVALID_ARGUMENT` | no |
| other 5xx | `BACKEND_ERROR` | yes, if idempotent |

Retries apply only to reads and unconditional updates. A delete, a conditional
update and a notification are never retried automatically.

---

## Container

Two-stage build onto `scratch`: a static binary, CA certificates, a non-root
numeric UID, no shell. The absence of a shell is a control in its own right —
an attacker who reaches command execution has nothing to execute.

```bash
make docker VERSION=1.0.0
make docker-scan          # trivy, HIGH+CRITICAL, non-zero on findings
make sbom                 # CycloneDX
```

The Go toolchain is pinned in both `go.mod` and the Dockerfile. Most of what a
vulnerability scan reports against a server like this one is in the standard
library, so the toolchain version belongs under the same review as any
dependency bump.

Runtime hardening the manifest above applies: read-only root filesystem, all
capabilities dropped, no privilege escalation, `RuntimeDefault` seccomp.

---

## Pre-production checklist

- [ ] `mcp-server -check-config` passes against the real environment
- [ ] TLS terminated upstream; HSTS at the edge
- [ ] `MCP_AUTH_MODE=oauth` with issuer, audience and JWKS
- [ ] `TENANCY_ENABLED=true` for a multi-tenant deployment
- [ ] `CURSOR_SECRET` set, identical across replicas, from a secret manager
- [ ] `MCP_HTTP_STATELESS=true` for more than one replica
- [ ] rate limits divided by the replica count, or enforced at the gateway
- [ ] `MCP_HTTP_TRUST_PROXY` matches reality (proxy present and overwriting)
- [ ] `/healthz` and `/readyz` wired to liveness and readiness respectively
- [ ] `/metrics` scraped; not exposed publicly
- [ ] stderr shipped; the `log_type:audit` stream routed to its own retention
- [ ] SSE pass-through verified end to end, not just to the load balancer
- [ ] `terminationGracePeriodSeconds` > `MCP_HTTP_SHUTDOWN_TIMEOUT`
- [ ] backend enforces `X-Tenant-Id` itself
- [ ] alerts on the rules in [OPERATIONS.md](OPERATIONS.md)
- [ ] a tested rollback
