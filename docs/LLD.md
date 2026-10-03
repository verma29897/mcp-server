# Low-Level Design

Company MCP Server — implementation reference.

SDK: `github.com/modelcontextprotocol/go-sdk` **v1.7.0**
Schema engine: `github.com/google/jsonschema-go` (JSON Schema draft 2020-12)
JWT: `github.com/golang-jwt/jwt/v5`
Toolchain: pinned to **go1.26.6** in `go.mod` and the Dockerfile

---

## 1. Package map

```
cmd/server/main.go              lifecycle: config → backend → service → MCP → transport

internal/
  config/config.go              environment parsing, validation, warnings, redaction
  config/dotenv.go              .env loading; the environment always wins

  domain/
    customer.go                 Customer, Order, Notification, Page, enums, versions
    errors.go                   domain.Error, nine classifications, constructors
    pii.go                      data classification, masking, fingerprinting

  authz/
    principal.go                Principal, scopes, context, Require/RequireTenant
    policy.go                   the tool/resource/prompt → scopes table

  authn/
    verifier.go                 Verifier interface, static bearer, local principal
    jwt.go                      JWT verification: iss, aud, exp, alg pinning, claims
    jwks.go                     caching JWKS client, RSA + EC key parsing

  audit/audit.go                the security event stream

  observability/
    reqctx.go                   request id, W3C trace context, header sanitising
    metrics.go                  registry + Prometheus text exposition
    names.go                    metric names and help text (one place)

  ratelimit/limiter.go          layered token buckets with TTL eviction
  idempotency/store.go          Store interface + in-process TTL implementation
  paging/cursor.go              HMAC-authenticated, query-bound cursors

  backend/
    backend.go                  Backend interface (tenant is an explicit parameter)
    memory.go                   seeded, tenant-partitioned in-process store
    http.go                     REST client, status → domain.Code, tenant header
    resilience.go               retry policy, backoff, jitter, circuit breaker

  services/customer.go          authorization, tenancy, validation, paging,
                                idempotency, optimistic locking, derived views

  tools/customer/
    input.go                    typed tool inputs/outputs (the schema source of truth)
    tool.go                     *mcp.Tool descriptors, descriptions, annotations
    handler.go                  thin handlers: (ctx, In) → (Out, error)

  resources/customer.go         descriptors, view projections, size caps, masking
  prompts/customer.go           descriptors, handlers, untrusted-data framing

  mcp/
    server.go                   sdk.NewServer, options, registration, deps
    middleware.go               the seven-stage receiving chain
    auth.go                     token verification seam, principal reconstruction
    audit.go                    authentication audit events (HTTP boundary)
    feature.go                  request → (kind, name) extraction
    tools.go                    sdk.AddTool wiring + adapt() + response size cap
    resources.go                AddResource / AddResourceTemplate wiring
    prompts.go                  AddPrompt wiring + completion handler
    transport.go                stdio, HTTP, mux, probes, metrics, hardening
    errors.go                   domain.Error → tool error / JSON-RPC error
```

### Import direction

```
cmd/server
    └─► internal/mcp ──► internal/tools/customer ─┐
            │      │                              │
            │      ├──► internal/resources ───────┤
            │      ├──► internal/prompts ─────────┤
            │      ├──► internal/authn            ├──► internal/services ──► internal/backend
            │      ├──► internal/audit            │            │                    │
            │      ├──► internal/ratelimit        │            ├──► internal/paging │
            │      └──► internal/observability ───┘            └──► internal/idempotency
            │                                                               │
    every layer ──────────────────────────────────────────────────────► internal/domain
                                                                        internal/authz
```

`internal/domain` and `internal/authz` import nothing from this module, which is
what breaks the cycle between `backend` and `services` and lets an authorization
decision be tested without a protocol.

---

## 2. SDK API surface used

| Concern | API |
|---|---|
| Server | `mcp.NewServer(*mcp.Implementation, *mcp.ServerOptions)` |
| Tools | `mcp.AddTool[In, Out](server, *mcp.Tool, mcp.ToolHandlerFor[In, Out])` |
| Resources | `server.AddResource`, `server.AddResourceTemplate` |
| Prompts | `server.AddPrompt` |
| Completion | `ServerOptions.CompletionHandler` |
| Middleware | `server.AddReceivingMiddleware` — applied left to right, so the first runs outermost |
| Identity | `RequestExtra.TokenInfo`, `RequestExtra.Header` |
| Authentication | `auth.RequireBearerToken`, `auth.TokenInfo` |
| stdio | `server.Run(ctx, &mcp.StdioTransport{})` |
| Streamable HTTP | `mcp.NewStreamableHTTPHandler(getServer, *mcp.StreamableHTTPOptions)` |
| Errors | plain `error` → tool error; `*jsonrpc.Error` → protocol error; `mcp.ResourceNotFoundError` |

`StreamableHTTPOptions` set here: `Stateless`, `JSONResponse`, `SessionTimeout`,
`MaxRequestBodyBytes`, `PropagateRequestCancellation`, `Logger`.

No JSON-RPC framing, transport, discovery or schema validation is implemented in
this repository.

---

## 3. The identity path

This is the mechanism the whole security model rests on, so it is worth reading
once in full.

```
HTTP request with Authorization: Bearer <token>
    │
    ▼
s.securityHeaders  →  crossOrigin  →  s.clientContext  →  s.challenge
    │                                        │
    │   clientContext deletes any inbound X-Mcp-Client-Ip and sets the resolved
    │   one, so a caller cannot forge its own address
    ▼
auth.RequireBearerToken(verify, opts)          [SDK]
    │   verify → authn.Verifier.Verify(token) → *authz.Principal
    │   principal → toTokenInfo() → *auth.TokenInfo
    │   401 here; nothing below runs
    ▼
mcp.NewStreamableHTTPHandler                    [SDK]
    │   reads auth.TokenInfoFromContext(r.Context())
    │   attaches it to every jsonrpc.Request as RequestExtra.TokenInfo
    ▼
authenticateMiddleware
    │   req.GetExtra().TokenInfo → tokenClaims → authz.Principal
    │   → authz.NewContext(ctx, principal)
    ▼
authorizeMiddleware → handler → service
        both read authz.FromContext(ctx)
```

Two properties fall out of this shape:

- **Nothing in the JSON-RPC body participates.** The principal is reconstructed
  from claims the SDK carried from a verified signature. A tool argument cannot
  reach it.
- **`authz.FromContext` on a context with no principal returns an anonymous
  one**, not nil. A caller that forgets to check still fails closed, because
  every `Require` on an anonymous principal is a denial.

On stdio there is no HTTP layer, so `authenticateMiddleware` falls back to the
configured local principal. There is no third case: a request always runs as
some principal, and an unauthenticated one holds nothing.

---

## 4. Middleware chain

Registered in `server.go`, in this order:

| # | Middleware | Responsibility |
|---|---|---|
| 1 | `recoveryMiddleware` | recover a panic → JSON-RPC internal error; stack to the log only |
| 2 | `correlationMiddleware` | request id + trace context onto the context |
| 3 | `observeMiddleware` | duration, counters, one structured line; never arguments |
| 4 | `authenticateMiddleware` | claims → principal; pin the tenant when tenancy is off |
| 5 | `throttleMiddleware` | rate limit; exempts `initialize` and `ping` |
| 6 | `authorizeMiddleware` | scope + tenant gate; filters list results |
| 7 | `auditMiddleware` | one audit record per data operation |

`initialize` and `ping` are exempt from throttling because rejecting a
reconnecting client makes it retry harder.

### Denial encoding

`Server.denial` picks the shape from the method:

```go
if method != methodToolsCall {
    return nil, protocolError(classify(ctx, err, method))   // no in-band channel
}
return &sdk.CallToolResult{
    IsError: true,
    Content: []sdk.Content{&sdk.TextContent{Text: de.Error()}},
}, nil
```

A `tools/call` denial is a result, not an error, so the model reads it. A
`resources/read` or `prompts/get` denial has no in-band channel and becomes a
JSON-RPC error.

### List filtering

`filterListing` rewrites `ListToolsResult`, `ListResourcesResult`,
`ListResourceTemplatesResult` and `ListPromptsResult` per principal. Computed
per request, never cached — the answer depends on who is asking.

---

## 5. Schema generation

Go types are the source of truth. `mcp.AddTool` infers input and output schemas,
so schema and handler cannot drift.

| Go | JSON Schema |
|---|---|
| field **without** `omitempty` | **required** property |
| field **with** `omitempty` | optional property |
| `jsonschema:"..."` tag | property `description` |
| `time.Time` | `string` |
| struct | `object`, `additionalProperties: false` |

Constraints a tag cannot express are applied by patching the inferred schema:

```go
InputSchema: mustSchema[SearchCustomersInput](func(s *jsonschema.Schema) {
    enum(s, "status", domain.StatusStrings())   // the same slice the validator reads
    bounds(s, "limit", 1, maxSearchLimit)       // the same constant the service clamps to
    maxLen(s, "query", services.MaxSearchTextLength)
}),
```

`prop()` panics if a patched property name no longer exists, so renaming a JSON
tag without updating the patch fails at process start rather than silently
producing an unconstrained schema. `tests/schema` catches it a build earlier.

**`additionalProperties: false` matters more than it looks.** An unknown
argument is refused rather than ignored, and an ignored argument is how a caller
convinces itself it passed a tenant, a filter or an override that the server
never saw.

---

## 6. Tool reference

Every tool: `INVALID_ARGUMENT` on bad input, `UNAUTHORIZED` without a
credential, `FORBIDDEN` without the scope, `RATE_LIMITED` over budget,
`TIMEOUT` and `BACKEND_ERROR` from upstream.

```
get_customer                 READ_ONLY          customer:read
  in    customer_id: string (required)
  out   { customer: {customer_id, name, email, status, tier, country,
                     version, created_at, updated_at} }
  api   GET /customers/{id}                              retried
  errs  + NOT_FOUND

search_customers             READ_ONLY          customer:search
  in    query?, status?, tier?, limit? (1..100), cursor?
  out   { customers[], count, truncated, next_cursor? }
  api   GET /customers?q=&status=&tier=&limit=&after=    retried
  rules at least one filter; limit clamped, not rejected; cursor bound to
        tenant+principal+operation+filters, 15-minute TTL

list_customer_orders         READ_ONLY          customer:orders:read
  in    customer_id (required), limit? (1..200), cursor?
  out   { customer_id, orders[], count, truncated, next_cursor? }
  api   GET /customers/{id}/orders?limit=&after=         retried
  errs  + NOT_FOUND

update_customer              MUTATING           customer:update
  in    customer_id (required), name?, email?, status?, tier?, expected_version?
  out   { customer, updated_fields[] }
  api   PATCH /customers/{id}      retried only without expected_version
  rules at least one field; email must be a bare address (no display-name form);
        omitted fields unchanged; version bumps on every write
  errs  + NOT_FOUND, CONFLICT

delete_customer              DESTRUCTIVE        customer:delete
  in    customer_id (required), confirm: bool (required, must be true),
        expected_version?
  out   { customer_id, deleted: true }
  api   DELETE /customers/{id}?expected_version=         never retried
  errs  + NOT_FOUND, CONFLICT

send_customer_notification   EXTERNAL_SIDE_EFFECT   notification:send
  in    customer_id (required), channel: email|sms (required),
        subject? (required for email, ≤200), body (required, ≤4000),
        idempotency_key? (8..128)
  out   { message_id, customer_id, channel, accepted_at, replayed? }
  api   POST /customers/{id}/notifications               never retried
  rules subject refuses control characters (header injection); body refuses
        non-printables but allows newlines; stricter rate limit; same key +
        same message replays, same key + different message is CONFLICT
  errs  + NOT_FOUND, CONFLICT
```

---

## 7. Resource reference

| URI | Scopes | Contents |
|---|---|---|
| `customer://directory` | `customer:search` | active customers, capped at 50 |
| `customer://{id}` | `customer:read` | one full record |
| `customer://{id}/orders` | `customer:orders:read` | order history, newest first, capped at 200 |
| `customer://{id}/summary` | `customer:read` **+** `customer:orders:read` | record plus roll-ups |

Bodies are **view projections**, not domain types: `tenant_id` is never
serialised towards a client, so adding a field to `domain.Customer` cannot leak
it by accident.

**Routing.** Exact resources are matched before templates, and a template
variable never matches across `/`. `customer://directory` reaches its own
handler rather than being looked up as a customer named "directory", and
`customer://1001` and `customer://1001/orders` route unambiguously.

**Size.** A body over `MAX_RESOURCE_BYTES` is refused, not truncated — truncated
JSON is invalid JSON, and a model handed a broken document reasons about it
anyway.

`lifetime_spend` excludes cancelled orders. `last_order_at` is the newest order
whatever its status, because "when did this account last order?" has an answer
even when that order was cancelled. `currency: "MIXED"` means the orders span
several currencies and the total must not be shown as one figure. `partial:
true` means the roll-up covers only the most recent page, so the totals are a
floor.

---

## 8. Prompt reference

```
customer-analysis            customer:read + customer:orders:read
  args   customer_id (required), focus ∈ overview|retention|revenue|support
  embeds the live summary
  frames the JSON as data, not instructions
  forbids calling state-changing tools

customer-outreach-draft      customer:read
  args   customer_id (required), topic (required), tone ∈ formal|friendly|urgent
  embeds the live customer record
  produces subject + body for human review
  forbids calling send_customer_notification
```

`completion/complete` offers the closed sets for `focus` and `tone`. Customer
ids are deliberately **not** completed: enumerating the customer base into an
autocomplete list is a data-exposure decision, not a side effect of typing.

---

## 9. Error mapping

```
domain.Code            tools/call                  resources/read, prompts/get
─────────────────────  ──────────────────────────  ────────────────────────────
INVALID_ARGUMENT       IsError, "CODE: message"    -32602 InvalidParams
NOT_FOUND              IsError                     ResourceNotFoundError / -32602
UNAUTHORIZED           IsError                     -32602
FORBIDDEN              IsError                     -32602
CONFLICT               IsError                     -32602
TIMEOUT                IsError                     -32602
RATE_LIMITED           IsError                     -32602
BACKEND_ERROR          IsError                     -32603 InternalError
INTERNAL_ERROR         IsError                     -32603
```

The client-facing text is `"CODE: message"`, or `"CODE: message (field \"x\")"`
for a validation failure. The internal cause never appears — reaching it
requires `Detail()`, which only `logFailure` calls, and that line carries the
`request_id` so an operator can join it to the redacted message the client saw.

Upstream status mapping lives in `classifyStatus` (`internal/backend/http.go`);
the table is in [DEPLOYMENT.md](DEPLOYMENT.md).

---

## 10. Concurrency and state

| Component | Sharing | Protection |
|---|---|---|
| `backend.Memory` | one per process | `sync.RWMutex`, tenant-partitioned maps |
| `ratelimit.Limiter` | one per process | `sync.Mutex`; TTL eviction bounds the map |
| `idempotency.Memory` | one per process | `sync.Mutex`; TTL + max-entries bound it |
| `observability.Metrics` | one per process | `RWMutex` for the registry, atomics for counters |
| `authn.KeySet` | one per verifier | `RWMutex` + a single-flight mutex on refresh |
| `backend.circuit` | one per HTTP backend | `sync.Mutex`; one probe at a time when half-open |
| SDK sessions | many | owned by the SDK |
| `authz.Principal` | one per request | immutable once built |

`go test -race ./...` is clean.

**Optimistic locking.** `Customer.Version` starts at 1 and increments on every
write. A caller passes the version it read as `expected_version`; a mismatch is
`CONFLICT`. Version 0 means "not supplied" — which is why numbering starts at 1,
so a caller cannot express an expectation that does not exist.

**Idempotency.** `Begin` reserves, `Commit` stores, `Abort` releases on failure.
A concurrent duplicate is refused rather than queued. A reservation left by a
crashed process expires after five minutes, so a key is never blocked forever.

---

## 11. Lifecycle

```
main()
  ├─ config.LoadEnvFile(path)    fill gaps from .env; never override the environment
  ├─ config.Load()               validate; fatal on an invalid combination
  ├─ cfg.Warnings()              log what is legal but questionable
  ├─ -check-config               → exit 0 here
  ├─ newBackend(cfg)             memory | http (+ retry, circuit)
  ├─ services.NewCustomerService(be, {Cursors, Idempotency})
  ├─ svc.Health(ctx)             http mode: fatal · memory mode: warn
  ├─ appmcp.New(cfg, svc, logger, NewDeps(cfg, logger, svc.Health))
  │     ├─ buildVerifier(cfg)    static | JWT | none
  │     ├─ AddReceivingMiddleware(...)  seven stages
  │     └─ register tools, resources, prompts
  ├─ signal.NotifyContext(SIGINT, SIGTERM)
  ├─ server.Serve(ctx)           stdio or HTTP — chosen after registration
  ├─ server.Shutdown(grace)      close remaining sessions
  └─ backend.Close()
```

**Shutdown.** HTTP: stop accepting, drain for `MCP_HTTP_SHUTDOWN_TIMEOUT`, close
sessions. stdio: `Run` returns on cancellation, closing the session and waiting
for the in-flight handler. Signal interception is released after the first
signal, so a second Ctrl-C kills the process rather than being swallowed.

---

## 12. Test map

| Property | Where |
|---|---|
| Scope matching, policy coverage, fail-closed defaults | `internal/authz` |
| Token verification, algorithm confusion, JWKS | `internal/authn` |
| Cursor authentication and binding | `internal/paging` |
| Rate-limit budgets and layer independence | `internal/ratelimit` |
| Idempotency contract and races | `internal/idempotency` |
| Trace propagation, metric rendering | `internal/observability` |
| Status classification, tenancy, paging, versions, retry, circuit | `internal/backend` |
| Config defaults, validation, redaction, .env precedence | `internal/config` |
| Authorization, tenancy, concurrency, idempotency, validation | `tests/services` |
| Tool-layer input handling | `tests/tools` |
| Resource URIs, payloads, redaction | `tests/resources` |
| Prompt arguments, context, guard rails | `tests/prompts` |
| Schema/validator drift, annotations, policy coverage | `tests/schema` |
| Protocol, both transports, operational endpoints | `tests/integration` |
| The threat model, through a real client | `tests/security` |
| Parsers on the trust boundary | `tests/fuzz` |
| Sizing figures | `tests/bench` |

---

## 13. Extending the server

### A new tool

1. Add input/output types in `internal/tools/customer/input.go`.
2. Add the descriptor in `tool.go`: name, title, description (what it does, when
   to use it, **when not to**, limits, side effects), behaviour class, schema
   patches.
3. Add a handler in `handler.go`: shape input, one service call, shape output.
4. Add the business rule in `internal/services`, including the scope check.
5. **Add the scope to `internal/authz/policy.go`.** Until you do,
   `tests/schema` fails and the tool is unreachable at runtime.
6. Register it in `internal/mcp/tools.go`.
7. If it is destructive or reaches outside the system: a stricter rate-limit
   rule, an idempotency key or a confirmation argument, a `tests/security` case.

### A new backend

Implement `backend.Backend`. The tenant is an explicit parameter on every method
that touches customer data, and cross-tenant must produce `NOT_FOUND` rather
than `FORBIDDEN`. Classify failures as `*domain.Error` — no upstream text may
reach the caller. Copy `internal/backend/memory_test.go` as the conformance
suite.

### A shared idempotency store

Implement the three-method `idempotency.Store` against Redis. `Begin` must be
atomic (`SET key value NX EX ttl`), or two replicas can both believe they won
and both send. `TestConcurrentBeginElectsOneWinner` defines the contract.
