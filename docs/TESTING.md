# Testing

```bash
make test         # everything
make test-race    # under the race detector
make cover        # coverage of internal/...
make fuzz         # each fuzz target, 30s (FUZZTIME=5m for longer)
make bench        # benchmarks
make vuln         # govulncheck
make check        # fmt-check + vet + test-race + vuln
```

---

## Layout

| Package | Covers |
|---|---|
| `internal/authz` | scope matching, the policy table, tenant checks, fail-closed defaults |
| `internal/authn` | static and JWT verification, algorithm confusion, JWKS caching and key validation |
| `internal/paging` | cursor authentication, binding, expiry, tampering |
| `internal/ratelimit` | budgets, refill, layer independence, eviction, concurrency |
| `internal/idempotency` | reserve/commit/abort, replay, mismatch, expiry, single-winner races |
| `internal/observability` | trace-context propagation, header sanitising, metric rendering |
| `internal/backend` | status classification, redaction, tenancy, pagination, versions, retry, circuit breaker |
| `internal/config` | defaults, parsing, validation failures, secret redaction |
| `tests/services` | authorization, tenancy, concurrency, idempotency, pagination, validation |
| `tests/tools` | tool-layer input handling and error classification |
| `tests/resources` | URI parsing, payload shape, redaction |
| `tests/prompts` | argument handling, live context, guard rails |
| `tests/schema` | schema/validator drift, annotations, policy coverage |
| `tests/integration` | MCP protocol, both transports, operational endpoints |
| `tests/security` | the threat model, driven through a real client |
| `tests/fuzz` | parsers on the trust boundary |
| `tests/bench` | the paths a deployment is sized on |

`internal/backend` and `internal/config` keep their tests beside them in the
usual Go style; everything else sits under `tests/` so a test package cannot
reach into an implementation detail it should not know about.

---

## What each suite is for

**`tests/security` is the one to read first.** Every test names the threat it
covers, and [THREAT-MODEL.md](THREAT-MODEL.md) maps the other way, from threat
to test. It drives a real MCP client against a real server, so what is asserted
is what a client observes — not what an internal function returns.

**`tests/schema` fails the build on drift.** The schemas are inferred from Go
types and then patched with constraints a struct tag cannot express. Inference
keeps property names honest; the patches are where drift creeps in. These tests
compare the enum in the schema against the values the validator accepts, the
bounds against the service limits, the required list against the struct tags,
and the tool list against the authorization policy. A tool added without a
policy entry fails here rather than being silently unreachable in production.

**`tests/fuzz` asserts one property for any input at all**: a classified
refusal, never a panic, a hang, or a value getting through that the validator was
supposed to stop. The notification target additionally asserts that a refused
message never reached the provider — that tool contacts a real person and there
is no undo.

**`tests/integration/transport_test.go` builds the real binary** and speaks to
it over a pipe, so the stdio path is exercised as a client would, not simulated.
It also asserts the invariant the architecture rests on: stdio and HTTP expose
an identical feature set.

---

## Conventions

**Every test names the property, not the mechanism.** A failure message should
say what is now wrong with the system, not which line differed. Compare:

```go
t.Fatalf("the customer was contacted %d times, want 1", n)      // yes
t.Fatalf("calls = %d, want 1", n)                               // no
```

**Denial tests assert the backend was never reached.** A refusal that still
performed the operation is worse than no refusal at all, so
`be.Calls("DeleteCustomer")` is checked alongside the error code.

**Time is injected, not slept.** The rate limiter, the idempotency store and the
cursor codec all take a clock, so budget refill and expiry are deterministic. The
suite runs in a few seconds.

**Tests carry a principal.** `testutil.Context()` supplies a fully privileged
one; `testutil.ContextAs(testutil.Principal(scopes...))` narrows it. A context
with no principal is refused, which is the correct default and the reason the
helper exists.

**Audit assertions parse the JSON.** `testutil.AuditRecorder` decodes the
records rather than matching substrings — an audit assertion that passes because
the word "denied" appears somewhere in a log line is not an assertion about the
audit record.

---

## Adding a tool

The tests that will fail until you have finished, in the order you will hit
them:

1. `tests/schema` — `TestEveryToolIsCoveredByTheAuthorizationPolicy` fails until
   the tool has an entry in `internal/authz/policy.go`.
2. `tests/schema` — `TestEveryToolHasACompleteDescriptor` fails until the
   description covers what it does, when not to use it, its limits and its side
   effects.
3. `tests/schema` — `TestSchemaPropertiesMatchTheStructTags` and
   `TestEveryPropertyIsDescribed` fail on an undescribed or mismatched property.
4. `tests/integration` — the surface-parity test fails until the tool appears
   over both transports.

Then add, by hand: a `tests/services` case for its authorization and validation
rules, a `tests/security` case if it touches anything destructive or external,
and a fuzz seed if it accepts free-form input.

---

## Manual verification: MCP Inspector

Automated tests cover the protocol; the Inspector covers a real client's view of
it, including the browser-facing controls that have no test here.

```bash
make inspect                                    # stdio
make run-http && npx @modelcontextprotocol/inspector   # Streamable HTTP
```

| Check | Expected |
|---|---|
| `initialize` | name, version, instructions |
| capabilities | `tools`, `resources`, `prompts`, `completions` |
| `tools/list` | 6 tools with input schema, output schema, annotations |
| `tools/call` | `get_customer {"customer_id":"1001"}` → Acme Industries |
| tool error | `get_customer {"customer_id":"9999"}` → `isError`, `NOT_FOUND` |
| schema rejection | `search_customers {"status":"archived"}` → rejected before the handler |
| destructive guard | `delete_customer` without `confirm` → `INVALID_ARGUMENT` |
| scope filtering | narrow `MCP_LOCAL_SCOPES`, reconnect → a shorter tool list |
| `resources/list` | `customer://directory` |
| `resources/templates/list` | 3 templates |
| `resources/read` | `customer://1001/summary` → JSON with roll-ups |
| resource miss | `customer://9999` → protocol error, not found |
| `prompts/list` | 2 prompts with argument metadata |
| `prompts/get` | `customer-analysis {"customer_id":"1001"}` → live data embedded |
| completion | `focus` with `re` → `retention`, `revenue` |
| cross-origin | a request with a foreign `Origin` → 403 |
| DNS rebinding | a loopback request with a non-localhost `Host` → 403 |

The last two also have automated coverage (`TestCrossOriginRequestIsRejected`,
`TestDNSRebindingIsRejected`), but they are SDK and standard-library behaviour,
so re-checking them by hand after an SDK upgrade is still worth the minute it
takes.

---

## Coverage

```bash
make cover
```

Coverage is a floor, not a target. The suites that matter most here —
`tests/security` and `tests/schema` — assert properties rather than exercising
lines, and a line-coverage number says nothing about whether a scope check is
enforced. Read the security suite instead.
