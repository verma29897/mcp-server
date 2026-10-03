# Client compatibility

**Nothing in this document is claimed unless it was run.** Rows marked *Not
verified* were not tested in this environment; they are not "broken" and they
are not "supported" — they are untested, and the honest word for that is
unknown.

Verified on: **2026-09-03**, against SDK `github.com/modelcontextprotocol/go-sdk
v1.7.0`, Go 1.26.6, Node 24.16.0, linux/amd64.

---

## Matrix

| Client / agent | Transport | Tools | Resources | Prompts | Completion | Streaming | Auth | Status |
|---|---|:-:|:-:|:-:|:-:|:-:|---|---|
| Go MCP SDK client v1.7.0 (in-memory) | in-process | ✅ | ✅ | ✅ | ✅ | n/a | local | **Verified** |
| Go MCP SDK client v1.7.0 (stdio) | stdio | ✅ | ✅ | ✅ | ✅ | n/a | local | **Verified** |
| Go MCP SDK client v1.7.0 (HTTP) | Streamable HTTP | ✅ | ✅ | ✅ | ✅ | ✅ SSE | static bearer | **Verified** |
| Raw JSON-RPC client (Python stdlib, no SDK) | stdio | ✅ | ✅ | ✅ | ✅ | n/a | local | **Verified** |
| Raw JSON-RPC client (`curl`) | Streamable HTTP | ✅ | ✅ | ✅ | ✅ | ✅ SSE | static bearer | **Verified** |
| MCP Inspector CLI (`@modelcontextprotocol/inspector`) | stdio | ✅ | ✅ | ✅ | n/a¹ | n/a | local | **Verified** |
| Claude Desktop | stdio | — | — | — | — | n/a | local | Not verified |
| Claude.ai custom connector | Streamable HTTP | — | — | — | — | — | OAuth / bearer | Not verified |
| MCP Inspector web UI | stdio / HTTP | — | — | — | — | — | configurable | Not verified |
| OpenAI-based agent (any MCP client library) | Streamable HTTP | — | — | — | — | — | OAuth / bearer | Not verified |
| Gemini-based agent (any MCP client library) | Streamable HTTP | — | — | — | — | — | OAuth / bearer | Not verified |
| LangChain / LlamaIndex MCP adapters | stdio / HTTP | — | — | — | — | — | configurable | Not verified |

¹ `completion/complete` is not implemented by the Inspector's CLI mode
(`Unsupported method`), so it could not be exercised there. It is verified by
the four other rows.

The first five verified rows are exercised by `tests/integration` and
`tests/security` on every run, plus the by-hand transcripts reproduced below.

**Why the unverified rows are still likely to work:** they speak the same
protocol, and the two raw-client rows demonstrate that a client needs no SDK at
all — just JSON-RPC over stdio or Streamable HTTP. That is an argument, not
evidence. Run the transcripts below against your own client before claiming a
row.

---

## What "verified" covers

For each verified row: `initialize` and version negotiation, `tools/list`,
`tools/call` (success and in-band error), `resources/list`,
`resources/templates/list`, `resources/read`, `prompts/list`, `prompts/get`,
`completion/complete`, `ping`, cursor pagination across two pages, and clean
shutdown.

For the HTTP rows, additionally: session issue and reuse, bearer authentication
(accepted and rejected), the `WWW-Authenticate` challenge, cross-origin
rejection, DNS-rebinding rejection, security headers, `/healthz`, `/readyz` and
`/metrics`.

---

## Transcript 1 — a generic client over stdio, no SDK

Forty lines of standard-library Python. If this works, any language works.

```python
import json, subprocess, os

env = dict(os.environ, MCP_TRANSPORT="stdio", LOG_LEVEL="error", BACKEND_MODE="memory")
p = subprocess.Popen(["./bin/mcp-server"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                     stderr=subprocess.DEVNULL, env=env, text=True, bufsize=1)

def send(msg):
    p.stdin.write(json.dumps(msg) + "\n"); p.stdin.flush()

def call(rid, method, params=None):
    send({"jsonrpc": "2.0", "id": rid, "method": method, **({"params": params} if params else {})})
    while True:
        m = json.loads(p.stdout.readline())
        if m.get("id") == rid:
            return m

r = call(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "raw-python-client", "version": "1.0"}})["result"]
send({"jsonrpc": "2.0", "method": "notifications/initialized"})

print(call(2, "tools/list")["result"]["tools"])
print(call(3, "tools/call", {"name": "get_customer",
                             "arguments": {"customer_id": "1001"}})["result"])
```

Observed output, unedited:

```
1 initialize   -> company-mcp-server 2025-06-18 caps: ['completions', 'logging', 'prompts', 'resources', 'tools']
2 tools/list   -> 6 ['delete_customer', 'get_customer', 'list_customer_orders', 'search_customers', 'send_customer_notification', 'update_customer']
3 resources    -> ['customer://directory'] + 3 templates
4 prompts/list -> ['customer-analysis', 'customer-outreach-draft']
5 tools/call   -> isError=False Acme Industries v1
6 tool error   -> isError=True NOT_FOUND: customer "9999" was not found
7 destructive  -> isError=True INVALID_ARGUMENT: deletion is irreversible; set
8 resource     -> spend 17790.75 USD, open 2, tenant leaked: False
9 prompts/get  -> Account review for customer 1001 with revenue focus | data framed: True
10 completion  -> ['retention', 'revenue']
11 pagination  -> count=1 truncated=True next_cursor=eyJ2IjoxLCJhIjoi...
12 page 2      -> 1002 (page 1 was 1001)
13 ping        -> ok
14 shutdown    -> exit code 0
```

Note the ordering rule that catches most hand-written clients: **wait for the
`initialize` response before sending `notifications/initialized`.** Piping all
the messages in at once produces `initialized before initialize` and the session
closes.

## Transcript 2 — a generic client over Streamable HTTP

```bash
export MCP_TRANSPORT=http MCP_HTTP_ADDR=127.0.0.1:8080 \
       MCP_AUTH_MODE=static MCP_HTTP_BEARER_TOKEN=a-test-token-long-enough
./bin/mcp-server &

AUTH='Authorization: Bearer a-test-token-long-enough'
ACCEPT='Accept: application/json, text/event-stream'

# initialize; keep the Mcp-Session-Id from the response headers
curl -sD headers.txt -X POST localhost:8080/mcp -H "$AUTH" -H 'Content-Type: application/json' -H "$ACCEPT" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2026-07-28","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}'
SID=$(grep -i '^mcp-session-id:' headers.txt | tr -d '\r' | awk '{print $2}')

curl -s -X POST localhost:8080/mcp -H "$AUTH" -H "Mcp-Session-Id: $SID" \
  -H 'Content-Type: application/json' -H "$ACCEPT" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'

curl -s -X POST localhost:8080/mcp -H "$AUTH" -H "Mcp-Session-Id: $SID" \
  -H 'Content-Type: application/json' -H "$ACCEPT" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_customer","arguments":{"customer_id":"1001"}}}'
```

Observed:

```
--- healthz ---            {"service":"company-mcp-server","status":"ok","version":"1.0.0"}
--- readyz ---             {"checks":{"backend":"ok"},"status":"ready"}
--- security headers ---   Cache-Control: no-store
                           Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
                           Referrer-Policy: no-referrer
                           X-Content-Type-Options: nosniff
--- unauthenticated ---    status=401
--- initialize ---         negotiated: 2025-11-25 | server: company-mcp-server
--- tools/call ---         1001 Acme Industries v1 isError=False
--- foreign Origin ---     status=403
--- foreign Host ---       status=403
```

A client asking for `2026-07-28` was negotiated down to `2025-11-25`, the newest
version this SDK build implements. Version negotiation works; ask for what you
support and use what comes back.

---

## Notes per client family

### Claude Desktop (stdio)

```json
{
  "mcpServers": {
    "company-customers": {
      "command": "/absolute/path/to/bin/mcp-server",
      "env": {
        "MCP_TRANSPORT": "stdio",
        "BACKEND_MODE": "memory",
        "MCP_LOCAL_SCOPES": "customer:read,customer:search,customer:orders:read"
      }
    }
  }
}
```

Use an absolute path, make the binary executable, and restart the application
fully after editing. Narrowing `MCP_LOCAL_SCOPES` is how a stdio deployment gets
least privilege — there is no token to scope, so the configuration is the grant.

### Remote clients over Streamable HTTP

Requirements, all covered in [DEPLOYMENT.md](DEPLOYMENT.md):

1. HTTPS, terminated at the proxy.
2. Authentication: `MCP_AUTH_MODE=static` or `oauth`.
3. `MCP_HTTP_STATELESS=true` for more than one replica, plus a shared
   `CURSOR_SECRET`.
4. SSE pass-through — the proxy must not buffer `text/event-stream`. If it
   cannot be persuaded, set `MCP_HTTP_JSON_RESPONSE=true`; requests still work
   and server-initiated messages are lost.
5. Long read timeouts on the MCP path; no short write timeout.

### OpenAI-, Gemini- and other model-based agents

There is nothing provider-specific in this server, and there is nothing to add.
The layering is:

```
   model (any provider)
        │
   agent framework
        │
   MCP client library
        │  MCP over stdio or Streamable HTTP
        ▼
   this server  ──►  services  ──►  backend
```

**Model selection happens entirely outside this server.** It has no model
client, no provider SDK, no prompt-completion call and no per-provider branch.
It never sees which model is on the other end, and could not behave differently
if it wanted to. The tool descriptions, schemas and annotations are the whole
interface, and they are the same for every caller.

The practical consequence: any framework with an MCP client — the OpenAI Agents
SDK, LangChain's MCP adapters, LlamaIndex, a Gemini-based agent, or forty lines
of Python as above — connects the same way. Point it at the stdio command or the
HTTP endpoint.

### MCP Inspector

```bash
make inspect                                          # stdio, web UI
make run-http && npx @modelcontextprotocol/inspector  # Streamable HTTP, http://localhost:8080/mcp

# CLI mode, which is what was verified here
npx @modelcontextprotocol/inspector --cli ./bin/mcp-server --method tools/list
npx @modelcontextprotocol/inspector --cli ./bin/mcp-server \
    --method tools/call --tool-name get_customer --tool-arg 'customer_id="1001"'
```

Verified in CLI mode: `tools/list`, `tools/call` (success, in-band error,
destructive guard, schema rejection, unknown-argument rejection),
`resources/list`, `resources/templates/list`, `resources/read` (hit and miss),
`prompts/list`, `prompts/get`. The web UI was not exercised.

**Its schema-portability check passes with zero findings.** It reported three
warnings on an earlier revision — inferred Go slice outputs declared
`"type": ["null","array"]`, which several clients read as a single string and
either reject or silently drop. Those three output schemas now declare a plain
`"array"`, and `TestOutputSchemasDeclareASingleType` plus
`TestSliceOutputsAreNeverNil` keep it that way.

**One gotcha, and it is the Inspector's, not the server's.** `--tool-arg
customer_id=1001` is coerced to a JSON *number*, and the server correctly
refuses it: `type: 1001 has type "integer", want "string"`. Quote the value —
`--tool-arg 'customer_id="1001"'` — and it works. A model filling in arguments
from the schema produces a string and never hits this.

---

## Verifying a client yourself

1. Connect and confirm `initialize` returns the server name and the four
   capabilities.
2. `tools/list` → 6 tools with input schema, output schema and annotations.
   Fewer means the scope filter is at work; check `MCP_LOCAL_SCOPES` or the
   token.
3. `tools/call get_customer {"customer_id":"1001"}` → Acme Industries.
4. `tools/call get_customer {"customer_id":"9999"}` → `isError: true`,
   `NOT_FOUND` — **as a result, not a protocol error.** A client that surfaces
   this as a transport failure is not reading `CallToolResult.IsError`.
5. `resources/read customer://1001/summary` → JSON with roll-ups.
6. `prompts/get customer-analysis {"customer_id":"1001"}` → live data embedded.
7. `completion/complete` on `focus` with `re` → `retention`, `revenue`.

If all seven pass, add the row — with the client name, its version, and the date.
