# Authentication and authorization

Two questions, answered in two places, with two different failure modes.

**Authentication** — *who is calling?* Answered at the HTTP boundary by
verifying a bearer token. Failure is `401`, and a fresh credential fixes it.

**Authorization** — *may this caller do this?* Answered from the resulting
principal, per operation. Failure is `FORBIDDEN`, and no amount of retrying
helps.

Keeping them apart matters because collapsing them produces the two classic
bugs: a token that is valid for *something* being treated as valid for
*everything*, and a permission failure being reported in a way that invites an
infinite retry loop.

---

## The chain

```
  HTTP request
      │
      ▼
  auth.RequireBearerToken (SDK)          ── verifies the signature
      │                                     401 here; nothing below runs
      ▼
  RequestExtra.TokenInfo                 ── the SDK carries the verified claims
      │                                     onto every JSON-RPC request
      ▼
  authenticateMiddleware                 ── claims → authz.Principal on the ctx
      │
      ▼
  authorizeMiddleware                    ── policy check, per operation
      │
      ▼
  handler → service                      ── checks the principal again
```

The property that matters: **nothing in the JSON-RPC body participates at any
step.** A tool argument, a prompt, or text inside a customer's record arrives on
the far side of every one of these checks. That is what makes prompt injection
unable to escalate privilege here — not the wording of any instruction.

---

## Modes

Set with `MCP_AUTH_MODE`.

### `none`

No credential. The principal is synthetic and carries `MCP_LOCAL_SCOPES` inside
`MCP_LOCAL_TENANT`.

Correct for **stdio**, where the OS process boundary is the security boundary:
whoever can spawn the binary can use it, and a token in the client's config adds
nothing.

Over HTTP the server **refuses to start** unless `MCP_ALLOW_INSECURE_HTTP=true`.
An unauthenticated HTTP deployment has to be a decision someone made, not a
default someone inherited.

### `static`

One shared bearer token, compared in constant time.

```bash
MCP_AUTH_MODE=static
MCP_HTTP_BEARER_TOKEN=<32+ random bytes, base64>   # SECRET
MCP_LOCAL_SUBJECT=hosted-connector
MCP_LOCAL_TENANT=acme
MCP_LOCAL_SCOPES=customer:read,customer:search,customer:orders:read
```

Be clear about what this is: **every caller presenting the token is the same
principal, with the same tenant and the same scopes.** It authenticates a
deployment, not a user. That is a real and reasonable configuration behind a
trusted proxy — and it is not multi-tenancy, which is why `TENANCY_ENABLED=true`
refuses to start in this mode. The server logs a warning saying so at startup.

Minimum length is enforced (16 characters; use far more). Generate with
`openssl rand -base64 32`.

### `oauth`

Verified JWT access tokens. The only mode that supports per-user authorization
and multi-tenancy.

```bash
MCP_AUTH_MODE=oauth
MCP_OAUTH_ISSUER=https://idp.example.com/
MCP_OAUTH_AUDIENCE=https://mcp.example.com/mcp
MCP_OAUTH_JWKS_URL=https://idp.example.com/.well-known/jwks.json
MCP_OAUTH_TENANT_CLAIM=tenant_id
MCP_OAUTH_SCOPE_CLAIMS=scope,scp,permissions
MCP_OAUTH_RESOURCE_METADATA_URL=https://mcp.example.com/.well-known/oauth-protected-resource
```

Checked on every token, in this order:

1. **Signature**, against a key from the JWKS. The algorithm list is pinned —
   this is what stops an attacker swapping `RS256` for `HS256` and signing with
   the public key, or for `none` and signing with nothing.
2. **`iss`**, exact match.
3. **`aud`**, must contain this server's resource identifier.
4. **`exp`**, required, with 60 seconds of clock-skew tolerance. `nbf` if
   present.
5. **`sub`**, required and non-empty.
6. **Tenant claim**, required. A token with no tenant cannot reach customer
   data at all.
7. **Required scopes**, if `MCP_OAUTH_REQUIRED_SCOPES` is set.

Per-operation scopes are checked later, per call — not at connection time. A
token that may read but not delete connects successfully and is refused at
`delete_customer`, with a message naming the permission it lacked. Refusing the
connection instead would make a partially-privileged client look broken.

#### Why the audience is mandatory

Without it, a token minted by the same issuer for *any other service* would be
accepted here. That is the confused-deputy problem RFC 8707 exists to prevent:
your analytics service's token becomes a key to your customer database.
Configuration refuses to start without one, and `NewJWT` refuses to construct a
verifier without one.

#### Why an HMAC secret is discouraged

`MCP_OAUTH_HMAC_SECRET` enables HS256 for an internal issuer. It works, and it
means this server holds the key that *mints* tokens as well as the key that
verifies them. A compromise of this process becomes a token-forging capability
against every service that trusts the issuer. Use asymmetric keys and a JWKS URL
for anything public.

#### JWKS handling

- Cached, refreshed every `MCP_OAUTH_JWKS_REFRESH` (default 15 minutes).
- An unknown `kid` triggers one refresh, rate-limited to once a minute so a
  flood of bogus tokens cannot become a flood of requests at the identity
  provider.
- If the provider is unreachable, the **last good key set is served past its
  refresh interval** rather than discarded. Refusing every request while an
  unrelated service is down is the worse failure.
- RSA (≥2048-bit modulus, enforced) and EC (P-256/384/521, validated through
  `crypto/ecdh` so an off-curve point — the invalid-curve attack — is refused).
- One malformed key does not invalidate the rest of the set.

#### Failures are undifferentiated

"Expired", "wrong issuer", "bad signature" and "unknown key" all produce the
same `401`. An attacker probing the endpoint learns nothing about which check
failed. The specific reason goes to the audit record.

---

## Scopes

```
customer:read           read one customer record
customer:search         search, and read the customer directory
customer:orders:read    read a customer's orders
customer:update         change fields on a customer
customer:delete         permanently delete a customer
notification:send       send an email or SMS to a customer
```

Read from the first claim that carries any, in `MCP_OAUTH_SCOPE_CLAIMS` order —
issuers disagree about the shape:

| Issuer | Claim | Shape |
|---|---|---|
| RFC 8693 / most | `scope` | space-delimited string |
| Microsoft Entra | `scp` | space-delimited string |
| Auth0 | `permissions` | array of strings |

Matching is **exact**, with two wildcard forms honoured because real
authorization servers emit them: `*` grants everything, and `customer:*` grants
that prefix. Deliberately *not* matched: substrings and case variants. An issuer
handing out `customer:read-only` must not thereby grant `customer:read`, and
`Customer:Read` is a different string. `TestHasMatchesExactlyAndByWildcard`.

### Suggested grants

| Client | Scopes |
|---|---|
| Read-only analytics | `customer:read customer:search customer:orders:read` |
| Support agent | the above plus `customer:update` |
| Outreach automation | `customer:read notification:send` |
| Data steward | all six |

Grant the narrowest set that works. The listing filter means a client sees only
the tools it can call, so a narrow grant produces a smaller, clearer tool list
rather than a broken one.

---

## Tenancy

`TENANCY_ENABLED=true` requires `MCP_AUTH_MODE=oauth`, and startup fails
otherwise. The reason is not pedantry: only a verified token can carry a
per-caller tenant. A static token names one tenant for every caller, which is
single-tenancy wearing a multi-tenant label — the most dangerous kind of
misconfiguration, because it looks correct.

With tenancy enabled, the tenant comes from `MCP_OAUTH_TENANT_CLAIM` on the
verified token. With it disabled, every caller is pinned to `TENANCY_DEFAULT`,
overriding whatever a token claims — so a token minted elsewhere cannot name a
tenant this deployment does not serve.

**There is no request field that names a tenant.** No tool argument, no header,
no prompt text. `TestTenantIsNotTakenFromTheRequest`.

---

## Client configuration

### Claude Desktop (stdio)

```json
{
  "mcpServers": {
    "company-customers": {
      "command": "/absolute/path/to/bin/mcp-server",
      "env": {
        "MCP_TRANSPORT": "stdio",
        "BACKEND_MODE": "http",
        "BACKEND_BASE_URL": "https://api.internal.example.com/v1",
        "BACKEND_API_TOKEN": "…",
        "MCP_LOCAL_SCOPES": "customer:read,customer:search,customer:orders:read"
      }
    }
  }
}
```

Narrowing `MCP_LOCAL_SCOPES` is how a stdio deployment gets least privilege:
there is no token to scope, so the configuration is the grant.

### Remote client (HTTP, static)

```
POST /mcp HTTP/1.1
Authorization: Bearer <MCP_HTTP_BEARER_TOKEN>
Content-Type: application/json
Accept: application/json, text/event-stream
```

### Remote client (HTTP, OAuth)

Standard OAuth 2.1 with PKCE against your identity provider, then present the
access token as a bearer. A `401` carries `WWW-Authenticate` with the
`resource_metadata` pointer when `MCP_OAUTH_RESOURCE_METADATA_URL` is set, so a
spec-compliant client can discover the authorization server (RFC 9728) instead
of being told to guess.

---

## Operational notes

- **Rotating a static token:** accept both old and new at the proxy during a
  short overlap, or restart replicas one at a time. The server holds one token,
  so a rolling restart is the rotation.
- **Rotating signing keys:** publish the new key in the JWKS before issuing
  tokens with it. An unknown `kid` triggers a refresh, so no restart is needed.
- **Revocation:** this server does not introspect tokens; a revoked token is
  valid until it expires. Keep access-token lifetimes short (5–15 minutes). If
  immediate revocation is a requirement, terminate OAuth at a gateway that
  introspects.
- **Never log a token.** Nothing in this codebase does, and the audit test
  asserts it: `TestStreamableHTTPRequiresBearerToken` fails if the token appears
  anywhere in the audit stream.
