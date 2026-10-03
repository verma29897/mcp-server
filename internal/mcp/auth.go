package mcp

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	sdkauth "github.com/modelcontextprotocol/go-sdk/auth"

	"github.com/verma29897/mcp-server/internal/authn"
	"github.com/verma29897/mcp-server/internal/authz"
	"github.com/verma29897/mcp-server/internal/config"
	"github.com/verma29897/mcp-server/internal/observability"
)

// This file is the seam between the SDK's HTTP-level authentication and this
// server's own notion of a principal.
//
// The flow, in order, because the order is the security property:
//
//	1. auth.RequireBearerToken verifies the credential at the HTTP boundary.
//	   A request with no valid token never reaches the MCP handler at all.
//	2. The verified claims are attached to the request, and the SDK carries
//	   them onto every JSON-RPC request in RequestExtra.TokenInfo.
//	3. authMiddleware turns those claims into an authz.Principal on the
//	   handler's context.
//	4. Every authorization decision downstream reads that principal.
//
// Nothing in the JSON-RPC body participates. A tool argument, a prompt, or text
// inside a customer record cannot influence step 1 through 4, which is exactly
// the property that makes prompt injection unable to escalate privilege here.

// tokenClaims is the subset of the SDK's TokenInfo this server consumes.
//
// A local type rather than the SDK's, so nothing below internal/mcp needs to
// import the SDK to reason about identity.
type tokenClaims struct {
	scopes     []string
	expiration time.Time
	userID     string
	extra      map[string]any
}

// principalKeyTenant is the key under which the verifier stashes the tenant.
const principalKeyTenant = "tenant_id"

// principalKeys are the extra-map keys the verifier populates.
const (
	principalKeySubject  = "sub"
	principalKeyClientID = "client_id"
	principalKeyIssuer   = "iss"
	principalKeyMode     = "auth_mode"
)

// toPrincipal rebuilds a principal from verified token claims.
func (t *tokenClaims) toPrincipal() *authz.Principal {
	if t == nil {
		return nil
	}
	p := &authz.Principal{
		Subject:   stringFrom(t.extra, principalKeySubject),
		TenantID:  stringFrom(t.extra, principalKeyTenant),
		Scopes:    append([]string(nil), t.scopes...),
		ClientID:  stringFrom(t.extra, principalKeyClientID),
		Issuer:    stringFrom(t.extra, principalKeyIssuer),
		ExpiresAt: t.expiration,
		Mode:      authz.AuthMode(stringFrom(t.extra, principalKeyMode)),
	}
	if p.Subject == "" {
		p.Subject = t.userID
	}
	return p
}

func stringFrom(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

// toTokenInfo renders a principal into the SDK's TokenInfo, which is how it
// travels from the HTTP layer to the MCP layer.
func toTokenInfo(p *authz.Principal) *sdkauth.TokenInfo {
	return &sdkauth.TokenInfo{
		Scopes:     p.Scopes,
		Expiration: p.ExpiresAt,
		// UserID lets the SDK's streamable transport bind a session to the user
		// who created it, which is what stops one caller resuming another's
		// session by guessing its id.
		UserID: p.Subject,
		Extra: map[string]any{
			principalKeySubject:  p.Subject,
			principalKeyTenant:   p.TenantID,
			principalKeyClientID: p.ClientID,
			principalKeyIssuer:   p.Issuer,
			principalKeyMode:     string(p.Mode),
		},
	}
}

// buildVerifier constructs the token verifier for the configured auth mode.
func buildVerifier(cfg *config.Config) (authn.Verifier, error) {
	switch cfg.Auth.Mode {
	case config.AuthStatic:
		return authn.NewStatic(
			cfg.Auth.StaticToken,
			cfg.Auth.LocalSubject,
			cfg.Tenancy.DefaultTenant,
			cfg.Auth.LocalScopes,
		)
	case config.AuthOAuth:
		var keys *authn.KeySet
		if cfg.Auth.JWKSURL != "" {
			keys = authn.NewKeySet(cfg.Auth.JWKSURL, &http.Client{Timeout: 10 * time.Second}, cfg.Auth.JWKSRefresh)
		}
		return authn.NewJWT(authn.JWTConfig{
			Issuer:         cfg.Auth.Issuer,
			Audience:       cfg.Auth.Audience,
			JWKSURL:        cfg.Auth.JWKSURL,
			HMACSecret:     cfg.Auth.HMACSecret,
			TenantClaim:    cfg.Auth.TenantClaim,
			ScopeClaims:    cfg.Auth.ScopeClaims,
			RequiredScopes: cfg.Auth.RequiredScopes,
		}, keys)
	default:
		return nil, nil
	}
}

// localPrincipal is the identity used where no credential is presented: the
// stdio transport, and an HTTP deployment that explicitly opted out of auth.
func (s *Server) localPrincipal() *authz.Principal {
	mode := authz.AuthLocal
	if s.cfg.Transport == config.TransportHTTP {
		mode = authz.AuthNone
	}
	tenant := s.cfg.Auth.LocalTenant
	if tenant == "" {
		tenant = s.cfg.Tenancy.DefaultTenant
	}
	return authn.LocalPrincipal(s.cfg.Auth.LocalSubject, tenant, s.cfg.Auth.LocalScopes, mode)
}

// httpAuth wraps a handler with bearer-token verification.
//
// It uses the SDK's RequireBearerToken so that the 401 response, the
// WWW-Authenticate header and the RFC 9728 resource-metadata pointer are
// exactly what an MCP client expects to see - a hand-rolled 401 is where
// interoperability with a spec-compliant client quietly breaks.
func (s *Server) httpAuth(next http.Handler) http.Handler {
	if s.verifier == nil {
		return next
	}

	opts := &sdkauth.RequireBearerTokenOptions{
		ResourceMetadataURL: s.cfg.Auth.ResourceMetadataURL,
		// Scopes are checked per operation, not per connection: a token that
		// may read but not delete should connect successfully and be refused at
		// delete_customer, with a message saying which permission it lacked.
		Scopes: nil,
		// A static token has no expiry to carry, so requiring one would reject
		// every request in static mode.
		AllowMissingExpiration: s.cfg.Auth.Mode == config.AuthStatic,
		ClockSkew:              60 * time.Second,
	}

	verify := func(ctx context.Context, token string, r *http.Request) (*sdkauth.TokenInfo, error) {
		principal, err := s.verifier.Verify(ctx, token)
		if err != nil {
			s.metrics.Inc(observability.AuthFailures, "reason", failureReason(err))
			s.auditAuthFailure(ctx, r, err)
			// Collapse every verification failure onto the SDK's sentinel, so
			// the client sees one 401 and learns nothing about which check
			// failed. The detail is in the audit record.
			return nil, errors.Join(sdkauth.ErrInvalidToken, err)
		}
		s.auditAuthSuccess(ctx, r, principal)
		return toTokenInfo(principal), nil
	}

	return sdkauth.RequireBearerToken(verify, opts)(next)
}

// failureReason classifies an authentication failure for the metric label.
//
// The set is closed and coarse on purpose: a label taken from an error string
// would let a caller create unbounded metric cardinality by varying its token.
func failureReason(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, authn.ErrInvalidToken):
		return "invalid_token"
	default:
		return "verifier_error"
	}
}

// clientIP resolves the caller's address for rate limiting and audit.
//
// X-Forwarded-For is honoured only when the deployment has declared it sits
// behind a proxy. Trusting it unconditionally would let any caller pick its own
// identity for rate limiting and put a chosen address into every audit record.
func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.HTTP.TrustProxyHeaders {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// The left-most entry is the original client; everything after it
			// was appended by intermediaries.
			if first, _, ok := strings.Cut(xff, ","); ok {
				return strings.TrimSpace(first)
			}
			return strings.TrimSpace(xff)
		}
		if real := r.Header.Get("X-Real-Ip"); real != "" {
			return strings.TrimSpace(real)
		}
	}
	return observability.FromHTTP(r).RemoteAddr
}
