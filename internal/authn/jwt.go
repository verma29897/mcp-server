package authn

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/verma29897/mcp-server/internal/authz"
)

// JWTConfig configures OAuth 2.1 / OIDC access-token verification.
//
// Every field that narrows who may call the server is required, because the
// failure mode of a permissive default here is that any valid token from any
// issuer for any audience is accepted. Audience in particular: without it, a
// token minted for a different service in the same identity provider would be
// replayable against this one - the confused-deputy problem RFC 8707 exists to
// prevent.
type JWTConfig struct {
	// Issuer is the exact `iss` value that must appear in the token.
	Issuer string
	// Audience is the resource identifier of this MCP server; the token's `aud`
	// must contain it.
	Audience string
	// JWKSURL serves the issuer's public signing keys. Mutually exclusive with
	// HMACSecret.
	JWKSURL string
	// HMACSecret enables HS256 verification with a shared secret. It is for
	// internal issuers only; a public deployment should use asymmetric keys so
	// the resource server cannot mint tokens.
	HMACSecret string
	// TenantClaim names the claim carrying the tenant id.
	TenantClaim string
	// ScopeClaims names the claims that may carry scopes, in priority order.
	ScopeClaims []string
	// RequiredScopes must all be present or the token is rejected outright.
	RequiredScopes []string
	// AllowedAlgs restricts acceptable `alg` values. Never empty in practice:
	// an unrestricted verifier accepts "none" and algorithm-confusion attacks.
	AllowedAlgs []string
	// Leeway tolerates clock drift on time-based claims.
	Leeway time.Duration
}

// JWTVerifier verifies signed JWT access tokens.
type JWTVerifier struct {
	cfg    JWTConfig
	keys   *KeySet
	hmac   []byte
	parser *jwt.Parser
}

var _ Verifier = (*JWTVerifier)(nil)

// NewJWT builds a JWT verifier.
func NewJWT(cfg JWTConfig, keys *KeySet) (*JWTVerifier, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("authn: JWT issuer is required")
	}
	if cfg.Audience == "" {
		return nil, errors.New("authn: JWT audience is required; without it a token for another service would be accepted")
	}
	if cfg.JWKSURL == "" && cfg.HMACSecret == "" {
		return nil, errors.New("authn: one of JWKS URL or HMAC secret is required")
	}
	if cfg.JWKSURL != "" && cfg.HMACSecret != "" {
		return nil, errors.New("authn: JWKS URL and HMAC secret are mutually exclusive")
	}
	if cfg.HMACSecret != "" && len(cfg.HMACSecret) < 32 {
		return nil, errors.New("authn: HMAC secret must be at least 32 characters")
	}
	if cfg.TenantClaim == "" {
		cfg.TenantClaim = "tenant_id"
	}
	if len(cfg.ScopeClaims) == 0 {
		cfg.ScopeClaims = []string{"scope", "scp", "permissions"}
	}
	if len(cfg.AllowedAlgs) == 0 {
		if cfg.HMACSecret != "" {
			cfg.AllowedAlgs = []string{"HS256", "HS384", "HS512"}
		} else {
			cfg.AllowedAlgs = []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}
		}
	}
	if cfg.Leeway <= 0 {
		cfg.Leeway = clockSkew
	}

	v := &JWTVerifier{cfg: cfg, keys: keys, hmac: []byte(cfg.HMACSecret)}
	v.parser = jwt.NewParser(
		// Pinning the algorithm list is what stops an attacker swapping RS256
		// for HS256 and signing with the public key, or for "none" and signing
		// with nothing.
		jwt.WithValidMethods(cfg.AllowedAlgs),
		jwt.WithIssuer(cfg.Issuer),
		jwt.WithAudience(cfg.Audience),
		jwt.WithLeeway(cfg.Leeway),
		jwt.WithExpirationRequired(),
	)
	return v, nil
}

// Mode implements Verifier.
func (v *JWTVerifier) Mode() authz.AuthMode { return authz.AuthOAuth }

// Verify implements Verifier.
//
// Order matters: signature and registered claims first (the parser does both),
// then the application claims. Nothing is read out of an unverified token.
func (v *JWTVerifier) Verify(ctx context.Context, token string) (*authz.Principal, error) {
	claims := jwt.MapClaims{}
	parsed, err := v.parser.ParseWithClaims(strings.TrimSpace(token), claims, func(t *jwt.Token) (any, error) {
		return v.key(ctx, t)
	})
	if err != nil {
		return nil, invalid("jwt verification failed: %v", err)
	}
	if !parsed.Valid {
		return nil, invalid("jwt reported invalid")
	}

	subject, _ := claims["sub"].(string)
	if subject == "" {
		return nil, invalid("jwt has no sub claim")
	}

	tenant := stringClaim(claims, v.cfg.TenantClaim)
	if tenant == "" {
		return nil, invalid("jwt has no %q claim; a token without a tenant cannot reach customer data", v.cfg.TenantClaim)
	}

	scopes := v.scopes(claims)
	principal := &authz.Principal{
		Subject:  subject,
		TenantID: tenant,
		Scopes:   scopes,
		ClientID: firstString(claims, "client_id", "azp", "cid"),
		Issuer:   v.cfg.Issuer,
		Mode:     authz.AuthOAuth,
	}
	if exp, err := claims.GetExpirationTime(); err == nil && exp != nil {
		principal.ExpiresAt = exp.Time
	}

	for _, required := range v.cfg.RequiredScopes {
		if !principal.Has(required) {
			return nil, invalid("jwt is missing the required scope %q", required)
		}
	}
	return principal, nil
}

// key selects the verification key for one token.
func (v *JWTVerifier) key(ctx context.Context, t *jwt.Token) (any, error) {
	if len(v.hmac) > 0 {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %q for an HMAC verifier", t.Method.Alg())
		}
		return v.hmac, nil
	}
	kid, _ := t.Header["kid"].(string)
	return v.keys.key(ctx, kid, t.Method.Alg())
}

// scopes extracts the granted scopes from the first claim that carries any.
//
// Issuers disagree about the shape: RFC 8693 says a space-delimited string in
// `scope`, Azure AD uses `scp`, Auth0 uses a `permissions` array. All three are
// accepted, in the configured order, and the first that yields anything wins.
func (v *JWTVerifier) scopes(claims jwt.MapClaims) []string {
	for _, name := range v.cfg.ScopeClaims {
		switch raw := claims[name].(type) {
		case string:
			if s := authz.ParseScopes(raw); len(s) > 0 {
				return s
			}
		case []any:
			out := make([]string, 0, len(raw))
			for _, item := range raw {
				if s, ok := item.(string); ok && s != "" {
					out = append(out, s)
				}
			}
			if len(out) > 0 {
				return out
			}
		}
	}
	return nil
}

func stringClaim(claims jwt.MapClaims, name string) string {
	s, _ := claims[name].(string)
	return strings.TrimSpace(s)
}

func firstString(claims jwt.MapClaims, names ...string) string {
	for _, n := range names {
		if s := stringClaim(claims, n); s != "" {
			return s
		}
	}
	return ""
}
