// Package authn turns a presented credential into an authenticated principal.
//
// It knows about tokens and signatures. It knows nothing about MCP, about
// tools, or about what the resulting principal is then allowed to do - that is
// internal/authz. The split matters because authentication and authorization
// fail differently: a bad token is a 401 and a retry with a fresh credential; a
// valid token without a scope is a 403 and no amount of retrying helps.
package authn

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/verma29897/mcp-server/internal/authz"
	"github.com/verma29897/mcp-server/internal/domain"
)

// ErrInvalidToken is returned for any credential that fails verification.
//
// It is deliberately undifferentiated: "expired", "wrong issuer", "bad
// signature" and "unknown key" all produce the same client-visible outcome, so
// an attacker probing the endpoint learns nothing about which part was wrong.
// The specific reason is attached as an internal cause for the server log.
var ErrInvalidToken = errors.New("invalid token")

// Verifier validates a bearer token and reports who presented it.
type Verifier interface {
	// Verify returns the principal for token, or an error wrapping
	// ErrInvalidToken. It must not log the token.
	Verify(ctx context.Context, token string) (*authz.Principal, error)
	// Mode names the mechanism, for audit records.
	Mode() authz.AuthMode
}

// invalid wraps a reason as an ErrInvalidToken. The reason is for the server
// log; callers surface only the sentinel.
func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidToken, fmt.Sprintf(format, args...))
}

// StaticVerifier accepts one shared secret and grants a fixed principal.
//
// This is the deployment where the MCP server sits behind a trusted proxy and
// the token identifies the deployment rather than a user. It is honest about
// what it is: every caller presenting the token is the same principal, with the
// same tenant and the same scopes. It is not a substitute for OAuth in a
// multi-user deployment, and the documentation says so.
type StaticVerifier struct {
	token    []byte
	subject  string
	tenantID string
	scopes   []string
}

// NewStatic returns a verifier for a single shared bearer token.
func NewStatic(token, subject, tenantID string, scopes []string) (*StaticVerifier, error) {
	if token == "" {
		return nil, errors.New("authn: static bearer token must not be empty")
	}
	if len(token) < 16 {
		return nil, errors.New("authn: static bearer token must be at least 16 characters")
	}
	if tenantID == "" {
		return nil, errors.New("authn: static bearer token needs a tenant")
	}
	if subject == "" {
		subject = "static-token"
	}
	return &StaticVerifier{
		token:    []byte(token),
		subject:  subject,
		tenantID: tenantID,
		scopes:   append([]string(nil), scopes...),
	}, nil
}

// Mode implements Verifier.
func (v *StaticVerifier) Mode() authz.AuthMode { return authz.AuthStatic }

// Verify implements Verifier.
func (v *StaticVerifier) Verify(_ context.Context, token string) (*authz.Principal, error) {
	// Constant time, so a rejected request leaks nothing about how much of the
	// token was correct. The length comparison is a separate branch because
	// ConstantTimeCompare returns 0 for mismatched lengths without comparing.
	got := []byte(strings.TrimSpace(token))
	if subtle.ConstantTimeCompare(got, v.token) != 1 {
		return nil, invalid("static token mismatch")
	}
	return &authz.Principal{
		Subject:  v.subject,
		TenantID: v.tenantID,
		Scopes:   append([]string(nil), v.scopes...),
		Mode:     authz.AuthStatic,
	}, nil
}

// LocalPrincipal builds the principal used when authentication is not in play:
// the stdio transport, where the OS process boundary is the security boundary,
// and an explicitly unauthenticated HTTP deployment behind a trusted network.
func LocalPrincipal(subject, tenantID string, scopes []string, mode authz.AuthMode) *authz.Principal {
	if subject == "" {
		subject = "local"
	}
	return &authz.Principal{
		Subject:  subject,
		TenantID: tenantID,
		Scopes:   append([]string(nil), scopes...),
		Mode:     mode,
	}
}

// Denied converts a verification failure into the classified error a transport
// should surface. The cause is preserved for logging and never rendered to the
// client by domain.Error.Error.
func Denied(err error) *domain.Error {
	return domain.Unauthorized("the presented credential was not accepted").WithCause(err)
}

// clockSkew is the tolerance applied to token time claims.
//
// Distributed issuers and resource servers do not share a clock. Without a
// tolerance, a token minted a fraction of a second ago can appear to be
// not-yet-valid, which shows up as intermittent 401s that are painful to
// diagnose. Sixty seconds is the usual industry setting.
const clockSkew = 60 * time.Second
