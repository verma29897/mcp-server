// Package authz holds the authenticated identity and the authorization rules
// applied to it.
//
// It imports neither the MCP SDK nor net/http: an authorization decision is a
// property of the caller and the operation, not of the protocol that carried
// the request. That is what lets the same rules be enforced in the MCP
// middleware, re-enforced in the service layer, and unit-tested with neither.
//
// The single most important rule in this package: a decision is made from the
// Principal, which comes from a cryptographically verified credential. It is
// never made from tool arguments, prompt text, resource contents or anything
// else a model can influence.
package authz

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/verma29897/mcp-server/internal/domain"
)

// Scopes recognised by this server. They name operations, not tools, so a tool
// rename does not silently widen a grant.
const (
	ScopeCustomerRead       = "customer:read"
	ScopeCustomerSearch     = "customer:search"
	ScopeCustomerUpdate     = "customer:update"
	ScopeCustomerDelete     = "customer:delete"
	ScopeCustomerOrdersRead = "customer:orders:read"
	ScopeNotificationSend   = "notification:send"
)

// AllScopes lists every scope this server understands, in a stable order.
var AllScopes = []string{
	ScopeCustomerRead,
	ScopeCustomerSearch,
	ScopeCustomerUpdate,
	ScopeCustomerDelete,
	ScopeCustomerOrdersRead,
	ScopeNotificationSend,
}

// ReadOnlyScopes is the grant an analytics or reporting client should get.
var ReadOnlyScopes = []string{
	ScopeCustomerRead,
	ScopeCustomerSearch,
	ScopeCustomerOrdersRead,
}

// AuthMode records how a principal was established, for audit records.
type AuthMode string

const (
	// AuthNone means authentication is switched off for this deployment. The
	// principal is synthetic and carries the configured local grant.
	AuthNone AuthMode = "none"
	// AuthStatic means a shared static bearer token was presented.
	AuthStatic AuthMode = "static"
	// AuthOAuth means a signed JWT access token was verified.
	AuthOAuth AuthMode = "oauth"
	// AuthLocal means the process is on stdio, where the OS process boundary is
	// the authentication boundary.
	AuthLocal AuthMode = "local"
)

// Principal is the authenticated caller.
//
// It is immutable once built. Nothing downstream may widen Scopes or change
// TenantID: both come from the verified credential.
type Principal struct {
	// Subject identifies the caller. For OAuth it is the token's `sub`.
	Subject string
	// TenantID is the isolation boundary every data access is scoped to.
	TenantID string
	// Scopes are the operations this caller may perform.
	Scopes []string
	// ClientID identifies the calling application, when the credential says so.
	ClientID string
	// Issuer is the authorization server that minted the credential.
	Issuer string
	// ExpiresAt bounds the credential's validity. Zero means no in-band expiry.
	ExpiresAt time.Time
	// Mode records how the principal was established.
	Mode AuthMode
}

// Anonymous reports whether p carries no established identity at all.
func (p *Principal) Anonymous() bool { return p == nil || p.Subject == "" }

// Has reports whether the principal holds scope.
//
// Two wildcard forms are honoured, because real authorization servers emit
// them: "*" grants everything, and a trailing "*" after a colon grants a
// prefix, so "customer:*" covers customer:read and customer:orders:read alike.
// Matching is exact otherwise - no substring, no case folding.
func (p *Principal) Has(scope string) bool {
	if p == nil {
		return false
	}
	for _, s := range p.Scopes {
		if s == scope || s == "*" {
			return true
		}
		if prefix, ok := strings.CutSuffix(s, "*"); ok && prefix != "" &&
			strings.HasSuffix(prefix, ":") && strings.HasPrefix(scope, prefix) {
			return true
		}
	}
	return false
}

// Require returns nil when the principal may perform the operation named by
// scope, and a classified error otherwise.
//
// The distinction between UNAUTHORIZED and FORBIDDEN is deliberate: the first
// tells a client to authenticate, the second tells it that authenticating again
// will not help. Neither message names the scopes the principal does hold.
func (p *Principal) Require(scope string) error {
	if p.Anonymous() {
		return domain.Unauthorized("this operation requires an authenticated caller")
	}
	if !p.ExpiresAt.IsZero() && time.Now().After(p.ExpiresAt) {
		return domain.Unauthorized("the credential presented for this session has expired")
	}
	if !p.Has(scope) {
		return domain.Forbidden("this operation requires the %q permission, which the caller does not hold", scope)
	}
	return nil
}

// RequireTenant returns nil when the principal may act inside tenantID.
//
// A caller with no tenant is never allowed to borrow one from a request
// argument: that is precisely the escalation this guards.
func (p *Principal) RequireTenant(tenantID string) error {
	if p.Anonymous() {
		return domain.Unauthorized("this operation requires an authenticated caller")
	}
	if p.TenantID == "" {
		return domain.Forbidden("the caller's credential carries no tenant, so no customer data can be reached")
	}
	if tenantID != "" && tenantID != p.TenantID {
		// NOT_FOUND rather than FORBIDDEN: see domain.NotFound.
		return domain.NotFound("customer", "")
	}
	return nil
}

// String renders the principal for a log line. It carries no credential
// material - only the identifiers an operator needs to trace a request.
func (p *Principal) String() string {
	if p.Anonymous() {
		return "anonymous"
	}
	return p.Subject + "@" + p.TenantID
}

// Redacted returns the log-safe attribute set for this principal.
func (p *Principal) Redacted() map[string]any {
	if p == nil {
		return map[string]any{"principal": "anonymous"}
	}
	scopes := append([]string(nil), p.Scopes...)
	sort.Strings(scopes)
	return map[string]any{
		"principal": p.Subject,
		"tenant":    p.TenantID,
		"client_id": p.ClientID,
		"issuer":    p.Issuer,
		"auth_mode": string(p.Mode),
		"scopes":    strings.Join(scopes, " "),
	}
}

type principalKey struct{}

// NewContext returns ctx carrying p.
func NewContext(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// FromContext returns the principal carried by ctx.
//
// A context with no principal yields an anonymous one rather than nil, so a
// caller that forgets to check still fails closed: every Require on an
// anonymous principal is a denial.
func FromContext(ctx context.Context) *Principal {
	p, _ := ctx.Value(principalKey{}).(*Principal)
	if p == nil {
		return &Principal{}
	}
	return p
}

// Require is the ergonomic form of FromContext(ctx).Require(scope).
func Require(ctx context.Context, scope string) error {
	return FromContext(ctx).Require(scope)
}

// TenantOf returns the tenant the current caller acts inside.
func TenantOf(ctx context.Context) string { return FromContext(ctx).TenantID }

// denyUnknown is the answer for a feature with no policy entry.
func denyUnknown() error {
	return domain.Forbidden("this operation is not permitted")
}

// ParseScopes splits a space- or comma-separated scope string.
func ParseScopes(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == ',' || r == '\t' || r == '\n'
	})
	out := make([]string, 0, len(fields))
	seen := map[string]bool{}
	for _, f := range fields {
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	return out
}
