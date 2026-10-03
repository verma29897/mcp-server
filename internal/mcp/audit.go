package mcp

import (
	"context"
	"crypto/subtle"
	"net/http"

	"github.com/verma29897/mcp-server/internal/audit"
	"github.com/verma29897/mcp-server/internal/authz"
	"github.com/verma29897/mcp-server/internal/domain"
	"github.com/verma29897/mcp-server/internal/observability"
)

// Authentication events are recorded at the HTTP boundary rather than in the
// MCP middleware, because a request that fails authentication never becomes an
// MCP request at all. Without a record here, the most interesting event in the
// log - repeated rejected credentials from one address - would be invisible.

// auditAuthSuccess records an accepted credential.
func (s *Server) auditAuthSuccess(ctx context.Context, r *http.Request, p *authz.Principal) {
	s.audit.Log(ctx, audit.Event{
		Action:     audit.ActionAuthSuccess,
		Result:     audit.ResultSuccess,
		Principal:  p,
		RequestID:  observability.FromHTTP(r).RequestID,
		Method:     r.Method + " " + r.URL.Path,
		Client:     truncateUA(r.UserAgent()),
		RemoteAddr: s.clientIP(r),
	})
}

// auditAuthFailure records a rejected credential.
//
// The token is not logged, not even truncated or hashed: a partial token is
// still a secret, and a hash of one is a verifier for anybody who later obtains
// a candidate. The address, the user agent and the time are what an
// investigation actually uses.
func (s *Server) auditAuthFailure(ctx context.Context, r *http.Request, err error) {
	s.audit.Log(ctx, audit.Event{
		Action:     audit.ActionAuthFailure,
		Result:     audit.ResultDenied,
		RequestID:  observability.FromHTTP(r).RequestID,
		Method:     r.Method + " " + r.URL.Path,
		Code:       domain.CodeUnauthorized,
		Reason:     failureReason(err),
		Client:     truncateUA(r.UserAgent()),
		RemoteAddr: s.clientIP(r),
	})
}

func truncateUA(ua string) string {
	const max = 120
	if len(ua) > max {
		return ua[:max]
	}
	return ua
}

// constantTimeEqual compares two secrets without leaking their common prefix
// through timing.
func constantTimeEqual(got, want string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
