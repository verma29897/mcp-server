// Package audit emits the security event stream.
//
// It is deliberately separate from the application log. An application log
// answers "why is this slow?"; an audit log answers "who read that customer's
// record, from where, and did it succeed?" - and it has to answer that months
// later, to someone who was not there. That difference drives three rules:
//
//   - Every record has the same shape, so it is queryable without parsing prose.
//   - A record is emitted for the denial as well as the success. An audit trail
//     that only records what worked cannot show an attempted breach.
//   - No record ever contains a credential, a message body, or a customer's
//     name or address in the clear. Identifiers and fingerprints only.
package audit

import (
	"context"
	"log/slog"
	"time"

	"github.com/verma29897/mcp-server/internal/authz"
	"github.com/verma29897/mcp-server/internal/domain"
)

// Action names an auditable operation.
type Action string

const (
	ActionAuthSuccess   Action = "auth.success"
	ActionAuthFailure   Action = "auth.failure"
	ActionAuthzDenied   Action = "authz.denied"
	ActionRateLimited   Action = "ratelimit.exceeded"
	ActionCustomerRead  Action = "customer.read"
	ActionCustomerList  Action = "customer.search"
	ActionOrdersRead    Action = "customer.orders.read"
	ActionCustomerWrite Action = "customer.update"
	ActionCustomerDel   Action = "customer.delete"
	ActionNotifySend    Action = "notification.send"
	ActionResourceRead  Action = "resource.read"
	ActionPromptRender  Action = "prompt.render"
)

// Result is the outcome of an audited operation.
type Result string

const (
	ResultSuccess Result = "success"
	ResultDenied  Result = "denied"
	ResultFailure Result = "failure"
)

// Event is one audit record.
//
// Target is an identifier, never a name or an address. Detail carries extra
// structured context and is filtered through the same rule: identifiers,
// classifications and counts, never content.
type Event struct {
	Action    Action
	Result    Result
	Principal *authz.Principal
	// RequestID correlates the record with the application log and with the
	// caller's own trace.
	RequestID string
	SessionID string
	TraceID   string
	// Method is the MCP method, e.g. "tools/call".
	Method string
	// Feature is the tool, resource URI or prompt name.
	Feature string
	// Target is the customer id, or empty for operations without one.
	Target string
	// Code classifies a failure. Empty on success.
	Code domain.Code
	// Reason is a short, non-sensitive explanation of a denial.
	Reason string
	// Client is the calling application as it identified itself.
	Client string
	// RemoteAddr is the source address, already stripped of its port.
	RemoteAddr string
	// Duration is how long the operation took.
	Duration time.Duration
	// Detail is extra structured context; keys must be non-sensitive.
	Detail map[string]any
}

// Logger writes audit events.
type Logger struct {
	log     *slog.Logger
	enabled bool
}

// New returns an audit logger writing to base.
//
// The records are tagged with a "log_type":"audit" attribute so a shipping
// pipeline can route them to a different index, with a different retention
// policy, from ordinary application logs.
func New(base *slog.Logger, enabled bool) *Logger {
	if base == nil {
		base = slog.Default()
	}
	return &Logger{log: base.With("log_type", "audit"), enabled: enabled}
}

// Enabled reports whether audit records are being emitted.
func (l *Logger) Enabled() bool { return l != nil && l.enabled }

// Log writes one audit event.
//
// It always logs at info or warn, never debug: an audit record that a
// production log level can suppress is not an audit record. Denials and
// failures are warnings so they surface in an alerting rule without one having
// to parse the body.
func (l *Logger) Log(ctx context.Context, e Event) {
	if !l.Enabled() {
		return
	}

	attrs := []any{
		"action", string(e.Action),
		"result", string(e.Result),
		"ts", time.Now().UTC().Format(time.RFC3339Nano),
	}
	if p := e.Principal; p != nil && !p.Anonymous() {
		attrs = append(attrs,
			"principal", p.Subject,
			"tenant", p.TenantID,
			"auth_mode", string(p.Mode),
		)
		if p.ClientID != "" {
			attrs = append(attrs, "client_id", p.ClientID)
		}
		if p.Issuer != "" {
			attrs = append(attrs, "issuer", p.Issuer)
		}
	} else {
		attrs = append(attrs, "principal", "anonymous")
	}

	attrs = appendIf(attrs, "request_id", e.RequestID)
	attrs = appendIf(attrs, "session_id", e.SessionID)
	attrs = appendIf(attrs, "trace_id", e.TraceID)
	attrs = appendIf(attrs, "method", e.Method)
	attrs = appendIf(attrs, "feature", e.Feature)
	attrs = appendIf(attrs, "target", e.Target)
	attrs = appendIf(attrs, "code", string(e.Code))
	attrs = appendIf(attrs, "reason", e.Reason)
	attrs = appendIf(attrs, "client", e.Client)
	attrs = appendIf(attrs, "remote_addr", e.RemoteAddr)
	if e.Duration > 0 {
		attrs = append(attrs, "duration_ms", e.Duration.Milliseconds())
	}
	for k, v := range e.Detail {
		attrs = append(attrs, k, v)
	}

	if e.Result == ResultSuccess {
		l.log.InfoContext(ctx, "audit", attrs...)
		return
	}
	l.log.WarnContext(ctx, "audit", attrs...)
}

func appendIf(attrs []any, key, value string) []any {
	if value == "" {
		return attrs
	}
	return append(attrs, key, value)
}
