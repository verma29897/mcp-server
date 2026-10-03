// Package observability carries the per-request identity used for correlation
// and the process metrics.
//
// Correlation is deliberately vendor-neutral. The W3C Trace Context header
// (traceparent/tracestate) is the interoperable wire format every tracing
// system understands, including every OpenTelemetry SDK, so this package
// parses, propagates and generates it directly rather than pulling in a tracing
// SDK the deployment may not want. An operator who does want OpenTelemetry
// wraps the HTTP handler and the backend transport with the otelhttp
// instrumentation; the trace ids stay the same, because they are the same
// header. See docs/OPERATIONS.md.
package observability

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
)

// Header names carried across the trust boundary.
const (
	// HeaderRequestID is the correlation id, honoured if the caller sends one.
	HeaderRequestID = "X-Request-Id"
	// HeaderTraceParent is the W3C Trace Context traversal header.
	HeaderTraceParent = "traceparent"
	// HeaderTraceState is the W3C vendor state header, forwarded verbatim.
	HeaderTraceState = "tracestate"
)

// RequestContext is the correlation identity of one inbound request.
type RequestContext struct {
	// RequestID correlates every log and audit record for this request.
	RequestID string
	// TraceID is the 32-hex-character W3C trace id.
	TraceID string
	// SpanID is the 16-hex-character id of the caller's span, which is this
	// request's parent.
	SpanID string
	// TraceFlags is the W3C sampling byte, propagated unchanged.
	TraceFlags string
	// TraceState is the W3C vendor state, propagated unchanged.
	TraceState string
	// RemoteAddr is the source address without its port.
	RemoteAddr string
	// UserAgent identifies the calling application.
	UserAgent string
}

// TraceParent renders the context back into a traceparent header, so the same
// trace continues into the backend call this request makes.
func (rc *RequestContext) TraceParent() string {
	if rc == nil || rc.TraceID == "" || rc.SpanID == "" {
		return ""
	}
	flags := rc.TraceFlags
	if flags == "" {
		flags = "01"
	}
	return "00-" + rc.TraceID + "-" + rc.SpanID + "-" + flags
}

type requestKey struct{}

// NewContext returns ctx carrying rc.
func NewContext(ctx context.Context, rc *RequestContext) context.Context {
	return context.WithValue(ctx, requestKey{}, rc)
}

// FromContext returns the request context carried by ctx, or an empty one.
func FromContext(ctx context.Context) *RequestContext {
	rc, _ := ctx.Value(requestKey{}).(*RequestContext)
	if rc == nil {
		return &RequestContext{}
	}
	return rc
}

// RequestIDFrom is the ergonomic accessor for the correlation id.
func RequestIDFrom(ctx context.Context) string { return FromContext(ctx).RequestID }

// TraceIDFrom is the ergonomic accessor for the trace id.
func TraceIDFrom(ctx context.Context) string { return FromContext(ctx).TraceID }

// FromHTTP builds a RequestContext from an inbound HTTP request.
//
// A caller-supplied request id is honoured, because a gateway usually assigns
// one and losing it breaks the trace across the hop. It is length-limited and
// stripped of anything but printable ASCII first: the value ends up in log
// records, and an unfiltered header is a log-injection vector.
func FromHTTP(r *http.Request) *RequestContext {
	rc := &RequestContext{
		RequestID:  sanitizeID(r.Header.Get(HeaderRequestID)),
		RemoteAddr: stripPort(r.RemoteAddr),
		UserAgent:  truncate(r.UserAgent(), 200),
	}
	if rc.RequestID == "" {
		rc.RequestID = NewID()
	}
	parseTraceParent(rc, r.Header.Get(HeaderTraceParent))
	rc.TraceState = truncate(sanitizeHeader(r.Header.Get(HeaderTraceState)), 512)
	if rc.TraceID == "" {
		rc.TraceID = randomHex(16)
		rc.TraceFlags = "01"
	}
	// This server is the parent of whatever it calls next.
	rc.SpanID = randomHex(8)
	return rc
}

// HeaderClientIP carries the server-resolved client address from the HTTP
// wrapper to the MCP middleware.
//
// The MCP SDK hands a request handler the inbound headers but not the
// connection, so the address has to travel as a header. The wrapper deletes any
// inbound value before setting its own, which is what stops a caller supplying
// its own address and escaping per-IP rate limiting.
const HeaderClientIP = "X-Mcp-Client-Ip"

// FromHeaders builds a RequestContext from the headers of an inbound MCP
// request, as the SDK surfaces them.
//
// It mirrors FromHTTP, for the point in the chain where only the header set is
// available. A request with no correlation headers still gets fresh ids.
func FromHeaders(h map[string][]string) *RequestContext {
	get := func(key string) string {
		if v := textproto(h, key); v != "" {
			return v
		}
		return ""
	}
	rc := &RequestContext{
		RequestID:  sanitizeID(get(HeaderRequestID)),
		RemoteAddr: sanitizeID(get(HeaderClientIP)),
		UserAgent:  truncate(sanitizeHeader(get("User-Agent")), 200),
	}
	if rc.RequestID == "" {
		rc.RequestID = NewID()
	}
	parseTraceParent(rc, get(HeaderTraceParent))
	rc.TraceState = truncate(sanitizeHeader(get(HeaderTraceState)), 512)
	if rc.TraceID == "" {
		rc.TraceID = randomHex(16)
		rc.TraceFlags = "01"
	}
	rc.SpanID = randomHex(8)
	return rc
}

// textproto reads a header case-insensitively from a plain map.
func textproto(h map[string][]string, key string) string {
	if v, ok := h[http.CanonicalHeaderKey(key)]; ok && len(v) > 0 {
		return v[0]
	}
	for k, v := range h {
		if len(v) > 0 && strings.EqualFold(k, key) {
			return v[0]
		}
	}
	return ""
}

// NewLocal builds a RequestContext for a transport with no headers, such as
// stdio. The ids are still generated so a stdio session's logs correlate.
func NewLocal() *RequestContext {
	return &RequestContext{
		RequestID:  NewID(),
		TraceID:    randomHex(16),
		SpanID:     randomHex(8),
		TraceFlags: "01",
		RemoteAddr: "stdio",
	}
}

// parseTraceParent fills the trace fields from a W3C traceparent header.
//
// A malformed header is ignored rather than rejected: a broken upstream tracer
// must not be able to fail requests. The all-zero ids the spec calls invalid
// are treated as absent.
func parseTraceParent(rc *RequestContext, header string) {
	parts := strings.Split(strings.TrimSpace(header), "-")
	if len(parts) != 4 || parts[0] != "00" {
		return
	}
	traceID, spanID, flags := parts[1], parts[2], parts[3]
	if !isHex(traceID, 32) || !isHex(spanID, 16) || !isHex(flags, 2) {
		return
	}
	if traceID == strings.Repeat("0", 32) || spanID == strings.Repeat("0", 16) {
		return
	}
	rc.TraceID = traceID
	rc.TraceFlags = flags
}

// InjectHTTP writes the correlation headers onto an outbound request, so the
// backend API's own logs join up with this server's.
func (rc *RequestContext) InjectHTTP(r *http.Request) {
	if rc == nil || r == nil {
		return
	}
	if rc.RequestID != "" {
		r.Header.Set(HeaderRequestID, rc.RequestID)
	}
	if tp := rc.TraceParent(); tp != "" {
		r.Header.Set(HeaderTraceParent, tp)
	}
	if rc.TraceState != "" {
		r.Header.Set(HeaderTraceState, rc.TraceState)
	}
}

// NewID returns a fresh 128-bit correlation id.
func NewID() string { return randomHex(16) }

func randomHex(n int) string {
	b := make([]byte, n)
	// crypto/rand.Read never fails on a supported platform; Go 1.24+ panics
	// internally rather than returning an error, so there is nothing to handle.
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// sanitizeID keeps a caller-supplied id usable as a log field: printable ASCII,
// no separators that would let a value forge a second field, bounded length.
func sanitizeID(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 128 {
		s = s[:128]
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			b.WriteByte(c)
		case c == '-' || c == '_' || c == '.' || c == ':':
			b.WriteByte(c)
		}
	}
	return b.String()
}

// sanitizeHeader strips control characters from a header value bound for a log.
func sanitizeHeader(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// stripPort removes the ":port" suffix from a remote address.
//
// The port is noise for correlation and, in an audit record, it is one more
// datum tying a record to a person's NAT session.
func stripPort(addr string) string {
	if addr == "" {
		return ""
	}
	if i := strings.LastIndex(addr, ":"); i > 0 {
		// Bracketed IPv6 keeps its brackets; strip them for readability.
		host := addr[:i]
		return strings.Trim(host, "[]")
	}
	return addr
}
