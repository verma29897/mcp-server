package observability

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTraceContextIsContinuedFromTheCaller(t *testing.T) {
	const (
		traceID = "4bf92f3577b34da6a3ce929d0e0e4736"
		spanID  = "00f067aa0ba902b7"
	)
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.Header.Set(HeaderTraceParent, "00-"+traceID+"-"+spanID+"-01")
	r.Header.Set(HeaderTraceState, "vendor=value")

	rc := FromHTTP(r)
	if rc.TraceID != traceID {
		t.Errorf("trace id = %q, want the caller's %q", rc.TraceID, traceID)
	}
	if rc.TraceState != "vendor=value" {
		t.Errorf("tracestate = %q, want it propagated verbatim", rc.TraceState)
	}
	// This server is the parent of whatever it calls next, so it mints its own
	// span id rather than reusing the caller's.
	if rc.SpanID == spanID {
		t.Error("the caller's span id was reused instead of a new one being generated")
	}
	if !strings.HasPrefix(rc.TraceParent(), "00-"+traceID+"-") {
		t.Errorf("outbound traceparent = %q, want the same trace id", rc.TraceParent())
	}
}

func TestMalformedTraceParentIsIgnoredNotFatal(t *testing.T) {
	// A broken upstream tracer must not be able to fail requests.
	bad := []string{
		"", "garbage", "00-tooshort-00f067aa0ba902b7-01",
		"01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
	}
	for _, header := range bad {
		r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		r.Header.Set(HeaderTraceParent, header)

		rc := FromHTTP(r)
		if len(rc.TraceID) != 32 {
			t.Errorf("traceparent %q produced trace id %q; a fresh one should have been generated", header, rc.TraceID)
		}
	}
}

func TestRequestIDIsHonouredButSanitised(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.Header.Set(HeaderRequestID, "req-abc-123")
	if got := FromHTTP(r).RequestID; got != "req-abc-123" {
		t.Errorf("request id = %q, want the caller's; losing it breaks the trace across the hop", got)
	}

	// The value ends up in log records, so anything that could forge a second
	// field has to be stripped before it gets there.
	r = httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.Header.Set(HeaderRequestID, "abc\n\"level\":\"error\",\"msg\":\"forged")
	got := FromHTTP(r).RequestID
	for _, bad := range []string{"\n", "\"", " ", ","} {
		if strings.Contains(got, bad) {
			t.Errorf("sanitised request id %q still contains %q", got, bad)
		}
	}

	r = httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.Header.Set(HeaderRequestID, strings.Repeat("a", 5000))
	if n := len(FromHTTP(r).RequestID); n > 128 {
		t.Errorf("request id length = %d, want it bounded", n)
	}
}

func TestFromHeadersMirrorsFromHTTP(t *testing.T) {
	h := map[string][]string{
		"X-Request-Id":    {"req-1"},
		"Traceparent":     {"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
		"X-Mcp-Client-Ip": {"203.0.113.9"},
	}
	rc := FromHeaders(h)
	if rc.RequestID != "req-1" {
		t.Errorf("request id = %q", rc.RequestID)
	}
	if rc.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("trace id = %q", rc.TraceID)
	}
	if rc.RemoteAddr != "203.0.113.9" {
		t.Errorf("remote addr = %q", rc.RemoteAddr)
	}

	// No headers at all still yields usable ids, so a stdio session correlates.
	if rc := FromHeaders(nil); rc.RequestID == "" || len(rc.TraceID) != 32 {
		t.Errorf("empty headers produced %+v, want generated ids", rc)
	}
}

func TestInjectHTTPCarriesCorrelationOnward(t *testing.T) {
	rc := NewLocal()
	out := httptest.NewRequest(http.MethodGet, "http://backend.example/customers", nil)
	rc.InjectHTTP(out)

	if out.Header.Get(HeaderRequestID) != rc.RequestID {
		t.Error("the request id was not propagated to the backend call")
	}
	if out.Header.Get(HeaderTraceParent) == "" {
		t.Error("no traceparent on the backend call; the trace stops at this server")
	}
}

func TestStripPortKeepsTheHostOnly(t *testing.T) {
	tests := map[string]string{
		"203.0.113.9:54321": "203.0.113.9",
		"[2001:db8::1]:443": "2001:db8::1",
		"203.0.113.9":       "203.0.113.9",
		"":                  "",
	}
	for in, want := range tests {
		if got := stripPort(in); got != want {
			t.Errorf("stripPort(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMetricsRenderPrometheusExposition(t *testing.T) {
	m := NewMetrics(true)
	m.Inc(ToolCalls, "tool", "get_customer", "outcome", OutcomeSuccess)
	m.Inc(ToolCalls, "tool", "get_customer", "outcome", OutcomeSuccess)
	m.Inc(ToolCalls, "tool", "delete_customer", "outcome", OutcomeDenied)
	m.Observe(ToolDuration, 25*time.Millisecond, "tool", "get_customer")
	m.SetGauge(ActiveSessions, "Currently open MCP sessions.", func() float64 { return 3 })

	out := m.Render()
	for _, want := range []string{
		"# TYPE mcp_tool_calls_total counter",
		`mcp_tool_calls_total{tool="get_customer",outcome="success"} 2`,
		`mcp_tool_calls_total{tool="delete_customer",outcome="denied"} 1`,
		"# TYPE mcp_tool_duration_seconds histogram",
		`mcp_tool_duration_seconds_bucket{tool="get_customer",le="+Inf"} 1`,
		"mcp_tool_duration_seconds_count",
		"# TYPE mcp_active_sessions gauge",
		"mcp_active_sessions 3",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("exposition output is missing %q\n---\n%s", want, out)
		}
	}
}

func TestDisabledMetricsCollectNothing(t *testing.T) {
	m := NewMetrics(false)
	m.Inc(ToolCalls, "tool", "get_customer", "outcome", OutcomeSuccess)
	if strings.Contains(m.Render(), "mcp_tool_calls_total") {
		t.Error("a disabled registry recorded a counter")
	}
}

func TestNilRegistryIsUsable(t *testing.T) {
	// The backend client holds a *Metrics that may be nil in a test or an
	// embedding process; a nil-pointer panic there would take down a request
	// path for the sake of a counter.
	var m *Metrics
	m.Inc(ToolCalls, "tool", "t", "outcome", OutcomeSuccess)
	m.Observe(ToolDuration, time.Second, "tool", "t")
	m.ObserveValue(ResponseBytes, 10, "feature", "t")
	m.SetGauge(ActiveSessions, "help", func() float64 { return 0 })
	if m.Enabled() {
		t.Error("a nil registry reports itself enabled")
	}
}

func TestLabelValuesAreEscaped(t *testing.T) {
	m := NewMetrics(true)
	m.Inc(Errors, "code", `we"ird\value`, "feature", "x")
	out := m.Render()
	if !strings.Contains(out, `code="we\"ird\\value"`) {
		t.Errorf("label value was not escaped:\n%s", out)
	}
}

func TestMetricsHandlerServesTheRightContentType(t *testing.T) {
	m := NewMetrics(true)
	m.Inc(MCPRequests, "method", "tools/call", "outcome", OutcomeSuccess)

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content type = %q, want the Prometheus text format", ct)
	}

	rec = httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/metrics", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /metrics = %d, want 405", rec.Code)
	}
}
