package integration_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/verma29897/mcp-server/internal/config"
	"github.com/verma29897/mcp-server/tests/testutil"
)

// These cover the HTTP surface that is not MCP: the probes an orchestrator
// uses, the metrics a scraper reads, and the transport hardening that applies
// to everything.

func TestHealthzIsIndependentOfDependencies(t *testing.T) {
	ts := newFullServer(t, testutil.Config(config.TransportHTTP))

	resp, err := ts.Client().Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("body = %v, want status ok", body)
	}
}

func TestReadyzReportsDependencyHealth(t *testing.T) {
	cfg := testutil.Config(config.TransportHTTP)

	t.Run("ready when the backend answers", func(t *testing.T) {
		ts := newFullServer(t, cfg)
		resp, err := ts.Client().Get(ts.URL + "/readyz")
		if err != nil {
			t.Fatalf("GET /readyz: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
	})

	t.Run("not ready when it does not", func(t *testing.T) {
		ts := newUnreadyServer(t, cfg)
		resp, err := ts.Client().Get(ts.URL + "/readyz")
		if err != nil {
			t.Fatalf("GET /readyz: %v", err)
		}
		defer resp.Body.Close()

		// 503 takes the replica out of the load balancer rather than letting it
		// answer every request with an error.
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want 503", resp.StatusCode)
		}
		payload, _ := io.ReadAll(resp.Body)
		// The probe is reachable from anywhere in a cluster, so it names the
		// failing check and nothing else.
		for _, leak := range []string{"password", "10.0.0", "postgres", "Bearer"} {
			if strings.Contains(string(payload), leak) {
				t.Errorf("readiness body leaks %q: %s", leak, payload)
			}
		}
	})
}

func TestLivenessStaysUpWhenTheBackendIsDown(t *testing.T) {
	// A liveness probe that fails on a backend outage gets the pod restarted,
	// which fixes nothing and removes the capacity that could still serve.
	ts := newUnreadyServer(t, testutil.Config(config.TransportHTTP))

	resp, err := ts.Client().Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("liveness = %d while the backend was down, want 200", resp.StatusCode)
	}
}

func TestMetricsEndpointServesPrometheusText(t *testing.T) {
	cfg := testutil.Config(config.TransportHTTP)
	ts := newFullServer(t, cfg)

	resp, err := ts.Client().Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content type = %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "mcp_uptime_seconds") {
		t.Errorf("metrics output looks empty:\n%s", body)
	}
}

func TestMetricsCanRequireItsOwnToken(t *testing.T) {
	// A scraper should not hold a credential that can read customer data, and
	// an MCP client should not be able to read the server's internals.
	cfg := testutil.Config(config.TransportHTTP)
	cfg.HTTP.MetricsToken = "metrics-token"
	ts := newFullServer(t, cfg)

	resp, err := ts.Client().Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated /metrics = %d, want 401", resp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer metrics-token")
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /metrics with a token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("authenticated /metrics = %d, want 200", resp.StatusCode)
	}
}

func TestSecurityHeadersAreSet(t *testing.T) {
	ts := newFullServer(t, testutil.Config(config.TransportHTTP))

	resp, err := ts.Client().Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
		"Cache-Control":          "no-store",
	}
	for header, value := range want {
		if got := resp.Header.Get(header); got != value {
			t.Errorf("%s = %q, want %q", header, got, value)
		}
	}
	// HSTS is meaningless on a plaintext response and misleading in a config
	// review, so it is only sent over TLS.
	if got := resp.Header.Get("Strict-Transport-Security"); got != "" {
		t.Errorf("Strict-Transport-Security = %q on a plaintext response", got)
	}
}

func TestOversizedRequestBodyIsRefused(t *testing.T) {
	cfg := testutil.Config(config.TransportHTTP)
	cfg.HTTP.MaxRequestBytes = 4096
	ts := newHTTPServer(t, cfg)

	huge := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_customer","arguments":{"customer_id":"` +
		strings.Repeat("a", 64*1024) + `"}}}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(huge))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", resp.StatusCode)
	}
}

func TestRequestIDIsEchoedForCorrelation(t *testing.T) {
	ts := newHTTPServer(t, testutil.Config(config.TransportHTTP))

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("X-Request-Id", "trace-me-123")

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	// A caller has to be able to quote an id in a support request and have it
	// match what the server logged.
	if got := resp.Header.Get("X-Request-Id"); got != "trace-me-123" {
		t.Errorf("X-Request-Id = %q, want the caller's own", got)
	}
}

func TestForgedClientIPHeaderIsStripped(t *testing.T) {
	// The client address travels to the MCP layer as a header, because the SDK
	// exposes headers rather than the connection. A caller supplying its own
	// value would escape per-IP rate limiting and falsify every audit record,
	// so the wrapper deletes any inbound value before setting its own.
	cfg := testutil.Config(config.TransportHTTP)
	ts := newHTTPServer(t, cfg)

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("X-Mcp-Client-Ip", "1.2.3.4")
	req.Header.Set("X-Forwarded-For", "9.9.9.9")

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	// The request still succeeds - forging the header is ineffective, not
	// fatal - which is the behaviour a proxy misconfiguration needs.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestUnknownPathIsNotFound(t *testing.T) {
	ts := newFullServer(t, testutil.Config(config.TransportHTTP))

	resp, err := ts.Client().Get(ts.URL + "/admin")
	if err != nil {
		t.Fatalf("GET /admin: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestUnauthorizedCarriesAChallenge(t *testing.T) {
	// RFC 9110 requires a WWW-Authenticate header on a 401, and a
	// spec-compliant MCP client uses it to discover how to authenticate. A 401
	// with no challenge reads as "this endpoint is broken" rather than "you
	// need a credential".
	cfg := testutil.Config(config.TransportHTTP)
	cfg.Auth.Mode = config.AuthStatic
	cfg.Auth.StaticToken = "a-token-of-sufficient-length"
	ts := newHTTPServer(t, cfg)

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); !strings.HasPrefix(got, "Bearer") {
		t.Errorf("WWW-Authenticate = %q, want a Bearer challenge", got)
	}
}

func TestChallengeDoesNotOverrideResourceMetadata(t *testing.T) {
	// When the richer RFC 9728 challenge is available it must win: it tells the
	// client where the authorization server is, which the fallback cannot.
	cfg := testutil.Config(config.TransportHTTP)
	cfg.Auth.Mode = config.AuthStatic
	cfg.Auth.StaticToken = "a-token-of-sufficient-length"
	cfg.Auth.ResourceMetadataURL = "https://mcp.example.com/.well-known/oauth-protected-resource"
	ts := newHTTPServer(t, cfg)

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("WWW-Authenticate"); !strings.Contains(got, "resource_metadata") {
		t.Errorf("WWW-Authenticate = %q, want the resource-metadata pointer", got)
	}
}

func TestCrossOriginRequestIsRejected(t *testing.T) {
	// The threat is a malicious web page driving a locally running MCP server
	// with the user's ambient credentials. There is no wildcard allowlist, so
	// the default is same-origin only.
	ts := newHTTPServer(t, testutil.Config(config.TransportHTTP))

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Origin", "https://evil.example")

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d for a foreign Origin, want 403", resp.StatusCode)
	}
}

func TestDNSRebindingIsRejected(t *testing.T) {
	// A loopback request whose Host header names another site is the DNS
	// rebinding shape: the browser resolved an attacker domain to 127.0.0.1.
	ts := newHTTPServer(t, testutil.Config(config.TransportHTTP))

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Host = "attacker.example"

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d for a non-localhost Host on a loopback request, want 403", resp.StatusCode)
	}
}

func TestAllowedOriginIsAccepted(t *testing.T) {
	// An operator who does serve a browser client names the origin explicitly.
	cfg := testutil.Config(config.TransportHTTP)
	cfg.HTTP.AllowedOrigins = []string{"https://console.example.com"}
	ts := newHTTPServer(t, cfg)

	req, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Origin", "https://console.example.com")

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d for an allowlisted origin, want 200", resp.StatusCode)
	}
}

func TestRootIsASignpostNotADeadEnd(t *testing.T) {
	// The first thing anyone does after starting the server is open the
	// address in a browser. A bare "404 page not found" there, followed by a
	// cryptic 400 from /mcp about a missing session header, is a wall. The
	// index turns it into directions.
	ts := newFullServer(t, testutil.Config(config.TransportHTTP))

	resp, err := ts.Client().Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var body struct {
		Service   string `json:"service"`
		Hint      string `json:"hint"`
		Error     string `json:"error"`
		Endpoints []struct {
			Path string `json:"path"`
		} `json:"endpoints"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	paths := map[string]bool{}
	for _, e := range body.Endpoints {
		paths[e.Path] = true
	}
	for _, want := range []string{"/mcp", "/healthz", "/readyz", "/metrics"} {
		if !paths[want] {
			t.Errorf("the index does not list %q", want)
		}
	}
	if !strings.Contains(body.Hint, "not a website") {
		t.Errorf("hint = %q, want it to say MCP is not browsable", body.Hint)
	}
	if body.Error != "" {
		t.Errorf("the root carries an error field: %q", body.Error)
	}
}

func TestUnknownPathGetsDirectionsAnd404(t *testing.T) {
	ts := newFullServer(t, testutil.Config(config.TransportHTTP))

	resp, err := ts.Client().Get(ts.URL + "/admin")
	if err != nil {
		t.Fatalf("GET /admin: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	var body struct {
		Error     string `json:"error"`
		Endpoints []struct {
			Path string `json:"path"`
		} `json:"endpoints"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(body.Error, "/admin") {
		t.Errorf("error = %q, want it to name the path that was not found", body.Error)
	}
	// A wrong path is exactly when knowing the right ones helps.
	if len(body.Endpoints) == 0 {
		t.Error("a 404 carries no directions")
	}
}

func TestIndexDisclosesNothingOperational(t *testing.T) {
	// Paths are already in the configuration, the docs and the 401 challenge,
	// so listing them costs nothing. Whether authentication is on, which
	// backend is in use, or what the tenant is are a different matter: they
	// help someone decide whether this host is worth attacking.
	cfg := testutil.Config(config.TransportHTTP)
	cfg.Auth.Mode = config.AuthStatic
	cfg.Auth.StaticToken = "a-token-of-sufficient-length"
	cfg.Auth.LocalTenant = "acme-secret-tenant"
	ts := newFullServer(t, cfg)

	resp, err := ts.Client().Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()

	payload, _ := io.ReadAll(resp.Body)
	for _, leak := range []string{
		"a-token-of-sufficient-length", "acme-secret-tenant",
		"static", "auth_mode", "memory", "backend", "cursor",
	} {
		if strings.Contains(strings.ToLower(string(payload)), strings.ToLower(leak)) {
			t.Errorf("the index discloses %q: %s", leak, payload)
		}
	}
}

func TestUnknownPathsShareOneMetricLabel(t *testing.T) {
	// The catch-all route makes the request path caller-controlled. Using it
	// as a metric label directly would let anyone create unbounded time series
	// by requesting /a, /b, /c - which is how a metrics backend is brought
	// down by a trivial script.
	ts := newFullServer(t, testutil.Config(config.TransportHTTP))

	for _, p := range []string{"/aaa", "/bbb", "/ccc", "/ddd/eee", "/../etc/passwd"} {
		resp, err := ts.Client().Get(ts.URL + p)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		resp.Body.Close()
	}

	resp, err := ts.Client().Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(resp.Body)

	for _, p := range []string{"aaa", "bbb", "ccc", "ddd"} {
		if strings.Contains(string(payload), p) {
			t.Errorf("metric labels contain the caller-supplied path %q; cardinality is unbounded", p)
		}
	}
	if !strings.Contains(string(payload), `path="other"`) {
		t.Errorf("unknown paths were not collapsed onto a single label:\n%s", payload)
	}
}

func TestMethodNameMistakenForAPathIsExplained(t *testing.T) {
	// The wrong turn almost everyone takes: reading a method name out of the
	// docs or a log line and requesting it as a URL. "no such endpoint" is
	// true and useless there.
	ts := newFullServer(t, testutil.Config(config.TransportHTTP))

	for _, path := range []string{"/tools/list", "/tools/call", "/resources/read", "/prompts/get", "/initialize"} {
		t.Run(path, func(t *testing.T) {
			resp, err := ts.Client().Get(ts.URL + path)
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("status = %d, want 404", resp.StatusCode)
			}
			var body struct {
				Hint string `json:"hint"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatalf("decode: %v", err)
			}
			method := strings.Trim(path, "/")
			if !strings.Contains(body.Hint, "JSON-RPC method, not a URL path") {
				t.Errorf("hint = %q, want it to name the mistake", body.Hint)
			}
			if !strings.Contains(body.Hint, method) {
				t.Errorf("hint = %q, want it to quote the method %q", body.Hint, method)
			}
			// The hint has to carry the request that actually works, or it
			// diagnoses without helping.
			if !strings.Contains(body.Hint, `"jsonrpc":"2.0"`) || !strings.Contains(body.Hint, "/mcp") {
				t.Errorf("hint = %q, want a usable request shape", body.Hint)
			}
		})
	}
}

func TestOrdinaryWrongPathKeepsTheGenericHint(t *testing.T) {
	// Only a real method name gets the tailored hint; anything else keeps the
	// general one, so the specific advice stays trustworthy.
	ts := newFullServer(t, testutil.Config(config.TransportHTTP))

	resp, err := ts.Client().Get(ts.URL + "/tools/nonsense")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	var body struct {
		Hint  string `json:"hint"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if strings.Contains(body.Hint, "JSON-RPC method") {
		t.Errorf("hint = %q; /tools/nonsense is not a method name", body.Hint)
	}
	if !strings.Contains(body.Hint, "not a website") {
		t.Errorf("hint = %q, want the general hint", body.Hint)
	}
}

func TestMethodPathsStillShareTheOtherMetricLabel(t *testing.T) {
	// The tailored hint must not have introduced a new label value: the path is
	// still caller-controlled, and the closed set lives in the code, not in the
	// metric.
	ts := newFullServer(t, testutil.Config(config.TransportHTTP))

	for _, p := range []string{"/tools/list", "/prompts/get", "/initialize"} {
		resp, err := ts.Client().Get(ts.URL + p)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		resp.Body.Close()
	}

	resp, err := ts.Client().Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(resp.Body)

	for _, p := range []string{`path="/tools/list"`, `path="/prompts/get"`, `path="/initialize"`} {
		if strings.Contains(string(payload), p) {
			t.Errorf("metrics carry a caller-controlled label %s", p)
		}
	}
}
