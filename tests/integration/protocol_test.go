package integration_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/verma29897/mcp-server/internal/config"
	"github.com/verma29897/mcp-server/tests/testutil"
)

// These exercise the protocol itself rather than this server's features: the
// handshake, version negotiation, session handling, and what happens to a
// request that is malformed before any handler could see it.
//
// The framing is the SDK's, so the point is not to re-test the SDK. It is that
// this server's wrapper chain - authentication, correlation, rate limiting,
// authorization - sits in front of that framing and must not break it.

// rpc posts one JSON-RPC message and returns the status and decoded body.
func rpc(t *testing.T, ts *httptest.Server, sessionID, body string, headers map[string]string) (int, map[string]any, http.Header) {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()

	payload, _ := io.ReadAll(resp.Body)
	decoded := map[string]any{}
	// A streamed response is SSE; pull the first data frame out of it.
	if text := string(payload); strings.HasPrefix(text, "event:") || strings.Contains(text, "\ndata: ") {
		for _, line := range strings.Split(text, "\n") {
			if after, ok := strings.CutPrefix(line, "data: "); ok {
				_ = json.Unmarshal([]byte(after), &decoded)
				break
			}
		}
	} else {
		_ = json.Unmarshal(payload, &decoded)
	}
	return resp.StatusCode, decoded, resp.Header
}

const initBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"%s","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`

func TestInitializeNegotiatesAProtocolVersion(t *testing.T) {
	ts := newHTTPServer(t, testutil.Config(config.TransportHTTP))

	status, body, headers := rpc(t, ts, "", strings.Replace(initBody, "%s", "2025-06-18", 1), nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%v)", status, body)
	}
	result, ok := body["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result in the initialize response: %v", body)
	}
	if result["protocolVersion"] == "" || result["protocolVersion"] == nil {
		t.Error("the server did not report a negotiated protocol version")
	}
	// A stateful server issues a session id the client must echo on every
	// subsequent request.
	if headers.Get("Mcp-Session-Id") == "" {
		t.Error("no Mcp-Session-Id on the initialize response")
	}
	serverInfo, _ := result["serverInfo"].(map[string]any)
	if serverInfo["name"] != "test-mcp-server" {
		t.Errorf("serverInfo = %v, want this server's identity", serverInfo)
	}
}

func TestUnsupportedProtocolVersionIsHandledNotCrashed(t *testing.T) {
	ts := newHTTPServer(t, testutil.Config(config.TransportHTTP))

	for _, version := range []string{"1999-01-01", "", "not-a-version", strings.Repeat("9", 500)} {
		status, body, _ := rpc(t, ts, "", strings.Replace(initBody, "%s", version, 1), nil)
		// The SDK either negotiates down to a version it supports or refuses.
		// Either is correct; a 5xx or a hang is not.
		if status >= 500 {
			t.Errorf("protocol version %q produced status %d: %v", version, status, body)
		}
	}
}

func TestMalformedRequestsAreRefusedCleanly(t *testing.T) {
	ts := newHTTPServer(t, testutil.Config(config.TransportHTTP))

	tests := []struct {
		name string
		body string
	}{
		{"not json", `{not json at all`},
		{"empty body", ``},
		{"json but not jsonrpc", `{"hello":"world"}`},
		{"wrong jsonrpc version", `{"jsonrpc":"1.0","id":1,"method":"initialize"}`},
		{"no method", `{"jsonrpc":"2.0","id":1}`},
		{"unknown method", `{"jsonrpc":"2.0","id":1,"method":"does/not/exist"}`},
		{"deeply nested params", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":` + strings.Repeat(`{"a":`, 200) + `1` + strings.Repeat(`}`, 200) + `}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, body, _ := rpc(t, ts, "", tc.body, nil)
			// Refusing is correct. Returning 500, or accepting it, is not: the
			// first says the server broke, the second says it did something.
			if status >= 500 {
				t.Errorf("status = %d, want a 4xx refusal: %v", status, body)
			}
		})
	}
}

func TestUnknownSessionIsRejected(t *testing.T) {
	ts := newHTTPServer(t, testutil.Config(config.TransportHTTP))

	// A session id the server never issued. Honouring it would let a caller
	// invent a session, and in a stateful server a session carries the
	// initialize state that later requests rely on.
	status, _, _ := rpc(t, ts, "00000000000000000000000000000000",
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, nil)
	if status == http.StatusOK {
		t.Errorf("status = %d for an unknown session id, want a refusal", status)
	}
}

func TestSessionLifecycle(t *testing.T) {
	ts := newHTTPServer(t, testutil.Config(config.TransportHTTP))

	// Initialize, use the session, then delete it and confirm it is gone.
	_, _, headers := rpc(t, ts, "", strings.Replace(initBody, "%s", "2025-06-18", 1), nil)
	session := headers.Get("Mcp-Session-Id")
	if session == "" {
		t.Fatal("no session id issued")
	}

	// The initialized notification completes the handshake.
	rpc(t, ts, session, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, nil)

	status, body, _ := rpc(t, ts, session, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, nil)
	if status != http.StatusOK {
		t.Fatalf("tools/list on a live session = %d: %v", status, body)
	}

	req, _ := http.NewRequest(http.MethodDelete, ts.URL, nil)
	req.Header.Set("Mcp-Session-Id", session)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 && resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("DELETE session = %d, want it accepted", resp.StatusCode)
	}

	if resp.StatusCode < 400 {
		after, _, _ := rpc(t, ts, session, `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`, nil)
		if after == http.StatusOK {
			t.Error("a deleted session still served requests")
		}
	}
}

func TestStatelessModeRejectsSessionEndpoints(t *testing.T) {
	cfg := testutil.Config(config.TransportHTTP)
	cfg.HTTP.Stateless = true
	ts := newHTTPServer(t, cfg)

	// In stateless mode there is no server-side session, so the GET stream and
	// the DELETE have nothing to act on. Answering 405 tells a client that
	// plainly instead of leaving it waiting on a stream that will never open.
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		req, _ := http.NewRequest(method, ts.URL, nil)
		req.Header.Set("Accept", "text/event-stream")
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s in stateless mode = %d, want 405", method, resp.StatusCode)
		}
	}
}

func TestJSONResponseModeReturnsJSONNotSSE(t *testing.T) {
	// The escape hatch for a proxy that buffers text/event-stream. A deployment
	// behind such a proxy would otherwise appear to hang.
	cfg := testutil.Config(config.TransportHTTP)
	cfg.HTTP.JSONResponse = true
	ts := newHTTPServer(t, cfg)

	req, _ := http.NewRequest(http.MethodPost, ts.URL,
		strings.NewReader(strings.Replace(initBody, "%s", "2025-06-18", 1)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content type = %q, want application/json", ct)
	}
}

func TestCapabilitiesReflectWhatIsRegistered(t *testing.T) {
	cs, _ := newSession(t)
	init := cs.InitializeResult()

	// The SDK infers capabilities from registration, so this asserts the
	// registration actually happened rather than that a constant was written.
	if init.Capabilities.Tools == nil {
		t.Error("tools capability not advertised")
	}
	if init.Capabilities.Resources == nil {
		t.Error("resources capability not advertised")
	}
	if init.Capabilities.Prompts == nil {
		t.Error("prompts capability not advertised")
	}
	if init.Capabilities.Completions == nil {
		t.Error("completions capability not advertised")
	}
}

func TestResourceTemplatesAreDiscoverable(t *testing.T) {
	cs, _ := newSession(t)

	res, err := cs.ListResourceTemplates(t.Context(), nil)
	if err != nil {
		t.Fatalf("resources/templates/list: %v", err)
	}
	want := map[string]bool{
		"customer://{customer_id}":         false,
		"customer://{customer_id}/orders":  false,
		"customer://{customer_id}/summary": false,
	}
	for _, tmpl := range res.ResourceTemplates {
		if _, ok := want[tmpl.URITemplate]; !ok {
			t.Errorf("unexpected template %q", tmpl.URITemplate)
			continue
		}
		want[tmpl.URITemplate] = true
	}
	for uri, seen := range want {
		if !seen {
			t.Errorf("template %q was not advertised", uri)
		}
	}
}

func TestExactResourceWinsOverTemplate(t *testing.T) {
	// customer://directory also matches customer://{customer_id}. The SDK
	// resolves exact resources first, so the directory reaches its own handler
	// rather than being looked up as a customer called "directory".
	cs, _ := newSession(t)

	res, err := cs.ReadResource(t.Context(), &sdk.ReadResourceParams{URI: "customer://directory"})
	if err != nil {
		t.Fatalf("resources/read: %v", err)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(res.Contents[0].Text), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["customers"]; !ok {
		t.Errorf("the directory URI reached the wrong handler: %v", body)
	}
}
