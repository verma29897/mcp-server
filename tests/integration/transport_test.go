package integration_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/verma29897/mcp-server/internal/config"
	"github.com/verma29897/mcp-server/internal/domain"
	appmcp "github.com/verma29897/mcp-server/internal/mcp"
	"github.com/verma29897/mcp-server/tests/testutil"
)

// The point of these tests is the invariant in the brief: tool, resource and
// prompt registration is independent of transport, so a client sees exactly the
// same capability set over stdio and over Streamable HTTP.

// surface is the feature set a client can discover, in a comparable form.
type surface struct {
	tools     []string
	resources []string
	templates []string
	prompts   []string
}

func discover(t *testing.T, cs *sdk.ClientSession) surface {
	t.Helper()
	ctx := context.Background()

	var s surface

	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	for _, tool := range tools.Tools {
		s.tools = append(s.tools, tool.Name)
	}

	res, err := cs.ListResources(ctx, nil)
	if err != nil {
		t.Fatalf("resources/list: %v", err)
	}
	for _, r := range res.Resources {
		s.resources = append(s.resources, r.URI)
	}

	tmpl, err := cs.ListResourceTemplates(ctx, nil)
	if err != nil {
		t.Fatalf("resources/templates/list: %v", err)
	}
	for _, r := range tmpl.ResourceTemplates {
		s.templates = append(s.templates, r.URITemplate)
	}

	pr, err := cs.ListPrompts(ctx, nil)
	if err != nil {
		t.Fatalf("prompts/list: %v", err)
	}
	for _, p := range pr.Prompts {
		s.prompts = append(s.prompts, p.Name)
	}

	sort.Strings(s.tools)
	sort.Strings(s.resources)
	sort.Strings(s.templates)
	sort.Strings(s.prompts)
	return s
}

func (s surface) String() string {
	return "tools=" + strings.Join(s.tools, ",") +
		" resources=" + strings.Join(s.resources, ",") +
		" templates=" + strings.Join(s.templates, ",") +
		" prompts=" + strings.Join(s.prompts, ",")
}

// newHTTPServer starts the Streamable HTTP handler on a test server.
func newHTTPServer(t *testing.T, cfg *config.Config) *httptest.Server {
	ts, _ := newHTTPServerWithAudit(t, cfg)
	return ts
}

// newHTTPServerWithAudit is newHTTPServer plus the captured audit records.
func newHTTPServerWithAudit(t *testing.T, cfg *config.Config) (*httptest.Server, *testutil.AuditRecorder) {
	t.Helper()

	svc, _ := testutil.NewService()
	deps, recorder := testutil.Deps(cfg)
	srv, err := appmcp.New(cfg, svc, testutil.Logger(), deps)
	if err != nil {
		t.Fatalf("create MCP server: %v", err)
	}

	// The same handler the production path mounts, wrapper chain included: the
	// chain is where the transport-level security lives, so a test that
	// bypassed it would be testing a different server.
	ts := httptest.NewServer(srv.HTTPHandler())
	t.Cleanup(ts.Close)
	return ts, recorder
}

// newUnreadyServer mounts the complete mux with a backend that is unreachable,
// so the readiness and liveness probes can be told apart.
func newUnreadyServer(t *testing.T, cfg *config.Config) *httptest.Server {
	t.Helper()

	svc, be := testutil.NewService()
	be.PingFn = func(context.Context) error {
		return domain.Backend("ping", errors.New("dial tcp 10.0.0.5:5432: password=hunter2 refused"))
	}
	deps, _ := testutil.Deps(cfg)
	deps.Ready = svc.Health
	srv, err := appmcp.New(cfg, svc, testutil.Logger(), deps)
	if err != nil {
		t.Fatalf("create MCP server: %v", err)
	}
	ts := httptest.NewServer(srv.Mux())
	t.Cleanup(ts.Close)
	return ts
}

// newFullServer mounts the complete mux, including the operational endpoints.
func newFullServer(t *testing.T, cfg *config.Config) *httptest.Server {
	t.Helper()

	svc, _ := testutil.NewService()
	deps, _ := testutil.Deps(cfg)
	deps.Ready = svc.Health
	srv, err := appmcp.New(cfg, svc, testutil.Logger(), deps)
	if err != nil {
		t.Fatalf("create MCP server: %v", err)
	}
	ts := httptest.NewServer(srv.Mux())
	t.Cleanup(ts.Close)
	return ts
}

func connectHTTP(t *testing.T, endpoint string, client *http.Client) *sdk.ClientSession {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	c := sdk.NewClient(&sdk.Implementation{Name: "http-test-client", Version: "1.0.0"}, nil)
	cs, err := c.Connect(ctx, &sdk.StreamableClientTransport{
		Endpoint:   endpoint,
		HTTPClient: client,
	}, nil)
	if err != nil {
		t.Fatalf("connect over streamable HTTP: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func TestStreamableHTTPTransport(t *testing.T) {
	ts := newHTTPServer(t, testutil.Config(config.TransportHTTP))
	cs := connectHTTP(t, ts.URL, ts.Client())

	if got := cs.InitializeResult().ServerInfo.Name; got != "test-mcp-server" {
		t.Errorf("server name over HTTP = %q, want %q", got, "test-mcp-server")
	}

	res, err := cs.CallTool(context.Background(), &sdk.CallToolParams{
		Name:      "get_customer",
		Arguments: map[string]any{"customer_id": "1001"},
	})
	if err != nil {
		t.Fatalf("tools/call over HTTP: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool error over HTTP: %s", contentText(res))
	}
}

func TestStreamableHTTPStatelessMode(t *testing.T) {
	cfg := testutil.Config(config.TransportHTTP)
	// Stateless mode is what a horizontally scaled deployment behind a load
	// balancer without sticky sessions needs.
	cfg.HTTP.Stateless = true

	ts := newHTTPServer(t, cfg)
	cs := connectHTTP(t, ts.URL, ts.Client())

	res, err := cs.CallTool(context.Background(), &sdk.CallToolParams{
		Name:      "search_customers",
		Arguments: map[string]any{"query": "acme"},
	})
	if err != nil {
		t.Fatalf("tools/call in stateless mode: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool error in stateless mode: %s", contentText(res))
	}
}

func TestStreamableHTTPRequiresBearerToken(t *testing.T) {
	cfg := testutil.Config(config.TransportHTTP)
	cfg.Auth.Mode = config.AuthStatic
	cfg.Auth.StaticToken = "s3cret-token-long-enough"

	ts, audit := newHTTPServerWithAudit(t, cfg)

	post := func(auth string) int {
		req, err := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(
			`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`))
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatalf("do request: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	tests := []struct {
		name string
		auth string
		want int
	}{
		{"no header", "", http.StatusUnauthorized},
		{"wrong scheme", "Basic s3cret-token-long-enough", http.StatusUnauthorized},
		{"wrong token", "Bearer wrong", http.StatusUnauthorized},
		{"prefix of the token", "Bearer s3cret", http.StatusUnauthorized},
		{"correct token", "Bearer s3cret-token-long-enough", http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := post(tc.auth); got != tc.want {
				t.Errorf("status = %d, want %d", got, tc.want)
			}
		})
	}

	// A rejected credential has to leave a record, or the most interesting
	// event in the log - repeated failures from one source - is invisible.
	if audit.Find("auth.failure") == nil {
		t.Error("no auth.failure audit record for the rejected credentials")
	}
	if audit.Find("auth.success") == nil {
		t.Error("no auth.success audit record for the accepted credential")
	}
	// And it must not leave the credential itself.
	if strings.Contains(audit.Raw(), "s3cret-token-long-enough") {
		t.Error("the audit log contains the bearer token")
	}
}

func TestStdioTransport(t *testing.T) {
	bin := buildServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(),
		"MCP_TRANSPORT=stdio",
		"BACKEND_MODE=memory",
		"MCP_SERVER_NAME=test-mcp-server",
		"MCP_SERVER_VERSION=0.0.0-test",
		"LOG_LEVEL=error",
	)
	// The child's stderr is separate from its protocol stream; surface it so a
	// failure here is diagnosable.
	cmd.Stderr = os.Stderr

	client := sdk.NewClient(&sdk.Implementation{Name: "stdio-test-client", Version: "1.0.0"}, nil)
	cs, err := client.Connect(ctx, &sdk.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connect over stdio: %v", err)
	}
	defer cs.Close()

	if got := cs.InitializeResult().ServerInfo.Name; got != "test-mcp-server" {
		t.Errorf("server name over stdio = %q, want %q", got, "test-mcp-server")
	}

	res, err := cs.CallTool(ctx, &sdk.CallToolParams{
		Name:      "get_customer",
		Arguments: map[string]any{"customer_id": "1001"},
	})
	if err != nil {
		t.Fatalf("tools/call over stdio: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool error over stdio: %s", contentText(res))
	}
	if !strings.Contains(contentText(res), "Acme Industries") {
		t.Errorf("unexpected result over stdio: %s", contentText(res))
	}
}

func TestSameSurfaceOverBothTransports(t *testing.T) {
	// stdio.
	bin := buildServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(), "MCP_TRANSPORT=stdio", "BACKEND_MODE=memory", "LOG_LEVEL=error")
	cmd.Stderr = os.Stderr

	stdioClient := sdk.NewClient(&sdk.Implementation{Name: "surface-stdio", Version: "1.0.0"}, nil)
	stdioSession, err := stdioClient.Connect(ctx, &sdk.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connect over stdio: %v", err)
	}
	defer stdioSession.Close()

	// Streamable HTTP.
	ts := newHTTPServer(t, testutil.Config(config.TransportHTTP))
	httpSession := connectHTTP(t, ts.URL, ts.Client())

	stdio := discover(t, stdioSession)
	over := discover(t, httpSession)

	if stdio.String() != over.String() {
		t.Errorf("transports expose different feature sets:\n stdio: %s\n  http: %s", stdio, over)
	}
	if len(stdio.tools) != 6 || len(stdio.resources) != 1 || len(stdio.templates) != 3 || len(stdio.prompts) != 2 {
		t.Errorf("unexpected feature counts: %s", stdio)
	}
}

func TestHTTPServeShutsDownGracefully(t *testing.T) {
	// Reserve an ephemeral port first, so the test knows where to connect.
	addr := freePort(t)
	cfg := testutil.Config(config.TransportHTTP)
	cfg.HTTP.Addr = addr

	svc, _ := testutil.NewService()
	deps, _ := testutil.Deps(cfg)
	deps.Ready = svc.Health
	srv, err := appmcp.New(cfg, svc, testutil.Logger(), deps)
	if err != nil {
		t.Fatalf("create MCP server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var (
		wg       sync.WaitGroup
		serveErr error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		serveErr = srv.ServeHTTP(ctx)
	}()

	// Wait for the listener to accept.
	if !waitForHealth(t, "http://"+addr+"/healthz") {
		cancel()
		wg.Wait()
		t.Fatal("server never became healthy")
	}

	cancel()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("ServeHTTP did not return after context cancellation")
	}
	if serveErr != nil {
		t.Errorf("graceful shutdown returned an error: %v", serveErr)
	}
}

// --- helpers ---

var (
	buildOnce sync.Once
	buildPath string
	buildErr  error
)

// buildServer compiles cmd/server once per test binary and returns its path.
func buildServer(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping: building the server binary is too slow for -short")
	}

	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "mcp-server-build")
		if err != nil {
			buildErr = err
			return
		}
		out := filepath.Join(dir, "mcp-server")
		if runtime.GOOS == "windows" {
			out += ".exe"
		}
		cmd := exec.Command("go", "build", "-o", out, "./cmd/server")
		cmd.Dir = moduleRoot(t)
		if output, err := cmd.CombinedOutput(); err != nil {
			buildErr = &buildFailure{err: err, output: string(output)}
			return
		}
		buildPath = out
	})
	if buildErr != nil {
		t.Fatalf("build server binary: %v", buildErr)
	}
	return buildPath
}

type buildFailure struct {
	err    error
	output string
}

func (b *buildFailure) Error() string { return b.err.Error() + ": " + b.output }

// moduleRoot returns the repository root, two levels up from tests/integration.
func moduleRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

// freePort reserves and immediately releases a port, returning its address.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// waitForHealth polls the health endpoint until it answers or times out.
func waitForHealth(t *testing.T, url string) bool {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return true
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}
