package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/verma29897/mcp-server/internal/config"
	"github.com/verma29897/mcp-server/internal/observability"
)

// Transport selection happens here and nowhere else.
//
// Everything registered on the server - tools, resources, prompts - is
// identical across both transports, because registration completed in New()
// before either of these functions is called. A client on stdio and a client on
// Streamable HTTP see exactly the same capability set, subject to the same
// authorization.

// Serve runs the server on the transport named in the configuration and blocks
// until ctx is cancelled or the transport stops.
func (s *Server) Serve(ctx context.Context) error {
	switch s.cfg.Transport {
	case config.TransportStdio:
		return s.ServeStdio(ctx)
	case config.TransportHTTP:
		return s.ServeHTTP(ctx)
	default:
		return fmt.Errorf("mcp: unsupported transport %q", s.cfg.Transport)
	}
}

// ServeStdio runs a single MCP session over stdin/stdout.
//
// This is what Claude Desktop and the MCP Inspector launch. The process owns
// one session for its lifetime, so returning from Run means the client
// disconnected and there is nothing left to serve.
//
// stdout carries the JSON-RPC stream. Anything else written there corrupts the
// protocol, which is why the logger in cmd/server writes to stderr.
func (s *Server) ServeStdio(ctx context.Context) error {
	s.logger.Info("serving MCP over stdio transport")

	// Run connects the transport, serves the session, and returns when the
	// session ends or ctx is cancelled - at which point it closes the session
	// and waits for the in-flight handler to finish. That is the graceful
	// shutdown path for stdio.
	err := s.sdk.Run(ctx, &sdk.StdioTransport{})

	switch {
	case err == nil:
		s.logger.Info("stdio session ended")
		return nil
	case errors.Is(err, context.Canceled):
		// A cancelled context is the shutdown signal, not a failure.
		s.logger.Info("stdio transport shut down")
		return nil
	case isPeerDisconnect(err):
		// The client closed stdin. That is how a normal stdio disconnect
		// looks - Claude Desktop quitting, or the Inspector detaching - so it
		// must exit zero rather than be reported as a crash.
		s.logger.Info("stdio client disconnected")
		return nil
	default:
		return fmt.Errorf("stdio transport: %w", err)
	}
}

// codeServerClosing is the JSON-RPC code the SDK's transport layer reports when
// the connection is torn down because the peer went away. Reaching stdin EOF
// surfaces as this code wrapping io.EOF, but the EOF is formatted into the
// message rather than wrapped, so the code is the part that can be matched.
const codeServerClosing = -32004

// isPeerDisconnect reports whether err is an ordinary client disconnect rather
// than a transport failure.
func isPeerDisconnect(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, sdk.ErrConnectionClosed) ||
		errors.Is(err, &jsonrpc.Error{Code: codeServerClosing})
}

// ServeHTTP runs the Streamable HTTP transport until ctx is cancelled.
//
// One handler serves many concurrent sessions, so shutdown is a two-step
// affair: stop accepting new connections, then give in-flight requests a bounded
// window to finish.
func (s *Server) ServeHTTP(ctx context.Context) error {
	httpSrv := &http.Server{
		Addr:              s.cfg.HTTP.Addr,
		Handler:           s.Mux(),
		ReadHeaderTimeout: s.cfg.HTTP.ReadHeaderTimeout,
		IdleTimeout:       s.cfg.HTTP.IdleTimeout,
		MaxHeaderBytes:    s.cfg.HTTP.MaxHeaderBytes,
		// No WriteTimeout: a streamable session holds a long-lived SSE
		// response, and a write deadline would sever it mid-stream. The
		// per-request budget comes from ReadHeaderTimeout, the SDK's session
		// timeout and the backend's own deadlines instead.
		BaseContext: func(net.Listener) context.Context { return ctx },
		ErrorLog:    nil,
	}

	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("serving MCP over streamable HTTP transport",
			"addr", s.cfg.HTTP.Addr,
			"path", s.cfg.HTTP.Path,
			"stateless", s.cfg.HTTP.Stateless,
			"auth_mode", string(s.cfg.Auth.Mode),
			"metrics_path", s.cfg.HTTP.MetricsPath,
		)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("http transport: %w", err)
		}
		return nil
	case <-ctx.Done():
		s.logger.Info("shutting down HTTP transport", "timeout", s.cfg.HTTP.ShutdownTimeout)

		// Shutdown must not inherit the already-cancelled ctx, or in-flight
		// requests would be cut off instead of being allowed to drain.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.HTTP.ShutdownTimeout)
		defer cancel()

		if err := httpSrv.Shutdown(shutdownCtx); err != nil {
			s.logger.Error("graceful shutdown timed out; closing connections", "error", err)
			_ = httpSrv.Close()
			return fmt.Errorf("http shutdown: %w", err)
		}
		<-errCh
		s.logger.Info("HTTP transport shut down cleanly")
		return nil
	}
}

// Mux returns the full HTTP surface: the MCP endpoint plus the operational
// endpoints.
//
// The operational endpoints sit outside the MCP path deliberately. A load
// balancer must be able to probe liveness without opening an MCP session, and a
// scraper must be able to read metrics without holding a credential that can
// read customer data.
func (s *Server) Mux() http.Handler {
	mux := http.NewServeMux()
	mux.Handle(s.cfg.HTTP.Path, s.HTTPHandler())

	// Liveness: is this process running? It must not touch a dependency. A
	// liveness probe that fails when the backend is down gets the pod killed
	// and restarted, which fixes nothing and removes the capacity that would
	// have served the requests that do not need the backend.
	mux.Handle("GET /healthz", s.operational(s.healthHandler()))

	// Readiness: should this replica receive traffic? This one does check the
	// backend, because a replica that cannot reach it should be taken out of
	// the load balancer rather than answering every request with an error.
	mux.Handle("GET /readyz", s.operational(s.readyHandler()))

	if s.cfg.HTTP.MetricsPath != "" {
		mux.Handle("GET "+s.cfg.HTTP.MetricsPath, s.operational(s.metricsHandler()))
	}

	// A signpost at "/" and on any unmatched path.
	//
	// Without it, the first thing anyone does after starting the server -
	// open the address in a browser - is a bare "404 page not found", and the
	// second thing is a 400 from /mcp saying a session header is missing.
	// Both are correct and neither explains that MCP is not browsable. The
	// index says so, and names the paths that are.
	//
	// It discloses nothing: these paths are already in the configuration, the
	// documentation and the 401 challenge. It deliberately does not report
	// whether authentication is on, which backend is in use, or anything else
	// that would help someone decide whether this host is worth attacking.
	mux.Handle("/", s.operational(s.indexHandler()))
	return mux
}

// indexHandler serves the endpoint directory.
func (s *Server) indexHandler() http.Handler {
	type endpoint struct {
		Path        string `json:"path"`
		Methods     string `json:"methods"`
		Description string `json:"description"`
	}
	endpoints := []endpoint{
		{s.cfg.HTTP.Path, "POST, GET, DELETE", "MCP endpoint (JSON-RPC 2.0 over Streamable HTTP; not browsable)"},
		{"/healthz", "GET", "liveness: this process only"},
		{"/readyz", "GET", "readiness: this replica's required dependencies"},
	}
	if s.cfg.HTTP.MetricsPath != "" {
		endpoints = append(endpoints, endpoint{s.cfg.HTTP.MetricsPath, "GET", "Prometheus metrics"})
	}

	hint := "This is an MCP server, not a website. Connect an MCP client to " +
		s.cfg.HTTP.Path + " rather than opening it in a browser."

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Built per request rather than shared. A handler that mutated a
		// captured map would race between concurrent requests, and the "error"
		// key from one 404 would leak into the next request's 200.
		body := map[string]any{
			"service":   s.cfg.Identity.Name,
			"version":   s.cfg.Identity.Version,
			"protocol":  "Model Context Protocol",
			"endpoints": endpoints,
			"hint":      hint,
		}

		// ServeMux routes every unmatched path here, so anything but the root
		// is genuinely not found - but it still gets the directory, because a
		// wrong path is exactly when knowing the right ones helps.
		status := http.StatusOK
		if r.URL.Path != "/" {
			status = http.StatusNotFound
			// The path is echoed, so it is sanitised: it reaches a JSON body
			// and, through the operational wrapper, a metric label.
			clean := sanitizePath(r.URL.Path)
			body["error"] = "no such endpoint: " + clean

			// The specific wrong turn almost everyone takes: reading a method
			// name out of the docs or a log line and requesting it as a URL.
			// "no such endpoint" is true and useless there; naming the mistake
			// and showing the request that works is not.
			if method, ok := mcpMethodFromPath(clean); ok {
				body["hint"] = fmt.Sprintf(
					"%q is a JSON-RPC method, not a URL path. POST it to %s as "+
						`{"jsonrpc":"2.0","id":1,"method":%q} `+
						"after an initialize handshake, with "+
						"Accept: application/json, text/event-stream.",
					method, s.cfg.HTTP.Path, method)
			}
		}
		writeJSON(w, status, body)
	})
}

// HTTPHandler returns the MCP endpoint handler with the full wrapper chain.
//
// It is exported so tests (and an embedding process with its own router) can
// mount the same handler the production path uses - the chain is where most of
// the transport-level security lives, and a test that bypassed it would be
// testing a different server.
func (s *Server) HTTPHandler() http.Handler {
	// NewStreamableHTTPHandler implements the entire Streamable HTTP transport:
	// POST for messages, GET for the server-to-client SSE stream, DELETE to end
	// a session, plus Mcp-Session-Id handling and DNS-rebinding protection.
	// None of that framing is reimplemented here.
	var handler http.Handler = sdk.NewStreamableHTTPHandler(
		func(*http.Request) *sdk.Server { return s.sdk },
		&sdk.StreamableHTTPOptions{
			Stateless:      s.cfg.HTTP.Stateless,
			JSONResponse:   s.cfg.HTTP.JSONResponse,
			SessionTimeout: s.cfg.HTTP.SessionTimeout,
			Logger:         s.logger,
			// Bounded before anything is parsed, so an oversized body is
			// refused rather than buffered.
			MaxRequestBodyBytes: s.cfg.HTTP.MaxRequestBytes,
			// Tie the handler's context to the HTTP request's, so a client that
			// hangs up stops the work it asked for.
			PropagateRequestCancellation: true,
		},
	)

	// Innermost first: each wrapper below runs before the one above it.
	handler = s.httpAuth(handler)
	handler = s.challenge(handler)
	handler = s.clientContext(handler)
	handler = crossOrigin(s.cfg.HTTP.AllowedOrigins).Handler(handler)
	handler = s.securityHeaders(handler)
	return handler
}

// crossOrigin builds the browser cross-origin policy.
//
// The default is same-origin only, which is right for an MCP server: its
// clients are agents and desktop applications, not web pages. An operator who
// does serve a browser-based client names the origins explicitly; there is no
// wildcard, because a wildcard here would let any page on the internet drive
// this server with the user's ambient credentials.
func crossOrigin(allowed []string) *http.CrossOriginProtection {
	p := http.NewCrossOriginProtection()
	for _, origin := range allowed {
		if origin == "" || origin == "*" {
			// A wildcard is refused rather than honoured. Ignoring it fails
			// closed, which is the direction a misconfiguration should fail in.
			continue
		}
		// An unparseable origin is a configuration error, but refusing to start
		// over one would be worse than skipping it: skipping means the origin
		// is not trusted, which again fails closed.
		_ = p.AddTrustedOrigin(origin)
	}
	return p
}

// challenge guarantees a WWW-Authenticate header on every 401.
//
// RFC 9110 requires one, and a spec-compliant MCP client uses it to discover
// how to authenticate rather than guessing. The SDK's bearer middleware emits
// the header only when it has something to put in it - a resource-metadata URL
// or a required scope list - so a deployment with neither would answer 401 with
// no challenge at all, which reads to a client as "this endpoint is broken"
// rather than "you need a credential".
//
// A header the inner handler already set is left alone, so the richer RFC 9728
// challenge wins whenever it is available.
func (s *Server) challenge(next http.Handler) http.Handler {
	if s.verifier == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&challengeWriter{ResponseWriter: w}, r)
	})
}

// challengeWriter adds the fallback challenge as the status is written, which
// is the last moment the header block is still mutable.
type challengeWriter struct {
	http.ResponseWriter
	written bool
}

func (w *challengeWriter) WriteHeader(code int) {
	if !w.written {
		w.written = true
		if code == http.StatusUnauthorized && w.Header().Get("WWW-Authenticate") == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="mcp"`)
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *challengeWriter) Write(b []byte) (int, error) {
	// An implicit 200 still has to mark the header block as settled, or a later
	// WriteHeader would try to mutate headers that are already on the wire.
	w.written = true
	return w.ResponseWriter.Write(b)
}

// Flush forwards to the underlying writer, so wrapping cannot break SSE.
func (w *challengeWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// clientContext resolves the caller's address and stamps the correlation
// headers before the SDK sees the request.
//
// The client address has to travel as a header because the SDK hands a handler
// the header set, not the connection. Any inbound value is deleted first, so a
// caller cannot supply its own address and escape per-IP rate limiting or
// falsify an audit record.
func (s *Server) clientContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := s.clientIP(r)
		r.Header.Del(observability.HeaderClientIP)
		if ip != "" {
			r.Header.Set(observability.HeaderClientIP, ip)
		}

		rc := observability.FromHTTP(r)
		// Echo the correlation id so a caller can quote it in a support
		// request, and set it on the request so the MCP layer reuses the same
		// one rather than generating a second.
		r.Header.Set(observability.HeaderRequestID, rc.RequestID)
		w.Header().Set(observability.HeaderRequestID, rc.RequestID)

		next.ServeHTTP(w, r.WithContext(observability.NewContext(r.Context(), rc)))
	})
}

// securityHeaders sets the response headers that matter for a JSON API.
//
// Only the ones that do something here. An API that never returns HTML gains
// nothing from X-Frame-Options or a full CSP, and shipping headers that do not
// apply makes the ones that do harder to review:
//
//	Strict-Transport-Security  pins future requests to TLS
//	X-Content-Type-Options     stops a client sniffing JSON as something else
//	Referrer-Policy            keeps the URL out of a cross-origin referer
//	Cache-Control              keeps customer data out of intermediary caches
//	Content-Security-Policy    a minimal one, for the error pages that are HTML
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	if !s.cfg.HTTP.SecurityHeaders {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// Only over TLS: sending HSTS on a plaintext response is ignored by
		// browsers and misleading to a reader of the configuration.
		if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// operational wraps a non-MCP endpoint with the security headers and a metric.
func (s *Server) operational(next http.Handler) http.Handler {
	return s.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.metrics.Inc(observability.HTTPRequests,
			"path", s.pathLabel(r.URL.Path),
			"status", statusClass(rec.status))
	}))
}

// pathLabel collapses a request path onto the closed set of paths this server
// actually serves.
//
// The catch-all route means r.URL.Path is caller-controlled, and using it as a
// metric label directly would let anyone create unbounded time series by
// requesting /a, /b, /c... - which is how a metrics backend is brought down by
// a trivial script. Everything unrecognised becomes one label value.
func (s *Server) pathLabel(path string) string {
	switch path {
	case "/", "/healthz", "/readyz", s.cfg.HTTP.Path:
		return path
	case s.cfg.HTTP.MetricsPath:
		if s.cfg.HTTP.MetricsPath != "" {
			return path
		}
	}
	return "other"
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Flush forwards to the underlying writer when it supports flushing, so
// wrapping cannot break a streaming response.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// statusClass buckets a status code, so the metric label stays a closed set.
func statusClass(code int) string {
	switch {
	case code < 300:
		return "2xx"
	case code < 400:
		return "3xx"
	case code < 500:
		return "4xx"
	default:
		return "5xx"
	}
}

// healthHandler reports process liveness. It touches nothing.
func (s *Server) healthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "ok",
			"service": s.cfg.Identity.Name,
			"version": s.cfg.Identity.Version,
		})
	})
}

// readyHandler reports whether this replica can serve traffic.
//
// The body names the failing check but nothing else: a readiness endpoint is
// usually reachable from anywhere inside a cluster, and an error string from a
// backend client is exactly the sort of thing that carries a hostname, a port
// and sometimes a credential.
func (s *Server) readyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.ready == nil {
			writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		if err := s.ready(ctx); err != nil {
			s.logger.Warn("readiness check failed", "error", err)
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"status": "not ready",
				"checks": map[string]string{"backend": "unavailable"},
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "ready",
			"checks": map[string]string{"backend": "ok"},
		})
	})
}

// metricsHandler serves the Prometheus endpoint, optionally behind its own
// token.
//
// A separate token from the MCP one, because the two grant different things and
// are held by different parties: a scraper should not hold a credential that
// can read customer data, and an MCP client should not be able to read the
// operational metrics of the server it is talking to.
func (s *Server) metricsHandler() http.Handler {
	inner := s.metrics.Handler()
	if s.cfg.HTTP.MetricsToken == "" {
		return inner
	}
	want := s.cfg.HTTP.MetricsToken
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || !constantTimeEqual(strings.TrimSpace(got), want) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		inner.ServeHTTP(w, r)
	})
}

// mcpMethodFromPath reports whether a request path is really an MCP method
// name that someone has mistaken for a URL.
//
// The set is closed and defined in this package, so nothing caller-controlled
// reaches a label or a format string through it.
func mcpMethodFromPath(path string) (string, bool) {
	candidate := strings.Trim(path, "/")
	for _, method := range []string{
		methodInitialize, methodPing,
		methodToolsList, methodToolsCall,
		methodResourcesList, methodResourceTemplates, methodResourcesRead,
		methodPromptsList, methodPromptsGet,
		methodComplete,
	} {
		if candidate == method {
			return method, true
		}
	}
	return "", false
}

// sanitizePath bounds and cleans a caller-supplied path before it is echoed.
func sanitizePath(p string) string {
	const max = 128
	if len(p) > max {
		p = p[:max] + "..."
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, p)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// Shutdown releases server-side resources, closing any session still open.
//
// It is called after Serve returns, so the transport has already stopped
// accepting work; this is the last step of the lifecycle.
func (s *Server) Shutdown(timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for sess := range s.sdk.Sessions() {
		if time.Now().After(deadline) {
			s.logger.Warn("shutdown deadline reached with sessions still open")
			return
		}
		if err := sess.Close(); err != nil {
			s.logger.Warn("closing MCP session failed", "session", sess.ID(), "error", err)
		}
	}
	s.logger.Info("all MCP sessions closed")
}
