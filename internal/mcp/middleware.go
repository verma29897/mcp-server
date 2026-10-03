package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/verma29897/mcp-server/internal/audit"
	"github.com/verma29897/mcp-server/internal/authz"
	"github.com/verma29897/mcp-server/internal/domain"
	"github.com/verma29897/mcp-server/internal/observability"
	"github.com/verma29897/mcp-server/internal/ratelimit"
)

// Middleware here is registered with Server.AddReceivingMiddleware, so it wraps
// every inbound MCP method - tools/call, resources/read, prompts/get, the list
// methods and initialize alike - without any handler having to opt in.
//
// The chain, outermost first, and the order is load-bearing:
//
//	recovery     a panic anywhere below becomes an error, not a dead process
//	correlate    assigns the request id everything else logs against
//	observe      times and counts, including the failures the layers below emit
//	authenticate turns verified token claims into a principal on the context
//	throttle     rejects before any work is done, using that principal
//	authorize    the scope and tenant gate, and the list filter
//	audit        records what was actually attempted, and what came of it
//	handler
//
// Authentication precedes throttling so a limit can be per-principal rather than
// only per-address. Throttling precedes authorization so a caller cannot use
// rejected requests as a free probe of what it is allowed to do. Authorization
// precedes audit so a denial is recorded with the reason it was denied.

// recoveryMiddleware turns a panic in a handler into a JSON-RPC error instead
// of taking the process down.
//
// A panic in one tool call must not kill a server that may be holding many
// other sessions. The stack trace goes to the log and never to the client.
func recoveryMiddleware(logger *slog.Logger, metrics *observability.Metrics) sdk.Middleware {
	return func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (result sdk.Result, err error) {
			defer func() {
				if r := recover(); r != nil {
					logger.Error("panic recovered in MCP handler",
						"method", method,
						"request_id", observability.RequestIDFrom(ctx),
						"panic", fmt.Sprint(r),
						"stack", string(debug.Stack()),
					)
					metrics.Inc(observability.Errors, "code", string(domain.CodeInternalError), "feature", method)
					result = nil
					err = &jsonrpc.Error{
						Code:    jsonrpc.CodeInternalError,
						Message: "INTERNAL_ERROR: the server failed to handle this request",
					}
				}
			}()
			return next(ctx, method, req)
		}
	}
}

// correlationMiddleware puts a request id and trace context on every request.
//
// On HTTP the ids come from the caller's headers when it sent any, so a trace
// started at the gateway continues through this server and into the backend
// call it makes. On stdio there are no headers, so fresh ids are generated: a
// stdio session's logs still correlate with each other.
func correlationMiddleware() sdk.Middleware {
	return func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			rc := observability.NewLocal()
			if headers := requestHeaders(req); headers != nil {
				rc = observability.FromHeaders(headers)
			}
			return next(observability.NewContext(ctx, rc), method, req)
		}
	}
}

// observeMiddleware records one log line and the metrics for each method.
//
// Only the method name, feature, session id and outcome are recorded.
// Arguments are not: they routinely carry customer data, and an MCP server's
// log is not the place for it.
func observeMiddleware(logger *slog.Logger, metrics *observability.Metrics) sdk.Middleware {
	return func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			start := time.Now()
			result, err := next(ctx, method, req)
			elapsed := time.Since(start)

			f := featureOf(method, req)
			rc := observability.FromContext(ctx)
			attrs := []any{
				"method", method,
				"duration_ms", elapsed.Milliseconds(),
				"session_id", sessionID(req),
				"request_id", rc.RequestID,
			}
			if rc.TraceID != "" {
				attrs = append(attrs, "trace_id", rc.TraceID)
			}
			if f.name != "" {
				attrs = append(attrs, "feature", f.name)
			}

			metrics.Observe(observability.MCPRequestDuration, elapsed, "method", method)
			outcome, code := classifyOutcome(result, err)
			metrics.Inc(observability.MCPRequests, "method", method, "outcome", outcome)
			recordFeature(metrics, f, method, elapsed, outcome)

			switch {
			case err != nil:
				logger.Warn("mcp request failed",
					append(attrs, "outcome", outcome, "error_class", code)...)
			case outcome == observability.OutcomeError:
				// A tool that failed in-band returns no error: the failure lives
				// in CallToolResult.IsError. Surface it so the log is not
				// misleading about what the client actually received.
				logger.Info("mcp request completed with tool error",
					append(attrs, "outcome", outcome)...)
			default:
				logger.Debug("mcp request completed", append(attrs, "outcome", outcome)...)
			}
			return result, err
		}
	}
}

// classifyOutcome reports the outcome label and the error classification.
func classifyOutcome(result sdk.Result, err error) (outcome, code string) {
	if err != nil {
		return observability.OutcomeError, string(domain.CodeOf(err))
	}
	if ctr, ok := result.(*sdk.CallToolResult); ok && ctr.IsError {
		return observability.OutcomeError, codeFromToolResult(ctr)
	}
	return observability.OutcomeSuccess, ""
}

// codeFromToolResult recovers the classification from an in-band tool error.
//
// The message is built by toolError as "CODE: message", so the prefix is the
// classification. Anything unrecognised is reported as INTERNAL_ERROR rather
// than being used as a metric label, which keeps label cardinality closed.
func codeFromToolResult(res *sdk.CallToolResult) string {
	for _, c := range res.Content {
		tc, ok := c.(*sdk.TextContent)
		if !ok {
			continue
		}
		prefix, _, found := strings.Cut(tc.Text, ":")
		if !found {
			continue
		}
		if known := domain.Code(prefix); isKnownCode(known) {
			return string(known)
		}
	}
	return string(domain.CodeInternalError)
}

func isKnownCode(c domain.Code) bool {
	switch c {
	case domain.CodeInvalidArgument, domain.CodeNotFound, domain.CodeUnauthorized,
		domain.CodeForbidden, domain.CodeConflict, domain.CodeTimeout,
		domain.CodeRateLimited, domain.CodeBackendError, domain.CodeInternalError:
		return true
	default:
		return false
	}
}

func recordFeature(metrics *observability.Metrics, f feature, method string, elapsed time.Duration, outcome string) {
	switch f.kind {
	case kindTool:
		metrics.Inc(observability.ToolCalls, "tool", f.name, "outcome", outcome)
		metrics.Observe(observability.ToolDuration, elapsed, "tool", f.name)
	case kindResource:
		metrics.Inc(observability.ResourceReads, "resource", resourceLabel(f.name), "outcome", outcome)
	case kindPrompt:
		metrics.Inc(observability.PromptRenders, "prompt", f.name, "outcome", outcome)
	default:
		_ = method
	}
}

// resourceLabel collapses a resource URI onto its template.
//
// A per-customer URI as a metric label would create one time series per
// customer, which is how a metrics backend is brought down by ordinary use.
func resourceLabel(uri string) string {
	const scheme = "customer://"
	rest, ok := strings.CutPrefix(uri, scheme)
	if !ok {
		return "other"
	}
	switch {
	case rest == "directory":
		return "customer://directory"
	case strings.HasSuffix(rest, "/orders"):
		return "customer://{id}/orders"
	case strings.HasSuffix(rest, "/summary"):
		return "customer://{id}/summary"
	default:
		return "customer://{id}"
	}
}

// authenticateMiddleware puts the caller's principal on the context.
//
// The claims come from RequestExtra.TokenInfo, which the SDK populated from the
// verified token at the HTTP boundary. When there are none - stdio, or an
// explicitly unauthenticated deployment - the configured local principal is
// used instead. There is no third case: a request always runs as some
// principal, and an unauthenticated one holds nothing.
func (s *Server) authenticateMiddleware() sdk.Middleware {
	return func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			principal := s.localPrincipal()
			if claims := tokenInfo(req); claims != nil {
				if p := claims.toPrincipal(); p != nil && !p.Anonymous() {
					principal = p
				}
			}
			if !s.cfg.Tenancy.Enabled {
				// Single-tenant deployment: every caller acts in one tenant,
				// whatever their token says. Overriding rather than trusting the
				// claim means a token minted elsewhere cannot name a tenant this
				// deployment does not serve.
				principal.TenantID = s.cfg.Tenancy.DefaultTenant
			}
			return next(authz.NewContext(ctx, principal), method, req)
		}
	}
}

// throttleMiddleware applies the rate limiter.
//
// It runs before authorization so that a caller cannot use denied requests as a
// free channel: a rejected request still costs the same budget as an accepted
// one.
func (s *Server) throttleMiddleware() sdk.Middleware {
	return func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			if !s.limiter.Enabled() {
				return next(ctx, method, req)
			}
			// The handshake and liveness methods are exempt. Throttling
			// initialize would reject a reconnecting client, and a client that
			// cannot reconnect retries harder.
			if method == methodInitialize || method == methodPing {
				return next(ctx, method, req)
			}

			p := authz.FromContext(ctx)
			f := featureOf(method, req)
			decision := s.limiter.Allow(ratelimit.Request{
				IP:        remoteAddrOf(ctx),
				Principal: p.Subject,
				Tenant:    p.TenantID,
				Tool:      toolNameOf(f),
			})
			if decision.Allowed {
				return next(ctx, method, req)
			}

			s.metrics.Inc(observability.RateLimited, "scope_kind", decision.Scope)
			s.audit.Log(ctx, audit.Event{
				Action:     audit.ActionRateLimited,
				Result:     audit.ResultDenied,
				Principal:  p,
				RequestID:  observability.RequestIDFrom(ctx),
				SessionID:  sessionID(req),
				TraceID:    observability.TraceIDFrom(ctx),
				Method:     method,
				Feature:    f.name,
				Code:       domain.CodeRateLimited,
				Reason:     "rate limit exceeded at the " + decision.Scope + " layer",
				RemoteAddr: remoteAddrOf(ctx),
			})

			err := domain.RateLimited(
				"too many requests; retry in %d seconds. Slow down rather than retrying immediately.",
				int(decision.RetryAfter.Seconds()))
			return s.denial(ctx, method, f, err)
		}
	}
}

// authorizeMiddleware is the scope and tenant gate.
//
// This is the enforcement point the whole design turns on. It runs before any
// handler, decides from the principal alone, and cannot be reached or
// influenced by anything a model emits. A tool description that says "you may
// delete customers", a prompt that says "you are an administrator" and a
// customer record whose name is "ignore previous instructions" all arrive on
// the far side of this check and change nothing about it.
func (s *Server) authorizeMiddleware() sdk.Middleware {
	return func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			p := authz.FromContext(ctx)

			if isListMethod(method) {
				result, err := next(ctx, method, req)
				if err != nil {
					return result, err
				}
				return filterListing(method, result, p), nil
			}
			if !isDataMethod(method) {
				return next(ctx, method, req)
			}

			f := featureOf(method, req)
			scopes, known := requiredScopes(f)
			if !known {
				// An unregistered feature: let the SDK produce its own
				// "unknown tool" error rather than inventing a denial for
				// something that does not exist.
				return next(ctx, method, req)
			}

			if err := p.RequireAll(scopes); err != nil {
				s.metrics.Inc(observability.AuthzDenials, "scope", strings.Join(scopes, "+"), "feature", featureLabel(f))
				s.audit.Log(ctx, audit.Event{
					Action:     audit.ActionAuthzDenied,
					Result:     audit.ResultDenied,
					Principal:  p,
					RequestID:  observability.RequestIDFrom(ctx),
					SessionID:  sessionID(req),
					TraceID:    observability.TraceIDFrom(ctx),
					Method:     method,
					Feature:    featureLabel(f),
					Code:       domain.CodeOf(err),
					Reason:     "missing scope: " + strings.Join(scopes, " "),
					RemoteAddr: remoteAddrOf(ctx),
				})
				return s.denial(ctx, method, f, err)
			}
			return next(ctx, method, req)
		}
	}
}

// requiredScopes maps a feature onto the scopes the policy requires.
func requiredScopes(f feature) ([]string, bool) {
	switch f.kind {
	case kindTool:
		return authz.ToolScopes(f.name)
	case kindResource:
		return authz.ResourceScopes(f.name)
	case kindPrompt:
		return authz.PromptScopes(f.name)
	default:
		return nil, false
	}
}

// featureLabel renders a feature for a metric or audit field, collapsing
// per-customer resource URIs onto their template.
func featureLabel(f feature) string {
	if f.kind == kindResource {
		return resourceLabel(f.name)
	}
	return f.name
}

// denial encodes an authorization or throttling refusal in the right shape for
// the method that was refused.
//
// tools/call gets an in-band CallToolResult, because that is the channel the
// model reads: a JSON-RPC error is invisible to it, and a model that cannot see
// why a call failed will simply try again. resources/read and prompts/get have
// no in-band channel, so they get a protocol error.
func (s *Server) denial(ctx context.Context, method string, f feature, err error) (sdk.Result, error) {
	if method != methodToolsCall {
		return nil, protocolError(classify(ctx, err, method))
	}
	de := classify(ctx, err, f.name)
	return &sdk.CallToolResult{
		IsError: true,
		Content: []sdk.Content{&sdk.TextContent{Text: de.Error()}},
	}, nil
}

// filterListing removes features the caller may not use from a list result.
//
// Filtering rather than refusing: a client that holds read but not delete
// should see the tools it can call and not see the one it cannot, so the model
// never proposes an action that was always going to be refused. The listing is
// per-principal, which is why it is computed here rather than cached.
func filterListing(method string, result sdk.Result, p *authz.Principal) sdk.Result {
	switch method {
	case methodToolsList:
		res, ok := result.(*sdk.ListToolsResult)
		if !ok {
			return result
		}
		out := make([]*sdk.Tool, 0, len(res.Tools))
		for _, t := range res.Tools {
			if authz.CanUseTool(p, t.Name) {
				out = append(out, t)
			}
		}
		res.Tools = out
		return res

	case methodResourcesList:
		res, ok := result.(*sdk.ListResourcesResult)
		if !ok {
			return result
		}
		out := make([]*sdk.Resource, 0, len(res.Resources))
		for _, r := range res.Resources {
			if authz.CanReadResource(p, r.URI) {
				out = append(out, r)
			}
		}
		res.Resources = out
		return res

	case methodResourceTemplates:
		res, ok := result.(*sdk.ListResourceTemplatesResult)
		if !ok {
			return result
		}
		out := make([]*sdk.ResourceTemplate, 0, len(res.ResourceTemplates))
		for _, t := range res.ResourceTemplates {
			if authz.CanReadResource(p, t.URITemplate) {
				out = append(out, t)
			}
		}
		res.ResourceTemplates = out
		return res

	case methodPromptsList:
		res, ok := result.(*sdk.ListPromptsResult)
		if !ok {
			return result
		}
		out := make([]*sdk.Prompt, 0, len(res.Prompts))
		for _, pr := range res.Prompts {
			if authz.CanUsePrompt(p, pr.Name) {
				out = append(out, pr)
			}
		}
		res.Prompts = out
		return res

	default:
		return result
	}
}

// auditMiddleware records every operation that reaches customer data.
func (s *Server) auditMiddleware() sdk.Middleware {
	return func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			if !s.audit.Enabled() || !isDataMethod(method) {
				return next(ctx, method, req)
			}

			f := featureOf(method, req)
			start := time.Now()
			result, err := next(ctx, method, req)

			outcome, code := classifyOutcome(result, err)
			event := audit.Event{
				Action:     auditAction(f, method),
				Result:     audit.ResultSuccess,
				Principal:  authz.FromContext(ctx),
				RequestID:  observability.RequestIDFrom(ctx),
				SessionID:  sessionID(req),
				TraceID:    observability.TraceIDFrom(ctx),
				Method:     method,
				Feature:    featureLabel(f),
				Target:     auditTarget(f),
				Duration:   time.Since(start),
				RemoteAddr: remoteAddrOf(ctx),
			}
			if outcome == observability.OutcomeError {
				event.Result = audit.ResultFailure
				event.Code = domain.Code(code)
				if err != nil {
					event.Code = domain.CodeOf(err)
				}
			}
			s.audit.Log(ctx, event)
			return result, err
		}
	}
}

// auditAction maps a feature onto the action name recorded in the audit log.
//
// The action names an operation on data, not a tool: renaming a tool must not
// break a retention query written against last quarter's records.
func auditAction(f feature, method string) audit.Action {
	switch f.kind {
	case kindTool:
		switch f.name {
		case "get_customer":
			return audit.ActionCustomerRead
		case "search_customers":
			return audit.ActionCustomerList
		case "list_customer_orders":
			return audit.ActionOrdersRead
		case "update_customer":
			return audit.ActionCustomerWrite
		case "delete_customer":
			return audit.ActionCustomerDel
		case "send_customer_notification":
			return audit.ActionNotifySend
		}
	case kindResource:
		return audit.ActionResourceRead
	case kindPrompt:
		return audit.ActionPromptRender
	}
	return audit.Action(method)
}

// auditTarget extracts the customer id an operation addressed, when the routing
// information carries one.
//
// Deliberately derived from the URI rather than from the arguments. An audit
// record needs to say which customer was touched, but reading arguments to find
// out would put the whole argument object one refactor away from the log.
func auditTarget(f feature) string {
	if f.kind != kindResource {
		return ""
	}
	rest, ok := strings.CutPrefix(f.name, "customer://")
	if !ok || rest == "directory" {
		return ""
	}
	id, _, _ := strings.Cut(rest, "/")
	return id
}

func toolNameOf(f feature) string {
	if f.kind == kindTool {
		return f.name
	}
	return ""
}

// remoteAddrOf reports the caller's address, as recorded by the correlation
// middleware.
func remoteAddrOf(ctx context.Context) string {
	return observability.FromContext(ctx).RemoteAddr
}
