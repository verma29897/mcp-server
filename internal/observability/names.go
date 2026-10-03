package observability

// Metric names.
//
// One place, so a dashboard query and the code that feeds it cannot drift, and
// so the closed set of label values is visible in a single screen. Nothing here
// takes a label value from a request argument: tool, method, resource kind and
// error code are all drawn from sets defined in this repository.
const (
	// MCPRequests counts inbound MCP methods. Labels: method, outcome.
	MCPRequests = "mcp_requests_total"
	// MCPRequestDuration times inbound MCP methods. Labels: method.
	MCPRequestDuration = "mcp_request_duration_seconds"
	// ToolCalls counts tool invocations. Labels: tool, outcome.
	ToolCalls = "mcp_tool_calls_total"
	// ToolDuration times tool invocations. Labels: tool.
	ToolDuration = "mcp_tool_duration_seconds"
	// ResourceReads counts resources/read. Labels: resource, outcome.
	ResourceReads = "mcp_resource_reads_total"
	// PromptRenders counts prompts/get. Labels: prompt, outcome.
	PromptRenders = "mcp_prompt_renders_total"
	// Errors counts failures by classification. Labels: code, feature.
	Errors = "mcp_errors_total"
	// AuthFailures counts rejected credentials. Labels: reason.
	AuthFailures = "mcp_auth_failures_total"
	// AuthzDenials counts scope and tenant denials. Labels: scope, feature.
	AuthzDenials = "mcp_authz_denials_total"
	// RateLimited counts throttled requests. Labels: scope_kind.
	RateLimited = "mcp_rate_limited_total"
	// BackendRequests counts upstream calls. Labels: operation, outcome.
	BackendRequests = "mcp_backend_requests_total"
	// BackendDuration times upstream calls. Labels: operation.
	BackendDuration = "mcp_backend_duration_seconds"
	// BackendRetries counts retried upstream calls. Labels: operation.
	BackendRetries = "mcp_backend_retries_total"
	// CircuitState reports the breaker state as a gauge: 0 closed, 1 half-open,
	// 2 open.
	CircuitState = "mcp_backend_circuit_state"
	// ActiveSessions reports currently open MCP sessions.
	ActiveSessions = "mcp_active_sessions"
	// HTTPRequests counts non-MCP HTTP endpoints. Labels: path, status.
	HTTPRequests = "mcp_http_requests_total"
	// ResponseBytes observes the size of a rendered tool or resource payload.
	// Labels: feature.
	ResponseBytes = "mcp_response_bytes"
	// IdempotentReplays counts side-effecting calls served from the
	// idempotency store instead of being executed again. Labels: operation.
	IdempotentReplays = "mcp_idempotent_replays_total"
)

// helpFor returns the HELP text for a metric name.
func helpFor(name string) string {
	switch name {
	case MCPRequests:
		return "Inbound MCP method calls by method and outcome."
	case MCPRequestDuration:
		return "Inbound MCP method latency in seconds."
	case ToolCalls:
		return "Tool invocations by tool and outcome."
	case ToolDuration:
		return "Tool invocation latency in seconds."
	case ResourceReads:
		return "Resource reads by resource kind and outcome."
	case PromptRenders:
		return "Prompt renders by prompt and outcome."
	case Errors:
		return "Failures by domain error classification."
	case AuthFailures:
		return "Credentials rejected during authentication."
	case AuthzDenials:
		return "Requests denied for insufficient scope or wrong tenant."
	case RateLimited:
		return "Requests rejected by a rate limiter."
	case BackendRequests:
		return "Upstream backend calls by operation and outcome."
	case BackendDuration:
		return "Upstream backend call latency in seconds."
	case BackendRetries:
		return "Upstream backend calls that were retried."
	case CircuitState:
		return "Backend circuit breaker state: 0 closed, 1 half-open, 2 open."
	case ActiveSessions:
		return "Currently open MCP sessions."
	case HTTPRequests:
		return "HTTP requests to the operational endpoints."
	case ResponseBytes:
		return "Serialised size in bytes of tool and resource payloads."
	case IdempotentReplays:
		return "Side-effecting calls served from the idempotency store."
	default:
		return "Application metric."
	}
}

// Outcome label values, a closed set.
const (
	OutcomeSuccess = "success"
	OutcomeError   = "error"
	OutcomeDenied  = "denied"
)
