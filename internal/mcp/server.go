package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/verma29897/mcp-server/internal/audit"
	"github.com/verma29897/mcp-server/internal/authn"
	"github.com/verma29897/mcp-server/internal/config"
	"github.com/verma29897/mcp-server/internal/observability"
	"github.com/verma29897/mcp-server/internal/prompts"
	"github.com/verma29897/mcp-server/internal/ratelimit"
	"github.com/verma29897/mcp-server/internal/resources"
	"github.com/verma29897/mcp-server/internal/services"
	"github.com/verma29897/mcp-server/internal/tools/customer"
)

// Server wraps the SDK server together with what the transports need.
type Server struct {
	sdk    *sdk.Server
	cfg    *config.Config
	logger *slog.Logger

	verifier authn.Verifier
	limiter  *ratelimit.Limiter
	metrics  *observability.Metrics
	audit    *audit.Logger
	// ready reports backend reachability for the readiness probe.
	ready func(context.Context) error
}

// Deps are the collaborators the MCP layer needs beyond the service.
//
// They are injected rather than constructed here so that a test can supply a
// limiter with a one-request budget, or an audit logger writing to a buffer,
// without reaching into the package.
type Deps struct {
	Metrics *observability.Metrics
	Audit   *audit.Logger
	Limiter *ratelimit.Limiter
	// Ready reports whether required dependencies are reachable. Nil means
	// always ready.
	Ready func(context.Context) error
}

// SDK exposes the underlying *sdk.Server.
//
// It is what the transports connect and what tests drive through an in-memory
// client, so the same registered feature set is exercised everywhere.
func (s *Server) SDK() *sdk.Server { return s.sdk }

// Metrics exposes the registry, for the /metrics handler and for tests.
func (s *Server) Metrics() *observability.Metrics { return s.metrics }

// New builds a fully registered MCP server.
//
// Registration happens once, here, and is entirely independent of transport:
// the same *Server is served over stdio or Streamable HTTP without any tool,
// resource or prompt being aware of the difference.
func New(cfg *config.Config, svc services.CustomerService, logger *slog.Logger, deps Deps) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("mcp: nil config")
	}
	if svc == nil {
		return nil, fmt.Errorf("mcp: nil customer service")
	}
	if logger == nil {
		logger = slog.Default()
	}
	if deps.Metrics == nil {
		deps.Metrics = observability.NewMetrics(false)
	}
	if deps.Audit == nil {
		deps.Audit = audit.New(logger, false)
	}
	if deps.Limiter == nil {
		deps.Limiter = ratelimit.New(ratelimit.Config{})
	}

	verifier, err := buildVerifier(cfg)
	if err != nil {
		return nil, fmt.Errorf("mcp: build token verifier: %w", err)
	}

	// Implementation is the server identity the client receives in the
	// initialize response.
	impl := &sdk.Implementation{
		Name:        cfg.Identity.Name,
		Version:     cfg.Identity.Version,
		Title:       cfg.Identity.Title,
		Description: cfg.Identity.Description,
	}

	opts := &sdk.ServerOptions{
		// Instructions describe the server as a whole to the client, as
		// opposed to the per-tool descriptions.
		Instructions: cfg.Identity.Instructions,
		Logger:       logger,
		KeepAlive:    cfg.KeepAlive,
		// Completion for prompt arguments; advertised only because a handler
		// is set here, which the SDK detects when computing capabilities.
		CompletionHandler: completionHandler(logger),
	}

	srv := sdk.NewServer(impl, opts)

	s := &Server{
		sdk:      srv,
		cfg:      cfg,
		logger:   logger,
		verifier: verifier,
		limiter:  deps.Limiter,
		metrics:  deps.Metrics,
		audit:    deps.Audit,
		ready:    deps.Ready,
	}

	// Registering these as receiving middleware means they wrap every MCP
	// method uniformly, including ones added later. Order is documented in
	// middleware.go and is load-bearing.
	srv.AddReceivingMiddleware(
		recoveryMiddleware(logger, s.metrics),
		correlationMiddleware(),
		observeMiddleware(logger, s.metrics),
		s.authenticateMiddleware(),
		s.throttleMiddleware(),
		s.authorizeMiddleware(),
		s.auditMiddleware(),
	)

	// Capabilities are inferred by the SDK from what is registered: adding
	// tools advertises "tools", adding resources advertises "resources", and
	// so on. There is no separate capability declaration to keep in sync.
	registerTools(srv, customer.NewHandlers(svc), logger, s.metrics, cfg.Limits.MaxToolResponseBytes)
	registerResources(srv, resources.NewProvider(svc, resources.Options{
		MaskPII:  cfg.Limits.MaskPIIInResources,
		MaxBytes: cfg.Limits.MaxResourceBytes,
	}), logger, s.metrics)
	registerPrompts(srv, prompts.NewProvider(svc), logger)

	s.metrics.SetGauge(observability.ActiveSessions, "Currently open MCP sessions.", func() float64 {
		return float64(s.sessionCount())
	})

	// Neither name nor version is repeated here: the process logger already
	// carries both on every line. A duplicate key in a JSON log is worse than a
	// missing one - most pipelines keep an arbitrary occurrence and drop the
	// rest, so the record becomes ambiguous rather than merely redundant.
	logger.Info("mcp server initialised",
		"tools", len(customer.All()),
		"resources", 1,
		"resource_templates", 3,
		"prompts", 2,
		"auth_mode", string(cfg.Auth.Mode),
		"tenancy", cfg.Tenancy.Enabled,
		"rate_limited", s.limiter.Enabled(),
		"audit", s.audit.Enabled(),
	)
	return s, nil
}

// sessionCount reports how many MCP sessions are currently open.
func (s *Server) sessionCount() int {
	n := 0
	for range s.sdk.Sessions() {
		n++
	}
	return n
}

// NewDeps assembles the standard collaborators from configuration.
//
// It lives here rather than in cmd/server so that the wiring a production
// process uses is the same wiring the transport tests exercise.
func NewDeps(cfg *config.Config, logger *slog.Logger, ready func(context.Context) error) Deps {
	return Deps{
		Metrics: observability.NewMetrics(cfg.Observability.MetricsEnabled),
		Audit:   audit.New(logger, cfg.Observability.AuditEnabled),
		Limiter: ratelimit.New(rateLimitConfig(cfg)),
		Ready:   ready,
	}
}

// rateLimitConfig translates configuration into limiter rules.
//
// The two stricter per-tool budgets are the ones that matter most. A model
// stuck in a loop over get_customer wastes money; a model stuck in a loop over
// send_customer_notification harasses a customer, and there is no undo.
func rateLimitConfig(cfg *config.Config) ratelimit.Config {
	if !cfg.RateLimit.Enabled {
		return ratelimit.Config{}
	}
	burst := cfg.RateLimit.Burst
	return ratelimit.Config{
		PerIP:        ratelimit.Rule{PerMinute: cfg.RateLimit.PerIPPerMinute, Burst: burst},
		PerPrincipal: ratelimit.Rule{PerMinute: cfg.RateLimit.PerPrincipalPerMinute, Burst: burst},
		PerTenant:    ratelimit.Rule{PerMinute: cfg.RateLimit.PerTenantPerMinute, Burst: burst},
		PerTool: map[string]ratelimit.Rule{
			"send_customer_notification": {PerMinute: cfg.RateLimit.NotificationPerMinute},
			"delete_customer":            {PerMinute: cfg.RateLimit.DeletePerMinute},
		},
		TTL: 10 * time.Minute,
	}
}
