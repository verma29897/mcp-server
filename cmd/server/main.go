// Command server runs the company MCP server.
//
// Lifecycle:
//
//	load and validate configuration
//	  -> build the backend client
//	  -> build the service layer (cursors, idempotency)
//	  -> create the MCP server and register tools, resources and prompts
//	  -> select a transport (stdio or Streamable HTTP)
//	  -> serve until SIGINT/SIGTERM
//	  -> shut the transport down gracefully, then close the backend
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	appbackend "github.com/verma29897/mcp-server/internal/backend"
	"github.com/verma29897/mcp-server/internal/config"
	"github.com/verma29897/mcp-server/internal/idempotency"
	appmcp "github.com/verma29897/mcp-server/internal/mcp"
	"github.com/verma29897/mcp-server/internal/paging"
	"github.com/verma29897/mcp-server/internal/services"
)

func main() {
	showVersion := flag.Bool("version", false, "print the server name and version, then exit")
	checkConfig := flag.Bool("check-config", false, "validate the configuration and exit without serving")
	envFile := flag.String("env-file", config.DefaultEnvFile,
		"file of KEY=VALUE defaults; real environment variables always win. Empty disables it.")
	flag.Parse()

	if err := run(*showVersion, *checkConfig, *envFile); err != nil {
		// stderr, never stdout: on the stdio transport stdout is the JSON-RPC
		// stream and any stray byte on it breaks the session.
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run(showVersion, checkConfig bool, envFile string) error {
	// Read the .env before anything else, so every value below sees it. A
	// missing file is fine - that is what production looks like - but a
	// malformed one is fatal: silently ignoring a line the operator believed
	// was setting a token is exactly the failure config validation exists to
	// prevent.
	var envResult config.EnvFileResult
	if envFile != "" {
		var err error
		if envResult, err = config.LoadEnvFile(envFile); err != nil {
			return fmt.Errorf("load %s: %w", envFile, err)
		}
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	if showVersion {
		fmt.Fprintf(os.Stderr, "%s %s\n", cfg.Identity.Name, cfg.Identity.Version)
		return nil
	}

	logger := newLogger(cfg)
	logger.Info("starting MCP server", slogArgs(cfg.Redacted())...)
	// Names only, never values: a .env is where the secrets are.
	if envResult.Path != "" {
		logger.Info("loaded environment file",
			"path", envResult.Path,
			"applied", envResult.Applied,
			"overridden_by_environment", envResult.Skipped,
		)
	}
	// Valid but questionable settings are surfaced rather than enforced, so an
	// operator sees them in the first ten lines of a deployment's logs instead
	// of discovering them in an incident review.
	for _, w := range cfg.Warnings() {
		logger.Warn("configuration warning", "detail", w)
	}
	if checkConfig {
		fmt.Fprintln(os.Stderr, "configuration is valid")
		return nil
	}

	// Backend: the outermost layer, and the only one that talks to a data
	// source. Swapping it changes nothing above.
	be, err := newBackend(cfg)
	if err != nil {
		return fmt.Errorf("initialise backend: %w", err)
	}
	defer func() {
		if err := be.Close(); err != nil {
			logger.Warn("closing backend failed", "error", err)
		}
	}()

	// Service layer: business rules, no protocol and no transport.
	svc := services.NewCustomerService(be, services.Options{
		Cursors:     paging.NewCodec(cfg.CursorSecret),
		Idempotency: newIdempotencyStore(cfg),
	})

	// Verify the backend before advertising the server as up, so a
	// misconfigured deployment fails at start rather than on the first tool
	// call from a user.
	healthCtx, cancelHealth := context.WithTimeout(context.Background(), cfg.Backend.Timeout)
	healthErr := svc.Health(healthCtx)
	cancelHealth()
	if healthErr != nil {
		if cfg.Backend.Mode == config.BackendHTTP {
			return fmt.Errorf("backend health check failed: %w", healthErr)
		}
		logger.Warn("backend health check failed", "error", healthErr)
	}

	// MCP layer: tools, resources and prompts are registered here, once, for
	// whichever transport is selected next.
	server, err := appmcp.New(cfg, svc, logger, appmcp.NewDeps(cfg, logger, svc.Health))
	if err != nil {
		return fmt.Errorf("create MCP server: %w", err)
	}

	// Cancel on SIGINT/SIGTERM. Both transports treat cancellation as the
	// signal to drain and stop.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErr := server.Serve(ctx)

	// Stop intercepting signals: a second Ctrl-C during shutdown should kill
	// the process rather than be swallowed.
	stop()
	server.Shutdown(shutdownGrace(cfg))

	if serveErr != nil && !errors.Is(serveErr, context.Canceled) {
		return serveErr
	}
	logger.Info("MCP server stopped")
	return nil
}

// newBackend builds the configured data source.
func newBackend(cfg *config.Config) (appbackend.Backend, error) {
	switch cfg.Backend.Mode {
	case config.BackendMemory:
		return appbackend.NewMemory(), nil
	case config.BackendHTTP:
		return appbackend.NewHTTP(appbackend.HTTPOptions{
			BaseURL:               cfg.Backend.BaseURL,
			Token:                 cfg.Backend.APIToken,
			Timeout:               cfg.Backend.Timeout,
			DialTimeout:           cfg.Backend.DialTimeout,
			ResponseHeaderTimeout: cfg.Backend.ResponseHeaderTimeout,
			MaxResponseBytes:      cfg.Backend.MaxResponseBytes,
			Retry: appbackend.RetryConfig{
				MaxAttempts: cfg.Backend.RetryAttempts,
				BaseDelay:   cfg.Backend.RetryBaseWait,
				MaxDelay:    cfg.Backend.RetryMaxWait,
				Jitter:      true,
			},
			Circuit: appbackend.CircuitConfig{
				FailureThreshold: cfg.Backend.CircuitThreshold,
				OpenDuration:     cfg.Backend.CircuitOpenFor,
			},
		})
	default:
		return nil, fmt.Errorf("unsupported backend mode %q", cfg.Backend.Mode)
	}
}

// newIdempotencyStore builds the replay-protection store.
//
// In-process, which is correct for one replica and stated plainly to be wrong
// for several: config.Warnings says so at startup, and docs/DEPLOYMENT.md
// describes what a shared implementation has to provide.
func newIdempotencyStore(cfg *config.Config) idempotency.Store {
	if !cfg.Idempotency.Enabled {
		return nil
	}
	return idempotency.NewMemory(cfg.Idempotency.TTL, cfg.Idempotency.MaxEntries)
}

// newLogger builds the process logger.
//
// It writes to stderr unconditionally. Under the stdio transport stdout belongs
// to the protocol; under HTTP it makes no difference, so there is one rule
// rather than a transport-dependent one that could be got wrong.
func newLogger(cfg *config.Config) *slog.Logger {
	opts := &slog.HandlerOptions{Level: cfg.Observability.LogLevel}
	var handler slog.Handler = slog.NewJSONHandler(os.Stderr, opts)
	if cfg.Observability.LogFormat == "text" {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}
	// Every line carries the service identity, so records from several
	// deployments in one log index remain separable.
	return slog.New(handler).With(
		"service", cfg.Identity.Name,
		"version", cfg.Identity.Version,
	)
}

// shutdownGrace is how long to wait for open sessions to close.
func shutdownGrace(cfg *config.Config) time.Duration {
	if cfg.Transport == config.TransportHTTP {
		return cfg.HTTP.ShutdownTimeout
	}
	return 5 * time.Second
}

// slogArgs flattens a map into the alternating key/value form slog expects.
func slogArgs(m map[string]any) []any {
	args := make([]any, 0, len(m)*2)
	for k, v := range m {
		args = append(args, k, v)
	}
	return args
}
