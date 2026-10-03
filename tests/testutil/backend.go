// Package testutil provides test doubles shared by the tool, resource and
// integration test packages.
package testutil

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/verma29897/mcp-server/internal/audit"
	"github.com/verma29897/mcp-server/internal/authz"
	"github.com/verma29897/mcp-server/internal/backend"
	"github.com/verma29897/mcp-server/internal/config"
	"github.com/verma29897/mcp-server/internal/domain"
	"github.com/verma29897/mcp-server/internal/idempotency"
	appmcp "github.com/verma29897/mcp-server/internal/mcp"
	"github.com/verma29897/mcp-server/internal/observability"
	"github.com/verma29897/mcp-server/internal/paging"
	"github.com/verma29897/mcp-server/internal/ratelimit"
	"github.com/verma29897/mcp-server/internal/services"
)

// Tenants seeded by the in-memory backend, re-exported so a test does not have
// to know which package owns the constant.
const (
	Tenant      = backend.DefaultTenant
	OtherTenant = backend.SecondaryTenant
)

// FakeBackend wraps the in-memory backend and lets a test override any single
// method, which is how backend failures (outage, timeout, unauthorized) get
// injected without a network.
type FakeBackend struct {
	Inner *backend.Memory

	GetCustomerFn      func(ctx context.Context, tenantID, id string) (domain.Customer, error)
	SearchCustomersFn  func(ctx context.Context, q domain.SearchQuery) (domain.CustomerList, error)
	ListOrdersFn       func(ctx context.Context, tenantID, customerID string, p domain.Page) (domain.OrderList, error)
	UpdateCustomerFn   func(ctx context.Context, tenantID, id string, patch domain.CustomerPatch) (domain.Customer, error)
	DeleteCustomerFn   func(ctx context.Context, tenantID, id string, expectedVersion *int) error
	SendNotificationFn func(ctx context.Context, n domain.Notification) (domain.Receipt, error)
	PingFn             func(ctx context.Context) error

	mu sync.Mutex
	// calls counts invocations by method name, so a test can assert that a
	// rejected call never reached the backend.
	calls map[string]int
}

var _ backend.Backend = (*FakeBackend)(nil)

// NewFakeBackend returns a fake backed by the seeded in-memory store.
func NewFakeBackend() *FakeBackend {
	return &FakeBackend{Inner: backend.NewMemory(), calls: map[string]int{}}
}

func (f *FakeBackend) record(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[name]++
}

// Calls reports how many times a backend method was invoked.
func (f *FakeBackend) Calls(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[name]
}

// GetCustomer implements backend.Backend.
func (f *FakeBackend) GetCustomer(ctx context.Context, tenantID, id string) (domain.Customer, error) {
	f.record("GetCustomer")
	if f.GetCustomerFn != nil {
		return f.GetCustomerFn(ctx, tenantID, id)
	}
	return f.Inner.GetCustomer(ctx, tenantID, id)
}

// SearchCustomers implements backend.Backend.
func (f *FakeBackend) SearchCustomers(ctx context.Context, q domain.SearchQuery) (domain.CustomerList, error) {
	f.record("SearchCustomers")
	if f.SearchCustomersFn != nil {
		return f.SearchCustomersFn(ctx, q)
	}
	return f.Inner.SearchCustomers(ctx, q)
}

// ListOrders implements backend.Backend.
func (f *FakeBackend) ListOrders(ctx context.Context, tenantID, customerID string, p domain.Page) (domain.OrderList, error) {
	f.record("ListOrders")
	if f.ListOrdersFn != nil {
		return f.ListOrdersFn(ctx, tenantID, customerID, p)
	}
	return f.Inner.ListOrders(ctx, tenantID, customerID, p)
}

// UpdateCustomer implements backend.Backend.
func (f *FakeBackend) UpdateCustomer(ctx context.Context, tenantID, id string, patch domain.CustomerPatch) (domain.Customer, error) {
	f.record("UpdateCustomer")
	if f.UpdateCustomerFn != nil {
		return f.UpdateCustomerFn(ctx, tenantID, id, patch)
	}
	return f.Inner.UpdateCustomer(ctx, tenantID, id, patch)
}

// DeleteCustomer implements backend.Backend.
func (f *FakeBackend) DeleteCustomer(ctx context.Context, tenantID, id string, expectedVersion *int) error {
	f.record("DeleteCustomer")
	if f.DeleteCustomerFn != nil {
		return f.DeleteCustomerFn(ctx, tenantID, id, expectedVersion)
	}
	return f.Inner.DeleteCustomer(ctx, tenantID, id, expectedVersion)
}

// SendNotification implements backend.Backend.
func (f *FakeBackend) SendNotification(ctx context.Context, n domain.Notification) (domain.Receipt, error) {
	f.record("SendNotification")
	if f.SendNotificationFn != nil {
		return f.SendNotificationFn(ctx, n)
	}
	return f.Inner.SendNotification(ctx, n)
}

// Ping implements backend.Backend.
func (f *FakeBackend) Ping(ctx context.Context) error {
	f.record("Ping")
	if f.PingFn != nil {
		return f.PingFn(ctx)
	}
	return f.Inner.Ping(ctx)
}

// Close implements backend.Backend.
func (f *FakeBackend) Close() error { return f.Inner.Close() }

// NewService returns a customer service over a fresh fake backend, with
// idempotency and cursor signing enabled.
func NewService() (services.CustomerService, *FakeBackend) {
	be := NewFakeBackend()
	return services.NewCustomerService(be, services.Options{
		Cursors:     paging.NewCodec("test-cursor-secret"),
		Idempotency: idempotency.NewMemory(time.Hour, 1000),
	}), be
}

// NewServiceWithout returns a service with the named feature disabled, for the
// tests that assert the feature-off behaviour.
func NewServiceWithoutIdempotency() (services.CustomerService, *FakeBackend) {
	be := NewFakeBackend()
	return services.NewCustomerService(be, services.Options{
		Cursors: paging.NewCodec("test-cursor-secret"),
	}), be
}

// Logger returns a logger that discards output, so test runs stay readable.
func Logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discard{}, &slog.HandlerOptions{Level: slog.LevelError + 100}))
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// AuditRecorder captures audit records so a test can assert on them.
//
// It parses the JSON lines rather than matching substrings: an audit assertion
// that passes because the word "denied" appears somewhere in a log line is not
// an assertion about the audit record.
type AuditRecorder struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// NewAuditRecorder returns a recorder and the audit logger writing into it.
func NewAuditRecorder() (*AuditRecorder, *audit.Logger) {
	r := &AuditRecorder{}
	logger := slog.New(slog.NewJSONHandler(r, &slog.HandlerOptions{Level: slog.LevelInfo}))
	return r, audit.New(logger, true)
}

func (r *AuditRecorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.Write(p)
}

// Events returns every audit record captured so far.
func (r *AuditRecorder) Events() []map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()

	var out []map[string]any
	for _, line := range strings.Split(r.buf.String(), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if rec["log_type"] != "audit" {
			continue
		}
		out = append(out, rec)
	}
	return out
}

// Find returns the first audit record with the given action.
func (r *AuditRecorder) Find(action string) map[string]any {
	for _, e := range r.Events() {
		if e["action"] == action {
			return e
		}
	}
	return nil
}

// Raw returns everything written, for the tests that assert an absence.
func (r *AuditRecorder) Raw() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.String()
}

// Config returns a configuration suitable for tests, with the given transport.
//
// Rate limiting is off by default: a test that drives a hundred calls through
// one principal should fail for the reason it is testing, not because it hit a
// production budget. The rate-limit tests opt back in explicitly.
func Config(transport config.Transport) *config.Config {
	return &config.Config{
		Identity: config.Identity{
			Name:         "test-mcp-server",
			Version:      "0.0.0-test",
			Title:        "Test server",
			Description:  "MCP server under test",
			Instructions: "Test instructions.",
		},
		Transport: transport,
		HTTP: config.HTTPConfig{
			Addr:              "127.0.0.1:0",
			Path:              "/mcp",
			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       30 * time.Second,
			ShutdownTimeout:   5 * time.Second,
			MaxRequestBytes:   4 << 20,
			MaxHeaderBytes:    1 << 20,
			SecurityHeaders:   true,
			MetricsPath:       "/metrics",
		},
		Auth: config.AuthConfig{
			Mode:         config.AuthNone,
			LocalSubject: "test-principal",
			LocalTenant:  Tenant,
			LocalScopes:  authz.AllScopes,
		},
		Tenancy: config.TenancyConfig{
			Enabled:       false,
			DefaultTenant: Tenant,
		},
		RateLimit: config.RateLimitConfig{Enabled: false},
		Backend:   config.BackendConfig{Mode: config.BackendMemory, Timeout: 5 * time.Second},
		Limits: config.LimitsConfig{
			MaxToolResponseBytes: 256 << 10,
			MaxResourceBytes:     256 << 10,
		},
		Observability: config.ObservabilityConfig{
			LogLevel:       slog.LevelError,
			LogFormat:      "json",
			MetricsEnabled: true,
			AuditEnabled:   true,
		},
		Idempotency:       config.IdempotencyConfig{Enabled: true, TTL: time.Hour, MaxEntries: 1000},
		CursorSecret:      "test-cursor-secret",
		AllowInsecureHTTP: true,
	}
}

// Deps returns the MCP collaborators for a test, with metrics and audit on.
func Deps(cfg *config.Config) (appmcp.Deps, *AuditRecorder) {
	recorder, auditLogger := NewAuditRecorder()
	return appmcp.Deps{
		Metrics: observability.NewMetrics(true),
		Audit:   auditLogger,
		Limiter: ratelimit.New(ratelimit.Config{}),
	}, recorder
}

// Principal returns a principal with the given scopes inside the default
// tenant, for the service-level tests that run without a server.
func Principal(scopes ...string) *authz.Principal {
	if len(scopes) == 0 {
		scopes = authz.AllScopes
	}
	return &authz.Principal{
		Subject:  "test-principal",
		TenantID: Tenant,
		Scopes:   scopes,
		Mode:     authz.AuthLocal,
	}
}

// PrincipalIn returns a fully privileged principal inside a named tenant.
func PrincipalIn(tenant string, scopes ...string) *authz.Principal {
	p := Principal(scopes...)
	p.TenantID = tenant
	return p
}

// Context returns a background context carrying a fully privileged principal.
//
// Almost every handler and service test needs one: without a principal on the
// context every call is refused, which is the correct default and a tedious one
// to restate.
func Context() context.Context {
	return authz.NewContext(context.Background(), Principal())
}

// ContextAs returns a context carrying p.
func ContextAs(p *authz.Principal) context.Context {
	return authz.NewContext(context.Background(), p)
}

// CancelledContext returns a context that is already cancelled, for exercising
// the cancellation path without a real deadline. It carries a principal, so a
// test sees the cancellation rather than an authorization failure.
func CancelledContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(Context())
	cancel()
	return ctx
}
