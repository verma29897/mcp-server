// Package bench_test measures the paths a production deployment is sized on.
//
// The numbers are not assertions - hardware differs, and a benchmark that fails
// CI on a noisy runner gets deleted. They exist so that a change which makes
// tool dispatch ten times slower is visible before it ships, and so
// docs/OPERATIONS.md can quote a figure that was actually measured.
//
// Run: go test -bench . -benchmem ./tests/bench/
package bench_test

import (
	"context"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/verma29897/mcp-server/internal/config"
	"github.com/verma29897/mcp-server/internal/domain"
	appmcp "github.com/verma29897/mcp-server/internal/mcp"
	"github.com/verma29897/mcp-server/internal/services"
	"github.com/verma29897/mcp-server/internal/tools/customer"
	"github.com/verma29897/mcp-server/tests/testutil"
)

// newSession wires a client to a server over the in-memory transport, so what
// is measured is the server's own work rather than a loopback socket.
func newSession(b *testing.B) *sdk.ClientSession {
	b.Helper()

	cfg := testutil.Config(config.TransportStdio)
	svc, _ := testutil.NewService()
	deps, _ := testutil.Deps(cfg)
	srv, err := appmcp.New(cfg, svc, testutil.Logger(), deps)
	if err != nil {
		b.Fatalf("create MCP server: %v", err)
	}

	ctx := context.Background()
	clientTransport, serverTransport := sdk.NewInMemoryTransports()
	serverSession, err := srv.SDK().Connect(ctx, serverTransport, nil)
	if err != nil {
		b.Fatalf("connect server: %v", err)
	}
	b.Cleanup(func() { _ = serverSession.Close() })

	client := sdk.NewClient(&sdk.Implementation{Name: "bench-client", Version: "1.0.0"}, nil)
	cs, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		b.Fatalf("connect client: %v", err)
	}
	b.Cleanup(func() { _ = cs.Close() })
	return cs
}

func BenchmarkInitialize(b *testing.B) {
	cfg := testutil.Config(config.TransportStdio)
	svc, _ := testutil.NewService()
	deps, _ := testutil.Deps(cfg)
	srv, err := appmcp.New(cfg, svc, testutil.Logger(), deps)
	if err != nil {
		b.Fatalf("create MCP server: %v", err)
	}
	ctx := context.Background()

	b.ReportAllocs()
	for b.Loop() {
		clientTransport, serverTransport := sdk.NewInMemoryTransports()
		serverSession, err := srv.SDK().Connect(ctx, serverTransport, nil)
		if err != nil {
			b.Fatalf("connect server: %v", err)
		}
		client := sdk.NewClient(&sdk.Implementation{Name: "bench-client", Version: "1.0.0"}, nil)
		cs, err := client.Connect(ctx, clientTransport, nil)
		if err != nil {
			b.Fatalf("connect client: %v", err)
		}
		_ = cs.Close()
		_ = serverSession.Close()
	}
}

func BenchmarkToolsList(b *testing.B) {
	cs := newSession(b)
	ctx := context.Background()

	b.ReportAllocs()
	for b.Loop() {
		if _, err := cs.ListTools(ctx, nil); err != nil {
			b.Fatalf("tools/list: %v", err)
		}
	}
}

func BenchmarkGetCustomer(b *testing.B) {
	cs := newSession(b)
	ctx := context.Background()
	params := &sdk.CallToolParams{Name: "get_customer", Arguments: map[string]any{"customer_id": "1001"}}

	b.ReportAllocs()
	for b.Loop() {
		res, err := cs.CallTool(ctx, params)
		if err != nil || res.IsError {
			b.Fatalf("get_customer: %v", err)
		}
	}
}

func BenchmarkSearchCustomers(b *testing.B) {
	cs := newSession(b)
	ctx := context.Background()
	params := &sdk.CallToolParams{Name: "search_customers", Arguments: map[string]any{"status": "active"}}

	b.ReportAllocs()
	for b.Loop() {
		res, err := cs.CallTool(ctx, params)
		if err != nil || res.IsError {
			b.Fatalf("search_customers: %v", err)
		}
	}
}

func BenchmarkUpdateCustomer(b *testing.B) {
	cs := newSession(b)
	ctx := context.Background()
	params := &sdk.CallToolParams{
		Name:      "update_customer",
		Arguments: map[string]any{"customer_id": "1002", "tier": "pro"},
	}

	b.ReportAllocs()
	for b.Loop() {
		res, err := cs.CallTool(ctx, params)
		if err != nil || res.IsError {
			b.Fatalf("update_customer: %v", err)
		}
	}
}

func BenchmarkReadSummaryResource(b *testing.B) {
	cs := newSession(b)
	ctx := context.Background()
	params := &sdk.ReadResourceParams{URI: "customer://1001/summary"}

	b.ReportAllocs()
	for b.Loop() {
		if _, err := cs.ReadResource(ctx, params); err != nil {
			b.Fatalf("resources/read: %v", err)
		}
	}
}

// BenchmarkConcurrentClients measures the shape that matters most in
// production: many sessions issuing tool calls at once. The middleware chain,
// the rate limiter and the metric registry are all shared state, so this is
// where contention would show up.
func BenchmarkConcurrentClients(b *testing.B) {
	cfg := testutil.Config(config.TransportStdio)
	svc, _ := testutil.NewService()
	deps, _ := testutil.Deps(cfg)
	srv, err := appmcp.New(cfg, svc, testutil.Logger(), deps)
	if err != nil {
		b.Fatalf("create MCP server: %v", err)
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		clientTransport, serverTransport := sdk.NewInMemoryTransports()
		serverSession, err := srv.SDK().Connect(ctx, serverTransport, nil)
		if err != nil {
			b.Errorf("connect server: %v", err)
			return
		}
		defer serverSession.Close()

		client := sdk.NewClient(&sdk.Implementation{Name: "bench-client", Version: "1.0.0"}, nil)
		cs, err := client.Connect(ctx, clientTransport, nil)
		if err != nil {
			b.Errorf("connect client: %v", err)
			return
		}
		defer cs.Close()

		params := &sdk.CallToolParams{Name: "get_customer", Arguments: map[string]any{"customer_id": "1001"}}
		for pb.Next() {
			if _, err := cs.CallTool(ctx, params); err != nil {
				b.Errorf("tools/call: %v", err)
				return
			}
		}
	})
}

// BenchmarkServiceGetCustomer isolates the service layer, so a regression can
// be attributed to business logic rather than to protocol overhead.
func BenchmarkServiceGetCustomer(b *testing.B) {
	svc, _ := testutil.NewService()
	ctx := testutil.Context()

	b.ReportAllocs()
	for b.Loop() {
		if _, err := svc.GetCustomer(ctx, "1001"); err != nil {
			b.Fatalf("GetCustomer: %v", err)
		}
	}
}

// BenchmarkBackendLatency measures the cost the server adds on top of a slow
// backend, which is the number that decides whether a timeout budget is
// realistic.
func BenchmarkBackendLatency(b *testing.B) {
	for _, latency := range []time.Duration{0, time.Millisecond, 10 * time.Millisecond} {
		b.Run(latency.String(), func(b *testing.B) {
			svc, be := testutil.NewService()
			be.GetCustomerFn = func(ctx context.Context, tenant, id string) (domain.Customer, error) {
				if latency > 0 {
					select {
					case <-time.After(latency):
					case <-ctx.Done():
						return domain.Customer{}, ctx.Err()
					}
				}
				return be.Inner.GetCustomer(ctx, tenant, id)
			}
			h := customer.NewHandlers(svc)
			ctx := testutil.Context()

			b.ReportAllocs()
			for b.Loop() {
				if _, err := h.GetCustomer(ctx, customer.GetCustomerInput{CustomerID: "1001"}); err != nil {
					b.Fatalf("GetCustomer: %v", err)
				}
			}
		})
	}
}

// BenchmarkPaginationWalk measures the cost of walking a listing page by page,
// which is what a model doing research over an account base actually does.
func BenchmarkPaginationWalk(b *testing.B) {
	svc, _ := testutil.NewService()
	ctx := testutil.Context()

	b.ReportAllocs()
	for b.Loop() {
		cursor := ""
		for {
			res, err := svc.SearchCustomers(ctx, services.SearchRequest{
				Status: domain.StatusActive, Limit: 1, Cursor: cursor,
			})
			if err != nil {
				b.Fatalf("SearchCustomers: %v", err)
			}
			if res.NextCursor == "" {
				break
			}
			cursor = res.NextCursor
		}
	}
}

// BenchmarkNotificationIdempotency measures the replay path, which every retry
// takes and which must stay cheap enough not to encourage skipping the key.
func BenchmarkNotificationIdempotency(b *testing.B) {
	svc, _ := testutil.NewService()
	ctx := testutil.Context()

	var seq atomic.Int64
	b.ReportAllocs()
	for b.Loop() {
		key := "bench-key-" + strconv.FormatInt(seq.Add(1), 10)
		n := domain.Notification{
			CustomerID: "1001", Channel: domain.ChannelSMS, Body: "hello", IdempotencyKey: key,
		}
		if _, err := svc.SendNotification(ctx, n); err != nil {
			b.Fatalf("first send: %v", err)
		}
		if _, err := svc.SendNotification(ctx, n); err != nil {
			b.Fatalf("replay: %v", err)
		}
	}
}
