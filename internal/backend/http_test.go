package backend

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/verma29897/mcp-server/internal/domain"
)

// newTestBackend starts a fake upstream API and returns a client for it.
func newTestBackend(t *testing.T, h http.HandlerFunc) (*HTTP, *httptest.Server) {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)

	be, err := NewHTTP(HTTPOptions{
		BaseURL: ts.URL,
		Token:   "upstream-token",
		Timeout: 5 * time.Second,
		// One attempt: these tests assert what a single call does, and a retry
		// would make a "was this classified correctly?" test also depend on
		// how many times the classification happened.
		Retry: RetryConfig{MaxAttempts: 1},
	})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	t.Cleanup(func() { _ = be.Close() })
	return be, ts
}

func TestHTTPBackendSendsAuthorization(t *testing.T) {
	var gotAuth, gotPath, gotTenant string
	be, _ := newTestBackend(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotTenant = r.Header.Get(TenantHeader)
		_ = json.NewEncoder(w).Encode(domain.Customer{ID: "1001", Name: "Acme"})
	})

	if _, err := be.GetCustomer(context.Background(), "acme", "1001"); err != nil {
		t.Fatalf("GetCustomer: %v", err)
	}
	if gotAuth != "Bearer upstream-token" {
		t.Errorf("Authorization = %q, want the configured bearer token", gotAuth)
	}
	if gotPath != "/customers/1001" {
		t.Errorf("path = %q, want /customers/1001", gotPath)
	}
	// The tenant must reach the upstream API, so that its own authorization
	// layer scopes the query rather than trusting this server to have done it.
	if gotTenant != "acme" {
		t.Errorf("%s = %q, want the caller's tenant", TenantHeader, gotTenant)
	}
}

func TestHTTPBackendEscapesPathSegments(t *testing.T) {
	var gotPath string
	be, _ := newTestBackend(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		w.WriteHeader(http.StatusNotFound)
	})

	// The service layer rejects ids like this, but the backend must not rely
	// on that: a raw id must never be able to climb the URL path.
	_, _ = be.GetCustomer(context.Background(), "acme", "../admin")

	if strings.Contains(gotPath, "../") {
		t.Errorf("escaped path = %q, want the id percent-encoded", gotPath)
	}
}

func TestHTTPBackendClassifiesStatusCodes(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		wantCode domain.Code
	}{
		{"not found", http.StatusNotFound, domain.CodeNotFound},
		{"unauthorized", http.StatusUnauthorized, domain.CodeUnauthorized},
		{"forbidden", http.StatusForbidden, domain.CodeForbidden},
		{"rate limited", http.StatusTooManyRequests, domain.CodeRateLimited},
		{"gateway timeout", http.StatusGatewayTimeout, domain.CodeTimeout},
		{"bad request", http.StatusBadRequest, domain.CodeInvalidArgument},
		{"server error", http.StatusInternalServerError, domain.CodeBackendError},
		{"bad gateway", http.StatusBadGateway, domain.CodeBackendError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			be, _ := newTestBackend(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				// A body that must never reach a client.
				_, _ = w.Write([]byte(`{"error":"db password=hunter2 at 10.0.0.5"}`))
			})

			_, err := be.GetCustomer(context.Background(), "acme", "1001")
			if err == nil {
				t.Fatal("expected an error")
			}
			de, ok := domain.AsError(err)
			if !ok {
				t.Fatalf("error %v is not a *domain.Error", err)
			}
			if de.Code != tc.wantCode {
				t.Errorf("code = %s, want %s", de.Code, tc.wantCode)
			}
			if strings.Contains(de.Error(), "hunter2") || strings.Contains(de.Error(), "10.0.0.5") {
				t.Errorf("client-facing message leaks the upstream body: %q", de.Error())
			}
			if !strings.Contains(de.Detail(), "hunter2") {
				t.Errorf("Detail() should keep the upstream body for logs, got %q", de.Detail())
			}
		})
	}
}

func TestHTTPBackendRateLimitCarriesRetryAfter(t *testing.T) {
	be, _ := newTestBackend(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
	})

	_, err := be.GetCustomer(context.Background(), "acme", "1001")
	de, ok := domain.AsError(err)
	if !ok {
		t.Fatalf("error %v is not a *domain.Error", err)
	}
	if !strings.Contains(de.Message, "30") {
		t.Errorf("message = %q, want it to surface the Retry-After hint", de.Message)
	}
	if !de.Retryable {
		t.Error("a rate limit should be retryable")
	}
}

func TestHTTPBackendHonoursContextCancellation(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	be, _ := newTestBackend(t, func(w http.ResponseWriter, r *http.Request) {
		// Hold the request until the client's context expires.
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := be.GetCustomer(ctx, "acme", "1001")
	elapsed := time.Since(start)

	de, ok := domain.AsError(err)
	if !ok {
		t.Fatalf("error %v is not a *domain.Error", err)
	}
	if de.Code != domain.CodeTimeout {
		t.Errorf("code = %s, want %s", de.Code, domain.CodeTimeout)
	}
	if elapsed > 2*time.Second {
		t.Errorf("call took %s; the request should abort as soon as the context expires", elapsed)
	}
}

func TestHTTPBackendSearchBuildsQuery(t *testing.T) {
	var gotQuery string
	be, _ := newTestBackend(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"items":[{"customer_id":"1001","name":"Acme"}]}`))
	})

	got, err := be.SearchCustomers(context.Background(), domain.SearchQuery{
		TenantID: "acme",
		Text:     "acme",
		Status:   domain.StatusActive,
		Tier:     domain.TierEnterprise,
		Limit:    25,
	})
	if err != nil {
		t.Fatalf("SearchCustomers: %v", err)
	}
	if len(got.Items) != 1 || got.Items[0].ID != "1001" {
		t.Fatalf("got %+v, want one customer 1001", got.Items)
	}
	for _, want := range []string{"q=acme", "status=active", "tier=enterprise", "limit=25"} {
		if !strings.Contains(gotQuery, want) {
			t.Errorf("query %q is missing %q", gotQuery, want)
		}
	}
}

func TestHTTPBackendRejectsNonHTTPBaseURL(t *testing.T) {
	if _, err := NewHTTP(HTTPOptions{BaseURL: "ftp://example.com", Timeout: time.Second}); err == nil {
		t.Fatal("NewHTTP accepted a non-HTTP base URL")
	}
}

func TestHTTPBackendDeleteAcceptsEmptyBody(t *testing.T) {
	be, _ := newTestBackend(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	if err := be.DeleteCustomer(context.Background(), "acme", "1001", nil); err != nil {
		t.Fatalf("DeleteCustomer: %v", err)
	}
}
