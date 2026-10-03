package backend

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/verma29897/mcp-server/internal/domain"
)

// fastRetry keeps the backoff out of the test's wall clock while preserving
// the retry logic under test.
func fastRetry(attempts int) RetryConfig {
	return RetryConfig{MaxAttempts: attempts, BaseDelay: time.Millisecond, MaxDelay: 2 * time.Millisecond}
}

func newResilientBackend(t *testing.T, retry RetryConfig, circuit CircuitConfig, h http.HandlerFunc) *HTTP {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)

	be, err := NewHTTP(HTTPOptions{
		BaseURL: ts.URL,
		Timeout: 2 * time.Second,
		Retry:   retry,
		Circuit: circuit,
	})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	t.Cleanup(func() { _ = be.Close() })
	return be
}

func TestReadIsRetriedThroughATransientFailure(t *testing.T) {
	var calls atomic.Int32
	be := newResilientBackend(t, fastRetry(3), CircuitConfig{}, func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(domain.Customer{ID: "1001", Name: "Acme"})
	})

	got, err := be.GetCustomer(context.Background(), "acme", "1001")
	if err != nil {
		t.Fatalf("GetCustomer: %v", err)
	}
	if got.ID != "1001" {
		t.Errorf("customer = %+v, want 1001", got)
	}
	if n := calls.Load(); n != 3 {
		t.Errorf("upstream called %d times, want 3 (two failures then a success)", n)
	}
}

func TestPermanentFailuresAreNotRetried(t *testing.T) {
	// A 404 will be a 404 next time too. Retrying it multiplies the load on a
	// backend for no possible gain.
	tests := []struct {
		name   string
		status int
	}{
		{"not found", http.StatusNotFound},
		{"bad request", http.StatusBadRequest},
		{"forbidden", http.StatusForbidden},
		{"conflict", http.StatusConflict},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			be := newResilientBackend(t, fastRetry(3), CircuitConfig{}, func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(tc.status)
			})

			if _, err := be.GetCustomer(context.Background(), "acme", "1001"); err == nil {
				t.Fatal("expected an error")
			}
			if n := calls.Load(); n != 1 {
				t.Errorf("upstream called %d times, want exactly 1", n)
			}
		})
	}
}

func TestNonIdempotentOperationsAreNeverRetried(t *testing.T) {
	// A retried DELETE reports NOT_FOUND for a deletion that succeeded, and a
	// retried notification contacts the customer twice. Neither is acceptable,
	// so neither is retried regardless of how transient the failure looks.
	t.Run("delete", func(t *testing.T) {
		var calls atomic.Int32
		be := newResilientBackend(t, fastRetry(3), CircuitConfig{}, func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.WriteHeader(http.StatusBadGateway)
		})
		_ = be.DeleteCustomer(context.Background(), "acme", "1001", nil)
		if n := calls.Load(); n != 1 {
			t.Errorf("delete attempted %d times, want 1", n)
		}
	})

	t.Run("notification", func(t *testing.T) {
		var calls atomic.Int32
		be := newResilientBackend(t, fastRetry(3), CircuitConfig{}, func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.WriteHeader(http.StatusBadGateway)
		})
		_, _ = be.SendNotification(context.Background(), domain.Notification{
			CustomerID: "1001", TenantID: "acme", Channel: domain.ChannelEmail,
			Subject: "s", Body: "b",
		})
		if n := calls.Load(); n != 1 {
			t.Errorf("notification attempted %d times, want 1: a retry is a second message", n)
		}
	})

	t.Run("update with an optimistic lock", func(t *testing.T) {
		var calls atomic.Int32
		be := newResilientBackend(t, fastRetry(3), CircuitConfig{}, func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.WriteHeader(http.StatusBadGateway)
		})
		version := 3
		_, _ = be.UpdateCustomer(context.Background(), "acme", "1001", domain.CustomerPatch{ExpectedVersion: &version})
		if n := calls.Load(); n != 1 {
			t.Errorf("conditional update attempted %d times, want 1: the first may have succeeded", n)
		}
	})
}

func TestRetryStopsWhenTheCallerGivesUp(t *testing.T) {
	var calls atomic.Int32
	be := newResilientBackend(t, RetryConfig{MaxAttempts: 5, BaseDelay: 200 * time.Millisecond, MaxDelay: time.Second},
		CircuitConfig{}, func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.WriteHeader(http.StatusBadGateway)
		})

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := be.GetCustomer(ctx, "acme", "1001")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error")
	}
	// The point: a cancelled request must abandon its remaining retries rather
	// than continuing to load the backend for an answer nobody wants.
	if elapsed > 2*time.Second {
		t.Errorf("retries continued for %s after the caller gave up", elapsed)
	}
	if n := calls.Load(); n > 2 {
		t.Errorf("upstream called %d times after cancellation", n)
	}
}

func TestCircuitOpensAndFailsFast(t *testing.T) {
	var calls atomic.Int32
	be := newResilientBackend(t, RetryConfig{MaxAttempts: 1},
		CircuitConfig{FailureThreshold: 3, OpenDuration: time.Minute, HalfOpenSuccesses: 1},
		func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
		})

	for i := 0; i < 3; i++ {
		if _, err := be.GetCustomer(context.Background(), "acme", "1001"); err == nil {
			t.Fatalf("call %d unexpectedly succeeded", i+1)
		}
	}
	if got := be.CircuitState(); got != CircuitOpen {
		t.Fatalf("circuit state = %v, want open after the failure threshold", got)
	}

	before := calls.Load()
	_, err := be.GetCustomer(context.Background(), "acme", "1001")
	if err == nil {
		t.Fatal("a call through an open circuit succeeded")
	}
	if domain.CodeOf(err) != domain.CodeBackendError {
		t.Errorf("code = %s, want %s", domain.CodeOf(err), domain.CodeBackendError)
	}
	// Failing fast is the point: the struggling backend must stop receiving
	// traffic, not merely receive it with an error attached.
	if calls.Load() != before {
		t.Error("an open circuit still sent the request upstream")
	}
}

func TestCircuitRecoversThroughHalfOpen(t *testing.T) {
	var healthy atomic.Bool
	be := newResilientBackend(t, RetryConfig{MaxAttempts: 1},
		CircuitConfig{FailureThreshold: 2, OpenDuration: 20 * time.Millisecond, HalfOpenSuccesses: 1},
		func(w http.ResponseWriter, _ *http.Request) {
			if !healthy.Load() {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(domain.Customer{ID: "1001"})
		})

	for i := 0; i < 2; i++ {
		_, _ = be.GetCustomer(context.Background(), "acme", "1001")
	}
	if be.CircuitState() != CircuitOpen {
		t.Fatal("circuit did not open")
	}

	healthy.Store(true)
	time.Sleep(40 * time.Millisecond)

	if _, err := be.GetCustomer(context.Background(), "acme", "1001"); err != nil {
		t.Fatalf("the probe after the open window failed: %v", err)
	}
	if got := be.CircuitState(); got != CircuitClosed {
		t.Errorf("circuit state = %v, want closed after a successful probe", got)
	}
}

func TestNotFoundDoesNotOpenTheCircuit(t *testing.T) {
	// A missing customer is a correct answer. Letting it trip the breaker would
	// take the backend out of service over ordinary use.
	be := newResilientBackend(t, RetryConfig{MaxAttempts: 1},
		CircuitConfig{FailureThreshold: 2, OpenDuration: time.Minute},
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})

	for i := 0; i < 10; i++ {
		_, _ = be.GetCustomer(context.Background(), "acme", "missing")
	}
	if got := be.CircuitState(); got != CircuitClosed {
		t.Errorf("circuit state = %v, want closed: 404s are answers, not faults", got)
	}
}

func TestBackoffGrowsAndStaysBounded(t *testing.T) {
	rc := RetryConfig{BaseDelay: 100 * time.Millisecond, MaxDelay: time.Second, Jitter: false}

	first := rc.delay(1, func() float64 { return 1 })
	second := rc.delay(2, func() float64 { return 1 })
	if second <= first {
		t.Errorf("delays %s then %s; backoff must grow", first, second)
	}
	if got := rc.delay(20, func() float64 { return 1 }); got > rc.MaxDelay {
		t.Errorf("delay %s exceeds the cap %s", got, rc.MaxDelay)
	}
}

func TestJitterSpreadsRetriesWithoutRemovingTheFloor(t *testing.T) {
	// Without jitter a fleet retries in lockstep and delivers a synchronised
	// second spike to a backend that is already struggling.
	rc := RetryConfig{BaseDelay: time.Second, MaxDelay: time.Minute, Jitter: true}

	low := rc.delay(1, func() float64 { return 0 })
	high := rc.delay(1, func() float64 { return 1 })
	if low == high {
		t.Fatal("jitter produced identical delays for the extremes of the random range")
	}
	if low < rc.BaseDelay/2 {
		t.Errorf("jittered delay %s is below the half-interval floor", low)
	}
	if high > rc.BaseDelay {
		t.Errorf("jittered delay %s exceeds the un-jittered interval", high)
	}
}
