package backend

import (
	"context"
	"errors"
	"math"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/verma29897/mcp-server/internal/domain"
)

// Resilience configures how upstream failures are absorbed.
type RetryConfig struct {
	// MaxAttempts includes the first try. 1 disables retries.
	MaxAttempts int
	// BaseDelay is the first backoff interval; each subsequent one doubles.
	BaseDelay time.Duration
	// MaxDelay caps the backoff.
	MaxDelay time.Duration
	// Jitter randomises each delay in [d/2, d].
	//
	// Without it, a fleet of replicas that all saw the same upstream blip
	// retries in lockstep and delivers a second, synchronised load spike to a
	// backend that is already struggling.
	Jitter bool
}

// DefaultRetry is a conservative policy: three attempts over roughly a second.
func DefaultRetry() RetryConfig {
	return RetryConfig{MaxAttempts: 3, BaseDelay: 100 * time.Millisecond, MaxDelay: 2 * time.Second, Jitter: true}
}

// delay computes the backoff before attempt n (1-based, so n=1 is the first
// retry).
func (rc RetryConfig) delay(n int, rnd func() float64) time.Duration {
	d := float64(rc.BaseDelay) * math.Pow(2, float64(n-1))
	if max := float64(rc.MaxDelay); rc.MaxDelay > 0 && d > max {
		d = max
	}
	if rc.Jitter {
		// Full jitter over the lower half keeps a floor, so a retry storm is
		// spread without any attempt firing immediately.
		d = d/2 + d/2*rnd()
	}
	return time.Duration(d)
}

// retryable reports whether an operation may be retried after err.
//
// Two conditions must both hold. The error has to be transient - a 404 or a
// validation failure will fail identically on the next attempt, and retrying it
// only multiplies the load. And the operation has to be safe to repeat: a
// retried DELETE or a retried notification is a duplicate side effect, which is
// worse than the failure being reported. This is why send_customer_notification
// carries an idempotency key instead of relying on retries.
func retryable(err error, idempotent bool) bool {
	if !idempotent {
		return false
	}
	de, ok := domain.AsError(err)
	if !ok {
		return false
	}
	switch de.Code {
	case domain.CodeBackendError, domain.CodeTimeout, domain.CodeRateLimited:
		return de.Retryable
	default:
		return false
	}
}

// CircuitConfig configures the breaker.
type CircuitConfig struct {
	// FailureThreshold is how many consecutive failures open the circuit.
	FailureThreshold int
	// OpenDuration is how long the circuit stays open before a probe.
	OpenDuration time.Duration
	// HalfOpenSuccesses is how many probes must succeed to close it again.
	HalfOpenSuccesses int
}

// DefaultCircuit opens after five consecutive failures and probes every 30s.
func DefaultCircuit() CircuitConfig {
	return CircuitConfig{FailureThreshold: 5, OpenDuration: 30 * time.Second, HalfOpenSuccesses: 2}
}

// CircuitState is the breaker's current position.
type CircuitState int

const (
	// CircuitClosed passes every call through.
	CircuitClosed CircuitState = iota
	// CircuitOpen rejects immediately.
	CircuitOpen
	// CircuitHalfOpen admits one probe at a time.
	CircuitHalfOpen
)

func (s CircuitState) String() string {
	switch s {
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half-open"
	default:
		return "closed"
	}
}

// ErrCircuitOpen is the internal cause recorded when the breaker rejects.
var ErrCircuitOpen = errors.New("circuit breaker is open")

// circuit is a three-state breaker.
//
// The point of the breaker is not to protect this server; it is to stop this
// server from being the thing that keeps a struggling backend down. When every
// call is timing out, continuing to send them costs a connection and a
// goroutine each, adds queueing delay at the backend, and makes every MCP
// request wait the full timeout before failing. Failing fast turns a slow,
// cascading outage into a quick, legible one.
type circuit struct {
	cfg CircuitConfig
	now func() time.Time

	mu            sync.Mutex
	state         CircuitState
	failures      int
	successes     int
	openedAt      time.Time
	probeInFlight bool
}

func newCircuit(cfg CircuitConfig) *circuit {
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = 5
	}
	if cfg.OpenDuration <= 0 {
		cfg.OpenDuration = 30 * time.Second
	}
	if cfg.HalfOpenSuccesses <= 0 {
		cfg.HalfOpenSuccesses = 2
	}
	return &circuit{cfg: cfg, now: time.Now}
}

// allow reports whether a call may proceed.
func (c *circuit) allow() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	switch c.state {
	case CircuitClosed:
		return true
	case CircuitOpen:
		if c.now().Sub(c.openedAt) < c.cfg.OpenDuration {
			return false
		}
		c.state = CircuitHalfOpen
		c.successes = 0
		c.probeInFlight = true
		return true
	default: // half-open
		// One probe at a time: admitting the full load into a backend that has
		// just come back is how a recovering service is knocked over again.
		if c.probeInFlight {
			return false
		}
		c.probeInFlight = true
		return true
	}
}

// record updates the breaker with the outcome of a call.
func (c *circuit) record(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.probeInFlight = false
	// Only an upstream fault counts. A 404 is a correct answer, and letting it
	// open the circuit would take the backend out over a missing customer.
	if !isUpstreamFault(err) {
		c.failures = 0
		if c.state == CircuitHalfOpen {
			c.successes++
			if c.successes >= c.cfg.HalfOpenSuccesses {
				c.state = CircuitClosed
				c.successes = 0
			}
		}
		return
	}

	c.failures++
	switch c.state {
	case CircuitHalfOpen:
		c.state = CircuitOpen
		c.openedAt = c.now()
		c.successes = 0
	case CircuitClosed:
		if c.failures >= c.cfg.FailureThreshold {
			c.state = CircuitOpen
			c.openedAt = c.now()
		}
	}
}

// State reports the current position, for a metric gauge.
func (c *circuit) State() CircuitState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

func isUpstreamFault(err error) bool {
	if err == nil {
		return false
	}
	de, ok := domain.AsError(err)
	if !ok {
		return true
	}
	switch de.Code {
	case domain.CodeBackendError, domain.CodeTimeout:
		return true
	default:
		return false
	}
}

// sleep waits for d or until ctx is done, whichever comes first.
func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func jitterSource() float64 { return rand.Float64() }
