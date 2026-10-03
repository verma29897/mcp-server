// Package ratelimit bounds how fast a caller may drive the server.
//
// The threat this addresses is specific to an MCP server: the caller is a model
// in a loop. A model that misreads a result and retries, or that decides to
// enumerate a customer base one get_customer at a time, will generate a request
// storm no human would. The limiter is what turns that from an incident at the
// backend into a RATE_LIMITED result the model can see and reason about.
//
// Limits are layered, and the first one to reject wins:
//
//	per IP        - protects the endpoint before a caller is even identified
//	per principal - one token's fair share
//	per tenant    - one customer's fair share across all their tokens
//	per tool      - a stricter budget for the expensive or dangerous calls
package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Rule is one bucket's shape: a sustained rate plus a burst allowance.
type Rule struct {
	// PerMinute is the sustained rate. Zero disables this rule entirely.
	PerMinute float64
	// Burst is how many requests may arrive at once. Zero derives a burst from
	// the rate, so a rule is never accidentally configured to reject the first
	// request of a quiet minute.
	Burst int
}

// Enabled reports whether the rule constrains anything.
func (r Rule) Enabled() bool { return r.PerMinute > 0 }

func (r Rule) limit() rate.Limit { return rate.Limit(r.PerMinute / 60.0) }

func (r Rule) burst() int {
	if r.Burst > 0 {
		return r.Burst
	}
	// A tenth of a minute's allowance, floor 1: enough to absorb a client that
	// issues its opening calls back to back, small enough to stay a limit.
	if b := int(r.PerMinute / 10); b > 0 {
		return b
	}
	return 1
}

// Decision is the outcome of a limiter check.
type Decision struct {
	// Allowed reports whether the request may proceed.
	Allowed bool
	// Scope names which layer rejected it, for the metric label and the audit
	// record: "ip", "principal", "tenant" or "tool".
	Scope string
	// RetryAfter is how long the caller should wait. Always rounded up to a
	// whole second, because that is the granularity of the Retry-After header.
	RetryAfter time.Duration
}

// Config is the full set of rules.
type Config struct {
	PerIP        Rule
	PerPrincipal Rule
	PerTenant    Rule
	// PerTool overrides the per-principal rule for named tools. A tool with no
	// entry is governed by the layers above only.
	PerTool map[string]Rule
	// TTL evicts a bucket that has been idle this long, so a server that has
	// seen a million distinct principals does not hold a million limiters.
	TTL time.Duration
}

// Limiter enforces a Config.
//
// It is safe for concurrent use and holds no lock while a caller is being
// checked against more than one layer.
type Limiter struct {
	cfg Config

	mu      sync.Mutex
	buckets map[string]*bucket
	// lastSweep bounds how often eviction walks the map.
	lastSweep time.Time
	now       func() time.Time
}

type bucket struct {
	lim  *rate.Limiter
	seen time.Time
}

// New returns a limiter for cfg. A Config with no enabled rule yields a
// limiter that allows everything and allocates nothing per request.
func New(cfg Config) *Limiter {
	if cfg.TTL <= 0 {
		cfg.TTL = 10 * time.Minute
	}
	return &Limiter{
		cfg:     cfg,
		buckets: map[string]*bucket{},
		now:     time.Now,
	}
}

// Enabled reports whether any rule constrains anything.
func (l *Limiter) Enabled() bool {
	if l == nil {
		return false
	}
	if l.cfg.PerIP.Enabled() || l.cfg.PerPrincipal.Enabled() || l.cfg.PerTenant.Enabled() {
		return true
	}
	for _, r := range l.cfg.PerTool {
		if r.Enabled() {
			return true
		}
	}
	return false
}

// Request describes the caller and operation being checked.
type Request struct {
	IP        string
	Principal string
	Tenant    string
	Tool      string
}

// Allow checks req against every applicable layer.
//
// Layers are evaluated cheapest-and-broadest first. A rejection short-circuits,
// so a request refused at the IP layer does not also consume the principal's
// budget - otherwise a flood from one address would exhaust the quota of the
// legitimate token it is impersonating.
func (l *Limiter) Allow(req Request) Decision {
	if !l.Enabled() {
		return Decision{Allowed: true}
	}

	checks := []struct {
		scope string
		key   string
		rule  Rule
	}{
		{"ip", "ip:" + req.IP, l.cfg.PerIP},
		{"tenant", "tenant:" + req.Tenant, l.cfg.PerTenant},
		{"principal", "principal:" + req.Principal, l.cfg.PerPrincipal},
	}
	if req.Tool != "" {
		if rule, ok := l.cfg.PerTool[req.Tool]; ok {
			checks = append(checks, struct {
				scope string
				key   string
				rule  Rule
			}{"tool", "tool:" + req.Tool + "|" + req.Principal, rule})
		}
	}

	for _, c := range checks {
		if !c.rule.Enabled() || keyEmpty(c.key) {
			continue
		}
		lim := l.limiter(c.key, c.rule)
		res := lim.ReserveN(l.now(), 1)
		if !res.OK() {
			return Decision{Scope: c.scope, RetryAfter: time.Second}
		}
		if delay := res.DelayFrom(l.now()); delay > 0 {
			// The reservation would only be honoured in the future, which means
			// the bucket is empty. Give the token back so a rejected request
			// does not deepen the debt of the next one.
			res.CancelAt(l.now())
			return Decision{Scope: c.scope, RetryAfter: ceilSecond(delay)}
		}
	}
	return Decision{Allowed: true}
}

// limiter returns the bucket for key, creating it on first use.
func (l *Limiter) limiter(key string, rule Rule) *rate.Limiter {
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	l.sweepLocked(now)

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{lim: rate.NewLimiter(rule.limit(), rule.burst())}
		l.buckets[key] = b
	}
	b.seen = now
	return b.lim
}

// sweepLocked evicts idle buckets, at most once per TTL.
func (l *Limiter) sweepLocked(now time.Time) {
	if now.Sub(l.lastSweep) < l.cfg.TTL {
		return
	}
	l.lastSweep = now
	for k, b := range l.buckets {
		if now.Sub(b.seen) > l.cfg.TTL {
			delete(l.buckets, k)
		}
	}
}

// Size reports how many buckets are held. Exposed for tests and for a gauge.
func (l *Limiter) Size() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

func keyEmpty(key string) bool {
	for i := 0; i < len(key); i++ {
		if key[i] == ':' {
			return i == len(key)-1
		}
	}
	return true
}

func ceilSecond(d time.Duration) time.Duration {
	if d <= 0 {
		return time.Second
	}
	return d.Round(time.Second) + time.Second
}
