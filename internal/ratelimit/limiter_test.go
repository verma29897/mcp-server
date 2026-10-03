package ratelimit

import (
	"sync"
	"testing"
	"time"
)

// at returns a limiter whose clock the test drives, so budget refill is
// deterministic rather than a sleep.
func at(cfg Config, start time.Time) (*Limiter, *time.Time) {
	l := New(cfg)
	now := start
	l.now = func() time.Time { return now }
	return l, &now
}

func TestDisabledLimiterAllowsEverything(t *testing.T) {
	l := New(Config{})
	if l.Enabled() {
		t.Fatal("a limiter with no rules reports itself enabled")
	}
	for i := 0; i < 1000; i++ {
		if d := l.Allow(Request{IP: "1.2.3.4", Principal: "p", Tenant: "t"}); !d.Allowed {
			t.Fatalf("request %d refused by a disabled limiter", i)
		}
	}
	if l.Size() != 0 {
		t.Errorf("a disabled limiter allocated %d buckets", l.Size())
	}
}

func TestPerPrincipalBudgetIsSpentAndRefilled(t *testing.T) {
	start := time.Now()
	l, now := at(Config{PerPrincipal: Rule{PerMinute: 60, Burst: 3}}, start)

	req := Request{IP: "1.2.3.4", Principal: "user-1", Tenant: "acme"}
	for i := 0; i < 3; i++ {
		if d := l.Allow(req); !d.Allowed {
			t.Fatalf("request %d refused inside the burst allowance", i+1)
		}
	}
	d := l.Allow(req)
	if d.Allowed {
		t.Fatal("the fourth request was allowed past a burst of three")
	}
	if d.Scope != "principal" {
		t.Errorf("scope = %q, want principal", d.Scope)
	}
	if d.RetryAfter <= 0 {
		t.Error("a refusal carries no retry hint, so a client has nothing to wait for")
	}

	// 60/minute is one per second, so a second of elapsed time buys one call.
	*now = now.Add(time.Second)
	if d := l.Allow(req); !d.Allowed {
		t.Error("the budget did not refill after a second")
	}
}

func TestLayersAreIndependent(t *testing.T) {
	start := time.Now()
	l, _ := at(Config{PerPrincipal: Rule{PerMinute: 60, Burst: 1}}, start)

	if d := l.Allow(Request{IP: "1.1.1.1", Principal: "user-1", Tenant: "acme"}); !d.Allowed {
		t.Fatal("first caller refused")
	}
	if d := l.Allow(Request{IP: "1.1.1.1", Principal: "user-1", Tenant: "acme"}); d.Allowed {
		t.Fatal("the same principal was allowed twice on a burst of one")
	}
	// A different principal has its own budget: one noisy client must not
	// starve every other client of the same deployment.
	if d := l.Allow(Request{IP: "1.1.1.1", Principal: "user-2", Tenant: "acme"}); !d.Allowed {
		t.Fatal("a second principal was refused because the first exhausted its own budget")
	}
}

func TestRejectionAtOneLayerDoesNotSpendAnother(t *testing.T) {
	start := time.Now()
	// The IP layer is exhausted immediately; the principal layer is generous.
	l, _ := at(Config{
		PerIP:        Rule{PerMinute: 60, Burst: 1},
		PerPrincipal: Rule{PerMinute: 600, Burst: 5},
	}, start)

	flood := Request{IP: "9.9.9.9", Principal: "victim", Tenant: "acme"}
	if d := l.Allow(flood); !d.Allowed {
		t.Fatal("first request refused")
	}
	for i := 0; i < 4; i++ {
		if d := l.Allow(flood); d.Allowed || d.Scope != "ip" {
			t.Fatalf("request %d: got %+v, want a refusal at the ip layer", i+2, d)
		}
	}

	// The principal's own budget must be almost untouched: otherwise a flood
	// from one address would exhaust the quota of the token it is impersonating,
	// turning a throttle into a denial of service against a legitimate client.
	// Each of these arrives from its own address so that the IP layer, which
	// also has a burst of one, does not mask the thing being measured.
	for i := 0; i < 4; i++ {
		fromElsewhere := Request{
			IP:        "10.0.0." + string(rune('1'+i)),
			Principal: "victim",
			Tenant:    "acme",
		}
		if d := l.Allow(fromElsewhere); !d.Allowed {
			t.Fatalf("the victim's own budget was spent by the flood (refused at %d, scope %q)", i+1, d.Scope)
		}
	}
}

func TestToolRuleIsStricterThanThePrincipalRule(t *testing.T) {
	start := time.Now()
	l, _ := at(Config{
		PerPrincipal: Rule{PerMinute: 600, Burst: 50},
		PerTool: map[string]Rule{
			"send_customer_notification": {PerMinute: 6, Burst: 2},
		},
	}, start)

	notify := Request{IP: "1.1.1.1", Principal: "user-1", Tenant: "acme", Tool: "send_customer_notification"}
	for i := 0; i < 2; i++ {
		if d := l.Allow(notify); !d.Allowed {
			t.Fatalf("notification %d refused inside its burst", i+1)
		}
	}
	d := l.Allow(notify)
	if d.Allowed || d.Scope != "tool" {
		t.Fatalf("got %+v, want a refusal at the tool layer: a loop must not keep messaging a customer", d)
	}

	// A cheaper tool is unaffected by the notification budget.
	read := Request{IP: "1.1.1.1", Principal: "user-1", Tenant: "acme", Tool: "get_customer"}
	if d := l.Allow(read); !d.Allowed {
		t.Error("a read was refused because the notification budget was exhausted")
	}
}

func TestTenantBudgetIsSharedAcrossPrincipals(t *testing.T) {
	start := time.Now()
	l, _ := at(Config{PerTenant: Rule{PerMinute: 60, Burst: 2}}, start)

	if d := l.Allow(Request{IP: "1.1.1.1", Principal: "a", Tenant: "acme"}); !d.Allowed {
		t.Fatal("first refused")
	}
	if d := l.Allow(Request{IP: "2.2.2.2", Principal: "b", Tenant: "acme"}); !d.Allowed {
		t.Fatal("second refused")
	}
	d := l.Allow(Request{IP: "3.3.3.3", Principal: "c", Tenant: "acme"})
	if d.Allowed || d.Scope != "tenant" {
		t.Fatalf("got %+v, want the tenant budget to bind across principals", d)
	}
	if d := l.Allow(Request{IP: "4.4.4.4", Principal: "d", Tenant: "northwind"}); !d.Allowed {
		t.Error("one tenant exhausting its budget throttled another")
	}
}

func TestEmptyKeysAreSkippedRatherThanShared(t *testing.T) {
	start := time.Now()
	l, _ := at(Config{PerPrincipal: Rule{PerMinute: 60, Burst: 1}}, start)

	// An anonymous caller has no principal. Bucketing every such caller into a
	// single "" key would let one of them throttle all the others.
	for i := 0; i < 10; i++ {
		if d := l.Allow(Request{IP: "1.1.1.1", Tenant: "acme"}); !d.Allowed {
			t.Fatalf("request %d refused on an empty principal key", i+1)
		}
	}
}

func TestIdleBucketsAreEvicted(t *testing.T) {
	start := time.Now()
	l, now := at(Config{PerPrincipal: Rule{PerMinute: 600}, TTL: time.Minute}, start)

	for i := 0; i < 50; i++ {
		l.Allow(Request{IP: "1.1.1.1", Principal: string(rune('a'+i%26)) + "-caller", Tenant: "acme"})
	}
	before := l.Size()
	if before == 0 {
		t.Fatal("no buckets were created")
	}

	// Long after the TTL, one more request triggers the sweep.
	*now = now.Add(2 * time.Minute)
	l.Allow(Request{IP: "1.1.1.1", Principal: "fresh", Tenant: "acme"})
	if after := l.Size(); after >= before {
		t.Errorf("bucket count went from %d to %d; idle buckets were not evicted", before, after)
	}
}

func TestConcurrentUseIsSafe(t *testing.T) {
	l := New(Config{PerPrincipal: Rule{PerMinute: 60000, Burst: 1000}, PerIP: Rule{PerMinute: 60000, Burst: 1000}})

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				l.Allow(Request{IP: "1.1.1.1", Principal: "p", Tenant: "acme"})
			}
		}(i)
	}
	wg.Wait()
}
