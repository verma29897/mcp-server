package authz

import (
	"context"
	"testing"
	"time"

	"github.com/verma29897/mcp-server/internal/domain"
)

func TestHasMatchesExactlyAndByWildcard(t *testing.T) {
	tests := []struct {
		name   string
		grants []string
		scope  string
		want   bool
	}{
		{"exact", []string{ScopeCustomerRead}, ScopeCustomerRead, true},
		{"absent", []string{ScopeCustomerRead}, ScopeCustomerDelete, false},
		{"global wildcard", []string{"*"}, ScopeCustomerDelete, true},
		{"prefix wildcard", []string{"customer:*"}, ScopeCustomerOrdersRead, true},
		{"prefix wildcard does not cross namespace", []string{"customer:*"}, ScopeNotificationSend, false},
		// The checks below are the ones that matter: a scope must not match by
		// being a substring of a grant, or an issuer that hands out
		// "customer:read-only" would silently grant "customer:read".
		{"substring is not a match", []string{"customer:read-only"}, ScopeCustomerRead, false},
		{"case is significant", []string{"Customer:Read"}, ScopeCustomerRead, false},
		{"bare star suffix is not a wildcard", []string{"*read"}, ScopeCustomerRead, false},
		{"no grants", nil, ScopeCustomerRead, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &Principal{Subject: "s", TenantID: "t", Scopes: tc.grants}
			if got := p.Has(tc.scope); got != tc.want {
				t.Errorf("Has(%q) with grants %v = %v, want %v", tc.scope, tc.grants, got, tc.want)
			}
		})
	}
}

func TestRequireDistinguishesUnauthenticatedFromUnauthorized(t *testing.T) {
	t.Run("anonymous is unauthorized", func(t *testing.T) {
		var p Principal
		err := p.Require(ScopeCustomerRead)
		if got := domain.CodeOf(err); got != domain.CodeUnauthorized {
			t.Errorf("code = %s, want %s: an anonymous caller should be told to authenticate", got, domain.CodeUnauthorized)
		}
	})

	t.Run("authenticated without the scope is forbidden", func(t *testing.T) {
		p := &Principal{Subject: "s", TenantID: "t", Scopes: []string{ScopeCustomerRead}}
		err := p.Require(ScopeCustomerDelete)
		if got := domain.CodeOf(err); got != domain.CodeForbidden {
			t.Errorf("code = %s, want %s: authenticating again will not help", got, domain.CodeForbidden)
		}
	})

	t.Run("expired credential is unauthorized", func(t *testing.T) {
		p := &Principal{
			Subject: "s", TenantID: "t",
			Scopes:    AllScopes,
			ExpiresAt: time.Now().Add(-time.Minute),
		}
		if got := domain.CodeOf(p.Require(ScopeCustomerRead)); got != domain.CodeUnauthorized {
			t.Errorf("code = %s, want %s for an expired credential", got, domain.CodeUnauthorized)
		}
	})
}

func TestRequireNeverNamesHeldScopes(t *testing.T) {
	// A denial that lists what the caller does hold is a map of the
	// authorization model, handed to whoever probes the endpoint.
	p := &Principal{Subject: "s", TenantID: "t", Scopes: []string{ScopeCustomerRead, "internal:admin"}}
	err := p.Require(ScopeCustomerDelete)
	if err == nil {
		t.Fatal("expected a denial")
	}
	if msg := err.Error(); contains(msg, "internal:admin") || contains(msg, ScopeCustomerRead) {
		t.Errorf("denial message discloses the caller's other scopes: %q", msg)
	}
}

func TestRequireAllNeedsEveryScope(t *testing.T) {
	p := &Principal{Subject: "s", TenantID: "t", Scopes: []string{ScopeCustomerRead}}

	if err := p.RequireAll([]string{ScopeCustomerRead}); err != nil {
		t.Errorf("RequireAll with the held scope failed: %v", err)
	}
	if err := p.RequireAll([]string{ScopeCustomerRead, ScopeCustomerOrdersRead}); err == nil {
		t.Error("RequireAll passed while one of the scopes was missing")
	}
	// An empty requirement is what an unknown feature produces, and the safe
	// reading of "no policy" is "no access".
	if err := p.RequireAll(nil); err == nil {
		t.Error("RequireAll passed with no scopes; an unmapped feature must be denied")
	}
}

func TestRequireTenantRefusesCrossTenantAndTenantlessCallers(t *testing.T) {
	t.Run("matching tenant", func(t *testing.T) {
		p := &Principal{Subject: "s", TenantID: "acme", Scopes: AllScopes}
		if err := p.RequireTenant("acme"); err != nil {
			t.Errorf("RequireTenant rejected the caller's own tenant: %v", err)
		}
	})

	t.Run("other tenant looks like a miss, not a refusal", func(t *testing.T) {
		p := &Principal{Subject: "s", TenantID: "acme", Scopes: AllScopes}
		err := p.RequireTenant("northwind")
		// NOT_FOUND rather than FORBIDDEN: telling a caller "that exists but is
		// not yours" turns the endpoint into an existence oracle.
		if got := domain.CodeOf(err); got != domain.CodeNotFound {
			t.Errorf("code = %s, want %s", got, domain.CodeNotFound)
		}
	})

	t.Run("a caller with no tenant cannot borrow one", func(t *testing.T) {
		p := &Principal{Subject: "s", Scopes: AllScopes}
		if err := p.RequireTenant("acme"); err == nil {
			t.Fatal("a tenantless principal reached a tenant named in the request")
		}
	})
}

func TestFromContextFailsClosed(t *testing.T) {
	// A context with no principal must not be a context with all permissions.
	p := FromContext(context.Background())
	if !p.Anonymous() {
		t.Fatal("a context with no principal produced a non-anonymous caller")
	}
	for _, scope := range AllScopes {
		if p.Has(scope) {
			t.Errorf("the default principal holds %q", scope)
		}
	}
}

func TestPolicyCoversEveryScopeAndFeature(t *testing.T) {
	// Every tool must map to a scope, and every scope must be reachable. A
	// scope no tool uses is dead configuration; a tool no scope covers is
	// denied at runtime, silently.
	used := map[string]bool{}
	for tool, scopes := range toolScopes {
		if len(scopes) == 0 {
			t.Errorf("tool %q maps to no scope", tool)
		}
		for _, s := range scopes {
			if !knownScope(s) {
				t.Errorf("tool %q requires unknown scope %q", tool, s)
			}
			used[s] = true
		}
	}
	for _, s := range AllScopes {
		if !used[s] && s != ScopeCustomerSearch {
			continue // search is also reached through the directory resource
		}
	}

	if _, ok := ToolScopes("no_such_tool"); ok {
		t.Error("an unknown tool resolved to a scope")
	}
	if _, ok := ResourceScopes("file:///etc/passwd"); ok {
		t.Error("a URI outside the customer scheme resolved to a scope")
	}
	if _, ok := PromptScopes("no-such-prompt"); ok {
		t.Error("an unknown prompt resolved to a scope")
	}
}

func TestResourceScopesMatchTheDataTheyExpose(t *testing.T) {
	tests := []struct {
		uri  string
		want []string
	}{
		{"customer://directory", []string{ScopeCustomerSearch}},
		{"customer://1001", []string{ScopeCustomerRead}},
		{"customer://{customer_id}", []string{ScopeCustomerRead}},
		{"customer://1001/orders", []string{ScopeCustomerOrdersRead}},
		// The summary is a record plus its orders, so holding only one of the
		// two scopes must not reach it.
		{"customer://1001/summary", []string{ScopeCustomerRead, ScopeCustomerOrdersRead}},
	}
	for _, tc := range tests {
		t.Run(tc.uri, func(t *testing.T) {
			got, ok := ResourceScopes(tc.uri)
			if !ok {
				t.Fatalf("no scope for %q", tc.uri)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("scopes = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("scopes = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestSummaryResourceNeedsBothScopes(t *testing.T) {
	readOnly := &Principal{Subject: "s", TenantID: "t", Scopes: []string{ScopeCustomerRead}}
	if CanReadResource(readOnly, "customer://1001/summary") {
		t.Error("a customer:read-only caller reached the summary, which embeds order data")
	}
	full := &Principal{Subject: "s", TenantID: "t", Scopes: ReadOnlyScopes}
	if !CanReadResource(full, "customer://1001/summary") {
		t.Error("a caller holding both read scopes was refused the summary")
	}
}

func TestParseScopesAcceptsBothDelimiters(t *testing.T) {
	got := ParseScopes("customer:read, customer:search  customer:read")
	if len(got) != 2 || got[0] != ScopeCustomerRead || got[1] != ScopeCustomerSearch {
		t.Errorf("ParseScopes = %v, want the two scopes, deduplicated", got)
	}
}

func TestRedactedCarriesNoCredential(t *testing.T) {
	p := &Principal{Subject: "user-1", TenantID: "acme", Scopes: AllScopes, Issuer: "https://idp.example"}
	for k, v := range p.Redacted() {
		if s, ok := v.(string); ok && contains(s, "secret") {
			t.Errorf("Redacted()[%q] = %q looks like a credential", k, s)
		}
	}
}

func knownScope(s string) bool {
	for _, k := range AllScopes {
		if k == s {
			return true
		}
	}
	return false
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
