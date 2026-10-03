package backend

import (
	"context"
	"testing"

	"github.com/verma29897/mcp-server/internal/domain"
)

func TestMemoryPartitionsByTenant(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()

	// 1001 exists in the default tenant and 2001 in the secondary one. Neither
	// may be reachable from the other, and the refusal must look like a miss
	// rather than a refusal - see domain.NotFound.
	tests := []struct {
		tenant, id string
		wantFound  bool
	}{
		{DefaultTenant, "1001", true},
		{DefaultTenant, "2001", false},
		{SecondaryTenant, "2001", true},
		{SecondaryTenant, "1001", false},
		{"no-such-tenant", "1001", false},
	}
	for _, tc := range tests {
		_, err := m.GetCustomer(ctx, tc.tenant, tc.id)
		if tc.wantFound && err != nil {
			t.Errorf("GetCustomer(%q, %q) = %v, want the record", tc.tenant, tc.id, err)
		}
		if !tc.wantFound {
			if got := domain.CodeOf(err); got != domain.CodeNotFound {
				t.Errorf("GetCustomer(%q, %q) code = %s, want %s", tc.tenant, tc.id, got, domain.CodeNotFound)
			}
		}
	}
}

func TestMemorySearchNeverCrossesTenants(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()

	list, err := m.SearchCustomers(ctx, domain.SearchQuery{TenantID: DefaultTenant, Status: domain.StatusActive, Limit: 100})
	if err != nil {
		t.Fatalf("SearchCustomers: %v", err)
	}
	if len(list.Items) == 0 {
		t.Fatal("no results in the default tenant")
	}
	for _, c := range list.Items {
		if c.TenantID != DefaultTenant {
			t.Errorf("customer %s belongs to tenant %q", c.ID, c.TenantID)
		}
	}
}

func TestMemoryOrdersRequireTheOwningTenant(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()

	if _, err := m.ListOrders(ctx, SecondaryTenant, "1001", domain.Page{Limit: 10}); domain.CodeOf(err) != domain.CodeNotFound {
		t.Errorf("orders for another tenant's customer = %v, want NOT_FOUND", err)
	}
	list, err := m.ListOrders(ctx, DefaultTenant, "1001", domain.Page{Limit: 10})
	if err != nil {
		t.Fatalf("ListOrders: %v", err)
	}
	if len(list.Items) != 3 {
		t.Errorf("got %d orders, want 3", len(list.Items))
	}
}

func TestMemoryPaginationWalksEveryRecordExactlyOnce(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()

	seen := map[string]int{}
	after := ""
	for page := 0; page < 20; page++ {
		list, err := m.SearchCustomers(ctx, domain.SearchQuery{
			TenantID: DefaultTenant, Status: domain.StatusActive, Limit: 1, After: after,
		})
		if err != nil {
			t.Fatalf("page %d: %v", page, err)
		}
		for _, c := range list.Items {
			seen[c.ID]++
		}
		if list.NextAfter == "" {
			break
		}
		after = list.NextAfter
	}

	if len(seen) == 0 {
		t.Fatal("pagination returned nothing")
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("customer %s appeared %d times across pages, want exactly once", id, n)
		}
	}
	// The unpaginated result is the reference.
	all, err := m.SearchCustomers(ctx, domain.SearchQuery{TenantID: DefaultTenant, Status: domain.StatusActive, Limit: 100})
	if err != nil {
		t.Fatalf("SearchCustomers: %v", err)
	}
	if len(seen) != len(all.Items) {
		t.Errorf("pagination yielded %d customers, a single page yields %d", len(seen), len(all.Items))
	}
}

func TestMemoryPaginationSurvivesADeletedResumeKey(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()

	list, err := m.SearchCustomers(ctx, domain.SearchQuery{TenantID: DefaultTenant, Status: domain.StatusActive, Limit: 1})
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	if list.NextAfter == "" {
		t.Skip("only one active customer in the fixture")
	}
	if err := m.DeleteCustomer(ctx, DefaultTenant, list.NextAfter, nil); err != nil {
		t.Fatalf("delete the resume key's record: %v", err)
	}

	// The record the cursor points at is gone. Returning nothing would silently
	// truncate the listing; returning the remainder is the safe direction.
	next, err := m.SearchCustomers(ctx, domain.SearchQuery{
		TenantID: DefaultTenant, Status: domain.StatusActive, Limit: 10, After: list.NextAfter,
	})
	if err != nil {
		t.Fatalf("second page: %v", err)
	}
	if len(next.Items) == 0 {
		t.Error("a deleted resume key truncated the listing to nothing")
	}
}

func TestMemoryVersionIncrementsAndGuardsConcurrentWrites(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()

	before, err := m.GetCustomer(ctx, DefaultTenant, "1002")
	if err != nil {
		t.Fatalf("GetCustomer: %v", err)
	}
	tier := domain.TierEnterprise

	after, err := m.UpdateCustomer(ctx, DefaultTenant, "1002", domain.CustomerPatch{
		Tier:            &tier,
		ExpectedVersion: &before.Version,
	})
	if err != nil {
		t.Fatalf("UpdateCustomer: %v", err)
	}
	if after.Version != before.Version+1 {
		t.Errorf("version = %d, want %d", after.Version, before.Version+1)
	}

	// The second writer is working from the version it read before the first
	// write landed. Without the check its change would silently replace the
	// first one - the lost-update problem.
	free := domain.TierFree
	_, err = m.UpdateCustomer(ctx, DefaultTenant, "1002", domain.CustomerPatch{
		Tier:            &free,
		ExpectedVersion: &before.Version,
	})
	if got := domain.CodeOf(err); got != domain.CodeConflict {
		t.Fatalf("code = %s, want %s for a stale write", got, domain.CodeConflict)
	}

	current, err := m.GetCustomer(ctx, DefaultTenant, "1002")
	if err != nil {
		t.Fatalf("GetCustomer: %v", err)
	}
	if current.Tier != domain.TierEnterprise {
		t.Errorf("tier = %q; the refused write was applied anyway", current.Tier)
	}
}

func TestMemoryUpdateWithoutAPreconditionStillSucceeds(t *testing.T) {
	// Optimistic locking is opt-in: a caller that does not pass a version is
	// not forced to, so existing clients keep working.
	ctx := context.Background()
	m := NewMemory()

	name := "Renamed"
	if _, err := m.UpdateCustomer(ctx, DefaultTenant, "1002", domain.CustomerPatch{Name: &name}); err != nil {
		t.Fatalf("UpdateCustomer without a precondition: %v", err)
	}
}

func TestMemoryDeleteHonoursThePrecondition(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()

	stale := 99
	if err := m.DeleteCustomer(ctx, DefaultTenant, "1004", &stale); domain.CodeOf(err) != domain.CodeConflict {
		t.Fatalf("delete with a stale version = %v, want CONFLICT", err)
	}
	if _, err := m.GetCustomer(ctx, DefaultTenant, "1004"); err != nil {
		t.Fatal("the record was deleted despite the refused precondition")
	}

	current, _ := m.GetCustomer(ctx, DefaultTenant, "1004")
	if err := m.DeleteCustomer(ctx, DefaultTenant, "1004", &current.Version); err != nil {
		t.Fatalf("delete with the current version: %v", err)
	}
}

func TestMemoryNotificationRequiresTheOwningTenant(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()

	_, err := m.SendNotification(ctx, domain.Notification{
		CustomerID: "1001", TenantID: SecondaryTenant,
		Channel: domain.ChannelEmail, Subject: "s", Body: "b",
	})
	if got := domain.CodeOf(err); got != domain.CodeNotFound {
		t.Fatalf("code = %s, want %s: a message must not be sent across a tenant boundary", got, domain.CodeNotFound)
	}
	if n := len(m.Sent()); n != 0 {
		t.Errorf("%d messages were sent, want 0", n)
	}
}
