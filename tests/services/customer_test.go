// Package services_test covers the business rules: authorization, tenancy,
// validation, pagination, optimistic locking and idempotency - all without a
// protocol, a transport or a client.
package services_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/verma29897/mcp-server/internal/authz"
	"github.com/verma29897/mcp-server/internal/domain"
	"github.com/verma29897/mcp-server/internal/services"
	"github.com/verma29897/mcp-server/tests/testutil"
)

func newService() (services.CustomerService, *testutil.FakeBackend) {
	return testutil.NewService()
}

func requireCode(t *testing.T, err error, want domain.Code) *domain.Error {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a %s error, got nil", want)
	}
	de, ok := domain.AsError(err)
	if !ok {
		t.Fatalf("error %v (%T) is not a *domain.Error", err, err)
	}
	if de.Code != want {
		t.Fatalf("code = %s, want %s (%v)", de.Code, want, de)
	}
	return de
}

// --- authorization ---------------------------------------------------------

func TestEveryOperationRequiresItsScope(t *testing.T) {
	// The table is the authorization contract restated from the caller's side:
	// holding every scope but this one must not be enough.
	tests := []struct {
		name string
		// scope is the one permission withheld.
		scope string
		// backendMethod is what a successful call would have reached. A denial
		// must never get that far.
		backendMethod string
		call          func(context.Context, services.CustomerService) error
	}{
		{"get", authz.ScopeCustomerRead, "GetCustomer", func(ctx context.Context, s services.CustomerService) error {
			_, err := s.GetCustomer(ctx, "1001")
			return err
		}},
		{"search", authz.ScopeCustomerSearch, "SearchCustomers", func(ctx context.Context, s services.CustomerService) error {
			_, err := s.SearchCustomers(ctx, services.SearchRequest{Text: "acme"})
			return err
		}},
		{"orders", authz.ScopeCustomerOrdersRead, "ListOrders", func(ctx context.Context, s services.CustomerService) error {
			_, err := s.ListOrders(ctx, "1001", services.PageRequest{})
			return err
		}},
		{"update", authz.ScopeCustomerUpdate, "UpdateCustomer", func(ctx context.Context, s services.CustomerService) error {
			tier := domain.TierPro
			_, err := s.UpdateCustomer(ctx, "1001", domain.CustomerPatch{Tier: &tier})
			return err
		}},
		{"delete", authz.ScopeCustomerDelete, "DeleteCustomer", func(ctx context.Context, s services.CustomerService) error {
			return s.DeleteCustomer(ctx, services.DeleteRequest{CustomerID: "1004", Confirm: true})
		}},
		{"notify", authz.ScopeNotificationSend, "SendNotification", func(ctx context.Context, s services.CustomerService) error {
			_, err := s.SendNotification(ctx, domain.Notification{
				CustomerID: "1001", Channel: domain.ChannelSMS, Body: "hello",
			})
			return err
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, be := newService()

			// Everything except the scope under test.
			var others []string
			for _, s := range authz.AllScopes {
				if s != tc.scope {
					others = append(others, s)
				}
			}
			ctx := testutil.ContextAs(testutil.Principal(others...))
			requireCode(t, tc.call(ctx, svc), domain.CodeForbidden)

			// The denial must happen before the backend is touched: a refused
			// delete that still reached the store would be a disaster.
			if n := be.Calls(tc.backendMethod); n != 0 {
				t.Errorf("backend %s ran %d times after the call was denied", tc.backendMethod, n)
			}

			// With the scope, the same call works.
			ok := testutil.ContextAs(testutil.Principal(authz.AllScopes...))
			if err := tc.call(ok, svc); err != nil {
				t.Errorf("the call failed for a caller holding %q: %v", tc.scope, err)
			}
		})
	}
}

func TestAnonymousCallerReachesNothing(t *testing.T) {
	svc, be := newService()
	ctx := context.Background() // no principal at all

	if _, err := svc.GetCustomer(ctx, "1001"); domain.CodeOf(err) != domain.CodeUnauthorized {
		t.Errorf("get = %v, want UNAUTHORIZED", err)
	}
	if err := svc.DeleteCustomer(ctx, services.DeleteRequest{CustomerID: "1001", Confirm: true}); domain.CodeOf(err) != domain.CodeUnauthorized {
		t.Errorf("delete = %v, want UNAUTHORIZED", err)
	}
	if be.Calls("GetCustomer")+be.Calls("DeleteCustomer") != 0 {
		t.Error("an unauthenticated caller reached the backend")
	}
}

func TestCallerWithNoTenantIsRefused(t *testing.T) {
	svc, _ := newService()
	p := testutil.Principal()
	p.TenantID = ""

	err := requireCode(t, mustErr(svc.GetCustomer(testutil.ContextAs(p), "1001")), domain.CodeForbidden)
	if !strings.Contains(err.Message, "tenant") {
		t.Errorf("message = %q, want it to name the missing tenant", err.Message)
	}
}

func TestSummaryNeedsBothReadScopes(t *testing.T) {
	svc, _ := newService()

	// The summary combines a record with its order roll-up. A caller holding
	// only customer:read must not reach the order data through it.
	ctx := testutil.ContextAs(testutil.Principal(authz.ScopeCustomerRead))
	requireCode(t, mustErrSummary(svc.Summarize(ctx, "1001")), domain.CodeForbidden)

	full := testutil.ContextAs(testutil.Principal(authz.ScopeCustomerRead, authz.ScopeCustomerOrdersRead))
	if _, err := svc.Summarize(full, "1001"); err != nil {
		t.Errorf("a caller holding both scopes was refused: %v", err)
	}
}

// --- tenant isolation ------------------------------------------------------

func TestCrossTenantAccessLooksLikeAMiss(t *testing.T) {
	svc, _ := newService()
	// 2001 exists, in the other tenant.
	ctx := testutil.ContextAs(testutil.PrincipalIn(testutil.Tenant))

	requireCode(t, mustErr(svc.GetCustomer(ctx, "2001")), domain.CodeNotFound)

	// And from the other side, so the test is not passing because the id is
	// simply absent everywhere.
	other := testutil.ContextAs(testutil.PrincipalIn(testutil.OtherTenant))
	if _, err := svc.GetCustomer(other, "2001"); err != nil {
		t.Fatalf("the owning tenant could not read its own customer: %v", err)
	}
}

func TestSearchIsScopedToTheCallersTenant(t *testing.T) {
	svc, _ := newService()

	res, err := svc.SearchCustomers(testutil.ContextAs(testutil.PrincipalIn(testutil.OtherTenant)),
		services.SearchRequest{Status: domain.StatusActive, Limit: 100})
	if err != nil {
		t.Fatalf("SearchCustomers: %v", err)
	}
	if len(res.Customers) == 0 {
		t.Fatal("no results in the secondary tenant")
	}
	for _, c := range res.Customers {
		if c.TenantID != testutil.OtherTenant {
			t.Errorf("customer %s from tenant %q leaked into the result", c.ID, c.TenantID)
		}
	}
}

func TestServiceDropsRowsTheBackendShouldNotHaveReturned(t *testing.T) {
	// The backend is asked for one tenant. If a buggy or compromised one
	// answers with a neighbouring tenant's rows anyway, that must be caught
	// here rather than becoming a disclosure.
	svc, be := newService()
	be.SearchCustomersFn = func(context.Context, domain.SearchQuery) (domain.CustomerList, error) {
		return domain.CustomerList{Items: []domain.Customer{
			{ID: "1001", TenantID: testutil.Tenant, Name: "Ours"},
			{ID: "2001", TenantID: testutil.OtherTenant, Name: "Theirs"},
		}}, nil
	}

	res, err := svc.SearchCustomers(testutil.Context(), services.SearchRequest{Text: "a"})
	if err != nil {
		t.Fatalf("SearchCustomers: %v", err)
	}
	for _, c := range res.Customers {
		if c.TenantID == testutil.OtherTenant {
			t.Fatalf("a foreign-tenant row survived the service layer: %+v", c)
		}
	}
	if len(res.Customers) != 1 {
		t.Errorf("got %d rows, want just the caller's own", len(res.Customers))
	}
}

func TestCrossTenantWritesAndSendsAreRefused(t *testing.T) {
	svc, be := newService()
	ctx := testutil.ContextAs(testutil.PrincipalIn(testutil.Tenant))
	tier := domain.TierFree

	if _, err := svc.UpdateCustomer(ctx, "2001", domain.CustomerPatch{Tier: &tier}); domain.CodeOf(err) != domain.CodeNotFound {
		t.Errorf("cross-tenant update = %v, want NOT_FOUND", err)
	}
	if err := svc.DeleteCustomer(ctx, services.DeleteRequest{CustomerID: "2001", Confirm: true}); domain.CodeOf(err) != domain.CodeNotFound {
		t.Errorf("cross-tenant delete = %v, want NOT_FOUND", err)
	}
	_, err := svc.SendNotification(ctx, domain.Notification{
		CustomerID: "2001", Channel: domain.ChannelEmail, Subject: "s", Body: "b",
	})
	if domain.CodeOf(err) != domain.CodeNotFound {
		t.Errorf("cross-tenant notification = %v, want NOT_FOUND", err)
	}
	if n := be.Calls("SendNotification"); n != 0 {
		t.Errorf("a cross-tenant message reached the provider (%d sends)", n)
	}
}

// --- optimistic concurrency ------------------------------------------------

func TestConcurrentUpdateIsRefusedRatherThanLost(t *testing.T) {
	svc, _ := newService()
	ctx := testutil.Context()

	original, err := svc.GetCustomer(ctx, "1002")
	if err != nil {
		t.Fatalf("GetCustomer: %v", err)
	}

	// Someone else writes first.
	pro := domain.TierPro
	if _, err := svc.UpdateCustomer(ctx, "1002", domain.CustomerPatch{Tier: &pro}); err != nil {
		t.Fatalf("first write: %v", err)
	}

	// Our write is based on a record that has since changed.
	free := domain.TierFree
	err = mustErr(svc.UpdateCustomer(ctx, "1002", domain.CustomerPatch{
		Tier:            &free,
		ExpectedVersion: &original.Version,
	}))
	de := requireCode(t, err, domain.CodeConflict)
	if !strings.Contains(de.Message, "re-read") {
		t.Errorf("message = %q, want it to tell the caller what to do next", de.Message)
	}

	after, _ := svc.GetCustomer(ctx, "1002")
	if after.Tier != domain.TierPro {
		t.Errorf("tier = %q; the first writer's change was lost", after.Tier)
	}
}

func TestDeleteHonoursAVersionPrecondition(t *testing.T) {
	svc, _ := newService()
	ctx := testutil.Context()

	stale := 99
	err := svc.DeleteCustomer(ctx, services.DeleteRequest{CustomerID: "1004", Confirm: true, ExpectedVersion: &stale})
	requireCode(t, err, domain.CodeConflict)

	if _, err := svc.GetCustomer(ctx, "1004"); err != nil {
		t.Fatal("the customer was deleted despite a refused precondition")
	}
}

// --- destructive safety ----------------------------------------------------

func TestDeleteRequiresConfirmationEvenWithThePermission(t *testing.T) {
	svc, be := newService()

	// Holding customer:delete is not the same as having been told to delete
	// this record. The confirmation is checked server-side precisely so that
	// no amount of instruction text can substitute for it.
	err := svc.DeleteCustomer(testutil.Context(), services.DeleteRequest{CustomerID: "1004", Confirm: false})
	de := requireCode(t, err, domain.CodeInvalidArgument)
	if de.Field != "confirm" {
		t.Errorf("field = %q, want confirm", de.Field)
	}
	if n := be.Calls("DeleteCustomer"); n != 0 {
		t.Fatalf("the backend delete ran %d times without confirmation", n)
	}
}

// --- idempotency -----------------------------------------------------------

func TestRetryWithTheSameKeyReplaysInsteadOfResending(t *testing.T) {
	svc, be := newService()
	ctx := testutil.Context()

	n := domain.Notification{
		CustomerID: "1001", Channel: domain.ChannelEmail,
		Subject: "Renewal", Body: "Your plan renews next month.",
		IdempotencyKey: "renewal-2026-03-1001",
	}

	first, err := svc.SendNotification(ctx, n)
	if err != nil {
		t.Fatalf("first send: %v", err)
	}
	if first.Replayed {
		t.Error("the first send was marked as a replay")
	}

	second, err := svc.SendNotification(ctx, n)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if !second.Replayed {
		t.Error("the retry was not marked as a replay")
	}
	if second.MessageID != first.MessageID {
		t.Errorf("message ids %q then %q; a replay must return the original receipt", first.MessageID, second.MessageID)
	}
	if got := be.Calls("SendNotification"); got != 1 {
		t.Fatalf("the provider was called %d times, want 1: the customer was contacted twice", got)
	}
}

func TestReusingAKeyForADifferentMessageConflicts(t *testing.T) {
	svc, be := newService()
	ctx := testutil.Context()

	base := domain.Notification{
		CustomerID: "1001", Channel: domain.ChannelEmail,
		Subject: "Renewal", Body: "Original text.",
		IdempotencyKey: "key-abcdef12",
	}
	if _, err := svc.SendNotification(ctx, base); err != nil {
		t.Fatalf("first send: %v", err)
	}

	// Silently replaying here would tell the caller its new message was sent
	// when in fact nothing was.
	changed := base
	changed.Body = "Completely different text."
	requireCode(t, mustErrReceipt(svc.SendNotification(ctx, changed)), domain.CodeConflict)

	if got := be.Calls("SendNotification"); got != 1 {
		t.Errorf("provider calls = %d, want 1", got)
	}
}

func TestFailedSendDoesNotPoisonTheKey(t *testing.T) {
	svc, be := newService()
	ctx := testutil.Context()

	fail := true
	be.SendNotificationFn = func(ctx context.Context, n domain.Notification) (domain.Receipt, error) {
		if fail {
			return domain.Receipt{}, domain.Backend("send_customer_notification", context.DeadlineExceeded)
		}
		return be.Inner.SendNotification(ctx, n)
	}

	n := domain.Notification{
		CustomerID: "1001", Channel: domain.ChannelSMS, Body: "hello",
		IdempotencyKey: "key-12345678",
	}
	if _, err := svc.SendNotification(ctx, n); err == nil {
		t.Fatal("the failing send reported success")
	}

	fail = false
	receipt, err := svc.SendNotification(ctx, n)
	if err != nil {
		t.Fatalf("the retry after a failure was blocked: %v", err)
	}
	if receipt.Replayed {
		t.Error("the retry replayed a receipt that was never stored")
	}
}

func TestIdempotencyKeyIsValidated(t *testing.T) {
	svc, _ := newService()
	ctx := testutil.Context()

	for _, key := range []string{"short", strings.Repeat("k", 200), "has spaces", "line\nbreak"} {
		_, err := svc.SendNotification(ctx, domain.Notification{
			CustomerID: "1001", Channel: domain.ChannelSMS, Body: "hi", IdempotencyKey: key,
		})
		de := requireCode(t, err, domain.CodeInvalidArgument)
		if de.Field != "idempotency_key" {
			t.Errorf("field = %q for key %q, want idempotency_key", de.Field, key)
		}
	}
}

func TestKeyIsRefusedRatherThanIgnoredWhenDisabled(t *testing.T) {
	// A caller that believes it has replay protection and does not is worse off
	// than one told plainly that it must retry differently.
	svc, be := testutil.NewServiceWithoutIdempotency()

	_, err := svc.SendNotification(testutil.Context(), domain.Notification{
		CustomerID: "1001", Channel: domain.ChannelSMS, Body: "hi",
		IdempotencyKey: "key-abcdef12",
	})
	requireCode(t, err, domain.CodeInvalidArgument)
	if n := be.Calls("SendNotification"); n != 0 {
		t.Error("the message was sent despite the key being unusable")
	}
}

func TestKeysDoNotCollideAcrossTenantsOrPrincipals(t *testing.T) {
	svc, be := newService()
	const key = "shared-key-12345"

	send := func(ctx context.Context) (domain.Receipt, error) {
		return svc.SendNotification(ctx, domain.Notification{
			CustomerID: "1001", Channel: domain.ChannelSMS, Body: "hi", IdempotencyKey: key,
		})
	}

	first, err := send(testutil.Context())
	if err != nil {
		t.Fatalf("first: %v", err)
	}

	// A different principal in the same tenant chose the same UUID. It must get
	// its own message, not the other caller's receipt.
	other := testutil.Principal()
	other.Subject = "another-principal"
	second, err := send(testutil.ContextAs(other))
	if err != nil {
		t.Fatalf("second principal: %v", err)
	}
	if second.MessageID == first.MessageID {
		t.Error("two principals sharing a key received the same receipt")
	}
	if got := be.Calls("SendNotification"); got != 2 {
		t.Errorf("provider calls = %d, want 2", got)
	}
}

// --- pagination ------------------------------------------------------------

func TestSearchPaginatesWithAnOpaqueCursor(t *testing.T) {
	svc, _ := newService()
	ctx := testutil.Context()

	first, err := svc.SearchCustomers(ctx, services.SearchRequest{Status: domain.StatusActive, Limit: 1})
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	if len(first.Customers) != 1 {
		t.Fatalf("got %d customers, want 1", len(first.Customers))
	}
	if first.NextCursor == "" {
		t.Fatal("no cursor for a truncated result")
	}
	// The older flag stays, so a client that never learned about cursors is
	// not silently told there is nothing more.
	if !first.Truncated {
		t.Error("truncated = false on a page that was cut short")
	}

	second, err := svc.SearchCustomers(ctx, services.SearchRequest{
		Status: domain.StatusActive, Limit: 1, Cursor: first.NextCursor,
	})
	if err != nil {
		t.Fatalf("second page: %v", err)
	}
	if len(second.Customers) != 1 {
		t.Fatalf("got %d customers on page two", len(second.Customers))
	}
	if second.Customers[0].ID == first.Customers[0].ID {
		t.Error("the second page repeated the first")
	}
}

func TestCursorFromADifferentSearchIsRefused(t *testing.T) {
	svc, _ := newService()
	ctx := testutil.Context()

	page, err := svc.SearchCustomers(ctx, services.SearchRequest{Status: domain.StatusActive, Limit: 1})
	if err != nil || page.NextCursor == "" {
		t.Fatalf("first page: %v", err)
	}

	// Same caller, different filters: the cursor names a position in a result
	// set that no longer describes what is being asked for.
	_, err = svc.SearchCustomers(ctx, services.SearchRequest{Tier: domain.TierEnterprise, Limit: 1, Cursor: page.NextCursor})
	de := requireCode(t, err, domain.CodeInvalidArgument)
	if de.Field != "cursor" {
		t.Errorf("field = %q, want cursor", de.Field)
	}

	// Another tenant's caller must not be able to resume it either.
	_, err = svc.SearchCustomers(testutil.ContextAs(testutil.PrincipalIn(testutil.OtherTenant)),
		services.SearchRequest{Status: domain.StatusActive, Limit: 1, Cursor: page.NextCursor})
	requireCode(t, err, domain.CodeInvalidArgument)
}

func TestForgedCursorIsRefused(t *testing.T) {
	svc, _ := newService()
	for _, forged := range []string{"eyJhIjoiOTk5OSJ9.deadbeef", "not-a-cursor", strings.Repeat("A", 2000)} {
		_, err := svc.SearchCustomers(testutil.Context(),
			services.SearchRequest{Status: domain.StatusActive, Limit: 1, Cursor: forged})
		requireCode(t, err, domain.CodeInvalidArgument)
	}
}

func TestOrdersPaginate(t *testing.T) {
	svc, _ := newService()
	ctx := testutil.Context()

	seen := map[string]bool{}
	cursor := ""
	for i := 0; i < 10; i++ {
		res, err := svc.ListOrders(ctx, "1001", services.PageRequest{Limit: 1, Cursor: cursor})
		if err != nil {
			t.Fatalf("page %d: %v", i, err)
		}
		for _, o := range res.Orders {
			if seen[o.ID] {
				t.Fatalf("order %s appeared twice", o.ID)
			}
			seen[o.ID] = true
		}
		if res.NextCursor == "" {
			break
		}
		cursor = res.NextCursor
	}
	if len(seen) != 3 {
		t.Errorf("walked %d orders, want the 3 this customer has", len(seen))
	}
}

// --- input validation ------------------------------------------------------

func TestEmailValidationRejectsDisplayNameForms(t *testing.T) {
	svc, _ := newService()
	ctx := testutil.Context()

	// mail.ParseAddress accepts `Ops <ops@acme.example>`. Storing that would
	// let a caller smuggle an attacker-chosen name into every rendering of the
	// record.
	for _, email := range []string{
		"Ops <ops@acme.example>",
		"\"Admin\" <a@b.example>",
		"not-an-email",
		"a@b@c.example",
		"",
	} {
		patch := domain.CustomerPatch{Email: &email}
		if email == "" {
			continue // an empty string means "leave unchanged" at the tool layer
		}
		_, err := svc.UpdateCustomer(ctx, "1002", patch)
		de := requireCode(t, err, domain.CodeInvalidArgument)
		if de.Field != "email" {
			t.Errorf("email %q: field = %q, want email", email, de.Field)
		}
	}
}

func TestNotificationRejectsHeaderInjection(t *testing.T) {
	svc, be := newService()
	ctx := testutil.Context()

	// A CR or LF in a subject lets a caller append headers of its own at
	// whatever gateway sends the mail - including Bcc.
	_, err := svc.SendNotification(ctx, domain.Notification{
		CustomerID: "1001", Channel: domain.ChannelEmail,
		Subject: "Hello\r\nBcc: attacker@evil.example",
		Body:    "text",
	})
	de := requireCode(t, err, domain.CodeInvalidArgument)
	if de.Field != "subject" {
		t.Errorf("field = %q, want subject", de.Field)
	}
	if n := be.Calls("SendNotification"); n != 0 {
		t.Error("the injected message reached the provider")
	}

	// A body legitimately contains newlines, so those stay allowed.
	if _, err := svc.SendNotification(ctx, domain.Notification{
		CustomerID: "1001", Channel: domain.ChannelEmail,
		Subject: "Hello", Body: "line one\nline two\n",
	}); err != nil {
		t.Errorf("a body with ordinary newlines was refused: %v", err)
	}
}

func TestOversizedInputsAreRefused(t *testing.T) {
	svc, _ := newService()
	ctx := testutil.Context()

	long := strings.Repeat("x", services.MaxSearchTextLength+1)
	_, err := svc.SearchCustomers(ctx, services.SearchRequest{Text: long})
	requireCode(t, err, domain.CodeInvalidArgument)

	name := strings.Repeat("n", services.MaxNameLength+1)
	_, err = svc.UpdateCustomer(ctx, "1002", domain.CustomerPatch{Name: &name})
	requireCode(t, err, domain.CodeInvalidArgument)
}

func TestSearchLimitIsClampedNotRejected(t *testing.T) {
	svc, be := newService()
	var seen int
	be.SearchCustomersFn = func(_ context.Context, q domain.SearchQuery) (domain.CustomerList, error) {
		seen = q.Limit
		return domain.CustomerList{}, nil
	}

	if _, err := svc.SearchCustomers(testutil.Context(), services.SearchRequest{Text: "a", Limit: 1 << 20}); err != nil {
		t.Fatalf("SearchCustomers: %v", err)
	}
	if seen != services.MaxSearchLimit {
		t.Errorf("limit reaching the backend = %d, want it clamped to %d", seen, services.MaxSearchLimit)
	}
}

// --- summary arithmetic ----------------------------------------------------

func TestSummaryReportsTheNewestOrderEvenIfCancelled(t *testing.T) {
	svc, be := newService()
	be.ListOrdersFn = func(context.Context, string, string, domain.Page) (domain.OrderList, error) {
		return domain.OrderList{Items: []domain.Order{
			{ID: "o-2", CustomerID: "1001", Status: domain.OrderCancelled, Total: 100, Currency: "USD", PlacedAt: mustTime("2026-02-01")},
			{ID: "o-1", CustomerID: "1001", Status: domain.OrderDelivered, Total: 50, Currency: "USD", PlacedAt: mustTime("2026-01-01")},
		}}, nil
	}

	summary, err := svc.Summarize(testutil.Context(), "1001")
	if err != nil {
		t.Fatalf("Summarize: %v", err)
	}
	// "When did this account last order?" has an answer even when that order
	// was later cancelled; reporting none would be wrong.
	if summary.LastOrderAt == nil {
		t.Fatal("last_order_at is absent because the newest order was cancelled")
	}
	if !summary.LastOrderAt.Equal(mustTime("2026-02-01")) {
		t.Errorf("last_order_at = %v, want the newest order's date", summary.LastOrderAt)
	}
	// The cancelled order still does not count towards spend.
	if summary.LifetimeSpend != 50 {
		t.Errorf("lifetime_spend = %v, want 50", summary.LifetimeSpend)
	}
}

// --- helpers ---------------------------------------------------------------

func mustErr(_ domain.Customer, err error) error { return err }

func mustErrReceipt(_ domain.Receipt, err error) error { return err }

func mustErrSummary(_ services.CustomerSummary, err error) error { return err }

func mustTime(s string) time.Time {
	parsed, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return parsed
}
