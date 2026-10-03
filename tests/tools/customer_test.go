// Package tools_test covers the tool layer: input validation, service
// delegation and error classification, without a protocol or a transport.
package tools_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/verma29897/mcp-server/internal/domain"
	"github.com/verma29897/mcp-server/internal/services"
	"github.com/verma29897/mcp-server/internal/tools/customer"
	"github.com/verma29897/mcp-server/tests/testutil"
)

func newHandlers() (*customer.Handlers, *testutil.FakeBackend) {
	svc, be := testutil.NewService()
	return customer.NewHandlers(svc), be
}

func TestGetCustomerValidInput(t *testing.T) {
	h, _ := newHandlers()

	out, err := h.GetCustomer(testutil.Context(), customer.GetCustomerInput{CustomerID: "1001"})
	if err != nil {
		t.Fatalf("GetCustomer: unexpected error: %v", err)
	}
	if out.Customer.CustomerID != "1001" {
		t.Errorf("customer_id = %q, want %q", out.Customer.CustomerID, "1001")
	}
	if out.Customer.Name != "Acme Industries" {
		t.Errorf("name = %q, want %q", out.Customer.Name, "Acme Industries")
	}
	if out.Customer.Status != string(domain.StatusActive) {
		t.Errorf("status = %q, want %q", out.Customer.Status, domain.StatusActive)
	}
}

func TestGetCustomerMissingAndInvalidID(t *testing.T) {
	tests := []struct {
		name  string
		id    string
		field string
	}{
		{"empty", "", "customer_id"},
		{"whitespace only", "   ", "customer_id"},
		{"path traversal", "../etc/passwd", "customer_id"},
		{"sql-ish", "1' OR '1'='1", "customer_id"},
		{"too long", strings.Repeat("a", 65), "customer_id"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, be := newHandlers()

			_, err := h.GetCustomer(testutil.Context(), customer.GetCustomerInput{CustomerID: tc.id})
			de := requireDomainError(t, err)
			if de.Code != domain.CodeInvalidArgument {
				t.Errorf("code = %s, want %s", de.Code, domain.CodeInvalidArgument)
			}
			if de.Field != tc.field {
				t.Errorf("field = %q, want %q", de.Field, tc.field)
			}
			// Validation must reject before the backend is touched.
			if n := be.Calls("GetCustomer"); n != 0 {
				t.Errorf("backend called %d times, want 0", n)
			}
		})
	}
}

func TestGetCustomerNotFound(t *testing.T) {
	h, _ := newHandlers()

	_, err := h.GetCustomer(testutil.Context(), customer.GetCustomerInput{CustomerID: "does-not-exist"})
	de := requireDomainError(t, err)
	if de.Code != domain.CodeNotFound {
		t.Fatalf("code = %s, want %s", de.Code, domain.CodeNotFound)
	}
}

func TestGetCustomerBackendError(t *testing.T) {
	h, be := newHandlers()
	// An unclassified upstream failure carrying a secret in its text.
	be.GetCustomerFn = func(context.Context, string, string) (domain.Customer, error) {
		return domain.Customer{}, domain.Backend("get_customer",
			errors.New("dial tcp 10.0.0.5:5432: password=hunter2 refused"))
	}

	_, err := h.GetCustomer(testutil.Context(), customer.GetCustomerInput{CustomerID: "1001"})
	de := requireDomainError(t, err)
	if de.Code != domain.CodeBackendError {
		t.Fatalf("code = %s, want %s", de.Code, domain.CodeBackendError)
	}
	if !de.Retryable {
		t.Error("backend errors should be marked retryable")
	}
	// The client-facing text must not carry the internal cause.
	if strings.Contains(de.Error(), "hunter2") || strings.Contains(de.Error(), "10.0.0.5") {
		t.Errorf("client-facing message leaks internal detail: %q", de.Error())
	}
	// The cause must still be reachable for server-side logging.
	if !strings.Contains(de.Detail(), "hunter2") {
		t.Errorf("Detail() should retain the cause for logging, got %q", de.Detail())
	}
}

func TestGetCustomerUnauthorized(t *testing.T) {
	h, be := newHandlers()
	be.GetCustomerFn = func(context.Context, string, string) (domain.Customer, error) {
		return domain.Customer{}, domain.Unauthorized("the server is not authorized to reach the customer backend")
	}

	_, err := h.GetCustomer(testutil.Context(), customer.GetCustomerInput{CustomerID: "1001"})
	de := requireDomainError(t, err)
	if de.Code != domain.CodeUnauthorized {
		t.Fatalf("code = %s, want %s", de.Code, domain.CodeUnauthorized)
	}
}

func TestGetCustomerHonoursCancellation(t *testing.T) {
	h, _ := newHandlers()

	_, err := h.GetCustomer(testutil.CancelledContext(t), customer.GetCustomerInput{CustomerID: "1001"})
	de := requireDomainError(t, err)
	if de.Code != domain.CodeTimeout {
		t.Fatalf("code = %s, want %s", de.Code, domain.CodeTimeout)
	}
	if !errors.Is(err, context.Canceled) {
		t.Error("cancellation should remain visible through errors.Is")
	}
}

func TestSearchCustomers(t *testing.T) {
	t.Run("by text", func(t *testing.T) {
		h, _ := newHandlers()

		out, err := h.SearchCustomers(testutil.Context(), customer.SearchCustomersInput{Query: "acme"})
		if err != nil {
			t.Fatalf("SearchCustomers: %v", err)
		}
		if out.Count != 1 || out.Customers[0].CustomerID != "1001" {
			t.Fatalf("got %d results %+v, want just customer 1001", out.Count, out.Customers)
		}
		if out.Truncated {
			t.Error("truncated = true, want false for a single result")
		}
	})

	t.Run("by status", func(t *testing.T) {
		h, _ := newHandlers()

		out, err := h.SearchCustomers(testutil.Context(), customer.SearchCustomersInput{Status: string(domain.StatusSuspended)})
		if err != nil {
			t.Fatalf("SearchCustomers: %v", err)
		}
		if out.Count != 1 || out.Customers[0].CustomerID != "1003" {
			t.Fatalf("got %+v, want only the suspended customer 1003", out.Customers)
		}
	})

	t.Run("reports truncation", func(t *testing.T) {
		h, _ := newHandlers()

		out, err := h.SearchCustomers(testutil.Context(), customer.SearchCustomersInput{
			Status: string(domain.StatusActive),
			Limit:  1,
		})
		if err != nil {
			t.Fatalf("SearchCustomers: %v", err)
		}
		if out.Count != 1 {
			t.Fatalf("count = %d, want 1", out.Count)
		}
		if !out.Truncated {
			t.Error("truncated = false, want true when the limit was hit")
		}
	})

	t.Run("rejects unconstrained search", func(t *testing.T) {
		h, be := newHandlers()

		_, err := h.SearchCustomers(testutil.Context(), customer.SearchCustomersInput{})
		de := requireDomainError(t, err)
		if de.Code != domain.CodeInvalidArgument {
			t.Fatalf("code = %s, want %s", de.Code, domain.CodeInvalidArgument)
		}
		if n := be.Calls("SearchCustomers"); n != 0 {
			t.Errorf("backend called %d times, want 0", n)
		}
	})

	t.Run("rejects unknown status", func(t *testing.T) {
		h, _ := newHandlers()

		_, err := h.SearchCustomers(testutil.Context(), customer.SearchCustomersInput{Status: "archived"})
		de := requireDomainError(t, err)
		if de.Field != "status" {
			t.Fatalf("field = %q, want %q", de.Field, "status")
		}
	})

	t.Run("clamps an oversized limit", func(t *testing.T) {
		h, be := newHandlers()
		var seen int
		be.SearchCustomersFn = func(_ context.Context, q domain.SearchQuery) (domain.CustomerList, error) {
			seen = q.Limit
			return domain.CustomerList{}, nil
		}

		if _, err := h.SearchCustomers(testutil.Context(), customer.SearchCustomersInput{
			Query: "a", Limit: 10_000,
		}); err != nil {
			t.Fatalf("SearchCustomers: %v", err)
		}
		if seen != services.MaxSearchLimit {
			t.Errorf("limit passed to backend = %d, want %d", seen, services.MaxSearchLimit)
		}
	})
}

func TestListCustomerOrders(t *testing.T) {
	h, _ := newHandlers()

	out, err := h.ListCustomerOrders(testutil.Context(), customer.ListCustomerOrdersInput{CustomerID: "1001"})
	if err != nil {
		t.Fatalf("ListCustomerOrders: %v", err)
	}
	if out.Count != 3 {
		t.Fatalf("count = %d, want 3", out.Count)
	}
	// Newest first.
	for i := 1; i < len(out.Orders); i++ {
		if out.Orders[i-1].PlacedAt.Before(out.Orders[i].PlacedAt) {
			t.Fatalf("orders are not newest-first: %v before %v", out.Orders[i-1].PlacedAt, out.Orders[i].PlacedAt)
		}
	}
}

func TestListCustomerOrdersUnknownCustomer(t *testing.T) {
	h, _ := newHandlers()

	_, err := h.ListCustomerOrders(testutil.Context(), customer.ListCustomerOrdersInput{CustomerID: "9999"})
	de := requireDomainError(t, err)
	if de.Code != domain.CodeNotFound {
		t.Fatalf("code = %s, want %s", de.Code, domain.CodeNotFound)
	}
}

func TestUpdateCustomer(t *testing.T) {
	t.Run("applies only the supplied fields", func(t *testing.T) {
		h, _ := newHandlers()

		out, err := h.UpdateCustomer(testutil.Context(), customer.UpdateCustomerInput{
			CustomerID: "1002",
			Status:     string(domain.StatusSuspended),
		})
		if err != nil {
			t.Fatalf("UpdateCustomer: %v", err)
		}
		if out.Customer.Status != string(domain.StatusSuspended) {
			t.Errorf("status = %q, want %q", out.Customer.Status, domain.StatusSuspended)
		}
		if out.Customer.Name != "Bluepeak Labs" {
			t.Errorf("name = %q; an omitted field must be left unchanged", out.Customer.Name)
		}
		if len(out.UpdatedFields) != 1 || out.UpdatedFields[0] != "status" {
			t.Errorf("updated_fields = %v, want [status]", out.UpdatedFields)
		}
	})

	t.Run("normalizes email", func(t *testing.T) {
		h, _ := newHandlers()

		out, err := h.UpdateCustomer(testutil.Context(), customer.UpdateCustomerInput{
			CustomerID: "1002",
			Email:      "  NEW@Bluepeak.Example  ",
		})
		if err != nil {
			t.Fatalf("UpdateCustomer: %v", err)
		}
		if out.Customer.Email != "new@bluepeak.example" {
			t.Errorf("email = %q, want it trimmed and lower-cased", out.Customer.Email)
		}
	})

	t.Run("rejects an invalid email", func(t *testing.T) {
		h, be := newHandlers()

		_, err := h.UpdateCustomer(testutil.Context(), customer.UpdateCustomerInput{
			CustomerID: "1002",
			Email:      "not-an-email",
		})
		de := requireDomainError(t, err)
		if de.Field != "email" {
			t.Fatalf("field = %q, want %q", de.Field, "email")
		}
		if n := be.Calls("UpdateCustomer"); n != 0 {
			t.Errorf("backend called %d times, want 0", n)
		}
	})

	t.Run("rejects an empty patch", func(t *testing.T) {
		h, _ := newHandlers()

		_, err := h.UpdateCustomer(testutil.Context(), customer.UpdateCustomerInput{CustomerID: "1002"})
		de := requireDomainError(t, err)
		if de.Code != domain.CodeInvalidArgument {
			t.Fatalf("code = %s, want %s", de.Code, domain.CodeInvalidArgument)
		}
	})

	t.Run("is idempotent", func(t *testing.T) {
		h, _ := newHandlers()
		in := customer.UpdateCustomerInput{CustomerID: "1002", Tier: string(domain.TierEnterprise)}

		first, err := h.UpdateCustomer(testutil.Context(), in)
		if err != nil {
			t.Fatalf("first update: %v", err)
		}
		second, err := h.UpdateCustomer(testutil.Context(), in)
		if err != nil {
			t.Fatalf("second update: %v", err)
		}
		if first.Customer.Tier != second.Customer.Tier {
			t.Errorf("tier changed between identical updates: %q then %q", first.Customer.Tier, second.Customer.Tier)
		}
	})
}

func TestDeleteCustomerRequiresConfirmation(t *testing.T) {
	h, be := newHandlers()

	_, err := h.DeleteCustomer(testutil.Context(), customer.DeleteCustomerInput{CustomerID: "1004", Confirm: false})
	de := requireDomainError(t, err)
	if de.Field != "confirm" {
		t.Fatalf("field = %q, want %q", de.Field, "confirm")
	}
	if n := be.Calls("DeleteCustomer"); n != 0 {
		t.Fatalf("backend delete called %d times without confirmation, want 0", n)
	}
}

func TestDeleteCustomerConfirmed(t *testing.T) {
	h, _ := newHandlers()

	out, err := h.DeleteCustomer(testutil.Context(), customer.DeleteCustomerInput{CustomerID: "1004", Confirm: true})
	if err != nil {
		t.Fatalf("DeleteCustomer: %v", err)
	}
	if !out.Deleted || out.CustomerID != "1004" {
		t.Fatalf("got %+v, want customer 1004 deleted", out)
	}

	if _, err := h.GetCustomer(testutil.Context(), customer.GetCustomerInput{CustomerID: "1004"}); err == nil {
		t.Fatal("customer is still readable after deletion")
	}
}

func TestSendCustomerNotification(t *testing.T) {
	t.Run("accepts a well-formed email", func(t *testing.T) {
		h, be := newHandlers()

		out, err := h.SendCustomerNotification(testutil.Context(), customer.SendCustomerNotificationInput{
			CustomerID: "1001",
			Channel:    string(domain.ChannelEmail),
			Subject:    "Renewal reminder",
			Body:       "Your enterprise plan renews next month.",
		})
		if err != nil {
			t.Fatalf("SendCustomerNotification: %v", err)
		}
		if out.MessageID == "" {
			t.Error("message_id is empty")
		}
		if n := be.Calls("SendNotification"); n != 1 {
			t.Errorf("backend called %d times, want 1", n)
		}
	})

	t.Run("requires a subject for email", func(t *testing.T) {
		h, be := newHandlers()

		_, err := h.SendCustomerNotification(testutil.Context(), customer.SendCustomerNotificationInput{
			CustomerID: "1001",
			Channel:    string(domain.ChannelEmail),
			Body:       "No subject supplied.",
		})
		de := requireDomainError(t, err)
		if de.Field != "subject" {
			t.Fatalf("field = %q, want %q", de.Field, "subject")
		}
		if n := be.Calls("SendNotification"); n != 0 {
			t.Errorf("an external message was sent despite invalid input (%d calls)", n)
		}
	})

	t.Run("rejects an unknown channel", func(t *testing.T) {
		h, _ := newHandlers()

		_, err := h.SendCustomerNotification(testutil.Context(), customer.SendCustomerNotificationInput{
			CustomerID: "1001",
			Channel:    "carrier-pigeon",
			Body:       "hello",
		})
		de := requireDomainError(t, err)
		if de.Field != "channel" {
			t.Fatalf("field = %q, want %q", de.Field, "channel")
		}
	})

	t.Run("rejects an oversized body", func(t *testing.T) {
		h, _ := newHandlers()

		_, err := h.SendCustomerNotification(testutil.Context(), customer.SendCustomerNotificationInput{
			CustomerID: "1001",
			Channel:    string(domain.ChannelSMS),
			Body:       strings.Repeat("x", services.MaxNotificationBody+1),
		})
		de := requireDomainError(t, err)
		if de.Field != "body" {
			t.Fatalf("field = %q, want %q", de.Field, "body")
		}
	})

	t.Run("propagates a rate limit", func(t *testing.T) {
		h, be := newHandlers()
		be.SendNotificationFn = func(context.Context, domain.Notification) (domain.Receipt, error) {
			return domain.Receipt{}, domain.RateLimited("the customer backend is rate limiting requests")
		}

		_, err := h.SendCustomerNotification(testutil.Context(), customer.SendCustomerNotificationInput{
			CustomerID: "1001",
			Channel:    string(domain.ChannelSMS),
			Body:       "hello",
		})
		de := requireDomainError(t, err)
		if de.Code != domain.CodeRateLimited {
			t.Fatalf("code = %s, want %s", de.Code, domain.CodeRateLimited)
		}
		if !de.Retryable {
			t.Error("a rate limit should be retryable")
		}
	})
}

// requireDomainError asserts that err carries a *domain.Error and returns it.
func requireDomainError(t *testing.T, err error) *domain.Error {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	de, ok := domain.AsError(err)
	if !ok {
		t.Fatalf("error %v (%T) is not a *domain.Error", err, err)
	}
	return de
}
