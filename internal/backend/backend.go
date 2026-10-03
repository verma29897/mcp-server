// Package backend holds data-source clients.
//
// Nothing here knows about MCP. A backend receives a context.Context and
// returns domain types or *domain.Error, which lets the same service layer run
// against the in-memory store, a real REST API, or a test double.
//
// Every method that touches customer data takes a tenant id as an explicit
// parameter rather than reading one from the context. That is a deliberate
// ergonomic choice: an implicit tenant is a tenant a new method can forget, and
// the failure mode of forgetting is one customer reading another's data. As an
// explicit argument it cannot compile without a decision being made.
package backend

import (
	"context"

	"github.com/verma29897/mcp-server/internal/domain"
)

// Backend is the customer data source contract.
//
// Implementations must honour ctx for cancellation and deadlines, must scope
// every operation to tenantID, and must classify their failures as
// *domain.Error so that no upstream detail (URLs, tokens, response bodies)
// reaches an MCP client.
//
// A record that exists in another tenant must be reported as
// domain.CodeNotFound, never as CodeForbidden: the difference between the two
// tells a caller that the record exists, which is itself a disclosure.
type Backend interface {
	// GetCustomer returns the customer with the given id inside tenantID, or a
	// domain.CodeNotFound error.
	GetCustomer(ctx context.Context, tenantID, id string) (domain.Customer, error)

	// SearchCustomers returns one page of customers matching q, newest first.
	// q.TenantID is always set by the time this is called. An empty result is
	// not an error.
	SearchCustomers(ctx context.Context, q domain.SearchQuery) (domain.CustomerList, error)

	// ListOrders returns one page of orders for a customer, newest first.
	ListOrders(ctx context.Context, tenantID, customerID string, page domain.Page) (domain.OrderList, error)

	// UpdateCustomer applies a sparse patch and returns the updated record. A
	// non-nil patch.ExpectedVersion is an optimistic-locking precondition and
	// must produce domain.CodeConflict when it does not match.
	UpdateCustomer(ctx context.Context, tenantID, id string, patch domain.CustomerPatch) (domain.Customer, error)

	// DeleteCustomer permanently removes a customer. A non-nil expectedVersion
	// is an optimistic-locking precondition, as for UpdateCustomer.
	DeleteCustomer(ctx context.Context, tenantID, id string, expectedVersion *int) error

	// SendNotification delivers a message to a customer through an external
	// channel and returns the delivery receipt. n.TenantID is always set.
	SendNotification(ctx context.Context, n domain.Notification) (domain.Receipt, error)

	// Ping reports whether the backend is reachable. Used by health checks.
	Ping(ctx context.Context) error

	// Close releases any resources held by the backend.
	Close() error
}
