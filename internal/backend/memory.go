package backend

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/verma29897/mcp-server/internal/domain"
)

// DefaultTenant is the tenant the seeded sample data belongs to, and the tenant
// a single-tenant deployment runs everything under.
const DefaultTenant = "default"

// SecondaryTenant is a second seeded tenant.
//
// It exists so that tenant isolation is exercised by the ordinary test run
// rather than by a special fixture: with only one tenant in the store, a
// cross-tenant bug is invisible because there is nothing to cross into.
const SecondaryTenant = "tenant-b"

// Memory is an in-process Backend seeded with sample data.
//
// It exists so the server is runnable and Inspector-testable with zero external
// dependencies, and so tests have a deterministic data source.
type Memory struct {
	mu sync.RWMutex
	// customers and orders are keyed by tenant, then by id. The partition is
	// structural: a lookup in the wrong tenant cannot find a record, rather
	// than finding one and being expected to reject it.
	customers map[string]map[string]domain.Customer
	orders    map[string]map[string][]domain.Order
	sent      []domain.Receipt
	// now is injectable so tests get deterministic timestamps.
	now func() time.Time
	seq int
}

// compile-time assertion that Memory satisfies the Backend contract.
var _ Backend = (*Memory)(nil)

// NewMemory returns a Memory backend seeded with the sample dataset.
func NewMemory() *Memory {
	m := &Memory{
		customers: make(map[string]map[string]domain.Customer),
		orders:    make(map[string]map[string][]domain.Order),
		now:       time.Now,
	}
	m.seed()
	return m
}

// NewMemoryWithClock returns a Memory backend using the supplied clock.
func NewMemoryWithClock(now func() time.Time) *Memory {
	m := NewMemory()
	m.now = now
	return m
}

func (m *Memory) seed() {
	base := time.Date(2026, 1, 15, 9, 0, 0, 0, time.UTC)
	seedCustomers := []domain.Customer{
		{ID: "1001", TenantID: DefaultTenant, Name: "Acme Industries", Email: "ops@acme.example", Status: domain.StatusActive, Tier: domain.TierEnterprise, Country: "IN"},
		{ID: "1002", TenantID: DefaultTenant, Name: "Bluepeak Labs", Email: "hello@bluepeak.example", Status: domain.StatusActive, Tier: domain.TierPro, Country: "US"},
		{ID: "1003", TenantID: DefaultTenant, Name: "Cobalt Retail", Email: "support@cobalt.example", Status: domain.StatusSuspended, Tier: domain.TierPro, Country: "DE"},
		{ID: "1004", TenantID: DefaultTenant, Name: "Delta Logistics", Email: "accounts@delta.example", Status: domain.StatusInactive, Tier: domain.TierFree, Country: "IN"},
		{ID: "1005", TenantID: DefaultTenant, Name: "Everline Health", Email: "it@everline.example", Status: domain.StatusActive, Tier: domain.TierEnterprise, Country: "GB"},
		// A second tenant, so cross-tenant access has something to fail at.
		{ID: "2001", TenantID: SecondaryTenant, Name: "Northwind Trading", Email: "ops@northwind.example", Status: domain.StatusActive, Tier: domain.TierPro, Country: "SG"},
		{ID: "2002", TenantID: SecondaryTenant, Name: "Orbit Media", Email: "hello@orbit.example", Status: domain.StatusActive, Tier: domain.TierFree, Country: "AU"},
	}
	for i, c := range seedCustomers {
		c.CreatedAt = base.AddDate(0, 0, -i*30)
		c.UpdatedAt = base.AddDate(0, 0, -i)
		c.Version = 1
		m.tenantCustomers(c.TenantID)[c.ID] = c
	}

	seedOrders := []domain.Order{
		{ID: "ord-9001", CustomerID: "1001", TenantID: DefaultTenant, Total: 12400.50, Currency: "USD", Status: domain.OrderDelivered},
		{ID: "ord-9002", CustomerID: "1001", TenantID: DefaultTenant, Total: 890.00, Currency: "USD", Status: domain.OrderShipped},
		{ID: "ord-9003", CustomerID: "1001", TenantID: DefaultTenant, Total: 4500.25, Currency: "USD", Status: domain.OrderPending},
		{ID: "ord-9004", CustomerID: "1002", TenantID: DefaultTenant, Total: 310.75, Currency: "USD", Status: domain.OrderDelivered},
		{ID: "ord-9005", CustomerID: "1003", TenantID: DefaultTenant, Total: 1290.00, Currency: "EUR", Status: domain.OrderCancelled},
		{ID: "ord-9006", CustomerID: "1005", TenantID: DefaultTenant, Total: 78200.00, Currency: "GBP", Status: domain.OrderDelivered},
		{ID: "ord-9101", CustomerID: "2001", TenantID: SecondaryTenant, Total: 640.00, Currency: "SGD", Status: domain.OrderDelivered},
	}
	for i, o := range seedOrders {
		o.PlacedAt = base.AddDate(0, 0, -i*7)
		byCustomer := m.tenantOrders(o.TenantID)
		byCustomer[o.CustomerID] = append(byCustomer[o.CustomerID], o)
	}
}

// tenantCustomers returns the customer map for a tenant, creating it if absent.
// Callers must hold the write lock, or be inside seed().
func (m *Memory) tenantCustomers(tenant string) map[string]domain.Customer {
	if m.customers[tenant] == nil {
		m.customers[tenant] = map[string]domain.Customer{}
	}
	return m.customers[tenant]
}

func (m *Memory) tenantOrders(tenant string) map[string][]domain.Order {
	if m.orders[tenant] == nil {
		m.orders[tenant] = map[string][]domain.Order{}
	}
	return m.orders[tenant]
}

// GetCustomer implements Backend.
func (m *Memory) GetCustomer(ctx context.Context, tenantID, id string) (domain.Customer, error) {
	if err := ctx.Err(); err != nil {
		return domain.Customer{}, domain.Timeout("get_customer", err)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	c, ok := m.customers[tenantID][id]
	if !ok {
		return domain.Customer{}, domain.NotFound("customer", id)
	}
	return c, nil
}

// SearchCustomers implements Backend.
func (m *Memory) SearchCustomers(ctx context.Context, q domain.SearchQuery) (domain.CustomerList, error) {
	if err := ctx.Err(); err != nil {
		return domain.CustomerList{}, domain.Timeout("search_customers", err)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	text := strings.ToLower(strings.TrimSpace(q.Text))
	var out []domain.Customer
	for _, c := range m.customers[q.TenantID] {
		if q.Status != "" && c.Status != q.Status {
			continue
		}
		if q.Tier != "" && c.Tier != q.Tier {
			continue
		}
		if text != "" &&
			!strings.Contains(strings.ToLower(c.Name), text) &&
			!strings.Contains(strings.ToLower(c.Email), text) &&
			!strings.Contains(strings.ToLower(c.ID), text) {
			continue
		}
		out = append(out, c)
	}

	// Newest first, with ID as a tiebreak so results are deterministic - which
	// is also what makes the ID usable as a stable pagination key.
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})

	out = resumeAfter(out, q.After, func(c domain.Customer) string { return c.ID })
	return page(out, q.Limit, func(c domain.Customer) string { return c.ID }, func(items []domain.Customer, next string) domain.CustomerList {
		return domain.CustomerList{Items: items, NextAfter: next}
	}), nil
}

// ListOrders implements Backend.
func (m *Memory) ListOrders(ctx context.Context, tenantID, customerID string, p domain.Page) (domain.OrderList, error) {
	if err := ctx.Err(); err != nil {
		return domain.OrderList{}, domain.Timeout("list_customer_orders", err)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	if _, ok := m.customers[tenantID][customerID]; !ok {
		return domain.OrderList{}, domain.NotFound("customer", customerID)
	}
	src := m.orders[tenantID][customerID]
	out := make([]domain.Order, len(src))
	copy(out, src)
	sort.Slice(out, func(i, j int) bool {
		if out[i].PlacedAt.Equal(out[j].PlacedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].PlacedAt.After(out[j].PlacedAt)
	})

	out = resumeAfter(out, p.After, func(o domain.Order) string { return o.ID })
	return page(out, p.Limit, func(o domain.Order) string { return o.ID }, func(items []domain.Order, next string) domain.OrderList {
		return domain.OrderList{Items: items, NextAfter: next}
	}), nil
}

// UpdateCustomer implements Backend.
func (m *Memory) UpdateCustomer(ctx context.Context, tenantID, id string, patch domain.CustomerPatch) (domain.Customer, error) {
	if err := ctx.Err(); err != nil {
		return domain.Customer{}, domain.Timeout("update_customer", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	tenant := m.customers[tenantID]
	c, ok := tenant[id]
	if !ok {
		return domain.Customer{}, domain.NotFound("customer", id)
	}
	if err := checkVersion(c.Version, patch.ExpectedVersion); err != nil {
		return domain.Customer{}, err
	}
	if patch.Name != nil {
		c.Name = *patch.Name
	}
	if patch.Email != nil {
		c.Email = *patch.Email
	}
	if patch.Status != nil {
		c.Status = *patch.Status
	}
	if patch.Tier != nil {
		c.Tier = *patch.Tier
	}
	c.Version++
	c.UpdatedAt = m.now().UTC()
	tenant[id] = c
	return c, nil
}

// DeleteCustomer implements Backend.
func (m *Memory) DeleteCustomer(ctx context.Context, tenantID, id string, expectedVersion *int) error {
	if err := ctx.Err(); err != nil {
		return domain.Timeout("delete_customer", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	c, ok := m.customers[tenantID][id]
	if !ok {
		return domain.NotFound("customer", id)
	}
	if err := checkVersion(c.Version, expectedVersion); err != nil {
		return err
	}
	delete(m.customers[tenantID], id)
	delete(m.orders[tenantID], id)
	return nil
}

// SendNotification implements Backend. It records the message rather than
// contacting a real provider, but keeps the same contract and side-effect
// semantics as one that would.
func (m *Memory) SendNotification(ctx context.Context, n domain.Notification) (domain.Receipt, error) {
	if err := ctx.Err(); err != nil {
		return domain.Receipt{}, domain.Timeout("send_customer_notification", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.customers[n.TenantID][n.CustomerID]; !ok {
		return domain.Receipt{}, domain.NotFound("customer", n.CustomerID)
	}
	m.seq++
	r := domain.Receipt{
		MessageID:  fmt.Sprintf("msg-%05d", m.seq),
		CustomerID: n.CustomerID,
		Channel:    n.Channel,
		AcceptedAt: m.now().UTC(),
	}
	m.sent = append(m.sent, r)
	return r, nil
}

// Ping implements Backend. The in-memory store is always reachable.
func (m *Memory) Ping(ctx context.Context) error {
	return ctx.Err()
}

// Close implements Backend.
func (m *Memory) Close() error { return nil }

// Sent returns a copy of the notifications accepted so far. Test helper.
func (m *Memory) Sent() []domain.Receipt {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]domain.Receipt, len(m.sent))
	copy(out, m.sent)
	return out
}

// checkVersion enforces an optimistic-locking precondition.
func checkVersion(current int, expected *int) error {
	if expected == nil || *expected == current {
		return nil
	}
	return domain.Conflict("expected_version",
		"the record has changed since it was read (expected version %d, current version %d); re-read it and retry",
		*expected, current)
}

// resumeAfter drops everything up to and including the item whose key is after.
//
// An unknown key yields the full slice rather than an empty one. That is the
// safe direction: a record deleted between two pages should not silently
// truncate the listing to nothing.
func resumeAfter[T any](items []T, after string, key func(T) string) []T {
	if after == "" {
		return items
	}
	for i, item := range items {
		if key(item) == after {
			return items[i+1:]
		}
	}
	return items
}

// page truncates to limit and reports the resume key when more remain.
func page[T any, L any](items []T, limit int, key func(T) string, build func([]T, string) L) L {
	if limit <= 0 || len(items) <= limit {
		return build(items, "")
	}
	truncated := items[:limit]
	return build(truncated, key(truncated[len(truncated)-1]))
}
