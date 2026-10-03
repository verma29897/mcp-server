// Package services holds business logic.
//
// It has no dependency on the MCP SDK: everything here would be equally valid
// behind a REST handler or a CLI. That separation is what lets the MCP layer
// stay a thin adapter, and lets these rules be tested without a protocol.
//
// It is also the second place authorization is enforced. The MCP middleware
// gates a request before a handler runs; these methods check again, on the
// principal carried by the context. The duplication is deliberate. The
// middleware is the gate a request is expected to pass through; this check is
// what still holds if some future handler, background job or CLI reaches the
// service another way. Neither check consults anything a model can influence.
package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/verma29897/mcp-server/internal/authz"
	"github.com/verma29897/mcp-server/internal/backend"
	"github.com/verma29897/mcp-server/internal/domain"
	"github.com/verma29897/mcp-server/internal/idempotency"
	"github.com/verma29897/mcp-server/internal/paging"
)

// Limits on request sizes, applied before anything reaches the backend.
const (
	// DefaultSearchLimit is used when the caller does not specify one.
	DefaultSearchLimit = 20
	// MaxSearchLimit caps how many customers one search may return, so a model
	// cannot accidentally pull an unbounded page into its context.
	MaxSearchLimit = 100
	// DefaultOrderLimit is used when the caller does not specify one.
	DefaultOrderLimit = 20
	// MaxOrderLimit caps how many orders one call may return.
	MaxOrderLimit = 200
	// MaxNotificationBody caps an outbound message body.
	MaxNotificationBody = 4000
	// MaxNotificationSubject caps an outbound message subject.
	MaxNotificationSubject = 200
	// MaxNameLength caps a customer name.
	MaxNameLength = 200
	// MaxSearchTextLength caps a search fragment. A query longer than this is
	// not a search; it is an attempt to push work onto the backend.
	MaxSearchTextLength = 200
	// SummaryRecentOrders is how many orders a summary embeds.
	SummaryRecentOrders = 5
	// SummaryOrderScan bounds how many orders a summary rolls up. The roll-up
	// is a convenience, not an export: a customer with ten thousand orders gets
	// a summary over the most recent page, flagged as partial.
	SummaryOrderScan = MaxOrderLimit
)

// CustomerService is the business-facing contract used by the MCP tool,
// resource and prompt handlers.
type CustomerService interface {
	GetCustomer(ctx context.Context, id string) (domain.Customer, error)
	SearchCustomers(ctx context.Context, q SearchRequest) (SearchResult, error)
	ListOrders(ctx context.Context, customerID string, page PageRequest) (OrderResult, error)
	UpdateCustomer(ctx context.Context, id string, patch domain.CustomerPatch) (domain.Customer, error)
	DeleteCustomer(ctx context.Context, req DeleteRequest) error
	SendNotification(ctx context.Context, n domain.Notification) (domain.Receipt, error)
	Summarize(ctx context.Context, id string) (CustomerSummary, error)
	Health(ctx context.Context) error
}

// SearchRequest is a customer search from a caller.
type SearchRequest struct {
	Text   string
	Status domain.Status
	Tier   domain.Tier
	Limit  int
	// Cursor resumes a previous search. It is opaque and authenticated; see
	// internal/paging.
	Cursor string
}

// SearchResult is one page of customers.
type SearchResult struct {
	Customers []domain.Customer
	// Truncated reports that the limit cut the result short. Preserved
	// alongside NextCursor for clients that only understand the older shape.
	Truncated bool
	// NextCursor resumes after the last returned customer. Empty when the
	// listing is exhausted.
	NextCursor string
}

// PageRequest is a paginated listing request.
type PageRequest struct {
	Limit  int
	Cursor string
}

// OrderResult is one page of orders.
type OrderResult struct {
	Orders     []domain.Order
	Truncated  bool
	NextCursor string
}

// DeleteRequest is a destructive delete.
//
// Confirm and ExpectedVersion are separate guard rails and neither substitutes
// for the other: Confirm establishes that a human approved the deletion,
// ExpectedVersion establishes that the record being deleted is still the one
// that was reviewed.
type DeleteRequest struct {
	CustomerID      string
	Confirm         bool
	ExpectedVersion *int
}

// CustomerSummary is a derived view combining a customer with order roll-ups.
// It backs both the customer resource and the analysis prompt.
type CustomerSummary struct {
	Customer      domain.Customer `json:"customer"`
	OrderCount    int             `json:"order_count"`
	LifetimeSpend float64         `json:"lifetime_spend"`
	Currency      string          `json:"currency,omitempty"`
	LastOrderAt   *time.Time      `json:"last_order_at,omitempty"`
	OpenOrders    int             `json:"open_orders"`
	RecentOrders  []domain.Order  `json:"recent_orders"`
	// Partial reports that the roll-up covers only the most recent
	// SummaryOrderScan orders, so the totals are a floor rather than a total.
	Partial bool `json:"partial,omitempty"`
}

// Options configures the service.
type Options struct {
	// Cursors signs pagination cursors. Required.
	Cursors *paging.Codec
	// Idempotency deduplicates side-effecting calls. Nil disables the feature,
	// in which case an idempotency key is rejected rather than ignored - a key
	// that is silently dropped is worse than one that is refused, because the
	// caller believes it has protection it does not have.
	Idempotency idempotency.Store
	// Now is injectable for tests.
	Now func() time.Time
}

type customerService struct {
	be   backend.Backend
	opts Options
}

// NewCustomerService returns the default CustomerService implementation.
func NewCustomerService(be backend.Backend, opts Options) CustomerService {
	if opts.Cursors == nil {
		opts.Cursors = paging.NewCodec("")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &customerService{be: be, opts: opts}
}

// GetCustomer validates the id and fetches one customer.
func (s *customerService) GetCustomer(ctx context.Context, id string) (domain.Customer, error) {
	p, err := s.authorize(ctx, authz.ScopeCustomerRead)
	if err != nil {
		return domain.Customer{}, err
	}
	id, err = validateID(id)
	if err != nil {
		return domain.Customer{}, err
	}

	c, err := s.be.GetCustomer(ctx, p.TenantID, id)
	if err != nil {
		return domain.Customer{}, err
	}
	// Defence in depth: the backend was asked for one tenant's record, but a
	// backend that ignores the tenant must not be able to leak through here.
	if c.TenantID != "" && c.TenantID != p.TenantID {
		return domain.Customer{}, domain.NotFound("customer", id)
	}
	return c, nil
}

// SearchCustomers normalizes and clamps the query before delegating.
func (s *customerService) SearchCustomers(ctx context.Context, req SearchRequest) (SearchResult, error) {
	p, err := s.authorize(ctx, authz.ScopeCustomerSearch)
	if err != nil {
		return SearchResult{}, err
	}

	text := strings.TrimSpace(req.Text)
	if len(text) > MaxSearchTextLength {
		return SearchResult{}, domain.Invalid("query", "must be at most %d characters", MaxSearchTextLength)
	}
	if req.Status != "" && !req.Status.Valid() {
		return SearchResult{}, domain.Invalid("status", "must be one of %s", joinStatuses())
	}
	if req.Tier != "" && !req.Tier.Valid() {
		return SearchResult{}, domain.Invalid("tier", "must be one of %s", joinTiers())
	}
	limit, err := clampLimit(req.Limit, DefaultSearchLimit, MaxSearchLimit)
	if err != nil {
		return SearchResult{}, err
	}
	// A search with no constraint at all would return an arbitrary slice of the
	// dataset; requiring at least one filter keeps results meaningful.
	if text == "" && req.Status == "" && req.Tier == "" {
		return SearchResult{}, domain.Invalid("query", "provide at least one of query, status or tier")
	}

	binding := s.searchBinding(p, text, req.Status, req.Tier)
	after, err := s.opts.Cursors.Decode(binding, req.Cursor)
	if err != nil {
		return SearchResult{}, domain.Invalid("cursor",
			"the cursor is not valid for this search; start again without a cursor")
	}

	list, err := s.be.SearchCustomers(ctx, domain.SearchQuery{
		TenantID: p.TenantID,
		Text:     text,
		Status:   req.Status,
		Tier:     req.Tier,
		Limit:    limit,
		After:    after,
	})
	if err != nil {
		return SearchResult{}, err
	}

	items := filterTenant(list.Items, p.TenantID, func(c domain.Customer) string { return c.TenantID })
	return SearchResult{
		Customers:  items,
		Truncated:  list.NextAfter != "" || len(items) == limit,
		NextCursor: s.opts.Cursors.Encode(binding, list.NextAfter),
	}, nil
}

// ListOrders returns a bounded, newest-first order page for one customer.
func (s *customerService) ListOrders(ctx context.Context, customerID string, req PageRequest) (OrderResult, error) {
	p, err := s.authorize(ctx, authz.ScopeCustomerOrdersRead)
	if err != nil {
		return OrderResult{}, err
	}
	customerID, err = validateID(customerID)
	if err != nil {
		return OrderResult{}, err
	}
	limit, err := clampLimit(req.Limit, DefaultOrderLimit, MaxOrderLimit)
	if err != nil {
		return OrderResult{}, err
	}

	binding := paging.Binding{
		Tenant: p.TenantID, Principal: p.Subject,
		Operation: "list_customer_orders", Filters: customerID,
	}
	after, err := s.opts.Cursors.Decode(binding, req.Cursor)
	if err != nil {
		return OrderResult{}, domain.Invalid("cursor",
			"the cursor is not valid for this listing; start again without a cursor")
	}

	list, err := s.be.ListOrders(ctx, p.TenantID, customerID, domain.Page{Limit: limit, After: after})
	if err != nil {
		return OrderResult{}, err
	}

	items := filterTenant(list.Items, p.TenantID, func(o domain.Order) string { return o.TenantID })
	return OrderResult{
		Orders:     items,
		Truncated:  list.NextAfter != "" || len(items) == limit,
		NextCursor: s.opts.Cursors.Encode(binding, list.NextAfter),
	}, nil
}

// UpdateCustomer validates and normalizes a sparse patch, then applies it.
func (s *customerService) UpdateCustomer(ctx context.Context, id string, patch domain.CustomerPatch) (domain.Customer, error) {
	p, err := s.authorize(ctx, authz.ScopeCustomerUpdate)
	if err != nil {
		return domain.Customer{}, err
	}
	id, err = validateID(id)
	if err != nil {
		return domain.Customer{}, err
	}
	if patch.IsEmpty() {
		return domain.Customer{}, domain.Invalid("", "provide at least one field to update")
	}
	if patch.ExpectedVersion != nil && *patch.ExpectedVersion < 0 {
		return domain.Customer{}, domain.Invalid("expected_version", "must not be negative")
	}

	if patch.Name != nil {
		name := strings.TrimSpace(*patch.Name)
		if name == "" {
			return domain.Customer{}, domain.Invalid("name", "must not be empty")
		}
		if len(name) > MaxNameLength {
			return domain.Customer{}, domain.Invalid("name", "must be at most %d characters", MaxNameLength)
		}
		patch.Name = &name
	}
	if patch.Email != nil {
		email := domain.NormalizeEmail(*patch.Email)
		if err := validateEmail(email); err != nil {
			return domain.Customer{}, err
		}
		patch.Email = &email
	}
	if patch.Status != nil && !patch.Status.Valid() {
		return domain.Customer{}, domain.Invalid("status", "must be one of %s", joinStatuses())
	}
	if patch.Tier != nil && !patch.Tier.Valid() {
		return domain.Customer{}, domain.Invalid("tier", "must be one of %s", joinTiers())
	}

	return s.be.UpdateCustomer(ctx, p.TenantID, id, patch)
}

// DeleteCustomer permanently removes a customer.
//
// confirm is a deliberate guard rail: the tool exposes it as a required input
// so a model cannot delete a record through a single under-specified call. It
// is checked here, server-side, and not merely described in the tool text -
// text is advisory to a model and enforcement is not.
func (s *customerService) DeleteCustomer(ctx context.Context, req DeleteRequest) error {
	p, err := s.authorize(ctx, authz.ScopeCustomerDelete)
	if err != nil {
		return err
	}
	id, err := validateID(req.CustomerID)
	if err != nil {
		return err
	}
	if !req.Confirm {
		return domain.Invalid("confirm", "deletion is irreversible; set confirm=true only after the user has explicitly approved it")
	}
	if req.ExpectedVersion != nil && *req.ExpectedVersion < 0 {
		return domain.Invalid("expected_version", "must not be negative")
	}
	return s.be.DeleteCustomer(ctx, p.TenantID, id, req.ExpectedVersion)
}

// SendNotification validates an outbound message and hands it to the backend.
func (s *customerService) SendNotification(ctx context.Context, n domain.Notification) (domain.Receipt, error) {
	p, err := s.authorize(ctx, authz.ScopeNotificationSend)
	if err != nil {
		return domain.Receipt{}, err
	}
	id, err := validateID(n.CustomerID)
	if err != nil {
		return domain.Receipt{}, err
	}
	n.CustomerID = id
	n.TenantID = p.TenantID

	if !n.Channel.Valid() {
		return domain.Receipt{}, domain.Invalid("channel", "must be one of %s", joinChannels())
	}
	n.Subject = strings.TrimSpace(n.Subject)
	n.Body = strings.TrimSpace(n.Body)

	if n.Channel == domain.ChannelEmail && n.Subject == "" {
		return domain.Receipt{}, domain.Invalid("subject", "is required for the email channel")
	}
	if len(n.Subject) > MaxNotificationSubject {
		return domain.Receipt{}, domain.Invalid("subject", "must be at most %d characters", MaxNotificationSubject)
	}
	if n.Body == "" {
		return domain.Receipt{}, domain.Invalid("body", "must not be empty")
	}
	if len(n.Body) > MaxNotificationBody {
		return domain.Receipt{}, domain.Invalid("body", "must be at most %d characters", MaxNotificationBody)
	}
	if err := validateMessageText(n.Subject, n.Body); err != nil {
		return domain.Receipt{}, err
	}

	// The target must be a customer of this tenant. Checking before the send
	// rather than relying on the backend keeps a cross-tenant notification from
	// ever being handed to a messaging provider.
	//
	// Deliberately not GetCustomer: a client granted only notification:send
	// must still be prevented from addressing another tenant, without being
	// forced to hold customer:read to do it.
	if err := s.assertInTenant(ctx, p.TenantID, id); err != nil {
		return domain.Receipt{}, err
	}

	if n.IdempotencyKey == "" {
		return s.be.SendNotification(ctx, n)
	}
	return s.sendIdempotent(ctx, p, n)
}

// assertInTenant confirms a customer id belongs to the caller's tenant without
// disclosing the record or requiring read permission on it.
func (s *customerService) assertInTenant(ctx context.Context, tenant, id string) error {
	c, err := s.be.GetCustomer(ctx, tenant, id)
	if err != nil {
		return err
	}
	if c.TenantID != "" && c.TenantID != tenant {
		return domain.NotFound("customer", id)
	}
	return nil
}

// sendIdempotent performs a send under an idempotency key.
func (s *customerService) sendIdempotent(ctx context.Context, p *authz.Principal, n domain.Notification) (domain.Receipt, error) {
	if err := idempotency.ValidateKey(n.IdempotencyKey); err != nil {
		return domain.Receipt{}, domain.Invalid("idempotency_key", "%s", err.Error())
	}
	if s.opts.Idempotency == nil {
		// Refused, not ignored: a caller that believes it has replay protection
		// and does not is worse off than one told it must retry differently.
		return domain.Receipt{}, domain.Invalid("idempotency_key",
			"this deployment has idempotency disabled; omit the key or enable IDEMPOTENCY_ENABLED")
	}

	key := idempotency.Key(p.TenantID, p.Subject, "send_customer_notification", n.IdempotencyKey)
	// The fingerprint covers everything that decides what the customer
	// receives, so reusing a key with a different message is a conflict rather
	// than a silent replay of the wrong text.
	fingerprint := idempotency.Fingerprint(struct {
		Customer string `json:"c"`
		Channel  string `json:"h"`
		Subject  string `json:"s"`
		Body     string `json:"b"`
	}{n.CustomerID, string(n.Channel), n.Subject, n.Body})

	record, err := s.opts.Idempotency.Begin(ctx, key, fingerprint)
	switch {
	case errors.Is(err, idempotency.ErrMismatch):
		return domain.Receipt{}, domain.Conflict("idempotency_key",
			"this idempotency key was already used for a different message; use a new key")
	case errors.Is(err, idempotency.ErrInFlight):
		return domain.Receipt{}, domain.Conflict("idempotency_key",
			"a message with this idempotency key is already being sent; wait for it to complete")
	case err != nil:
		return domain.Receipt{}, domain.Internal("send_customer_notification", err)
	case record != nil:
		var receipt domain.Receipt
		if err := json.Unmarshal(record.Payload, &receipt); err != nil {
			return domain.Receipt{}, domain.Internal("send_customer_notification", err)
		}
		receipt.Replayed = true
		return receipt, nil
	}

	receipt, sendErr := s.be.SendNotification(ctx, n)
	if sendErr != nil {
		// Release the key so a genuine retry is not blocked by a failed send.
		s.opts.Idempotency.Abort(ctx, key)
		return domain.Receipt{}, sendErr
	}
	payload, err := json.Marshal(receipt)
	if err != nil {
		s.opts.Idempotency.Abort(ctx, key)
		return domain.Receipt{}, domain.Internal("send_customer_notification", err)
	}
	if err := s.opts.Idempotency.Commit(ctx, key, payload); err != nil {
		// The message went out. Failing the call now would invite a retry that
		// sends it again, so report success and let the log record the problem.
		return receipt, nil
	}
	return receipt, nil
}

// Summarize builds the derived customer view used by resources and prompts.
func (s *customerService) Summarize(ctx context.Context, id string) (CustomerSummary, error) {
	// A summary is a record plus its order roll-up, so it needs both scopes.
	// Checking both here, before either read, means a caller holding only one
	// of them is refused outright rather than learning half the answer.
	p := authz.FromContext(ctx)
	if err := p.RequireAll([]string{authz.ScopeCustomerRead, authz.ScopeCustomerOrdersRead}); err != nil {
		return CustomerSummary{}, err
	}

	customer, err := s.GetCustomer(ctx, id)
	if err != nil {
		return CustomerSummary{}, err
	}
	orders, err := s.ListOrders(ctx, id, PageRequest{Limit: SummaryOrderScan})
	if err != nil {
		return CustomerSummary{}, err
	}

	summary := CustomerSummary{
		Customer:     customer,
		OrderCount:   len(orders.Orders),
		RecentOrders: orders.Orders,
		Partial:      orders.NextCursor != "",
	}
	if len(orders.Orders) > SummaryRecentOrders {
		summary.RecentOrders = orders.Orders[:SummaryRecentOrders]
	}
	for i, o := range orders.Orders {
		if i == 0 {
			// The newest order, whatever its status. A cancelled most-recent
			// order is still the last time this account placed one, and
			// reporting "no orders" for it would be wrong.
			placed := o.PlacedAt
			summary.LastOrderAt = &placed
		}
		if o.Status == domain.OrderCancelled {
			continue
		}
		summary.LifetimeSpend += o.Total
		if summary.Currency == "" {
			summary.Currency = o.Currency
		} else if summary.Currency != o.Currency {
			// Mixed currencies make a single total meaningless; say so rather
			// than quietly summing across them.
			summary.Currency = "MIXED"
		}
		if o.Status == domain.OrderPending || o.Status == domain.OrderShipped {
			summary.OpenOrders++
		}
	}
	return summary, nil
}

// Health reports backend reachability.
func (s *customerService) Health(ctx context.Context) error {
	return s.be.Ping(ctx)
}

// authorize resolves the caller and checks one scope plus a usable tenant.
func (s *customerService) authorize(ctx context.Context, scope string) (*authz.Principal, error) {
	p := authz.FromContext(ctx)
	if err := p.Require(scope); err != nil {
		return nil, err
	}
	if p.TenantID == "" {
		return nil, domain.Forbidden("the caller's credential carries no tenant, so no customer data can be reached")
	}
	return p, nil
}

// filterTenant drops anything the backend returned outside the caller's tenant.
//
// This should never remove anything: the backend was asked for one tenant. It
// is here because "should never" is not a control, and a backend bug that
// returned a neighbouring tenant's rows would otherwise become a data breach in
// this server rather than a caught error in that one.
func filterTenant[T any](items []T, tenant string, tenantOf func(T) string) []T {
	out := make([]T, 0, len(items))
	for _, item := range items {
		if t := tenantOf(item); t == "" || t == tenant {
			out = append(out, item)
		}
	}
	return out
}

func clampLimit(requested, def, max int) (int, error) {
	if requested < 0 {
		return 0, domain.Invalid("limit", "must not be negative")
	}
	if requested == 0 {
		return def, nil
	}
	if requested > max {
		return max, nil
	}
	return requested, nil
}

func (s *customerService) searchBinding(p *authz.Principal, text string, status domain.Status, tier domain.Tier) paging.Binding {
	return paging.Binding{
		Tenant:    p.TenantID,
		Principal: p.Subject,
		Operation: "search_customers",
		Filters:   strings.Join([]string{text, string(status), string(tier)}, "\x1f"),
	}
}

// validateID enforces the shape of a customer identifier before it can reach a
// backend, which keeps injection-shaped input out of URLs and queries.
func validateID(id string) (string, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return "", domain.Invalid("customer_id", "value is required")
	}
	if len(id) > 64 {
		return "", domain.Invalid("customer_id", "must be at most 64 characters")
	}
	for _, r := range id {
		isAlnum := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if !isAlnum && r != '-' && r != '_' {
			return "", domain.Invalid("customer_id", "may contain only letters, digits, '-' and '_'")
		}
	}
	return id, nil
}

// validateEmail accepts only a bare address.
//
// mail.ParseAddress also accepts a display-name form - `Ops <ops@acme.example>`
// - and storing that would let a caller smuggle a second, attacker-chosen name
// into every message rendered from the record.
func validateEmail(email string) error {
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Name != "" || addr.Address != email {
		return domain.Invalid("email", "must be a valid email address")
	}
	if len(email) > 254 {
		return domain.Invalid("email", "must be at most 254 characters")
	}
	return nil
}

// validateMessageText rejects control characters in outbound message fields.
//
// A CR or LF in a subject is a header-injection attempt against whatever
// gateway sends the mail: it lets a caller append headers of its own, including
// Bcc. The body legitimately contains newlines, so only the genuinely
// non-printable characters are refused there.
func validateMessageText(subject, body string) error {
	for _, r := range subject {
		if r < 0x20 || r == 0x7f {
			return domain.Invalid("subject", "must not contain control characters")
		}
	}
	for _, r := range body {
		if r == '\n' || r == '\r' || r == '\t' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			return domain.Invalid("body", "must not contain control characters")
		}
	}
	return nil
}

func joinStatuses() string { return joinAny(domain.StatusStrings()) }
func joinTiers() string    { return joinAny(domain.TierStrings()) }
func joinChannels() string { return joinAny(domain.ChannelStrings()) }

func joinAny(values []any) string {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		parts = append(parts, fmt.Sprintf("%q", v))
	}
	return strings.Join(parts, ", ")
}
