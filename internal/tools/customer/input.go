// Package customer defines the MCP tool surface for customer operations:
// the typed input/output schemas, the tool descriptors, and thin handlers that
// delegate to the service layer.
//
// This package depends on the MCP SDK only for tool metadata types. It contains
// no protocol plumbing, no transport awareness and no business rules.
package customer

import (
	"time"

	"github.com/verma29897/mcp-server/internal/domain"
	"github.com/verma29897/mcp-server/internal/services"
)

// Input and output types below are the single source of truth for every tool's
// JSON Schema: mcp.AddTool infers both schemas from these Go types, so schema
// and handler cannot drift apart.
//
// Schema rules that follow from the inference used by the SDK:
//   - a field WITHOUT omitempty/omitzero becomes a REQUIRED property;
//   - a field WITH omitempty becomes OPTIONAL;
//   - the `jsonschema` struct tag supplies the property description.
//
// Constraints the tag cannot express (enums, bounds) are applied in tool.go by
// patching the inferred schema, which keeps one source of truth.

// GetCustomerInput is the input for the get_customer tool.
type GetCustomerInput struct {
	CustomerID string `json:"customer_id" jsonschema:"Unique customer identifier, for example 1001. Letters, digits, hyphen and underscore only."`
}

// SearchCustomersInput is the input for the search_customers tool.
type SearchCustomersInput struct {
	Query  string `json:"query,omitempty" jsonschema:"Free-text fragment matched case-insensitively against customer name, email and id."`
	Status string `json:"status,omitempty" jsonschema:"Restrict results to this account status."`
	Tier   string `json:"tier,omitempty" jsonschema:"Restrict results to this commercial tier."`
	Limit  int    `json:"limit,omitempty" jsonschema:"Maximum number of customers to return. Defaults to 20, capped at 100."`
	Cursor string `json:"cursor,omitempty" jsonschema:"Opaque next_cursor value from a previous call with the same filters, to fetch the next page. Do not construct or edit one."`
}

// ListCustomerOrdersInput is the input for the list_customer_orders tool.
type ListCustomerOrdersInput struct {
	CustomerID string `json:"customer_id" jsonschema:"Unique customer identifier whose orders should be listed."`
	Limit      int    `json:"limit,omitempty" jsonschema:"Maximum number of orders to return, newest first. Defaults to 20, capped at 200."`
	Cursor     string `json:"cursor,omitempty" jsonschema:"Opaque next_cursor value from a previous call for the same customer, to fetch the next page. Do not construct or edit one."`
}

// UpdateCustomerInput is the input for the update_customer tool. Every field
// except customer_id is optional; omitted fields are left unchanged.
type UpdateCustomerInput struct {
	CustomerID      string `json:"customer_id" jsonschema:"Unique customer identifier to update."`
	Name            string `json:"name,omitempty" jsonschema:"New display name. Omit to leave unchanged."`
	Email           string `json:"email,omitempty" jsonschema:"New contact email address. Omit to leave unchanged."`
	Status          string `json:"status,omitempty" jsonschema:"New account status. Omit to leave unchanged."`
	Tier            string `json:"tier,omitempty" jsonschema:"New commercial tier. Omit to leave unchanged."`
	ExpectedVersion int    `json:"expected_version,omitempty" jsonschema:"The version field from the record you read. Supply it to make the update fail with CONFLICT if someone else changed the record in the meantime, instead of silently overwriting their change."`
}

// DeleteCustomerInput is the input for the delete_customer tool.
type DeleteCustomerInput struct {
	CustomerID      string `json:"customer_id" jsonschema:"Unique customer identifier to permanently delete."`
	Confirm         bool   `json:"confirm" jsonschema:"Must be true. Set it only after the user has explicitly approved deleting this specific customer; the operation cannot be undone."`
	ExpectedVersion int    `json:"expected_version,omitempty" jsonschema:"The version field from the record you showed the user. Supply it so the deletion fails with CONFLICT if the record changed after they approved it."`
}

// SendCustomerNotificationInput is the input for the
// send_customer_notification tool.
type SendCustomerNotificationInput struct {
	CustomerID     string `json:"customer_id" jsonschema:"Unique customer identifier to notify."`
	Channel        string `json:"channel" jsonschema:"Delivery channel for the message."`
	Subject        string `json:"subject,omitempty" jsonschema:"Message subject. Required for the email channel, ignored for sms."`
	Body           string `json:"body" jsonschema:"Message body in plain text, at most 4000 characters."`
	IdempotencyKey string `json:"idempotency_key,omitempty" jsonschema:"A unique key for this specific message, 8 to 128 characters of letters, digits, '-', '_', '.' or ':'. Generate it once before the first attempt and reuse the SAME key if you retry, so a retry replays the original receipt instead of contacting the customer twice. Never reuse a key for a different message."`
}

// CustomerPayload is the wire shape of a customer in tool output.
//
// It is a projection of domain.Customer, not the type itself: the tenant a
// record belongs to is an internal boundary and never travels to a client.
type CustomerPayload struct {
	CustomerID string    `json:"customer_id" jsonschema:"Unique customer identifier."`
	Name       string    `json:"name" jsonschema:"Customer display name."`
	Email      string    `json:"email" jsonschema:"Primary contact email address."`
	Status     string    `json:"status" jsonschema:"Account status: active, inactive or suspended."`
	Tier       string    `json:"tier" jsonschema:"Commercial tier: free, pro or enterprise."`
	Country    string    `json:"country" jsonschema:"ISO 3166-1 alpha-2 country code."`
	Version    int       `json:"version" jsonschema:"Record version, incremented on every change. Pass it back as expected_version on update_customer or delete_customer to avoid overwriting a concurrent change."`
	CreatedAt  time.Time `json:"created_at" jsonschema:"RFC 3339 timestamp of when the customer was created."`
	UpdatedAt  time.Time `json:"updated_at" jsonschema:"RFC 3339 timestamp of the last modification."`
}

// OrderPayload is the wire shape of an order in tool output.
type OrderPayload struct {
	OrderID    string    `json:"order_id" jsonschema:"Unique order identifier."`
	CustomerID string    `json:"customer_id" jsonschema:"Identifier of the customer who placed the order."`
	Total      float64   `json:"total" jsonschema:"Order total in the order currency."`
	Currency   string    `json:"currency" jsonschema:"ISO 4217 currency code of the total."`
	Status     string    `json:"status" jsonschema:"Fulfilment status: pending, shipped, delivered or cancelled."`
	PlacedAt   time.Time `json:"placed_at" jsonschema:"RFC 3339 timestamp of when the order was placed."`
}

// GetCustomerOutput is the structured output of the get_customer tool.
type GetCustomerOutput struct {
	Customer CustomerPayload `json:"customer" jsonschema:"The requested customer record."`
}

// SearchCustomersOutput is the structured output of the search_customers tool.
type SearchCustomersOutput struct {
	Customers  []CustomerPayload `json:"customers" jsonschema:"Matching customers, newest first."`
	Count      int               `json:"count" jsonschema:"Number of customers returned, which may be less than the total number of matches because of the limit."`
	Truncated  bool              `json:"truncated" jsonschema:"True when the result was cut off by the limit and more matches may exist."`
	NextCursor string            `json:"next_cursor,omitempty" jsonschema:"Pass this back as cursor, with the same filters, to fetch the next page. Absent when there are no more results."`
}

// ListCustomerOrdersOutput is the structured output of the
// list_customer_orders tool.
type ListCustomerOrdersOutput struct {
	CustomerID string         `json:"customer_id" jsonschema:"Identifier of the customer the orders belong to."`
	Orders     []OrderPayload `json:"orders" jsonschema:"Orders for this customer, newest first."`
	Count      int            `json:"count" jsonschema:"Number of orders returned."`
	Truncated  bool           `json:"truncated" jsonschema:"True when the result was cut off by the limit and older orders exist."`
	NextCursor string         `json:"next_cursor,omitempty" jsonschema:"Pass this back as cursor for the same customer to fetch the next page. Absent when there are no more orders."`
}

// UpdateCustomerOutput is the structured output of the update_customer tool.
type UpdateCustomerOutput struct {
	Customer      CustomerPayload `json:"customer" jsonschema:"The customer record after the update was applied."`
	UpdatedFields []string        `json:"updated_fields" jsonschema:"Names of the fields that were changed by this call."`
}

// DeleteCustomerOutput is the structured output of the delete_customer tool.
type DeleteCustomerOutput struct {
	CustomerID string `json:"customer_id" jsonschema:"Identifier of the customer that was deleted."`
	Deleted    bool   `json:"deleted" jsonschema:"Always true when the call succeeds."`
}

// SendCustomerNotificationOutput is the structured output of the
// send_customer_notification tool.
type SendCustomerNotificationOutput struct {
	MessageID  string    `json:"message_id" jsonschema:"Provider-assigned identifier for the accepted message."`
	CustomerID string    `json:"customer_id" jsonschema:"Identifier of the notified customer."`
	Channel    string    `json:"channel" jsonschema:"Channel the message was accepted for."`
	AcceptedAt time.Time `json:"accepted_at" jsonschema:"RFC 3339 timestamp of when the provider accepted the message."`
	Replayed   bool      `json:"replayed,omitempty" jsonschema:"True when this receipt was replayed from a previous call with the same idempotency_key. No new message was sent."`
}

// toCustomerPayload converts a domain customer into its wire shape.
func toCustomerPayload(c domain.Customer) CustomerPayload {
	return CustomerPayload{
		CustomerID: c.ID,
		Name:       c.Name,
		Email:      c.Email,
		Status:     string(c.Status),
		Tier:       string(c.Tier),
		Country:    c.Country,
		Version:    c.Version,
		CreatedAt:  c.CreatedAt,
		UpdatedAt:  c.UpdatedAt,
	}
}

// toCustomerPayloads converts a slice of domain customers.
func toCustomerPayloads(cs []domain.Customer) []CustomerPayload {
	out := make([]CustomerPayload, 0, len(cs))
	for _, c := range cs {
		out = append(out, toCustomerPayload(c))
	}
	return out
}

// toOrderPayload converts a domain order into its wire shape.
func toOrderPayload(o domain.Order) OrderPayload {
	return OrderPayload{
		OrderID:    o.ID,
		CustomerID: o.CustomerID,
		Total:      o.Total,
		Currency:   o.Currency,
		Status:     string(o.Status),
		PlacedAt:   o.PlacedAt,
	}
}

// toOrderPayloads converts a slice of domain orders.
func toOrderPayloads(os []domain.Order) []OrderPayload {
	out := make([]OrderPayload, 0, len(os))
	for _, o := range os {
		out = append(out, toOrderPayload(o))
	}
	return out
}

// optionalVersion turns the zero-valued schema field into the tri-state the
// service expects.
//
// Zero means "not supplied", which is why version numbering starts at 1: a
// caller cannot express "I expect version 0", and there is no such version to
// expect. Negative values are passed through so the service can reject them
// with a named field rather than silently ignoring nonsense.
func optionalVersion(v int) *int {
	if v == 0 {
		return nil
	}
	return &v
}

// Limits re-exported so the schema patches in tool.go read from one source.
const (
	maxSearchLimit = services.MaxSearchLimit
	maxOrderLimit  = services.MaxOrderLimit
)
