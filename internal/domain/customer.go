package domain

import (
	"strings"
	"time"
)

// Status is the lifecycle state of a customer account.
type Status string

const (
	StatusActive    Status = "active"
	StatusInactive  Status = "inactive"
	StatusSuspended Status = "suspended"
)

// ValidStatuses lists every accepted Status, in a stable order. It is reused
// for JSON Schema enum generation so the schema and the validator cannot drift.
var ValidStatuses = []Status{StatusActive, StatusInactive, StatusSuspended}

// Valid reports whether s is a known status.
func (s Status) Valid() bool {
	for _, v := range ValidStatuses {
		if v == s {
			return true
		}
	}
	return false
}

// Tier is the commercial plan a customer is on.
type Tier string

const (
	TierFree       Tier = "free"
	TierPro        Tier = "pro"
	TierEnterprise Tier = "enterprise"
)

// ValidTiers lists every accepted Tier, in a stable order.
var ValidTiers = []Tier{TierFree, TierPro, TierEnterprise}

// Valid reports whether t is a known tier.
func (t Tier) Valid() bool {
	for _, v := range ValidTiers {
		if v == t {
			return true
		}
	}
	return false
}

// Customer is a company customer record.
//
// TenantID is the isolation boundary: every read and every write is scoped to
// one tenant, and the field is never serialised towards an MCP client (the
// resource and tool layers project onto their own view types). Version backs
// optimistic locking on update_customer.
type Customer struct {
	ID        string    `json:"customer_id"`
	TenantID  string    `json:"tenant_id,omitempty"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	Status    Status    `json:"status"`
	Tier      Tier      `json:"tier"`
	Country   string    `json:"country"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CustomerPatch is a sparse update. A nil field means "leave unchanged".
//
// ExpectedVersion, when non-nil, is an optimistic-locking precondition: the
// write is refused with CodeConflict unless the stored record is still at that
// version. It is not itself a mutable field.
type CustomerPatch struct {
	Name            *string `json:"name,omitempty"`
	Email           *string `json:"email,omitempty"`
	Status          *Status `json:"status,omitempty"`
	Tier            *Tier   `json:"tier,omitempty"`
	ExpectedVersion *int    `json:"expected_version,omitempty"`
}

// IsEmpty reports whether the patch would change nothing. The precondition does
// not count as a change.
func (p CustomerPatch) IsEmpty() bool {
	return p.Name == nil && p.Email == nil && p.Status == nil && p.Tier == nil
}

// SearchQuery describes a customer search. Zero values mean "no constraint",
// except TenantID, which is always required by the time a query reaches a
// backend.
type SearchQuery struct {
	TenantID string
	// Text matches case-insensitively against name and email.
	Text   string
	Status Status
	Tier   Tier
	Limit  int
	// After resumes the listing immediately after this sort key. It is the
	// decoded, authorization-checked form of an opaque cursor.
	After string
}

// Page is a decoded pagination request for a listing.
type Page struct {
	Limit int
	// After resumes immediately after this sort key; empty starts at the top.
	After string
}

// CustomerList is one page of customers.
type CustomerList struct {
	Items []Customer
	// NextAfter is the sort key to resume after, empty when the listing is
	// exhausted. The service layer signs it into an opaque cursor.
	NextAfter string
}

// OrderStatus is the fulfilment state of an order.
type OrderStatus string

const (
	OrderPending   OrderStatus = "pending"
	OrderShipped   OrderStatus = "shipped"
	OrderDelivered OrderStatus = "delivered"
	OrderCancelled OrderStatus = "cancelled"
)

// Order is a purchase placed by a customer.
type Order struct {
	ID         string      `json:"order_id"`
	CustomerID string      `json:"customer_id"`
	TenantID   string      `json:"tenant_id,omitempty"`
	Total      float64     `json:"total"`
	Currency   string      `json:"currency"`
	Status     OrderStatus `json:"status"`
	PlacedAt   time.Time   `json:"placed_at"`
}

// OrderList is one page of orders.
type OrderList struct {
	Items     []Order
	NextAfter string
}

// Channel is a delivery medium for an outbound notification.
type Channel string

const (
	ChannelEmail Channel = "email"
	ChannelSMS   Channel = "sms"
)

// ValidChannels lists every accepted Channel, in a stable order.
var ValidChannels = []Channel{ChannelEmail, ChannelSMS}

// Valid reports whether c is a known channel.
func (c Channel) Valid() bool {
	for _, v := range ValidChannels {
		if v == c {
			return true
		}
	}
	return false
}

// Notification is an outbound message request. Sending one has an effect
// outside this system, so the tool that triggers it is annotated accordingly.
//
// IdempotencyKey, when set, lets a retry of the same request return the
// original receipt instead of contacting the customer twice.
type Notification struct {
	CustomerID     string  `json:"customer_id"`
	TenantID       string  `json:"tenant_id,omitempty"`
	Channel        Channel `json:"channel"`
	Subject        string  `json:"subject"`
	Body           string  `json:"body"`
	IdempotencyKey string  `json:"idempotency_key,omitempty"`
}

// Receipt acknowledges an accepted Notification.
type Receipt struct {
	MessageID  string    `json:"message_id"`
	CustomerID string    `json:"customer_id"`
	Channel    Channel   `json:"channel"`
	AcceptedAt time.Time `json:"accepted_at"`
	// Replayed reports that this receipt was served from the idempotency store
	// rather than produced by a fresh send.
	Replayed bool `json:"replayed,omitempty"`
}

// NormalizeEmail lower-cases and trims an email address for comparison and
// storage. It performs no validation; see services for that.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// StatusStrings returns ValidStatuses as plain strings, for schema enums.
func StatusStrings() []any {
	out := make([]any, 0, len(ValidStatuses))
	for _, s := range ValidStatuses {
		out = append(out, string(s))
	}
	return out
}

// TierStrings returns ValidTiers as plain strings, for schema enums.
func TierStrings() []any {
	out := make([]any, 0, len(ValidTiers))
	for _, t := range ValidTiers {
		out = append(out, string(t))
	}
	return out
}

// ChannelStrings returns ValidChannels as plain strings, for schema enums.
func ChannelStrings() []any {
	out := make([]any, 0, len(ValidChannels))
	for _, c := range ValidChannels {
		out = append(out, string(c))
	}
	return out
}
