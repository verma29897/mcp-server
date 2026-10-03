package customer

import (
	"context"

	"github.com/verma29897/mcp-server/internal/domain"
	"github.com/verma29897/mcp-server/internal/services"
)

// Handlers implements the tool handlers for this package.
//
// Handlers are deliberately thin: shape the input, call one service method,
// shape the result. Business rules - including every authorization and tenancy
// decision - live in internal/services, and the MCP result and error encoding
// lives in internal/mcp. Because these methods take and return plain Go values,
// they are unit-testable without a server, a transport or a client.
type Handlers struct {
	svc services.CustomerService
}

// NewHandlers returns handlers bound to a customer service.
func NewHandlers(svc services.CustomerService) *Handlers {
	return &Handlers{svc: svc}
}

// GetCustomer handles the get_customer tool.
func (h *Handlers) GetCustomer(ctx context.Context, in GetCustomerInput) (GetCustomerOutput, error) {
	c, err := h.svc.GetCustomer(ctx, in.CustomerID)
	if err != nil {
		return GetCustomerOutput{}, err
	}
	return GetCustomerOutput{Customer: toCustomerPayload(c)}, nil
}

// SearchCustomers handles the search_customers tool.
func (h *Handlers) SearchCustomers(ctx context.Context, in SearchCustomersInput) (SearchCustomersOutput, error) {
	res, err := h.svc.SearchCustomers(ctx, services.SearchRequest{
		Text:   in.Query,
		Status: domain.Status(in.Status),
		Tier:   domain.Tier(in.Tier),
		Limit:  in.Limit,
		Cursor: in.Cursor,
	})
	if err != nil {
		return SearchCustomersOutput{}, err
	}
	return SearchCustomersOutput{
		Customers:  toCustomerPayloads(res.Customers),
		Count:      len(res.Customers),
		Truncated:  res.Truncated,
		NextCursor: res.NextCursor,
	}, nil
}

// ListCustomerOrders handles the list_customer_orders tool.
func (h *Handlers) ListCustomerOrders(ctx context.Context, in ListCustomerOrdersInput) (ListCustomerOrdersOutput, error) {
	res, err := h.svc.ListOrders(ctx, in.CustomerID, services.PageRequest{Limit: in.Limit, Cursor: in.Cursor})
	if err != nil {
		return ListCustomerOrdersOutput{}, err
	}
	return ListCustomerOrdersOutput{
		CustomerID: in.CustomerID,
		Orders:     toOrderPayloads(res.Orders),
		Count:      len(res.Orders),
		Truncated:  res.Truncated,
		NextCursor: res.NextCursor,
	}, nil
}

// UpdateCustomer handles the update_customer tool.
//
// The input uses omitempty strings, so an absent field and an empty string are
// the same thing on the wire. That is intentional: none of these fields may be
// set to empty, so "" can only mean "leave unchanged".
func (h *Handlers) UpdateCustomer(ctx context.Context, in UpdateCustomerInput) (UpdateCustomerOutput, error) {
	var (
		patch   domain.CustomerPatch
		changed []string
	)
	if in.Name != "" {
		name := in.Name
		patch.Name = &name
		changed = append(changed, "name")
	}
	if in.Email != "" {
		email := in.Email
		patch.Email = &email
		changed = append(changed, "email")
	}
	if in.Status != "" {
		status := domain.Status(in.Status)
		patch.Status = &status
		changed = append(changed, "status")
	}
	if in.Tier != "" {
		tier := domain.Tier(in.Tier)
		patch.Tier = &tier
		changed = append(changed, "tier")
	}
	patch.ExpectedVersion = optionalVersion(in.ExpectedVersion)

	c, err := h.svc.UpdateCustomer(ctx, in.CustomerID, patch)
	if err != nil {
		return UpdateCustomerOutput{}, err
	}
	if changed == nil {
		changed = []string{}
	}
	return UpdateCustomerOutput{
		Customer:      toCustomerPayload(c),
		UpdatedFields: changed,
	}, nil
}

// DeleteCustomer handles the delete_customer tool.
func (h *Handlers) DeleteCustomer(ctx context.Context, in DeleteCustomerInput) (DeleteCustomerOutput, error) {
	err := h.svc.DeleteCustomer(ctx, services.DeleteRequest{
		CustomerID:      in.CustomerID,
		Confirm:         in.Confirm,
		ExpectedVersion: optionalVersion(in.ExpectedVersion),
	})
	if err != nil {
		return DeleteCustomerOutput{}, err
	}
	return DeleteCustomerOutput{CustomerID: in.CustomerID, Deleted: true}, nil
}

// SendCustomerNotification handles the send_customer_notification tool.
func (h *Handlers) SendCustomerNotification(ctx context.Context, in SendCustomerNotificationInput) (SendCustomerNotificationOutput, error) {
	receipt, err := h.svc.SendNotification(ctx, domain.Notification{
		CustomerID:     in.CustomerID,
		Channel:        domain.Channel(in.Channel),
		Subject:        in.Subject,
		Body:           in.Body,
		IdempotencyKey: in.IdempotencyKey,
	})
	if err != nil {
		return SendCustomerNotificationOutput{}, err
	}
	return SendCustomerNotificationOutput{
		MessageID:  receipt.MessageID,
		CustomerID: receipt.CustomerID,
		Channel:    string(receipt.Channel),
		AcceptedAt: receipt.AcceptedAt,
		Replayed:   receipt.Replayed,
	}, nil
}
