package mcp

import (
	"context"
	"encoding/json"
	"log/slog"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/verma29897/mcp-server/internal/domain"
	"github.com/verma29897/mcp-server/internal/observability"
	"github.com/verma29897/mcp-server/internal/tools/customer"
)

// registerTools binds every tool descriptor to its handler.
//
// sdk.AddTool is the generic registration entry point: it infers the input and
// output JSON Schemas from the type parameters (unless the descriptor already
// carries a schema, as ours do), validates incoming arguments against the input
// schema before the handler runs, marshals the returned value into
// StructuredContent, and validates that against the output schema.
func registerTools(srv *sdk.Server, h *customer.Handlers, logger *slog.Logger, metrics *observability.Metrics, maxBytes int) {
	a := adapter{logger: logger, metrics: metrics, maxBytes: maxBytes}

	sdk.AddTool(srv, customer.GetCustomerTool,
		adapt(a, customer.GetCustomerTool.Name, h.GetCustomer))

	sdk.AddTool(srv, customer.SearchCustomersTool,
		adapt(a, customer.SearchCustomersTool.Name, h.SearchCustomers))

	sdk.AddTool(srv, customer.ListCustomerOrdersTool,
		adapt(a, customer.ListCustomerOrdersTool.Name, h.ListCustomerOrders))

	sdk.AddTool(srv, customer.UpdateCustomerTool,
		adapt(a, customer.UpdateCustomerTool.Name, h.UpdateCustomer))

	sdk.AddTool(srv, customer.DeleteCustomerTool,
		adapt(a, customer.DeleteCustomerTool.Name, h.DeleteCustomer))

	sdk.AddTool(srv, customer.SendCustomerNotificationTool,
		adapt(a, customer.SendCustomerNotificationTool.Name, h.SendCustomerNotification))
}

// handlerFunc is the protocol-free shape of a tool handler: context in, typed
// input in, typed output and a domain error out.
type handlerFunc[In, Out any] func(ctx context.Context, in In) (Out, error)

// adapter carries what every tool adapter needs.
type adapter struct {
	logger   *slog.Logger
	metrics  *observability.Metrics
	maxBytes int
}

// adapt lifts a handlerFunc into the SDK's ToolHandlerFor.
//
// This is the seam that keeps the tool package free of protocol concerns: the
// handler deals in Go values and domain errors, and everything MCP-specific -
// the request/result types, the error encoding and the response budget -
// happens here.
//
// The context passed through is the SDK's per-request context. It is cancelled
// when the client cancels the request or the session ends, so a handler that
// propagates it (as all of ours do, down to the backend HTTP call) stops doing
// work as soon as the answer stops being wanted.
func adapt[In, Out any](a adapter, tool string, fn handlerFunc[In, Out]) sdk.ToolHandlerFor[In, Out] {
	return func(ctx context.Context, _ *sdk.CallToolRequest, in In) (*sdk.CallToolResult, Out, error) {
		var zero Out

		out, err := fn(ctx, in)
		if err != nil {
			// Returning a non-nil error makes the SDK emit
			// CallToolResult{IsError: true} with this message as its content,
			// which is what lets the model see and react to the failure.
			return nil, zero, toolError(ctx, a.logger, tool, err)
		}
		if err := a.checkSize(tool, out); err != nil {
			return nil, zero, toolError(ctx, a.logger, tool, err)
		}
		// A nil result lets the SDK build it: StructuredContent from out, plus
		// a JSON TextContent block for clients that do not read structured
		// output.
		return nil, out, nil
	}
}

// checkSize refuses a result larger than the configured budget.
//
// A tool result is loaded into a model's context in full, so its size is a cost
// the caller pays and a limit the operator sets. Every list-shaped tool here
// already caps its row count, so exceeding the byte budget means the rows
// themselves are unexpectedly large - which is precisely the case where
// returning them anyway is worst. Refusing names the limit and points at the
// narrower call, so the model can correct itself rather than guess.
func (a adapter) checkSize(tool string, out any) error {
	if a.maxBytes <= 0 {
		return nil
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return domain.Internal(tool, err)
	}
	a.metrics.ObserveValue(observability.ResponseBytes, float64(len(encoded)), "feature", tool)
	if len(encoded) > a.maxBytes {
		return domain.Invalid("limit",
			"the result is %d bytes, over this server's %d byte response limit; narrow the filters or lower the limit and try again",
			len(encoded), a.maxBytes)
	}
	return nil
}
