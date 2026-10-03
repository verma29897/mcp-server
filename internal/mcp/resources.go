package mcp

import (
	"context"
	"log/slog"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/verma29897/mcp-server/internal/observability"
	"github.com/verma29897/mcp-server/internal/resources"
)

// registerResources binds the static resource and the resource templates.
//
// Static resources are matched by exact URI; templates are matched by RFC 6570
// pattern, and the SDK checks exact resources first. A template variable does
// not match across "/", so customer://{customer_id} and
// customer://{customer_id}/orders cannot both match the same URI.
func registerResources(srv *sdk.Server, p *resources.Provider, logger *slog.Logger, metrics *observability.Metrics) {
	srv.AddResource(p.Directory(), wrapResource(logger, metrics, p.ReadDirectory))

	handlers := map[string]sdk.ResourceHandler{
		resources.CustomerURITemplate: wrapResource(logger, metrics, p.ReadCustomer),
		resources.OrdersURITemplate:   wrapResource(logger, metrics, p.ReadOrders),
		resources.SummaryURITemplate:  wrapResource(logger, metrics, p.ReadSummary),
	}
	for _, tmpl := range p.Templates() {
		h, ok := handlers[tmpl.URITemplate]
		if !ok {
			// A descriptor with no handler would 404 at read time in a way
			// that is hard to trace, so fail loudly at startup instead.
			panic("mcp: no resource handler registered for template " + tmpl.URITemplate)
		}
		srv.AddResourceTemplate(tmpl, h)
	}
}

// wrapResource adds error encoding and the response-size metric around a
// resource handler.
//
// resources/read has no in-band error channel, so a failure has to become a
// JSON-RPC error; resourceError also maps a missing record onto the code the
// spec reserves for it.
func wrapResource(logger *slog.Logger, metrics *observability.Metrics, fn sdk.ResourceHandler) sdk.ResourceHandler {
	return func(ctx context.Context, req *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
		res, err := fn(ctx, req)
		if err != nil {
			return nil, resourceError(ctx, logger, req.Params.URI, err)
		}
		metrics.ObserveValue(observability.ResponseBytes, float64(resources.BodySize(res)),
			"feature", resourceLabel(req.Params.URI))
		return res, nil
	}
}
