// Package mcp is the adapter between this application and the official MCP Go
// SDK (github.com/modelcontextprotocol/go-sdk).
//
// It owns every SDK call: server construction, tool/resource/prompt
// registration, transport selection and error encoding. Everything beneath it
// (services, backend, domain) is protocol-agnostic, and everything above it
// (cmd/server) only asks it to start and stop.
package mcp

import (
	"context"
	"errors"
	"log/slog"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/verma29897/mcp-server/internal/domain"
	"github.com/verma29897/mcp-server/internal/observability"
)

// MCP distinguishes two kinds of failure, and getting the split right matters:
//
//   - A TOOL error is a result. The SDK packs it into CallToolResult with
//     IsError set, so the model sees it, can explain it and can self-correct.
//     Bad arguments, a missing customer and an upstream outage are all tool
//     errors: the call was well-formed, the outcome was a failure.
//
//   - A PROTOCOL error is a JSON-RPC error response. The model does not see it
//     as tool output. It is for failures of the request itself, and for
//     resources/prompts, which have no IsError channel.
//
// The SDK selects between them by type: returning a *jsonrpc.Error from a
// handler produces a protocol error, and any other error becomes a tool error.

// toolError converts a handler error into the error a tool handler should
// return, and logs the internal detail.
//
// The returned error text is the only thing the model sees, so it carries the
// classification and a safe message and never the cause.
func toolError(ctx context.Context, logger *slog.Logger, tool string, err error) error {
	if err == nil {
		return nil
	}

	de := classify(ctx, err, tool)
	logFailure(ctx, logger, "tool call failed", "tool", tool, de)

	// Returning a plain error makes the SDK produce CallToolResult{IsError:true}
	// with this text as its content, which is what the MCP spec asks for: the
	// model must be able to see and reason about a tool failure.
	return errors.New(de.Error())
}

// resourceError converts a handler error into the error a resource handler
// should return.
//
// resources/read has no IsError channel, so failures are protocol errors. A
// missing resource uses the SDK's ResourceNotFoundError so the client sees the
// code the MCP spec defines for it.
func resourceError(ctx context.Context, logger *slog.Logger, uri string, err error) error {
	if err == nil {
		return nil
	}

	de := classify(ctx, err, "resources/read")
	logFailure(ctx, logger, "resource read failed", "uri", uri, de)

	if de.Code == domain.CodeNotFound {
		return sdk.ResourceNotFoundError(uri)
	}
	return protocolError(de)
}

// promptError converts a handler error into the error a prompt handler should
// return. prompts/get likewise has no IsError channel.
func promptError(ctx context.Context, logger *slog.Logger, name string, err error) error {
	if err == nil {
		return nil
	}

	de := classify(ctx, err, "prompts/get")
	logFailure(ctx, logger, "prompt get failed", "prompt", name, de)

	return protocolError(de)
}

// protocolError builds the JSON-RPC error response for a classified failure.
//
// The SDK recognises *jsonrpc.Error by type and puts its code and message
// straight onto the wire; any other error type would be flattened to a generic
// internal error, losing the classification.
func protocolError(de *domain.Error) error {
	return &jsonrpc.Error{Code: rpcCode(de.Code), Message: de.Error()}
}

// classify normalizes any error into a *domain.Error.
//
// An unclassified error is reported as INTERNAL_ERROR with a generic message:
// an unexpected error may embed a connection string, a query or a stack trace,
// and none of that may reach a client.
func classify(ctx context.Context, err error, op string) *domain.Error {
	if de, ok := domain.AsError(err); ok {
		return de
	}
	// A cancelled or expired request context explains the failure better than
	// "internal error" does, and tells the model whether retrying is sensible.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return domain.Timeout(op, err)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return domain.Timeout(op, errors.Join(ctxErr, err))
	}
	return domain.Internal(op, err)
}

// rpcCode maps a domain classification onto a JSON-RPC error code.
//
// JSON-RPC has a small standard set, so several classifications share a code;
// the precise classification is preserved in the message text.
func rpcCode(code domain.Code) int64 {
	switch code {
	case domain.CodeInvalidArgument,
		domain.CodeNotFound,
		domain.CodeUnauthorized,
		domain.CodeForbidden,
		domain.CodeConflict,
		domain.CodeRateLimited,
		domain.CodeTimeout:
		return jsonrpc.CodeInvalidParams
	default:
		return jsonrpc.CodeInternalError
	}
}

// logFailure records the full internal detail server-side.
//
// This is the counterpart to redacting the client-facing message: an operator
// still needs the cause, so it is logged here and nowhere else.
func logFailure(ctx context.Context, logger *slog.Logger, msg, subjectKey, subject string, de *domain.Error) {
	level := slog.LevelWarn
	if de.Code == domain.CodeInternalError || de.Code == domain.CodeBackendError {
		level = slog.LevelError
	}
	logger.Log(ctx, level, msg,
		subjectKey, subject,
		"code", string(de.Code),
		"retryable", de.Retryable,
		"detail", de.Detail(),
		// The correlation id is what ties this line - the only place the
		// internal cause exists - to the redacted message the client received.
		"request_id", observability.RequestIDFrom(ctx),
	)
}
