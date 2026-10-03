// Package domain holds transport-agnostic business types and errors.
//
// Nothing in this package imports the MCP SDK. It is the shared vocabulary
// between the backend clients, the service layer and the MCP adapter layer,
// which keeps the MCP protocol concerns out of the business logic.
package domain

import (
	"errors"
	"fmt"
)

// Code is a coarse, transport-agnostic classification of a failure.
//
// The MCP adapter layer (internal/mcp/errors.go) maps these onto MCP tool
// errors or JSON-RPC protocol errors. Business code never needs to know which.
type Code string

const (
	CodeInvalidArgument Code = "INVALID_ARGUMENT"
	CodeNotFound        Code = "NOT_FOUND"
	CodeUnauthorized    Code = "UNAUTHORIZED"
	CodeForbidden       Code = "FORBIDDEN"
	CodeConflict        Code = "CONFLICT"
	CodeTimeout         Code = "TIMEOUT"
	CodeRateLimited     Code = "RATE_LIMITED"
	CodeBackendError    Code = "BACKEND_ERROR"
	CodeInternalError   Code = "INTERNAL_ERROR"
)

// Error is a classified application error.
//
// Message is the only part ever shown to an MCP client, and therefore to the
// model: it must stay free of credentials, connection strings, stack traces and
// upstream response bodies. The unexported cause carries the full detail for
// server-side logging and is reachable through errors.Unwrap / Detail.
type Error struct {
	Code Code
	// Message is a safe, human-readable explanation for the caller.
	Message string
	// Field names the offending input for CodeInvalidArgument. Optional.
	Field string
	// Retryable hints that the same call may succeed later.
	Retryable bool

	cause error
}

// Error implements error. It deliberately omits the cause so that accidental
// %v formatting of a domain error can never leak internal detail.
func (e *Error) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("%s: %s (field %q)", e.Code, e.Message, e.Field)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap exposes the internal cause to errors.Is / errors.As.
func (e *Error) Unwrap() error { return e.cause }

// Detail returns the full error including the internal cause. Use it for
// server-side logs only, never in a response to an MCP client.
func (e *Error) Detail() string {
	if e.cause == nil {
		return e.Error()
	}
	return fmt.Sprintf("%s: cause: %v", e.Error(), e.cause)
}

// WithCause attaches an internal cause and returns the receiver.
func (e *Error) WithCause(cause error) *Error {
	e.cause = cause
	return e
}

// AsError extracts a *Error from err, if there is one in its chain.
func AsError(err error) (*Error, bool) {
	var de *Error
	if errors.As(err, &de) {
		return de, true
	}
	return nil, false
}

// CodeOf reports the classification of err, defaulting to CodeInternalError.
func CodeOf(err error) Code {
	if de, ok := AsError(err); ok {
		return de.Code
	}
	if err == nil {
		return ""
	}
	return CodeInternalError
}

// Invalid reports a caller-supplied value that failed validation.
func Invalid(field, format string, args ...any) *Error {
	return &Error{Code: CodeInvalidArgument, Field: field, Message: fmt.Sprintf(format, args...)}
}

// NotFound reports a missing entity. kind is a noun such as "customer".
//
// It is also the deliberate answer to a cross-tenant reference: telling a
// caller that a record exists but belongs to someone else turns the tool into
// an existence oracle over the whole customer base.
func NotFound(kind, id string) *Error {
	return &Error{Code: CodeNotFound, Message: fmt.Sprintf("%s %q was not found", kind, id)}
}

// Unauthorized reports missing or invalid credentials.
func Unauthorized(format string, args ...any) *Error {
	return &Error{Code: CodeUnauthorized, Message: fmt.Sprintf(format, args...)}
}

// Forbidden reports valid credentials without sufficient permission.
func Forbidden(format string, args ...any) *Error {
	return &Error{Code: CodeForbidden, Message: fmt.Sprintf(format, args...)}
}

// Conflict reports that the caller's view of the record is stale, or that an
// idempotency key was reused with different arguments. Retrying the identical
// call will not help; the caller must re-read and decide.
func Conflict(field, format string, args ...any) *Error {
	return &Error{Code: CodeConflict, Field: field, Message: fmt.Sprintf(format, args...)}
}

// Timeout reports that an operation exceeded its deadline or was cancelled.
func Timeout(op string, cause error) *Error {
	return (&Error{
		Code:      CodeTimeout,
		Message:   fmt.Sprintf("the %s operation did not complete in time", op),
		Retryable: true,
	}).WithCause(cause)
}

// RateLimited reports that the caller exceeded a quota.
func RateLimited(format string, args ...any) *Error {
	return &Error{Code: CodeRateLimited, Message: fmt.Sprintf(format, args...), Retryable: true}
}

// Backend reports an upstream failure. The cause is kept internal.
func Backend(op string, cause error) *Error {
	return (&Error{
		Code:      CodeBackendError,
		Message:   fmt.Sprintf("the backend could not complete the %s operation", op),
		Retryable: true,
	}).WithCause(cause)
}

// Internal reports a defect in this server. The cause is kept internal.
func Internal(op string, cause error) *Error {
	return (&Error{
		Code:    CodeInternalError,
		Message: fmt.Sprintf("an internal error occurred while handling %s", op),
	}).WithCause(cause)
}
