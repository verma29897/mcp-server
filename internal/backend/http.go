package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/verma29897/mcp-server/internal/domain"
	"github.com/verma29897/mcp-server/internal/observability"
)

// HTTP is a Backend backed by a remote REST API.
//
// It is the only place in the project that knows the upstream wire format.
// Upstream status codes are translated into domain.Code values, and response
// bodies are never propagated to the caller: they can contain internal detail
// that must not reach a model.
type HTTP struct {
	baseURL string
	token   string
	client  *http.Client

	retry   RetryConfig
	circuit *circuit
	metrics *observability.Metrics

	// maxResponseBytes bounds what is read from one upstream response.
	maxResponseBytes int64
}

var _ Backend = (*HTTP)(nil)

// HTTPOptions configures the REST backend.
type HTTPOptions struct {
	BaseURL string
	// Token is a secret. It is sent upstream and never anywhere else.
	Token string
	// Timeout bounds one attempt, on top of any caller deadline.
	Timeout time.Duration
	// DialTimeout bounds connection establishment.
	DialTimeout time.Duration
	// ResponseHeaderTimeout bounds the wait for the first response byte, which
	// is what catches a backend that accepts a connection and then stalls.
	ResponseHeaderTimeout time.Duration
	// MaxResponseBytes bounds one upstream response body.
	MaxResponseBytes int64
	Retry            RetryConfig
	Circuit          CircuitConfig
	Metrics          *observability.Metrics
}

// NewHTTP returns an HTTP backend. BaseURL must be an absolute http(s) URL.
func NewHTTP(opts HTTPOptions) (*HTTP, error) {
	u, err := url.Parse(opts.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse backend base URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("backend base URL must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("backend base URL must include a host")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = 5 * time.Second
	}
	if opts.ResponseHeaderTimeout <= 0 {
		opts.ResponseHeaderTimeout = opts.Timeout
	}
	if opts.MaxResponseBytes <= 0 {
		opts.MaxResponseBytes = 8 << 20
	}
	if opts.Retry.MaxAttempts <= 0 {
		opts.Retry = DefaultRetry()
	}

	return &HTTP{
		baseURL:          strings.TrimRight(opts.BaseURL, "/"),
		token:            opts.Token,
		retry:            opts.Retry,
		circuit:          newCircuit(opts.Circuit),
		metrics:          opts.Metrics,
		maxResponseBytes: opts.MaxResponseBytes,
		client: &http.Client{
			Timeout: opts.Timeout,
			Transport: &http.Transport{
				DialContext:           (&net.Dialer{Timeout: opts.DialTimeout, KeepAlive: 30 * time.Second}).DialContext,
				ResponseHeaderTimeout: opts.ResponseHeaderTimeout,
				MaxIdleConns:          64,
				MaxIdleConnsPerHost:   16,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   5 * time.Second,
				ExpectContinueTimeout: time.Second,
				ForceAttemptHTTP2:     true,
			},
		},
	}, nil
}

// CircuitState reports the breaker position, for a metric gauge and /readyz.
func (h *HTTP) CircuitState() CircuitState { return h.circuit.State() }

// request describes one upstream call.
type request struct {
	method string
	path   string
	// tenant scopes the call. It is sent as a header rather than being spliced
	// into the path, so an upstream that ignores it fails loudly at its own
	// authorization layer rather than silently serving the wrong tenant.
	tenant string
	query  url.Values
	body   any
	out    any
	// op names the logical operation for errors and metrics.
	op string
	// kind and id describe the entity, so a 404 becomes a precise NOT_FOUND.
	kind, id string
	// idempotent marks the call safe to retry.
	idempotent bool
}

// TenantHeader carries the tenant to the upstream API.
const TenantHeader = "X-Tenant-Id"

// IdempotencyHeader carries a client idempotency key to the upstream API.
const IdempotencyHeader = "Idempotency-Key"

// GetCustomer implements Backend.
func (h *HTTP) GetCustomer(ctx context.Context, tenantID, id string) (domain.Customer, error) {
	var out domain.Customer
	err := h.do(ctx, request{
		method: http.MethodGet, path: "/customers/" + url.PathEscape(id),
		tenant: tenantID, out: &out, op: "get_customer", kind: "customer", id: id,
		idempotent: true,
	})
	return out, err
}

// SearchCustomers implements Backend.
func (h *HTTP) SearchCustomers(ctx context.Context, q domain.SearchQuery) (domain.CustomerList, error) {
	vals := url.Values{}
	if q.Text != "" {
		vals.Set("q", q.Text)
	}
	if q.Status != "" {
		vals.Set("status", string(q.Status))
	}
	if q.Tier != "" {
		vals.Set("tier", string(q.Tier))
	}
	if q.Limit > 0 {
		vals.Set("limit", strconv.Itoa(q.Limit))
	}
	if q.After != "" {
		vals.Set("after", q.After)
	}

	var out struct {
		Items     []domain.Customer `json:"items"`
		NextAfter string            `json:"next_after"`
	}
	if err := h.do(ctx, request{
		method: http.MethodGet, path: "/customers", query: vals,
		tenant: q.TenantID, out: &out, op: "search_customers", kind: "customer",
		idempotent: true,
	}); err != nil {
		return domain.CustomerList{}, err
	}
	return domain.CustomerList{Items: out.Items, NextAfter: out.NextAfter}, nil
}

// ListOrders implements Backend.
func (h *HTTP) ListOrders(ctx context.Context, tenantID, customerID string, p domain.Page) (domain.OrderList, error) {
	vals := url.Values{}
	if p.Limit > 0 {
		vals.Set("limit", strconv.Itoa(p.Limit))
	}
	if p.After != "" {
		vals.Set("after", p.After)
	}

	var out struct {
		Items     []domain.Order `json:"items"`
		NextAfter string         `json:"next_after"`
	}
	if err := h.do(ctx, request{
		method: http.MethodGet, path: "/customers/" + url.PathEscape(customerID) + "/orders", query: vals,
		tenant: tenantID, out: &out, op: "list_customer_orders", kind: "customer", id: customerID,
		idempotent: true,
	}); err != nil {
		return domain.OrderList{}, err
	}
	return domain.OrderList{Items: out.Items, NextAfter: out.NextAfter}, nil
}

// UpdateCustomer implements Backend.
//
// The patch replaces the named fields outright, so repeating it produces the
// same final state and it is safe to retry. When it carries an optimistic-lock
// precondition it is not retried: the first attempt may have succeeded and
// bumped the version, and the retry would then report a spurious CONFLICT.
func (h *HTTP) UpdateCustomer(ctx context.Context, tenantID, id string, patch domain.CustomerPatch) (domain.Customer, error) {
	var out domain.Customer
	err := h.do(ctx, request{
		method: http.MethodPatch, path: "/customers/" + url.PathEscape(id),
		tenant: tenantID, body: patch, out: &out,
		op: "update_customer", kind: "customer", id: id,
		idempotent: patch.ExpectedVersion == nil,
	})
	return out, err
}

// DeleteCustomer implements Backend.
func (h *HTTP) DeleteCustomer(ctx context.Context, tenantID, id string, expectedVersion *int) error {
	vals := url.Values{}
	if expectedVersion != nil {
		vals.Set("expected_version", strconv.Itoa(*expectedVersion))
	}
	// Not retried: a second DELETE after a timed-out first one would report
	// NOT_FOUND for a delete that actually succeeded, which reads to the model
	// as "the customer never existed".
	return h.do(ctx, request{
		method: http.MethodDelete, path: "/customers/" + url.PathEscape(id), query: vals,
		tenant: tenantID, op: "delete_customer", kind: "customer", id: id,
	})
}

// SendNotification implements Backend.
func (h *HTTP) SendNotification(ctx context.Context, n domain.Notification) (domain.Receipt, error) {
	var out domain.Receipt
	err := h.do(ctx, request{
		method: http.MethodPost, path: "/customers/" + url.PathEscape(n.CustomerID) + "/notifications",
		tenant: n.TenantID, body: n, out: &out,
		op: "send_customer_notification", kind: "customer", id: n.CustomerID,
		// Never retried here. Deduplication is the idempotency store's job in
		// the service layer, where the client's key is known.
	})
	return out, err
}

// Ping implements Backend.
func (h *HTTP) Ping(ctx context.Context) error {
	return h.do(ctx, request{
		method: http.MethodGet, path: "/healthz", op: "ping", kind: "backend",
		idempotent: true,
	})
}

// Close implements Backend.
func (h *HTTP) Close() error {
	h.client.CloseIdleConnections()
	return nil
}

// do performs one upstream call with retries and the circuit breaker.
func (h *HTTP) do(ctx context.Context, req request) error {
	if !h.circuit.allow() {
		h.metrics.Inc(observability.BackendRequests, "operation", req.op, "outcome", "circuit_open")
		return domain.Backend(req.op, ErrCircuitOpen)
	}

	attempts := 1
	if req.idempotent && h.retry.MaxAttempts > 1 {
		attempts = h.retry.MaxAttempts
	}

	start := time.Now()
	var err error
	for attempt := 1; attempt <= attempts; attempt++ {
		if attempt > 1 {
			h.metrics.Inc(observability.BackendRetries, "operation", req.op)
			if waitErr := sleep(ctx, h.retry.delay(attempt-1, jitterSource)); waitErr != nil {
				err = domain.Timeout(req.op, waitErr)
				break
			}
		}
		err = h.attempt(ctx, req)
		if err == nil || !retryable(err, req.idempotent) {
			break
		}
	}

	h.circuit.record(err)
	h.metrics.Observe(observability.BackendDuration, time.Since(start), "operation", req.op)
	outcome := observability.OutcomeSuccess
	if err != nil {
		outcome = string(domain.CodeOf(err))
	}
	h.metrics.Inc(observability.BackendRequests, "operation", req.op, "outcome", outcome)
	return err
}

// attempt performs exactly one upstream call.
func (h *HTTP) attempt(ctx context.Context, r request) error {
	var reader io.Reader
	if r.body != nil {
		encoded, err := json.Marshal(r.body)
		if err != nil {
			return domain.Internal(r.op, fmt.Errorf("marshal request: %w", err))
		}
		reader = bytes.NewReader(encoded)
	}

	path := r.path
	if encoded := r.query.Encode(); encoded != "" {
		path += "?" + encoded
	}

	req, err := http.NewRequestWithContext(ctx, r.method, h.baseURL+path, reader)
	if err != nil {
		return domain.Internal(r.op, fmt.Errorf("build request: %w", err))
	}
	req.Header.Set("Accept", "application/json")
	if r.body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if h.token != "" {
		req.Header.Set("Authorization", "Bearer "+h.token)
	}
	if r.tenant != "" {
		req.Header.Set(TenantHeader, r.tenant)
	}
	if n, ok := r.body.(domain.Notification); ok && n.IdempotencyKey != "" {
		req.Header.Set(IdempotencyHeader, n.IdempotencyKey)
	}
	// Correlation headers, so the backend's logs join this server's trace.
	observability.FromContext(ctx).InjectHTTP(req)

	resp, err := h.client.Do(req)
	if err != nil {
		// Distinguish "the caller gave up / ran out of time" from a genuine
		// transport failure, so the model gets an accurate retry signal.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
			return domain.Timeout(r.op, err)
		}
		return domain.Backend(r.op, err)
	}
	defer resp.Body.Close()

	// Read a bounded prefix: enough for diagnostics, never unbounded.
	payload, readErr := io.ReadAll(io.LimitReader(resp.Body, h.maxResponseBytes))
	if readErr != nil {
		if errors.Is(readErr, context.Canceled) || errors.Is(readErr, context.DeadlineExceeded) {
			return domain.Timeout(r.op, readErr)
		}
		return domain.Backend(r.op, fmt.Errorf("read response: %w", readErr))
	}
	// Drain a bounded remainder so the connection can be reused; an endless
	// body must not be able to pin this goroutine here.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return classifyStatus(resp, payload, r.op, r.kind, r.id)
	}
	if r.out == nil || len(bytes.TrimSpace(payload)) == 0 {
		return nil
	}
	if err := json.Unmarshal(payload, r.out); err != nil {
		return domain.Backend(r.op, fmt.Errorf("decode response: %w", err))
	}
	return nil
}

// classifyStatus maps an upstream HTTP status onto a domain error. The upstream
// body is attached as an internal cause only, so it can be logged but never
// returned to an MCP client.
func classifyStatus(resp *http.Response, payload []byte, op, kind, id string) error {
	cause := fmt.Errorf("upstream %s returned %d: %s", op, resp.StatusCode, truncate(string(payload), 512))

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return domain.NotFound(kind, id).WithCause(cause)
	case resp.StatusCode == http.StatusUnauthorized:
		return domain.Unauthorized("the server is not authorized to reach the customer backend").WithCause(cause)
	case resp.StatusCode == http.StatusForbidden:
		return domain.Forbidden("the customer backend refused this operation").WithCause(cause)
	case resp.StatusCode == http.StatusConflict || resp.StatusCode == http.StatusPreconditionFailed:
		return domain.Conflict("", "the record changed in the backend since it was read; re-read it and retry").WithCause(cause)
	case resp.StatusCode == http.StatusTooManyRequests:
		msg := "the customer backend is rate limiting requests"
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			msg += "; retry after " + ra + "s"
		}
		return domain.RateLimited("%s", msg).WithCause(cause)
	case resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusGatewayTimeout:
		return domain.Timeout(op, cause)
	case resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnprocessableEntity:
		return domain.Invalid("", "the customer backend rejected the request as invalid").WithCause(cause)
	default:
		return domain.Backend(op, cause)
	}
}

func isTimeout(err error) bool {
	var te interface{ Timeout() bool }
	return errors.As(err, &te) && te.Timeout()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}
