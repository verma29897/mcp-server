// Package resources_test covers the resource layer: URI parsing, payload
// shape and error classification, without a protocol or a transport.
package resources_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/verma29897/mcp-server/internal/domain"
	"github.com/verma29897/mcp-server/internal/resources"
	"github.com/verma29897/mcp-server/tests/testutil"
)

func newProvider() (*resources.Provider, *testutil.FakeBackend) {
	svc, be := testutil.NewService()
	return resources.NewProvider(svc, resources.Options{}), be
}

// read invokes a resource handler with a URI, the way the SDK would.
func read(t *testing.T, fn func(context.Context, *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error), uri string) (*sdk.ReadResourceResult, error) {
	t.Helper()
	return fn(testutil.Context(), &sdk.ReadResourceRequest{
		Params: &sdk.ReadResourceParams{URI: uri},
	})
}

// decode asserts the result carries exactly one JSON content block for uri and
// unmarshals it into v.
func decode(t *testing.T, res *sdk.ReadResourceResult, uri string, v any) {
	t.Helper()
	if res == nil {
		t.Fatal("nil result")
	}
	if len(res.Contents) != 1 {
		t.Fatalf("got %d content blocks, want 1", len(res.Contents))
	}
	c := res.Contents[0]
	if c.URI != uri {
		t.Errorf("content URI = %q, want %q", c.URI, uri)
	}
	if c.MIMEType != resources.MIMEJSON {
		t.Errorf("mime type = %q, want %q", c.MIMEType, resources.MIMEJSON)
	}
	if err := json.Unmarshal([]byte(c.Text), v); err != nil {
		t.Fatalf("resource body is not valid JSON: %v\nbody: %s", err, c.Text)
	}
}

func TestDirectoryDescriptor(t *testing.T) {
	p, _ := newProvider()

	d := p.Directory()
	if d.URI != resources.DirectoryURI {
		t.Errorf("URI = %q, want %q", d.URI, resources.DirectoryURI)
	}
	if d.MIMEType != resources.MIMEJSON {
		t.Errorf("mime type = %q, want %q", d.MIMEType, resources.MIMEJSON)
	}
	if d.Description == "" {
		t.Error("a resource without a description gives the model nothing to decide on")
	}
}

func TestTemplateDescriptors(t *testing.T) {
	p, _ := newProvider()

	want := map[string]bool{
		resources.CustomerURITemplate: false,
		resources.OrdersURITemplate:   false,
		resources.SummaryURITemplate:  false,
	}
	for _, tmpl := range p.Templates() {
		if _, ok := want[tmpl.URITemplate]; !ok {
			t.Errorf("unexpected template %q", tmpl.URITemplate)
			continue
		}
		want[tmpl.URITemplate] = true
		if tmpl.Name == "" || tmpl.Description == "" || tmpl.MIMEType != resources.MIMEJSON {
			t.Errorf("template %q is missing name, description or mime type", tmpl.URITemplate)
		}
	}
	for uri, seen := range want {
		if !seen {
			t.Errorf("template %q was not registered", uri)
		}
	}
}

func TestReadDirectory(t *testing.T) {
	p, _ := newProvider()

	res, err := read(t, p.ReadDirectory, resources.DirectoryURI)
	if err != nil {
		t.Fatalf("ReadDirectory: %v", err)
	}

	var body struct {
		Customers []struct {
			CustomerID string `json:"customer_id"`
			Status     string `json:"status"`
		} `json:"customers"`
		Count int `json:"count"`
	}
	decode(t, res, resources.DirectoryURI, &body)

	if body.Count != len(body.Customers) {
		t.Errorf("count = %d but %d customers were listed", body.Count, len(body.Customers))
	}
	if body.Count == 0 {
		t.Fatal("directory is empty")
	}
	for _, c := range body.Customers {
		if c.Status != string(domain.StatusActive) {
			t.Errorf("customer %s has status %q; the directory lists active customers only", c.CustomerID, c.Status)
		}
	}
}

func TestReadCustomer(t *testing.T) {
	p, _ := newProvider()
	const uri = "customer://1001"

	res, err := read(t, p.ReadCustomer, uri)
	if err != nil {
		t.Fatalf("ReadCustomer: %v", err)
	}

	var c domain.Customer
	decode(t, res, uri, &c)
	if c.ID != "1001" || c.Name != "Acme Industries" {
		t.Errorf("got %+v, want customer 1001 Acme Industries", c)
	}
}

func TestReadOrders(t *testing.T) {
	p, _ := newProvider()
	const uri = "customer://1001/orders"

	res, err := read(t, p.ReadOrders, uri)
	if err != nil {
		t.Fatalf("ReadOrders: %v", err)
	}

	var body struct {
		CustomerID string         `json:"customer_id"`
		Orders     []domain.Order `json:"orders"`
		Count      int            `json:"count"`
	}
	decode(t, res, uri, &body)

	if body.CustomerID != "1001" {
		t.Errorf("customer_id = %q, want %q", body.CustomerID, "1001")
	}
	if body.Count != 3 {
		t.Errorf("count = %d, want 3", body.Count)
	}
}

func TestReadSummary(t *testing.T) {
	p, _ := newProvider()
	const uri = "customer://1001/summary"

	res, err := read(t, p.ReadSummary, uri)
	if err != nil {
		t.Fatalf("ReadSummary: %v", err)
	}

	var body struct {
		Customer      domain.Customer `json:"customer"`
		OrderCount    int             `json:"order_count"`
		LifetimeSpend float64         `json:"lifetime_spend"`
		Currency      string          `json:"currency"`
		OpenOrders    int             `json:"open_orders"`
	}
	decode(t, res, uri, &body)

	if body.Customer.ID != "1001" {
		t.Fatalf("customer id = %q, want %q", body.Customer.ID, "1001")
	}
	if body.OrderCount != 3 {
		t.Errorf("order_count = %d, want 3", body.OrderCount)
	}
	// 12400.50 delivered + 890.00 shipped + 4500.25 pending, none cancelled.
	if want := 17790.75; body.LifetimeSpend != want {
		t.Errorf("lifetime_spend = %v, want %v", body.LifetimeSpend, want)
	}
	if body.Currency != "USD" {
		t.Errorf("currency = %q, want USD", body.Currency)
	}
	// One shipped plus one pending.
	if body.OpenOrders != 2 {
		t.Errorf("open_orders = %d, want 2", body.OpenOrders)
	}
}

func TestSummaryExcludesCancelledOrders(t *testing.T) {
	p, _ := newProvider()
	const uri = "customer://1003/summary"

	res, err := read(t, p.ReadSummary, uri)
	if err != nil {
		t.Fatalf("ReadSummary: %v", err)
	}

	var body struct {
		LifetimeSpend float64 `json:"lifetime_spend"`
		OrderCount    int     `json:"order_count"`
	}
	decode(t, res, uri, &body)

	if body.OrderCount != 1 {
		t.Fatalf("order_count = %d, want 1", body.OrderCount)
	}
	if body.LifetimeSpend != 0 {
		t.Errorf("lifetime_spend = %v, want 0: the only order is cancelled", body.LifetimeSpend)
	}
}

func TestReadUnknownCustomer(t *testing.T) {
	p, _ := newProvider()

	_, err := read(t, p.ReadCustomer, "customer://9999")
	de := requireDomainError(t, err)
	if de.Code != domain.CodeNotFound {
		t.Fatalf("code = %s, want %s", de.Code, domain.CodeNotFound)
	}
}

func TestReadMalformedURI(t *testing.T) {
	p, _ := newProvider()

	tests := []struct {
		name string
		fn   func(context.Context, *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error)
		uri  string
	}{
		{"wrong scheme", p.ReadCustomer, "https://example.com/1001"},
		{"no id", p.ReadCustomer, "customer://"},
		{"nested path", p.ReadCustomer, "customer://1001/extra"},
		{"orders without suffix", p.ReadOrders, "customer://1001"},
		{"summary without suffix", p.ReadSummary, "customer://1001"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := read(t, tc.fn, tc.uri)
			de := requireDomainError(t, err)
			if de.Code != domain.CodeInvalidArgument {
				t.Fatalf("code = %s, want %s", de.Code, domain.CodeInvalidArgument)
			}
		})
	}
}

func TestReadBackendErrorIsRedacted(t *testing.T) {
	p, be := newProvider()
	be.GetCustomerFn = func(context.Context, string, string) (domain.Customer, error) {
		return domain.Customer{}, domain.Backend("get_customer",
			errShim("Bearer sk-live-abcdef refused by https://internal.api/customers"))
	}

	_, err := read(t, p.ReadCustomer, "customer://1001")
	de := requireDomainError(t, err)
	if strings.Contains(de.Error(), "sk-live") || strings.Contains(de.Error(), "internal.api") {
		t.Errorf("resource error leaks internal detail: %q", de.Error())
	}
}

func requireDomainError(t *testing.T, err error) *domain.Error {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	de, ok := domain.AsError(err)
	if !ok {
		t.Fatalf("error %v (%T) is not a *domain.Error", err, err)
	}
	return de
}

type errShim string

func (e errShim) Error() string { return string(e) }
