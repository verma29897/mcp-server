// Package fuzz_test fuzzes the parsers that sit on the trust boundary.
//
// The property under test is uniform: for any input at all, the server returns
// a classified refusal and never panics, hangs, or lets a value through that
// the validator was supposed to stop. A panic in a handler is contained by the
// recovery middleware, but a containment measure is not a reason to leave the
// panic there - a recovered panic still costs the request and pollutes the log.
package fuzz_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/verma29897/mcp-server/internal/authz"
	"github.com/verma29897/mcp-server/internal/domain"
	"github.com/verma29897/mcp-server/internal/idempotency"
	"github.com/verma29897/mcp-server/internal/paging"
	"github.com/verma29897/mcp-server/internal/resources"
	"github.com/verma29897/mcp-server/internal/services"
	"github.com/verma29897/mcp-server/internal/tools/customer"
	"github.com/verma29897/mcp-server/tests/testutil"
)

func FuzzCustomerID(f *testing.F) {
	for _, seed := range []string{
		"1001", "", " ", "../etc/passwd", "1' OR '1'='1", strings.Repeat("a", 65),
		"\x00", "￿", "1001\n", "%2e%2e", "ＩＤ", "1001/../1002",
	} {
		f.Add(seed)
	}

	svc, be := testutil.NewService()
	h := customer.NewHandlers(svc)
	ctx := testutil.Context()

	f.Fuzz(func(t *testing.T, id string) {
		out, err := h.GetCustomer(ctx, customer.GetCustomerInput{CustomerID: id})
		if err == nil {
			// A success is only legitimate for an id that survives validation
			// and names a real record.
			if out.Customer.CustomerID == "" {
				t.Fatalf("GetCustomer(%q) succeeded with an empty record", id)
			}
			return
		}
		de, ok := domain.AsError(err)
		if !ok {
			t.Fatalf("GetCustomer(%q) returned an unclassified error %v (%T)", id, err, err)
		}
		switch de.Code {
		case domain.CodeInvalidArgument, domain.CodeNotFound:
		default:
			t.Fatalf("GetCustomer(%q) = %s, want INVALID_ARGUMENT or NOT_FOUND", id, de.Code)
		}
		// The refusal must never echo the input back in a way that could carry
		// a control character into a log or a client.
		if strings.ContainsAny(de.Message, "\x00\r\n") {
			t.Fatalf("error message for %q contains control characters: %q", id, de.Message)
		}
		_ = be
	})
}

// readRequest builds the request shape a resource handler receives.
func readRequest(uri string) *sdk.ReadResourceRequest {
	return &sdk.ReadResourceRequest{Params: &sdk.ReadResourceParams{URI: uri}}
}

func FuzzResourceURI(f *testing.F) {
	for _, seed := range []string{
		"customer://1001",
		"customer://1001/orders",
		"customer://1001/summary",
		"customer://directory",
		"customer://",
		"customer://1001/",
		"customer:////",
		"customer://1001/orders/extra",
		"file:///etc/passwd",
		"customer://\x00",
		strings.Repeat("customer://a/", 100),
	} {
		f.Add(seed)
	}

	svc, _ := testutil.NewService()
	p := resources.NewProvider(svc, resources.Options{})
	ctx := testutil.Context()

	f.Fuzz(func(t *testing.T, uri string) {
		// Each handler parses the part of the URI it needs, so each is fuzzed.
		for _, read := range []func() error{
			func() error { _, err := p.ReadCustomer(ctx, readRequest(uri)); return err },
			func() error { _, err := p.ReadOrders(ctx, readRequest(uri)); return err },
			func() error { _, err := p.ReadSummary(ctx, readRequest(uri)); return err },
		} {
			err := read()
			if err == nil {
				continue
			}
			if _, ok := domain.AsError(err); !ok {
				t.Fatalf("read(%q) returned an unclassified error %v (%T)", uri, err, err)
			}
		}
	})
}

func FuzzSearchInput(f *testing.F) {
	f.Add("acme", "active", "pro", 20)
	f.Add("", "", "", 0)
	f.Add(strings.Repeat("x", 10000), "ARCHIVED", "gold", -1)
	f.Add("\x00\x01", "active", "", 1<<30)

	svc, _ := testutil.NewService()
	h := customer.NewHandlers(svc)
	ctx := testutil.Context()

	f.Fuzz(func(t *testing.T, query, status, tier string, limit int) {
		out, err := h.SearchCustomers(ctx, customer.SearchCustomersInput{
			Query: query, Status: status, Tier: tier, Limit: limit,
		})
		if err != nil {
			if _, ok := domain.AsError(err); !ok {
				t.Fatalf("SearchCustomers returned an unclassified error %v (%T)", err, err)
			}
			return
		}
		// A successful search must respect the cap however the limit was
		// expressed - that cap is what stops a bulk export in one call.
		if len(out.Customers) > services.MaxSearchLimit {
			t.Fatalf("returned %d customers, over the %d cap", len(out.Customers), services.MaxSearchLimit)
		}
		if out.Count != len(out.Customers) {
			t.Fatalf("count = %d but %d customers were returned", out.Count, len(out.Customers))
		}
	})
}

func FuzzCursor(f *testing.F) {
	codec := paging.NewCodec("fuzz-secret")
	binding := paging.Binding{Tenant: "acme", Principal: "p", Operation: "search_customers", Filters: "f"}

	f.Add(codec.Encode(binding, "1001"))
	for _, seed := range []string{"", ".", "a.b", "....", strings.Repeat("A", 2000), "\x00.\x00"} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, cursor string) {
		after, err := codec.Decode(binding, cursor)
		if err != nil {
			return
		}
		// The only cursors that verify are ones this codec issued, so a decoded
		// resume key must be something a decoder could have produced - never
		// arbitrary caller-controlled bytes reaching the backend.
		if !utf8.ValidString(after) {
			t.Fatalf("cursor %.40q decoded to invalid UTF-8 %q", cursor, after)
		}
		if strings.ContainsAny(after, "\x00\r\n") {
			t.Fatalf("cursor %.40q decoded to a control-bearing key %q", cursor, after)
		}
	})
}

func FuzzNotificationInput(f *testing.F) {
	f.Add("1001", "email", "Subject", "Body", "key-abcdef12")
	f.Add("1001", "sms", "", "hi", "")
	f.Add("1001", "email", "S\r\nBcc: evil@example", "b", "")
	f.Add("", "carrier-pigeon", strings.Repeat("s", 5000), strings.Repeat("b", 100000), strings.Repeat("k", 500))

	svc, be := testutil.NewService()
	h := customer.NewHandlers(svc)
	ctx := testutil.Context()

	f.Fuzz(func(t *testing.T, id, channel, subject, body, key string) {
		before := be.Calls("SendNotification")

		_, err := h.SendCustomerNotification(ctx, customer.SendCustomerNotificationInput{
			CustomerID: id, Channel: channel, Subject: subject, Body: body, IdempotencyKey: key,
		})
		if err != nil {
			if _, ok := domain.AsError(err); !ok {
				t.Fatalf("SendCustomerNotification returned an unclassified error %v (%T)", err, err)
			}
			// A refused message must not have been handed to the provider:
			// this tool contacts a real person and there is no undo.
			if after := be.Calls("SendNotification"); after != before {
				t.Fatalf("a refused notification still reached the provider (id=%q channel=%q)", id, channel)
			}
			return
		}
		// A message that was accepted must have passed every field rule.
		if !domain.Channel(channel).Valid() {
			t.Fatalf("channel %q was accepted", channel)
		}
		if strings.ContainsAny(strings.TrimSpace(subject), "\r\n") {
			t.Fatalf("a subject containing CR/LF was accepted: %q", subject)
		}
		if len(strings.TrimSpace(body)) > services.MaxNotificationBody {
			t.Fatalf("an oversized body was accepted (%d bytes)", len(body))
		}
		if key != "" && idempotency.ValidateKey(key) != nil {
			t.Fatalf("an invalid idempotency key was accepted: %q", key)
		}
	})
}

func FuzzScopeParsing(f *testing.F) {
	f.Add("customer:read customer:search")
	f.Add("")
	f.Add(",,, ,,,")
	f.Add(strings.Repeat("customer:read ", 1000))
	f.Add("customer:*")
	f.Add("*")

	f.Fuzz(func(t *testing.T, raw string) {
		scopes := authz.ParseScopes(raw)
		p := &authz.Principal{Subject: "s", TenantID: "t", Scopes: scopes}

		// The invariant that matters: a scope string can only grant what it
		// literally contains, or an explicit wildcard. No parse of arbitrary
		// text may hand out a permission by accident.
		for _, want := range authz.AllScopes {
			if !p.Has(want) {
				continue
			}
			granted := false
			for _, s := range scopes {
				if s == want || s == "*" || (strings.HasSuffix(s, ":*") && strings.HasPrefix(want, strings.TrimSuffix(s, "*"))) {
					granted = true
					break
				}
			}
			if !granted {
				t.Fatalf("input %q granted %q without containing it (parsed: %v)", raw, want, scopes)
			}
		}
	})
}
