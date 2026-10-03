package paging

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func binding() Binding {
	return Binding{Tenant: "acme", Principal: "user-1", Operation: "search_customers", Filters: "text\x1factive\x1f"}
}

func TestRoundTrip(t *testing.T) {
	c := NewCodec("a-secret")

	cursor := c.Encode(binding(), "1003")
	if cursor == "" {
		t.Fatal("Encode produced nothing for a non-empty resume key")
	}

	got, err := c.Decode(binding(), cursor)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got != "1003" {
		t.Errorf("resume key = %q, want 1003", got)
	}
}

func TestExhaustedListingHasNoCursor(t *testing.T) {
	// A cursor that leads nowhere invites a client to loop on it.
	if got := NewCodec("s").Encode(binding(), ""); got != "" {
		t.Errorf("Encode with no resume key = %q, want empty", got)
	}
	// And an empty cursor decodes to "start at the top", not to an error.
	after, err := NewCodec("s").Decode(binding(), "")
	if err != nil || after != "" {
		t.Errorf("Decode(\"\") = %q, %v; want an empty resume key and no error", after, err)
	}
}

func TestTamperedCursorIsRefused(t *testing.T) {
	c := NewCodec("a-secret")
	cursor := c.Encode(binding(), "1003")
	body, sig, _ := strings.Cut(cursor, ".")

	// Re-encode the payload with a different resume key, keeping the original
	// signature. This is the attack the HMAC exists to stop: paging from a
	// position the server never issued.
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var p payload
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	p.After = "9999"
	edited, _ := json.Marshal(p)
	forged := base64.RawURLEncoding.EncodeToString(edited) + "." + sig

	if _, err := c.Decode(binding(), forged); !errors.Is(err, ErrInvalidCursor) {
		t.Fatal("an edited cursor was accepted")
	}
}

func TestCursorIsBoundToItsQuery(t *testing.T) {
	c := NewCodec("a-secret")
	cursor := c.Encode(binding(), "1003")

	// Each of these is a different query, and the cursor must not carry across
	// any of them. The tenant and principal cases are the security-critical
	// ones: a cursor is a position in a result set that was computed under one
	// caller's authorization.
	tests := []struct {
		name string
		b    Binding
	}{
		{"different tenant", Binding{Tenant: "northwind", Principal: "user-1", Operation: "search_customers", Filters: "text\x1factive\x1f"}},
		{"different principal", Binding{Tenant: "acme", Principal: "user-2", Operation: "search_customers", Filters: "text\x1factive\x1f"}},
		{"different operation", Binding{Tenant: "acme", Principal: "user-1", Operation: "list_customer_orders", Filters: "text\x1factive\x1f"}},
		{"different filters", Binding{Tenant: "acme", Principal: "user-1", Operation: "search_customers", Filters: "other\x1factive\x1f"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := c.Decode(tc.b, cursor); !errors.Is(err, ErrInvalidCursor) {
				t.Fatalf("a cursor issued for one query was accepted for another (%s)", tc.name)
			}
		})
	}
}

func TestCursorFromAnotherProcessIsRefused(t *testing.T) {
	issued := NewCodec("secret-a").Encode(binding(), "1003")
	if _, err := NewCodec("secret-b").Decode(binding(), issued); !errors.Is(err, ErrInvalidCursor) {
		t.Fatal("a cursor signed with a different secret was accepted")
	}
}

func TestExpiredCursorIsRefused(t *testing.T) {
	c := NewCodec("a-secret")
	cursor := c.Encode(binding(), "1003")

	// Advance the codec's clock past the TTL rather than sleeping.
	c.now = func() time.Time { return time.Now().Add(TTL + time.Minute) }
	if _, err := c.Decode(binding(), cursor); !errors.Is(err, ErrInvalidCursor) {
		t.Fatal("an expired cursor was accepted")
	}
}

func TestMalformedCursorsAreRefusedWithoutPanicking(t *testing.T) {
	c := NewCodec("a-secret")
	inputs := []string{
		"nonsense",
		".",
		"..",
		"a.b",
		strings.Repeat("A", 5000), // over the length bound
		base64.RawURLEncoding.EncodeToString([]byte("{}")) + ".sig",
		"\x00\x01\x02.\x03",
	}
	for _, in := range inputs {
		if _, err := c.Decode(binding(), in); err == nil {
			t.Errorf("Decode(%.20q) succeeded, want a refusal", in)
		}
	}
}

func TestOversizedCursorIsRefusedBeforeDecoding(t *testing.T) {
	c := NewCodec("a-secret")
	// A megabyte of base64 must not become a megabyte of decoded memory.
	huge := strings.Repeat("A", 1<<20)
	if _, err := c.Decode(binding(), huge); !errors.Is(err, ErrInvalidCursor) {
		t.Fatal("an oversized cursor was not refused outright")
	}
}
