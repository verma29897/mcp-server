// Package schema_test guards against schema drift.
//
// The schemas are inferred from Go types and then patched with the constraints
// a struct tag cannot express - enums, bounds, lengths. Inference keeps the
// property names honest; the patches are where drift creeps in, because a JSON
// tag can be renamed without the patch noticing, and an enum can gain a value
// in the validator without gaining one in the schema.
//
// These tests fail when the two sides disagree, which is the only moment the
// disagreement is cheap to fix.
package schema_test

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/verma29897/mcp-server/internal/authz"
	"github.com/verma29897/mcp-server/internal/domain"
	"github.com/verma29897/mcp-server/internal/services"
	"github.com/verma29897/mcp-server/internal/tools/customer"
	"github.com/verma29897/mcp-server/tests/testutil"
)

// schemaOf renders a tool's input schema as a generic map.
func schemaOf(t *testing.T, tool *sdk.Tool) map[string]any {
	t.Helper()
	data, err := json.Marshal(tool.InputSchema)
	if err != nil {
		t.Fatalf("marshal %s input schema: %v", tool.Name, err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal %s input schema: %v", tool.Name, err)
	}
	return m
}

func propertiesOf(t *testing.T, tool *sdk.Tool) map[string]any {
	t.Helper()
	props, _ := schemaOf(t, tool)["properties"].(map[string]any)
	if props == nil {
		t.Fatalf("tool %s has no properties", tool.Name)
	}
	return props
}

func strings_(t *testing.T, v any) []string {
	t.Helper()
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, _ := item.(string)
		out = append(out, s)
	}
	return out
}

func TestEveryToolHasACompleteDescriptor(t *testing.T) {
	for _, tool := range customer.All() {
		t.Run(tool.Name, func(t *testing.T) {
			if tool.Description == "" {
				t.Error("no description; the description is the primary control over whether a model picks the right tool")
			}
			if tool.InputSchema == nil {
				t.Error("no input schema")
			}
			if tool.Annotations == nil {
				t.Fatal("no annotations")
			}
			// Every description states what the tool does, when not to use it,
			// its limits and its side effects. The headings are load-bearing:
			// a model reads them. Descriptions are hard-wrapped, so the text is
			// flattened before matching - otherwise the assertion depends on
			// where the line breaks happen to fall.
			flat := flatten(tool.Description)
			for _, section := range []string{"use this tool", "do not use"} {
				if !strings.Contains(strings.ToLower(flat), section) {
					t.Errorf("description does not cover %q", section)
				}
			}
		})
	}
}

func TestEveryToolIsCoveredByTheAuthorizationPolicy(t *testing.T) {
	// A tool registered without a policy entry is denied at runtime. That fails
	// safe, but silently: an operator discovers it from a support ticket.
	scopes, missing := customer.RequiredScopes()
	if len(missing) > 0 {
		t.Fatalf("tools with no authorization policy entry: %v", missing)
	}
	for tool, required := range scopes {
		if len(required) == 0 {
			t.Errorf("tool %q requires no scope", tool)
		}
		for _, s := range required {
			if !knownScope(s) {
				t.Errorf("tool %q requires unknown scope %q", tool, s)
			}
		}
	}
}

// flatten collapses a hard-wrapped description onto one line, so an assertion
// about its content does not depend on where the wrapping falls.
func flatten(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func knownScope(s string) bool {
	for _, k := range authz.AllScopes {
		if k == s {
			return true
		}
	}
	return false
}

func TestEnumsMatchTheValidator(t *testing.T) {
	// The schema and the validator read from the same domain slices, so this
	// test is what catches someone hard-coding a list into one of them.
	tests := []struct {
		tool     *sdk.Tool
		property string
		want     []string
	}{
		{customer.SearchCustomersTool, "status", asStrings(domain.StatusStrings())},
		{customer.SearchCustomersTool, "tier", asStrings(domain.TierStrings())},
		{customer.UpdateCustomerTool, "status", asStrings(domain.StatusStrings())},
		{customer.UpdateCustomerTool, "tier", asStrings(domain.TierStrings())},
		{customer.SendCustomerNotificationTool, "channel", asStrings(domain.ChannelStrings())},
	}
	for _, tc := range tests {
		t.Run(tc.tool.Name+"."+tc.property, func(t *testing.T) {
			prop, ok := propertiesOf(t, tc.tool)[tc.property].(map[string]any)
			if !ok {
				t.Fatalf("no property %q", tc.property)
			}
			got := strings_(t, prop["enum"])
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("enum = %v, want %v", got, tc.want)
			}

			// Every advertised value must actually validate, and nothing else
			// may. This is the half a shared slice cannot guarantee on its own.
			for _, v := range got {
				if !valid(tc.property, v) {
					t.Errorf("schema offers %q but the validator rejects it", v)
				}
			}
			if valid(tc.property, "definitely-not-a-real-value") {
				t.Errorf("the validator accepts a value the schema does not offer")
			}
		})
	}
}

func valid(property, value string) bool {
	switch property {
	case "status":
		return domain.Status(value).Valid()
	case "tier":
		return domain.Tier(value).Valid()
	case "channel":
		return domain.Channel(value).Valid()
	default:
		return false
	}
}

func asStrings(values []any) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		s, _ := v.(string)
		out = append(out, s)
	}
	return out
}

func TestBoundsMatchTheServiceLimits(t *testing.T) {
	// A schema that advertises a higher maximum than the service enforces
	// teaches a model to make calls that are silently clamped; a lower one
	// makes a legal call look illegal.
	tests := []struct {
		tool     *sdk.Tool
		property string
		wantMax  float64
	}{
		{customer.SearchCustomersTool, "limit", services.MaxSearchLimit},
		{customer.ListCustomerOrdersTool, "limit", services.MaxOrderLimit},
	}
	for _, tc := range tests {
		t.Run(tc.tool.Name+"."+tc.property, func(t *testing.T) {
			prop, _ := propertiesOf(t, tc.tool)[tc.property].(map[string]any)
			max, ok := prop["maximum"].(float64)
			if !ok {
				t.Fatalf("property %q has no maximum", tc.property)
			}
			if max != tc.wantMax {
				t.Errorf("maximum = %v, want the service limit %v", max, tc.wantMax)
			}
		})
	}
}

func TestLengthLimitsMatchTheServiceLimits(t *testing.T) {
	tests := []struct {
		tool     *sdk.Tool
		property string
		wantMax  float64
	}{
		{customer.UpdateCustomerTool, "name", services.MaxNameLength},
		{customer.SearchCustomersTool, "query", services.MaxSearchTextLength},
		{customer.SendCustomerNotificationTool, "subject", services.MaxNotificationSubject},
		{customer.SendCustomerNotificationTool, "body", services.MaxNotificationBody},
	}
	for _, tc := range tests {
		t.Run(tc.tool.Name+"."+tc.property, func(t *testing.T) {
			prop, _ := propertiesOf(t, tc.tool)[tc.property].(map[string]any)
			got, ok := prop["maxLength"].(float64)
			if !ok {
				t.Fatalf("property %q has no maxLength", tc.property)
			}
			if got != tc.wantMax {
				t.Errorf("maxLength = %v, want %v", got, tc.wantMax)
			}
		})
	}
}

func TestRequiredPropertiesMatchTheGoTypes(t *testing.T) {
	// A field without omitempty is required; a field with it is optional. The
	// rule is the SDK's, and this is what stops a tag edit silently making a
	// required argument optional.
	tests := []struct {
		tool *sdk.Tool
		want []string
	}{
		{customer.GetCustomerTool, []string{"customer_id"}},
		{customer.SearchCustomersTool, nil},
		{customer.ListCustomerOrdersTool, []string{"customer_id"}},
		{customer.UpdateCustomerTool, []string{"customer_id"}},
		{customer.DeleteCustomerTool, []string{"confirm", "customer_id"}},
		{customer.SendCustomerNotificationTool, []string{"body", "channel", "customer_id"}},
	}
	for _, tc := range tests {
		t.Run(tc.tool.Name, func(t *testing.T) {
			got := strings_(t, schemaOf(t, tc.tool)["required"])
			sort.Strings(got)
			want := append([]string(nil), tc.want...)
			sort.Strings(want)
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("required = %v, want %v", got, want)
			}
		})
	}
}

func TestSchemaPropertiesMatchTheStructTags(t *testing.T) {
	// The patches in tool.go address properties by JSON name. Renaming a tag
	// without updating the patch panics at startup, which is the right time -
	// but this test finds it a build earlier, and covers the reverse case of a
	// property that exists in the struct and is never constrained.
	tests := []struct {
		tool *sdk.Tool
		typ  any
	}{
		{customer.GetCustomerTool, customer.GetCustomerInput{}},
		{customer.SearchCustomersTool, customer.SearchCustomersInput{}},
		{customer.ListCustomerOrdersTool, customer.ListCustomerOrdersInput{}},
		{customer.UpdateCustomerTool, customer.UpdateCustomerInput{}},
		{customer.DeleteCustomerTool, customer.DeleteCustomerInput{}},
		{customer.SendCustomerNotificationTool, customer.SendCustomerNotificationInput{}},
	}
	for _, tc := range tests {
		t.Run(tc.tool.Name, func(t *testing.T) {
			want := jsonFieldNames(tc.typ)
			got := make([]string, 0, len(want))
			for name := range propertiesOf(t, tc.tool) {
				got = append(got, name)
			}
			sort.Strings(got)
			sort.Strings(want)
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("schema properties = %v, struct fields = %v", got, want)
			}
		})
	}
}

func jsonFieldNames(v any) []string {
	rt := reflect.TypeOf(v)
	out := make([]string, 0, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		out = append(out, name)
	}
	return out
}

func TestEveryPropertyIsDescribed(t *testing.T) {
	// An undescribed property is one the model has to guess at, and guessing is
	// how a destructive argument gets set by accident.
	for _, tool := range customer.All() {
		t.Run(tool.Name, func(t *testing.T) {
			for name, raw := range propertiesOf(t, tool) {
				prop, _ := raw.(map[string]any)
				if desc, _ := prop["description"].(string); strings.TrimSpace(desc) == "" {
					t.Errorf("property %q has no description", name)
				}
			}
		})
	}
}

func TestInputSchemasAreClosed(t *testing.T) {
	// additionalProperties must be false, so an argument the server does not
	// know about is refused rather than ignored. An ignored argument is how a
	// caller convinces itself it passed a tenant, a filter or an override that
	// the server never saw.
	for _, tool := range customer.All() {
		t.Run(tool.Name, func(t *testing.T) {
			schema := schemaOf(t, tool)
			additional, present := schema["additionalProperties"]
			if !present {
				t.Fatal("additionalProperties is unset; unknown arguments would be silently ignored")
			}
			if allowed, _ := additional.(bool); allowed {
				t.Error("additionalProperties is true")
			}
		})
	}
}

func TestAnnotationsMatchTheBehaviourClass(t *testing.T) {
	// The hints are how a client decides whether to ask a human first. A
	// destructive tool annotated read-only would skip that confirmation.
	tests := []struct {
		tool        *sdk.Tool
		readOnly    bool
		destructive bool
		idempotent  bool
		openWorld   bool
	}{
		{customer.GetCustomerTool, true, false, true, false},
		{customer.SearchCustomersTool, true, false, true, false},
		{customer.ListCustomerOrdersTool, true, false, true, false},
		{customer.UpdateCustomerTool, false, false, true, false},
		{customer.DeleteCustomerTool, false, true, true, false},
		{customer.SendCustomerNotificationTool, false, false, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.tool.Name, func(t *testing.T) {
			a := tc.tool.Annotations
			if a.ReadOnlyHint != tc.readOnly {
				t.Errorf("readOnlyHint = %v, want %v", a.ReadOnlyHint, tc.readOnly)
			}
			if a.DestructiveHint == nil || *a.DestructiveHint != tc.destructive {
				t.Errorf("destructiveHint = %v, want %v", a.DestructiveHint, tc.destructive)
			}
			if a.IdempotentHint != tc.idempotent {
				t.Errorf("idempotentHint = %v, want %v", a.IdempotentHint, tc.idempotent)
			}
			if a.OpenWorldHint == nil || *a.OpenWorldHint != tc.openWorld {
				t.Errorf("openWorldHint = %v, want %v", a.OpenWorldHint, tc.openWorld)
			}
		})
	}
}

func TestDangerousToolsDocumentTheirGuardRails(t *testing.T) {
	if !strings.Contains(flatten(customer.DeleteCustomerTool.Description), "IRREVERSIBLE") {
		t.Error("the delete tool does not say the operation cannot be undone")
	}
	if !strings.Contains(flatten(customer.SendCustomerNotificationTool.Description), "cannot be recalled") {
		t.Error("the notification tool does not say a sent message cannot be recalled")
	}
	confirm, _ := propertiesOf(t, customer.DeleteCustomerTool)["confirm"].(map[string]any)
	if desc, _ := confirm["description"].(string); !strings.Contains(desc, "explicitly approved") {
		t.Errorf("the confirm argument does not tie itself to explicit user approval: %q", desc)
	}
	key, _ := propertiesOf(t, customer.SendCustomerNotificationTool)["idempotency_key"].(map[string]any)
	if desc, _ := key["description"].(string); !strings.Contains(desc, "retry") {
		t.Errorf("the idempotency key does not explain how to use it on a retry: %q", desc)
	}
}

func TestSliceOutputsAreNeverNil(t *testing.T) {
	// The output schemas narrow these three properties from the inferred
	// ["null","array"] to plain "array", because no handler can produce nil.
	// If that ever stops being true, the SDK's output validation rejects the
	// result at runtime — so the assumption is asserted here instead.
	//
	// The narrowing is not cosmetic: the MCP Inspector's portability check
	// flags the array form because several clients read `type` as a single
	// string and either reject the tool or drop the constraint.
	svc, be := testutil.NewService()
	h := customer.NewHandlers(svc)
	ctx := testutil.Context()

	t.Run("search with no matches", func(t *testing.T) {
		be.SearchCustomersFn = func(context.Context, domain.SearchQuery) (domain.CustomerList, error) {
			return domain.CustomerList{Items: nil}, nil
		}
		out, err := h.SearchCustomers(ctx, customer.SearchCustomersInput{Query: "nothing-matches-this"})
		if err != nil {
			t.Fatalf("SearchCustomers: %v", err)
		}
		if out.Customers == nil {
			t.Error("customers is nil; the output schema declares a non-nullable array")
		}
	})

	t.Run("orders for a customer with none", func(t *testing.T) {
		be.ListOrdersFn = func(context.Context, string, string, domain.Page) (domain.OrderList, error) {
			return domain.OrderList{Items: nil}, nil
		}
		out, err := h.ListCustomerOrders(ctx, customer.ListCustomerOrdersInput{CustomerID: "1001"})
		if err != nil {
			t.Fatalf("ListCustomerOrders: %v", err)
		}
		if out.Orders == nil {
			t.Error("orders is nil; the output schema declares a non-nullable array")
		}
	})

	t.Run("update that changes nothing nameable", func(t *testing.T) {
		out, err := h.UpdateCustomer(ctx, customer.UpdateCustomerInput{
			CustomerID: "1002", Tier: string(domain.TierPro),
		})
		if err != nil {
			t.Fatalf("UpdateCustomer: %v", err)
		}
		if out.UpdatedFields == nil {
			t.Error("updated_fields is nil; the output schema declares a non-nullable array")
		}
	})
}

func TestOutputSchemasDeclareASingleType(t *testing.T) {
	// A `type` array is legal JSON Schema and poorly supported: several MCP
	// clients read it as a single string and either reject the tool or drop the
	// constraint. Keeping every declared type a single string is what makes the
	// tool surface portable across clients.
	for _, tool := range customer.All() {
		t.Run(tool.Name, func(t *testing.T) {
			data, err := json.Marshal(tool.OutputSchema)
			if err != nil {
				t.Fatalf("marshal output schema: %v", err)
			}
			if len(data) == 0 || string(data) == "null" {
				return // inferred at registration; nothing declared here to check
			}
			var schema map[string]any
			if err := json.Unmarshal(data, &schema); err != nil {
				t.Fatalf("unmarshal output schema: %v", err)
			}
			for path, kind := range multiTypedPaths(schema, "") {
				t.Errorf("%s declares `type` as an array (%v); several clients cannot read that form", path, kind)
			}
		})
	}
}

// multiTypedPaths walks a schema and reports every `type` expressed as an array.
func multiTypedPaths(node any, path string) map[string]any {
	found := map[string]any{}
	switch n := node.(type) {
	case map[string]any:
		if raw, ok := n["type"]; ok {
			if list, isList := raw.([]any); isList {
				found[path+".type"] = list
			}
		}
		for key, child := range n {
			if key == "type" {
				continue
			}
			for k, v := range multiTypedPaths(child, path+"."+key) {
				found[k] = v
			}
		}
	case []any:
		for i, child := range n {
			for k, v := range multiTypedPaths(child, fmt.Sprintf("%s[%d]", path, i)) {
				found[k] = v
			}
		}
	}
	return found
}
