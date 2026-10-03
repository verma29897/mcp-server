package customer

import (
	"fmt"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/verma29897/mcp-server/internal/authz"
	"github.com/verma29897/mcp-server/internal/domain"
	"github.com/verma29897/mcp-server/internal/idempotency"
	"github.com/verma29897/mcp-server/internal/services"
)

// Schema bounds that are not business limits.
const (
	// maxCursorLength matches the bound internal/paging enforces before it
	// parses anything, so an oversized cursor is refused by the schema rather
	// than reaching the decoder.
	maxCursorLength = 1024
	// maxEmailLength is the RFC 5321 maximum.
	maxEmailLength = 254
	// maxVersion is a sanity bound on an optimistic-lock precondition.
	maxVersion = 1 << 31
)

// Behaviour classes for the tools in this package. MCP expresses these through
// mcp.ToolAnnotations hints; the constants below record the intent so the
// mapping in annotations() stays explicit and reviewable.
//
//	READ_ONLY             does not modify anything
//	MUTATING              modifies internal state, non-destructively
//	DESTRUCTIVE           irreversibly removes state
//	EXTERNAL_SIDE_EFFECT  causes an effect outside this system
const (
	ClassReadOnly           = "READ_ONLY"
	ClassMutating           = "MUTATING"
	ClassDestructive        = "DESTRUCTIVE"
	ClassExternalSideEffect = "EXTERNAL_SIDE_EFFECT"
)

// Tool descriptors.
//
// Descriptions are written for the model, not for a developer: each states what
// the tool does, when to reach for it, when not to, its limits and its side
// effects. They are the primary control over whether a model picks the right
// tool.
var (
	// GetCustomerTool is READ_ONLY.
	GetCustomerTool = &mcp.Tool{
		Name:  "get_customer",
		Title: "Get customer by ID",
		Description: `Get the full record for one customer using their unique customer ID.

Use this tool when the user names or has already established a specific customer ID
and wants details such as name, contact email, account status or commercial tier.

Do not use this tool to find a customer whose ID you do not know: call
search_customers first to resolve a name or email into an ID, then call this tool.
Do not call it repeatedly to enumerate customers.

Limitations: it returns exactly one customer and nothing about their orders. Use
list_customer_orders for purchase history, or read the customer://{id}/summary
resource for a combined view.

This tool is read-only: it never modifies customer data.`,
		Annotations: annotations(ClassReadOnly, "Get customer by ID"),
		InputSchema: mustSchema[GetCustomerInput](nil),
	}

	// SearchCustomersTool is READ_ONLY.
	SearchCustomersTool = &mcp.Tool{
		Name:  "search_customers",
		Title: "Search customers",
		Description: `Find customers by a name or email fragment, by account status, or by commercial tier.

Use this tool when the user refers to a customer by something other than an ID
("the Acme account", "suspended enterprise customers"), or when they want a list
of customers matching a condition. The usual flow is search_customers to obtain
an ID, then get_customer for the detail.

At least one of query, status or tier must be supplied; an unconstrained search is
rejected rather than returning an arbitrary slice of the customer base.

Do not use this tool to page through the whole customer base, and do not call it
repeatedly with widening filters to assemble one: if a result is truncated, narrow the
filters or follow next_cursor, rather than raising the limit. Do not use it to look up a
customer whose ID you already have - call get_customer instead.

Limitations: matching on query is a case-insensitive substring match, not fuzzy
search, so a misspelt name returns nothing. Results are capped (default 20, maximum
100) and the response reports whether it was truncated; narrow the filters rather
than raising the limit repeatedly.

This tool is read-only: it never modifies customer data.`,
		Annotations: annotations(ClassReadOnly, "Search customers"),
		OutputSchema: mustSchema[SearchCustomersOutput](func(s *jsonschema.Schema) {
			alwaysPresent(s, "customers")
		}),
		InputSchema: mustSchema[SearchCustomersInput](func(s *jsonschema.Schema) {
			enum(s, "status", domain.StatusStrings())
			enum(s, "tier", domain.TierStrings())
			bounds(s, "limit", 1, maxSearchLimit)
			maxLen(s, "query", services.MaxSearchTextLength)
			maxLen(s, "cursor", maxCursorLength)
		}),
	}

	// ListCustomerOrdersTool is READ_ONLY.
	ListCustomerOrdersTool = &mcp.Tool{
		Name:  "list_customer_orders",
		Title: "List customer orders",
		Description: `List the orders placed by one customer, newest first.

Use this tool when the user asks about a customer's purchase history, spend,
recent activity, or whether they have open orders.

Do not use it to look up a single order by order ID, and do not use it as a way to
discover customers: it requires a customer ID you already have.

Limitations: results are capped (default 20, maximum 200) and the response reports
whether older orders were cut off. Totals are returned per order in that order's own
currency and are not converted or summed.

This tool is read-only: it never modifies orders or customer data.`,
		Annotations: annotations(ClassReadOnly, "List customer orders"),
		OutputSchema: mustSchema[ListCustomerOrdersOutput](func(s *jsonschema.Schema) {
			alwaysPresent(s, "orders")
		}),
		InputSchema: mustSchema[ListCustomerOrdersInput](func(s *jsonschema.Schema) {
			bounds(s, "limit", 1, maxOrderLimit)
			maxLen(s, "cursor", maxCursorLength)
		}),
	}

	// UpdateCustomerTool is MUTATING.
	UpdateCustomerTool = &mcp.Tool{
		Name:  "update_customer",
		Title: "Update customer details",
		Description: `Update one or more fields on an existing customer record.

Use this tool only when the user has clearly asked for a change and has supplied the
new values. Send only the fields that should change; omitted fields are left exactly
as they are. Confirm the customer identity with get_customer first if there is any
ambiguity about which record is meant.

Do not use it to create a customer (it fails if the ID does not exist) and do not use
it to guess at corrections the user has not asked for.

Limitations: at least one changeable field must be supplied. Email must be a valid
address; status and tier must be one of the documented values.

Side effects: this tool WRITES to the customer record. The change is visible to other
systems immediately. It is idempotent: applying the same patch twice leaves the same
final state.`,
		Annotations: annotations(ClassMutating, "Update customer details"),
		OutputSchema: mustSchema[UpdateCustomerOutput](func(s *jsonschema.Schema) {
			alwaysPresent(s, "updated_fields")
		}),
		InputSchema: mustSchema[UpdateCustomerInput](func(s *jsonschema.Schema) {
			enum(s, "status", domain.StatusStrings())
			enum(s, "tier", domain.TierStrings())
			minLen(s, "name", 1)
			maxLen(s, "name", services.MaxNameLength)
			maxLen(s, "email", maxEmailLength)
			bounds(s, "expected_version", 1, maxVersion)
		}),
	}

	// DeleteCustomerTool is DESTRUCTIVE.
	DeleteCustomerTool = &mcp.Tool{
		Name:  "delete_customer",
		Title: "Permanently delete a customer",
		Description: `Permanently delete a customer record and all of its orders.

This operation is DESTRUCTIVE AND IRREVERSIBLE. There is no undo and no soft-delete:
the record and its order history are gone.

Use this tool only when the user has explicitly and unambiguously asked to delete a
specific customer. Before calling it, confirm the exact record with get_customer and
state plainly to the user what will be destroyed. The confirm argument must be set to
true, and you should set it only after that explicit approval.

Do not use this tool to deactivate an account: to stop a customer being active, call
update_customer with status set to inactive or suspended, which is reversible.

Side effects: this tool DESTROYS data in the customer backend.`,
		Annotations: annotations(ClassDestructive, "Permanently delete a customer"),
		InputSchema: mustSchema[DeleteCustomerInput](func(s *jsonschema.Schema) {
			bounds(s, "expected_version", 1, maxVersion)
		}),
	}

	// SendCustomerNotificationTool is EXTERNAL_SIDE_EFFECT.
	SendCustomerNotificationTool = &mcp.Tool{
		Name:  "send_customer_notification",
		Title: "Send a message to a customer",
		Description: `Send an email or SMS message to a customer through the company messaging provider.

This tool contacts a real person outside this system. A sent message cannot be
recalled.

Use it only when the user has asked for a message to be sent and has approved the
content. Show the user the exact subject and body you intend to send and get their
agreement before calling. The customer-outreach-draft prompt is the right way to
compose that text first.

Do not use this tool to test connectivity, to send yourself a copy, or to notify a
customer of something the user did not ask you to communicate.

Limitations: subject is required for the email channel and ignored for sms; the body
is plain text limited to 4000 characters. Delivery is asynchronous, so a returned
message ID means accepted for delivery, not read.

Side effects: this tool sends an EXTERNAL message and is not idempotent - calling it
twice sends two messages.`,
		Annotations: annotations(ClassExternalSideEffect, "Send a message to a customer"),
		InputSchema: mustSchema[SendCustomerNotificationInput](func(s *jsonschema.Schema) {
			enum(s, "channel", domain.ChannelStrings())
			maxLen(s, "subject", services.MaxNotificationSubject)
			minLen(s, "body", 1)
			maxLen(s, "body", services.MaxNotificationBody)
			minLen(s, "idempotency_key", idempotency.MinKeyLength)
			maxLen(s, "idempotency_key", idempotency.MaxKeyLength)
		}),
	}
)

// annotations converts a behaviour class into the MCP hint set for it.
//
// The SDK models destructiveHint and openWorldHint as *bool so that "unset" is
// distinguishable from false; both default to true on the wire, so a read-only
// or closed-world tool has to say so explicitly.
func annotations(class, title string) *mcp.ToolAnnotations {
	a := &mcp.ToolAnnotations{Title: title}
	switch class {
	case ClassReadOnly:
		a.ReadOnlyHint = true
		a.IdempotentHint = true
		a.DestructiveHint = ptr(false)
		a.OpenWorldHint = ptr(false)
	case ClassMutating:
		a.ReadOnlyHint = false
		a.IdempotentHint = true
		a.DestructiveHint = ptr(false)
		a.OpenWorldHint = ptr(false)
	case ClassDestructive:
		a.ReadOnlyHint = false
		a.IdempotentHint = true // deleting twice leaves the same end state
		a.DestructiveHint = ptr(true)
		a.OpenWorldHint = ptr(false)
	case ClassExternalSideEffect:
		a.ReadOnlyHint = false
		a.IdempotentHint = false // each call sends another message
		a.DestructiveHint = ptr(false)
		a.OpenWorldHint = ptr(true)
	default:
		panic(fmt.Sprintf("unknown tool behaviour class %q", class))
	}
	return a
}

// RequiredScopes returns the authorization scopes each tool needs, and reports
// any tool with no policy entry.
//
// The MCP layer does not use this - it consults the policy directly. It exists
// so a test can assert the two lists have not drifted apart: a tool registered
// without a policy entry is denied at runtime, which is safe but silent, and a
// silent denial is a bug an operator discovers from a support ticket.
func RequiredScopes() (map[string][]string, []string) {
	out := make(map[string][]string, len(All()))
	var missing []string
	for _, tool := range All() {
		scopes, ok := authz.ToolScopes(tool.Name)
		if !ok || len(scopes) == 0 {
			missing = append(missing, tool.Name)
			continue
		}
		out[tool.Name] = scopes
	}
	return out, missing
}

// All returns every tool descriptor in this package, in registration order.
func All() []*mcp.Tool {
	return []*mcp.Tool{
		GetCustomerTool,
		SearchCustomersTool,
		ListCustomerOrdersTool,
		UpdateCustomerTool,
		DeleteCustomerTool,
		SendCustomerNotificationTool,
	}
}

// mustSchema infers a JSON Schema from T and applies optional refinements.
//
// Inference keeps the schema tied to the Go type (so required properties,
// property names and descriptions cannot drift from the handler), while the
// patch adds the constraints the struct tag cannot express. A failure here is a
// programming error discovered at process start, so it panics.
func mustSchema[T any](patch func(*jsonschema.Schema)) *jsonschema.Schema {
	s, err := jsonschema.For[T](nil)
	if err != nil {
		panic(fmt.Sprintf("infer schema for %T: %v", *new(T), err))
	}
	if patch != nil {
		patch(s)
	}
	return s
}

// prop returns the named property schema, panicking if it is absent: that means
// the JSON name in the patch no longer matches the struct.
func prop(s *jsonschema.Schema, name string) *jsonschema.Schema {
	p, ok := s.Properties[name]
	if !ok {
		panic(fmt.Sprintf("schema has no property %q", name))
	}
	return p
}

// alwaysPresent narrows an inferred slice property from ["null","array"] to
// plain "array".
//
// Schema inference has to allow null, because a Go slice can be nil. These
// three never are - every handler builds them with make() or substitutes an
// empty slice - so the inferred schema is describing a value this server cannot
// produce.
//
// It is worth correcting rather than tolerating. The MCP Inspector's schema
// portability check flags the array form because several clients read `type` as
// a single string and either reject the tool or silently drop the constraint;
// either way the model loses the shape of the result. TestSliceOutputsAreNeverNil
// guards the assumption this narrowing rests on.
func alwaysPresent(s *jsonschema.Schema, name string) {
	p := prop(s, name)
	p.Types = nil
	p.Type = "array"
}

func enum(s *jsonschema.Schema, name string, values []any) {
	prop(s, name).Enum = values
}

func bounds(s *jsonschema.Schema, name string, min, max float64) {
	p := prop(s, name)
	p.Minimum = &min
	p.Maximum = &max
}

func minLen(s *jsonschema.Schema, name string, n int) {
	prop(s, name).MinLength = &n
}

func maxLen(s *jsonschema.Schema, name string, n int) {
	prop(s, name).MaxLength = &n
}

func ptr[T any](v T) *T { return &v }
