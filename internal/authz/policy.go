package authz

import "strings"

// The policy: which scopes each MCP feature requires.
//
// It lives in one table rather than being scattered across handlers so that
// "what can this token do?" is answerable by reading forty lines, and so a new
// tool cannot be added without a deliberate decision about who may call it.
//
// A feature may require more than one scope, and all of them must be held. That
// is not pedantry: the customer summary combines a record with its order
// history, so a principal holding only customer:read must not reach it. A
// single-scope policy would have made the summary a way around the orders
// boundary.
//
// The mapping is enforced twice: once in the MCP middleware, before a handler
// runs, and again in the service layer, on the principal carried by the
// context. The duplication is intentional. The middleware is the gate; the
// service check is what still holds if a future handler is wired up without
// going through the gate.

// toolScopes maps a tool name onto the scopes required to call it.
var toolScopes = map[string][]string{
	"get_customer":               {ScopeCustomerRead},
	"search_customers":           {ScopeCustomerSearch},
	"list_customer_orders":       {ScopeCustomerOrdersRead},
	"update_customer":            {ScopeCustomerUpdate},
	"delete_customer":            {ScopeCustomerDelete},
	"send_customer_notification": {ScopeNotificationSend},
}

// promptScopes maps a prompt name onto the scopes required to render it.
//
// A prompt embeds live customer data, so rendering one is a read of that data
// and is gated as such. The analysis prompt embeds the order roll-up, so it
// needs the orders scope as well. Neither needs notification:send: the outreach
// prompt produces text and sends nothing.
var promptScopes = map[string][]string{
	"customer-analysis":       {ScopeCustomerRead, ScopeCustomerOrdersRead},
	"customer-outreach-draft": {ScopeCustomerRead},
}

// ToolScopes returns the scopes required to call the named tool, and whether
// the tool is known to the policy.
//
// An unknown tool returns false, and every caller treats that as "deny": a tool
// registered without a policy entry must not become callable by default.
func ToolScopes(tool string) ([]string, bool) {
	s, ok := toolScopes[tool]
	return s, ok
}

// PromptScopes returns the scopes required to render the named prompt.
func PromptScopes(name string) ([]string, bool) {
	s, ok := promptScopes[name]
	return s, ok
}

// ResourceScopes returns the scopes required to read a resource URI.
//
// Resource URIs are structural rather than enumerable - customer://{id}/orders
// is a template - so the decision is made on the shape of the URI. A URI
// outside the scheme is unknown, and unknown means deny.
func ResourceScopes(uri string) ([]string, bool) {
	const scheme = "customer://"
	if !strings.HasPrefix(uri, scheme) {
		return nil, false
	}
	rest := strings.TrimPrefix(uri, scheme)
	switch {
	case rest == "directory":
		// The directory enumerates the customer base, which is a search.
		return []string{ScopeCustomerSearch}, true
	case strings.HasSuffix(rest, "/orders"):
		return []string{ScopeCustomerOrdersRead}, true
	case strings.HasSuffix(rest, "/summary"):
		// A summary is a record plus its order roll-up: both boundaries apply.
		return []string{ScopeCustomerRead, ScopeCustomerOrdersRead}, true
	default:
		return []string{ScopeCustomerRead}, true
	}
}

// RequireAll returns nil only when p holds every scope in scopes.
//
// An empty scope list is a denial, not a pass: it is what an unknown feature
// produces, and the safe reading of "no policy" is "no access".
func (p *Principal) RequireAll(scopes []string) error {
	if len(scopes) == 0 {
		return denyUnknown()
	}
	for _, s := range scopes {
		if err := p.Require(s); err != nil {
			return err
		}
	}
	return nil
}

// HasAll reports whether p holds every scope in scopes.
func (p *Principal) HasAll(scopes []string) bool {
	if len(scopes) == 0 {
		return false
	}
	for _, s := range scopes {
		if !p.Has(s) {
			return false
		}
	}
	return true
}

// CanUseTool reports whether p may call the named tool.
func CanUseTool(p *Principal, tool string) bool {
	scopes, ok := ToolScopes(tool)
	return ok && p.HasAll(scopes)
}

// CanUsePrompt reports whether p may render the named prompt.
func CanUsePrompt(p *Principal, name string) bool {
	scopes, ok := PromptScopes(name)
	return ok && p.HasAll(scopes)
}

// CanReadResource reports whether p may read the resource at uri.
//
// It also serves resource templates, whose variables are left in place: the
// decision only inspects the trailing path segment, which a template preserves.
func CanReadResource(p *Principal, uri string) bool {
	scopes, ok := ResourceScopes(uri)
	return ok && p.HasAll(scopes)
}
