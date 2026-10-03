package mcp

import (
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// MCP method names this server reasons about.
const (
	methodInitialize        = "initialize"
	methodPing              = "ping"
	methodToolsList         = "tools/list"
	methodToolsCall         = "tools/call"
	methodResourcesList     = "resources/list"
	methodResourceTemplates = "resources/templates/list"
	methodResourcesRead     = "resources/read"
	methodPromptsList       = "prompts/list"
	methodPromptsGet        = "prompts/get"
	methodComplete          = "completion/complete"
)

// feature identifies what a request is asking for, in the terms the
// authorization policy and the audit log are written in.
type feature struct {
	// kind is "tool", "resource", "prompt" or "" for a protocol method.
	kind string
	// name is the tool name, resource URI or prompt name.
	name string
}

const (
	kindTool     = "tool"
	kindResource = "resource"
	kindPrompt   = "prompt"
)

// featureOf extracts the feature a request addresses.
//
// It reads only the routing fields - a name or a URI - and never the arguments.
// Arguments carry customer data; nothing in the middleware chain has a reason to
// see them, and a middleware that did would eventually log them.
func featureOf(method string, req sdk.Request) feature {
	if req == nil {
		return feature{}
	}
	switch method {
	case methodToolsCall:
		if p, ok := req.GetParams().(*sdk.CallToolParamsRaw); ok && p != nil {
			return feature{kind: kindTool, name: p.Name}
		}
	case methodResourcesRead:
		if p, ok := req.GetParams().(*sdk.ReadResourceParams); ok && p != nil {
			return feature{kind: kindResource, name: p.URI}
		}
	case methodPromptsGet:
		if p, ok := req.GetParams().(*sdk.GetPromptParams); ok && p != nil {
			return feature{kind: kindPrompt, name: p.Name}
		}
	}
	return feature{}
}

// isDataMethod reports whether a method reaches customer data, and so needs an
// authorization decision and an audit record.
//
// The list methods are deliberately excluded: they are answered from the
// registry, not from the backend, and they are filtered by scope rather than
// refused. Refusing tools/list outright would leave a client unable to discover
// even the tools it may call.
func isDataMethod(method string) bool {
	switch method {
	case methodToolsCall, methodResourcesRead, methodPromptsGet:
		return true
	default:
		return false
	}
}

// isListMethod reports whether a result should be filtered by scope.
func isListMethod(method string) bool {
	switch method {
	case methodToolsList, methodResourcesList, methodResourceTemplates, methodPromptsList:
		return true
	default:
		return false
	}
}

// sessionID reports the session a request arrived on, for log correlation.
func sessionID(req sdk.Request) string {
	if req == nil {
		return ""
	}
	sess := req.GetSession()
	if sess == nil {
		return ""
	}
	return sess.ID()
}

// requestHeaders returns the HTTP headers a request arrived with, if any. A
// stdio request has none.
func requestHeaders(req sdk.Request) (headers map[string][]string) {
	if req == nil {
		return nil
	}
	extra := req.GetExtra()
	if extra == nil || extra.Header == nil {
		return nil
	}
	return extra.Header
}

// tokenInfo returns the verified token attached by the HTTP auth middleware.
//
// This is the only path by which an identity reaches a handler. It comes from
// the SDK, which took it from the request context that auth.RequireBearerToken
// populated after verifying the signature. Nothing in the JSON-RPC body
// contributes to it, which is what makes it unforgeable by a model.
func tokenInfo(req sdk.Request) *tokenClaims {
	if req == nil {
		return nil
	}
	extra := req.GetExtra()
	if extra == nil || extra.TokenInfo == nil {
		return nil
	}
	return &tokenClaims{
		scopes:     extra.TokenInfo.Scopes,
		expiration: extra.TokenInfo.Expiration,
		userID:     extra.TokenInfo.UserID,
		extra:      extra.TokenInfo.Extra,
	}
}
