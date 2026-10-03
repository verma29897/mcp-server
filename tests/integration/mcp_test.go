// Package integration_test drives the real MCP server through a real MCP
// client, exercising the full path:
//
//	client -> transport -> SDK server -> middleware -> tool/resource/prompt
//	       -> service -> mock backend
package integration_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/verma29897/mcp-server/internal/config"
	"github.com/verma29897/mcp-server/internal/domain"
	appmcp "github.com/verma29897/mcp-server/internal/mcp"
	"github.com/verma29897/mcp-server/internal/prompts"
	"github.com/verma29897/mcp-server/internal/resources"
	"github.com/verma29897/mcp-server/tests/testutil"
)

// newSession builds a server, connects an in-memory client to it and returns
// the client session. The in-memory transport exercises the same session
// machinery as stdio and HTTP without any I/O.
func newSession(t *testing.T) (*sdk.ClientSession, *testutil.FakeBackend) {
	cs, be, _ := newSessionWith(t, testutil.Config(config.TransportStdio))
	return cs, be
}

// newSessionWith connects an in-memory client to a server built from cfg, and
// returns the audit records the session produced.
func newSessionWith(t *testing.T, cfg *config.Config) (*sdk.ClientSession, *testutil.FakeBackend, *testutil.AuditRecorder) {
	t.Helper()

	svc, be := testutil.NewService()
	deps, recorder := testutil.Deps(cfg)
	srv, err := appmcp.New(cfg, svc, testutil.Logger(), deps)
	if err != nil {
		t.Fatalf("create MCP server: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	clientTransport, serverTransport := sdk.NewInMemoryTransports()

	// The server must be connected before the client, since connecting the
	// client runs the initialize handshake.
	serverSession, err := srv.SDK().Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("connect server: %v", err)
	}
	t.Cleanup(func() { _ = serverSession.Close() })

	client := sdk.NewClient(&sdk.Implementation{Name: "integration-test-client", Version: "1.0.0"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("connect client: %v", err)
	}
	t.Cleanup(func() { _ = clientSession.Close() })

	return clientSession, be, recorder
}

func TestInitializeAdvertisesIdentityAndCapabilities(t *testing.T) {
	cs, _ := newSession(t)

	init := cs.InitializeResult()
	if init == nil {
		t.Fatal("no initialize result")
	}
	if init.ServerInfo.Name != "test-mcp-server" {
		t.Errorf("server name = %q, want %q", init.ServerInfo.Name, "test-mcp-server")
	}
	if init.ServerInfo.Version != "0.0.0-test" {
		t.Errorf("server version = %q, want %q", init.ServerInfo.Version, "0.0.0-test")
	}
	if init.Instructions == "" {
		t.Error("instructions are empty; a client has nothing describing the server as a whole")
	}

	// Capabilities are inferred by the SDK from what was registered.
	if init.Capabilities.Tools == nil {
		t.Error("tools capability not advertised")
	}
	if init.Capabilities.Resources == nil {
		t.Error("resources capability not advertised")
	}
	if init.Capabilities.Prompts == nil {
		t.Error("prompts capability not advertised")
	}
	if init.Capabilities.Completions == nil {
		t.Error("completions capability not advertised despite a completion handler being set")
	}
}

func TestToolsListExposesSchemasAndAnnotations(t *testing.T) {
	cs, _ := newSession(t)

	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}

	want := map[string]struct {
		readOnly    bool
		destructive bool
		openWorld   bool
	}{
		"get_customer":               {readOnly: true},
		"search_customers":           {readOnly: true},
		"list_customer_orders":       {readOnly: true},
		"update_customer":            {},
		"delete_customer":            {destructive: true},
		"send_customer_notification": {openWorld: true},
	}
	if len(res.Tools) != len(want) {
		t.Fatalf("got %d tools, want %d", len(res.Tools), len(want))
	}

	for _, tool := range res.Tools {
		spec, ok := want[tool.Name]
		if !ok {
			t.Errorf("unexpected tool %q", tool.Name)
			continue
		}
		if tool.Description == "" {
			t.Errorf("tool %q has no description", tool.Name)
		}
		if tool.InputSchema == nil {
			t.Errorf("tool %q has no input schema", tool.Name)
		}
		if tool.OutputSchema == nil {
			t.Errorf("tool %q has no output schema", tool.Name)
		}
		if tool.Annotations == nil {
			t.Fatalf("tool %q has no annotations", tool.Name)
		}
		if tool.Annotations.ReadOnlyHint != spec.readOnly {
			t.Errorf("tool %q readOnlyHint = %v, want %v", tool.Name, tool.Annotations.ReadOnlyHint, spec.readOnly)
		}
		if got := tool.Annotations.DestructiveHint; got == nil || *got != spec.destructive {
			t.Errorf("tool %q destructiveHint = %v, want %v", tool.Name, got, spec.destructive)
		}
		if got := tool.Annotations.OpenWorldHint; got == nil || *got != spec.openWorld {
			t.Errorf("tool %q openWorldHint = %v, want %v", tool.Name, got, spec.openWorld)
		}
	}
}

func TestToolInputSchemaMarksRequiredAndEnums(t *testing.T) {
	cs, _ := newSession(t)

	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	byName := map[string]*sdk.Tool{}
	for _, tool := range res.Tools {
		byName[tool.Name] = tool
	}

	t.Run("required properties", func(t *testing.T) {
		schema := asMap(t, byName["get_customer"].InputSchema)
		required := asStrings(t, schema["required"])
		if len(required) != 1 || required[0] != "customer_id" {
			t.Errorf("required = %v, want [customer_id]", required)
		}
	})

	t.Run("optional properties", func(t *testing.T) {
		schema := asMap(t, byName["search_customers"].InputSchema)
		if raw, ok := schema["required"]; ok && len(asStrings(t, raw)) != 0 {
			t.Errorf("required = %v, want none: every search filter is optional", raw)
		}
	})

	t.Run("enum constraints", func(t *testing.T) {
		schema := asMap(t, byName["search_customers"].InputSchema)
		props := asMap(t, schema["properties"])
		status := asMap(t, props["status"])
		got := asStrings(t, status["enum"])
		want := []string{"active", "inactive", "suspended"}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("status enum = %v, want %v", got, want)
		}
	})

	t.Run("descriptions reach the model", func(t *testing.T) {
		schema := asMap(t, byName["delete_customer"].InputSchema)
		props := asMap(t, schema["properties"])
		confirm := asMap(t, props["confirm"])
		if desc, _ := confirm["description"].(string); !strings.Contains(desc, "cannot be undone") {
			t.Errorf("confirm description = %q, want it to warn that deletion is irreversible", desc)
		}
	})
}

func TestCallToolReturnsStructuredContent(t *testing.T) {
	cs, _ := newSession(t)

	res, err := cs.CallTool(context.Background(), &sdk.CallToolParams{
		Name:      "get_customer",
		Arguments: map[string]any{"customer_id": "1001"},
	})
	if err != nil {
		t.Fatalf("tools/call: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected tool error: %s", contentText(res))
	}
	if res.StructuredContent == nil {
		t.Fatal("no structured content")
	}

	var out struct {
		Customer struct {
			CustomerID string `json:"customer_id"`
			Name       string `json:"name"`
		} `json:"customer"`
	}
	remarshal(t, res.StructuredContent, &out)
	if out.Customer.CustomerID != "1001" || out.Customer.Name != "Acme Industries" {
		t.Errorf("got %+v, want customer 1001 Acme Industries", out.Customer)
	}

	// Content is also populated, for clients that do not read structured output.
	if contentText(res) == "" {
		t.Error("content block is empty")
	}
}

func TestCallToolValidationRejectedBySDK(t *testing.T) {
	cs, be := newSession(t)

	// "archived" is not in the status enum, so the SDK rejects the call
	// against the input schema before the handler is reached.
	res, err := cs.CallTool(context.Background(), &sdk.CallToolParams{
		Name:      "search_customers",
		Arguments: map[string]any{"status": "archived"},
	})
	if err != nil {
		t.Fatalf("tools/call returned a protocol error, want an in-band tool error: %v", err)
	}
	if !res.IsError {
		t.Fatal("IsError = false, want true for schema-invalid arguments")
	}
	if n := be.Calls("SearchCustomers"); n != 0 {
		t.Errorf("backend reached %d times despite invalid arguments", n)
	}
}

func TestCallToolMissingRequiredArgument(t *testing.T) {
	cs, _ := newSession(t)

	res, err := cs.CallTool(context.Background(), &sdk.CallToolParams{
		Name:      "get_customer",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("tools/call: %v", err)
	}
	if !res.IsError {
		t.Fatal("IsError = false, want true when a required argument is missing")
	}
	if !strings.Contains(strings.ToLower(contentText(res)), "customer_id") {
		t.Errorf("error text %q does not name the missing argument", contentText(res))
	}
}

func TestCallToolErrorsAreInBandAndClassified(t *testing.T) {
	tests := []struct {
		name     string
		params   *sdk.CallToolParams
		wantCode domain.Code
	}{
		{
			name: "not found",
			params: &sdk.CallToolParams{
				Name:      "get_customer",
				Arguments: map[string]any{"customer_id": "9999"},
			},
			wantCode: domain.CodeNotFound,
		},
		{
			name: "invalid argument",
			params: &sdk.CallToolParams{
				Name:      "update_customer",
				Arguments: map[string]any{"customer_id": "1001", "email": "nope"},
			},
			wantCode: domain.CodeInvalidArgument,
		},
		{
			name: "destructive call without confirmation",
			params: &sdk.CallToolParams{
				Name:      "delete_customer",
				Arguments: map[string]any{"customer_id": "1001", "confirm": false},
			},
			wantCode: domain.CodeInvalidArgument,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cs, _ := newSession(t)

			res, err := cs.CallTool(context.Background(), tc.params)
			// A tool failure must be a result, not a protocol error, so the
			// model can see it and correct itself.
			if err != nil {
				t.Fatalf("got a protocol error, want an in-band tool error: %v", err)
			}
			if !res.IsError {
				t.Fatal("IsError = false, want true")
			}
			if got := contentText(res); !strings.Contains(got, string(tc.wantCode)) {
				t.Errorf("error text = %q, want it to carry the %s classification", got, tc.wantCode)
			}
		})
	}
}

func TestCallToolBackendFailureIsRedacted(t *testing.T) {
	cs, be := newSession(t)
	be.GetCustomerFn = func(context.Context, string, string) (domain.Customer, error) {
		return domain.Customer{}, domain.Backend("get_customer",
			errShim("postgres://admin:hunter2@10.0.0.5:5432/customers: connection refused"))
	}

	res, err := cs.CallTool(context.Background(), &sdk.CallToolParams{
		Name:      "get_customer",
		Arguments: map[string]any{"customer_id": "1001"},
	})
	if err != nil {
		t.Fatalf("tools/call: %v", err)
	}
	if !res.IsError {
		t.Fatal("IsError = false, want true")
	}

	text := contentText(res)
	for _, secret := range []string{"hunter2", "10.0.0.5", "postgres://", "admin"} {
		if strings.Contains(text, secret) {
			t.Errorf("tool error leaks %q to the client: %s", secret, text)
		}
	}
	if !strings.Contains(text, string(domain.CodeBackendError)) {
		t.Errorf("error text = %q, want the BACKEND_ERROR classification", text)
	}
}

func TestCallUnknownTool(t *testing.T) {
	cs, _ := newSession(t)

	// An unknown tool is a protocol failure, not a tool result.
	if _, err := cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "no_such_tool"}); err == nil {
		t.Fatal("calling an unknown tool succeeded")
	}
}

func TestMutatingToolRoundTrip(t *testing.T) {
	cs, _ := newSession(t)
	ctx := context.Background()

	update, err := cs.CallTool(ctx, &sdk.CallToolParams{
		Name:      "update_customer",
		Arguments: map[string]any{"customer_id": "1002", "tier": "enterprise"},
	})
	if err != nil || update.IsError {
		t.Fatalf("update_customer failed: err=%v result=%s", err, contentText(update))
	}

	read, err := cs.CallTool(ctx, &sdk.CallToolParams{
		Name:      "get_customer",
		Arguments: map[string]any{"customer_id": "1002"},
	})
	if err != nil || read.IsError {
		t.Fatalf("get_customer failed: err=%v result=%s", err, contentText(read))
	}

	var out struct {
		Customer struct {
			Tier string `json:"tier"`
		} `json:"customer"`
	}
	remarshal(t, read.StructuredContent, &out)
	if out.Customer.Tier != "enterprise" {
		t.Errorf("tier = %q after update, want enterprise", out.Customer.Tier)
	}
}

func TestResourcesListAndRead(t *testing.T) {
	cs, _ := newSession(t)
	ctx := context.Background()

	list, err := cs.ListResources(ctx, nil)
	if err != nil {
		t.Fatalf("resources/list: %v", err)
	}
	if len(list.Resources) != 1 || list.Resources[0].URI != resources.DirectoryURI {
		t.Fatalf("got %+v, want only %s", list.Resources, resources.DirectoryURI)
	}

	templates, err := cs.ListResourceTemplates(ctx, nil)
	if err != nil {
		t.Fatalf("resources/templates/list: %v", err)
	}
	if len(templates.ResourceTemplates) != 3 {
		t.Fatalf("got %d templates, want 3", len(templates.ResourceTemplates))
	}

	for _, uri := range []string{
		resources.DirectoryURI,
		"customer://1001",
		"customer://1001/orders",
		"customer://1001/summary",
	} {
		t.Run(uri, func(t *testing.T) {
			res, err := cs.ReadResource(ctx, &sdk.ReadResourceParams{URI: uri})
			if err != nil {
				t.Fatalf("resources/read %s: %v", uri, err)
			}
			if len(res.Contents) != 1 {
				t.Fatalf("got %d contents, want 1", len(res.Contents))
			}
			c := res.Contents[0]
			if c.MIMEType != resources.MIMEJSON {
				t.Errorf("mime type = %q, want %q", c.MIMEType, resources.MIMEJSON)
			}
			var any map[string]any
			if err := json.Unmarshal([]byte(c.Text), &any); err != nil {
				t.Errorf("body is not a JSON object: %v", err)
			}
		})
	}
}

func TestReadUnknownResourceIsProtocolError(t *testing.T) {
	cs, _ := newSession(t)

	// resources/read has no in-band error channel, so a miss is a JSON-RPC error.
	_, err := cs.ReadResource(context.Background(), &sdk.ReadResourceParams{URI: "customer://9999"})
	if err == nil {
		t.Fatal("reading a missing customer resource succeeded")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "not found") {
		t.Errorf("error = %q, want it to say the resource was not found", err)
	}
}

func TestReadUnregisteredSchemeIsProtocolError(t *testing.T) {
	cs, _ := newSession(t)

	if _, err := cs.ReadResource(context.Background(), &sdk.ReadResourceParams{URI: "file:///etc/passwd"}); err == nil {
		t.Fatal("reading an unregistered URI succeeded; the SDK should refuse it")
	}
}

func TestPromptsListAndGet(t *testing.T) {
	cs, _ := newSession(t)
	ctx := context.Background()

	list, err := cs.ListPrompts(ctx, nil)
	if err != nil {
		t.Fatalf("prompts/list: %v", err)
	}
	if len(list.Prompts) != 2 {
		t.Fatalf("got %d prompts, want 2", len(list.Prompts))
	}

	res, err := cs.GetPrompt(ctx, &sdk.GetPromptParams{
		Name:      prompts.AnalysisPromptName,
		Arguments: map[string]string{"customer_id": "1001", "focus": prompts.FocusRevenue},
	})
	if err != nil {
		t.Fatalf("prompts/get: %v", err)
	}
	if len(res.Messages) != 1 {
		t.Fatalf("got %d messages, want 1", len(res.Messages))
	}
	tc, ok := res.Messages[0].Content.(*sdk.TextContent)
	if !ok {
		t.Fatalf("content is %T, want *mcp.TextContent", res.Messages[0].Content)
	}
	if !strings.Contains(tc.Text, "Acme Industries") {
		t.Error("prompt text does not embed the live customer record")
	}
}

func TestGetPromptWithBadArgumentIsProtocolError(t *testing.T) {
	cs, _ := newSession(t)

	_, err := cs.GetPrompt(context.Background(), &sdk.GetPromptParams{
		Name:      prompts.AnalysisPromptName,
		Arguments: map[string]string{"customer_id": "1001", "focus": "astrology"},
	})
	if err == nil {
		t.Fatal("prompts/get accepted an out-of-range focus")
	}
	if !strings.Contains(err.Error(), string(domain.CodeInvalidArgument)) {
		t.Errorf("error = %q, want the INVALID_ARGUMENT classification", err)
	}
}

func TestCompletionForPromptArguments(t *testing.T) {
	cs, _ := newSession(t)

	res, err := cs.Complete(context.Background(), &sdk.CompleteParams{
		Ref:      &sdk.CompleteReference{Type: "ref/prompt", Name: prompts.AnalysisPromptName},
		Argument: sdk.CompleteParamsArgument{Name: "focus", Value: "re"},
	})
	if err != nil {
		t.Fatalf("completion/complete: %v", err)
	}
	got := strings.Join(res.Completion.Values, ",")
	if want := "retention,revenue"; got != want {
		t.Errorf("completions = %q, want %q", got, want)
	}
}

func TestPingKeepsSessionAlive(t *testing.T) {
	cs, _ := newSession(t)

	if err := cs.Ping(context.Background(), nil); err != nil {
		t.Fatalf("ping: %v", err)
	}
}

func TestPanicInHandlerDoesNotKillSession(t *testing.T) {
	cs, be := newSession(t)
	ctx := context.Background()

	be.GetCustomerFn = func(context.Context, string, string) (domain.Customer, error) {
		panic("simulated defect in a tool handler")
	}

	// The recovery middleware turns the panic into an error response.
	if _, err := cs.CallTool(ctx, &sdk.CallToolParams{
		Name:      "get_customer",
		Arguments: map[string]any{"customer_id": "1001"},
	}); err == nil {
		t.Fatal("a panicking handler returned success")
	}

	// The session must survive, so a later call still works.
	be.GetCustomerFn = nil
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{
		Name:      "get_customer",
		Arguments: map[string]any{"customer_id": "1001"},
	})
	if err != nil {
		t.Fatalf("session did not survive the panic: %v", err)
	}
	if res.IsError {
		t.Fatalf("follow-up call failed: %s", contentText(res))
	}
}

func TestRequestCancellationPropagates(t *testing.T) {
	cs, be := newSession(t)

	released := make(chan struct{})
	be.GetCustomerFn = func(ctx context.Context, _, _ string) (domain.Customer, error) {
		// Block until the caller gives up, then report why.
		<-ctx.Done()
		close(released)
		return domain.Customer{}, ctx.Err()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	if _, err := cs.CallTool(ctx, &sdk.CallToolParams{
		Name:      "get_customer",
		Arguments: map[string]any{"customer_id": "1001"},
	}); err == nil {
		t.Fatal("a cancelled tool call returned success")
	}

	select {
	case <-released:
		// The handler observed the cancellation, which is the point: backend
		// work stops when the MCP request is abandoned.
	case <-time.After(5 * time.Second):
		t.Fatal("handler context was never cancelled; backend work would continue after the client gave up")
	}
}

// --- helpers ---

func contentText(res *sdk.CallToolResult) string {
	if res == nil {
		return ""
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*sdk.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func remarshal(t *testing.T, from any, to any) {
	t.Helper()
	data, err := json.Marshal(from)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := json.Unmarshal(data, to); err != nil {
		t.Fatalf("unmarshal into %T: %v\njson: %s", to, err, data)
	}
}

func asMap(t *testing.T, v any) map[string]any {
	t.Helper()
	var m map[string]any
	remarshal(t, v, &m)
	return m
}

func asStrings(t *testing.T, v any) []string {
	t.Helper()
	if v == nil {
		return nil
	}
	var s []string
	remarshal(t, v, &s)
	return s
}

type errShim string

func (e errShim) Error() string { return string(e) }
