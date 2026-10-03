// Package prompts_test covers the prompt layer: argument handling, live
// context assembly and the guard rails baked into the prompt text.
package prompts_test

import (
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/verma29897/mcp-server/internal/domain"
	"github.com/verma29897/mcp-server/internal/prompts"
	"github.com/verma29897/mcp-server/tests/testutil"
)

func newProvider() (*prompts.Provider, *testutil.FakeBackend) {
	svc, be := testutil.NewService()
	return prompts.NewProvider(svc), be
}

// get invokes a prompt handler with the given arguments.
func get(t *testing.T, fn sdk.PromptHandler, name string, args map[string]string) (*sdk.GetPromptResult, error) {
	t.Helper()
	return fn(testutil.Context(), &sdk.GetPromptRequest{
		Params: &sdk.GetPromptParams{Name: name, Arguments: args},
	})
}

// text returns the single user message of a prompt result.
func text(t *testing.T, res *sdk.GetPromptResult) string {
	t.Helper()
	if res == nil || len(res.Messages) != 1 {
		t.Fatalf("got %v, want exactly one message", res)
	}
	m := res.Messages[0]
	if m.Role != "user" {
		t.Errorf("role = %q, want user", m.Role)
	}
	tc, ok := m.Content.(*sdk.TextContent)
	if !ok {
		t.Fatalf("content is %T, want *mcp.TextContent", m.Content)
	}
	return tc.Text
}

func TestDescriptors(t *testing.T) {
	p, _ := newProvider()

	for _, pr := range []*sdk.Prompt{p.Analysis(), p.Outreach()} {
		if pr.Name == "" || pr.Description == "" {
			t.Errorf("prompt %+v is missing a name or description", pr)
		}
		var required int
		for _, a := range pr.Arguments {
			if a.Description == "" {
				t.Errorf("prompt %q argument %q has no description", pr.Name, a.Name)
			}
			if a.Required {
				required++
			}
		}
		if required == 0 {
			t.Errorf("prompt %q declares no required argument", pr.Name)
		}
	}
}

func TestAnalysisEmbedsLiveContext(t *testing.T) {
	p, be := newProvider()

	res, err := get(t, p.HandleAnalysis, prompts.AnalysisPromptName, map[string]string{"customer_id": "1001"})
	if err != nil {
		t.Fatalf("HandleAnalysis: %v", err)
	}

	body := text(t, res)
	for _, want := range []string{"Acme Industries", "lifetime_spend", "order_count"} {
		if !strings.Contains(body, want) {
			t.Errorf("prompt text is missing %q", want)
		}
	}
	// The default focus must be reflected in the description.
	if !strings.Contains(res.Description, prompts.FocusOverview) {
		t.Errorf("description = %q, want it to mention the %q focus", res.Description, prompts.FocusOverview)
	}
	// Building the prompt reads data; it must not write any.
	for _, method := range []string{"UpdateCustomer", "DeleteCustomer", "SendNotification"} {
		if n := be.Calls(method); n != 0 {
			t.Errorf("prompt assembly called %s %d times; prompts must not mutate state", method, n)
		}
	}
}

func TestAnalysisFocusVariants(t *testing.T) {
	p, _ := newProvider()

	for _, focus := range []string{prompts.FocusOverview, prompts.FocusRetention, prompts.FocusRevenue, prompts.FocusSupport} {
		t.Run(focus, func(t *testing.T) {
			res, err := get(t, p.HandleAnalysis, prompts.AnalysisPromptName, map[string]string{
				"customer_id": "1001",
				"focus":       focus,
			})
			if err != nil {
				t.Fatalf("HandleAnalysis(%s): %v", focus, err)
			}
			if !strings.Contains(res.Description, focus) {
				t.Errorf("description = %q, want it to mention focus %q", res.Description, focus)
			}
		})
	}
}

func TestAnalysisRejectsUnknownFocus(t *testing.T) {
	p, _ := newProvider()

	_, err := get(t, p.HandleAnalysis, prompts.AnalysisPromptName, map[string]string{
		"customer_id": "1001",
		"focus":       "astrology",
	})
	de := requireDomainError(t, err)
	if de.Field != "focus" {
		t.Fatalf("field = %q, want %q", de.Field, "focus")
	}
}

func TestAnalysisRequiresCustomerID(t *testing.T) {
	p, _ := newProvider()

	_, err := get(t, p.HandleAnalysis, prompts.AnalysisPromptName, map[string]string{"focus": prompts.FocusRevenue})
	de := requireDomainError(t, err)
	if de.Code != domain.CodeInvalidArgument || de.Field != "customer_id" {
		t.Fatalf("got %s/%s, want INVALID_ARGUMENT/customer_id", de.Code, de.Field)
	}
}

func TestAnalysisUnknownCustomer(t *testing.T) {
	p, _ := newProvider()

	_, err := get(t, p.HandleAnalysis, prompts.AnalysisPromptName, map[string]string{"customer_id": "9999"})
	de := requireDomainError(t, err)
	if de.Code != domain.CodeNotFound {
		t.Fatalf("code = %s, want %s", de.Code, domain.CodeNotFound)
	}
}

func TestOutreachDoesNotSend(t *testing.T) {
	p, be := newProvider()

	res, err := get(t, p.HandleOutreach, prompts.OutreachPromptName, map[string]string{
		"customer_id": "1002",
		"topic":       "renewal reminder",
		"tone":        prompts.ToneFriendly,
	})
	if err != nil {
		t.Fatalf("HandleOutreach: %v", err)
	}

	body := text(t, res)
	if !strings.Contains(body, "Bluepeak Labs") {
		t.Error("prompt text does not include the customer name")
	}
	if !strings.Contains(body, "Do not call send_customer_notification") {
		t.Error("the draft prompt must tell the model not to send the message itself")
	}
	if n := be.Calls("SendNotification"); n != 0 {
		t.Fatalf("drafting sent %d messages; it must send none", n)
	}
}

func TestOutreachRequiresTopic(t *testing.T) {
	p, _ := newProvider()

	_, err := get(t, p.HandleOutreach, prompts.OutreachPromptName, map[string]string{"customer_id": "1002"})
	de := requireDomainError(t, err)
	if de.Field != "topic" {
		t.Fatalf("field = %q, want %q", de.Field, "topic")
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
