package mcp

import (
	"context"
	"log/slog"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/verma29897/mcp-server/internal/prompts"
)

// registerPrompts binds the prompt descriptors to their handlers.
//
// Prompts are user-invoked templates, not model-invoked actions: the handlers
// only assemble text and live context, and never mutate anything.
func registerPrompts(srv *sdk.Server, p *prompts.Provider, logger *slog.Logger) {
	analysis := p.Analysis()
	srv.AddPrompt(analysis, wrapPrompt(logger, analysis.Name, p.HandleAnalysis))

	outreach := p.Outreach()
	srv.AddPrompt(outreach, wrapPrompt(logger, outreach.Name, p.HandleOutreach))
}

// wrapPrompt adds error encoding around a prompt handler.
func wrapPrompt(logger *slog.Logger, name string, fn sdk.PromptHandler) sdk.PromptHandler {
	return func(ctx context.Context, req *sdk.GetPromptRequest) (*sdk.GetPromptResult, error) {
		res, err := fn(ctx, req)
		if err != nil {
			return nil, promptError(ctx, logger, name, err)
		}
		return res, nil
	}
}

// completionHandler serves completion/complete for prompt arguments.
//
// It offers the closed value sets (focus, tone) so a client can present them as
// a picker. Customer IDs are deliberately not completed: enumerating the
// customer base into an autocomplete list is a data-exposure decision that
// should be explicit, not a side effect of typing.
func completionHandler(logger *slog.Logger) func(context.Context, *sdk.CompleteRequest) (*sdk.CompleteResult, error) {
	suggestions := map[string]map[string][]string{
		prompts.AnalysisPromptName: {
			"focus": {prompts.FocusOverview, prompts.FocusRetention, prompts.FocusRevenue, prompts.FocusSupport},
		},
		prompts.OutreachPromptName: {
			"tone": {prompts.ToneFormal, prompts.ToneFriendly, prompts.ToneUrgent},
		},
	}

	return func(_ context.Context, req *sdk.CompleteRequest) (*sdk.CompleteResult, error) {
		res := &sdk.CompleteResult{}
		if req.Params == nil || req.Params.Ref == nil || req.Params.Ref.Type != "ref/prompt" {
			return res, nil
		}

		values := suggestions[req.Params.Ref.Name][req.Params.Argument.Name]
		prefix := req.Params.Argument.Value
		for _, v := range values {
			if prefix == "" || hasPrefixFold(v, prefix) {
				res.Completion.Values = append(res.Completion.Values, v)
			}
		}
		res.Completion.Total = len(res.Completion.Values)
		logger.Debug("completion served",
			"prompt", req.Params.Ref.Name,
			"argument", req.Params.Argument.Name,
			"matches", res.Completion.Total,
		)
		return res, nil
	}
}

// hasPrefixFold reports whether s starts with prefix, ignoring ASCII case.
func hasPrefixFold(s, prefix string) bool {
	if len(prefix) > len(s) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if lowerASCII(s[i]) != lowerASCII(prefix[i]) {
			return false
		}
	}
	return true
}

func lowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}
