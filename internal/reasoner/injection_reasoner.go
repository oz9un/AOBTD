package reasoner

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/ozzyw/aobtd/internal/llm"
)

// InjectionReasoner — domain specialist for parameter injection.
// Demonstrates the Reasoner extension pattern: same interface as
// AuthReasoner, different system prompt, different evidence subset,
// same Executor handles dispatch. Adding more reasoners is this shape.
//
// The Executor currently only implements the `sqli_generic` technique
// as a stub (logged as "unimplemented"). Real SQLi primitive lives in
// the Verifier today via baseline-diff and Explorer directives;
// wiring Executor.execSQLi is a small follow-up.
type InjectionReasoner struct {
	llm    llm.Provider
	logger *slog.Logger
}

// NewInjectionReasoner constructs the injection reasoner.
func NewInjectionReasoner(provider llm.Provider, logger *slog.Logger) *InjectionReasoner {
	if logger == nil {
		logger = slog.Default()
	}
	return &InjectionReasoner{llm: provider, logger: logger}
}

// Name identifies the reasoner in logs / narrations.
func (r *InjectionReasoner) Name() string { return "InjectionReasoner" }

// Apply turns Evidence into injection-focused ProbePlans. Mirrors
// AuthReasoner.Apply exactly except for the system prompt and the
// fast-reject condition.
func (r *InjectionReasoner) Apply(ctx context.Context, ev Evidence) ([]ProbePlan, ReasonerUsage, error) {
	if r.llm == nil {
		return nil, ReasonerUsage{}, nil
	}
	// Fast-reject: no parameters observed anywhere.
	if len(ev.QueryEndpoints) == 0 && len(ev.APIEndpoints) == 0 {
		r.logger.Info("InjectionReasoner: no parameter surface, skipping",
			"scan_id", ev.ScanID)
		return nil, ReasonerUsage{}, nil
	}

	userMessage := r.buildUserMessage(ev)
	req := &llm.Request{
		SystemPrompt: injectionSystemPrompt,
		Messages: []llm.Message{
			{Role: "user", Content: userMessage},
		},
		Temperature: 0.2,
		MaxTokens:   llm.StructuredOutputTokenLimit(r.llm, 3500, 10240),
		JSONMode:    true,
	}

	resp, err := r.llm.Complete(ctx, req)
	if err != nil {
		return nil, reasonerUsageFromError(err, r.llm), fmt.Errorf("injection reasoner LLM: %w", err)
	}
	usage := ReasonerUsage{
		InputTokens:  resp.Usage.InputTokens,
		OutputTokens: resp.Usage.OutputTokens,
		ModelID:      llm.ResponseModel(resp, r.llm),
	}

	plans, err := parsePlans(resp.Content)
	if err != nil {
		r.logger.Warn("InjectionReasoner: plan parse failed",
			"err", err,
			"content_preview", truncate(resp.Content, 300))
		return nil, usage, fmt.Errorf("parse plans: %w", err)
	}

	validated := validatePlans(plans, ev)
	for i := range validated {
		validated[i].SourceReasoner = r.Name()
	}
	r.logger.Info("InjectionReasoner: emitted plans",
		"scan_id", ev.ScanID,
		"input_tokens", usage.InputTokens,
		"output_tokens", usage.OutputTokens,
		"raw_count", len(plans),
		"validated_count", len(validated),
		"raw_response_preview", truncate(resp.Content, 400))

	return validated, usage, nil
}

// buildUserMessage trims evidence to what injection reasoning needs:
// query / API endpoints and their parameter names. No need for emails
// or JWT samples here.
func (r *InjectionReasoner) buildUserMessage(ev Evidence) string {
	type endpointLite struct {
		URL    string   `json:"url"`
		Method string   `json:"method"`
		Params []string `json:"params,omitempty"`
	}
	toLite := func(eps []DiscoveredEndpoint) []endpointLite {
		out := make([]endpointLite, 0, len(eps))
		for _, e := range eps {
			out = append(out, endpointLite{
				URL:    e.URL,
				Method: e.Method,
				Params: e.Params,
			})
		}
		return out
	}
	doc := map[string]any{
		"target":            ev.Target,
		"query_endpoints":   toLite(ev.QueryEndpoints),
		"api_endpoints":     toLite(ev.APIEndpoints),
		"existing_findings": summariseFindings(ev.Findings),
	}
	if ev.Hypothesis != nil {
		doc["strategist_hypothesis"] = ev.Hypothesis.Statement
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	return string(b)
}
