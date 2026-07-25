package agent

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/ozzyw/aobtd/internal/llm"
)

// TestStrategistOpenAILiveGrounding is an opt-in, low-cost semantic smoke.
// It exercises the real planner prompt, parser, and deterministic citation
// resolver without sending any request to a target application.
func TestStrategistOpenAILiveGrounding(t *testing.T) {
	if os.Getenv("AOBTD_OPENAI_STRATEGIST_SMOKE") != "1" {
		t.Skip("set AOBTD_OPENAI_STRATEGIST_SMOKE=1 to run live strategist smoke")
	}
	key := os.Getenv("OPENAI_API_KEY")
	if key == "" {
		key = os.Getenv("AOBTD_LLM_KEY")
	}
	if key == "" {
		t.Fatal("OPENAI_API_KEY or AOBTD_LLM_KEY is required")
	}
	provider, err := llm.NewProvider("openai", "", key, "gpt-4.1-mini")
	if err != nil {
		t.Fatal(err)
	}
	wm := &strategistWorldModel{
		ScanID: 1, Target: "https://app.example.test", Status: "running",
		EndpointCount: 12, ProfileCount: 2,
		Hosts: []wmHost{{Host: "app.example.test", Endpoints: 12}},
		InterestingEndpoints: []wmEndpointCard{
			{ID: "orders-profile", Method: "GET", Path: "/api/orders/{id}", Purpose: "Returns the authenticated customer's order", Auth: "required", HasInput: true, IsAPI: true},
			{ID: "catalog-profile", Method: "GET", Path: "/api/catalog/{id}", Purpose: "Public product catalog", Auth: "none", IsAPI: true},
		},
		OwnershipCandidates: []wmOwnershipCandidate{{
			Pattern: "/api/orders/{id}", Method: "GET", Resource: "order", Auth: "required",
			IDs: []string{"41", "42"}, EvidenceRefs: []string{"endpoint:orders-profile"},
			Reason: "Repeated authenticated object path with distinct order ids",
		}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	resp, err := provider.Complete(ctx, &llm.Request{
		SystemPrompt: strategistSystemPromptV2,
		Messages:     []llm.Message{{Role: "user", Content: buildStrategistPrompt(wm)}},
		Temperature:  0.1,
		MaxTokens:    1200,
		JSONMode:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	out, parseErrs := parseStrategistOutputV2(resp.Content)
	if out == nil {
		t.Fatalf("planner output did not parse: %v", parseErrs)
	}
	rejected := validateStrategistGrounding(out, wm)
	for _, hypothesis := range out.Hypotheses {
		if len(hypothesis.SupportingEvidence) == 0 {
			t.Fatalf("retained hypothesis has no resolved evidence: %+v", hypothesis)
		}
	}
	for _, directive := range out.Directives {
		if directive.Action != "stop" && len(directive.GroundedIn) == 0 {
			t.Fatalf("retained directive has no resolved evidence: %+v", directive)
		}
	}
	t.Logf("model=%s hypotheses=%d directives=%d parser_rejections=%d grounding_rejections=%d usage=%+v",
		llm.ResponseModel(resp, provider), len(out.Hypotheses), len(out.Directives), len(parseErrs), len(rejected), resp.Usage)
}
