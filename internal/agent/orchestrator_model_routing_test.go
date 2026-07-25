package agent

import (
	"context"
	"testing"

	"github.com/ozzyw/aobtd/internal/llm"
)

type routingTestProvider struct{ model string }

func (p *routingTestProvider) Complete(context.Context, *llm.Request) (*llm.Response, error) {
	return &llm.Response{Content: `{}`}, nil
}
func (p *routingTestProvider) CountTokens(string) int { return 1 }
func (p *routingTestProvider) ModelInfo() llm.ModelInfo {
	return llm.ModelInfo{Name: p.model, SupportsJSON: true}
}
func (p *routingTestProvider) Name() string { return "test" }

func TestNewOrchestratorRoutesReasoningAndStrategistModels(t *testing.T) {
	scout := &routingTestProvider{model: "scout"}
	deep := &routingTestProvider{model: "deep"}
	o := NewOrchestrator(nil, nil, OrchestratorConfig{
		Target:            "https://example.test",
		Provider:          scout,
		ReasoningProvider: deep,
	}, nil)

	if o.provider != scout {
		t.Fatal("scout provider was not retained")
	}
	if o.reasoningProvider != deep {
		t.Fatal("reasoning provider was not routed")
	}
	if o.strategistProvider != scout {
		t.Fatal("strategist should default to scout provider unless explicitly configured")
	}
}

func TestNewOrchestratorHonorsExplicitStrategistProvider(t *testing.T) {
	scout := &routingTestProvider{model: "scout"}
	deep := &routingTestProvider{model: "deep"}
	strategist := &routingTestProvider{model: "strategist"}
	o := NewOrchestrator(nil, nil, OrchestratorConfig{
		Target: "https://example.test", Provider: scout,
		ReasoningProvider: deep, StrategistProvider: strategist,
	}, nil)
	if o.strategistProvider != strategist {
		t.Fatal("explicit strategist provider was not routed")
	}
}

func TestNewOrchestratorFallsBackToScoutForAllRoles(t *testing.T) {
	scout := &routingTestProvider{model: "scout"}
	o := NewOrchestrator(nil, nil, OrchestratorConfig{
		Target:   "https://example.test",
		Provider: scout,
	}, nil)

	if o.reasoningProvider != scout || o.strategistProvider != scout {
		t.Fatal("omitted role providers should fall back to scout")
	}
}
