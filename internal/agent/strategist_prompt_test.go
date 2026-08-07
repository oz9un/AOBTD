package agent

import (
	"strings"
	"testing"
	"time"
)

func TestStrategistPromptCannotSelfConfirmFindings(t *testing.T) {
	for _, required := range []string{
		"Planner prose, profile issue labels, HTTP 200 alone",
		"ownership-aware comparison",
		"planner, not a verifier",
		"PUBLIC-DATA GATE",
		"list/filter parameter named ids",
		"Require an observed 3xx Location",
	} {
		if !strings.Contains(strategistSystemPromptV2, required) {
			t.Fatalf("strategist prompt missing truthfulness rule %q", required)
		}
	}
}

func TestStrategistLocalCallTimeoutIsBounded(t *testing.T) {
	if strategistCallTimeout > 3*time.Minute {
		t.Fatalf("strategistCallTimeout = %s", strategistCallTimeout)
	}
}

func TestStrategistFinalReconPromptCapsOutput(t *testing.T) {
	prompt := buildStrategistCyclePrompt(&strategistWorldModel{
		ScanID: 1,
		Target: "https://example.test",
		Status: "running",
	}, "recon_final_model", true)
	for _, required := range []string{
		"Final Recon compression rules",
		"under 900 output tokens",
		"max 2 hypotheses",
		"max 1 directive",
		"directives: []",
	} {
		if !strings.Contains(prompt, required) {
			t.Fatalf("final recon prompt missing %q", required)
		}
	}
}

func TestStrategistFinalReconMiniMaxLimitIsCompact(t *testing.T) {
	if got := strategistMaxOutputTokens(&routingTestProvider{model: "MiniMax-M3"}, "recon_final_model"); got != 4096 {
		t.Fatalf("final MiniMax strategist output limit = %d, want 4096", got)
	}
	if got := strategistMaxOutputTokens(&routingTestProvider{model: "MiniMax-M3"}, "post_analysis"); got != 10240 {
		t.Fatalf("normal MiniMax strategist output limit = %d, want 10240", got)
	}
}
