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
	if strategistCallTimeout > 2*time.Minute {
		t.Fatalf("strategistCallTimeout = %s", strategistCallTimeout)
	}
}
