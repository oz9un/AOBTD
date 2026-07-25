package agent

import (
	"strings"
	"testing"

	"github.com/ozzyw/aobtd/pkg/types"
)

func TestOwnershipCandidatesFromProfilesDetectsPairedObjectResources(t *testing.T) {
	profs := []types.PageProfile{
		{
			ID:           "basket-a",
			Method:       "GET",
			URL:          "http://127.0.0.1:3000/rest/basket/7",
			AuthRequired: "required",
		},
		{
			ID:           "basket-b",
			Method:       "GET",
			URL:          "http://127.0.0.1:3000/rest/basket/8",
			AuthRequired: "required",
		},
		{
			ID:     "asset",
			Method: "GET",
			URL:    "http://127.0.0.1:3000/assets/1",
		},
	}

	got := ownershipCandidatesFromProfiles(profs, 8)
	if len(got) != 1 {
		t.Fatalf("candidates len = %d, want 1: %+v", len(got), got)
	}
	c := got[0]
	if c.Method != "GET" || c.Pattern != "/rest/basket/{id}" || c.Resource != "basket" {
		t.Fatalf("candidate = %+v", c)
	}
	if strings.Join(c.IDs, ",") != "7,8" {
		t.Fatalf("ids = %v, want [7 8]", c.IDs)
	}
	for _, want := range []string{"endpoint:basket-a", "endpoint:basket-b"} {
		if !containsString(c.EvidenceRefs, want) {
			t.Fatalf("evidence refs missing %q: %+v", want, c.EvidenceRefs)
		}
	}
	if !strings.Contains(c.Reason, "ownership-aware") {
		t.Fatalf("reason does not guide ownership testing: %q", c.Reason)
	}
}

func TestBuildStrategistPromptIncludesOwnershipCandidates(t *testing.T) {
	prompt := buildStrategistPrompt(&strategistWorldModel{
		ScanID:        1,
		Target:        "http://127.0.0.1:3000",
		Status:        "running",
		EndpointCount: 12,
		OwnershipCandidates: []wmOwnershipCandidate{{
			Method:       "GET",
			Pattern:      "/rest/basket/{id}",
			Resource:     "basket",
			Auth:         "required",
			IDs:          []string{"7", "8"},
			Examples:     []string{"GET /rest/basket/7", "GET /rest/basket/8"},
			EvidenceRefs: []string{"endpoint:basket-a", "endpoint:basket-b"},
			Reason:       "multiple basket object identifiers observed on the same resource pattern; prioritize ownership-aware A/B authorization testing over blind id sweeps",
		}},
	})

	for _, want := range []string{
		"Ownership / BOLA candidate resources",
		"`GET /rest/basket/{id}`",
		"Treat them as authorization hypotheses, not confirmed findings",
		"grounding: endpoint:basket-a, endpoint:basket-b",
		"ownership-aware A/B authorization testing",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("prompt missing %q:\n%s", want, prompt)
		}
	}
}

func containsString(list []string, want string) bool {
	for _, got := range list {
		if got == want {
			return true
		}
	}
	return false
}
