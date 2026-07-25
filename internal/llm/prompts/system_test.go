package prompts

import (
	"strings"
	"testing"
)

func TestAppSummaryPromptRequiresCompactCompleteJSON(t *testing.T) {
	for _, requirement := range []string{
		"hard maximums",
		"roles: 3",
		"objects: 5",
		"workflows: 3",
		"ownership_boundaries: 4",
		"unknowns: 5",
		"under 12 words",
		"Never exceed a limit",
		"Never omit evidence",
		"valid read-only workflow",
		"one-step journey is acceptable",
		"package_registry",
		"geospatial",
		"not a vulnerability verdict",
		"Lead with the target's business purpose",
		"do not spend summary words on scanner behavior",
		"Order unknowns by missing core journey",
	} {
		if !strings.Contains(AppSummaryPrompt, requirement) {
			t.Fatalf("AppSummaryPrompt missing compact-output requirement %q", requirement)
		}
	}
}

func TestAnalyzerPromptRequiresEvidenceBeforeClaims(t *testing.T) {
	for _, required := range []string{
		"TESTABLE HYPOTHESIS",
		"CONFIRMED ISSUE",
		"two identities",
		"Never infer absence of rate limiting from a single request",
		"Bearer-token APIs are not automatically CSRF-vulnerable",
		"PUBLIC-DATA GATE",
		"do not require per-user ownership validation",
		"If no such boundary exists, keep issues empty",
		"FRAMEWORK-SERIALIZATION GATE",
		"framework transport evidence—not debug-data",
	} {
		if !strings.Contains(AnalyzerSystemPrompt, required) {
			t.Fatalf("AnalyzerSystemPrompt missing grounding rule %q", required)
		}
	}
}

func TestNavigatorPromptUsesRepresentativeUISampling(t *testing.T) {
	for _, required := range []string{
		"representative UI sampling",
		"workflow or page type",
		"Do not click every product, article, course, card",
		"destructive state changes",
	} {
		if !strings.Contains(NavigatorSystemPrompt, required) {
			t.Fatalf("NavigatorSystemPrompt missing UI-tour rule %q", required)
		}
	}
}
