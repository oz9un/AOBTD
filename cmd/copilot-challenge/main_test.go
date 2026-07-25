package main

import (
	"testing"

	"github.com/ozzyw/aobtd/internal/ask"
)

func TestAssessRequiresSuccessfulEvidenceAndExactNumbers(t *testing.T) {
	item := challenge{
		ID: "strict", RequireQuery: true, MustNumbers: []string{"7"},
		RefKinds: []string{"finding"}, ForbiddenRefs: []string{"finding:999999"},
	}
	failed := assess(item, &ask.Result{
		Answer:   "There are 247 analyzed rows.",
		Steps:    []ask.Step{{SQL: "SELECT broken", Error: "no such column"}},
		Evidence: []ask.EvidenceRef{{Kind: "finding", ID: "999999"}},
	}, nil)
	if failed.Passed == failed.Total {
		t.Fatalf("weak result unexpectedly passed: %+v", failed.Checks)
	}

	passed := assess(item, &ask.Result{
		Answer: "There are exactly 7 hosts.",
		Steps: []ask.Step{{
			SQL: "SELECT COUNT(*) FROM traffic WHERE scan_id = ?1", RowNum: 1,
		}},
		Evidence: []ask.EvidenceRef{{Kind: "finding", ID: "7"}},
	}, nil)
	if passed.Passed != passed.Total {
		t.Fatalf("grounded result failed: %+v", passed.Checks)
	}
}

func TestAssessRejectsForbiddenSemanticPattern(t *testing.T) {
	item := challenge{ID: "semantic", MustNotRegex: []string{`(?s)default.{0,80}credentials\s*:\s*["']?omit`}}
	failed := assess(item, &ask.Result{Answer: `The default fetch uses credentials: "omit".`}, nil)
	if failed.Passed == failed.Total {
		t.Fatalf("semantic falsehood passed: %+v", failed.Checks)
	}
	passed := assess(item, &ask.Result{Answer: `The default fetch uses credentials: "same-origin".`}, nil)
	if passed.Passed != passed.Total {
		t.Fatalf("correct semantics failed: %+v", passed.Checks)
	}
}

func TestCORSChallengeRejectsObservedBodyScopeOverreach(t *testing.T) {
	var item challenge
	for _, candidate := range challengeSuite() {
		if candidate.ID == "cors_impact_calibration" {
			item = candidate
			break
		}
	}
	bad := `Cookies may be sent, while JavaScript readability requires CORS permission. The queried response contains enabled=false, so it is a public global feature flag, harmless on this endpoint, and identical to what anyone gets without authentication.`
	result := assess(item, &ask.Result{
		Answer: bad,
		Steps:  []ask.Step{{SQL: "SELECT response_body FROM traffic WHERE scan_id=?1", RowNum: 1}},
	}, nil)
	matchedFailure := false
	for _, check := range result.Checks {
		if check.Name == "forbidden semantic pattern" && !check.Passed {
			matchedFailure = true
		}
	}
	if !matchedFailure {
		t.Fatalf("observed-body scope overreach escaped CORS patterns: %+v", result.Checks)
	}
}

func TestAssessConditionsBodyClaimsOnSuccessfulBodyQuery(t *testing.T) {
	item := challenge{ID: "body", BodyEvidenceAware: true}
	grounded := assess(item, &ask.Result{
		Answer: "The observed JSON contains enabled=false.",
		Steps:  []ask.Step{{SQL: "SELECT response_body FROM traffic WHERE scan_id = ?1", RowNum: 1}},
	}, nil)
	if grounded.Passed != grounded.Total {
		t.Fatalf("queried body claim failed: %+v", grounded.Checks)
	}
	abstained := assess(item, &ask.Result{Answer: "The body was not queried, so its contents are unknown."}, nil)
	if abstained.Passed != abstained.Total {
		t.Fatalf("body abstention failed: %+v", abstained.Checks)
	}
	ungrounded := assess(item, &ask.Result{Answer: "The path suggests a feature flag."}, nil)
	if ungrounded.Passed == ungrounded.Total {
		t.Fatalf("unqueried body inference passed: %+v", ungrounded.Checks)
	}
}
