package agent

import (
	"testing"

	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/internal/llm"
)

func TestNormalizeAppTypeFromEvidenceUpgradesAPIService(t *testing.T) {
	got := normalizeAppTypeFromEvidence(
		"other",
		"crAPI (Completely Ridiculous API) exposes JWT-authenticated user and vehicle functionality.",
		"Observed profiles include GET /identity/api/auth/login, /api/v1/vehicle, bearer token auth, and application/json responses.",
	)
	if got != "api_service" {
		t.Fatalf("normalizeAppTypeFromEvidence()=%q, want api_service", got)
	}
}

func TestNormalizeAppTypeFromEvidenceKeepsSpecificType(t *testing.T) {
	got := normalizeAppTypeFromEvidence(
		"e-commerce",
		"Storefront with products and checkout.",
		"Observed product detail and basket pages.",
	)
	if got != "e-commerce" {
		t.Fatalf("normalizeAppTypeFromEvidence()=%q, want e-commerce", got)
	}
}

func TestSalvageAppSummaryFromPartialJSON(t *testing.T) {
	body := `{
	  "app_type": "other",
	  "summary": "crAPI (Completely Ridiculous API) exposes JWT-authenticated vehicle and workshop APIs.",
	  "roles": [{"id":"user","name":"User"`
	gotType, gotSummary, ok := salvageAppSummaryFromPartial(body, "Observed /identity/api/v2/user/dashboard and bearer auth.")
	if !ok {
		t.Fatal("expected partial app summary to be salvaged")
	}
	if gotType != "api_service" {
		t.Fatalf("app type = %q, want api_service", gotType)
	}
	if gotSummary == "" || gotSummary[:5] != "crAPI" {
		t.Fatalf("summary not salvaged: %q", gotSummary)
	}
}

func TestPartialJSONStringFieldHandlesEscapes(t *testing.T) {
	body := `{"summary":"API \"training\" app with JWT auth","roles":[`
	if got := partialJSONStringField(body, "summary"); got != `API "training" app with JWT auth` {
		t.Fatalf("partialJSONStringField()=%q", got)
	}
}

func TestSalvageAppSynthesisRecoversCompleteArraysBeforeTruncation(t *testing.T) {
	body := `{
	  "app_type":"e-commerce",
	  "summary":"Observed storefront with grounded actors and objects.",
	  "roles":[{"id":"visitor","name":"Visitor","description":"Reads [public] pages","evidence":[{"kind":"endpoint","ref":"GET /","detail":"Text with an escaped quote: \"ok\""}]}],
	  "objects":[{"id":"product","name":"Product","evidence":[{"kind":"endpoint","ref":"GET /products"}]}],
	  "workflows":[{"id":"browse","name":"Browse","steps":[{"id":"list","page_ids":["GET /products"]}]}],
	  "ownership_boundaries":[],
	  "unknowns":[{"id":"truncated","question":"What happens next?"`

	got, ok := salvageAppSynthesisFromPartial(body, "Observed product pages")
	if !ok {
		t.Fatal("expected synthesis prefix to be salvaged")
	}
	if len(got.Roles) != 1 || got.Roles[0].ID != "visitor" {
		t.Fatalf("roles = %+v", got.Roles)
	}
	if len(got.Objects) != 1 || got.Objects[0].ID != "product" {
		t.Fatalf("objects = %+v", got.Objects)
	}
	if len(got.Workflows) != 1 || got.Workflows[0].ID != "browse" {
		t.Fatalf("workflows = %+v", got.Workflows)
	}
	if got.OwnershipBoundaries == nil || len(got.OwnershipBoundaries) != 0 {
		t.Fatalf("complete empty boundaries array not recovered: %+v", got.OwnershipBoundaries)
	}
	if got.Unknowns != nil {
		t.Fatalf("truncated unknowns must not be accepted: %+v", got.Unknowns)
	}
	var roles []extract.ReconRole
	if !partialJSONArrayField(body, "roles", &roles) || len(roles) != 1 {
		t.Fatalf("direct partial array recovery failed: %+v", roles)
	}
}

func TestAnalyzerReservesOutputForTerminalAppSummary(t *testing.T) {
	budget := llm.NewBudget(0, appSummaryMaxTokens+2048-1, 0, nil)
	analyzer := &AnalyzerAgent{provider: fixedTokenProvider{}, budget: budget}
	reservation := analyzer.reserveAppSummaryOutput()
	if reservation == nil {
		t.Fatal("terminal app-summary output was not reserved")
	}
	if competing, ok := budget.Reserve("fixed-token-test", 0, 2048); ok {
		competing.Release()
		t.Fatal("endpoint call consumed output headroom reserved for app summary")
	}
	reservation.Release()
	if competing, ok := budget.Reserve("fixed-token-test", 0, 2048); !ok {
		t.Fatal("released app-summary headroom was not reusable")
	} else {
		competing.Release()
	}
}
