package extract

import (
	"strings"
	"testing"

	"github.com/ozzyw/aobtd/pkg/types"
)

func TestRefreshPagePurposeCardsGroundsProfiles(t *testing.T) {
	u := NewAppUnderstanding()
	u.RefreshPagePurposeCards([]types.PageProfile{{
		ID: "POST /api/orders", URL: "https://shop.test/api/orders", Method: "POST",
		Purpose: "Create an order", AuthRequired: "session", Confidence: .82,
		Inputs: []types.Input{{Name: "basketId"}}, Behaviors: []string{"creates order"},
	}})
	if len(u.Recon.Pages) != 1 {
		t.Fatalf("pages = %d, want 1", len(u.Recon.Pages))
	}
	p := u.Recon.Pages[0]
	if p.ID != "POST /api/orders" || p.Area != "transaction" || p.Inputs[0] != "basketId" {
		t.Fatalf("unexpected purpose card: %+v", p)
	}
	if len(p.Evidence) != 1 || p.Evidence[0].Ref != p.ID {
		t.Fatalf("page evidence = %+v", p.Evidence)
	}
}

func TestNormalizeReconModelDropsDanglingReferencesAndCrossLinks(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Pages = []PagePurposeCard{{ID: "POST /orders", Method: "POST", Purpose: "Create order"}}
	u.Recon.Roles = []ReconRole{{ID: "customer", Name: "Customer", Confidence: 2}}
	u.Recon.Objects = []BusinessObject{{ID: "order", Name: "Order", Confidence: .8, Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "POST /orders"}}}}
	u.Recon.Workflows = []BusinessWorkflow{{ID: "checkout", Name: "Checkout", Confidence: .7, Steps: []WorkflowStep{{
		ID: "place", Label: "Place order", PageIDs: []string{"POST /orders", "GET /invented"},
		RoleIDs: []string{"customer", "admin"}, ObjectIDs: []string{"order", "phantom"}, StateChange: true,
	}}}}
	u.Recon.OwnershipBoundaries = []OwnershipBoundary{
		{ID: "order-owner", ObjectID: "order", OwnerRoleID: "customer", Rule: "customers access their own orders", EnforcedAt: []string{"POST /orders", "GET /invented"}},
		{ID: "bad", ObjectID: "phantom", Rule: "invented"},
	}
	u.NormalizeReconModel()

	step := u.Recon.Workflows[0].Steps[0]
	if len(step.PageIDs) != 1 || len(step.RoleIDs) != 1 || len(step.ObjectIDs) != 1 {
		t.Fatalf("dangling references survived: %+v", step)
	}
	if !step.StateChange {
		t.Fatal("POST-backed workflow step lost its state-change marker")
	}
	if got := u.Recon.Pages[0].ObjectIDs; len(got) != 1 || got[0] != "order" {
		t.Fatalf("page object cross-link = %v", got)
	}
	if len(u.Recon.OwnershipBoundaries) != 1 || len(u.Recon.OwnershipBoundaries[0].EnforcedAt) != 1 {
		t.Fatalf("boundaries = %+v", u.Recon.OwnershipBoundaries)
	}
	if u.Recon.OwnershipBoundaries[0].Confidence != 0 {
		t.Fatalf("zero-confidence ownership hypothesis unexpectedly changed: %+v", u.Recon.OwnershipBoundaries[0])
	}
	if u.Recon.Roles[0].Confidence != 1 {
		t.Fatalf("confidence not clamped: %v", u.Recon.Roles[0].Confidence)
	}
}

func TestReconJSONRoundTripAndLLMRendering(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Pages = []PagePurposeCard{{ID: "GET /invoices", Purpose: "List invoices", Confidence: .8}}
	u.Recon.Objects = []BusinessObject{{ID: "invoice", Name: "Invoice", Identifiers: []string{"invoice_id"}, Confidence: .75}}
	u.Recon.Unknowns = []ReconUnknown{{ID: "tenant", Question: "Is tenant isolation enforced?", SuggestedAction: "compare two accounts", Priority: 9}}
	raw := u.ReconJSON()
	reloaded := NewAppUnderstanding()
	reloaded.LoadReconJSON(raw)
	if len(reloaded.Recon.Objects) != 1 || reloaded.Recon.Metrics.OpenQuestions != 1 {
		t.Fatalf("round trip = %+v", reloaded.Recon)
	}
	rendered := reloaded.RenderReconForLLM()
	if !strings.Contains(rendered, "invoice") || !strings.Contains(rendered, "tenant isolation") {
		t.Fatalf("render missing semantic context: %s", rendered)
	}
	if strings.Contains(rendered, "GET /invoices") {
		t.Fatalf("compact recon context unexpectedly includes page inventory: %s", rendered)
	}
	evidence := reloaded.RenderReconEvidenceForLLM()
	if !strings.Contains(evidence, "GET /invoices") || !strings.Contains(evidence, "List invoices") {
		t.Fatalf("evidence context missing purpose card: %s", evidence)
	}
}

func TestNormalizeReconModelSynthesizesGroundedReadOnlyJourney(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Pages = []PagePurposeCard{
		{ID: "GET /cdn-cgi/challenge", Method: "GET", URL: "https://portal.test/cdn-cgi/challenge", Purpose: "Challenge helper", Confidence: .9},
		{ID: "GET /services", Method: "GET", URL: "https://portal.test/services", Purpose: "Browse government services", Area: "services", Confidence: .85, ObjectIDs: []string{"service"}},
	}
	u.NormalizeReconModel()
	if len(u.Recon.Workflows) != 1 {
		t.Fatalf("fallback workflows = %+v", u.Recon.Workflows)
	}
	workflow := u.Recon.Workflows[0]
	if workflow.ID != "observed_read_journey" || workflow.Steps[0].PageIDs[0] != "GET /services" || workflow.Confidence != .7 {
		t.Fatalf("fallback workflow = %+v", workflow)
	}
}

func TestNormalizeReconModelDoesNotTurnRateLimitPageIntoJourney(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Pages = []PagePurposeCard{{ID: "GET /", Method: "GET", URL: "https://map.test/", Purpose: "429 rate limited error page", Confidence: .8}}
	u.NormalizeReconModel()
	if len(u.Recon.Workflows) != 0 {
		t.Fatalf("rate-limit page became a journey: %+v", u.Recon.Workflows)
	}
}

func TestNormalizeReconModelEnforcesGroundingInvariants(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Pages = []PagePurposeCard{
		{ID: "GET /search", Method: "GET", Purpose: "Search"},
		{ID: "GET /cards", Method: "GET", Purpose: "List cards"},
	}
	u.Recon.Roles = []ReconRole{{ID: "user", Name: "User", Confidence: .8}}
	u.Recon.Objects = []BusinessObject{{ID: "card", Name: "Card", Confidence: .9, Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "GET /cards"}}}}
	u.Recon.Workflows = []BusinessWorkflow{{ID: "browse", Name: "Browse", Confidence: .8, Steps: []WorkflowStep{{
		ID: "search", Label: "Search", PageIDs: []string{"GET /search"}, ObjectIDs: []string{"card"}, StateChange: true,
	}}}}
	u.Recon.OwnershipBoundaries = []OwnershipBoundary{{
		ID: "card-owner", ObjectID: "card", OwnerRoleID: "user", Rule: "users see their own cards", Confidence: .99,
		Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "GET /cards"}},
	}}
	u.NormalizeReconModel()
	step := u.Recon.Workflows[0].Steps[0]
	if step.StateChange {
		t.Fatal("GET-only step remained state-changing")
	}
	if len(step.ObjectIDs) != 0 {
		t.Fatalf("object without shared page evidence remained linked: %v", step.ObjectIDs)
	}
	if got := u.Recon.OwnershipBoundaries[0].Confidence; got != .45 {
		t.Fatalf("unverified owner-specific confidence = %.2f, want .45", got)
	}
}

func TestNormalizeReconModelReducesGETOnlyMutationWorkflowToEntry(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Pages = []PagePurposeCard{
		{ID: "GET /articles", Method: "GET", URL: "https://wiki.test/articles", Purpose: "Browse articles", Confidence: .9},
		{ID: "GET /edit", Method: "GET", URL: "https://wiki.test/edit", Purpose: "Render edit form", Confidence: .9},
	}
	u.Recon.Workflows = []BusinessWorkflow{
		{ID: "browse", Name: "Browse articles", Steps: []WorkflowStep{{ID: "list", Label: "Read articles", PageIDs: []string{"GET /articles"}}}},
		{ID: "edit", Name: "Edit article workflow", Description: "Authenticated editor submits a page edit", Steps: []WorkflowStep{
			{ID: "open", Label: "Open edit form", PageIDs: []string{"GET /edit"}},
			{ID: "submit_edit", Label: "Submit edit", PageIDs: []string{"GET /edit"}},
		}},
	}
	u.NormalizeReconModel()
	if len(u.Recon.Workflows) != 2 || u.Recon.Workflows[0].ID != "browse" || u.Recon.Workflows[1].Name != "Open edit form journey" {
		t.Fatalf("GET-only mutation workflow was not reduced to its observed entry: %+v", u.Recon.Workflows)
	}
	foundGap := false
	for _, unknown := range u.Recon.Unknowns {
		if unknown.ID == "workflow_transition_evidence_gap" {
			foundGap = true
		}
	}
	if !foundGap {
		t.Fatalf("dropped transition did not become an explicit gap: %+v", u.Recon.Unknowns)
	}
}

func TestNormalizeReconModelResolvesUniqueJSONSafePageAliases(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Pages = []PagePurposeCard{{
		ID: "GET /api/Challenges/", Method: "GET", Purpose: "List challenges", Confidence: .9,
	}}
	u.Recon.Roles = []ReconRole{{
		ID: "participant", Name: "Participant", Confidence: .8,
		Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "get_api_Challenges_"}},
	}}
	u.Recon.Objects = []BusinessObject{{
		ID: "challenge", Name: "Challenge", Confidence: .8,
		Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "get_api_Challenges_"}},
	}}
	u.Recon.Workflows = []BusinessWorkflow{{
		ID: "browse", Name: "Browse challenges", Confidence: .8,
		Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "get_api_Challenges_"}},
		Steps:    []WorkflowStep{{ID: "list", PageIDs: []string{"get_api_Challenges_"}, RoleIDs: []string{"participant"}, ObjectIDs: []string{"challenge"}}},
	}}
	u.Recon.OwnershipBoundaries = []OwnershipBoundary{{
		ID: "challenge-access", ObjectID: "challenge", OwnerRoleID: "participant", Rule: "Progress belongs to the participant",
		EnforcedAt: []string{"get_api_Challenges_"}, Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "get_api_Challenges_"}},
	}}

	u.NormalizeReconModel()

	const exact = "GET /api/Challenges/"
	if got := u.Recon.Roles[0].Evidence[0].Ref; got != exact {
		t.Fatalf("role evidence ref = %q, want %q", got, exact)
	}
	if got := u.Recon.Objects[0].Evidence[0].Ref; got != exact {
		t.Fatalf("object evidence ref = %q, want %q", got, exact)
	}
	if len(u.Recon.Workflows) != 1 || u.Recon.Workflows[0].Steps[0].PageIDs[0] != exact {
		t.Fatalf("workflow aliases were not grounded: %+v", u.Recon.Workflows)
	}
	if len(u.Recon.OwnershipBoundaries) != 1 || u.Recon.OwnershipBoundaries[0].EnforcedAt[0] != exact {
		t.Fatalf("boundary aliases were not grounded: %+v", u.Recon.OwnershipBoundaries)
	}
}

func TestNormalizeReconModelDowngradesReadOnlyPurchaseStoryToEntryJourney(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Pages = []PagePurposeCard{{ID: "GET /products", Method: "GET", URL: "https://shop.test/products", Purpose: "List products", Confidence: .8}}
	u.Recon.Roles = []ReconRole{{ID: "user", Name: "User", Confidence: .8}}
	u.Recon.Workflows = []BusinessWorkflow{{ID: "purchase", Name: "Product Purchase", Description: "Complete checkout", Confidence: .9, Steps: []WorkflowStep{{
		ID: "browse", Label: "Browse", PageIDs: []string{"/products"}, RoleIDs: []string{"user"},
	}}}}
	u.NormalizeReconModel()
	if len(u.Recon.Workflows) != 1 || u.Recon.Workflows[0].Name != "Browse journey" || u.Recon.Workflows[0].Confidence != .55 {
		t.Fatalf("read-only purchase story was not calibrated: %+v", u.Recon.Workflows)
	}
	if len(u.Recon.Unknowns) != 1 || u.Recon.Unknowns[0].ID != "workflow_transition_evidence_gap" {
		t.Fatalf("missing workflow gap: %+v", u.Recon.Unknowns)
	}
}

func TestNormalizeReconModelCanonicalizesUniquePathEvidence(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Pages = []PagePurposeCard{{ID: "GET /api/cards", Method: "GET", URL: "https://app.test/api/cards", Purpose: "List cards"}}
	u.Recon.Roles = []ReconRole{{ID: "user", Name: "User"}}
	u.Recon.Objects = []BusinessObject{{ID: "card", Name: "Card", Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "/api/cards"}}}}
	u.Recon.OwnershipBoundaries = []OwnershipBoundary{{ID: "owner", ObjectID: "card", OwnerRoleID: "user", Rule: "own cards", Confidence: .9, Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "/api/cards"}}}}
	u.NormalizeReconModel()
	if got := u.Recon.Objects[0].Evidence[0].Ref; got != "GET /api/cards" {
		t.Fatalf("object evidence ref = %q", got)
	}
	if got := u.Recon.OwnershipBoundaries[0].EnforcedAt; len(got) != 1 || got[0] != "GET /api/cards" {
		t.Fatalf("derived enforcement refs = %v", got)
	}
}

func TestNormalizeReconModelConsolidatesSyntheticWorkflowGap(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Pages = []PagePurposeCard{{ID: "GET /", Method: "GET"}}
	u.Recon.Unknowns = []ReconUnknown{
		{ID: "observed_workflow_gap", Question: "Which pages form the complete workflow?", Priority: 9},
		{ID: "workflow_grounding_gap", Question: "Which observed pages form a complete end-to-end business workflow?", Priority: 8},
	}
	u.NormalizeReconModel()
	if len(u.Recon.Unknowns) != 1 || u.Recon.Unknowns[0].ID != "observed_workflow_gap" {
		t.Fatalf("workflow gaps not consolidated: %+v", u.Recon.Unknowns)
	}
}

func TestReconUnderstandingTargetsReachOneHundredOnlyWithGroundedModel(t *testing.T) {
	u := NewAppUnderstanding()
	u.AppType = "e-commerce"
	u.Summary = "A storefront where customers authenticate and place orders for catalog products."
	u.Recon.Pages = []PagePurposeCard{
		{ID: "GET /login", Method: "GET", URL: "https://shop.test/login", Purpose: "Authenticate a customer", Area: "authentication", Confidence: .9},
		{ID: "POST /orders", Method: "POST", URL: "https://shop.test/orders", Purpose: "Place an order", Area: "transaction", AuthRequired: "session", Inputs: []string{"order_id"}, Confidence: .9},
	}
	u.Recon.Roles = []ReconRole{{
		ID: "customer", Name: "Customer", Confidence: .9,
		Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "GET /login"}},
	}}
	u.Recon.Objects = []BusinessObject{{
		ID: "order", Name: "Order", Identifiers: []string{"order_id"}, Sensitivity: "personal", Confidence: .9,
		Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "POST /orders"}},
	}}
	u.Recon.Workflows = []BusinessWorkflow{{
		ID: "checkout", Name: "Checkout", Confidence: .9,
		Steps: []WorkflowStep{{ID: "place", Label: "Place order", PageIDs: []string{"POST /orders"}, ObjectIDs: []string{"order"}, RoleIDs: []string{"customer"}, StateChange: true}},
	}}
	u.Recon.OwnershipBoundaries = []OwnershipBoundary{{
		ID: "order-owner", ObjectID: "order", OwnerRoleID: "customer", Rule: "customers can access their own orders",
		EnforcedAt: []string{"POST /orders"}, Confidence: .7, Evidence: []ReconEvidence{{Kind: "authorization_test", Ref: "POST /orders", Detail: "Cross-persona differential confirmed the owner rule"}},
	}}
	u.Recon.Unknowns = []ReconUnknown{{
		ID: "refund-flow", Question: "How are order refunds authorized?", Priority: 8,
		SuggestedAction: "Observe the refund workflow with a test order.",
		Evidence:        []ReconEvidence{{Kind: "inference", Ref: "gap", Detail: "refund route not observed"}},
	}}

	u.NormalizeReconModel()
	if u.Recon.Metrics.UnderstandingLevel != "actionable" || u.Recon.Metrics.UnderstandingScore != 1 {
		t.Fatalf("understanding = %.2f %q; targets=%+v", u.Recon.Metrics.UnderstandingScore, u.Recon.Metrics.UnderstandingLevel, u.Recon.Targets)
	}
	if u.Recon.Metrics.TargetsMet != u.Recon.Metrics.TargetsTotal {
		t.Fatalf("targets met = %d/%d: %+v", u.Recon.Metrics.TargetsMet, u.Recon.Metrics.TargetsTotal, u.Recon.Targets)
	}
}

func TestReconUnderstandingLevelDoesNotCallHighScoreDeveloping(t *testing.T) {
	u := NewAppUnderstanding()
	u.AppType = "documentation"
	u.Summary = "A public standards reference with search and document browsing."
	u.Recon.Pages = []PagePurposeCard{{
		ID: "GET /search", Method: "GET", URL: "https://docs.test/search",
		Purpose: "Search public standards", Area: "search", Inputs: []string{"q"}, Confidence: .9,
	}}
	u.Recon.Roles = []ReconRole{{
		ID: "visitor", Name: "Public Visitor", Confidence: .9,
		Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "GET /search"}},
	}}
	u.Recon.Objects = []BusinessObject{{
		ID: "document", Name: "Standard Document", Confidence: .9,
		Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "GET /search"}},
	}}
	u.Recon.Workflows = []BusinessWorkflow{{
		ID: "search", Name: "Search documents", Confidence: .9,
		Steps: []WorkflowStep{{ID: "query", Label: "Search", PageIDs: []string{"GET /search"}, ObjectIDs: []string{"document"}, RoleIDs: []string{"visitor"}}},
	}}
	u.Recon.OwnershipBoundaries = []OwnershipBoundary{{
		ID: "public-documents", ObjectID: "document", OwnerRoleID: "visitor",
		Rule: "standards are publicly readable", EnforcedAt: []string{"GET /search"}, Confidence: .45,
		Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "GET /search"}},
	}}
	u.Recon.Unknowns = []ReconUnknown{{
		ID: "authoring", Question: "Where does authenticated authoring occur?", Priority: 8,
		SuggestedAction: "Map the linked author portal under separate scope.",
		Evidence:        []ReconEvidence{{Kind: "inference", Ref: "gap"}},
	}}
	u.NormalizeReconModel()

	if u.Recon.Metrics.UnderstandingScore < .85 || u.Recon.Metrics.UnderstandingLevel != "strong" {
		t.Fatalf("high-scoring model maturity = %+v, want strong with an unresolved core gate", u.Recon.Metrics)
	}
}

func TestPublicReadOnlyObjectsDoNotCreateFakeOwnershipGap(t *testing.T) {
	u := NewAppUnderstanding()
	u.AppType = "other"
	u.Summary = "A public documentation website serving technical guides and reference material."
	u.Recon.Identity = ReconIdentity{AppType: u.AppType, Summary: u.Summary}
	u.Recon.Pages = []PagePurposeCard{{
		ID: "GET /reference", Method: "GET", URL: "https://docs.test/reference",
		Purpose: "Browse public technical reference documentation", Area: "content", Confidence: .95,
	}}
	u.Recon.Roles = []ReconRole{{
		ID: "visitor", Name: "Public visitor", Confidence: .95,
		Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "GET /reference"}},
	}}
	u.Recon.Objects = []BusinessObject{{
		ID: "document", Name: "Reference document", Identifiers: []string{"path", "slug"},
		Operations: []string{"read", "search"}, Sensitivity: "public", Confidence: .95,
		Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "GET /reference"}},
	}}
	u.Recon.Workflows = []BusinessWorkflow{{
		ID: "browse", Name: "Browse documentation", Confidence: .9,
		Steps: []WorkflowStep{{ID: "read", Label: "Read reference", PageIDs: []string{"GET /reference"}, ObjectIDs: []string{"document"}, RoleIDs: []string{"visitor"}}},
	}}
	u.Recon.Unknowns = []ReconUnknown{{
		ID: "authoring", Question: "Where is authenticated authoring performed?", Priority: 7,
		SuggestedAction: "Map the separately scoped authoring service.",
		Evidence:        []ReconEvidence{{Kind: "inference", Ref: "gap"}},
	}}

	u.NormalizeReconModel()

	if u.Recon.Identity.AppType != "documentation" {
		t.Fatalf("app type = %q, want documentation", u.Recon.Identity.AppType)
	}
	if u.Recon.Metrics.OwnershipCoverage != 1 {
		t.Fatalf("public read-only ownership coverage = %.2f, want 1", u.Recon.Metrics.OwnershipCoverage)
	}
	for _, target := range u.Recon.Targets {
		if target.ID == "ownership_boundaries" && !target.Met {
			t.Fatalf("public read-only object created an ownership gap: %+v", target)
		}
		if target.ID == "ownership_boundaries" && strings.Contains(target.SuggestedAction, "second scoped persona") {
			t.Fatalf("public read-only object requested a second persona: %+v", target)
		}
	}
}

func TestPublicObjectOtherAffordanceDoesNotCreateOwnershipGap(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Identity = ReconIdentity{AppType: "government_portal", Summary: "An official government information portal publishing public events and agency news."}
	u.Recon.Pages = []PagePurposeCard{{
		ID: "GET /events/", Method: "GET", URL: "https://agency.gov/events/",
		Purpose: "Browse public agency events and an adjacent RSVP form", Area: "content", AuthRequired: "none", Confidence: .9,
	}}
	u.Recon.Roles = []ReconRole{{ID: "public_visitor", Name: "Public Visitor", Confidence: .9, Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "GET /events/"}}}}
	u.Recon.Objects = []BusinessObject{{
		ID: "event", Name: "Event", Identifiers: []string{"city filter"}, Operations: []string{"read", "search", "other: RSVP"},
		Sensitivity: "public", Confidence: .9, Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "GET /events/"}},
	}}
	u.NormalizeReconModel()
	if u.Recon.Metrics.OwnershipCoverage != 1 {
		t.Fatalf("public event ownership coverage = %.2f, want N/A coverage", u.Recon.Metrics.OwnershipCoverage)
	}
	for _, target := range u.Recon.Targets {
		if target.ID == "ownership_boundaries" && !target.Met {
			t.Fatalf("unclassified RSVP affordance created a BOLA prerequisite: %+v", target)
		}
	}
}

func TestReconUnknownActiveFormSuggestionsAreReservedForActiveRun(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Pages = []PagePurposeCard{{ID: "GET /events/", Method: "GET", URL: "https://agency.gov/events/", Purpose: "Public events and RSVP form", Confidence: .9}}
	u.Recon.Unknowns = []ReconUnknown{
		{ID: "rsvp", Question: "How is RSVP processed?", SuggestedAction: "Submit a test RSVP and capture the POST response", Priority: 8},
		{ID: "csrf", Question: "Is origin validation enforced?", SuggestedAction: "Submit form from a different origin and analyze the submission response", Priority: 8},
		{ID: "handler", Question: "Where is the handler?", SuggestedAction: "Intercept form submission POST to identify the handler", Priority: 8},
		{ID: "newsletter", Question: "What reaches the mailing provider?", SuggestedAction: "Capture newsletter POST request to examine endpoint and parameters", Priority: 8},
		{ID: "login-capture", Question: "What endpoint handles login?", SuggestedAction: "Capture login form submission to identify auth endpoint", Priority: 8},
		{ID: "external-domain", Question: "Is callback validation strict?", SuggestedAction: "Test login flow with external domain in cb parameter", Priority: 8},
		{ID: "replay", Question: "Is state reusable?", SuggestedAction: "Submit two form requests with the same state", Priority: 8},
		{ID: "redirect", Question: "Is cb an open redirect?", SuggestedAction: "Set cb to an external URL and confirm the open redirect", Priority: 8},
	}
	u.NormalizeReconModel()
	for _, unknown := range u.Recon.Unknowns {
		if !strings.Contains(unknown.SuggestedAction, "separate operator-authorized Active run") {
			t.Fatalf("unsafe form suggestion survived for %s: %q", unknown.ID, unknown.SuggestedAction)
		}
	}
}

func TestReconUnknownDoesNotInventJSONRouteVariant(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Pages = []PagePurposeCard{{ID: "GET /explore/agents/", Method: "GET", URL: "https://code.test/explore/agents/", Purpose: "Browse public agents", Confidence: .9}}
	u.Recon.Unknowns = []ReconUnknown{{
		ID: "agents_json", Question: "Is there an agent API?",
		SuggestedAction: "Try appending .json to /explore/agents/ and analyze response", Priority: 6,
	}}
	u.NormalizeReconModel()
	if got := u.Recon.Unknowns[0].SuggestedAction; !strings.Contains(got, "do not synthesize a .json suffix") {
		t.Fatalf("guessed JSON route survived normalization: %q", got)
	}
}

func TestOwnershipTargetExplainsExactTwoPersonaEvidencePrerequisites(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Identity = ReconIdentity{AppType: "marketplace", Summary: "An account marketplace where customers review their sensitive orders and delivery details."}
	u.Recon.Pages = []PagePurposeCard{{
		ID: "GET /orders/{id}", Method: "GET", URL: "https://shop.test/orders/42",
		Purpose: "View one customer order", Area: "account", AuthRequired: "required", Confidence: .9,
	}}
	u.Recon.Roles = []ReconRole{{
		ID: "customer", Name: "Customer", Confidence: .9,
		Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "GET /orders/{id}"}},
	}}
	u.Recon.Objects = []BusinessObject{{
		ID: "order", Name: "Order", Identifiers: []string{"order_id"}, Operations: []string{"read"},
		Sensitivity: "personal", OwnerRoleIDs: []string{"customer"}, Confidence: .9,
		Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "GET /orders/{id}"}},
	}}
	u.Recon.OwnershipBoundaries = []OwnershipBoundary{{
		ID: "customer_order", ObjectID: "order", OwnerRoleID: "customer",
		Rule: "Customers should read only their own orders", EnforcedAt: []string{"GET /orders/{id}"}, Confidence: .7,
		Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "GET /orders/{id}", Detail: "owner-specific route inferred, not tested"}},
	}}

	u.NormalizeReconModel()
	for _, target := range u.Recon.Targets {
		if target.ID != "ownership_boundaries" {
			continue
		}
		if target.Met {
			t.Fatalf("unverified ownership boundary unexpectedly met: %+v", target)
		}
		for _, want := range []string{"Order", "Customer", "GET /orders/{id}", "A→A", "B→B", "anon→B", "A→B", "proves B ownership"} {
			if !strings.Contains(target.SuggestedAction, want) {
				t.Fatalf("ownership prerequisite missing %q in %q", want, target.SuggestedAction)
			}
		}
		return
	}
	t.Fatal("ownership target missing")
}

func TestDocumentationModelSuppressesUngroundedEditorialActorsAndObjects(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Identity = ReconIdentity{AppType: "documentation", Summary: "A public technical documentation site with guides and API reference pages."}
	u.Recon.Pages = []PagePurposeCard{{
		ID: "GET /guide", Method: "GET", URL: "https://docs.test/guide",
		Purpose: "Read the public installation guide", Area: "content", Confidence: .95,
	}}
	u.Recon.Roles = []ReconRole{
		{ID: "visitor", Name: "Public visitor", Confidence: .95},
		{ID: "administrator", Name: "Documentation administrator", Confidence: .6, Evidence: []ReconEvidence{{Kind: "inference", Ref: "gap"}}},
	}
	u.Recon.Objects = []BusinessObject{
		{ID: "guide", Name: "Installation guide", Sensitivity: "public", Operations: []string{"read"}, Confidence: .9, Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "GET /guide"}}},
		{ID: "user_account", Name: "User account", Sensitivity: "personal", Confidence: .5, Evidence: []ReconEvidence{{Kind: "inference", Ref: "gap"}}},
	}

	u.NormalizeReconModel()
	if len(u.Recon.Roles) != 1 || u.Recon.Roles[0].ID != "visitor" || !hasGroundedReconEvidence(u.Recon.Roles[0].Evidence) {
		t.Fatalf("documentation roles = %+v, want only grounded public visitor", u.Recon.Roles)
	}
	if len(u.Recon.Objects) != 1 || u.Recon.Objects[0].ID != "guide" {
		t.Fatalf("documentation objects = %+v, want only grounded guide", u.Recon.Objects)
	}
}

func TestAnonymousPublicLogNormalizesInternalReadOnlyObject(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Identity = ReconIdentity{AppType: "developer_community", Summary: "A developer community with a public moderation and activity log."}
	u.Recon.Pages = []PagePurposeCard{{
		ID: "GET /moderations", Method: "GET", URL: "https://community.test/moderations",
		Purpose: "Public moderation log with filters and sorting; no authentication required", Area: "content", AuthRequired: "none", Confidence: .9,
	}}
	u.Recon.Roles = []ReconRole{{ID: "visitor", Name: "Public visitor", Confidence: .9}}
	u.Recon.Objects = []BusinessObject{{
		ID: "moderation_action", Name: "Moderation Action", Identifiers: []string{"action_id"},
		Operations: []string{"read", "filter", "sort"}, Sensitivity: "internal", Confidence: .85,
		Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "GET /moderations"}},
	}}

	u.NormalizeReconModel()
	if len(u.Recon.Objects) != 1 || u.Recon.Objects[0].Sensitivity != "public" || !reconPublicReadOnlyObject(u.Recon.Objects[0]) {
		t.Fatalf("public log object was not normalized as read-only: %+v", u.Recon.Objects)
	}
	for _, target := range u.Recon.Targets {
		if target.ID == "ownership_boundaries" && !target.Met {
			t.Fatalf("public moderation log created a fake ownership gap: %+v", target)
		}
	}
}

func TestNormalizeReconModelGroundsObjectsFromDistinctiveObservedPageNouns(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Pages = []PagePurposeCard{
		{ID: "GET /datasets", Method: "GET", URL: "https://ml.test/datasets", Purpose: "Browse the public dataset catalog", Confidence: .9},
		{ID: "GET /help", Method: "GET", URL: "https://ml.test/help", Purpose: "General user help", Confidence: .9},
	}
	u.Recon.Objects = []BusinessObject{
		{ID: "dataset", Name: "ML Training Dataset", Confidence: .85},
		{ID: "user", Name: "User", Confidence: .8},
	}
	u.NormalizeReconModel()

	if len(u.Recon.Objects[0].Evidence) != 1 || u.Recon.Objects[0].Evidence[0].Ref != "GET /datasets" {
		t.Fatalf("dataset evidence = %+v", u.Recon.Objects[0].Evidence)
	}
	if len(u.Recon.Objects[1].Evidence) != 0 {
		t.Fatalf("generic user object was auto-grounded: %+v", u.Recon.Objects[1].Evidence)
	}
	if len(u.Recon.Pages[0].ObjectIDs) != 1 || u.Recon.Pages[0].ObjectIDs[0] != "dataset" {
		t.Fatalf("page object links = %+v", u.Recon.Pages[0].ObjectIDs)
	}
}

func TestObjectGroundingDoesNotTurnGenericProductCopyIntoBoutiqueEvidence(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Pages = []PagePurposeCard{{
		ID: "GET /account/favorites", Method: "GET", URL: "https://shop.test/account/favorites",
		Purpose: "User favorites page for saved products", ObjectIDs: []string{"boutique_products"}, Confidence: .9,
	}}
	u.Recon.Objects = []BusinessObject{{ID: "boutique_products", Name: "Boutique Product Collections", Confidence: .6}}

	u.NormalizeReconModel()
	if hasGroundedReconEvidence(u.Recon.Objects[0].Evidence) {
		t.Fatalf("generic product copy grounded an unrelated boutique collection: %+v", u.Recon.Objects[0].Evidence)
	}
}

func TestObjectGroundingPrefersExactRouteNounOverIncidentalProse(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Pages = []PagePurposeCard{
		{ID: "GET /questions", Method: "GET", URL: "https://qa.test/questions", Purpose: "Browse the public question listing", Confidence: .85},
		{ID: "GET /tags", Method: "GET", URL: "https://qa.test/tags", Purpose: "Browse tags used to categorize questions", ObjectIDs: []string{"question"}, Confidence: .95},
	}
	u.Recon.Objects = []BusinessObject{{ID: "question", Name: "Question", Confidence: .9}}

	u.NormalizeReconModel()

	if got := u.Recon.Objects[0].Evidence; len(got) != 1 || got[0].Ref != "GET /questions" {
		t.Fatalf("question grounding = %+v, want exact /questions route", got)
	}
}

func TestObjectGroundingUpgradesEarlierFallbackToExactRoute(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Pages = []PagePurposeCard{
		{ID: "GET /questions", Method: "GET", URL: "https://qa.test/questions", Purpose: "Browse the public question listing", Confidence: .85},
		{ID: "GET /tags", Method: "GET", URL: "https://qa.test/tags", Purpose: "Browse tags used to categorize questions", ObjectIDs: []string{"question"}, Confidence: .95},
	}
	u.Recon.Objects = []BusinessObject{{
		ID: "question", Name: "Question", Confidence: .9,
		Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "GET /tags", Detail: "Observed page purpose names this business object."}},
	}}

	u.NormalizeReconModel()

	if got := u.Recon.Objects[0].Evidence; len(got) != 1 || got[0].Ref != "GET /questions" {
		t.Fatalf("upgraded question grounding = %+v, want exact /questions route", got)
	}
	if got := u.Recon.Pages[1].ObjectIDs; len(got) != 0 {
		t.Fatalf("stale /tags object link survived: %v", got)
	}
}

func TestReconAccessCeilingRejectsACompleteLookingBlockPageModel(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Identity = ReconIdentity{AppType: "e-commerce", Summary: "A retail storefront hidden behind bot protection and a 403 access boundary."}
	u.Recon.Pages = []PagePurposeCard{{ID: "GET /", Method: "GET", URL: "https://shop.test/", Purpose: "403 bot protection challenge", Confidence: .9}}
	u.Recon.Roles = []ReconRole{{ID: "shopper", Name: "Shopper", Confidence: .9, Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "GET /"}}}}
	u.Recon.Objects = []BusinessObject{{ID: "product", Name: "Product", Confidence: .9, Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "GET /"}}}}
	u.Recon.Workflows = []BusinessWorkflow{{ID: "buy", Name: "Buy", Confidence: .9, Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "GET /"}}, Steps: []WorkflowStep{{ID: "browse", Label: "Browse", PageIDs: []string{"GET /"}}}}}
	u.NormalizeReconModel()
	u.ApplyReconAccessCeiling("blocked")

	if len(u.Recon.Roles) != 0 || len(u.Recon.Objects) != 0 || len(u.Recon.Workflows) != 0 || len(u.Recon.OwnershipBoundaries) != 0 {
		t.Fatalf("blocked model retained semantic claims: %+v", u.Recon)
	}
	if u.Recon.Metrics.UnderstandingScore > .40 || u.Recon.Metrics.TargetsMet > 2 {
		t.Fatalf("blocked model escaped evidence ceiling: %+v", u.Recon.Metrics)
	}
}

func TestNormalizeReconAppTypeRecognizesExplicitRetailSummary(t *testing.T) {
	got := NormalizeReconAppType("other", "adidas.com e-commerce platform hidden behind WAF protection", "403 bot challenge")
	if got != "e-commerce" {
		t.Fatalf("retail app type = %q, want e-commerce", got)
	}
}

func TestReconUnderstandingTargetsExposeLowConfidenceCriticalPageGap(t *testing.T) {
	u := NewAppUnderstanding()
	u.AppType = "saas"
	u.Summary = "A team application with administrative account management and shared projects."
	u.Recon.Pages = []PagePurposeCard{{
		ID: "POST /admin/users", Method: "POST", URL: "https://app.test/admin/users",
		Purpose: "", Area: "admin", AuthRequired: "session", Inputs: []string{"user_id"}, Confidence: .1,
	}}
	u.NormalizeReconModel()

	var critical ReconTarget
	for _, target := range u.Recon.Targets {
		if target.ID == "critical_purpose_coverage" {
			critical = target
			break
		}
	}
	if critical.Met || critical.Actual != 0 || len(critical.EvidenceRefs) != 1 {
		t.Fatalf("critical purpose target = %+v", critical)
	}
	if u.Recon.Metrics.UnderstandingLevel == "actionable" {
		t.Fatalf("incomplete critical model reported actionable: %+v", u.Recon.Metrics)
	}
}

func TestReconActorTargetRejectsInventedEndpointAndInferenceOnlyEvidence(t *testing.T) {
	u := NewAppUnderstanding()
	u.AppType = "saas"
	u.Summary = "A shared workspace with team membership and project administration features."
	u.Recon.Pages = []PagePurposeCard{{ID: "GET /", Method: "GET", URL: "https://app.test/", Purpose: "Workspace home", Confidence: .9}}
	u.Recon.Roles = []ReconRole{{
		ID: "admin", Name: "Administrator", Confidence: .9,
		Evidence: []ReconEvidence{
			{Kind: "endpoint", Ref: "GET /invented-admin"},
			{Kind: "inference", Ref: "gap", Detail: "admin is common"},
		},
	}}
	u.NormalizeReconModel()

	if len(u.Recon.Roles) != 0 {
		t.Fatalf("inference-only privileged actor survived: %+v", u.Recon.Roles)
	}
	if len(u.Recon.Unknowns) != 1 || !strings.Contains(u.Recon.Unknowns[0].Question, "Administrator role exist") ||
		u.Recon.Unknowns[0].Evidence[0].Kind != "inference" {
		t.Fatalf("unsupported privileged actor was not demoted to an explicit unknown: %+v", u.Recon.Unknowns)
	}
	for _, target := range u.Recon.Targets {
		if target.ID == "actor_model" && target.Met {
			t.Fatalf("inference-only actor met grounded target: %+v", target)
		}
	}
}

func TestNormalizeReconModelDemotesUnsupportedPrivilegedRoleAndRewritesPresuppositionalUnknown(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Identity = ReconIdentity{AppType: "saas", Summary: "A partner workspace with a public authentication entry point."}
	u.Recon.Pages = []PagePurposeCard{{
		ID: "GET /login", Method: "GET", URL: "https://partner.test/login",
		Purpose: "Public partner login page", Area: "authentication", Confidence: .9,
	}}
	u.Recon.Roles = []ReconRole{
		{ID: "partner_merchant", Name: "Partner merchant", Description: "Possible signed-in business actor", Confidence: .55},
		{ID: "administrator", Name: "Administrator", Description: "Controls the admin console", Privileges: []string{"manage_partners"}, Confidence: .9},
	}
	u.Recon.Objects = []BusinessObject{{
		ID: "partner_record", Name: "Partner record", OwnerRoleIDs: []string{"administrator"}, Confidence: .7,
		Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "GET /login"}},
	}}
	u.Recon.Workflows = []BusinessWorkflow{{
		ID: "review", Name: "Review partners", Steps: []WorkflowStep{{
			ID: "open", Label: "Open partner records", PageIDs: []string{"GET /login"}, RoleIDs: []string{"administrator"},
		}},
	}}
	u.Recon.OwnershipBoundaries = []OwnershipBoundary{{
		ID: "admin_records", ObjectID: "partner_record", OwnerRoleID: "administrator",
		Rule: "Administrators control partner records", EnforcedAt: []string{"GET /login"},
	}}
	u.Recon.Unknowns = []ReconUnknown{
		{
			ID: "role_hierarchy_and_admin_auth", Question: "Is /admin separated from partner role?",
			WhyItMatters: "Determines privilege escalation surface", SuggestedAction: "Test admin access with partner-only credentials",
			Priority: 7, Evidence: []ReconEvidence{{Kind: "inference", Ref: "gap", Detail: "Admin redirect target unknown"}},
		},
		{
			ID: "admin_redirect_validation", Question: "Can the /admin redirect parameter become an open redirect?",
			WhyItMatters: "Redirect mechanics may enable phishing", SuggestedAction: "Inspect the Location header",
			Priority: 9, Evidence: []ReconEvidence{{Kind: "inference", Ref: "gap"}},
		},
	}

	u.NormalizeReconModel()

	if len(u.Recon.Roles) != 1 || u.Recon.Roles[0].ID != "partner_merchant" {
		t.Fatalf("ordinary nonprivileged hypothesis was not preserved or admin survived: %+v", u.Recon.Roles)
	}
	if len(u.Recon.Objects) != 1 || len(u.Recon.Objects[0].OwnerRoleIDs) != 0 {
		t.Fatalf("demoted privileged owner link survived: %+v", u.Recon.Objects)
	}
	if len(u.Recon.OwnershipBoundaries) != 0 {
		t.Fatalf("boundary owned by demoted privileged actor survived: %+v", u.Recon.OwnershipBoundaries)
	}
	for _, workflow := range u.Recon.Workflows {
		for _, step := range workflow.Steps {
			if len(step.RoleIDs) != 0 {
				t.Fatalf("workflow retained demoted privileged actor: %+v", u.Recon.Workflows)
			}
		}
	}
	var roleGap, redirectQuestion *ReconUnknown
	for i := range u.Recon.Unknowns {
		switch u.Recon.Unknowns[i].ID {
		case "role_hierarchy_and_admin_auth":
			roleGap = &u.Recon.Unknowns[i]
		case "admin_redirect_validation":
			redirectQuestion = &u.Recon.Unknowns[i]
		}
	}
	if roleGap == nil || !strings.Contains(roleGap.Question, "Does the Administrator role exist") ||
		strings.Contains(roleGap.Question, "/admin separated") || strings.Contains(roleGap.SuggestedAction, "Test admin access") ||
		!strings.Contains(roleGap.SuggestedAction, "before adding this role") {
		t.Fatalf("presuppositional admin unknown was not safely rewritten: %+v", roleGap)
	}
	if redirectQuestion == nil || redirectQuestion.Question != "Can the /admin redirect parameter become an open redirect?" ||
		redirectQuestion.SuggestedAction != "Inspect the Location header" {
		t.Fatalf("redirect-mechanics unknown was rewritten: %+v", redirectQuestion)
	}
}

func TestNormalizeReconModelPreservesPrivilegedRoleWithExactPageEvidence(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Identity = ReconIdentity{AppType: "internal_tool", Summary: "An observed administrative workspace for partner support operations."}
	u.Recon.Pages = []PagePurposeCard{{
		ID: "GET /admin", Method: "GET", URL: "https://partner.test/admin",
		Purpose: "Administrative support workspace", Area: "admin", Confidence: .9,
	}}
	u.Recon.Roles = []ReconRole{{
		ID: "administrator", Name: "Administrator", Privileges: []string{"manage_partners"}, Confidence: .9,
		Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "GET /admin", Detail: "Privileged UI affordance observed"}},
	}}

	u.NormalizeReconModel()

	if len(u.Recon.Roles) != 1 || u.Recon.Roles[0].ID != "administrator" ||
		len(u.Recon.Roles[0].Evidence) != 1 || u.Recon.Roles[0].Evidence[0].Ref != "GET /admin" {
		t.Fatalf("positively evidenced privileged role was removed: %+v", u.Recon.Roles)
	}
	if len(u.Recon.Roles[0].Privileges) != 0 ||
		!strings.Contains(u.Recon.Roles[0].Description, "authenticated privileges and enforcement remain unknown") {
		t.Fatalf("page evidence overstated authenticated privileges: %+v", u.Recon.Roles[0])
	}
	for _, unknown := range u.Recon.Unknowns {
		if strings.HasPrefix(unknown.ID, "privileged_role_evidence_gap_") {
			t.Fatalf("evidenced privileged role created a false gap: %+v", u.Recon.Unknowns)
		}
	}
}

func TestPublicLoginEvidenceKeepsRoleButStripsPostLoginPrivileges(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Pages = []PagePurposeCard{{
		ID: "GET /login", Method: "GET", URL: "https://app.test/login", Purpose: "Public login entry", Confidence: .9,
	}}
	u.Recon.Roles = []ReconRole{{
		ID: "authenticated_user", Name: "Authenticated User",
		Description: "Logged-in user can manage private projects", Privileges: []string{"manage_projects"}, Confidence: .9,
		Evidence: []ReconEvidence{{Kind: "form", Ref: "GET /login", Detail: "Login form observed"}},
	}}

	u.NormalizeReconModel()

	if len(u.Recon.Roles) != 1 || len(u.Recon.Roles[0].Privileges) != 0 {
		t.Fatalf("unverified authenticated privileges survived: %+v", u.Recon.Roles)
	}
	if !strings.Contains(u.Recon.Roles[0].Description, "post-login capabilities remain unknown") {
		t.Fatalf("role boundary explanation = %q", u.Recon.Roles[0].Description)
	}
}

func TestPublicModerationLogDoesNotProveModeratorPrivileges(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Pages = []PagePurposeCard{{
		ID: "GET /moderations", Method: "GET", URL: "https://community.test/moderations",
		Purpose: "Public moderation activity log", Area: "content", AuthRequired: "none", Confidence: .9,
	}}
	u.Recon.Roles = []ReconRole{{
		ID: "moderator", Name: "Moderator", Description: "Can ban users and edit tags",
		Privileges: []string{"ban_users", "edit_tags"}, Confidence: .9,
		Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "GET /moderations"}},
	}}

	u.NormalizeReconModel()
	if len(u.Recon.Roles) != 1 || len(u.Recon.Roles[0].Privileges) != 0 {
		t.Fatalf("public log proved unobserved moderator privileges: %+v", u.Recon.Roles)
	}
	if u.Recon.Roles[0].Confidence > .65 || !strings.Contains(u.Recon.Roles[0].Description, "authenticated privileges and enforcement remain unknown") {
		t.Fatalf("moderator evidence ceiling missing: %+v", u.Recon.Roles[0])
	}
}

func TestObservedRegistrationPageGroundsActorExistence(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Pages = []PagePurposeCard{{
		ID: "GET /account/register/", Method: "GET", URL: "https://registry.test/account/register/",
		Purpose: "Public user registration page", Area: "authentication", Confidence: .9,
	}}
	u.Recon.Roles = []ReconRole{{
		ID: "registered_user", Name: "Registered User", Privileges: []string{"manage packages"}, Confidence: .85,
	}}

	u.NormalizeReconModel()

	if got := u.Recon.Roles[0].Evidence; len(got) != 1 || got[0].Ref != "GET /account/register/" {
		t.Fatalf("registered actor evidence = %+v", got)
	}
	if len(u.Recon.Roles[0].Privileges) != 0 {
		t.Fatalf("registration page invented post-login privileges: %v", u.Recon.Roles[0].Privileges)
	}
}

func TestAnonymousActorEvidencePrefersHumanEntryPageOverUtilityDocument(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Pages = []PagePurposeCard{
		{ID: "GET /opensearch.xml", Method: "GET", URL: "https://registry.test/opensearch.xml", Purpose: "Browser search provider XML", Confidence: .99},
		{ID: "GET /", Method: "GET", URL: "https://registry.test/", Purpose: "Public package registry homepage", Confidence: .80},
	}
	u.Recon.Roles = []ReconRole{{ID: "anonymous", Name: "Public Visitor", Confidence: .85}}

	u.NormalizeReconModel()

	if got := u.Recon.Roles[0].Evidence; len(got) != 1 || got[0].Ref != "GET /" {
		t.Fatalf("anonymous actor evidence = %+v, want human entry page", got)
	}
}

func TestObjectGroundingPrefersExactIdentifierInput(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Pages = []PagePurposeCard{
		{ID: "GET /", Method: "GET", URL: "https://community.test/", Purpose: "Main story feed", ObjectIDs: []string{"story"}, Confidence: .9},
		{ID: "GET /s/abc/title", Method: "GET", URL: "https://community.test/s/abc/title", Purpose: "Story permalink and comments", Inputs: []string{"story_id"}, Confidence: .8},
	}
	u.Recon.Objects = []BusinessObject{{ID: "story", Name: "Story", Identifiers: []string{"story_id"}, Confidence: .8}}

	u.NormalizeReconModel()

	if got := u.Recon.Objects[0].Evidence; len(got) != 1 || got[0].Ref != "GET /s/abc/title" {
		t.Fatalf("story evidence = %+v, want exact identifier-bearing page", got)
	}
}

func TestObjectGroundingRecognizesActionNounInPagePurpose(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Pages = []PagePurposeCard{{
		ID: "GET /", Method: "GET", URL: "https://community.test/", Purpose: "Ranked stories with voting and commenting", Confidence: .9,
	}}
	u.Recon.Objects = []BusinessObject{{ID: "comment", Name: "Comment", Confidence: .8}}

	u.NormalizeReconModel()

	if got := u.Recon.Objects[0].Evidence; len(got) != 1 || got[0].Ref != "GET /" {
		t.Fatalf("comment evidence = %+v, want observed commenting surface", got)
	}
}

func TestFallbackReadOnlyWorkflowAvoidsUtilityDocument(t *testing.T) {
	workflow, ok := fallbackReadOnlyWorkflow([]PagePurposeCard{
		{ID: "GET /opensearch.xml", Method: "GET", URL: "https://community.test/opensearch.xml", Purpose: "OpenSearch search provider description", Confidence: 1},
		{ID: "GET /", Method: "GET", URL: "https://community.test/", Purpose: "Main public story feed", Confidence: .8},
	})
	if !ok || workflow.Steps[0].PageIDs[0] != "GET /" || workflow.Name != "Browse main feed journey" {
		t.Fatalf("fallback workflow = %+v, want human entry page", workflow)
	}
}

func TestSupplementReadOnlyWorkflowsPrefersDistinctPublicBusinessSurfaces(t *testing.T) {
	pages := []PagePurposeCard{
		{ID: "GET /api-beta/", Method: "GET", URL: "https://films.test/api-beta/", Purpose: "Developer API documentation", Confidence: .95},
		{ID: "GET /settings/", Method: "GET", URL: "https://films.test/settings/", Purpose: "Account settings", AuthRequired: "yes", Confidence: .95},
		{ID: "GET /cdn-cgi/challenge-platform/", Method: "GET", URL: "https://films.test/cdn-cgi/challenge-platform/", Purpose: "Just a moment security challenge", Confidence: .99},
		{ID: "GET /film/sneakers/", Method: "GET", URL: "https://films.test/film/sneakers/", Purpose: "Film detail page", Confidence: .82},
		{ID: "GET /reviews/popular/this/week/", Method: "GET", URL: "https://films.test/reviews/popular/this/week/", Purpose: "Popular film reviews", Confidence: .81},
		{ID: "GET /journal/bafta-winners/", Method: "GET", URL: "https://films.test/journal/bafta-winners/", Purpose: "Editorial story about award winners", Confidence: .80},
	}

	got := supplementReadOnlyWorkflows(pages, nil, 3)
	if len(got) != 3 {
		t.Fatalf("supplemented workflows = %+v, want three exact public journeys", got)
	}
	wantRefs := []string{"GET /reviews/popular/this/week/", "GET /film/sneakers/", "GET /journal/bafta-winners/"}
	for i, want := range wantRefs {
		if ref := got[i].Steps[0].PageIDs[0]; ref != want {
			t.Fatalf("workflow %d ref = %q, want %q; all=%+v", i, ref, want, got)
		}
		if got[i].Steps[0].StateChange {
			t.Fatalf("workflow %d became state changing: %+v", i, got[i])
		}
	}
}

func TestNormalizeReconModelGroundsUnauthenticatedVisitorSpelling(t *testing.T) {
	u := NewAppUnderstanding()
	u.AppType = "social_media"
	u.Recon.Identity = ReconIdentity{AppType: "social_media", Summary: "People discover and review films."}
	u.Recon.Pages = []PagePurposeCard{{
		ID: "GET /film/sneakers/", Method: "GET", URL: "https://films.test/film/sneakers/",
		Purpose: "Public film detail and reviews", Confidence: .85,
	}}
	u.Recon.Roles = []ReconRole{{ID: "unauthenticated_visitor", Name: "Unauthenticated Visitor", Confidence: .8}}

	u.NormalizeReconModel()

	if got := u.Recon.Roles[0].Evidence; len(got) != 1 || got[0].Ref != "GET /film/sneakers/" {
		t.Fatalf("unauthenticated visitor evidence = %+v, want exact public GET", got)
	}
}

func TestUtilityDocumentDoesNotGroundUnrelatedBusinessObject(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Pages = []PagePurposeCard{
		{ID: "GET /", Method: "GET", URL: "https://forum.test/", Purpose: "Community forum login landing page", Confidence: .8},
		{ID: "GET /opensearch.xml", Method: "GET", URL: "https://forum.test/opensearch.xml", Purpose: "OpenSearch descriptor for searching forum posts", Confidence: .99},
	}
	u.Recon.Objects = []BusinessObject{
		{ID: "forum_post", Name: "Forum Post", Confidence: .4, Evidence: []ReconEvidence{{Kind: "inference", Ref: "app_type"}}},
		{ID: "opensearch_descriptor", Name: "OpenSearch Descriptor", Confidence: .9},
	}

	u.NormalizeReconModel()

	if hasGroundedReconEvidence(u.Recon.Objects[0].Evidence) {
		t.Fatalf("utility document grounded forum post: %+v", u.Recon.Objects[0].Evidence)
	}
	if !hasGroundedReconEvidence(u.Recon.Objects[1].Evidence) {
		t.Fatalf("utility document did not ground its own descriptor: %+v", u.Recon.Objects[1].Evidence)
	}
}

func TestReconOwnershipIgnoresLoginFormArtifact(t *testing.T) {
	form := BusinessObject{
		ID: "login_form", Name: "Login Form", Description: "Authentication form accepting username and password",
		Identifiers: []string{"username", "password", "redirect"}, Operations: []string{"create"}, Sensitivity: "personal",
	}
	if reconOwnershipCandidate(form) {
		t.Fatal("login form UI artifact created a second-persona ownership requirement")
	}
	account := BusinessObject{ID: "user_account", Name: "User Account", Identifiers: []string{"user_id"}, Operations: []string{"read", "update"}, Sensitivity: "personal"}
	if !reconOwnershipCandidate(account) {
		t.Fatal("owned user account lost its ownership requirement")
	}
}

func TestReconOwnershipIgnoresPublicDirectoryAndFeedbackFormArtifacts(t *testing.T) {
	contact := BusinessObject{
		ID: "media_contact", Name: "Media Contact", Identifiers: []string{"path: /news/media-contacts/"},
		Operations: []string{"read"}, Sensitivity: "personal",
	}
	if reconOwnershipCandidate(contact) {
		t.Fatal("public contact directory created a cross-persona ownership requirement")
	}
	feedback := BusinessObject{
		ID: "feedback_survey", Name: "Educator Feedback Survey", Description: "Gravity Forms feedback form",
		Identifiers: []string{"form_id=117"}, Operations: []string{"read", "submit"}, Sensitivity: "unknown",
	}
	if reconOwnershipCandidate(feedback) {
		t.Fatal("feedback form interaction artifact created an ownership requirement")
	}
	contactSubmission := BusinessObject{
		ID: "contact_submission", Name: "Contact Submission", Identifiers: []string{"email_address", "message"},
		Operations: []string{"create"}, Sensitivity: "personal",
	}
	if reconOwnershipCandidate(contactSubmission) {
		t.Fatal("anonymous contact form submission created a cross-persona ownership requirement")
	}
	newsletter := BusinessObject{
		ID: "newsletter_subscription", Name: "Newsletter Subscription", Identifiers: []string{"EMAIL"},
		Operations: []string{"create"}, Sensitivity: "personal",
	}
	if reconOwnershipCandidate(newsletter) {
		t.Fatal("newsletter signup artifact created a cross-persona ownership requirement")
	}
	profile := BusinessObject{
		ID: "customer_profile", Name: "Customer Profile", Identifiers: []string{"user_id"},
		Operations: []string{"read"}, Sensitivity: "personal",
	}
	if !reconOwnershipCandidate(profile) {
		t.Fatal("owner-addressable personal profile lost its ownership requirement")
	}
}

func TestReconOwnershipIgnoresUngroundedObjectHypothesis(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Identity = ReconIdentity{AppType: "product_catalog", Summary: "Public product catalog with directly observed books and categories."}
	u.Recon.Objects = []BusinessObject{
		{ID: "book", Name: "Book", Identifiers: []string{"slug"}, Operations: []string{"read"}, Sensitivity: "public", Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "GET /book"}}},
		{ID: "review", Name: "Review", Identifiers: []string{"review_id"}, Operations: []string{"unknown"}, Sensitivity: "unknown", Evidence: []ReconEvidence{{Kind: "inference", Ref: "disabled_markup"}}},
	}
	u.RecalculateReconMetrics()
	for _, target := range u.Recon.Targets {
		if target.ID == "ownership_boundaries" && (!target.Met || target.Actual != 1 || strings.Contains(target.SuggestedAction, "Review")) {
			t.Fatalf("ungrounded review created ownership gap: %+v", target)
		}
	}
}

func TestNormalizeReconModelBlocksExternalCallbackProbeHiddenInObservedPath(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Pages = []PagePurposeCard{{
		ID: "GET /login", Method: "GET", URL: "https://shop.test/login", Purpose: "Login page", Confidence: .9,
	}}
	u.Recon.Unknowns = []ReconUnknown{{
		ID: "callback_redirect", Question: "Does the callback permit an off-site redirect?",
		SuggestedAction: "Test /login?cb=https://evil.example for redirect validation or domain restriction", Priority: 8,
	}}

	u.NormalizeReconModel()
	if got := u.Recon.Unknowns[0].SuggestedAction; !strings.Contains(got, "evil.example was not observed") || !strings.Contains(got, "do not guess or expand scope") {
		t.Fatalf("nested external callback probe was not bounded: %q", got)
	}
}

func TestPublicReadOnlyOwnershipNACountsAsSemanticCoverage(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Pages = []PagePurposeCard{{ID: "GET /books", Method: "GET", URL: "https://books.test/books", Purpose: "Public book catalog", AuthRequired: "none", Confidence: .9}}
	u.Recon.Roles = []ReconRole{{ID: "visitor", Name: "Public Visitor", Confidence: .9, Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "GET /books"}}}}
	u.Recon.Objects = []BusinessObject{{ID: "book", Name: "Book", Operations: []string{"read"}, Sensitivity: "public", Confidence: .9, Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "GET /books"}}}}
	u.Recon.Workflows = []BusinessWorkflow{{ID: "browse", Name: "Browse books", Confidence: .9, Steps: []WorkflowStep{{ID: "list", PageIDs: []string{"GET /books"}}}}}
	u.Recon.Unknowns = []ReconUnknown{{ID: "freshness", Question: "How fresh is the catalog?", SuggestedAction: "Inspect observed cache metadata", Priority: 6}}
	u.RecalculateReconMetrics()
	if u.Recon.Metrics.SemanticCoverage != 1 || u.Recon.Metrics.OverallConfidence < .89 {
		t.Fatalf("metrics=%+v, want ownership N/A to preserve complete public coverage", u.Recon.Metrics)
	}
}

func TestNormalizeReconModelSynthesizesObservedPublicVisitor(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Identity = ReconIdentity{AppType: "product_catalog", Summary: "Public book catalog with titles, categories, prices, and availability."}
	u.Recon.Pages = []PagePurposeCard{{
		ID: "GET /", Method: "GET", URL: "https://books.test/", Purpose: "Public book catalog homepage", AuthRequired: "none", Confidence: .92,
	}}
	u.NormalizeReconModel()

	if len(u.Recon.Roles) != 1 || u.Recon.Roles[0].ID != "public_visitor" || u.Recon.Roles[0].Confidence > .85 {
		t.Fatalf("public visitor fallback=%+v", u.Recon.Roles)
	}
	if !hasGroundedReconEvidence(u.Recon.Roles[0].Evidence) {
		t.Fatalf("public visitor was not grounded: %+v", u.Recon.Roles[0])
	}
}

func TestNormalizeReconModelDoesNotInventVisitorBehindAuth(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Pages = []PagePurposeCard{{
		ID: "GET /account", Method: "GET", URL: "https://app.test/account", Purpose: "Account dashboard", AuthRequired: "session", Confidence: .9,
	}}
	u.NormalizeReconModel()
	if len(u.Recon.Roles) != 0 {
		t.Fatalf("authenticated page invented public visitor: %+v", u.Recon.Roles)
	}
}

func TestNormalizeReconModelRemovesPresentationControlsFromBusinessObjects(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Identity = ReconIdentity{AppType: "product_catalog", Summary: "Public product catalog with books and categories."}
	u.Recon.Pages = []PagePurposeCard{{ID: "GET /", Method: "GET", URL: "https://books.test/", Purpose: "Public product catalog", AuthRequired: "none", Confidence: .9}}
	u.Recon.Objects = []BusinessObject{
		{ID: "book", Name: "Book Product", Operations: []string{"read"}, Sensitivity: "public", Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "GET /"}}},
		{ID: "pagination_controls", Name: "Pagination Controls", Operations: []string{"read"}, Sensitivity: "public", Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "GET /"}}},
		{ID: "category_navigation", Name: "Category Navigation Sidebar", Operations: []string{"read"}, Sensitivity: "public", Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "GET /"}}},
	}
	u.NormalizeReconModel()
	if len(u.Recon.Objects) != 1 || u.Recon.Objects[0].ID != "book" {
		t.Fatalf("presentation controls survived as business objects: %+v", u.Recon.Objects)
	}
}

func TestCommentedOutMarkupDoesNotGroundBusinessObject(t *testing.T) {
	evidence := canonicalizeReconEvidence([]ReconEvidence{{
		Kind: "endpoint", Ref: "GET /book", Detail: "Contains commented-out review-related links suggesting a workflow exists",
	}}, []PagePurposeCard{{ID: "GET /book", Method: "GET", URL: "https://books.test/book"}})
	if len(evidence) != 1 || evidence[0].Kind != "inference" || hasGroundedReconEvidence(evidence) {
		t.Fatalf("disabled markup remained grounded: %+v", evidence)
	}
}

func TestCanonicalEvidenceAcceptsExactPageAndFormAliases(t *testing.T) {
	pages := []PagePurposeCard{
		{ID: "GET /film/sneakers/", Method: "GET", URL: "https://films.test/film/sneakers/"},
		{ID: "GET /", Method: "GET", URL: "https://films.test/"},
	}
	evidence := canonicalizeReconEvidence([]ReconEvidence{
		{Kind: "page", Ref: "get_film_sneakers_", Detail: "Film page"},
		{Kind: "form", Ref: "get_root", Detail: "Login form"},
		{Kind: "page", Ref: "get_invented_admin", Detail: "Invented page"},
	}, pages)
	if len(evidence) != 2 || evidence[0].Kind != "endpoint" || evidence[0].Ref != "GET /film/sneakers/" || evidence[1].Kind != "endpoint" || evidence[1].Ref != "GET /" {
		t.Fatalf("canonical evidence = %+v, want two exact endpoint refs", evidence)
	}
}

func TestNormalizeReconModelStripsWriteOperationsGroundedOnlyByGET(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Pages = []PagePurposeCard{{
		ID: "GET /reviews/popular/", Method: "GET", URL: "https://films.test/reviews/popular/",
		Purpose: "Public popular reviews", AuthRequired: "none", Confidence: .9,
	}}
	u.Recon.Objects = []BusinessObject{{
		ID: "review", Name: "Review", Operations: []string{"read", "create", "update"}, Sensitivity: "public",
		Evidence: []ReconEvidence{{Kind: "page", Ref: "get_reviews_popular_"}},
	}}

	u.NormalizeReconModel()

	if got := u.Recon.Objects[0].Operations; len(got) != 1 || got[0] != "read" {
		t.Fatalf("GET-only object operations = %v, want read only", got)
	}
	if got := u.Recon.Objects[0].Evidence; len(got) != 1 || got[0].Ref != "GET /reviews/popular/" {
		t.Fatalf("GET-only object evidence = %+v", got)
	}
}

func TestReconUnknownActionsDoNotGuessRoutesOrHideActivePrerequisites(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Pages = []PagePurposeCard{{ID: "GET /", Method: "GET", URL: "https://shop.test/", Purpose: "Public catalog", AuthRequired: "none", Confidence: .9}}
	u.Recon.Unknowns = []ReconUnknown{
		{ID: "guessed", Question: "Are checkout routes present?", SuggestedAction: "Scan for /basket, /checkout, and /accounts endpoints", Priority: 8},
		{ID: "bruteforce", Question: "How many category IDs exist?", SuggestedAction: "Brute-force scan category IDs 29-100", Priority: 7},
	}
	u.NormalizeReconModel()
	if got := u.Recon.Unknowns[0].SuggestedAction; !strings.Contains(got, "/basket was not observed") || !strings.Contains(got, "do not guess or enumerate") {
		t.Fatalf("guessed-route action=%q", got)
	}
	if got := u.Recon.Unknowns[1].SuggestedAction; !strings.Contains(got, "separate operator-authorized Active run") {
		t.Fatalf("active prerequisite action=%q", got)
	}
}

func TestReconUnknownActionsReserveSubmissionAndEnumerationForActiveRun(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Pages = []PagePurposeCard{{ID: "GET /story/1569", Method: "GET", URL: "https://films.test/story/1569", Purpose: "Public story", Confidence: .8}}
	u.Recon.Unknowns = []ReconUnknown{
		{ID: "submit", Question: "Is ownership enforced?", SuggestedAction: "Submit diary entry POST with viewingId of a different user", Priority: 9},
		{ID: "enumerate", Question: "Are story tokens predictable?", SuggestedAction: "Test story token enumeration by accessing sequential story numbers", Priority: 8},
	}

	u.NormalizeReconModel()

	for _, unknown := range u.Recon.Unknowns {
		if !strings.Contains(unknown.SuggestedAction, "separate operator-authorized Active run") {
			t.Fatalf("unsafe Recon action survived: %+v", unknown)
		}
	}
}

func TestBusinessObjectCoverageRequiresGroundedEvidence(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Objects = []BusinessObject{
		{ID: "observed", Name: "Observed Object", Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "GET /objects"}}},
		{ID: "inferred", Name: "Inferred Object", Evidence: []ReconEvidence{{Kind: "inference", Ref: "app_type"}}},
	}
	u.RecalculateReconMetrics()
	for _, target := range u.Recon.Targets {
		if target.ID == "business_object_coverage" {
			if target.Actual != .5 {
				t.Fatalf("object coverage=%v, want .5 grounded objects", target.Actual)
			}
			return
		}
	}
	t.Fatal("business object coverage target missing")
}

func TestBusinessObjectCoverageIgnoresIdentifierRepeatedInGlobalChrome(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Pages = []PagePurposeCard{
		{ID: "GET /", Method: "GET", URL: "https://films.test/", Purpose: "Film homepage", Inputs: []string{"viewingId"}, Confidence: .9},
		{ID: "GET /films", Method: "GET", URL: "https://films.test/films", Purpose: "Film catalog", Inputs: []string{"viewingId"}, Confidence: .9},
		{ID: "GET /reviews", Method: "GET", URL: "https://films.test/reviews", Purpose: "Popular reviews", Inputs: []string{"viewingId"}, Confidence: .9},
		{ID: "GET /lists", Method: "GET", URL: "https://films.test/lists", Purpose: "Popular lists", Inputs: []string{"viewingId"}, Confidence: .9},
	}
	u.Recon.Objects = []BusinessObject{
		{ID: "film", Name: "Film", Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "GET /films"}}},
		{ID: "review", Name: "Review", Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "GET /reviews"}}},
	}
	u.RecalculateReconMetrics()

	for _, target := range u.Recon.Targets {
		if target.ID == "business_object_coverage" {
			if target.Actual != 1 {
				t.Fatalf("object coverage=%v, want grounded object ratio after shared chrome exclusion", target.Actual)
			}
			return
		}
	}
	t.Fatal("business object coverage target missing")
}

func TestNormalizeReconModelDropsUtilityOnlyWorkflow(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Pages = []PagePurposeCard{
		{ID: "GET /", Method: "GET", URL: "https://forum.test/", Purpose: "Community forum homepage", Confidence: .8},
		{ID: "GET /opensearch.xml", Method: "GET", URL: "https://forum.test/opensearch.xml", Purpose: "OpenSearch browser search provider XML", Confidence: .99},
	}
	u.Recon.Workflows = []BusinessWorkflow{
		{ID: "browse_forum", Name: "Browse Forum", Steps: []WorkflowStep{{ID: "home", PageIDs: []string{"GET /"}}}, Confidence: .8},
		{ID: "add_search_engine", Name: "Add Forum to Browser Search", Steps: []WorkflowStep{{ID: "descriptor", PageIDs: []string{"GET /opensearch.xml"}}}, Confidence: .9},
	}

	u.NormalizeReconModel()

	if len(u.Recon.Workflows) != 1 || u.Recon.Workflows[0].ID != "browse_forum" {
		t.Fatalf("utility-only workflow survived: %+v", u.Recon.Workflows)
	}
}

func TestNormalizeReconModelRebuildsSavedFallbackJourney(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Pages = []PagePurposeCard{
		{ID: "GET /opensearch.xml", Method: "GET", URL: "https://community.test/opensearch.xml", Purpose: "OpenSearch description", Confidence: 1},
		{ID: "GET /", Method: "GET", URL: "https://community.test/", Purpose: "Main public story feed", Confidence: .8},
	}
	u.Recon.Workflows = []BusinessWorkflow{{
		ID: "observed_read_journey", Name: "OpenSearch description journey",
		Description: "One-step read-only journey synthesized from a directly observed page.", Confidence: .7,
		Evidence: []ReconEvidence{{Kind: "endpoint", Ref: "GET /opensearch.xml"}},
		Steps:    []WorkflowStep{{ID: "visit_observed_page", Label: "OpenSearch description", PageIDs: []string{"GET /opensearch.xml"}}},
	}}

	u.NormalizeReconModel()

	if got := u.Recon.Workflows; len(got) != 1 || got[0].Steps[0].PageIDs[0] != "GET /" {
		t.Fatalf("rebuilt fallback workflow = %+v, want current human entry page", got)
	}
}

func TestNormalizeReconAppTypeCoversWiderPublicArchetypes(t *testing.T) {
	tests := []struct {
		name, appType, summary, evidence, want string
	}{
		{"wiki", "other", "Collaborative encyclopedia", "https://en.wikipedia.org/wiki/Main_Page", "knowledge_base"},
		{"registry", "unknown", "Software package search", "https://www.npmjs.com/package/react package dependencies", "package_registry"},
		{"python registry", "other", "The official Python Package Index", "https://pypi.org/", "package_registry"},
		{"map", "other", "Collaborative mapping platform and geographic data API", "https://www.openstreetmap.org/", "geospatial"},
		{"map beats transport", "api_service", "Geographic data API", "https://www.openstreetmap.org/", "geospatial"},
		{"government", "", "Public service portal", "https://www.gov.uk/", "government_service"},
		{"government information", "other", "Official government information website for agency news and public events", "https://agency.gov/", "government_portal"},
		{"nasa", "other", "Public information", "https://www.nasa.gov/", "government_portal"},
		{"model hub", "api_service", "ML model catalog", "https://huggingface.co/models", "developer_platform"},
		{"language community", "knowledge_base", "Official Python programming language website with a linked package registry", "https://www.python.org/", "developer_platform"},
		{"gitlab explore", "other", "Public projects and groups", "https://gitlab.com/explore", "developer_platform"},
		{"standards repository", "other", "Public standards repository and RFC index", "https://www.rfc-editor.org/", "documentation"},
		{"news", "other", "Public articles", "https://www.bbc.com/news", "news_media"},
		{"education", "other", "Public courses", "https://www.khanacademy.org/", "education_platform"},
		{"status", "api_service", "System status dashboard", "https://status.openai.com/", "status_dashboard"},
		{"http testing service", "other", "Public HTTP testing and debugging service that echoes request data and publishes an OpenAPI specification", "https://httpbin.example/ spec.json", "api_service"},
		{"docs", "other", "Language reference", "https://developer.example/docs/reference", "documentation"},
		{"documentation website", "other", "Docker public documentation website serving technical guides", "https://docs.example/", "documentation"},
		{"developer q and a", "other", "A public developer Q&A platform for questions and answers", "https://qa.example/questions", "developer_q_and_a"},
		{"developer community", "other", "A public link aggregation site where users submit stories with topic tags and discuss in comment threads", "https://community.example/", "developer_community"},
		{"community forum", "other", "Discourse Meta is a community forum for software users and developers", "https://meta.example/", "developer_community"},
		{"book catalog", "other", "Public book catalog scraping sandbox with titles, prices, and availability", "https://books.example/", "product_catalog"},
		{"quote catalog", "other", "Public quotes repository displaying quotes with author attribution and tag-based navigation", "https://quotes.example/", "content_catalog"},
		{"quote practice site", "other", "Educational web scraping practice site displaying famous quotes organized by author and tag. Public browse journey observed for quote collections.", "https://quotes.example/", "content_catalog"},
		{"tech news community", "other", "A public tech news aggregator where users submit links, comment, and vote", "https://news.community.example/", "developer_community"},
		{"lobsters", "other", "Public link aggregation site", "https://lobste.rs/", "developer_community"},
		{"letterboxd", "documentation", "Film diary and social platform", "https://letterboxd.com/", "social_media"},
		{"specific preserved", "social_media", "News links", "https://community.test/", "social_media"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeReconAppTypeForTarget(tt.appType, tt.summary, tt.evidence, tt.evidence); got != tt.want {
				t.Fatalf("NormalizeReconAppType() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGenericOtherIdentityCannotCloseApplicationIdentityGate(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Identity = ReconIdentity{
		AppType: "other",
		Summary: "A long but still generic description of an observed public application surface.",
	}
	u.RecalculateReconMetrics()
	for _, target := range u.Recon.Targets {
		if target.ID == "application_identity" {
			if target.Met || target.Actual != 0 {
				t.Fatalf("generic identity closed the gate: %+v", target)
			}
			return
		}
	}
	t.Fatal("application identity target missing")
}

func TestNormalizeReconModelUpgradesGenericIdentityFromGroundedPages(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Identity = ReconIdentity{AppType: "other", Summary: "Public content platform."}
	u.Recon.Pages = []PagePurposeCard{{
		ID: "GET /wiki/Main_Page", Method: "GET", URL: "https://en.wikipedia.org/wiki/Main_Page",
		Purpose: "Read encyclopedia articles", Area: "content", Confidence: .9,
	}}
	u.NormalizeReconModel()
	if u.Recon.Identity.AppType != "knowledge_base" {
		t.Fatalf("normalized app type = %q", u.Recon.Identity.AppType)
	}
}

func TestNormalizeReconModelDoesNotCallLinkedOnlyPathExposed(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Identity = ReconIdentity{
		AppType: "developer_q_and_a",
		Summary: "Public developer Q&A platform. Exposed /internal/ path linked from footer.",
	}
	u.NormalizeReconModel()

	if strings.Contains(strings.ToLower(u.Recon.Identity.Summary), "exposed /internal") {
		t.Fatalf("linked-only path remained exposed: %q", u.Recon.Identity.Summary)
	}
	for _, want := range []string{"Linked-only reference", "access was not observed"} {
		if !strings.Contains(u.Recon.Identity.Summary, want) {
			t.Fatalf("normalized summary = %q, missing %q", u.Recon.Identity.Summary, want)
		}
	}
}

func TestUnknownActionDoesNotGuessUnobservedHost(t *testing.T) {
	u := NewAppUnderstanding()
	u.Recon.Pages = []PagePurposeCard{{ID: "GET /", URL: "https://pypi.org/", Method: "GET", Purpose: "Package index", Confidence: .9}}
	u.Recon.Unknowns = []ReconUnknown{{
		ID: "upload", Question: "Where is package upload handled?", Priority: 9,
		SuggestedAction: "Analyze traffic to warehouse.pypi.org or follow upload links.",
	}}

	u.NormalizeReconModel()

	got := u.Recon.Unknowns[0].SuggestedAction
	for _, want := range []string{"warehouse.pypi.org was not observed", "do not guess or expand scope"} {
		if !strings.Contains(got, want) {
			t.Fatalf("suggested action = %q, missing %q", got, want)
		}
	}
}

func TestNormalizeReconModelUsesDominantTargetNotIncidentalLinkedProduct(t *testing.T) {
	u := NewAppUnderstanding()
	u.AppType = "knowledge_base"
	u.Summary = "Official Python language and community website."
	u.Recon.Identity = ReconIdentity{AppType: "knowledge_base", Summary: "Official Python language and community website."}
	u.Recon.Pages = []PagePurposeCard{
		{ID: "GET /", Method: "GET", URL: "https://www.python.org/", Purpose: "Python language homepage linking to Wikipedia and a package registry", Confidence: .9},
		{ID: "GET /jobs", Method: "GET", URL: "https://www.python.org/jobs/", Purpose: "Public developer job board", Confidence: .8},
	}
	u.NormalizeReconModel()
	if u.Recon.Identity.AppType != "developer_platform" {
		t.Fatalf("incidental linked product overrode target identity: %q", u.Recon.Identity.AppType)
	}
}

func TestFallbackReadOnlyWorkflowUsesReadableActionLabel(t *testing.T) {
	workflow, ok := fallbackReadOnlyWorkflow([]PagePurposeCard{{
		ID: "GET /jobs/", Method: "GET", URL: "https://www.python.org/jobs/",
		Purpose:    "Public job board listing page displaying job postings on python.org, a community-oriented developer platform.",
		Confidence: .8,
	}})
	if !ok {
		t.Fatal("expected a grounded read-only fallback workflow")
	}
	if workflow.Name != "Browse public job listings journey" || workflow.Steps[0].Label != "Browse public job listings" {
		t.Fatalf("fallback workflow label = %q / %q", workflow.Name, workflow.Steps[0].Label)
	}
}

func TestFallbackReadOnlyWorkflowUsesSemanticStoryLabel(t *testing.T) {
	workflow, ok := fallbackReadOnlyWorkflow([]PagePurposeCard{{
		ID: "GET /journal/bafta-winners/", Method: "GET", URL: "https://films.test/journal/bafta-winners/",
		Purpose:    "Public film community user story page displaying a long editorial feature and related links.",
		Confidence: .8,
	}})
	if !ok {
		t.Fatal("expected a grounded read-only fallback workflow")
	}
	if workflow.Name != "Read a public story journey" || workflow.Steps[0].Label != "Read a public story" {
		t.Fatalf("fallback workflow label = %q / %q", workflow.Name, workflow.Steps[0].Label)
	}
}
