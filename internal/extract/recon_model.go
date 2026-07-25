package extract

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"unicode"

	"github.com/ozzyw/aobtd/internal/target"
	"github.com/ozzyw/aobtd/pkg/types"
)

// ReconModel is AOBTD's semantic model of the target. It deliberately sits
// above the URL discovery graph: nodes describe business concepts and edges
// describe how a human uses the application, not merely which URL linked to
// another URL.
type ReconModel struct {
	Identity            ReconIdentity       `json:"identity"`
	Roles               []ReconRole         `json:"roles"`
	Objects             []BusinessObject    `json:"objects"`
	Pages               []PagePurposeCard   `json:"pages"`
	Workflows           []BusinessWorkflow  `json:"workflows"`
	OwnershipBoundaries []OwnershipBoundary `json:"ownership_boundaries"`
	Unknowns            []ReconUnknown      `json:"unknowns"`
	Targets             []ReconTarget       `json:"targets"`
	Metrics             ReconMetrics        `json:"metrics"`
}

// ReconIdentity keeps the scan-level application identity next to the
// semantic graph. AppUnderstanding retains the legacy top-level fields for
// compatibility, while this snapshot lets the planner and exported recon
// model assess identity coverage without reloading another database column.
type ReconIdentity struct {
	AppType string `json:"app_type"`
	Summary string `json:"summary"`
}

type ReconEvidence struct {
	Kind   string `json:"kind"` // endpoint, route, traffic, form, script, inference
	Ref    string `json:"ref"`
	Detail string `json:"detail,omitempty"`
}

type ReconRole struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Privileges  []string        `json:"privileges,omitempty"`
	Confidence  float64         `json:"confidence"`
	Evidence    []ReconEvidence `json:"evidence,omitempty"`
}

type BusinessObject struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	Description  string          `json:"description,omitempty"`
	Identifiers  []string        `json:"identifiers,omitempty"`
	Operations   []string        `json:"operations,omitempty"`
	Sensitivity  string          `json:"sensitivity,omitempty"`
	OwnerRoleIDs []string        `json:"owner_role_ids,omitempty"`
	Confidence   float64         `json:"confidence"`
	Evidence     []ReconEvidence `json:"evidence,omitempty"`
}

type PagePurposeCard struct {
	ID               string          `json:"id"`
	Method           string          `json:"method"`
	URL              string          `json:"url"`
	Purpose          string          `json:"purpose"`
	Area             string          `json:"area"`
	AuthRequired     string          `json:"auth_required"`
	Inputs           []string        `json:"inputs,omitempty"`
	Actions          []string        `json:"actions,omitempty"`
	ObjectIDs        []string        `json:"object_ids,omitempty"`
	SecurityInterest []string        `json:"security_interest,omitempty"`
	Confidence       float64         `json:"confidence"`
	Evidence         []ReconEvidence `json:"evidence,omitempty"`
}

type WorkflowStep struct {
	ID          string   `json:"id"`
	Label       string   `json:"label"`
	PageIDs     []string `json:"page_ids,omitempty"`
	ObjectIDs   []string `json:"object_ids,omitempty"`
	RoleIDs     []string `json:"role_ids,omitempty"`
	StateChange bool     `json:"state_change,omitempty"`
}

type BusinessWorkflow struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Steps       []WorkflowStep  `json:"steps"`
	Confidence  float64         `json:"confidence"`
	Evidence    []ReconEvidence `json:"evidence,omitempty"`
}

type OwnershipBoundary struct {
	ID          string          `json:"id"`
	ObjectID    string          `json:"object_id"`
	OwnerRoleID string          `json:"owner_role_id,omitempty"`
	Rule        string          `json:"rule"`
	EnforcedAt  []string        `json:"enforced_at,omitempty"`
	Confidence  float64         `json:"confidence"`
	Evidence    []ReconEvidence `json:"evidence,omitempty"`
}

type ReconUnknown struct {
	ID              string          `json:"id"`
	Question        string          `json:"question"`
	WhyItMatters    string          `json:"why_it_matters,omitempty"`
	SuggestedAction string          `json:"suggested_action,omitempty"`
	Priority        int             `json:"priority"`
	Evidence        []ReconEvidence `json:"evidence,omitempty"`
}

// ReconTarget is a measurable definition of "understands the target app".
// Targets are recalculated from grounded model state, not supplied by the
// LLM. An unmet target doubles as a safe, bounded objective for ReconPlanner.
type ReconTarget struct {
	ID              string   `json:"id"`
	Label           string   `json:"label"`
	Target          float64  `json:"target"`
	Actual          float64  `json:"actual"`
	Unit            string   `json:"unit"`
	Met             bool     `json:"met"`
	Priority        int      `json:"priority"`
	Weight          int      `json:"weight"`
	WhyItMatters    string   `json:"why_it_matters"`
	SuggestedAction string   `json:"suggested_action"`
	EvidenceRefs    []string `json:"evidence_refs,omitempty"`
}

type ReconMetrics struct {
	OverallConfidence    float64 `json:"overall_confidence"`
	SemanticCoverage     float64 `json:"semantic_coverage"`
	UnderstandingScore   float64 `json:"understanding_score"`
	UnderstandingLevel   string  `json:"understanding_level"`
	TargetsMet           int     `json:"targets_met"`
	TargetsTotal         int     `json:"targets_total"`
	PurposeCoverage      float64 `json:"purpose_coverage"`
	CriticalPageCoverage float64 `json:"critical_page_coverage"`
	WorkflowCoverage     float64 `json:"workflow_coverage"`
	OwnershipCoverage    float64 `json:"ownership_coverage"`
	SynthesizedPageCount int     `json:"synthesized_page_count"`
	PagesModeled         int     `json:"pages_modeled"`
	RolesIdentified      int     `json:"roles_identified"`
	ObjectsIdentified    int     `json:"objects_identified"`
	WorkflowsModeled     int     `json:"workflows_modeled"`
	OwnershipModeled     int     `json:"ownership_modeled"`
	OpenQuestions        int     `json:"open_questions"`
}

func (u *AppUnderstanding) LoadReconJSON(raw string) {
	if u == nil || strings.TrimSpace(raw) == "" {
		return
	}
	_ = json.Unmarshal([]byte(raw), &u.Recon)
	u.NormalizeReconModel()
}

func (u *AppUnderstanding) ReconJSON() string {
	if u == nil {
		return "{}"
	}
	u.RecalculateReconMetrics()
	b, err := json.Marshal(u.Recon)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// RefreshPagePurposeCards grounds the semantic model in analyzed profiles.
// LLM synthesis may enrich roles/workflows later, but every page card keeps a
// direct endpoint reference so the UI never presents an untraceable claim.
func (u *AppUnderstanding) RefreshPagePurposeCards(profiles []types.PageProfile) {
	if u == nil {
		return
	}
	existing := make(map[string]PagePurposeCard, len(u.Recon.Pages))
	for _, p := range u.Recon.Pages {
		existing[p.ID] = p
	}
	pages := make([]PagePurposeCard, 0, len(profiles)+len(existing))
	for _, p := range profiles {
		if p.ID == "" || p.ID == "attack_surface" || p.ID == "js_discovered_routes" {
			continue
		}
		card := existing[p.ID]
		card.ID = p.ID
		card.Method = strings.ToUpper(strings.TrimSpace(p.Method))
		if card.Method == "" {
			card.Method = methodFromProfileID(p.ID)
		}
		card.URL = p.URL
		card.Purpose = p.Purpose
		card.Area, _ = ClassifyFunctionalArea(p.URL)
		card.AuthRequired = p.AuthRequired
		card.Confidence = p.Confidence
		if card.Confidence <= 0 {
			card.Confidence = 0.45
		}
		card.Inputs = profileInputNames(p)
		card.Actions = dedupeReconStrings(append(append([]string{}, card.Actions...), p.Behaviors...))
		card.SecurityInterest = dedupeReconStrings(append(append([]string{}, card.SecurityInterest...), p.Issues...))
		card.Evidence = mergeReconEvidence(card.Evidence, ReconEvidence{Kind: "endpoint", Ref: p.ID, Detail: p.URL})
		pages = append(pages, card)
	}
	// Routed cards are grounded directly in captured traffic or navigator
	// provenance rather than a separate endpoint profile. Preserve them across
	// periodic profile refreshes so a later save does not collapse distinct
	// router views back into one generic endpoint or SPA shell.
	for _, card := range existing {
		if routedPageCard(card) {
			pages = append(pages, card)
		}
	}
	sort.Slice(pages, func(i, j int) bool { return pages[i].ID < pages[j].ID })
	u.Recon.Pages = pages
	u.RecalculateReconMetrics()
}

// RefreshQueryRoutedPagePurposeCards projects response-distinct router views
// into the semantic page model. These are deterministic, traffic-grounded
// cards: route labels describe what was observed, while roles, privileges and
// state changes remain for the synthesis pass to prove or leave unknown.
func (u *AppUnderstanding) RefreshQueryRoutedPagePurposeCards(views []QueryRoutedView) {
	if u == nil {
		return
	}
	existing := make(map[string]PagePurposeCard, len(u.Recon.Pages))
	kept := make([]PagePurposeCard, 0, len(u.Recon.Pages)+len(views))
	for _, card := range u.Recon.Pages {
		existing[card.ID] = card
		if !queryRoutedPageCard(card) {
			kept = append(kept, card)
		}
	}
	for _, view := range views {
		if view.Label == "" || view.Parameter == "" || view.Path == "" || len(view.TrafficIDs) == 0 {
			continue
		}
		id := "GET " + view.Path + " [" + view.Parameter + ":" + strings.ReplaceAll(view.Label, " ", "_") + "]"
		card := existing[id]
		card.ID = id
		card.Method = "GET"
		card.URL = view.URL
		card.Purpose = queryRoutePurpose(view.Label, view.Parameter)
		card.Area, _ = ClassifyFunctionalArea(view.Path + " " + view.Label)
		card.AuthRequired = "unknown"
		card.Confidence = .82
		card.Inputs = dedupeReconStrings(append(card.Inputs, view.Parameter))
		card.Actions = dedupeReconStrings(append(card.Actions, "Select "+view.Label+" through the "+view.Parameter+" query router"))
		card.SecurityInterest = dedupeReconStrings(append(card.SecurityInterest, "Query-controlled page routing"))
		card.Evidence = nil
		for _, trafficID := range view.TrafficIDs {
			card.Evidence = append(card.Evidence, ReconEvidence{
				Kind: "query_route", Ref: fmt.Sprintf("traffic:%d", trafficID),
				Detail: fmt.Sprintf("Observed %s response selected by %s; response shape %s.", view.ResponseKind, view.Parameter, view.ShapeID),
			})
		}
		kept = append(kept, card)
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].ID < kept[j].ID })
	u.Recon.Pages = kept
	u.RecalculateReconMetrics()
}

func queryRoutedPageCard(card PagePurposeCard) bool {
	for _, evidence := range card.Evidence {
		if strings.EqualFold(strings.TrimSpace(evidence.Kind), "query_route") {
			return true
		}
	}
	return false
}

// RefreshClientRoutedPagePurposeCards projects only browser-visited SPA hash
// routes into the model. A discovered fragment link alone is insufficient;
// each card retains the navigator discovery row recording the browser-opened
// URL. This evidence does not by itself prove rendered content or route logic.
func (u *AppUnderstanding) RefreshClientRoutedPagePurposeCards(views []ClientRoutedView) {
	if u == nil {
		return
	}
	existing := make(map[string]PagePurposeCard, len(u.Recon.Pages))
	kept := make([]PagePurposeCard, 0, len(u.Recon.Pages)+len(views))
	for _, card := range u.Recon.Pages {
		existing[card.ID] = card
		if !clientRoutedPageCard(card) {
			kept = append(kept, card)
		}
	}
	for _, view := range views {
		if view.Label == "" || view.Route == "" || len(view.DiscoveryIDs) == 0 {
			continue
		}
		id := "UI #" + view.Route
		card := existing[id]
		card.ID = id
		card.Method = "GET"
		card.URL = view.URL
		card.Purpose = titleReconWords(view.Label) + " client-side page observed in the browser"
		card.Area, _ = ClassifyFunctionalArea(view.Route + " " + view.Label)
		card.AuthRequired = "unknown"
		card.Confidence = .78
		card.Actions = dedupeReconStrings(append(card.Actions, "Open the "+view.Label+" client-side route"))
		card.SecurityInterest = dedupeReconStrings(append(card.SecurityInterest, "Client-side route with route-specific application state"))
		card.Evidence = nil
		for _, discoveryID := range view.DiscoveryIDs {
			card.Evidence = append(card.Evidence, ReconEvidence{
				Kind: "client_route", Ref: fmt.Sprintf("discovery:%d", discoveryID),
				Detail: "Controlled browser opened the exact client-side route " + view.Route + ".",
			})
		}
		kept = append(kept, card)
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].ID < kept[j].ID })
	u.Recon.Pages = kept
	u.RecalculateReconMetrics()
}

func clientRoutedPageCard(card PagePurposeCard) bool {
	for _, evidence := range card.Evidence {
		if strings.EqualFold(strings.TrimSpace(evidence.Kind), "client_route") {
			return true
		}
	}
	return false
}

func routedPageCard(card PagePurposeCard) bool {
	return queryRoutedPageCard(card) || clientRoutedPageCard(card)
}

func queryRoutePurpose(label, parameter string) string {
	name := titleReconWords(label)
	if name == "" {
		name = "Observed"
	}
	return fmt.Sprintf("%s page selected by the %s query router", name, parameter)
}

func titleReconWords(value string) string {
	words := strings.Fields(strings.TrimSpace(value))
	for i, word := range words {
		if word != "" {
			words[i] = strings.ToUpper(word[:1]) + word[1:]
		}
	}
	return strings.Join(words, " ")
}

func (u *AppUnderstanding) RecalculateReconMetrics() {
	if u == nil {
		return
	}
	if strings.TrimSpace(u.AppType) != "" {
		u.Recon.Identity.AppType = strings.TrimSpace(u.AppType)
	}
	if strings.TrimSpace(u.Summary) != "" {
		u.Recon.Identity.Summary = strings.TrimSpace(u.Summary)
	}
	m := &u.Recon.Metrics
	// Rebuild every derived field. This matters when a persisted model loses a
	// workflow or boundary during grounding normalization.
	*m = ReconMetrics{SynthesizedPageCount: m.SynthesizedPageCount}
	m.PagesModeled = len(u.Recon.Pages)
	m.RolesIdentified = len(u.Recon.Roles)
	m.ObjectsIdentified = len(u.Recon.Objects)
	m.WorkflowsModeled = len(u.Recon.Workflows)
	m.OwnershipModeled = len(u.Recon.OwnershipBoundaries)
	m.OpenQuestions = len(u.Recon.Unknowns)
	var total float64
	var count int
	for _, p := range u.Recon.Pages {
		total += clampConfidence(p.Confidence)
		count++
	}
	for _, r := range u.Recon.Roles {
		total += clampConfidence(r.Confidence)
		count++
	}
	for _, o := range u.Recon.Objects {
		total += clampConfidence(o.Confidence)
		count++
	}
	for _, w := range u.Recon.Workflows {
		total += clampConfidence(w.Confidence)
		count++
	}
	for _, b := range u.Recon.OwnershipBoundaries {
		total += clampConfidence(b.Confidence)
		count++
	}
	if count > 0 {
		assertionConfidence := total / float64(count)
		coverage := 0.0
		if len(u.Recon.Pages) > 0 {
			coverage += .10
		}
		if len(u.Recon.Roles) > 0 {
			coverage += .20
		}
		if len(u.Recon.Objects) > 0 {
			coverage += .20
		}
		if len(u.Recon.Workflows) > 0 {
			coverage += .25
		}
		if len(u.Recon.OwnershipBoundaries) > 0 || reconOwnershipNotApplicable(u.Recon.Objects) {
			coverage += .15
		}
		if len(u.Recon.Unknowns) > 0 {
			coverage += .10
		}
		m.SemanticCoverage = coverage
		m.OverallConfidence = assertionConfidence * coverage
	}
	u.Recon.Targets = u.evaluateReconTargets()
	m.TargetsTotal = len(u.Recon.Targets)
	weightedScore := 0.0
	totalWeight := 0
	coreTargetsMet := true
	for _, target := range u.Recon.Targets {
		if target.Met {
			m.TargetsMet++
		}
		if target.ID != "actionable_unknowns" && !target.Met {
			coreTargetsMet = false
		}
		weight := target.Weight
		if weight <= 0 {
			continue
		}
		totalWeight += weight
		progress := 0.0
		if target.Target > 0 {
			progress = target.Actual / target.Target
		}
		if progress > 1 {
			progress = 1
		}
		if progress < 0 {
			progress = 0
		}
		weightedScore += progress * float64(weight)
	}
	if totalWeight > 0 {
		m.UnderstandingScore = weightedScore / float64(totalWeight)
	}
	m.UnderstandingLevel = "initial"
	if m.UnderstandingScore >= .60 {
		m.UnderstandingLevel = "developing"
	}
	if m.UnderstandingScore >= .85 {
		m.UnderstandingLevel = "strong"
	}
	if m.UnderstandingScore >= .85 && coreTargetsMet {
		m.UnderstandingLevel = "actionable"
	}
}

func reconOwnershipNotApplicable(objects []BusinessObject) bool {
	if len(objects) == 0 {
		return false
	}
	for _, object := range objects {
		if reconOwnershipCandidate(object) && hasGroundedReconEvidence(object.Evidence) {
			return false
		}
	}
	return true
}

func (u *AppUnderstanding) evaluateReconTargets() []ReconTarget {
	pages := u.Recon.Pages
	meaningfulPages := 0
	criticalPages := 0
	criticalPurposePages := 0
	mutatingPages := map[string]bool{}
	workflowMutatingPages := map[string]bool{}
	identifierPages := map[string]bool{}
	pageIdentifierNames := map[string][]string{}
	identifierOccurrences := map[string]int{}
	objectEvidencePages := map[string]bool{}
	criticalRefs := make([]string, 0)

	for _, page := range pages {
		if page.Area != "static" {
			meaningfulPages++
		}
		_, priority := ClassifyFunctionalArea(page.URL + " " + page.Purpose)
		critical := priority >= 7 || reconMutatingMethod(page.Method) || reconAuthRequired(page.AuthRequired)
		if critical {
			criticalPages++
			criticalRefs = append(criticalRefs, page.ID)
			if meaningfulPurposeCard(page) {
				criticalPurposePages++
			}
		}
		if reconMutatingMethod(page.Method) {
			mutatingPages[page.ID] = true
		}
		seenIdentifiers := map[string]bool{}
		for _, input := range page.Inputs {
			if reconIdentifierName(input) {
				name := strings.ToLower(strings.TrimSpace(input))
				if !seenIdentifiers[name] {
					seenIdentifiers[name] = true
					pageIdentifierNames[page.ID] = append(pageIdentifierNames[page.ID], name)
					identifierOccurrences[name]++
				}
			}
		}
	}
	for _, page := range pages {
		for _, identifier := range pageIdentifierNames[page.ID] {
			// A hidden viewingId/session-shaped field repeated in the same global
			// page chrome is not a distinct business-object surface on every URL.
			// Count rare identifiers and mutating endpoints; if all identifiers
			// are shared chrome, coverage falls back to exact grounded objects.
			sharedChrome := meaningfulPages >= 3 && identifierOccurrences[identifier]*100 >= meaningfulPages*60
			if !sharedChrome || reconMutatingMethod(page.Method) {
				identifierPages[page.ID] = true
				break
			}
		}
	}
	if criticalPages == 0 {
		for _, page := range pages {
			if page.Area == "static" {
				continue
			}
			criticalPages++
			criticalRefs = append(criticalRefs, page.ID)
			if meaningfulPurposeCard(page) {
				criticalPurposePages++
			}
		}
	}
	for _, workflow := range u.Recon.Workflows {
		for _, step := range workflow.Steps {
			for _, pageID := range step.PageIDs {
				if mutatingPages[pageID] {
					workflowMutatingPages[pageID] = true
				}
			}
		}
	}
	for _, object := range u.Recon.Objects {
		for _, ev := range object.Evidence {
			if ev.Kind == "endpoint" {
				objectEvidencePages[ev.Ref] = true
			}
		}
	}

	purposeCoverage := ratio(criticalPurposePages, criticalPages)
	u.Recon.Metrics.PurposeCoverage = ratio(countMeaningfulPurposeCards(pages), meaningfulPages)
	u.Recon.Metrics.CriticalPageCoverage = purposeCoverage

	workflowCoverage := 0.0
	if len(mutatingPages) > 0 {
		workflowCoverage = ratio(len(workflowMutatingPages), len(mutatingPages))
	} else if len(u.Recon.Workflows) > 0 {
		workflowCoverage = 1
	}
	u.Recon.Metrics.WorkflowCoverage = workflowCoverage

	objectCoverage := 0.0
	if len(identifierPages) > 0 {
		covered := 0
		for pageID := range identifierPages {
			if objectEvidencePages[pageID] {
				covered++
			}
		}
		objectCoverage = ratio(covered, len(identifierPages))
	} else if len(u.Recon.Objects) > 0 {
		grounded := 0
		for _, object := range u.Recon.Objects {
			if hasGroundedReconEvidence(object.Evidence) {
				grounded++
			}
		}
		objectCoverage = ratio(grounded, len(u.Recon.Objects))
	}

	ownershipCandidates := 0
	ownedCandidates := map[string]bool{}
	for _, object := range u.Recon.Objects {
		if reconOwnershipCandidate(object) && hasGroundedReconEvidence(object.Evidence) {
			ownershipCandidates++
		}
	}
	for _, boundary := range u.Recon.OwnershipBoundaries {
		// A page reference tells us where a rule would belong; it does not
		// prove that an owner-specific authorization check was enforced. Only
		// differential/verification evidence closes that gate. Public rules
		// without an owner role can still be grounded by direct page access.
		if len(boundary.EnforcedAt) > 0 && (boundary.OwnerRoleID == "" || hasVerifiedOwnershipEvidence(boundary.Evidence)) {
			ownedCandidates[boundary.ObjectID] = true
		}
	}
	ownershipCoverage := 0.0
	if ownershipCandidates > 0 {
		covered := 0
		for _, object := range u.Recon.Objects {
			if reconOwnershipCandidate(object) && hasGroundedReconEvidence(object.Evidence) && ownedCandidates[object.ID] {
				covered++
			}
		}
		ownershipCoverage = ratio(covered, ownershipCandidates)
	} else if len(u.Recon.Objects) > 0 {
		// Public, non-owned objects do not create an authorization boundary.
		ownershipCoverage = 1
	}
	u.Recon.Metrics.OwnershipCoverage = ownershipCoverage
	ownershipNextAction := reconOwnershipSuggestedAction(
		u.Recon.Objects, u.Recon.Roles, u.Recon.OwnershipBoundaries, ownedCandidates,
	)

	identityActual := 0.0
	identityType := strings.ToLower(strings.TrimSpace(u.Recon.Identity.AppType))
	identityType = strings.ReplaceAll(identityType, "-", "_")
	identityTypeGrounded := identityType != "" && identityType != "other" && identityType != "unknown" && identityType != "unclassified"
	if identityTypeGrounded && len(strings.Fields(u.Recon.Identity.Summary)) >= 6 {
		identityActual = 1
	}
	actorActual := 0.0
	actorRefs := make([]string, 0)
	for _, role := range u.Recon.Roles {
		if !hasGroundedReconEvidence(role.Evidence) {
			continue
		}
		actorActual = 1
		for _, ev := range role.Evidence {
			if ev.Ref != "" {
				actorRefs = append(actorRefs, ev.Ref)
			}
		}
	}
	objectTarget := .60
	if len(identifierPages) == 0 && len(u.Recon.Objects) == 0 {
		objectTarget = 1
	}

	targets := []ReconTarget{
		{ID: "application_identity", Label: "Application identity", Target: 1, Actual: identityActual, Unit: "gate", Priority: 10, Weight: 15,
			WhyItMatters:    "Testing choices depend on knowing the application's real purpose and security-relevant business areas.",
			SuggestedAction: "Analyze representative HTML/API pages and synthesize a grounded application type and summary."},
		{ID: "critical_purpose_coverage", Label: "Critical purpose coverage", Target: .80, Actual: purposeCoverage, Unit: "ratio", Priority: 9, Weight: 20,
			WhyItMatters:    "Authentication, account, admin, transaction, financial, upload, and API surfaces need a useful purpose before specialist testing.",
			SuggestedAction: "Navigate to and analyze the least-understood observed high-priority page.", EvidenceRefs: firstReconRefs(criticalRefs, 8)},
		{ID: "actor_model", Label: "Actor and privilege model", Target: 1, Actual: actorActual, Unit: "gate", Priority: 9, Weight: 15,
			WhyItMatters:    "Authorization testing needs explicit anonymous, authenticated, and privileged actors rather than an undifferentiated user.",
			SuggestedAction: "Inspect observed login, account, membership, and privileged UI affordances and record only evidence-backed roles.", EvidenceRefs: firstReconRefs(actorRefs, 8)},
		{ID: "business_object_coverage", Label: "Business object coverage", Target: objectTarget, Actual: objectCoverage, Unit: "ratio", Priority: 8, Weight: 15,
			WhyItMatters:    "Object identifiers and sensitive records are the bridge from endpoint enumeration to ownership and access-control tests.",
			SuggestedAction: "Inspect identifier-bearing pages and API responses, then link grounded business objects to their exact page evidence.", EvidenceRefs: firstReconMapRefs(identifierPages, 8)},
		{ID: "workflow_grounding", Label: "Grounded workflow coverage", Target: .60, Actual: workflowCoverage, Unit: "ratio", Priority: 9, Weight: 20,
			WhyItMatters:    "Business-logic testing requires observed human journeys and real state transitions, not neighboring GET routes.",
			SuggestedAction: "Follow the primary observed journey and capture the controls or requests that connect its state transitions.", EvidenceRefs: firstReconMapRefs(mutatingPages, 8)},
		{ID: "ownership_boundaries", Label: "Ownership boundary coverage", Target: .50, Actual: ownershipCoverage, Unit: "ratio", Priority: 8, Weight: 10,
			WhyItMatters:    "User-, account-, and tenant-owned objects need an explicit authorization invariant before BOLA/IDOR reasoning is actionable.",
			SuggestedAction: ownershipNextAction},
		{ID: "claim_confidence", Label: "Evidence confidence", Target: .85, Actual: u.Recon.Metrics.OverallConfidence, Unit: "ratio", Priority: 9, Weight: 20,
			WhyItMatters:    "A complete-looking model is unsafe when its claims are mostly low-confidence inference.",
			SuggestedAction: "Replace the lowest-confidence inferred claims with direct endpoint, traffic, or workflow evidence."},
	}

	unmetCore := 0
	for i := range targets {
		targets[i].Met = targets[i].Actual >= targets[i].Target
		if !targets[i].Met {
			unmetCore++
		}
	}
	actionableUnknowns := 0
	for _, unknown := range u.Recon.Unknowns {
		if unknown.Priority >= 6 && strings.TrimSpace(unknown.SuggestedAction) != "" {
			actionableUnknowns++
		}
	}
	unknownActual := 1.0
	if unmetCore > 0 {
		unknownActual = ratio(actionableUnknowns, unmetCore)
	}
	unknownTarget := ReconTarget{ID: "actionable_unknowns", Label: "Actionable uncertainty queue", Target: .80, Actual: unknownActual, Unit: "ratio", Priority: 7, Weight: 5,
		WhyItMatters:    "Remaining uncertainty should produce a specific next recon action instead of silently lowering confidence.",
		SuggestedAction: "Turn each high-impact model gap into a prioritized question with a safe next action."}
	unknownTarget.Met = unknownTarget.Actual >= unknownTarget.Target
	return append(targets, unknownTarget)
}

func reconOwnershipSuggestedAction(objects []BusinessObject, roles []ReconRole, boundaries []OwnershipBoundary, covered map[string]bool) string {
	roleNames := make(map[string]string, len(roles))
	for _, role := range roles {
		roleNames[role.ID] = strings.TrimSpace(role.Name)
	}
	boundaryByObject := make(map[string]OwnershipBoundary, len(boundaries))
	for _, boundary := range boundaries {
		if _, exists := boundaryByObject[boundary.ObjectID]; !exists {
			boundaryByObject[boundary.ObjectID] = boundary
		}
	}
	for _, object := range objects {
		if !reconOwnershipCandidate(object) || !hasGroundedReconEvidence(object.Evidence) || covered[object.ID] {
			continue
		}
		objectName := strings.TrimSpace(object.Name)
		if objectName == "" {
			objectName = object.ID
		}
		boundary, hasBoundary := boundaryByObject[object.ID]
		owner := roleNames[boundary.OwnerRoleID]
		if owner == "" {
			owner = boundary.OwnerRoleID
		}
		location := "the exact object endpoint"
		if len(boundary.EnforcedAt) > 0 {
			location = boundary.EnforcedAt[0]
		}
		if !hasBoundary || strings.TrimSpace(boundary.OwnerRoleID) == "" {
			return fmt.Sprintf("For %s, first capture an authenticated object request at %s and identify a stable owner or tenant marker. Then add a second scoped persona with a different owned object before testing any cross-owner access.", objectName, location)
		}
		return fmt.Sprintf("For %s owned by %s, capture two scoped personas with distinct owner markers at %s. Compare the positive controls A→A and B→B, the anonymous negative control anon→B, then A→B; only a differential response that still proves B ownership verifies this boundary.", objectName, owner, location)
	}
	return "No per-user ownership proof is required for the modeled public read-only objects; revisit this gate only if authenticated, sensitive, or mutable object evidence appears."
}

func hasGroundedReconEvidence(evidence []ReconEvidence) bool {
	for _, ev := range evidence {
		if strings.TrimSpace(ev.Ref) == "" || strings.EqualFold(strings.TrimSpace(ev.Ref), "gap") {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(ev.Kind), "inference") {
			return true
		}
	}
	return false
}

func meaningfulPurposeCard(page PagePurposeCard) bool {
	purpose := strings.TrimSpace(page.Purpose)
	return purpose != "" && !strings.EqualFold(purpose, "unknown") && page.Confidence >= .50
}

func countMeaningfulPurposeCards(pages []PagePurposeCard) int {
	count := 0
	for _, page := range pages {
		if page.Area != "static" && meaningfulPurposeCard(page) {
			count++
		}
	}
	return count
}

func reconMutatingMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

func reconAuthRequired(raw string) bool {
	lower := strings.ToLower(strings.TrimSpace(raw))
	return lower != "" && lower != "none" && lower != "no" && lower != "public" && lower != "unknown"
}

func reconIdentifierName(raw string) bool {
	lower := strings.ToLower(strings.TrimSpace(raw))
	return lower == "id" || lower == "uuid" || lower == "uid" || strings.HasSuffix(lower, "_id") || strings.HasSuffix(lower, "id")
}

func reconSensitiveObject(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "personal", "financial", "secret":
		return true
	default:
		return false
	}
}

func reconOwnershipCandidate(object BusinessObject) bool {
	// Login/authentication forms and search descriptors are observed UI
	// artifacts, not per-user records. Their input names must not manufacture
	// an IDOR prerequisite for the form itself.
	if reconInteractionArtifactObject(object) {
		return false
	}
	if reconSensitiveObject(object.Sensitivity) {
		// Public directories may contain personal contact data without exposing
		// an owner-addressable record. Keep the privacy sensitivity, but do not
		// manufacture a cross-persona BOLA prerequisite from one public GET path.
		// A stable record/owner identifier or any write operation still keeps the
		// object in ownership analysis.
		if reconOnlyReadOperations(object.Operations) && len(object.OwnerRoleIDs) == 0 && !reconHasOwnerAddressableIdentifier(object.Identifiers) {
			return false
		}
		return true
	}
	if reconPublicReadOnlyObject(object) {
		return false
	}
	return len(object.Identifiers) > 0
}

func reconInteractionArtifactObject(object BusinessObject) bool {
	text := strings.ToLower(strings.Join([]string{object.ID, object.Name, object.Description}, " "))
	return containsReconSignal(text,
		"login form", "login_form", "sign-in form", "signin form", "authentication form",
		"login session", "login_session", "session cookie", "auth cookie",
		"registration form", "password reset form", "feedback form", "feedback survey", "survey form",
		"contact submission", "contact form submission", "newsletter subscription", "mailing list subscription",
		"opensearch descriptor", "search descriptor")
}

func reconOnlyReadOperations(operations []string) bool {
	if len(operations) == 0 {
		return false
	}
	for _, operation := range operations {
		switch strings.ToLower(strings.TrimSpace(operation)) {
		case "read", "view", "list", "search", "browse", "download", "filter", "sort":
		default:
			return false
		}
	}
	return true
}

func reconHasOwnerAddressableIdentifier(identifiers []string) bool {
	for _, identifier := range identifiers {
		lower := strings.ToLower(strings.TrimSpace(identifier))
		if reconIdentifierName(lower) || containsReconSignal(lower,
			"_id", " id", "uuid", "owner", "account", "tenant", "customer", "user", "record", "order", "email") {
			return true
		}
	}
	return false
}

func reconPresentationArtifactObject(object BusinessObject) bool {
	text := strings.ToLower(strings.Join([]string{object.ID, object.Name, object.Description}, " "))
	return containsReconSignal(text,
		"pagination control", "pagination_controls", "navigation sidebar", "category_navigation",
		"breadcrumb", "footer navigation", "header navigation")
}

// Public read-only catalog and documentation objects may have stable path or
// slug identifiers, but those identifiers do not imply per-user ownership.
// Treating them as owned resources creates a fake BOLA/IDOR coverage gap on
// public sites. Unknown, mutable, or sensitive objects remain candidates.
func reconPublicReadOnlyObject(object BusinessObject) bool {
	if !strings.EqualFold(strings.TrimSpace(object.Sensitivity), "public") || len(object.Operations) == 0 {
		return false
	}
	for _, operation := range object.Operations {
		normalized := strings.ToLower(strings.TrimSpace(operation))
		switch normalized {
		case "read", "view", "list", "search", "browse", "download", "filter", "sort":
		default:
			// Models sometimes preserve a nearby UI affordance as an
			// unclassified "other:" operation on the displayed public object
			// (for example, Event + "other: RSVP"). That does not prove the
			// public object itself became an owned record. Require an explicit
			// create/update/delete operation before opening a BOLA prerequisite.
			if strings.HasPrefix(normalized, "other:") {
				continue
			}
			return false
		}
	}
	return true
}

func normalizeReconPublicReadOnlyObject(object *BusinessObject, pages []PagePurposeCard) {
	if object == nil || len(object.OwnerRoleIDs) > 0 || len(object.Operations) == 0 {
		return
	}
	switch strings.ToLower(strings.TrimSpace(object.Sensitivity)) {
	case "personal", "financial", "secret":
		return
	}
	probe := *object
	probe.Sensitivity = "public"
	if !reconPublicReadOnlyObject(probe) {
		return
	}
	pageByID := make(map[string]PagePurposeCard, len(pages))
	for _, page := range pages {
		pageByID[page.ID] = page
	}
	for _, evidence := range object.Evidence {
		if !strings.EqualFold(strings.TrimSpace(evidence.Kind), "endpoint") {
			continue
		}
		page, ok := pageByID[evidence.Ref]
		if !ok || !strings.EqualFold(strings.TrimSpace(page.Method), "GET") || reconAuthRequired(page.AuthRequired) {
			continue
		}
		text := strings.ToLower(page.Purpose + " " + page.URL)
		if containsReconSignal(text, "public", "without authentication", "no authentication required", "anonymous") {
			object.Sensitivity = "public"
			return
		}
	}
}

// A form rendered by a GET page proves that a write affordance exists, not
// that the application accepted the write. Keep read/search semantics from
// the page, but require an exact mutating profile before retaining create,
// update, delete, or equivalent operations on the business object.
func normalizeReconObjectOperationsFromPages(object *BusinessObject, pages []PagePurposeCard) {
	if object == nil || len(object.Operations) == 0 {
		return
	}
	pageByID := make(map[string]PagePurposeCard, len(pages))
	for _, page := range pages {
		pageByID[page.ID] = page
	}
	hasObservedMutation := false
	for _, evidence := range object.Evidence {
		if !strings.EqualFold(strings.TrimSpace(evidence.Kind), "endpoint") {
			continue
		}
		if page, ok := pageByID[evidence.Ref]; ok && reconMutatingMethod(page.Method) {
			hasObservedMutation = true
			break
		}
	}
	if hasObservedMutation {
		return
	}
	kept := object.Operations[:0]
	for _, operation := range object.Operations {
		if reconMutationOperation(operation) {
			continue
		}
		kept = append(kept, operation)
	}
	object.Operations = kept
}

func reconMutationOperation(operation string) bool {
	text := strings.ToLower(strings.TrimSpace(operation))
	return containsReconSignal(" "+text+" ",
		" create ", " update ", " delete ", " edit ", " publish ", " submit ", " write ", " upload ",
		" manage ", " purchase ", " checkout ", " transfer ", " approve ", " vote ", " comment ", " post ")
}

func ratio(numerator, denominator int) float64 {
	if denominator <= 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}

func firstReconRefs(refs []string, limit int) []string {
	return firstReconMapRefs(func() map[string]bool {
		out := make(map[string]bool, len(refs))
		for _, ref := range refs {
			out[ref] = true
		}
		return out
	}(), limit)
}

func firstReconMapRefs(refs map[string]bool, limit int) []string {
	out := make([]string, 0, len(refs))
	for ref := range refs {
		if strings.TrimSpace(ref) != "" {
			out = append(out, ref)
		}
	}
	sort.Strings(out)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// NormalizeReconModel removes dangling semantic edges and cross-links workflow
// steps back into page cards. This is the trust boundary between probabilistic
// synthesis and the deterministic UI/planner: the LLM may explain a model, but
// it cannot create graph references to pages AOBTD never observed.
func (u *AppUnderstanding) NormalizeReconModel() {
	if u == nil {
		return
	}
	rawSummary := u.Recon.Identity.Summary
	if strings.TrimSpace(rawSummary) == "" {
		rawSummary = u.Summary
	}
	normalizedSummary := normalizeReconLinkedOnlySummary(rawSummary)
	u.Recon.Identity.Summary = normalizedSummary
	u.Summary = normalizedSummary
	var appEvidence strings.Builder
	for _, page := range u.Recon.Pages {
		fmt.Fprintf(&appEvidence, "%s %s %s %s\n", page.URL, page.Purpose, page.Area, strings.Join(page.Actions, " "))
	}
	rawAppType := u.Recon.Identity.AppType
	if strings.TrimSpace(rawAppType) == "" {
		rawAppType = u.AppType
	}
	normalizedAppType := NormalizeReconAppTypeForTarget(
		rawAppType, u.Recon.Identity.Summary, appEvidence.String(), dominantReconTarget(u.Recon.Pages))
	u.Recon.Identity.AppType = normalizedAppType
	// RecalculateReconMetrics intentionally keeps the legacy top-level fields
	// synchronized into Recon identity. Update both sides here so that sync does
	// not undo deterministic target-host normalization at the end of this pass.
	u.AppType = normalizedAppType
	pages := map[string]int{}
	roles := map[string]bool{}
	objects := map[string]bool{}
	objectEvidencePages := map[string]map[string]bool{}
	for i, p := range u.Recon.Pages {
		pages[p.ID] = i
	}
	u.Recon.Roles = uniqueReconRoles(u.Recon.Roles)
	ensureObservedPublicVisitor(&u.Recon)
	groundReconRolesFromObservedPages(&u.Recon)
	unsupportedPrivilegedRoles := make(map[string]ReconRole)
	groundedRoles := make([]ReconRole, 0, len(u.Recon.Roles))
	for i := range u.Recon.Roles {
		u.Recon.Roles[i].Evidence = canonicalizeReconEvidence(u.Recon.Roles[i].Evidence, u.Recon.Pages)
		r := u.Recon.Roles[i]
		// A route token such as /admin, an inference-only `gap`, or an
		// unresolved model reference cannot create a privileged actor in the
		// deterministic application graph. Preserve the useful hypothesis as an
		// explicit unknown below, but require one exact page/request reference
		// before the role itself is allowed across this trust boundary.
		if reconPrivilegedRole(r) && !hasGroundedPrivilegedRoleEvidence(r.Evidence) {
			unsupportedPrivilegedRoles[r.ID] = r
			continue
		}
		normalizeReconAuthenticatedRole(&r)
		if reconMostlyPublicContentType(normalizedAppType) && !hasGroundedReconEvidence(r.Evidence) {
			continue
		}
		roles[r.ID] = true
		groundedRoles = append(groundedRoles, r)
	}
	u.Recon.Roles = groundedRoles
	demoteUnsupportedPrivilegedRolesToUnknowns(&u.Recon, unsupportedPrivilegedRoles)
	u.Recon.Objects = uniqueReconObjects(u.Recon.Objects)
	groundReconObjectsFromObservedPages(&u.Recon)
	groundedObjects := make([]BusinessObject, 0, len(u.Recon.Objects))
	for i := range u.Recon.Objects {
		if reconPresentationArtifactObject(u.Recon.Objects[i]) {
			continue
		}
		u.Recon.Objects[i].Evidence = canonicalizeReconEvidence(u.Recon.Objects[i].Evidence, u.Recon.Pages)
		normalizeReconObjectOperationsFromPages(&u.Recon.Objects[i], u.Recon.Pages)
		normalizeReconPublicReadOnlyObject(&u.Recon.Objects[i], u.Recon.Pages)
		o := u.Recon.Objects[i]
		o.OwnerRoleIDs = filterKnownIDs(o.OwnerRoleIDs, func(id string) bool { return roles[id] })
		if reconMostlyPublicContentType(normalizedAppType) && !hasGroundedReconEvidence(o.Evidence) {
			continue
		}
		objects[o.ID] = true
		refs := map[string]bool{}
		for _, ev := range o.Evidence {
			if ev.Kind == "endpoint" {
				refs[ev.Ref] = true
			}
		}
		objectEvidencePages[o.ID] = refs
		groundedObjects = append(groundedObjects, o)
	}
	u.Recon.Objects = groundedObjects

	workflows := make([]BusinessWorkflow, 0, len(u.Recon.Workflows))
	seenWorkflow := map[string]bool{}
	droppedWorkflowTransition := false
	for _, w := range u.Recon.Workflows {
		// Rebuild our own one-page fallback on every normalization pass. A
		// later capture—or improved ranking—may provide a much more human
		// representative entry page than the utility page available earlier.
		if strings.HasPrefix(w.ID, "observed_read_journey") && w.Description == "One-step read-only journey synthesized from a directly observed page." {
			continue
		}
		if w.ID == "" || w.Name == "" || seenWorkflow[w.ID] {
			continue
		}
		seenWorkflow[w.ID] = true
		w.Confidence = clampConfidence(w.Confidence)
		w.Evidence = canonicalizeReconEvidence(w.Evidence, u.Recon.Pages)
		groundedSteps := make([]WorkflowStep, 0, len(w.Steps))
		for si := range w.Steps {
			step := &w.Steps[si]
			step.PageIDs = canonicalPageRefs(step.PageIDs, u.Recon.Pages)
			if len(step.PageIDs) == 0 {
				continue
			}
			step.RoleIDs = filterKnownIDs(step.RoleIDs, func(id string) bool { return roles[id] })
			step.ObjectIDs = filterKnownIDs(step.ObjectIDs, func(id string) bool {
				if !objects[id] {
					return false
				}
				if len(step.PageIDs) == 0 {
					return true
				}
				for _, pageID := range step.PageIDs {
					if objectEvidencePages[id][pageID] {
						return true
					}
				}
				return false
			})
			if step.StateChange {
				mutating := false
				for _, pageID := range step.PageIDs {
					method := strings.ToUpper(u.Recon.Pages[pages[pageID]].Method)
					if method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE" {
						mutating = true
						break
					}
				}
				if !mutating {
					step.StateChange = false
				}
			}
			groundedSteps = append(groundedSteps, *step)
		}
		readOnlySteps := make([]WorkflowStep, 0, len(groundedSteps))
		for _, step := range groundedSteps {
			if workflowStepClaimsMutation(step) && !workflowStepHasMutationPage(step, u.Recon.Pages, pages) {
				droppedWorkflowTransition = true
				continue
			}
			readOnlySteps = append(readOnlySteps, step)
		}
		w.Steps = readOnlySteps
		if len(w.Steps) == 0 {
			continue
		}
		if reconWorkflowOnlyUsesUtilityPages(w, u.Recon.Pages, pages) {
			continue
		}
		if workflowClaimsUngroundedTransition(w, u.Recon.Pages, pages) {
			droppedWorkflowTransition = true
			w.Name = observedWorkflowEntryName(w.Steps[0])
			w.Description = "Observed read-only entry point; state-changing transition not captured."
			if w.Confidence > .55 {
				w.Confidence = .55
			}
		}
		for _, step := range w.Steps {
			for _, pageID := range step.PageIDs {
				idx := pages[pageID]
				u.Recon.Pages[idx].ObjectIDs = dedupeReconStrings(append(u.Recon.Pages[idx].ObjectIDs, step.ObjectIDs...))
				if step.Label != "" {
					u.Recon.Pages[idx].Actions = dedupeReconStrings(append(u.Recon.Pages[idx].Actions, step.Label))
				}
			}
		}
		workflows = append(workflows, w)
	}
	u.Recon.Workflows = workflows
	u.Recon.Workflows = supplementReadOnlyWorkflows(u.Recon.Pages, u.Recon.Workflows, 3)

	boundaries := make([]OwnershipBoundary, 0, len(u.Recon.OwnershipBoundaries))
	seenBoundary := map[string]bool{}
	for _, b := range u.Recon.OwnershipBoundaries {
		if b.ID == "" || b.Rule == "" || !objects[b.ObjectID] || seenBoundary[b.ID] {
			continue
		}
		// A rule explicitly owned by a demoted privileged actor would preserve
		// the same unsupported semantic claim under a different card. Drop that
		// dependent boundary; ownerless/public rules remain unaffected.
		if _, demoted := unsupportedPrivilegedRoles[b.OwnerRoleID]; demoted {
			continue
		}
		if b.OwnerRoleID != "" && !roles[b.OwnerRoleID] {
			b.OwnerRoleID = ""
		}
		b.Evidence = canonicalizeReconEvidence(b.Evidence, u.Recon.Pages)
		b.EnforcedAt = canonicalPageRefs(b.EnforcedAt, u.Recon.Pages)
		if len(b.EnforcedAt) == 0 {
			for _, ev := range b.Evidence {
				if ev.Kind == "endpoint" {
					b.EnforcedAt = append(b.EnforcedAt, ev.Ref)
				}
			}
			b.EnforcedAt = canonicalPageRefs(b.EnforcedAt, u.Recon.Pages)
		}
		b.Confidence = clampConfidence(b.Confidence)
		verified := hasVerifiedOwnershipEvidence(b.Evidence)
		if b.OwnerRoleID != "" && !verified && b.Confidence > .45 {
			b.Confidence = .45
		}
		if !verified && b.Confidence > .75 {
			b.Confidence = .75
		}
		seenBoundary[b.ID] = true
		boundaries = append(boundaries, b)
	}
	u.Recon.OwnershipBoundaries = boundaries

	unknowns := make([]ReconUnknown, 0, len(u.Recon.Unknowns))
	seenUnknown := map[string]bool{}
	observedHosts := reconObservedHosts(u.Recon.Pages)
	observedPaths := reconObservedPaths(u.Recon.Pages)
	hasNonSyntheticWorkflowUnknown := false
	for _, q := range u.Recon.Unknowns {
		text := strings.ToLower(q.Question + " " + q.SuggestedAction)
		if q.ID != "workflow_grounding_gap" && (strings.Contains(text, "workflow") || strings.Contains(text, "state-changing")) {
			hasNonSyntheticWorkflowUnknown = true
		}
	}
	for _, q := range u.Recon.Unknowns {
		if q.ID == "" || q.Question == "" || seenUnknown[q.ID] {
			continue
		}
		if q.ID == "workflow_grounding_gap" && hasNonSyntheticWorkflowUnknown {
			continue
		}
		if q.Priority < 1 {
			q.Priority = 1
		}
		if q.Priority > 10 {
			q.Priority = 10
		}
		q.Evidence = canonicalizeReconEvidence(q.Evidence, u.Recon.Pages)
		if host := reconUnobservedSuggestedHost(q.SuggestedAction, observedHosts); host != "" {
			q.SuggestedAction = fmt.Sprintf("Use an exact discovered in-scope URL to answer this question; %s was not observed in target traffic, so do not guess or expand scope.", host)
		} else if path := reconUnobservedSuggestedPath(q.SuggestedAction, observedPaths); path != "" {
			q.SuggestedAction = fmt.Sprintf("Inspect current evidence for an exact discovered in-scope route that answers this question; %s was not observed, so do not guess or enumerate it during Recon.", path)
		} else if reconSuggestedActionGuessesRouteVariant(q.SuggestedAction) {
			q.SuggestedAction = "Choose an exact discovered in-scope URL from current evidence; do not synthesize a .json suffix, extension, or neighboring route during Recon."
		} else if reconSuggestedActionNeedsActive(q.SuggestedAction) {
			q.SuggestedAction = "Map the exact observed route, form, and surrounding read-only behavior in Recon; reserve the state-changing or high-volume check for a separate operator-authorized Active run."
		}
		seenUnknown[q.ID] = true
		unknowns = append(unknowns, q)
	}
	u.Recon.Unknowns = unknowns
	hasWorkflowUnknown := seenUnknown["workflow_grounding_gap"]
	for _, q := range u.Recon.Unknowns {
		text := strings.ToLower(q.Question + " " + q.SuggestedAction)
		if strings.Contains(text, "workflow") || strings.Contains(text, "state-changing") {
			hasWorkflowUnknown = true
			break
		}
	}
	if len(u.Recon.Workflows) == 0 && len(u.Recon.Pages) > 0 && !hasWorkflowUnknown && !droppedWorkflowTransition {
		u.Recon.Unknowns = append(u.Recon.Unknowns, ReconUnknown{
			ID: "workflow_grounding_gap", Priority: 8,
			Question:        "Which observed pages form a complete end-to-end business workflow?",
			WhyItMatters:    "Business-logic testing needs grounded state transitions rather than adjacency guesses from read-only endpoints.",
			SuggestedAction: "Navigate the primary user journey and capture its POST, PUT, PATCH, or DELETE transitions.",
			Evidence:        []ReconEvidence{{Kind: "inference", Ref: "gap", Detail: "No workflow survived page-level grounding."}},
		})
	}
	if droppedWorkflowTransition && !seenUnknown["workflow_transition_evidence_gap"] {
		u.Recon.Unknowns = append(u.Recon.Unknowns, ReconUnknown{
			ID: "workflow_transition_evidence_gap", Priority: 9,
			Question:        "Which request proves the modeled state-changing workflow transition?",
			WhyItMatters:    "A read-only entry page does not prove the described write completed.",
			SuggestedAction: "Map the form in Recon and reserve the mutation for a separate operator-authorized Active run.",
			Evidence:        []ReconEvidence{{Kind: "inference", Ref: "gap", Detail: "A mutation-claiming workflow referenced only read-only pages."}},
		})
	}
	u.RecalculateReconMetrics()
}

func reconMostlyPublicContentType(appType string) bool {
	switch strings.ToLower(strings.TrimSpace(appType)) {
	case "documentation", "knowledge_base", "news_media", "status_dashboard", "product_catalog", "content_catalog", "government_portal":
		return true
	default:
		return false
	}
}

func ensureObservedPublicVisitor(recon *ReconModel) {
	if recon == nil || len(recon.Roles) > 0 {
		return
	}
	best := -1
	bestScore := -1.0
	for i, page := range recon.Pages {
		method := strings.ToUpper(strings.TrimSpace(page.Method))
		if method == "" && strings.HasPrefix(strings.ToUpper(strings.TrimSpace(page.ID)), "GET ") {
			method = "GET"
		}
		if method != "GET" || reconAuthRequired(page.AuthRequired) || !meaningfulPurposeCard(page) || reconUtilityPage(page) {
			continue
		}
		score := reconAnonymousRoleEvidenceScore(page)
		if best < 0 || score > bestScore {
			best, bestScore = i, score
		}
	}
	if best < 0 {
		return
	}
	page := recon.Pages[best]
	confidence := page.Confidence
	if confidence <= 0 || confidence > .85 {
		confidence = .85
	}
	recon.Roles = append(recon.Roles, ReconRole{
		ID: "public_visitor", Name: "Public Visitor",
		Description: "Unauthenticated visitor to the observed public application surface.",
		Privileges:  []string{"View observed public pages"}, Confidence: confidence,
		Evidence: []ReconEvidence{{Kind: "endpoint", Ref: page.ID,
			Detail: "Observed GET page was publicly reachable without authentication."}},
	})
}

func reconObservedHosts(pages []PagePurposeCard) map[string]bool {
	hosts := make(map[string]bool)
	for _, page := range pages {
		parsed, err := url.Parse(strings.TrimSpace(page.URL))
		if err == nil && parsed.Hostname() != "" {
			hosts[strings.ToLower(parsed.Hostname())] = true
		}
	}
	return hosts
}

func reconObservedPaths(pages []PagePurposeCard) map[string]bool {
	paths := make(map[string]bool)
	for _, page := range pages {
		if parsed, err := url.Parse(strings.TrimSpace(page.URL)); err == nil && parsed.Path != "" {
			paths[strings.ToLower(parsed.Path)] = true
		}
		if path := reconRefPath(page.ID); path != "" {
			paths[strings.ToLower(path)] = true
		}
	}
	return paths
}

func reconUnobservedSuggestedPath(action string, observed map[string]bool) string {
	for _, raw := range strings.Fields(action) {
		token := strings.Trim(raw, "\"'`()[]{}<>,;:.")
		if len(token) < 2 || !strings.HasPrefix(token, "/") || strings.HasPrefix(token, "//") {
			continue
		}
		if query := strings.IndexByte(token, '?'); query >= 0 {
			token = token[:query]
		}
		path := strings.ToLower(strings.TrimSuffix(token, "/"))
		if path == "" {
			path = "/"
		}
		matched := observed[path]
		if !matched {
			for candidate := range observed {
				if strings.TrimSuffix(candidate, "/") == path {
					matched = true
					break
				}
			}
		}
		if !matched {
			return token
		}
	}
	return ""
}

func reconSuggestedActionNeedsActive(action string) bool {
	text := strings.ToLower(strings.TrimSpace(action))
	capturesMutation := strings.Contains(text, "capture") && containsReconSignal(text, " post ", " put ", " patch ", " delete ", "form submission")
	return capturesMutation || strings.HasPrefix(text, "submit ") || containsReconSignal(text,
		"brute-force", "bruteforce", "fuzz", "attempt post", "attempt put", "attempt patch", "attempt delete",
		"submit test", "submit a test", "submit one", "submit two", "submit form", "submit the form", "submission response",
		"form submission post", "intercept form submission", "from a different origin",
		"various id", "different id values", "multiple id", "initiate oauth",
		"open redirect", "external url", "external domain", "redirect to external", "redirect off-site",
		"enumerat", "test authentication flow", "test story token", "sequential story numbers",
		"inject", "payload", "exploit", "tamper", "authorization bypass", "cross-persona", "another user")
}

func reconSuggestedActionGuessesRouteVariant(action string) bool {
	text := strings.ToLower(strings.TrimSpace(action))
	return containsReconSignal(text,
		"append .json", "appending .json", "add .json", "adding .json", "try .json", ".json suffix", "json suffix",
		"append an extension", "change the extension", "replace the extension")
}

func reconUnobservedSuggestedHost(action string, observed map[string]bool) string {
	for _, raw := range strings.Fields(action) {
		token := strings.Trim(raw, "\"'`()[]{}<>,;:.")
		if token == "" {
			continue
		}
		// Models commonly embed an off-site probe inside a discovered callback,
		// for example /login?next=https://evil.example. url.Parse treats that
		// whole token as a relative path, so inspect the nested absolute URL
		// explicitly before applying the normal host check. Recon must never turn
		// such a hypothesis into an executable same-scope suggestion.
		lowerToken := strings.ToLower(token)
		for _, scheme := range []string{"https://", "http://"} {
			if offset := strings.Index(lowerToken, scheme); offset >= 0 {
				nested := strings.Trim(token[offset:], "\"'`()[]{}<>,;.")
				if parsed, err := url.Parse(nested); err == nil && parsed.Hostname() != "" {
					host := strings.ToLower(parsed.Hostname())
					if !observed[host] {
						return host
					}
				}
			}
		}
		candidate := token
		if !strings.Contains(candidate, "://") {
			if strings.Contains(candidate, "/") || !strings.Contains(candidate, ".") {
				continue
			}
			candidate = "//" + candidate
		}
		parsed, err := url.Parse(candidate)
		if err != nil || parsed.Hostname() == "" || !strings.Contains(parsed.Hostname(), ".") {
			continue
		}
		host := strings.ToLower(parsed.Hostname())
		if !observed[host] {
			return host
		}
	}
	return ""
}

func groundReconRolesFromObservedPages(recon *ReconModel) {
	if recon == nil {
		return
	}
	for roleIndex := range recon.Roles {
		role := &recon.Roles[roleIndex]
		if role.ID == "" || hasGroundedReconEvidence(role.Evidence) {
			continue
		}
		identity := strings.ToLower(role.ID + " " + role.Name)
		identity = strings.NewReplacer("unauthenticated", "anonymous", "un-authenticated", "anonymous").Replace(identity)
		anonymous := containsReconSignal(identity, "anonymous", "public visitor", "public user")
		authEntryActor := containsReconSignal(identity, "authenticated", "registered", "member") && !containsReconSignal(identity, "admin", "administrator", "owner", "maintainer")
		if !anonymous && !authEntryActor {
			continue
		}
		bestPage := -1
		bestScore := -1.0
		for pageIndex := range recon.Pages {
			page := recon.Pages[pageIndex]
			if page.ID == "" || page.Area == "static" || !meaningfulPurposeCard(page) {
				continue
			}
			text := strings.ToLower(page.URL + " " + page.Purpose + " " + page.Area)
			matches := anonymous
			if authEntryActor {
				matches = containsReconSignal(text, "/login", "/register", "/signup", "login page", "registration page", "authentication entry")
			}
			if !matches {
				continue
			}
			score := page.Confidence
			if anonymous {
				score = reconAnonymousRoleEvidenceScore(page)
			}
			if bestPage < 0 || score > bestScore {
				bestPage = pageIndex
				bestScore = score
			}
		}
		if bestPage < 0 {
			continue
		}
		detail := "Observed public page grounds this anonymous actor."
		if authEntryActor {
			detail = "Observed login or registration page grounds actor existence, not post-login privileges."
		}
		role.Evidence = append(role.Evidence, ReconEvidence{Kind: "endpoint", Ref: recon.Pages[bestPage].ID, Detail: detail})
	}
}

// Anonymous actor evidence should point at the page a person actually enters
// through, not a high-confidence utility document discovered beside it. This
// makes Target DNA useful at a glance while preserving the observed-only gate.
func reconAnonymousRoleEvidenceScore(page PagePurposeCard) float64 {
	score := page.Confidence
	parsed, err := url.Parse(page.URL)
	if err == nil {
		path := strings.ToLower(parsed.EscapedPath())
		if path == "" || path == "/" {
			score += 2
		}
		if containsReconSignal(path, ".xml", ".json", ".js", ".css", "favicon", "manifest", "robots.txt", "sitemap") {
			score -= 2
		}
	}
	if containsReconSignal(strings.ToLower(page.Purpose+" "+page.Area), "home page", "homepage", "landing page", "public feed", "main feed") {
		score += .5
	}
	return score
}

// A linked path is discovery evidence, not proof that the resource is exposed
// or reachable. Rewrite contradictory model sentences so the hero summary
// keeps the same evidence ceiling as the origin and route cards.
func normalizeReconLinkedOnlySummary(summary string) string {
	parts := strings.Split(strings.TrimSpace(summary), ".")
	for i, part := range parts {
		trimmed := strings.TrimSpace(part)
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "exposed ") && (strings.Contains(lower, " linked from ") || strings.Contains(lower, " link discovered")) {
			rest := strings.TrimSpace(trimmed[len("exposed "):])
			parts[i] = " Linked-only reference: " + rest + "; access was not observed"
		}
	}
	return strings.TrimSpace(strings.Join(parts, "."))
}

// A public login/signup affordance proves that an authenticated actor exists;
// it does not prove what that actor can do after login. Preserve the actor and
// its boundary evidence, but strip invented privileges until an authenticated
// request, authorization test, or verified session grounds them.
func normalizeReconAuthenticatedRole(role *ReconRole) {
	if role == nil {
		return
	}
	identity := strings.ToLower(role.ID + " " + role.Name)
	identity = strings.NewReplacer("unauthenticated", "anonymous", "un-authenticated", "anonymous").Replace(identity)
	privileged := reconPrivilegedRole(*role)
	if !containsReconSignal(identity, "authenticated", "logged-in", "logged in", "registered", "member", "admin", "owner", "moderator", "maintainer", "staff", "privileged") {
		return
	}
	for _, evidence := range role.Evidence {
		kind := strings.ToLower(strings.TrimSpace(evidence.Kind))
		if containsReconSignal(kind, "authenticated_request", "authorization_test", "verification", "verified_session", "credentialed") {
			return
		}
	}
	role.Privileges = nil
	if privileged {
		role.Description = "Role existence appears in public evidence; authenticated privileges and enforcement remain unknown."
		if role.Confidence > .65 {
			role.Confidence = .65
		}
		return
	}
	role.Description = "Authentication entry point observed; post-login capabilities remain unknown."
	if role.Confidence > .75 {
		role.Confidence = .75
	}
}

func reconPrivilegedRole(role ReconRole) bool {
	identity := strings.ToLower(strings.TrimSpace(role.ID + " " + role.Name))
	return containsReconSignal(identity,
		"admin", "administrator", "owner", "moderator", "maintainer", "staff", "privileged")
}

func hasGroundedPrivilegedRoleEvidence(evidence []ReconEvidence) bool {
	for _, item := range evidence {
		ref := strings.TrimSpace(item.Ref)
		if ref == "" || strings.EqualFold(ref, "gap") {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(item.Kind)) {
		case "endpoint", "authenticated_request", "authorization_test", "verification",
			"verified_session", "credentialed", "finding", "differential", "cross_persona":
			return true
		}
	}
	return false
}

// demoteUnsupportedPrivilegedRolesToUnknowns keeps a model hunch useful
// without presenting it as a discovered actor. Existing role-related unknowns
// are rewritten in place so repeated normalization is stable and does not
// grow a duplicate question queue.
func demoteUnsupportedPrivilegedRolesToUnknowns(model *ReconModel, roles map[string]ReconRole) {
	if model == nil || len(roles) == 0 {
		return
	}
	roleIDs := make([]string, 0, len(roles))
	for id := range roles {
		roleIDs = append(roleIDs, id)
	}
	sort.Strings(roleIDs)
	usedUnknowns := make(map[int]bool)
	for _, roleID := range roleIDs {
		role := roles[roleID]
		label := strings.TrimSpace(role.Name)
		if label == "" {
			label = strings.TrimSpace(role.ID)
		}
		if label == "" {
			label = "privileged actor"
		}
		question := fmt.Sprintf("Does the %s role exist, and what direct evidence proves it?", label)
		why := "No exact observed page, authenticated request, or authorization evidence currently grounds this privileged actor."
		next := "Capture a directly observed privileged affordance or an authenticated authorization response before adding this role to the actor model."

		matched := -1
		for i := range model.Unknowns {
			if usedUnknowns[i] || reconRedirectMechanicsUnknown(model.Unknowns[i]) ||
				!reconUnknownMentionsPrivilegedRole(model.Unknowns[i], role) {
				continue
			}
			matched = i
			break
		}
		if matched >= 0 {
			unknown := &model.Unknowns[matched]
			unknown.Question = question
			unknown.WhyItMatters = why
			unknown.SuggestedAction = next
			if unknown.Priority < 8 {
				unknown.Priority = 8
			}
			if len(unknown.Evidence) == 0 {
				unknown.Evidence = unsupportedPrivilegedRoleEvidence(role)
			}
			usedUnknowns[matched] = true
			continue
		}

		model.Unknowns = append(model.Unknowns, ReconUnknown{
			ID:              unsupportedPrivilegedRoleGapID(role),
			Question:        question,
			WhyItMatters:    why,
			SuggestedAction: next,
			Priority:        8,
			Evidence:        unsupportedPrivilegedRoleEvidence(role),
		})
	}
}

func reconRedirectMechanicsUnknown(unknown ReconUnknown) bool {
	text := strings.ToLower(strings.Join([]string{
		unknown.Question, unknown.WhyItMatters, unknown.SuggestedAction,
	}, " "))
	return containsReconSignal(text,
		"open redirect", "redirect parameter", "redirect target", "redirect chain",
		"redirect behavior", "redirect-only route", "location header")
}

func unsupportedPrivilegedRoleEvidence(role ReconRole) []ReconEvidence {
	label := strings.TrimSpace(role.Name)
	if label == "" {
		label = strings.TrimSpace(role.ID)
	}
	return []ReconEvidence{{
		Kind: "inference", Ref: "gap",
		Detail: fmt.Sprintf("%s was proposed without an exact supporting page or authenticated authorization observation.", label),
	}}
}

func unsupportedPrivilegedRoleGapID(role ReconRole) string {
	value := strings.ToLower(strings.TrimSpace(role.ID))
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
	})
	if len(parts) == 0 {
		parts = []string{"privileged_actor"}
	}
	return "privileged_role_evidence_gap_" + strings.Join(parts, "_")
}

func reconUnknownMentionsPrivilegedRole(unknown ReconUnknown, role ReconRole) bool {
	unknownWords := reconWordSet(strings.Join([]string{
		unknown.ID, unknown.Question, unknown.WhyItMatters, unknown.SuggestedAction,
	}, " "))
	roleWords := reconWordSet(role.ID + " " + role.Name)
	groups := [][]string{
		{"admin", "administrator", "administrative", "administration"},
		{"owner"}, {"moderator"}, {"maintainer"}, {"staff"}, {"privileged"},
	}
	for _, group := range groups {
		roleMatches := false
		for _, word := range group {
			roleMatches = roleMatches || roleWords[word]
		}
		if !roleMatches {
			continue
		}
		for _, word := range group {
			if unknownWords[word] {
				return true
			}
		}
	}
	return false
}

func reconWordSet(value string) map[string]bool {
	words := make(map[string]bool)
	for _, word := range strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
	}) {
		if word != "" {
			words[word] = true
		}
	}
	return words
}

// ApplyReconAccessCeiling prevents a block page, rate-limit response, or
// rendered SPA shell from masquerading as application understanding. The
// access-layer identity and unanswered questions remain useful, but semantic
// actors, business objects, journeys, and ownership rules require
// representative target evidence.
func (u *AppUnderstanding) ApplyReconAccessCeiling(access string) {
	if u == nil {
		return
	}
	state := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(access), "_", "-"))
	if state == "" || state == "available" {
		return
	}
	switch state {
	case "limited", "rate-limited", "blocked", "protected", "unavailable":
	default:
		return
	}
	u.Recon.Roles = nil
	u.Recon.Objects = nil
	u.Recon.Workflows = nil
	u.Recon.OwnershipBoundaries = nil
	for i := range u.Recon.Pages {
		u.Recon.Pages[i].ObjectIDs = nil
		u.Recon.Pages[i].Area = "static"
		u.Recon.Pages[i].AuthRequired = "unknown"
	}
	seen := false
	for _, unknown := range u.Recon.Unknowns {
		if unknown.ID == "target_access_evidence_gap" {
			seen = true
			break
		}
	}
	if !seen {
		u.Recon.Unknowns = append(u.Recon.Unknowns, ReconUnknown{
			ID: "target_access_evidence_gap", Priority: 10,
			Question:        "What representative application surface is hidden behind the current access boundary?",
			WhyItMatters:    "A block page or rendered shell cannot ground application actors, objects, or workflows.",
			SuggestedAction: "Retry from an authorized environment or supply the missing rendering dependency without expanding scope.",
			Evidence:        []ReconEvidence{{Kind: "inference", Ref: "gap", Detail: "Representative target content was not captured."}},
		})
	}
	u.RecalculateReconMetrics()
}

func groundReconObjectsFromObservedPages(recon *ReconModel) {
	if recon == nil {
		return
	}
	for objectIndex := range recon.Objects {
		object := &recon.Objects[objectIndex]
		if object.ID == "" {
			continue
		}
		// Re-evaluate our own deterministic fallback evidence on every
		// normalization pass. A later page may be a much stronger exact-route
		// match than the incidental prose match that was available earlier.
		keptEvidence := object.Evidence[:0]
		hadFallbackEvidence := false
		for _, evidence := range object.Evidence {
			if evidence.Kind == "endpoint" && evidence.Detail == "Observed page purpose names this business object." {
				hadFallbackEvidence = true
				continue
			}
			keptEvidence = append(keptEvidence, evidence)
		}
		object.Evidence = keptEvidence
		if hasGroundedReconEvidence(object.Evidence) {
			continue
		}
		if hadFallbackEvidence {
			for pageIndex := range recon.Pages {
				recon.Pages[pageIndex].ObjectIDs = filterKnownIDs(recon.Pages[pageIndex].ObjectIDs, func(id string) bool { return id != object.ID })
			}
		}
		bestPage := -1
		bestScore := 0
		objectTokens := reconDistinctiveTokens(object.ID + " " + object.Name)
		utilityObject := reconInteractionArtifactObject(*object) || containsReconSignal(
			strings.ToLower(object.ID+" "+object.Name), "opensearch", "manifest", "sitemap", "descriptor")
		if len(objectTokens) == 0 {
			continue
		}
		for pageIndex := range recon.Pages {
			page := &recon.Pages[pageIndex]
			if page.ID == "" || page.Area == "static" || !meaningfulPurposeCard(*page) {
				continue
			}
			if reconUtilityPage(*page) && !utilityObject {
				continue
			}
			score := 0
			for _, objectID := range page.ObjectIDs {
				if objectID == object.ID {
					// A model-proposed graph edge is useful but not stronger
					// than an exact observed route name. It still grounds an
					// otherwise unmatched object, while /questions can outrank
					// a mistaken Question edge on /tags.
					score += 6
					break
				}
			}
			pageTokens := reconTokenSet(strings.Join([]string{page.ID, page.URL, page.Purpose, strings.Join(page.Inputs, " ")}, " "))
			routeTokens := reconTokenSet(strings.Join([]string{page.ID, page.URL}, " "))
			for token := range objectTokens {
				if pageTokens[token] {
					score += 4
				}
				// A route named for the object is stronger evidence than the
				// same noun appearing incidentally in another page's prose.
				if routeTokens[token] {
					score += 8
				}
				for _, input := range page.Inputs {
					normalizedInput := strings.ToLower(strings.TrimSpace(input))
					if normalizedInput == token+"_id" || normalizedInput == token+"id" {
						score += 8
					}
				}
			}
			if score > bestScore || (score == bestScore && score > 0 && page.Confidence > recon.Pages[bestPage].Confidence) {
				bestPage = pageIndex
				bestScore = score
			}
		}
		// A model-proposed page→object edge contributes six points, but is not
		// direct evidence by itself. Require at least one independently matching
		// route/purpose/input token before converting that edge into a grounded
		// claim. A four-point noun match remains useful for single-concept
		// objects such as Comment on a page explicitly describing comments.
		if bestPage < 0 || bestScore < 4 || bestScore == 6 {
			continue
		}
		page := &recon.Pages[bestPage]
		object.Evidence = append(object.Evidence, ReconEvidence{
			Kind: "endpoint", Ref: page.ID,
			Detail: "Observed page purpose names this business object.",
		})
		page.ObjectIDs = dedupeReconStrings(append(page.ObjectIDs, object.ID))
	}
}

func reconUtilityPage(page PagePurposeCard) bool {
	text := strings.ToLower(page.ID + " " + page.URL + " " + page.Purpose + " " + page.Area)
	return containsReconSignal(text,
		"opensearch", "manifest.json", "site.webmanifest", "robots.txt", "sitemap.xml",
		"browser search provider", "search provider xml", "favicon")
}

func reconWorkflowOnlyUsesUtilityPages(workflow BusinessWorkflow, pages []PagePurposeCard, pageIndex map[string]int) bool {
	hasPage := false
	for _, step := range workflow.Steps {
		for _, pageID := range step.PageIDs {
			idx, ok := pageIndex[pageID]
			if !ok || idx < 0 || idx >= len(pages) {
				continue
			}
			hasPage = true
			if !reconUtilityPage(pages[idx]) {
				return false
			}
		}
	}
	return hasPage
}

func reconDistinctiveTokens(value string) map[string]bool {
	tokens := reconTokenSet(value)
	for _, generic := range []string{
		"user", "data", "item", "record", "resource", "result", "page", "account",
		"public", "private", "machine", "learning", "training", "application", "forum",
		"product", "listing", "collection", "catalog",
	} {
		delete(tokens, generic)
	}
	return tokens
}

func reconTokenSet(value string) map[string]bool {
	parts := strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	out := make(map[string]bool, len(parts))
	for _, part := range parts {
		if len(part) < 4 {
			continue
		}
		if strings.HasSuffix(part, "ies") && len(part) > 5 {
			part = part[:len(part)-3] + "y"
		} else if strings.HasSuffix(part, "ing") && len(part) > 7 {
			part = strings.TrimSuffix(part, "ing")
		} else if strings.HasSuffix(part, "s") && !strings.HasSuffix(part, "ss") && len(part) > 4 {
			part = strings.TrimSuffix(part, "s")
		}
		out[part] = true
	}
	return out
}

// NormalizeReconAppType keeps the semantic model useful outside the original
// e-commerce/API-heavy matrix. A specific model-selected type is preserved;
// only empty or generic labels are upgraded from strong application clues.
func NormalizeReconAppType(appType, summary, evidence string) string {
	return normalizeReconAppType(appType, summary, evidence, "")
}

// NormalizeReconAppTypeForTarget gives the concrete scan target precedence
// over incidental product names in child-page prose. Keep target separate from
// evidence: a Python page linking to Wikipedia or a package registry must not
// inherit that linked application's type.
func NormalizeReconAppTypeForTarget(appType, summary, evidence, target string) string {
	return normalizeReconAppType(appType, summary, evidence, target)
}

func normalizeReconAppType(appType, summary, evidence, target string) string {
	normalized := strings.ToLower(strings.TrimSpace(appType))
	normalized = strings.ReplaceAll(normalized, "-", "_")
	normalized = strings.ReplaceAll(normalized, " ", "_")
	text := strings.ToLower(summary + "\n" + evidence)
	targetText := strings.ToLower(strings.TrimSpace(target))
	// Exact product/host clues outrank incidental vocabulary in an analyzed
	// child page. For example, Python.org links to package registries and docs,
	// but that does not turn the whole language/community platform into either.
	switch {
	case containsReconSignal(targetText, "wikipedia.org"):
		return "knowledge_base"
	case containsReconSignal(targetText, "npmjs.com"):
		return "package_registry"
	case containsReconSignal(targetText, "pypi.org"):
		return "package_registry"
	case containsReconSignal(targetText, "openstreetmap"):
		return "geospatial"
	case containsReconSignal(targetText, "gov.uk"):
		return "government_service"
	case containsReconSignal(targetText, "nasa.gov", "whitehouse.gov"):
		return "government_portal"
	case containsReconSignal(targetText, "huggingface.co"):
		return "developer_platform"
	case containsReconSignal(targetText, "bbc.com", "bbc.co.uk"):
		return "news_media"
	case containsReconSignal(targetText, "github.com", "gitlab.com"):
		return "developer_platform"
	case containsReconSignal(targetText, "python.org"):
		return "developer_platform"
	case containsReconSignal(targetText, "rfc-editor.org"):
		return "documentation"
	case containsReconSignal(targetText, "lobste.rs"):
		return "developer_community"
	case containsReconSignal(targetText, "letterboxd.com"):
		return "social_media"
	case containsReconSignal(targetText, "khanacademy.org"):
		return "education_platform"
	case containsReconSignal(targetText, "status.openai.com", "statuspage.io"):
		return "status_dashboard"
	}
	// Content-only fallbacks are useful when the host is custom/unknown, but
	// intentionally run after the exact product identity table above.
	switch {
	case containsReconSignal(text, "collaborative encyclopedia"):
		return "knowledge_base"
	case containsReconSignal(text, "package registry", "python package index"):
		return "package_registry"
	case containsReconSignal(text, "government service", "public service portal"):
		return "government_service"
	case containsReconSignal(text, "government information portal", "government information website", "official government information"):
		return "government_portal"
	case containsReconSignal(text, "hugging face model hub", "python programming language"):
		return "developer_platform"
	case containsReconSignal(text, "film diary and social platform", "social film platform", "film logging social platform"):
		return "social_media"
	}
	switch normalized {
	case "api", "api_service", "microservice", "microservices", "rest_api", "graphql_api":
		return "api_service"
	case "ecommerce", "e_commerce":
		return "e-commerce"
	case "social_media", "marketplace", "documentation", "knowledge_base", "developer_platform", "developer_community", "developer_q_and_a", "package_registry", "product_catalog", "content_catalog", "geospatial", "government_service", "government_portal", "news_media", "education_platform", "status_dashboard", "saas", "cms", "banking", "healthcare", "internal_tool":
		return normalized
	}
	if normalized != "" && normalized != "other" && normalized != "unknown" && normalized != "unclassified" {
		return normalized
	}

	switch {
	case containsReconSignal(text, "e-commerce", "online retail", "retail storefront", "shopping catalog"):
		return "e-commerce"
	case containsReconSignal(text, "public book catalog", "book catalog", "product catalog", "catalog scraping sandbox"):
		return "product_catalog"
	case containsReconSignal(text, "quote repository", "quotes repository", "quote catalog", "quotes catalog") ||
		(containsReconSignal(text, "displaying quotes", "browse paginated quote") && containsReconSignal(text, "author", "tag")) ||
		(containsReconSignal(text, "quote", "quotes") && containsReconSignal(text, "author") && containsReconSignal(text, "tag") &&
			containsReconSignal(text, "public", "browse", "listing", "collection", "catalog")):
		return "content_catalog"
	case containsReconSignal(text, "tech news aggregator", "technical news aggregator") &&
		containsReconSignal(text, "submit links", "submit stories", "comment", "vote"):
		return "developer_community"
	case containsReconSignal(text, "/wiki/", "knowledge base"):
		return "knowledge_base"
	case containsReconSignal(text, "software package", "package dependencies"):
		return "package_registry"
	case containsReconSignal(text, "geospatial", "collaborative mapping", "map data"):
		return "geospatial"
	case containsReconSignal(text, "developer documentation", "documentation portal", "documentation website", "documentation site", "technical documentation", "api documentation", "language reference", "/docs/"):
		return "documentation"
	case containsReconSignal(text, "developer q&a", "developer question and answer", "question-and-answer platform", "questions and answers platform"):
		return "developer_q_and_a"
	case containsReconSignal(text, "community forum", "discussion forum", "forum community"):
		return "developer_community"
	case containsReconSignal(text, "developer community", "technical community") ||
		(containsReconSignal(text, "link aggregation") && containsReconSignal(text, "submit stories", "comment threads", "topic tags")):
		return "developer_community"
	case containsReconSignal(text, "news publisher", "news media", "breaking news"):
		return "news_media"
	case containsReconSignal(text, "two-sided marketplace", "buyer and seller", "travel marketplace"):
		return "marketplace"
	}

	apiSignals := 0
	for _, signal := range []string{
		"/api/", " api endpoint", " api service", "api path", "openapi", "postman",
		"api specification", "swagger", "http testing", "echoes request data",
		"graphql", "bearer", "jwt", "microservice", "identity/api", "application/json", "rest",
	} {
		if strings.Contains(text, signal) {
			apiSignals++
		}
	}
	if strings.Contains(text, "completely ridiculous api") {
		apiSignals += 2
	}
	if apiSignals >= 2 {
		return "api_service"
	}
	return "other"
}

func dominantReconTarget(pages []PagePurposeCard) string {
	counts := map[string]int{}
	first := map[string]string{}
	bestHost, bestCount := "", 0
	for _, page := range pages {
		parsed, err := url.Parse(strings.TrimSpace(page.URL))
		if err != nil || parsed.Hostname() == "" {
			continue
		}
		host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
		counts[host]++
		if first[host] == "" {
			first[host] = page.URL
		}
		if counts[host] > bestCount {
			bestHost, bestCount = host, counts[host]
		}
	}
	return first[bestHost]
}

func containsReconSignal(value string, signals ...string) bool {
	for _, signal := range signals {
		if strings.Contains(value, signal) {
			return true
		}
	}
	return false
}

func hasVerifiedOwnershipEvidence(evidence []ReconEvidence) bool {
	for _, ev := range evidence {
		switch strings.ToLower(strings.TrimSpace(ev.Kind)) {
		case "finding", "verification", "authorization_test", "differential", "cross_persona":
			return true
		}
	}
	return false
}

func (u *AppUnderstanding) RenderReconForLLM() string {
	if u == nil || (len(u.Recon.Pages) == 0 && len(u.Recon.Workflows) == 0 && len(u.Recon.Objects) == 0) {
		return ""
	}
	var b strings.Builder
	b.WriteString("## Semantic Recon Model\n")
	fmt.Fprintf(&b, "Modeled pages: %d; roles: %d; objects: %d; workflows: %d; ownership boundaries: %d; unknowns: %d\n",
		len(u.Recon.Pages), len(u.Recon.Roles), len(u.Recon.Objects), len(u.Recon.Workflows), len(u.Recon.OwnershipBoundaries), len(u.Recon.Unknowns))
	for _, target := range u.Recon.Targets {
		if target.Met {
			continue
		}
		fmt.Fprintf(&b, "  - unmet target P%d %s: %.0f%% / %.0f%%; next=%s\n",
			target.Priority, target.Label, target.Actual*100, target.Target*100, target.SuggestedAction)
	}
	for _, w := range u.Recon.Workflows {
		fmt.Fprintf(&b, "  - workflow %s: %s (%d steps, confidence %.2f)\n", w.ID, w.Name, len(w.Steps), w.Confidence)
	}
	for _, o := range u.Recon.Objects {
		fmt.Fprintf(&b, "  - object %s: %s; identifiers=%s; sensitivity=%s\n", o.ID, o.Name, strings.Join(o.Identifiers, ","), o.Sensitivity)
	}
	for _, q := range u.Recon.Unknowns {
		fmt.Fprintf(&b, "  - unknown P%d: %s; next=%s\n", q.Priority, q.Question, q.SuggestedAction)
	}
	return b.String()
}

// RenderReconEvidenceForLLM expands the compact semantic model with grounded
// page-purpose cards. It is intended for the one scan-level synthesis call;
// endpoint analysis and periodic Strategist cycles use RenderReconForLLM to
// avoid re-sending the entire page inventory on every request.
func (u *AppUnderstanding) RenderReconEvidenceForLLM() string {
	if u == nil || len(u.Recon.Pages) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("## Grounded Page Purpose Cards\n")
	for i, p := range u.Recon.Pages {
		if i >= 30 {
			fmt.Fprintf(&b, "  - ... %d additional page purpose cards omitted\n", len(u.Recon.Pages)-i)
			break
		}
		fmt.Fprintf(&b, "  - page %s: %s; area=%s; auth=%s; inputs=%s; actions=%s; confidence=%.2f\n",
			p.ID, p.Purpose, p.Area, p.AuthRequired, strings.Join(p.Inputs, ","), strings.Join(p.Actions, ","), p.Confidence)
	}
	return b.String()
}

func methodFromProfileID(id string) string {
	if fields := strings.Fields(id); len(fields) > 1 {
		return strings.ToUpper(fields[0])
	}
	return "GET"
}

func profileInputNames(p types.PageProfile) []string {
	out := make([]string, 0, len(p.Inputs)+len(p.ExtractedInputs))
	for _, in := range append(append([]types.Input{}, p.Inputs...), p.ExtractedInputs...) {
		if in.Name != "" {
			out = append(out, in.Name)
		}
	}
	return dedupeReconStrings(out)
}

func dedupeReconStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func mergeReconEvidence(in []ReconEvidence, add ReconEvidence) []ReconEvidence {
	for _, e := range in {
		if e.Kind == add.Kind && e.Ref == add.Ref {
			return in
		}
	}
	return append(in, add)
}

func clampConfidence(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func uniqueReconRoles(in []ReconRole) []ReconRole {
	seen := map[string]bool{}
	out := make([]ReconRole, 0, len(in))
	for _, r := range in {
		if r.ID == "" || r.Name == "" || seen[r.ID] {
			continue
		}
		r.Confidence = clampConfidence(r.Confidence)
		seen[r.ID] = true
		out = append(out, r)
	}
	return out
}

func uniqueReconObjects(in []BusinessObject) []BusinessObject {
	seen := map[string]bool{}
	out := make([]BusinessObject, 0, len(in))
	for _, o := range in {
		if o.ID == "" || o.Name == "" || seen[o.ID] {
			continue
		}
		o.Confidence = clampConfidence(o.Confidence)
		seen[o.ID] = true
		out = append(out, o)
	}
	return out
}

func filterKnownIDs(in []string, keep func(string) bool) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, id := range in {
		if id != "" && !seen[id] && keep(id) {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

func canonicalizeReconEvidence(in []ReconEvidence, pages []PagePurposeCard) []ReconEvidence {
	out := make([]ReconEvidence, 0, len(in))
	for _, ev := range in {
		kind := strings.ToLower(strings.TrimSpace(ev.Kind))
		// MiniMax occasionally returns schema-adjacent words such as "page" or
		// "form" even though the prompt requires an exact profile reference.
		// Treat those as endpoint evidence only when their ref resolves uniquely
		// to an observed page. This preserves the evidence ceiling while avoiding
		// a cosmetic vocabulary mismatch zeroing otherwise exact coverage.
		pageBacked := kind == "endpoint" || kind == "page" || kind == "profile" || kind == "form" || kind == "route" || kind == "traffic"
		if pageBacked {
			if refs := canonicalPageRefs([]string{ev.Ref}, pages); len(refs) == 1 {
				ev.Ref = refs[0]
				ev.Kind = "endpoint"
			} else {
				// Endpoint evidence is an actionable graph edge. If it cannot be
				// resolved to an observed page, it is not evidence.
				continue
			}
			if containsReconSignal(strings.ToLower(ev.Detail), "commented-out", "commented out", "disabled link", "disabled markup") {
				ev.Kind = "inference"
				ev.Detail = "Unexposed or disabled markup suggests this concept; reachable behavior was not observed."
			}
		}
		out = append(out, ev)
	}
	return out
}

func canonicalPageRefs(in []string, pages []PagePurposeCard) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, ref := range in {
		if id := resolvePageRef(ref, pages); id != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

func resolvePageRef(ref string, pages []PagePurposeCard) string {
	ref = strings.TrimSpace(ref)
	originalRef := ref
	for _, p := range pages {
		if p.ID == ref {
			return p.ID
		}
	}
	refPath := reconRefPath(ref)
	if refPath == "" {
		return ""
	}
	match := ""
	for _, p := range pages {
		idPath := reconRefPath(p.ID)
		urlPath := reconRefPath(p.URL)
		if strings.EqualFold(refPath, idPath) || strings.EqualFold(refPath, urlPath) {
			if match != "" && match != p.ID {
				return ""
			}
			match = p.ID
		}
	}
	if match != "" {
		return match
	}

	// Reasoning models commonly turn an exact profile ID into a JSON-safe
	// identifier (for example GET /api/Challenges/ -> get_api_challenges_).
	// Accept that deterministic alias only when it resolves to exactly one
	// already-observed page; collisions remain ungrounded.
	refSlug := reconPageRefSlug(originalRef)
	if refSlug == "" {
		return ""
	}
	if refSlug == "get_root" || refSlug == "root" {
		for _, p := range pages {
			if strings.EqualFold(strings.TrimSpace(p.Method), "GET") && reconRefPath(p.ID) == "/" {
				if match != "" && match != p.ID {
					return ""
				}
				match = p.ID
			}
		}
		if match != "" {
			return match
		}
	}
	for _, p := range pages {
		if refSlug != reconPageRefSlug(p.ID) && refSlug != reconPageRefSlug(p.URL) {
			continue
		}
		if match != "" && match != p.ID {
			return ""
		}
		match = p.ID
	}
	return match
}

func reconPageRefSlug(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return ""
	}
	var b strings.Builder
	underscore := false
	for _, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			underscore = false
			continue
		}
		if !underscore {
			b.WriteByte('_')
			underscore = true
		}
	}
	return b.String()
}

func reconRefPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if fields := strings.Fields(raw); len(fields) > 1 && !strings.Contains(fields[0], "://") {
		raw = strings.Join(fields[1:], " ")
	}
	if parsed, err := url.Parse(raw); err == nil && parsed.Path != "" {
		raw = parsed.Path
	}
	if i := strings.Index(raw, "?"); i >= 0 {
		raw = raw[:i]
	}
	if raw != "/" {
		raw = strings.TrimRight(raw, "/")
	}
	return raw
}

func workflowClaimsUngroundedTransition(w BusinessWorkflow, pages []PagePurposeCard, pageIndex map[string]int) bool {
	var stepLabels strings.Builder
	for _, step := range w.Steps {
		stepLabels.WriteString(" ")
		stepLabels.WriteString(step.ID)
		stepLabels.WriteString(" ")
		stepLabels.WriteString(step.Label)
	}
	claim := strings.ToLower(w.Name + " " + w.Description + stepLabels.String())
	transitionWords := []string{
		"purchase", "checkout", "transfer", "approval", "approve", "submit order", "complete order",
		"delete", "create", "update", "edit", "publish", "vote", "comment", "register", "sign up",
		"login", "log in", "sign in", "authenticate", "password reset", "change password", "add to cart",
	}
	claimsTransition := false
	for _, word := range transitionWords {
		if strings.Contains(claim, word) {
			claimsTransition = true
			break
		}
	}
	if !claimsTransition {
		return false
	}
	for _, step := range w.Steps {
		for _, pageID := range step.PageIDs {
			method := strings.ToUpper(pages[pageIndex[pageID]].Method)
			if method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE" {
				return false
			}
		}
	}
	return true
}

func workflowStepClaimsMutation(step WorkflowStep) bool {
	text := strings.ToLower(strings.TrimSpace(step.ID + " " + step.Label))
	for _, prefix := range []string{
		"submit", "save", "publish", "delete", "create", "update", "vote", "post ", "send",
		"register", "sign up", "authenticate", "reset password", "change password", "place order", "add to cart",
	} {
		if strings.HasPrefix(text, prefix) || strings.Contains(text, " "+prefix) {
			return true
		}
	}
	return false
}

func workflowStepHasMutationPage(step WorkflowStep, pages []PagePurposeCard, pageIndex map[string]int) bool {
	for _, pageID := range step.PageIDs {
		idx, ok := pageIndex[pageID]
		if !ok {
			continue
		}
		switch strings.ToUpper(pages[idx].Method) {
		case "POST", "PUT", "PATCH", "DELETE":
			return true
		}
	}
	return false
}

func observedWorkflowEntryName(step WorkflowStep) string {
	label := strings.TrimSpace(step.Label)
	if label == "" {
		label = "Observed entry"
	}
	label = strings.TrimSuffix(label, " journey")
	return label + " journey"
}

func fallbackReadOnlyWorkflow(pages []PagePurposeCard) (BusinessWorkflow, bool) {
	workflows := supplementReadOnlyWorkflows(pages, nil, 1)
	if len(workflows) == 0 {
		return BusinessWorkflow{}, false
	}
	return workflows[0], true
}

// supplementReadOnlyWorkflows turns independently observed public GET pages
// into a small set of bounded human journeys. It does not infer transitions:
// each workflow is exactly one captured page, and semantic diversity only
// decides which evidence is most useful to show. Existing model workflows are
// preserved and their represented surfaces are not duplicated.
func supplementReadOnlyWorkflows(pages []PagePurposeCard, existing []BusinessWorkflow, limit int) []BusinessWorkflow {
	out := append([]BusinessWorkflow(nil), existing...)
	if limit <= 0 || len(out) >= limit {
		return out
	}

	pageByID := make(map[string]PagePurposeCard, len(pages))
	for _, page := range pages {
		pageByID[page.ID] = page
	}
	represented := make(map[string]bool)
	for _, workflow := range existing {
		for _, step := range workflow.Steps {
			for _, pageID := range step.PageIDs {
				if page, ok := pageByID[pageID]; ok {
					if family := target.SurfaceFamily(page.URL, page.Purpose+" "+page.Area); family != "" {
						represented[family] = true
					}
				}
			}
		}
	}

	type candidate struct {
		page   PagePurposeCard
		family string
		score  int
	}
	bestByFamily := make(map[string]candidate)
	generic := candidate{score: -1}
	for _, page := range pages {
		if !reconPublicJourneyPage(page) {
			continue
		}
		family := target.SurfaceFamily(page.URL, page.Purpose+" "+page.Area)
		score := target.SurfaceValue(family)*100 + int(page.Confidence*10)
		if parsed, err := url.Parse(page.URL); err == nil && (parsed.EscapedPath() == "" || parsed.EscapedPath() == "/") {
			score += 6
		}
		if family == "" {
			if score > generic.score {
				generic = candidate{page: page, score: score}
			}
			continue
		}
		// These areas are valuable evidence, but they are supporting chrome,
		// not a deterministic substitute for the application's public business
		// journeys. A model-grounded workflow can still represent them.
		if !reconCoreJourneySurface(family) || represented[family] {
			continue
		}
		if current, ok := bestByFamily[family]; !ok || score > current.score {
			bestByFamily[family] = candidate{page: page, family: family, score: score}
		}
	}

	candidates := make([]candidate, 0, len(bestByFamily))
	for _, item := range bestByFamily {
		candidates = append(candidates, item)
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		return candidates[i].page.ID < candidates[j].page.ID
	})
	// Preserve the older single-page fallback for targets whose useful surface
	// is not yet in the shared vocabulary (for example a government /services
	// directory). It is only used when no modeled or classified journey exists.
	if len(out) == 0 && len(candidates) == 0 && generic.score >= 0 {
		candidates = append(candidates, generic)
	}

	for _, item := range candidates {
		if len(out) >= limit {
			break
		}
		id := "observed_read_journey"
		if len(out) > 0 || item.family != "" && len(candidates) > 1 {
			suffix := item.family
			if suffix == "" {
				suffix = fmt.Sprintf("%d", len(out)+1)
			}
			id = "observed_read_journey_" + suffix
		}
		name := fallbackJourneyLabel(item.page)
		confidence := item.page.Confidence
		if confidence <= 0 || confidence > .7 {
			confidence = .7
		}
		out = append(out, BusinessWorkflow{
			ID: id, Name: name + " journey",
			Description: "One-step read-only journey synthesized from a directly observed page.",
			Confidence:  confidence,
			Evidence:    []ReconEvidence{{Kind: "endpoint", Ref: item.page.ID, Detail: "Direct GET page supports a bounded read-only journey."}},
			Steps: []WorkflowStep{{
				ID: "visit_observed_page", Label: name, PageIDs: []string{item.page.ID}, ObjectIDs: append([]string(nil), item.page.ObjectIDs...),
			}},
		})
		represented[item.family] = true
	}
	return out
}

func reconPublicJourneyPage(page PagePurposeCard) bool {
	method := strings.ToUpper(strings.TrimSpace(page.Method))
	if method == "" && strings.HasPrefix(strings.ToUpper(strings.TrimSpace(page.ID)), "GET ") {
		method = "GET"
	}
	if method != "GET" || reconAuthRequired(page.AuthRequired) || !meaningfulPurposeCard(page) || reconUtilityPage(page) {
		return false
	}
	text := strings.ToLower(page.ID + " " + page.URL + " " + page.Purpose + " " + page.Area)
	return !containsReconSignal(text, "cdn-cgi", "challenge", "429", "rate limit", "access denied", "error page", "redirect helper", "static asset", "just a moment")
}

func reconCoreJourneySurface(family string) bool {
	switch family {
	case "review", "collection", "community", "transaction", "catalog", "search", "content", "jobs", "status":
		return true
	default:
		return false
	}
}

func fallbackJourneyLabel(page PagePurposeCard) string {
	text := strings.ToLower(page.URL + " " + page.Purpose + " " + page.Area)
	switch {
	case containsReconSignal(text, "main feed", "public feed", "story feed"):
		return "Browse main feed"
	case containsReconSignal(text, "/jobs", "job board", "job listing"):
		return "Browse public job listings"
	case containsReconSignal(text, "/search", "search results"):
		return "Browse public search results"
	case containsReconSignal(text, "/download", "downloads page"):
		return "Browse available downloads"
	case containsReconSignal(text, "/docs", "documentation", "language reference"):
		return "Browse documentation"
	case containsReconSignal(text, "/news", "news listing"):
		return "Browse public news"
	case containsReconSignal(text, "/history", "service status", "incident history"):
		return "Review service status"
	}
	if containsReconSignal(text, "story", "journal", "editorial feature") {
		return "Read a public story"
	}
	// Prefer the shared, host-agnostic surface vocabulary over copying an LLM
	// purpose sentence into a button label. This keeps deterministic fallback
	// journeys human-readable even when the source profile is verbose.
	switch target.SurfaceFamily(page.URL, page.Purpose+" "+page.Area) {
	case "review":
		return "Browse public reviews"
	case "collection":
		return "Browse public collections"
	case "community":
		return "Explore the public community"
	case "catalog":
		return "Browse the public catalog"
	case "content":
		if containsReconSignal(text, "story", "journal", "article", "blog", "post") {
			return "Read a public story"
		}
		return "Read public content"
	case "transaction":
		return "View the transaction entry point"
	}
	name := strings.TrimSpace(page.Purpose)
	if name == "" {
		return "Explore observed page"
	}
	if cut := strings.IndexAny(name, ".;\n"); cut > 0 {
		name = strings.TrimSpace(name[:cut])
	}
	const maxLabel = 56
	if len(name) > maxLabel {
		name = name[:maxLabel]
		if cut := strings.LastIndexByte(name, ' '); cut >= 32 {
			name = name[:cut]
		}
		name = strings.TrimSpace(name)
	}
	name = strings.TrimSuffix(name, " journey")
	return name
}
