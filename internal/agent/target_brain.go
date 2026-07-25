package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/internal/store"
)

const targetBrainMoveLimit = 3

// TargetBrainSnapshot is the compact operator-facing projection of AOBTD's
// normalized application model and its real learning queue. It intentionally
// contains no new semantic claims: every statement comes from ReconModel and
// every analysis move points to an exact captured endpoint family.
type TargetBrainSnapshot struct {
	ScanID      int64                  `json:"scan_id,omitempty"`
	State       string                 `json:"state"`
	StateLabel  string                 `json:"state_label"`
	Fingerprint string                 `json:"fingerprint"`
	Thesis      TargetBrainThesis      `json:"thesis"`
	Dimensions  []TargetBrainDimension `json:"dimensions"`
	Focus       *TargetBrainFocus      `json:"focus,omitempty"`
	Moves       []TargetBrainMove      `json:"moves"`
	Revisions   []TargetBrainRevision  `json:"revisions"`
	Saturation  TargetBrainSaturation  `json:"saturation"`
	Access      TargetBrainAccess      `json:"access"`
}

type TargetBrainAccess struct {
	State      string `json:"state,omitempty"`
	Label      string `json:"label,omitempty"`
	Detail     string `json:"detail,omitempty"`
	Constrains bool   `json:"constrains"`
}

type TargetBrainThesis struct {
	ApplicationType string   `json:"application_type"`
	Summary         string   `json:"summary"`
	Confidence      float64  `json:"confidence"`
	EvidenceRefs    []string `json:"evidence_refs"`
}

type TargetBrainDimension struct {
	ID           string             `json:"id"`
	Label        string             `json:"label"`
	Status       string             `json:"status"`
	Score        int                `json:"score"`
	Summary      string             `json:"summary"`
	Count        int                `json:"count"`
	EvidenceRefs []string           `json:"evidence_refs"`
	OpenGapIDs   []string           `json:"open_gap_ids,omitempty"`
	Claims       []TargetBrainClaim `json:"claims,omitempty"`
}

type TargetBrainClaim struct {
	Label        string   `json:"label"`
	Truth        string   `json:"truth"` // observed, partial, hypothesis, inferred, unknown
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
}

type TargetBrainFocus struct {
	Kind            string   `json:"kind"`
	ID              string   `json:"id"`
	Question        string   `json:"question"`
	WhyItMatters    string   `json:"why_it_matters,omitempty"`
	SuggestedAction string   `json:"suggested_action,omitempty"`
	Priority        int      `json:"priority"`
	EvidenceRefs    []string `json:"evidence_refs"`
	EvidenceReady   bool     `json:"evidence_ready"`
}

type TargetBrainMove struct {
	Rank          int                       `json:"rank"`
	Mode          string                    `json:"mode"`  // analyze, observe, prerequisite
	State         string                    `json:"state"` // captured, reanalysis, needs_capture, operator_input
	ObjectiveID   string                    `json:"objective_id"`
	ObjectiveKind string                    `json:"objective_kind"`
	Label         string                    `json:"label"`
	Why           string                    `json:"why"`
	Method        string                    `json:"method,omitempty"`
	URL           string                    `json:"url,omitempty"`
	Path          string                    `json:"path,omitempty"`
	EvidenceID    int64                     `json:"evidence_id,omitempty"`
	EvidenceGain  int                       `json:"evidence_gain,omitempty"`
	Expected      []store.AnalysisGapImpact `json:"expected,omitempty"`
	EvidenceRefs  []string                  `json:"evidence_refs,omitempty"`
}

type TargetBrainRevision struct {
	Sequence   int      `json:"sequence"`
	Status     string   `json:"status"`
	Headline   string   `json:"headline"`
	Detail     string   `json:"detail"`
	EvidenceID int64    `json:"evidence_id,omitempty"`
	GapIDs     []string `json:"gap_ids,omitempty"`
}

type TargetBrainSaturation struct {
	UnderstandingScore int    `json:"understanding_score"`
	TargetsMet         int    `json:"targets_met"`
	TargetsTotal       int    `json:"targets_total"`
	OpenTargets        int    `json:"open_targets"`
	OpenQuestions      int    `json:"open_questions"`
	CapturedReady      int    `json:"captured_ready"`
	ExactMoves         int    `json:"exact_moves"`
	BlockedObjectives  int    `json:"blocked_objectives"`
	Verdict            string `json:"verdict"`
	Reason             string `json:"reason"`
}

// BuildTargetBrain produces a deterministic, evidence-only briefing and plan.
// queue must already be ranked with the current scan-local feedback; the brain
// therefore inherits real learned ordering without bypassing queue guards.
func BuildTargetBrain(recon extract.ReconModel, objectives []ReconObjective, queue []store.AnalysisQueueItem, history []store.AnalysisLearningCheckpoint) TargetBrainSnapshot {
	brain := TargetBrainSnapshot{
		Thesis: TargetBrainThesis{
			ApplicationType: strings.TrimSpace(recon.Identity.AppType),
			Summary:         strings.TrimSpace(recon.Identity.Summary),
			Confidence:      recon.Metrics.OverallConfidence,
			EvidenceRefs:    targetBrainIdentityEvidence(recon),
		},
		Dimensions: targetBrainDimensions(recon),
		Moves:      []TargetBrainMove{},
		Revisions:  targetBrainRevisions(history),
	}
	if brain.Thesis.ApplicationType == "" {
		brain.Thesis.ApplicationType = "unclassified"
	}
	if brain.Thesis.Summary == "" {
		brain.Thesis.Summary = "Application identity is still forming from observed target evidence."
	}

	brain.Moves = targetBrainMoves(objectives, queue)
	if len(objectives) > 0 {
		focus := objectives[0]
		// Work on the highest-ranked gap that has an exact captured response
		// now. A higher-priority prerequisite remains visible in Moves, but it
		// must not make the scanner look idle while another explicit gap can be
		// reduced immediately.
		for _, move := range brain.Moves {
			if move.Mode != "analyze" {
				continue
			}
			matchedObjective := false
			for _, objective := range objectives {
				if objective.ID == move.ObjectiveID {
					focus = objective
					matchedObjective = true
					break
				}
			}
			if !matchedObjective && len(move.Expected) > 0 {
				impact := move.Expected[0]
				focus = ReconObjective{
					ID: impact.ID, Kind: impact.Kind, Priority: impact.Priority,
					Question:     "Reduce evidence gap: " + targetBrainText(impact.Label, impact.ID),
					WhyItMatters: move.Why,
				}
			}
			break
		}
		brain.Focus = &TargetBrainFocus{
			Kind: focus.Kind, ID: focus.ID, Question: focus.Question,
			WhyItMatters: focus.WhyItMatters, SuggestedAction: focus.SuggestedAction,
			Priority: focus.Priority, EvidenceRefs: targetBrainRefs(focus.EvidenceRefs, 4),
		}
		for _, move := range brain.Moves {
			if move.ObjectiveID == focus.ID && move.Mode == "analyze" {
				brain.Focus.EvidenceReady = true
				break
			}
		}
	} else {
		for _, move := range brain.Moves {
			if move.Mode != "analyze" || len(move.Expected) == 0 {
				continue
			}
			impact := move.Expected[0]
			brain.Focus = &TargetBrainFocus{
				Kind: impact.Kind, ID: impact.ID, Priority: impact.Priority,
				Question:     "Reduce evidence gap: " + targetBrainText(impact.Label, impact.ID),
				WhyItMatters: move.Why, EvidenceReady: true,
			}
			break
		}
	}
	brain.Saturation = targetBrainSaturation(recon, objectives, queue, brain.Moves)
	brain.State, brain.StateLabel = targetBrainState(recon, brain.Saturation)
	brain.Fingerprint = targetBrainFingerprint(brain)
	return brain
}

// ApplyTargetBrainAccess makes transport/rendering evidence ceilings part of
// the brain state. A protected or one-page capture is not model saturation.
func ApplyTargetBrainAccess(brain *TargetBrainSnapshot, state, label, detail string) {
	if brain == nil {
		return
	}
	state = strings.TrimSpace(state)
	brain.Access = TargetBrainAccess{
		State: state, Label: strings.TrimSpace(label), Detail: strings.TrimSpace(detail),
		Constrains: state != "" && state != "available",
	}
	if !brain.Access.Constrains {
		return
	}
	brain.State = "constrained"
	brain.StateLabel = targetBrainText(brain.Access.Label, "Evidence access constrained")
	brain.Saturation.Verdict = "access_constrained"
	brain.Saturation.Reason = targetBrainText(brain.Access.Detail,
		"Representative target evidence is unavailable; missing evidence is not saturation.")
	brain.Fingerprint = targetBrainFingerprint(*brain)
}

func targetBrainDimensions(recon extract.ReconModel) []TargetBrainDimension {
	targets := make(map[string]extract.ReconTarget, len(recon.Targets))
	for _, target := range recon.Targets {
		targets[target.ID] = target
	}
	unknownIDs := make([]string, 0, len(recon.Unknowns))
	for _, unknown := range recon.Unknowns {
		if strings.TrimSpace(unknown.ID) != "" {
			unknownIDs = append(unknownIDs, unknown.ID)
		}
	}
	sort.Strings(unknownIDs)

	roleRefs := []string{}
	roleClaims := []TargetBrainClaim{}
	for _, role := range recon.Roles {
		roleRefs = append(roleRefs, targetBrainGroundedEvidence(role.Evidence)...)
		roleClaims = append(roleClaims, targetBrainEntityClaim(targetBrainText(role.Name, role.ID), role.Evidence, targetBrainRoleTruth(role)))
	}
	objectRefs := []string{}
	objectClaims := []TargetBrainClaim{}
	for _, object := range recon.Objects {
		objectRefs = append(objectRefs, targetBrainGroundedEvidence(object.Evidence)...)
		objectClaims = append(objectClaims, targetBrainEntityClaim(targetBrainText(object.Name, object.ID), object.Evidence, ""))
	}
	workflowRefs := []string{}
	workflowClaims := []TargetBrainClaim{}
	for _, workflow := range recon.Workflows {
		workflowRefs = append(workflowRefs, targetBrainGroundedEvidence(workflow.Evidence)...)
		truth := ""
		for _, step := range workflow.Steps {
			if step.StateChange {
				truth = "partial"
				break
			}
		}
		workflowClaims = append(workflowClaims, targetBrainEntityClaim(targetBrainText(workflow.Name, workflow.ID), workflow.Evidence, truth))
	}
	boundaryRefs := []string{}
	boundaryClaims := []TargetBrainClaim{}
	for _, boundary := range recon.OwnershipBoundaries {
		boundaryRefs = append(boundaryRefs, targetBrainGroundedEvidence(boundary.Evidence)...)
		boundaryClaims = append(boundaryClaims, targetBrainEntityClaim(targetBrainText(boundary.Rule, boundary.ID), boundary.Evidence, "hypothesis"))
	}
	pageRefs := []string{}
	areas := map[string]bool{}
	pageClaims := []TargetBrainClaim{}
	for _, page := range recon.Pages {
		pageRefs = append(pageRefs, targetBrainGroundedEvidence(page.Evidence)...)
		if area := strings.TrimSpace(page.Area); area != "" {
			areas[area] = true
		}
		truth := "partial"
		if page.Confidence >= .7 && len(targetBrainGroundedEvidence(page.Evidence)) > 0 {
			truth = "observed"
		}
		pageClaims = append(pageClaims, targetBrainEntityClaim(targetBrainText(page.Purpose, page.ID), page.Evidence, truth))
	}
	unknownRefs := []string{}
	unknownClaims := []TargetBrainClaim{}
	for _, unknown := range recon.Unknowns {
		unknownRefs = append(unknownRefs, targetBrainGroundedEvidence(unknown.Evidence)...)
		unknownClaims = append(unknownClaims, TargetBrainClaim{Label: targetBrainText(unknown.Question, unknown.ID), Truth: "unknown", EvidenceRefs: targetBrainRefs(targetBrainGroundedEvidence(unknown.Evidence), 3)})
	}
	identityCount := 0
	identityTruth := "partial"
	appType := strings.ToLower(strings.TrimSpace(recon.Identity.AppType))
	if appType != "" && appType != "other" && appType != "unknown" && appType != "unclassified" {
		identityCount = 1
	}
	if targets["application_identity"].Met {
		identityTruth = "observed"
	}
	identityClaims := []TargetBrainClaim{{Label: targetBrainText(recon.Identity.AppType, "Application type remains unclassified"), Truth: identityTruth, EvidenceRefs: targetBrainIdentityEvidence(recon)}}

	dimensions := []TargetBrainDimension{
		targetBrainDimension("identity", "Identity", targets["application_identity"], identityCount,
			targetBrainClaimSummary(identityClaims, "Application type remains unclassified"), targetBrainIdentityEvidence(recon), nil, identityClaims),
		targetBrainDimension("surface", "Surface", targets["critical_purpose_coverage"], len(recon.Pages),
			fmt.Sprintf("%d observed page card%s across %d functional area%s", len(recon.Pages), targetBrainPlural(len(recon.Pages)), len(areas), targetBrainPlural(len(areas))), pageRefs, nil, targetBrainFirstClaims(pageClaims, 3)),
		targetBrainDimension("actors", "Actors", targets["actor_model"], len(recon.Roles),
			targetBrainClaimSummary(roleClaims, "No evidence-backed actor yet"), roleRefs, nil, targetBrainFirstClaims(roleClaims, 3)),
		targetBrainDimension("objects", "Objects", targets["business_object_coverage"], len(recon.Objects),
			targetBrainClaimSummary(objectClaims, "No grounded business object yet"), objectRefs, nil, targetBrainFirstClaims(objectClaims, 3)),
		targetBrainDimension("journeys", "Journeys", targets["workflow_grounding"], len(recon.Workflows),
			targetBrainClaimSummary(workflowClaims, "No grounded multi-step journey yet"), workflowRefs, nil, targetBrainFirstClaims(workflowClaims, 3)),
		targetBrainDimension("boundaries", "Boundaries", targets["ownership_boundaries"], len(recon.OwnershipBoundaries),
			targetBrainClaimSummary(boundaryClaims, fmt.Sprintf("%d modeled ownership or trust rule%s", len(recon.OwnershipBoundaries), targetBrainPlural(len(recon.OwnershipBoundaries)))), boundaryRefs, nil, targetBrainFirstClaims(boundaryClaims, 3)),
		targetBrainDimension("unknowns", "Unknowns", targets["actionable_unknowns"], len(recon.Unknowns),
			fmt.Sprintf("%d prioritized open question%s", len(recon.Unknowns), targetBrainPlural(len(recon.Unknowns))), unknownRefs, unknownIDs, targetBrainFirstClaims(unknownClaims, 3)),
	}
	return dimensions
}

func targetBrainDimension(id, label string, target extract.ReconTarget, count int, summary string, refs, gaps []string, claims []TargetBrainClaim) TargetBrainDimension {
	status := "open"
	if id == "boundaries" && target.Met && strings.Contains(strings.ToLower(target.SuggestedAction), "no per-user ownership proof is required") {
		status = "not_applicable"
	} else if target.Met {
		status = "grounded"
	} else if target.Actual > 0 || count > 0 {
		status = "partial"
	}
	score := int(target.Actual*100 + .5)
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	if id == "unknowns" && target.Met {
		status = "actionable"
	}
	return TargetBrainDimension{
		ID: id, Label: label, Status: status, Score: score, Summary: summary,
		Count: count, EvidenceRefs: targetBrainRefs(append(target.EvidenceRefs, refs...), 4),
		OpenGapIDs: targetBrainRefs(gaps, 6), Claims: claims,
	}
}

func targetBrainMoves(objectives []ReconObjective, queue []store.AnalysisQueueItem) []TargetBrainMove {
	moves := make([]TargetBrainMove, 0, targetBrainMoveLimit)
	used := map[string]bool{}
	covered := map[string]bool{}
	for _, objective := range objectives {
		for _, item := range queue {
			if item.Disposition == "skip" || used[item.EndpointHash] {
				continue
			}
			impacts := targetBrainMatchingImpacts(item.Impact, objective.ID)
			if len(impacts) == 0 {
				continue
			}
			label := strings.TrimSpace(item.Method + " " + targetBrainText(item.Path, item.URL))
			moves = append(moves, TargetBrainMove{
				Rank: len(moves) + 1, Mode: "analyze", State: targetBrainMoveState(item),
				ObjectiveID: objective.ID, ObjectiveKind: objective.Kind,
				Label: label, Why: targetBrainMoveWhy(objective, impacts, item),
				Method: item.Method, URL: item.URL, Path: item.Path,
				EvidenceID: item.EvidenceID, EvidenceGain: item.EvidenceGain,
				Expected: append([]store.AnalysisGapImpact(nil), item.Impact...), EvidenceRefs: targetBrainRefs(objective.EvidenceRefs, 3),
			})
			used[item.EndpointHash] = true
			covered[objective.ID] = true
			break
		}
		if len(moves) >= targetBrainMoveLimit {
			return moves
		}
	}

	// A spare slot may surface a high-value captured candidate whose exact gap
	// is not in the small Navigator objective window. It remains evidence-only.
	for _, item := range queue {
		if len(moves) >= targetBrainMoveLimit {
			break
		}
		if item.Disposition == "skip" || used[item.EndpointHash] || item.EvidenceGain <= 0 || len(item.Impact) == 0 {
			continue
		}
		impact := item.Impact[0]
		moves = append(moves, TargetBrainMove{
			Rank: len(moves) + 1, Mode: "analyze", State: targetBrainMoveState(item),
			ObjectiveID: impact.ID, ObjectiveKind: impact.Kind,
			Label:  strings.TrimSpace(item.Method + " " + targetBrainText(item.Path, item.URL)),
			Why:    targetBrainSpareMoveWhy(item, impact),
			Method: item.Method, URL: item.URL, Path: item.Path,
			EvidenceID: item.EvidenceID, EvidenceGain: item.EvidenceGain,
			Expected: append([]store.AnalysisGapImpact(nil), item.Impact...),
		})
		used[item.EndpointHash] = true
		covered[impact.ID] = true
	}

	// When no captured response can close an objective, state that honestly.
	// Navigator may later bind it to an exact visible affordance; this row does
	// not claim a request is ready and never invents a route.
	for _, objective := range objectives {
		if len(moves) >= targetBrainMoveLimit {
			break
		}
		if covered[objective.ID] {
			continue
		}
		mode := "observe"
		state := "needs_capture"
		label := targetBrainText(objective.SuggestedAction, "Collect another observed page or response for this gap")
		if targetBrainNeedsOperator(objective.SuggestedAction + " " + objective.WhyItMatters) {
			mode, state = "prerequisite", "operator_input"
		}
		moves = append(moves, TargetBrainMove{
			Rank: len(moves) + 1, Mode: mode, State: state,
			ObjectiveID: objective.ID, ObjectiveKind: objective.Kind,
			Label:        label,
			Why:          "No unprocessed captured response currently grounds this objective; only an exact observed affordance may become a navigation action.",
			EvidenceRefs: targetBrainRefs(objective.EvidenceRefs, 3),
		})
	}
	return moves
}

func targetBrainMatchingImpacts(impacts []store.AnalysisGapImpact, objectiveID string) []store.AnalysisGapImpact {
	out := make([]store.AnalysisGapImpact, 0, len(impacts))
	for _, impact := range impacts {
		if impact.ID == objectiveID {
			out = append(out, impact)
		}
	}
	return out
}

func targetBrainMoveWhy(objective ReconObjective, impacts []store.AnalysisGapImpact, item store.AnalysisQueueItem) string {
	labels := make([]string, 0, len(impacts))
	for _, impact := range impacts {
		labels = append(labels, targetBrainText(impact.Label, impact.ID))
	}
	why := fmt.Sprintf("Exact captured evidence is predicted to reduce %s; the next normalized checkpoint will measure whether it did.", strings.Join(labels, ", "))
	if item.Reanalysis {
		why = fmt.Sprintf("The prior page model is only %.0f%% confidence, so this exact captured response gets one bounded recovery pass. %s", item.ProfileConfidence*100, why)
	}
	return why
}

func targetBrainMoveState(item store.AnalysisQueueItem) string {
	if item.Reanalysis {
		return "reanalysis"
	}
	return "captured"
}

func targetBrainSpareMoveWhy(item store.AnalysisQueueItem, impact store.AnalysisGapImpact) string {
	why := fmt.Sprintf("Captured response is predicted to advance %s; the next checkpoint must verify movement.", targetBrainText(impact.Label, impact.ID))
	if item.Reanalysis {
		why = fmt.Sprintf("The prior page model is only %.0f%% confidence, so this exact captured response gets one bounded recovery pass. %s", item.ProfileConfidence*100, why)
	}
	return why
}

func targetBrainRevisions(history []store.AnalysisLearningCheckpoint) []TargetBrainRevision {
	revisions := make([]TargetBrainRevision, 0, 3)
	for _, checkpoint := range history {
		var chosen *store.AnalysisPriorityMovement
		for index := range checkpoint.Movements {
			movement := &checkpoint.Movements[index]
			if !movement.Selected {
				continue
			}
			if chosen == nil || movement.OutcomeStatus != "" || movement.FairnessLane || movement.RankDelta != 0 {
				chosen = movement
			}
			if movement.OutcomeStatus != "" {
				break
			}
		}
		if chosen == nil {
			continue
		}
		status := targetBrainText(chosen.OutcomeStatus, "selected")
		headline := "Plan selected new evidence"
		detail := fmt.Sprintf("%s %s entered the next %d-page analysis batch.", targetBrainText(chosen.Method, "GET"), targetBrainText(chosen.Path, chosen.URL), checkpoint.SelectedCount)
		gapIDs := []string{}
		for _, impact := range chosen.Impact {
			gapIDs = append(gapIDs, impact.ID)
		}
		if chosen.OutcomeStatus != "" {
			headline = "Model feedback: " + strings.ReplaceAll(chosen.OutcomeStatus, "_", " ")
			detail = "The normalized model moved after this selected batch. This is batch-scoped correlation, not proof that one route caused the change."
		} else if chosen.FairnessLane {
			headline = "Deferred evidence promoted"
			detail = fmt.Sprintf("A fairness slot advanced this exact captured family after %d deferred checkpoints.", chosen.QueueAge)
		} else if chosen.RankDelta != 0 {
			headline = "Plan priority changed"
			direction := "up"
			if chosen.RankDelta < 0 {
				direction = "down"
			}
			detail = fmt.Sprintf("The current target model moved this captured family %s %d rank%s.", direction, targetBrainAbs(chosen.RankDelta), targetBrainPlural(targetBrainAbs(chosen.RankDelta)))
		}
		revisions = append(revisions, TargetBrainRevision{
			Sequence: checkpoint.Sequence, Status: status, Headline: headline,
			Detail: detail, EvidenceID: chosen.EvidenceID, GapIDs: targetBrainRefs(gapIDs, 5),
		})
		if len(revisions) == 3 {
			break
		}
	}
	return revisions
}

func targetBrainSaturation(recon extract.ReconModel, objectives []ReconObjective, queue []store.AnalysisQueueItem, moves []TargetBrainMove) TargetBrainSaturation {
	openTargets := 0
	for _, target := range recon.Targets {
		if !target.Met {
			openTargets++
		}
	}
	ready := 0
	for _, item := range queue {
		if item.Disposition != "skip" {
			ready++
		}
	}
	exact := 0
	blocked := 0
	for _, move := range moves {
		if move.Mode == "analyze" && move.EvidenceID > 0 {
			exact++
		}
		if move.Mode != "analyze" {
			blocked++
		}
	}
	verdict := "learning"
	reason := fmt.Sprintf("%d exact captured candidate%s can still reduce %d open target%s.", exact, targetBrainPlural(exact), openTargets, targetBrainPlural(openTargets))
	switch {
	case len(recon.Targets) > 0 && openTargets == 0:
		verdict = "evidence_target_met"
		reason = "All deterministic understanding gates are grounded; new evidence may still revise the model."
	case len(recon.Pages) == 0 && ready == 0:
		verdict = "forming"
		reason = "No grounded page model or captured analysis candidate is available yet."
	case exact == 0 && len(objectives) > 0:
		verdict = "needs_evidence"
		reason = "Open objectives remain, but the current captured backlog cannot ground them; collect an exact observed affordance or satisfy the stated prerequisite."
	case len(objectives) == 0 && openTargets > 0:
		verdict = "needs_questions"
		reason = "Deterministic gates remain open, but no actionable model question is currently available."
	}
	return TargetBrainSaturation{
		UnderstandingScore: int(recon.Metrics.UnderstandingScore*100 + .5),
		TargetsMet:         recon.Metrics.TargetsMet, TargetsTotal: recon.Metrics.TargetsTotal,
		OpenTargets: openTargets, OpenQuestions: len(recon.Unknowns), CapturedReady: ready,
		ExactMoves: exact, BlockedObjectives: blocked, Verdict: verdict, Reason: reason,
	}
}

func targetBrainState(recon extract.ReconModel, saturation TargetBrainSaturation) (string, string) {
	switch saturation.Verdict {
	case "evidence_target_met":
		return "grounded", "Evidence target met"
	case "forming":
		return "forming", "Building the target model"
	case "needs_evidence":
		return "waiting", "Needs new observed evidence"
	case "needs_questions":
		return "waiting", "Needs an actionable question"
	default:
		if saturation.ExactMoves > 0 || len(recon.Pages) > 0 {
			return "adapting", "Adapting the recon plan"
		}
		return "forming", "Building the target model"
	}
}

func targetBrainFingerprint(brain TargetBrainSnapshot) string {
	parts := []string{brain.State, brain.Thesis.ApplicationType}
	if brain.Focus != nil {
		parts = append(parts, brain.Focus.Kind, brain.Focus.ID)
	}
	for _, move := range brain.Moves {
		parts = append(parts, move.Mode, move.ObjectiveID, move.Method, move.URL, fmt.Sprint(move.EvidenceGain))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:8])
}

func targetBrainIdentityEvidence(recon extract.ReconModel) []string {
	refs := []string{}
	for _, target := range recon.Targets {
		if target.ID == "application_identity" {
			refs = append(refs, target.EvidenceRefs...)
		}
	}
	for _, page := range recon.Pages {
		refs = append(refs, targetBrainGroundedEvidence(page.Evidence)...)
	}
	return targetBrainRefs(refs, 4)
}

func targetBrainGroundedEvidence(evidence []extract.ReconEvidence) []string {
	refs := []string{}
	for _, item := range evidence {
		kind := strings.ToLower(strings.TrimSpace(item.Kind))
		ref := strings.TrimSpace(item.Ref)
		if ref == "" || strings.EqualFold(ref, "gap") || kind == "inference" {
			continue
		}
		refs = append(refs, ref)
	}
	return refs
}

func targetBrainRefs(values []string, limit int) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || strings.EqualFold(value, "gap") || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func targetBrainEntityClaim(label string, evidence []extract.ReconEvidence, forcedTruth string) TargetBrainClaim {
	refs := targetBrainRefs(targetBrainGroundedEvidence(evidence), 3)
	truth := strings.TrimSpace(forcedTruth)
	if truth == "" {
		if len(refs) > 0 {
			truth = "observed"
		} else {
			truth = "inferred"
		}
	}
	return TargetBrainClaim{Label: label, Truth: truth, EvidenceRefs: refs}
}

func targetBrainRoleTruth(role extract.ReconRole) string {
	identity := strings.ToLower(strings.TrimSpace(role.ID + " " + role.Name))
	identity = strings.NewReplacer("unauthenticated", "anonymous", "un-authenticated", "anonymous").Replace(identity)
	privileged := false
	for _, signal := range []string{"administrator", "admin", "owner", "moderator", "maintainer", "staff", "privileged"} {
		privileged = privileged || strings.Contains(identity, signal)
	}
	// Anonymous actor existence is directly supported by a public response.
	// Do not let the substring "authenticated" inside "unauthenticated", or
	// incidental session prose in its description, turn that fact into an
	// authenticated-actor hypothesis.
	if !privileged && (strings.Contains(identity, "anonymous") || strings.Contains(identity, "public visitor") || strings.Contains(identity, "public user")) {
		return ""
	}
	text := strings.ToLower(strings.Join([]string{identity, role.Description, strings.Join(role.Privileges, " ")}, " "))
	for _, signal := range []string{"authenticated", "logged-in", "logged in", "registered", "member", "administrator", "admin", "owner", "session"} {
		if strings.Contains(text, signal) {
			// A public login/account page supports this as a testable actor
			// hypothesis, but does not prove an authenticated request occurred.
			return "hypothesis"
		}
	}
	return ""
}

func targetBrainClaimSummary(claims []TargetBrainClaim, empty string) string {
	if len(claims) == 0 {
		return empty
	}
	parts := make([]string, 0, 3)
	for _, claim := range claims {
		if strings.TrimSpace(claim.Label) == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s [%s]", claim.Label, targetBrainText(claim.Truth, "inferred")))
		if len(parts) == 3 {
			break
		}
	}
	if len(parts) == 0 {
		return empty
	}
	return strings.Join(parts, " · ")
}

func targetBrainFirstClaims(claims []TargetBrainClaim, limit int) []TargetBrainClaim {
	if limit <= 0 || len(claims) <= limit {
		return claims
	}
	return append([]TargetBrainClaim(nil), claims[:limit]...)
}

func targetBrainNeedsOperator(text string) bool {
	text = strings.ToLower(text)
	for _, signal := range []string{"second account", "second user", "another user", "authenticated session", "credentials", "operator", "login as", "two sessions", "two personas"} {
		if strings.Contains(text, signal) {
			return true
		}
	}
	return false
}

func targetBrainText(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return strings.TrimSpace(fallback)
}

func targetBrainPlural(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}

func targetBrainAbs(value int) int {
	if value < 0 {
		return -value
	}
	return value
}
