package agent

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/internal/store"
)

// ReconObjective is a bounded, read/navigation-oriented information goal
// derived from an explicit gap in the semantic application model.
type ReconObjective struct {
	ID              string   `json:"id"`
	Question        string   `json:"question"`
	WhyItMatters    string   `json:"why_it_matters,omitempty"`
	SuggestedAction string   `json:"suggested_action,omitempty"`
	Priority        int      `json:"priority"`
	EvidenceRefs    []string `json:"evidence_refs,omitempty"`
	Kind            string   `json:"kind"`
	DerivedTarget   bool     `json:"derived_target,omitempty"`
}

// ReconPlanner turns model uncertainty into browser exploration objectives.
// It does not invent URLs or issue requests itself; Navigator remains the
// policy-aware executor and may only act on affordances it can observe.
type ReconPlanner struct {
	db     *store.DB
	scanID int64
}

func NewReconPlanner(db *store.DB, scanID int64) *ReconPlanner {
	return &ReconPlanner{db: db, scanID: scanID}
}

func (p *ReconPlanner) Plan(limit int) ([]ReconObjective, error) {
	raw, err := p.db.GetReconModel(p.scanID)
	if err != nil {
		return nil, err
	}
	u := extract.NewAppUnderstanding()
	if appType, _, _, _, summary, loadErr := p.db.GetAppUnderstanding(p.scanID); loadErr == nil {
		u.AppType = appType
		u.Summary = summary
	}
	u.LoadReconJSON(raw)
	return BuildReconObjectives(u.Recon, limit), nil
}

// BuildReconObjectives exposes the same deterministic planner projection to
// the scanner and Target Brain API. This prevents the UI from independently
// reinterpreting gaps or presenting a different priority order.
func BuildReconObjectives(recon extract.ReconModel, limit int) []ReconObjective {
	if limit <= 0 {
		limit = 3
	}
	objectives := make([]ReconObjective, 0, len(recon.Unknowns)+len(recon.Targets))
	for _, unknown := range recon.Unknowns {
		if unknown.Priority < 6 {
			continue
		}
		obj := ReconObjective{
			ID: unknown.ID, Question: unknown.Question, WhyItMatters: unknown.WhyItMatters,
			SuggestedAction: unknown.SuggestedAction, Priority: unknown.Priority,
			Kind: classifyReconObjective(unknown),
		}
		for _, ev := range unknown.Evidence {
			if ev.Ref != "" && ev.Ref != "gap" {
				obj.EvidenceRefs = appendUniqueString(obj.EvidenceRefs, ev.Ref)
			}
		}
		objectives = append(objectives, obj)
	}
	// Deterministic targets keep navigation goal-directed even when the model
	// failed to emit a matching unknown. At equal priority the measurable gate
	// wins, keeping Navigator, the Recon hero, and Target Brain on one focus.
	for _, target := range recon.Targets {
		if target.Met || target.Priority < 6 {
			continue
		}
		question := fmt.Sprintf("Close target: %s — %.0f%% grounded / %.0f%% required.",
			target.Label, target.Actual*100, target.Target*100)
		objectives = append(objectives, ReconObjective{
			ID: target.ID, Question: question, WhyItMatters: target.WhyItMatters,
			SuggestedAction: target.SuggestedAction, Priority: target.Priority,
			EvidenceRefs: append([]string(nil), target.EvidenceRefs...),
			Kind:         classifyReconTarget(target), DerivedTarget: true,
		})
	}
	sort.SliceStable(objectives, func(i, j int) bool {
		if objectives[i].Priority != objectives[j].Priority {
			return objectives[i].Priority > objectives[j].Priority
		}
		if objectives[i].DerivedTarget != objectives[j].DerivedTarget {
			return objectives[i].DerivedTarget
		}
		return objectives[i].ID < objectives[j].ID
	})
	if len(objectives) > limit {
		objectives = objectives[:limit]
	}
	return objectives
}

func classifyReconTarget(target extract.ReconTarget) string {
	switch target.ID {
	case "workflow_grounding":
		return "workflow"
	case "actor_model":
		return "privilege"
	case "ownership_boundaries", "business_object_coverage":
		return "ownership"
	default:
		return "general"
	}
}

func classifyReconObjective(q extract.ReconUnknown) string {
	text := strings.ToLower(q.Question + " " + q.WhyItMatters + " " + q.SuggestedAction)
	switch {
	case containsAnyRecon(text, "workflow", "state-changing", "journey", "transition", "checkout", "purchase", "approval"):
		return "workflow"
	case containsAnyRecon(text, "role", "privilege", "admin", "membership", "authorization"):
		return "privilege"
	case containsAnyRecon(text, "owner", "tenant", "isolation", "other user"):
		return "ownership"
	case containsAnyRecon(text, "secret", "sensitive", "key", "token", "credential"):
		return "sensitive_data"
	default:
		return "general"
	}
}

func containsAnyRecon(text string, terms ...string) bool {
	for _, term := range terms {
		if strings.Contains(text, term) {
			return true
		}
	}
	return false
}

func renderReconObjectives(objectives []ReconObjective) string {
	if len(objectives) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("RECON OBJECTIVES — reduce these explicit knowledge gaps in priority order:\n")
	for _, obj := range objectives {
		fmt.Fprintf(&b, "- P%d [%s] %s", obj.Priority, obj.Kind, obj.Question)
		if obj.SuggestedAction != "" {
			fmt.Fprintf(&b, " Next safe action: %s", obj.SuggestedAction)
		}
		if len(obj.EvidenceRefs) > 0 {
			fmt.Fprintf(&b, " Grounded evidence: %s", strings.Join(obj.EvidenceRefs, ", "))
		}
		b.WriteString("\n")
	}
	b.WriteString("Choose the action with the highest expected information gain. Use only links, controls, forms, and routes actually observed in page state; never guess a route. If an objective requires a state transition, first navigate to the observed form or control that initiates it.\n")
	return b.String()
}

func reconObjectiveIDs(in []ReconObjective) string {
	ids := make([]string, 0, len(in))
	for _, obj := range in {
		ids = append(ids, obj.ID)
	}
	return strings.Join(ids, ", ")
}
