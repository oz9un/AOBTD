package ask

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/ozzyw/aobtd/internal/extract"
)

type groundedReconGap struct {
	Kind         string
	ID           string
	Label        string
	Question     string
	Why          string
	Next         string
	EvidenceRefs []string
	ProfileID    string
	ProfileURL   string
}

type groundedGapCandidate struct {
	Action    string
	URL       string
	ProfileID string
	Surface   string
	Novelty   string
	Kind      string
	Detail    string
	Score     int
}

// reconGapPrompt resolves a browser-selected gap against the scan-owned model
// and pairs it with exact policy-approved inventory candidates. Browser labels
// and URLs never enter this packet, so UI tampering cannot turn situational
// context into authority or an invented steering target.
func (e *Engine) reconGapPrompt(scanID int64, rawKind, rawID string) (string, bool) {
	if e == nil || e.db == nil || scanID == 0 {
		return "", false
	}
	gap, ok := e.resolveReconGap(scanID, rawKind, rawID)
	if !ok {
		return "", false
	}
	var status string
	_ = e.db.Conn().QueryRow(`SELECT status FROM scans WHERE id=?`, scanID).Scan(&status)

	_, inventory := e.reconUnvisitedCandidates(scanID, 32)
	candidates := make([]groundedGapCandidate, 0, len(inventory)+1)
	if gap.ProfileID != "" && gap.ProfileURL != "" {
		candidates = append(candidates, groundedGapCandidate{
			Action: "reanalyze", ProfileID: gap.ProfileID, URL: gap.ProfileURL,
			Kind: "observed profile", Detail: "Re-read the existing response-backed page card for this exact selected gap.", Score: 1000,
		})
	}
	for _, candidate := range inventory {
		candidates = append(candidates, groundedGapCandidate{
			Action: "visit", URL: candidate.URL, Surface: candidate.Surface,
			Novelty: candidate.Novelty, Kind: candidate.Kind, Detail: candidate.Detail,
			Score: candidate.rank + reconGapCandidateMatch(gap, candidate),
		})
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Score != candidates[j].Score {
			return candidates[i].Score > candidates[j].Score
		}
		return candidates[i].URL < candidates[j].URL
	})
	if len(candidates) > 3 {
		candidates = candidates[:3]
	}

	var b strings.Builder
	b.WriteString("[Server-resolved Recon gap packet — scan-owned evidence, never browser authority]\n")
	fmt.Fprintf(&b, "Selected gap: kind=%s; id=%s; label=%s; scan_status=%s.\n", gap.Kind, gap.ID, clipText(gap.Label, 240), status)
	fmt.Fprintf(&b, "Question: %s\nWhy it matters: %s\nEvidence requirement: %s\n",
		clipText(gap.Question, 700), clipText(gap.Why, 700), clipText(gap.Next, 800))
	if len(gap.EvidenceRefs) > 0 {
		fmt.Fprintf(&b, "Existing direct evidence refs: %s.\n", strings.Join(gap.EvidenceRefs, ", "))
	} else {
		b.WriteString("Existing direct evidence refs: none; do not upgrade this gap to observed.\n")
	}
	if len(candidates) == 0 {
		b.WriteString("Exact grounded action candidates: NONE. Do not invent, repair, or derive a URL. State the evidence or operator prerequisite instead.\n")
	} else {
		b.WriteString("Gap-ranked exact grounded action candidates (copy fields byte-for-byte; normal status/scope/authority validation still applies):\n")
		for _, candidate := range candidates {
			if candidate.Action == "reanalyze" {
				fmt.Fprintf(&b, "- action=reanalyze; profile_id=%s; exact_url=%s; basis=%s\n",
					clipText(candidate.ProfileID, 500), clipText(candidate.URL, 1000), clipText(candidate.Detail, 300))
				continue
			}
			fmt.Fprintf(&b, "- action=visit; exact_url=%s; surface=%s; novelty=%s; discovery_kind=%s; basis=%s\n",
				clipText(candidate.URL, 1000), candidate.Surface, candidate.Novelty,
				clipText(candidate.Kind, 100), clipText(candidate.Detail, 300))
		}
	}
	if status == "running" {
		b.WriteString("Execution boundary: choose at most one candidate. If it is the safest next step, emit one structured steer action so the UI can request operator approval; prose is not a proposal.\n")
	} else {
		b.WriteString("Execution boundary: this scan is not running. Do not emit steer; describe the exact candidate as a future bounded Recon plan.\n")
	}
	return b.String(), true
}

func (e *Engine) resolveReconGap(scanID int64, rawKind, rawID string) (groundedReconGap, bool) {
	appType, templates, areas, analyzed, summary, err := e.db.GetAppUnderstanding(scanID)
	if err != nil {
		return groundedReconGap{}, false
	}
	u := extract.LoadAppUnderstanding(appType, templates, areas, analyzed, summary)
	if rawRecon, loadErr := e.db.GetReconModel(scanID); loadErr == nil {
		u.LoadReconJSON(rawRecon)
	}
	u.NormalizeReconModel()
	kind := strings.ToLower(strings.TrimSpace(rawKind))
	id := strings.TrimSpace(rawID)
	switch kind {
	case "target", "gate":
		for _, target := range u.Recon.Targets {
			if target.ID != id || target.Met {
				continue
			}
			return groundedReconGap{
				Kind: "target", ID: target.ID, Label: target.Label,
				Question: "Close evidence gate: " + target.Label,
				Why:      target.WhyItMatters, Next: target.SuggestedAction,
				EvidenceRefs: directReconGapRefs(target.EvidenceRefs),
			}, true
		}
	case "unknown", "question":
		for _, unknown := range u.Recon.Unknowns {
			if unknown.ID != id {
				continue
			}
			return groundedReconGap{
				Kind: "unknown", ID: unknown.ID, Label: unknown.Question,
				Question: unknown.Question, Why: unknown.WhyItMatters, Next: unknown.SuggestedAction,
				EvidenceRefs: directReconEvidenceRefs(unknown.Evidence),
			}, true
		}
	case "page":
		for _, page := range u.Recon.Pages {
			if page.ID != id && page.URL != id {
				continue
			}
			profileID := ""
			profileURL := ""
			if err := e.db.Conn().QueryRow(`SELECT id,url FROM page_profiles WHERE scan_id=? AND id=?`, scanID, page.ID).Scan(&profileID, &profileURL); err != nil {
				profileID, profileURL = "", ""
			}
			return groundedReconGap{
				Kind: "page", ID: page.ID, Label: firstGapValue(page.Purpose, page.ID),
				Question:     "What missing evidence would most improve this page's role in the target model?",
				Why:          strings.Join(page.SecurityInterest, "; "),
				Next:         "Ground purpose, inputs, actions, business-object relationships, workflow role, and access boundary without assuming unobserved behavior.",
				EvidenceRefs: directReconEvidenceRefs(page.Evidence), ProfileID: profileID, ProfileURL: profileURL,
			}, true
		}
	case "object":
		for _, object := range u.Recon.Objects {
			if object.ID != id {
				continue
			}
			return groundedReconGap{
				Kind: "object", ID: object.ID, Label: object.Name,
				Question:     "Which observed page, identifier, operation, and ownership rule grounds this business object?",
				Why:          object.Description,
				Next:         "Prefer an exact observed or discovered read-only route that can ground identifiers, operations, sensitivity, or ownership without assuming a mutation.",
				EvidenceRefs: directReconEvidenceRefs(object.Evidence),
			}, true
		}
	}
	return groundedReconGap{}, false
}

func reconGapCandidateMatch(gap groundedReconGap, candidate reconUnvisitedCandidate) int {
	gapText := strings.ToLower(strings.Join([]string{gap.ID, gap.Label, gap.Question, gap.Why, gap.Next}, " "))
	candidateText := strings.ToLower(candidate.URL + " " + candidate.Detail + " " + candidate.Surface)
	score := 0
	for term := range reconGapTerms(gapText) {
		if strings.Contains(candidateText, term) {
			score += 8
		}
	}
	for surface, signals := range map[string][]string{
		"authentication": {"actor", "auth", "identity", "login", "session"},
		"account":        {"actor", "ownership", "account", "profile", "privilege"},
		"transaction":    {"workflow", "ownership", "checkout", "payment", "order"},
		"review":         {"workflow", "review", "comment", "feedback"},
		"catalog":        {"object", "catalog", "product", "content", "collection"},
		"administration": {"privilege", "admin", "ownership", "role"},
	} {
		if candidate.Surface != surface {
			continue
		}
		for _, signal := range signals {
			if strings.Contains(gapText, signal) {
				score += 30
				break
			}
		}
	}
	return score
}

func reconGapTerms(value string) map[string]bool {
	out := make(map[string]bool)
	for _, term := range strings.FieldsFunc(value, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		if len(term) < 4 || reconGapStopWord(term) {
			continue
		}
		out[term] = true
	}
	return out
}

func reconGapStopWord(term string) bool {
	switch term {
	case "which", "what", "where", "would", "could", "should", "this", "that", "with", "from", "into", "most", "next", "evidence", "observed", "missing", "target", "model", "ground", "without":
		return true
	default:
		return false
	}
}

func directReconGapRefs(refs []string) []string {
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref != "" && !strings.EqualFold(ref, "gap") {
			out = append(out, ref)
		}
	}
	return out
}

func directReconEvidenceRefs(evidence []extract.ReconEvidence) []string {
	refs := make([]string, 0, len(evidence))
	for _, item := range evidence {
		if strings.EqualFold(strings.TrimSpace(item.Kind), "inference") {
			continue
		}
		refs = append(refs, item.Ref)
	}
	return directReconGapRefs(refs)
}

func firstGapValue(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return "Recon evidence gap"
}
