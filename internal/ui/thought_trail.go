package ui

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/internal/store"
)

type thoughtTrail struct {
	Summary       string                 `json:"summary"`
	Metrics       thoughtTrailMetrics    `json:"metrics"`
	Workflows     []thoughtTrailWorkflow `json:"workflows"`
	Decisions     []thoughtTrailDecision `json:"decisions"`
	Hypotheses    []thoughtTrailHyp      `json:"hypotheses"`
	Findings      []thoughtTrailFinding  `json:"findings"`
	OpenQuestions []string               `json:"open_questions,omitempty"`
}

type thoughtTrailMetrics struct {
	WorkflowCount         int `json:"workflow_count"`
	HighPriorityWorkflows int `json:"high_priority_workflows"`
	GuardedActions        int `json:"guarded_actions"`
	ActiveHypotheses      int `json:"active_hypotheses"`
	TargetedTests         int `json:"targeted_tests"`
	ConfirmedFindings     int `json:"confirmed_findings"`
}

type thoughtTrailWorkflow struct {
	Name     string `json:"name"`
	Priority int    `json:"priority"`
	Status   string `json:"status"`
	Endpoint int    `json:"endpoint_count"`
	Why      string `json:"why"`
}

type thoughtTrailDecision struct {
	Agent   string `json:"agent"`
	Action  string `json:"action"`
	Message string `json:"message"`
	URL     string `json:"url,omitempty"`
	Tone    string `json:"tone"`
}

type thoughtTrailHyp struct {
	ID              string `json:"id"`
	Statement       string `json:"statement"`
	Status          string `json:"status"`
	Confidence      int    `json:"confidence"`
	Why             string `json:"why,omitempty"`
	EvidenceGrade   string `json:"evidence_grade"`
	EvidenceCount   int    `json:"evidence_count"`
	TestsPending    int    `json:"tests_pending"`
	TestsCompleted  int    `json:"tests_completed"`
	TestsFailed     int    `json:"tests_failed"`
	ConfirmedProofs int    `json:"confirmed_proofs"`
	NextQuestion    string `json:"next_question,omitempty"`
}

type thoughtTrailFinding struct {
	Title      string `json:"title"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	VulnType   string `json:"vuln_type,omitempty"`
	Endpoint   string `json:"endpoint,omitempty"`
}

func buildThoughtTrail(db *store.DB, scanID int64) thoughtTrail {
	trail := thoughtTrail{}
	trail.Workflows = thoughtTrailWorkflows(db, scanID)
	trail.Decisions = thoughtTrailDecisions(db, scanID)
	trail.Hypotheses = thoughtTrailHypotheses(db, scanID)
	trail.Findings = thoughtTrailFindings(db, scanID)
	trail.OpenQuestions = thoughtTrailOpenQuestions(trail)

	trail.Metrics.WorkflowCount = len(trail.Workflows)
	for _, w := range trail.Workflows {
		if w.Priority >= 8 {
			trail.Metrics.HighPriorityWorkflows++
		}
	}
	for _, d := range trail.Decisions {
		if d.Tone == "guarded" {
			trail.Metrics.GuardedActions++
		}
	}
	for _, h := range trail.Hypotheses {
		if strings.EqualFold(h.Status, store.HypothesisActive) {
			trail.Metrics.ActiveHypotheses++
		}
	}
	trail.Metrics.TargetedTests = countTargetedTests(db, scanID)
	for _, f := range trail.Findings {
		if strings.EqualFold(f.Confidence, "confirmed") {
			trail.Metrics.ConfirmedFindings++
		}
	}
	trail.Summary = thoughtTrailSummary(trail)
	return trail
}

func thoughtTrailWorkflows(db *store.DB, scanID int64) []thoughtTrailWorkflow {
	_, _, areasJSON, _, _, _ := db.GetAppUnderstanding(scanID)
	var areas []extract.FunctionalArea
	_ = json.Unmarshal([]byte(areasJSON), &areas)
	if len(areas) == 0 {
		return nil
	}
	for i := 1; i < len(areas); i++ {
		for j := i; j > 0 && areaLess(areas[j], areas[j-1]); j-- {
			areas[j], areas[j-1] = areas[j-1], areas[j]
		}
	}
	if len(areas) > 6 {
		areas = areas[:6]
	}
	out := make([]thoughtTrailWorkflow, 0, len(areas))
	for _, a := range areas {
		out = append(out, thoughtTrailWorkflow{
			Name:     a.Name,
			Priority: a.Priority,
			Status:   a.Status,
			Endpoint: len(a.Endpoints),
			Why:      workflowWhy(a.Name, a.Priority),
		})
	}
	return out
}

func areaLess(a, b extract.FunctionalArea) bool {
	if a.Priority != b.Priority {
		return a.Priority > b.Priority
	}
	return len(a.Endpoints) > len(b.Endpoints)
}

func workflowWhy(name string, priority int) string {
	switch name {
	case "authentication":
		return "Identity boundary: useful for auth bypass, session, rate-limit, and account-enumeration hypotheses."
	case "admin":
		return "Privilege boundary: admin-shaped surfaces usually deserve access-control attention."
	case "account":
		return "Ownership boundary: profile/settings endpoints often carry user, tenant, or role identifiers."
	case "transaction":
		return "Business transaction: order, booking, reservation, or workflow-step invariants may matter."
	case "financial":
		return "Money/value boundary: payment, wallet, invoice, refund, or transfer actions need careful approval."
	case "value_transfer":
		return "Business-value boundary: coupons, rewards, vouchers, and promos can create logic bugs."
	case "file_handling":
		return "Parser/storage boundary: uploads and imports can expose validation and content-type mistakes."
	case "messaging":
		return "User-content boundary: messages, comments, reviews, and tickets often mix ownership and stored content."
	case "api":
		return "Programmatic surface: APIs often expose object identifiers and cleaner authorization signals."
	case "search":
		return "Input-heavy surface: filters and queries are good low-risk probes for reflection and logic."
	default:
		if priority >= 8 {
			return "High-priority workflow based on path semantics and endpoint grouping."
		}
		return "Observed functional area from clustered endpoints."
	}
}

func thoughtTrailDecisions(db *store.DB, scanID int64) []thoughtTrailDecision {
	rows, err := db.Conn().Query(`
		SELECT agent, action, message, COALESCE(url, '')
		FROM narrations
		WHERE scan_id = ?
		  AND (
			action IN ('safe_form_plan','action_repeated','stale_action_replan','rejected_directive',
			           'queued_followups','plans_emitted','confirmed','chain_confirmed','no_plans')
			OR message LIKE '%Sensitive business controls visible%'
			OR message LIKE '%do not activate%'
			OR message LIKE '%do not submit%'
			OR message LIKE '%hypothesis%'
		  )
		ORDER BY id DESC
		LIMIT 12`, scanID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var reversed []thoughtTrailDecision
	for rows.Next() {
		var d thoughtTrailDecision
		if err := rows.Scan(&d.Agent, &d.Action, &d.Message, &d.URL); err != nil {
			continue
		}
		d.Message = truncateThought(d.Message, 220)
		d.Tone = decisionTone(d.Action, d.Message)
		reversed = append(reversed, d)
	}
	out := make([]thoughtTrailDecision, 0, len(reversed))
	for i := len(reversed) - 1; i >= 0; i-- {
		out = append(out, reversed[i])
	}
	return out
}

func decisionTone(action, message string) string {
	lower := strings.ToLower(action + " " + message)
	switch {
	case strings.Contains(lower, "do not activate") ||
		strings.Contains(lower, "do not submit") ||
		strings.Contains(lower, "sensitive business controls"):
		return "guarded"
	case strings.Contains(lower, "confirmed") || strings.Contains(lower, "chain_confirmed"):
		return "confirmed"
	case strings.Contains(lower, "rejected") || strings.Contains(lower, "no_plans"):
		return "constraint"
	case strings.Contains(lower, "safe_form"):
		return "action"
	default:
		return "thought"
	}
}

func thoughtTrailHypotheses(db *store.DB, scanID int64) []thoughtTrailHyp {
	hyps, err := db.ListHypotheses(scanID)
	if err != nil || len(hyps) == 0 {
		return nil
	}
	if len(hyps) > 8 {
		hyps = hyps[:8]
	}
	out := make([]thoughtTrailHyp, 0, len(hyps))
	for _, h := range hyps {
		why := ""
		if len(h.SupportingEvidence) > 0 {
			why = h.SupportingEvidence[0]
		} else {
			why = h.Notes
		}
		card := thoughtTrailHyp{
			ID:            h.ID,
			Statement:     truncateThought(h.Statement, 180),
			Status:        h.Status,
			Confidence:    int(h.Confidence*100 + 0.5),
			Why:           truncateThought(why, 160),
			EvidenceCount: len(h.SupportingEvidence),
		}
		_ = db.Conn().QueryRow(`
			SELECT
				COALESCE(SUM(CASE WHEN status IN ('pending','running') THEN 1 ELSE 0 END), 0),
				COALESCE(SUM(CASE WHEN status = 'done' THEN 1 ELSE 0 END), 0),
				COALESCE(SUM(CASE WHEN status IN ('failed','skipped') THEN 1 ELSE 0 END), 0)
			FROM follow_ups WHERE scan_id = ? AND hypothesis_id = ?`, scanID, h.ID).
			Scan(&card.TestsPending, &card.TestsCompleted, &card.TestsFailed)
		_ = db.Conn().QueryRow(`
			SELECT COUNT(*) FROM findings
			WHERE scan_id = ? AND hypothesis_id = ? AND confidence = 'confirmed'`, scanID, h.ID).
			Scan(&card.ConfirmedProofs)
		card.EvidenceGrade, card.NextQuestion = hypothesisEvidenceState(card)
		out = append(out, card)
	}
	return out
}

func hypothesisEvidenceState(h thoughtTrailHyp) (grade, next string) {
	switch {
	case h.ConfirmedProofs > 0 || strings.EqualFold(h.Status, store.HypothesisConfirmed):
		return "proven", "Proof is linked; preserve reproduction controls and impact evidence."
	case strings.EqualFold(h.Status, store.HypothesisRefuted):
		return "refuted", "The tested claim was contradicted; do not repeat the same experiment."
	case strings.EqualFold(h.Status, store.HypothesisStale):
		return "retired", "No further work is planned unless new evidence changes the model."
	case h.TestsPending > 0:
		return "testing", "Wait for the queued evidence or probe directive before revising confidence."
	case h.TestsCompleted > 0:
		return "tested", "Did the result satisfy the business invariant, or should this belief be lowered or retired?"
	case h.EvidenceCount > 0:
		return "grounded", "What is the smallest controlled experiment that could prove or refute this claim?"
	default:
		return "hunch", "Which observed endpoint, response, or workflow actually supports this claim?"
	}
}

func thoughtTrailOpenQuestions(t thoughtTrail) []string {
	var out []string
	hasAuth := false
	for _, workflow := range t.Workflows {
		if workflow.Name == "authentication" {
			hasAuth = true
		}
		if workflow.Priority >= 8 && workflow.Status != "fully_analyzed" {
			out = append(out, fmt.Sprintf("What roles, ownership rules, and forbidden transitions govern the %s workflow?", workflow.Name))
		}
	}
	if !hasAuth {
		out = append(out, "No authentication boundary has been observed yet; is the surface intentionally public or is authenticated coverage missing?")
	}
	for _, hypothesis := range t.Hypotheses {
		if hypothesis.EvidenceGrade == "hunch" {
			out = append(out, fmt.Sprintf("Ground %s in a concrete endpoint or retire it.", hypothesis.ID))
		}
	}
	if len(out) > 5 {
		out = out[:5]
	}
	return out
}

func thoughtTrailFindings(db *store.DB, scanID int64) []thoughtTrailFinding {
	rows, err := db.Conn().Query(`
		SELECT title, severity, confidence, COALESCE(vuln_type,''), COALESCE(endpoint_id,'')
		FROM findings
		WHERE scan_id = ?
		ORDER BY
			CASE confidence WHEN 'confirmed' THEN 0 WHEN 'possible' THEN 1 ELSE 2 END,
			CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
			              WHEN 'low' THEN 4 ELSE 5 END
		LIMIT 6`, scanID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []thoughtTrailFinding
	for rows.Next() {
		var f thoughtTrailFinding
		if err := rows.Scan(&f.Title, &f.Severity, &f.Confidence, &f.VulnType, &f.Endpoint); err != nil {
			continue
		}
		f.Title = truncateThought(f.Title, 160)
		out = append(out, f)
	}
	return out
}

func countTargetedTests(db *store.DB, scanID int64) int {
	var n sql.NullInt64
	_ = db.Conn().QueryRow(`
		SELECT COUNT(*) FROM follow_ups
		WHERE scan_id = ? AND status IN ('running','done','failed','skipped')`, scanID).Scan(&n)
	return int(n.Int64)
}

func thoughtTrailSummary(t thoughtTrail) string {
	if t.Metrics.WorkflowCount == 0 && len(t.Decisions) == 0 && len(t.Hypotheses) == 0 {
		return "AOBTD is still building its mental model of this target."
	}
	parts := []string{}
	if t.Metrics.WorkflowCount > 0 {
		parts = append(parts, fmt.Sprintf("mapped %d workflow area%s", t.Metrics.WorkflowCount, plural(t.Metrics.WorkflowCount)))
	}
	if t.Metrics.ActiveHypotheses > 0 {
		parts = append(parts, fmt.Sprintf("tracking %d active %s", t.Metrics.ActiveHypotheses, hypothesisWord(t.Metrics.ActiveHypotheses)))
	}
	if t.Metrics.TargetedTests > 0 {
		parts = append(parts, fmt.Sprintf("ran or queued %d targeted directive%s", t.Metrics.TargetedTests, plural(t.Metrics.TargetedTests)))
	}
	if t.Metrics.GuardedActions > 0 {
		parts = append(parts, fmt.Sprintf("held back from %d sensitive action%s", t.Metrics.GuardedActions, plural(t.Metrics.GuardedActions)))
	}
	if t.Metrics.ConfirmedFindings > 0 {
		parts = append(parts, fmt.Sprintf("confirmed %d finding%s", t.Metrics.ConfirmedFindings, plural(t.Metrics.ConfirmedFindings)))
	}
	if len(parts) == 0 {
		return "AOBTD has early observations but not enough evidence for a complete trail yet."
	}
	return "AOBTD has " + strings.Join(parts, ", ") + "."
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func hypothesisWord(n int) string {
	if n == 1 {
		return "hypothesis"
	}
	return "hypotheses"
}

func truncateThought(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if max <= 0 || len(s) <= max {
		return s
	}
	if max <= 1 {
		return "…"
	}
	return strings.TrimSpace(s[:max-1]) + "…"
}
