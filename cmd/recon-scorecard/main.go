// Command recon-scorecard turns saved scans into a compact, evidence-aware
// benchmark matrix. It uses the same normalization as the Recon UI so a raw
// model cannot keep an obsolete or inflated score.
package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/ozzyw/aobtd/internal/extract"
	_ "modernc.org/sqlite"
)

var summaryRiskClaimRE = regexp.MustCompile(`(?i)\b(?:idor|sqli|xss|authorization bypass|exploitable|vulnerable(?:\s+to)?)\b|\bsuggests?\b.{0,48}\bvulnerabilit`)

type scorecard struct {
	ScanID             int64    `json:"scan_id"`
	Target             string   `json:"target"`
	Status             string   `json:"status"`
	Access             string   `json:"access"`
	RuntimeSec         int      `json:"runtime_seconds"`
	Score              int      `json:"understanding"`
	Confidence         int      `json:"confidence"`
	GatesMet           int      `json:"gates_met"`
	GatesTotal         int      `json:"gates_total"`
	Pages              int      `json:"pages"`
	Roles              int      `json:"roles"`
	Objects            int      `json:"objects"`
	Workflows          int      `json:"workflows"`
	Boundaries         int      `json:"boundaries"`
	Unknowns           int      `json:"unknowns"`
	ObservedURLs       int      `json:"observed_urls"`
	Discoveries        int      `json:"discoveries"`
	Origins            int      `json:"origins"`
	QualityFlags       []string `json:"quality_flags"`
	OpenGateIDs        []string `json:"open_gate_ids"`
	HighestGap         string   `json:"highest_gap,omitempty"`
	Application        string   `json:"application_type"`
	Benchmark          string   `json:"benchmark"`
	BenchmarkGaps      []string `json:"benchmark_gaps,omitempty"`
	CopilotProposalSec int      `json:"copilot_proposal_seconds,omitempty"`
	CopilotDecisionSec int      `json:"copilot_decision_seconds,omitempty"`
	CopilotSteps       int      `json:"copilot_steps,omitempty"`
	CopilotDirective   string   `json:"copilot_directive_status,omitempty"`
}

func main() {
	dbPath := flag.String("db", "./aobtd-output/scan.db", "path to scan.db")
	format := flag.String("format", "markdown", "markdown or json")
	minID := flag.Int64("min-id", 0, "include scans at or above this id")
	flag.Parse()

	db, err := sql.Open("sqlite", "file:"+*dbPath+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		fatalf("open benchmark database: %v", err)
	}
	defer db.Close()

	cards, err := loadScorecards(db, *minID)
	if err != nil {
		fatalf("build scorecard: %v", err)
	}
	if strings.EqualFold(*format, "json") {
		out, _ := json.MarshalIndent(cards, "", "  ")
		fmt.Println(string(out))
		return
	}
	printMarkdown(cards)
}

func loadScorecards(db *sql.DB, minID int64) ([]scorecard, error) {
	rows, err := db.Query(`
		SELECT id, target, status,
			CAST((julianday(COALESCE(finished_at, 'now')) - julianday(started_at)) * 86400 AS INTEGER)
		FROM scans WHERE id >= ? ORDER BY id`, minID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cards []scorecard
	for rows.Next() {
		var card scorecard
		if err := rows.Scan(&card.ScanID, &card.Target, &card.Status, &card.RuntimeSec); err != nil {
			return nil, err
		}
		var appType, templates, areas, analyzed, summary, rawRecon string
		if err := db.QueryRow(`
			SELECT COALESCE(app_type,''), COALESCE(templates_json,'[]'), COALESCE(areas_json,'[]'),
			       COALESCE(analyzed_hashes_json,'{}'), COALESCE(summary,''), COALESCE(recon_json,'{}')
			FROM app_understanding WHERE scan_id=?`, card.ScanID).
			Scan(&appType, &templates, &areas, &analyzed, &summary, &rawRecon); err != nil && err != sql.ErrNoRows {
			return nil, err
		}
		u := extract.LoadAppUnderstanding(appType, templates, areas, analyzed, summary)
		u.LoadReconJSON(rawRecon)
		u.NormalizeReconModel()

		m := u.Recon.Metrics
		card.Score = percent(m.UnderstandingScore)
		card.Confidence = percent(m.OverallConfidence)
		card.GatesMet, card.GatesTotal = m.TargetsMet, m.TargetsTotal
		card.Pages, card.Roles, card.Objects = len(u.Recon.Pages), len(u.Recon.Roles), len(u.Recon.Objects)
		card.Workflows, card.Boundaries, card.Unknowns = len(u.Recon.Workflows), len(u.Recon.OwnershipBoundaries), len(u.Recon.Unknowns)
		card.Application = u.Recon.Identity.AppType

		var authObserved, mutationObserved, successfulHTML, rateLimited, accessDenied int
		_ = db.QueryRow(`
			SELECT EXISTS(SELECT 1 FROM narrations WHERE scan_id=?1 AND agent='auth' AND action IN ('success','api_login_success')),
			       EXISTS(SELECT 1 FROM traffic WHERE scan_id=?1 AND is_filtered=0 AND method IN ('POST','PUT','PATCH','DELETE'))`, card.ScanID).
			Scan(&authObserved, &mutationObserved)
		_ = db.QueryRow(`SELECT COUNT(DISTINCT url), COUNT(DISTINCT host) FROM traffic WHERE scan_id=? AND is_filtered=0`, card.ScanID).
			Scan(&card.ObservedURLs, &card.Origins)
		_ = db.QueryRow(`SELECT COUNT(DISTINCT target_url) FROM url_discoveries WHERE scan_id=?`, card.ScanID).
			Scan(&card.Discoveries)
		_ = db.QueryRow(`
			SELECT COALESCE(SUM(CASE WHEN status_code BETWEEN 200 AND 399 AND content_type LIKE 'text/html%' THEN 1 ELSE 0 END),0),
			       COALESCE(SUM(CASE WHEN status_code=429 THEN 1 ELSE 0 END),0),
			       COALESCE(SUM(CASE WHEN status_code IN (401,403) THEN 1 ELSE 0 END),0)
			FROM traffic WHERE scan_id=? AND is_filtered=0`, card.ScanID).
			Scan(&successfulHTML, &rateLimited, &accessDenied)
		card.Access = classifyAccess(successfulHTML, rateLimited, accessDenied,
			card.ObservedURLs, card.Discoveries, len(u.Recon.Pages))
		u.ApplyReconAccessCeiling(card.Access)
		m = u.Recon.Metrics
		card.Score = percent(m.UnderstandingScore)
		card.Confidence = percent(m.OverallConfidence)
		card.GatesMet, card.GatesTotal = m.TargetsMet, m.TargetsTotal
		card.Pages, card.Roles, card.Objects = len(u.Recon.Pages), len(u.Recon.Roles), len(u.Recon.Objects)
		card.Workflows, card.Boundaries, card.Unknowns = len(u.Recon.Workflows), len(u.Recon.OwnershipBoundaries), len(u.Recon.Unknowns)

		card.QualityFlags = assess(u.Recon, authObserved == 1, mutationObserved == 1, successfulHTML == 0)
		if card.Access == "limited" {
			card.QualityFlags = withoutQualityFlag(card.QualityFlags, "no-human-journey")
			card.QualityFlags = append(card.QualityFlags, "target-evidence-limited")
		}
		var open []extract.ReconTarget
		for _, target := range u.Recon.Targets {
			if !target.Met {
				open = append(open, target)
			}
		}
		sort.SliceStable(open, func(i, j int) bool { return open[i].Priority > open[j].Priority })
		for _, target := range open {
			card.OpenGateIDs = append(card.OpenGateIDs, target.ID)
		}
		if len(open) > 0 {
			card.HighestGap = open[0].ID
		}
		card.Benchmark, card.BenchmarkGaps = benchmarkVerdict(card)
		_ = db.QueryRow(`
			SELECT CAST(ROUND((julianday(a.created_at)-julianday(t.created_at))*86400) AS INTEGER),
			       CAST(ROUND((julianday(COALESCE(a.consumed_at,a.created_at))-julianday(a.created_at))*86400) AS INTEGER),
			       COALESCE(json_array_length(t.steps_json),0)
			FROM copilot_approvals a JOIN copilot_turns t ON t.id=a.turn_id
			WHERE a.scan_id=? AND a.status='approved'
			ORDER BY a.created_at DESC LIMIT 1`, card.ScanID).
			Scan(&card.CopilotProposalSec, &card.CopilotDecisionSec, &card.CopilotSteps)
		_ = db.QueryRow(`SELECT status FROM follow_ups WHERE scan_id=? AND source_agent='copilot' ORDER BY id DESC LIMIT 1`, card.ScanID).
			Scan(&card.CopilotDirective)
		cards = append(cards, card)
	}
	return cards, rows.Err()
}

func classifyAccess(successfulHTML, rateLimited, accessDenied, observedURLs, discoveries, modeledPages int) string {
	switch {
	case successfulHTML > 0 && observedURLs <= 1 && discoveries <= 1 && modeledPages <= 1:
		return "limited"
	case successfulHTML > 0:
		return "available"
	case rateLimited > 0:
		return "rate-limited"
	case accessDenied > 0:
		return "blocked"
	default:
		return "unavailable"
	}
}

func assess(recon extract.ReconModel, authObserved, mutationObserved, evidenceUnavailable bool) []string {
	flags := make([]string, 0, 6)
	appType := strings.ToLower(strings.TrimSpace(recon.Identity.AppType))
	identity := strings.ToLower(recon.Identity.Summary)
	if evidenceUnavailable {
		flags = append(flags, "target-evidence-unavailable")
	}
	if appType == "" || appType == "unknown" || appType == "unclassified" || appType == "other" {
		flags = append(flags, "weak-identity")
	}
	if summaryRiskClaimRE.MatchString(identity) {
		flags = append(flags, "security-hypothesis-in-summary")
	}
	if !authObserved && reconHasAuthenticatedClaims(recon) {
		flags = append(flags, "authenticated-role-hypothesis")
	}
	if !mutationObserved && reconHasStateChange(recon) {
		flags = append(flags, "state-change-without-request")
	}
	if len(recon.Workflows) == 0 && !evidenceUnavailable {
		flags = append(flags, "no-human-journey")
	}
	if len(recon.Unknowns) == 0 && recon.Metrics.TargetsMet < recon.Metrics.TargetsTotal {
		flags = append(flags, "gaps-without-questions")
	}
	if recon.Metrics.OwnershipModeled > 0 && recon.Metrics.OwnershipCoverage < .5 {
		flags = append(flags, "ownership-mostly-inferred")
	}
	for _, unknown := range recon.Unknowns {
		if unknown.ID == "workflow_transition_evidence_gap" {
			flags = append(flags, "workflow-entry-only")
			break
		}
	}
	return flags
}

func reconHasAuthenticatedClaims(recon extract.ReconModel) bool {
	for _, role := range recon.Roles {
		text := normalizeAnonymousAuthLanguage(strings.ToLower(role.ID + " " + role.Name + " " + role.Description + " " + strings.Join(role.Privileges, " ")))
		if containsAny(text, "authenticated", "logged-in", "logged in", "registered", "member", "admin", "owner") {
			return true
		}
	}
	for _, page := range recon.Pages {
		auth := strings.ToLower(strings.TrimSpace(page.AuthRequired))
		if auth != "" && !containsAny(auth, "none", "public", "anonymous", "unknown") {
			return true
		}
	}
	return false
}

func normalizeAnonymousAuthLanguage(value string) string {
	return strings.NewReplacer(
		"unauthenticated", "anonymous",
		"un-authenticated", "anonymous",
		"not authenticated", "anonymous",
		"no authenticated", "no protected",
	).Replace(value)
}

func reconHasStateChange(recon extract.ReconModel) bool {
	for _, workflow := range recon.Workflows {
		for _, step := range workflow.Steps {
			if step.StateChange {
				return true
			}
		}
	}
	return false
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if needle != "" && strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func withoutQualityFlag(flags []string, excluded string) []string {
	out := flags[:0]
	for _, flag := range flags {
		if flag != excluded {
			out = append(out, flag)
		}
	}
	return out
}

func percent(value float64) int { return int(value*100 + .5) }

func benchmarkVerdict(card scorecard) (string, []string) {
	if card.Status != "completed" {
		return "IN PROGRESS", nil
	}
	var gaps []string
	switch card.Access {
	case "available":
		if card.Score < 85 {
			gaps = append(gaps, "understanding<85")
		}
		if card.Confidence < 70 {
			gaps = append(gaps, "confidence<70")
		}
		if card.GatesMet < 5 {
			gaps = append(gaps, "grounded-gates<5")
		}
		for _, critical := range []string{"security-hypothesis-in-summary", "state-change-without-request", "gaps-without-questions"} {
			if containsAny(strings.Join(card.QualityFlags, " "), critical) {
				gaps = append(gaps, critical)
			}
		}
	case "limited", "rate-limited", "blocked", "unavailable":
		if card.Score > 40 {
			gaps = append(gaps, "access-failure-score>40")
		}
		if card.GatesMet > 2 {
			gaps = append(gaps, "access-failure-gates>2")
		}
		if card.Access == "limited" && !containsAny(strings.Join(card.QualityFlags, " "), "target-evidence-limited") {
			gaps = append(gaps, "missing-limited-evidence-flag")
		}
		if card.Access != "limited" && !containsAny(strings.Join(card.QualityFlags, " "), "target-evidence-unavailable") {
			gaps = append(gaps, "missing-unavailable-evidence-flag")
		}
	default:
		gaps = append(gaps, "unknown-access-class")
	}
	if len(gaps) == 0 {
		return "PASS", nil
	}
	return "FAIL", gaps
}

func printMarkdown(cards []scorecard) {
	fmt.Println("| Scan | Target | State | Time | Score | Confidence | Gates | Benchmark | P/R/O/W/B/U | URLs / discoveries / origins | Quality flags |")
	fmt.Println("|---:|---|---|---:|---:|---:|---:|---|---|---:|---|")
	for _, card := range cards {
		quality := strings.Join(card.QualityFlags, ", ")
		if quality == "" {
			quality = "clear"
		}
		benchmark := card.Benchmark
		if len(card.BenchmarkGaps) > 0 {
			benchmark += " (" + strings.Join(card.BenchmarkGaps, ", ") + ")"
		}
		fmt.Printf("| %d | %s | %s · %s | %dm%02ds | %d | %d%% | %d/%d | %s | %d/%d/%d/%d/%d/%d | %d / %d / %d | %s |\n",
			card.ScanID, card.Target, card.Status, card.Access, card.RuntimeSec/60, card.RuntimeSec%60,
			card.Score, card.Confidence, card.GatesMet, card.GatesTotal, benchmark,
			card.Pages, card.Roles, card.Objects, card.Workflows, card.Boundaries, card.Unknowns,
			card.ObservedURLs, card.Discoveries, card.Origins, quality)
	}
	printCopilotMarkdown(cards)
}

func printCopilotMarkdown(cards []scorecard) {
	var proposals []int
	for _, card := range cards {
		if card.CopilotProposalSec > 0 {
			proposals = append(proposals, card.CopilotProposalSec)
		}
	}
	if len(proposals) == 0 {
		return
	}
	fmt.Printf("\nCopilot proposal latency: p50 %ds · p95 %ds · %d approved UI run(s)\n\n", percentileNearestRank(proposals, .50), percentileNearestRank(proposals, .95), len(proposals))
	fmt.Println("| Scan | Proposal | Operator decision | Trace steps | Directive |")
	fmt.Println("|---:|---:|---:|---:|---|")
	for _, card := range cards {
		if card.CopilotProposalSec <= 0 {
			continue
		}
		fmt.Printf("| %d | %ds | %ds | %d | %s |\n", card.ScanID, card.CopilotProposalSec, card.CopilotDecisionSec, card.CopilotSteps, card.CopilotDirective)
	}
}

func percentileNearestRank(values []int, quantile float64) int {
	if len(values) == 0 {
		return 0
	}
	ordered := append([]int(nil), values...)
	sort.Ints(ordered)
	if quantile <= 0 {
		return ordered[0]
	}
	index := int(float64(len(ordered))*quantile+.999999999) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(ordered) {
		index = len(ordered) - 1
	}
	return ordered[index]
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
