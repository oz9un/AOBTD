package agent

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

// strategistWorldModel is the compressed view of a scan's state we hand to
// the Sovereign Strategist on each cycle. Goal: fit into a ~3-5k token
// prompt even when the raw scan has thousands of endpoints. We follow the
// Cognition/Manus pattern — structured summaries + top-K unresolved items,
// never a raw dump.
type strategistWorldModel struct {
	ScanID   int64
	Target   string
	Status   string
	Duration string

	EndpointCount       int
	ProfileCount        int
	ProfilesWithIssues  int
	FindingCount        int
	ConfirmedFindings   int
	NarrationCount      int
	DirectivesPending   int
	DirectivesCompleted int

	Hosts                []wmHost
	TopIssues            []wmIssueCluster
	InterestingEndpoints []wmEndpointCard
	OwnershipCandidates  []wmOwnershipCandidate
	Findings             []wmFindingCard
	RecentThoughts       []wmNarrationCard
	RejectedDirectives   []wmRejectedDirectiveCard
	ActiveHypotheses     []wmHypothesisCard // each hypothesis + what Explorer/Verifier learned about it
	AppUnderstanding     string

	// PreviousSummary is the executive summary the last Strategist cycle
	// wrote. Seeds the new cycle so the Strategist keeps continuity.
	PreviousSummary string
}

type wmHost struct {
	Host      string `json:"host"`
	Endpoints int    `json:"endpoints"`
}

type wmIssueCluster struct {
	Theme            string   `json:"theme"`
	Count            int      `json:"count"`
	ExampleEndpoints []string `json:"example_endpoints"`
}

type wmEndpointCard struct {
	ID       string   `json:"id"`
	Method   string   `json:"method"`
	Path     string   `json:"path"`
	Purpose  string   `json:"purpose,omitempty"`
	Auth     string   `json:"auth,omitempty"`
	Issues   []string `json:"issues,omitempty"`
	HasInput bool     `json:"has_input"`
	IsAPI    bool     `json:"is_api"`
}

type wmOwnershipCandidate struct {
	Pattern      string   `json:"pattern"`
	Method       string   `json:"method"`
	Resource     string   `json:"resource"`
	Auth         string   `json:"auth,omitempty"`
	IDs          []string `json:"ids"`
	Examples     []string `json:"examples"`
	EvidenceRefs []string `json:"evidence_refs"`
	Reason       string   `json:"reason"`
}

type wmFindingCard struct {
	ID         int64  `json:"id"`
	Title      string `json:"title"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	Endpoint   string `json:"endpoint"`
	VulnType   string `json:"vuln_type,omitempty"`
}

type wmNarrationCard struct {
	Agent   string `json:"agent"`
	Action  string `json:"action"`
	Message string `json:"message"`
}

type wmRejectedDirectiveCard struct {
	Message string `json:"message"`
	URL     string `json:"url,omitempty"`
}

var (
	strategistNumericObjectID = regexp.MustCompile(`^[0-9]+$`)
	strategistUUIDObjectID    = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

// wmHypothesisCard wraps a hypothesis with the evidence specialist agents
// collected about it since it was emitted. Closing the A2A loop: the
// Strategist now sees what Explorer and Verifier learned, so on the next
// cycle it can refine confidence, retire disproved hypotheses, or double
// down on promising ones.
type wmHypothesisCard struct {
	store.Hypothesis
	// Directive lifecycle — how the test queue resolved
	DirectivesDone    int
	DirectivesFailed  int
	DirectivesPending int
	// Recent result strings from Explorer (e.g. "CONFIRMED IDOR (confidence 0.85)",
	// "probed 'xu' with 5 values: …"). Most recent last.
	EvidenceSnippets []string
	// Confirmed findings whose probe chain links back to this hypothesis.
	// Found via shared `endpoint_id` on the directive → finding.
	LinkedFindings []string
}

// buildStrategistWorldModel pulls a compact snapshot from the DB. Caps every
// section so the prompt stays bounded even on giant scans.
func buildStrategistWorldModel(db *store.DB, scanID int64) (*strategistWorldModel, error) {
	wm := &strategistWorldModel{ScanID: scanID}

	// Scan row
	var startedAt, finishedAt string
	err := db.Conn().QueryRow(`
		SELECT target, status, started_at, COALESCE(finished_at,'')
		FROM scans WHERE id = ?`, scanID).
		Scan(&wm.Target, &wm.Status, &startedAt, &finishedAt)
	if err != nil {
		return nil, fmt.Errorf("load scan: %w", err)
	}
	if startedAt != "" {
		if t1, e1 := time.Parse("2006-01-02 15:04:05", startedAt); e1 == nil {
			endTime := time.Now().UTC()
			if finishedAt != "" {
				if t2, e2 := time.Parse("2006-01-02 15:04:05", finishedAt); e2 == nil {
					endTime = t2
				}
			}
			wm.Duration = endTime.Sub(t1).Round(time.Second).String()
		}
	}

	// Counts
	db.Conn().QueryRow(`SELECT COUNT(DISTINCT endpoint_hash) FROM traffic WHERE scan_id=? AND is_filtered=FALSE`, scanID).
		Scan(&wm.EndpointCount)
	db.Conn().QueryRow(`SELECT COUNT(*) FROM page_profiles WHERE scan_id=?`, scanID).
		Scan(&wm.ProfileCount)
	db.Conn().QueryRow(`SELECT COUNT(*) FROM page_profiles WHERE scan_id=? AND issues!='[]' AND issues!=''`, scanID).
		Scan(&wm.ProfilesWithIssues)
	db.Conn().QueryRow(`SELECT COUNT(*) FROM findings WHERE scan_id=?`, scanID).
		Scan(&wm.FindingCount)
	db.Conn().QueryRow(`SELECT COUNT(*) FROM findings WHERE scan_id=? AND confidence='confirmed'`, scanID).
		Scan(&wm.ConfirmedFindings)
	db.Conn().QueryRow(`SELECT COUNT(*) FROM narrations WHERE scan_id=?`, scanID).
		Scan(&wm.NarrationCount)
	db.Conn().QueryRow(`SELECT COUNT(*) FROM follow_ups WHERE scan_id=? AND status IN ('pending','running')`, scanID).
		Scan(&wm.DirectivesPending)
	db.Conn().QueryRow(`SELECT COUNT(*) FROM follow_ups WHERE scan_id=? AND status='done'`, scanID).
		Scan(&wm.DirectivesCompleted)

	// Hosts by endpoint count (top 8)
	rows, err := db.Conn().Query(`
		SELECT host, COUNT(DISTINCT endpoint_hash) AS n
		FROM traffic WHERE scan_id=? AND is_filtered=FALSE
		GROUP BY host ORDER BY n DESC LIMIT 8`, scanID)
	if err == nil {
		for rows.Next() {
			var h string
			var n int
			rows.Scan(&h, &n)
			wm.Hosts = append(wm.Hosts, wmHost{Host: h, Endpoints: n})
		}
		rows.Close()
	}

	// Profiles — cluster issues + pick interesting ones
	profs, err := db.GetAllProfiles(scanID)
	if err != nil {
		return nil, fmt.Errorf("load profiles: %w", err)
	}
	wm.TopIssues = clusterProfileIssues(profs)
	wm.InterestingEndpoints = topInterestingProfiles(profs, 12)
	wm.OwnershipCandidates = ownershipCandidatesFromProfiles(profs, 5)

	// Findings (confirmed first)
	rowsF, err := db.Conn().Query(`
		SELECT id, title, severity, confidence, endpoint_id, COALESCE(vuln_type,'')
		FROM findings WHERE scan_id=?
		ORDER BY
			CASE confidence WHEN 'confirmed' THEN 0 WHEN 'possible' THEN 1 ELSE 2 END,
			CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
			              WHEN 'low' THEN 4 ELSE 5 END
		LIMIT 12`, scanID)
	if err == nil {
		for rowsF.Next() {
			var f wmFindingCard
			rowsF.Scan(&f.ID, &f.Title, &f.Severity, &f.Confidence, &f.Endpoint, &f.VulnType)
			wm.Findings = append(wm.Findings, f)
		}
		rowsF.Close()
	}

	// Recent high-signal narrations (oldest → newest so the narrative reads L→R)
	rowsN, err := db.Conn().Query(`
		SELECT agent, action, message FROM narrations
		WHERE scan_id=? AND (
			action IN ('thought','confirmed','dismissed','queued_followups','diff','saturated','auth','phase','complete')
			OR agent IN ('verifier','change-detector','explorer','auth')
		)
		ORDER BY id DESC LIMIT 16`, scanID)
	if err == nil {
		for rowsN.Next() {
			var n wmNarrationCard
			rowsN.Scan(&n.Agent, &n.Action, &n.Message)
			if len(n.Message) > 220 {
				n.Message = n.Message[:220] + "…"
			}
			wm.RecentThoughts = append(wm.RecentThoughts, n)
		}
		rowsN.Close()
	}
	for i, j := 0, len(wm.RecentThoughts)-1; i < j; i, j = i+1, j-1 {
		wm.RecentThoughts[i], wm.RecentThoughts[j] = wm.RecentThoughts[j], wm.RecentThoughts[i]
	}

	// Recent planner rejections are not target evidence, but they are valuable
	// planning constraints. Without them the Strategist can re-emit the same
	// invalid body-mutation directive every final-convergence round.
	rowsR, err := db.Conn().Query(`
		SELECT message, COALESCE(url, '') FROM narrations
		WHERE scan_id=? AND agent='strategist' AND action='rejected_directive'
		ORDER BY id DESC LIMIT 6`, scanID)
	if err == nil {
		for rowsR.Next() {
			var r wmRejectedDirectiveCard
			rowsR.Scan(&r.Message, &r.URL)
			if len(r.Message) > 220 {
				r.Message = r.Message[:220] + "..."
			}
			wm.RejectedDirectives = append(wm.RejectedDirectives, r)
		}
		rowsR.Close()
	}
	for i, j := 0, len(wm.RejectedDirectives)-1; i < j; i, j = i+1, j-1 {
		wm.RejectedDirectives[i], wm.RejectedDirectives[j] = wm.RejectedDirectives[j], wm.RejectedDirectives[i]
	}

	// Active hypotheses from prior cycles (so we don't re-emit the same ones).
	// For each, roll up the evidence collected by Explorer + Verifier so the
	// Strategist can update its belief on the next cycle — this is the A2A
	// feedback loop.
	hyps, _ := db.ListHypotheses(scanID)
	for _, h := range hyps {
		if h.Status != store.HypothesisActive {
			continue
		}
		card := loadHypothesisEvidence(db, scanID, h)
		wm.ActiveHypotheses = append(wm.ActiveHypotheses, card)
		if len(wm.ActiveHypotheses) >= 6 {
			break
		}
	}

	// Previous summary
	cycles, _ := db.ListStrategistCycles(scanID, 1)
	if len(cycles) > 0 {
		wm.PreviousSummary = cycles[0].ExecutiveSummary
	}

	// App understanding: include the semantic recon layer so planning starts
	// from workflows, objects, trust boundaries and explicit unknowns rather
	// than rediscovering application meaning from endpoint names each cycle.
	appType, templatesJSON, areasJSON, hashesJSON, summary, _ := db.GetAppUnderstanding(scanID)
	if appType != "" || summary != "" {
		wm.AppUnderstanding = strings.TrimSpace(appType + ": " + summary)
	}
	u := extract.LoadAppUnderstanding(appType, templatesJSON, areasJSON, hashesJSON, summary)
	if reconJSON, err := db.GetReconModel(scanID); err == nil {
		u.LoadReconJSON(reconJSON)
		if semantic := strings.TrimSpace(u.RenderReconForLLM()); semantic != "" {
			if wm.AppUnderstanding != "" {
				wm.AppUnderstanding += "\n"
			}
			wm.AppUnderstanding += semantic
		}
	}

	return wm, nil
}

// clusterProfileIssues groups profile-level issue strings by keyword theme so
// the Strategist sees "47 profiles flag CSRF" not 47 nearly-identical strings.
func clusterProfileIssues(profs []types.PageProfile) []wmIssueCluster {
	themes := []struct{ key, pattern string }{
		{"IDOR / sequential IDs", `(?i)idor|sequential|predictable.?id|enumerable|insecure.?direct.?object`},
		{"Missing CSRF protection", `(?i)csrf|anti.?forgery`},
		{"Missing auth / no authentication", `(?i)no (authentication|auth)|missing auth|unauthenticated|no authorization`},
		{"Reflected XSS / missing encoding", `(?i)xss|reflected|html encoding|script injection`},
		{"Sensitive data exposure", `(?i)sensitive|pii|leak|exposure|credential`},
		{"Open redirect", `(?i)open.?redirect|unvalidated redirect`},
		{"Rate limiting absent", `(?i)rate.?limit`},
		{"Input not validated", `(?i)input.?validation|no validation|unvalidated input`},
		{"Session handling / cookies", `(?i)session|cookie flag|samesite|httponly`},
	}
	regexes := make([]*regexp.Regexp, len(themes))
	for i, t := range themes {
		regexes[i] = regexp.MustCompile(t.pattern)
	}

	counts := make(map[string]int)
	examples := make(map[string][]string)
	for _, p := range profs {
		for _, issue := range p.Issues {
			for i, re := range regexes {
				if re.MatchString(issue) {
					theme := themes[i].key
					counts[theme]++
					if len(examples[theme]) < 3 {
						examples[theme] = append(examples[theme], p.ID)
					}
					break
				}
			}
		}
	}

	var out []wmIssueCluster
	for _, t := range themes {
		if counts[t.key] > 0 {
			out = append(out, wmIssueCluster{
				Theme:            t.key,
				Count:            counts[t.key],
				ExampleEndpoints: examples[t.key],
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

// topInterestingProfiles picks the profiles most worthy of the Strategist's
// attention. Heuristic: has issues > has input > on an interesting path >
// requires auth.
func topInterestingProfiles(profs []types.PageProfile, n int) []wmEndpointCard {
	score := func(p types.PageProfile) int {
		s := len(p.Issues) * 10
		if len(p.Inputs) > 0 {
			s += 5
		}
		if p.AuthRequired != "none" && p.AuthRequired != "" && p.AuthRequired != "unknown" {
			s += 3
		}
		lower := strings.ToLower(p.URL)
		for _, t := range []string{"/admin", "/api/", "/auth", "/login", "/account", "/upload", "/graphql"} {
			if strings.Contains(lower, t) {
				s += 4
				break
			}
		}
		if p.Confidence > 0 {
			s += int(p.Confidence * 2)
		}
		return s
	}
	sort.Slice(profs, func(i, j int) bool { return score(profs[i]) > score(profs[j]) })
	if n > len(profs) {
		n = len(profs)
	}
	out := make([]wmEndpointCard, 0, n)
	for _, p := range profs[:n] {
		out = append(out, wmEndpointCard{
			ID:       p.ID,
			Method:   p.Method,
			Path:     stripHost(p.URL),
			Purpose:  truncateAt(p.Purpose, 180),
			Auth:     p.AuthRequired,
			Issues:   takeN(p.Issues, 3),
			HasInput: len(p.Inputs) > 0,
			IsAPI:    isLikelyAPI(p.URL),
		})
	}
	return out
}

func ownershipCandidatesFromProfiles(profs []types.PageProfile, max int) []wmOwnershipCandidate {
	type bucket struct {
		pattern      string
		method       string
		resource     string
		auth         string
		ids          map[string]bool
		examples     []string
		evidenceRefs []string
	}
	buckets := map[string]*bucket{}

	for _, p := range profs {
		method := strings.ToUpper(strings.TrimSpace(p.Method))
		if method == "" {
			method = "GET"
		}
		pattern, resource, id, ok := ownedObjectPattern(p.URL)
		if !ok {
			continue
		}
		key := method + " " + pattern
		b := buckets[key]
		if b == nil {
			b = &bucket{
				pattern:  pattern,
				method:   method,
				resource: resource,
				auth:     p.AuthRequired,
				ids:      map[string]bool{},
			}
			buckets[key] = b
		}
		if b.auth == "" || b.auth == "unknown" {
			b.auth = p.AuthRequired
		}
		b.ids[id] = true
		if len(b.examples) < 4 {
			b.examples = appendUniqueString(b.examples, method+" "+stripQuery(stripHost(p.URL)))
		}
		ref := "endpoint:" + p.ID
		if p.ID == "" {
			ref = "endpoint:" + method + " " + stripQuery(stripHost(p.URL))
		}
		if len(b.evidenceRefs) < 4 {
			b.evidenceRefs = appendUniqueString(b.evidenceRefs, ref)
		}
	}

	out := make([]wmOwnershipCandidate, 0, len(buckets))
	for _, b := range buckets {
		if len(b.ids) < 2 {
			continue
		}
		ids := make([]string, 0, len(b.ids))
		for id := range b.ids {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		out = append(out, wmOwnershipCandidate{
			Pattern:      b.pattern,
			Method:       b.method,
			Resource:     b.resource,
			Auth:         b.auth,
			IDs:          takeN(ids, 6),
			Examples:     b.examples,
			EvidenceRefs: b.evidenceRefs,
			Reason:       fmt.Sprintf("multiple %s object identifiers observed on the same resource pattern; prioritize ownership-aware A/B authorization testing over blind id sweeps", b.resource),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].IDs) != len(out[j].IDs) {
			return len(out[i].IDs) > len(out[j].IDs)
		}
		return out[i].Pattern < out[j].Pattern
	})
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out
}

func ownedObjectPattern(rawURL string) (pattern, resource, id string, ok bool) {
	path := stripQuery(stripHost(rawURL))
	if path == "" || path == "/" {
		return "", "", "", false
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i := len(parts) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(parts[i])
		if !looksLikeObjectID(candidate) {
			continue
		}
		resource = nearestResourceName(parts, i)
		if resource == "" || !isOwnedResourceWord(resource) {
			continue
		}
		parts[i] = "{id}"
		return "/" + strings.Join(parts, "/"), resource, candidate, true
	}
	return "", "", "", false
}

func nearestResourceName(parts []string, idIndex int) string {
	for i := idIndex - 1; i >= 0; i-- {
		part := strings.ToLower(strings.Trim(parts[i], "_- "))
		if part == "" || looksLikeObjectID(part) {
			continue
		}
		return part
	}
	return ""
}

func looksLikeObjectID(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if strategistNumericObjectID.MatchString(s) {
		return true
	}
	return strategistUUIDObjectID.MatchString(s)
}

func isOwnedResourceWord(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "account", "accounts", "address", "addresses", "basket", "baskets",
		"booking", "bookings", "cart", "carts", "customer", "customers",
		"document", "documents", "file", "files", "invoice", "invoices",
		"message", "messages", "order", "orders", "payment", "payments",
		"profile", "profiles", "subscription", "subscriptions", "tenant",
		"tenants", "ticket", "tickets", "user", "users", "wallet", "wallets":
		return true
	default:
		return false
	}
}

func stripQuery(path string) string {
	if cut := strings.IndexAny(path, "?#"); cut >= 0 {
		return path[:cut]
	}
	return path
}

func appendUniqueString(list []string, value string) []string {
	for _, existing := range list {
		if existing == value {
			return list
		}
	}
	return append(list, value)
}

func stripHost(rawURL string) string {
	i := strings.Index(rawURL, "://")
	if i < 0 {
		return rawURL
	}
	rest := rawURL[i+3:]
	if slash := strings.Index(rest, "/"); slash >= 0 {
		return rest[slash:]
	}
	return "/"
}

func isLikelyAPI(u string) bool {
	lower := strings.ToLower(u)
	return strings.Contains(lower, "/api/") || strings.Contains(lower, "/v1/") ||
		strings.Contains(lower, "/v2/") || strings.Contains(lower, "/graphql")
}

func truncateAt(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func takeN(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// loadHypothesisEvidence queries the directives emitted for a hypothesis and
// summarizes what the specialist agents found. This is the read-side of the
// feedback loop: Explorer wrote results into follow_ups.result when it
// finished executing, and we pull those back into the Strategist's view
// of the hypothesis it owns.
func loadHypothesisEvidence(db *store.DB, scanID int64, h store.Hypothesis) wmHypothesisCard {
	card := wmHypothesisCard{Hypothesis: h}

	// Count directives by status, scoped to this hypothesis.
	rows, err := db.Conn().Query(`
		SELECT status, COUNT(*)
		FROM follow_ups
		WHERE scan_id = ? AND hypothesis_id = ?
		GROUP BY status`, scanID, h.ID)
	if err == nil {
		for rows.Next() {
			var status string
			var n int
			if err := rows.Scan(&status, &n); err != nil {
				continue
			}
			switch status {
			case store.FollowUpDone:
				card.DirectivesDone = n
			case store.FollowUpFailed:
				card.DirectivesFailed = n
			case store.FollowUpPending, store.FollowUpRunning:
				card.DirectivesPending += n
			}
		}
		rows.Close()
	}

	// Pull the most recent result strings. These are Explorer's short-form
	// verdicts like "3 probes → CONFIRMED IDOR (confidence 0.85)" or
	// "HTTP 200, 1234 bytes". Cap at 4 so the prompt stays bounded.
	rows2, err := db.Conn().Query(`
		SELECT action, COALESCE(result,''), status
		FROM follow_ups
		WHERE scan_id = ? AND hypothesis_id = ? AND status IN ('done','failed')
		ORDER BY COALESCE(completed_at, created_at) DESC
		LIMIT 4`, scanID, h.ID)
	if err == nil {
		for rows2.Next() {
			var action, result, status string
			if err := rows2.Scan(&action, &result, &status); err != nil {
				continue
			}
			// Keep snippets short; the Strategist just needs the verdict.
			if len(result) > 160 {
				result = result[:160] + "…"
			}
			if result == "" {
				result = "(no result captured)"
			}
			card.EvidenceSnippets = append(card.EvidenceSnippets,
				fmt.Sprintf("%s[%s]: %s", action, status, result))
		}
		rows2.Close()
	}

	// Confirmed findings linked directly to this hypothesis via the
	// findings.hypothesis_id column (populated when Explorer or Verifier
	// produced the finding). Direct link is reliable; the old
	// endpoint_id-JOIN approach missed Strategist-originated findings
	// because Strategist directives don't carry source_profile_id.
	rows3, err := db.Conn().Query(`
		SELECT id, title, severity
		FROM findings
		WHERE scan_id = ? AND hypothesis_id = ? AND confidence = 'confirmed'
		LIMIT 5`, scanID, h.ID)
	if err == nil {
		for rows3.Next() {
			var id int64
			var title, severity string
			if err := rows3.Scan(&id, &title, &severity); err != nil {
				continue
			}
			card.LinkedFindings = append(card.LinkedFindings,
				fmt.Sprintf("finding:%d [%s] %s", id, severity, title))
		}
		rows3.Close()
	}

	return card
}
