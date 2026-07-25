package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

// WorldModel is the compressed view of a scan's state we hand to the Strategist.
// Goal: fit into a ~3-5k token prompt even when the raw scan has thousands of
// endpoints. We follow the Cognition/Manus pattern — structured summaries +
// top-K unresolved items, not a raw dump.
type WorldModel struct {
	ScanID   int64
	Target   string
	Status   string
	Duration string

	EndpointCount      int
	ProfileCount       int
	ProfilesWithIssues int
	FindingCount       int
	NarrationCount     int

	Hosts                []hostSummary  `json:"hosts"`
	TopIssues            []issueCluster `json:"top_issue_clusters"`
	InterestingEndpoints []endpointCard `json:"interesting_endpoints"`
	ConfirmedFindings    []findingCard  `json:"confirmed_findings"`
	DismissedFindings    []findingCard  `json:"dismissed_findings"`
	RecentThoughts       []narrationCard `json:"recent_agent_thoughts"`
	AppUnderstanding     string         `json:"app_understanding,omitempty"`
}

type hostSummary struct {
	Host      string `json:"host"`
	Endpoints int    `json:"endpoints"`
}

type issueCluster struct {
	Theme             string   `json:"theme"`
	Count             int      `json:"count"`
	ExampleEndpoints  []string `json:"example_endpoints"`
}

type endpointCard struct {
	ID       string   `json:"id"`        // profile id e.g. "GET /login" — Strategist grounds directives against this
	Method   string   `json:"method"`
	Path     string   `json:"path"`
	Purpose  string   `json:"purpose,omitempty"`
	Auth     string   `json:"auth,omitempty"`
	Issues   []string `json:"issues,omitempty"`
	HasInput bool     `json:"has_input"`
	IsAPI    bool     `json:"is_api"`
}

type findingCard struct {
	ID         int64  `json:"id"`
	Title      string `json:"title"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	Endpoint   string `json:"endpoint"`
	VulnType   string `json:"vuln_type,omitempty"`
}

type narrationCard struct {
	Agent   string `json:"agent"`
	Action  string `json:"action"`
	Message string `json:"message"`
}

func buildWorldModel(db *store.DB, scanID int64) (*WorldModel, error) {
	wm := &WorldModel{ScanID: scanID}

	// Scan metadata
	var startedAt, finishedAt string
	err := db.Conn().QueryRow(`
		SELECT target, status, started_at, COALESCE(finished_at,'')
		FROM scans WHERE id = ?`, scanID).
		Scan(&wm.Target, &wm.Status, &startedAt, &finishedAt)
	if err != nil {
		return nil, fmt.Errorf("load scan: %w", err)
	}
	if finishedAt != "" {
		if t1, err1 := time.Parse("2006-01-02 15:04:05", startedAt); err1 == nil {
			if t2, err2 := time.Parse("2006-01-02 15:04:05", finishedAt); err2 == nil {
				wm.Duration = t2.Sub(t1).Round(time.Second).String()
			}
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
	db.Conn().QueryRow(`SELECT COUNT(*) FROM narrations WHERE scan_id=?`, scanID).
		Scan(&wm.NarrationCount)

	// Hosts by endpoint count (top 10)
	rows, err := db.Conn().Query(`
		SELECT host, COUNT(DISTINCT endpoint_hash) AS n
		FROM traffic WHERE scan_id=? AND is_filtered=FALSE
		GROUP BY host ORDER BY n DESC LIMIT 10`, scanID)
	if err == nil {
		for rows.Next() {
			var h string
			var n int
			rows.Scan(&h, &n)
			wm.Hosts = append(wm.Hosts, hostSummary{Host: h, Endpoints: n})
		}
		rows.Close()
	}

	// Profiles
	profs, err := db.GetAllProfiles(scanID)
	if err != nil {
		return nil, fmt.Errorf("load profiles: %w", err)
	}
	wm.TopIssues = clusterIssues(profs)
	wm.InterestingEndpoints = topInterestingEndpoints(profs, 25)

	// Findings
	rowsF, err := db.Conn().Query(`
		SELECT id, title, severity, confidence, endpoint_id, COALESCE(vuln_type,'')
		FROM findings WHERE scan_id=?
		ORDER BY
			CASE confidence WHEN 'confirmed' THEN 0 WHEN 'possible' THEN 1 ELSE 2 END,
			CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
			              WHEN 'low' THEN 4 ELSE 5 END`, scanID)
	if err == nil {
		for rowsF.Next() {
			var f findingCard
			rowsF.Scan(&f.ID, &f.Title, &f.Severity, &f.Confidence, &f.Endpoint, &f.VulnType)
			if f.Confidence == "confirmed" {
				wm.ConfirmedFindings = append(wm.ConfirmedFindings, f)
			} else {
				wm.DismissedFindings = append(wm.DismissedFindings, f)
			}
		}
		rowsF.Close()
	}
	if len(wm.ConfirmedFindings) > 15 {
		wm.ConfirmedFindings = wm.ConfirmedFindings[:15]
	}
	if len(wm.DismissedFindings) > 8 {
		wm.DismissedFindings = wm.DismissedFindings[:8]
	}

	// Recent narrations — only the high-signal kinds
	rowsN, err := db.Conn().Query(`
		SELECT agent, action, message FROM narrations
		WHERE scan_id=? AND (
			action IN ('thought','confirmed','dismissed','queued_followups','diff','saturated','auth','phase','complete')
			OR agent IN ('verifier','change-detector','explorer','auth')
		)
		ORDER BY id DESC LIMIT 40`, scanID)
	if err == nil {
		for rowsN.Next() {
			var n narrationCard
			rowsN.Scan(&n.Agent, &n.Action, &n.Message)
			if len(n.Message) > 240 {
				n.Message = n.Message[:240] + "…"
			}
			wm.RecentThoughts = append(wm.RecentThoughts, n)
		}
		rowsN.Close()
	}
	// Reverse to oldest→newest so the Strategist reads the narrative chronologically
	for i, j := 0, len(wm.RecentThoughts)-1; i < j; i, j = i+1, j-1 {
		wm.RecentThoughts[i], wm.RecentThoughts[j] = wm.RecentThoughts[j], wm.RecentThoughts[i]
	}

	// App understanding
	var appType, summary string
	db.Conn().QueryRow(`
		SELECT COALESCE(app_type,''), COALESCE(summary,'')
		FROM app_understanding WHERE scan_id=?`, scanID).
		Scan(&appType, &summary)
	if appType != "" || summary != "" {
		wm.AppUnderstanding = strings.TrimSpace(appType + ": " + summary)
	}

	return wm, nil
}

// clusterIssues groups profile-level issue strings by keyword theme so the
// Strategist sees "47 profiles flag CSRF" not 47 near-identical strings.
// Dumb but effective — matches a handful of vulnerability keywords.
func clusterIssues(profs []types.PageProfile) []issueCluster {
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

	var out []issueCluster
	for _, t := range themes {
		if counts[t.key] > 0 {
			out = append(out, issueCluster{
				Theme:            t.key,
				Count:            counts[t.key],
				ExampleEndpoints: examples[t.key],
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

// topInterestingEndpoints picks profiles that are most likely worth the
// Strategist's attention: those with issues, with input, on API paths,
// or with auth requirements. Returns up to n.
func topInterestingEndpoints(profs []types.PageProfile, n int) []endpointCard {
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
	out := make([]endpointCard, 0, n)
	for _, p := range profs[:n] {
		out = append(out, endpointCard{
			ID:       p.ID,
			Method:   p.Method,
			Path:     pathOnly(p.URL),
			Purpose:  truncate2(p.Purpose, 180),
			Auth:     p.AuthRequired,
			Issues:   truncateStrings(p.Issues, 3),
			HasInput: len(p.Inputs) > 0,
			IsAPI:    looksLikeAPI(p.URL),
		})
	}
	return out
}

func pathOnly(rawURL string) string {
	// best-effort — avoid pulling net/url just for this. Split on :// and /.
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

func looksLikeAPI(u string) bool {
	lower := strings.ToLower(u)
	return strings.Contains(lower, "/api/") || strings.Contains(lower, "/v1/") ||
		strings.Contains(lower, "/v2/") || strings.Contains(lower, "/graphql")
}

func truncate2(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func truncateStrings(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
