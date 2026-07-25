package ui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/internal/store"
)

// handleExport builds a portable scan report in either Markdown or self-
// contained HTML and serves it as a download.
//
//	GET /api/scan/export?scan_id=42&format=md
//	GET /api/scan/export?scan_id=42&format=html
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	scanID := s.scanIDFromRequest(r)
	format := strings.ToLower(r.URL.Query().Get("format"))
	if format == "" {
		format = "md"
	}

	report, err := s.buildReport(scanID)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}

	targetSafe := sanitizeFilename(report.Target)
	ts := time.Now().Format("20060102-150405")

	switch format {
	case "md", "markdown":
		body := renderMarkdown(report)
		filename := fmt.Sprintf("aobtd-scan-%d-%s-%s.md", scanID, targetSafe, ts)
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		w.Write([]byte(body))
	case "html":
		body := renderHTML(report)
		filename := fmt.Sprintf("aobtd-scan-%d-%s-%s.html", scanID, targetSafe, ts)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		w.Write([]byte(body))
	default:
		jsonError(w, "unknown format: "+format+" (use md or html)", 400)
	}
}

// scanReport is the denormalized shape we feed the formatters.
type scanReport struct {
	ScanID        int64
	Target        string
	Status        string
	StartedAt     string
	FinishedAt    string
	TotalTokens   int
	CostUSD       float64
	EndpointCount int
	TrafficCount  int

	// Smart-Analysis enrichment — an accumulated picture of the target
	// built up across the scan (app_type heuristic, LLM-authored summary,
	// functional areas like "authentication"/"admin"/"checkout" with
	// security priorities, and matched page templates). Sourced from the
	// `app_understanding` table populated by the analyzer agent.
	AppType         string
	AppSummary      string
	FunctionalAreas []reportFunctionalArea
	PageTemplates   []reportPageTemplate
	Recon           extract.ReconModel

	Findings    []map[string]any // already severity-ordered
	Changes     []store.AssetChange
	Profiles    []profileSummary
	Narrations  []store.Narration // trimmed to most recent N
	Discoveries map[string]int    // kind -> count
}

type profileSummary struct {
	ID              string
	URL             string
	Method          string
	Purpose         string
	IssueCount      int
	Confidence      float64
	AuthRequired    string
	TemplateID      string // empty if not matched to a template
	InputCount      int    // total distinct inputs (union of LLM + extracted)
	ExtractedInputs int    // subset discovered by the zero-cost extractor
}

// reportFunctionalArea is the exported shape of an app-understanding
// functional area (authentication, admin, checkout, etc.) with its
// security priority and endpoint count.
type reportFunctionalArea struct {
	Name          string
	Priority      int
	EndpointCount int
}

// reportPageTemplate is a page template matched during analysis
// (e.g. "get_rest_products_search" seen 2 times).
type reportPageTemplate struct {
	ID            string
	Description   string
	EndpointCount int
}

func (s *Server) buildReport(scanID int64) (*scanReport, error) {
	r := &scanReport{ScanID: scanID}

	// Scan row
	err := s.db.Conn().QueryRow(`
		SELECT target, status, started_at, COALESCE(finished_at,'')
		FROM scans WHERE id = ?`, scanID,
	).Scan(&r.Target, &r.Status, &r.StartedAt, &r.FinishedAt)
	if err != nil {
		return nil, fmt.Errorf("scan not found: %w", err)
	}

	// LLM stats
	if totalIn, totalOut, _, _, costU, err := s.db.GetAILogStats(scanID); err == nil {
		r.TotalTokens = totalIn + totalOut
		r.CostUSD = float64(costU) / 1_000_000.0
	}

	// Endpoint count
	s.db.Conn().QueryRow(`
		SELECT COUNT(DISTINCT endpoint_hash) FROM traffic
		WHERE scan_id = ? AND is_filtered = FALSE`, scanID).Scan(&r.EndpointCount)

	// Traffic count
	s.db.Conn().QueryRow(`
		SELECT COUNT(*) FROM traffic WHERE scan_id = ?`, scanID).Scan(&r.TrafficCount)

	// Findings (confirmed first, highest severity first) — re-use the same
	// query the UI uses so the export matches what the user saw.
	rows, err := s.db.Conn().Query(`
		SELECT id, title, description, severity, confidence,
		       endpoint_id, evidence, COALESCE(remediation,''),
		       COALESCE(vuln_type,''), COALESCE(param_name,''), COALESCE(payload,''),
		       COALESCE(poc_request,''), COALESCE(poc_response,''),
		       COALESCE(steps_to_reproduce,''), COALESCE(impact,''),
		       created_at
		FROM findings WHERE scan_id = ?
		ORDER BY
			CASE confidence WHEN 'confirmed' THEN 0 WHEN 'possible' THEN 1 ELSE 2 END,
			CASE severity
				WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
				WHEN 'low' THEN 4 ELSE 5 END`, scanID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id int64
			var title, description, severity, confidence, endpointID, evidence, remediation string
			var vulnType, paramName, payload, pocReq, pocResp, steps, impact, createdAt string
			rows.Scan(&id, &title, &description, &severity, &confidence,
				&endpointID, &evidence, &remediation,
				&vulnType, &paramName, &payload,
				&pocReq, &pocResp, &steps, &impact,
				&createdAt)
			r.Findings = append(r.Findings, map[string]any{
				"id": id, "title": title, "description": description,
				"severity": severity, "confidence": confidence,
				"endpoint_id": endpointID, "evidence": evidence,
				"remediation": remediation, "created_at": createdAt,
				"vuln_type": vulnType, "param_name": paramName, "payload": payload,
				"poc_request": pocReq, "poc_response": pocResp,
				"steps_to_reproduce": steps, "impact": impact,
			})
		}
	}

	// Changes (Δ view)
	r.Changes, _ = s.db.ListAssetChanges(scanID, 50)

	// Profile summaries. Now includes the Smart-Analysis extras:
	//   - TemplateID so a pentest report shows "this endpoint matched the
	//     login-form template" at a glance
	//   - InputCount (union of LLM + extractor) and ExtractedInputs
	//     (zero-LLM-cost subset) so report reviewers can see how much of
	//     the surface was captured without spending tokens
	profs, _ := s.db.GetAllProfiles(scanID)
	for _, p := range profs {
		// Union distinct by name+location — same logic the analyzer uses
		seen := make(map[string]struct{}, len(p.Inputs)+len(p.ExtractedInputs))
		for _, inp := range p.ExtractedInputs {
			seen[inp.Name+":"+inp.Location] = struct{}{}
		}
		for _, inp := range p.Inputs {
			seen[inp.Name+":"+inp.Location] = struct{}{}
		}
		r.Profiles = append(r.Profiles, profileSummary{
			ID:              p.ID,
			URL:             p.URL,
			Method:          p.Method,
			Purpose:         p.Purpose,
			IssueCount:      len(p.Issues),
			Confidence:      p.Confidence,
			AuthRequired:    p.AuthRequired,
			TemplateID:      p.TemplateID,
			InputCount:      len(seen),
			ExtractedInputs: len(p.ExtractedInputs),
		})
	}

	// Application understanding — the evolving model the analyzer built
	// across the scan. Pulled from the `app_understanding` table. Renders
	// as a high-level "here's what the target does" section in the report.
	if appType, tmplJSON, areasJSON, _, summary, err := s.db.GetAppUnderstanding(scanID); err == nil {
		r.AppType = appType
		r.AppSummary = summary
		// Templates and areas are stored as JSON blobs — parse into the
		// report's exported shapes.
		var tmpls []struct {
			ID            string `json:"id"`
			Description   string `json:"description"`
			EndpointCount int    `json:"endpoint_count"`
		}
		if json.Unmarshal([]byte(tmplJSON), &tmpls) == nil {
			for _, t := range tmpls {
				r.PageTemplates = append(r.PageTemplates, reportPageTemplate{
					ID: t.ID, Description: t.Description, EndpointCount: t.EndpointCount,
				})
			}
		}
		var areas []struct {
			Name      string   `json:"name"`
			Priority  int      `json:"priority"`
			Endpoints []string `json:"endpoints"`
		}
		if json.Unmarshal([]byte(areasJSON), &areas) == nil {
			for _, a := range areas {
				r.FunctionalAreas = append(r.FunctionalAreas, reportFunctionalArea{
					Name: a.Name, Priority: a.Priority, EndpointCount: len(a.Endpoints),
				})
			}
		}
	}
	if reconJSON, err := s.db.GetReconModel(scanID); err == nil {
		_ = json.Unmarshal([]byte(reconJSON), &r.Recon)
		u := extract.NewAppUnderstanding()
		u.AppType = r.AppType
		u.Summary = r.AppSummary
		u.Recon = r.Recon
		u.NormalizeReconModel()
		r.Recon = u.Recon
	}

	// Trim narrations so the export doesn't bloat — most interesting are
	// auth, verifier confirmations, and change-detector diffs.
	narr, _ := s.db.GetNarrations(scanID, 0, 2000)
	for _, n := range narr {
		if n.Action == "thought" || n.Action == "confirmed" ||
			n.Action == "diff" || n.Agent == "auth" ||
			n.Agent == "verifier" || n.Agent == "change-detector" {
			r.Narrations = append(r.Narrations, n)
		}
	}
	if len(r.Narrations) > 80 {
		r.Narrations = r.Narrations[len(r.Narrations)-80:]
	}

	// Discovery-graph kind counts
	r.Discoveries = map[string]int{}
	rows2, err := s.db.Conn().Query(`
		SELECT kind, COUNT(*) FROM url_discoveries WHERE scan_id = ? GROUP BY kind`, scanID)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var kind string
			var n int
			rows2.Scan(&kind, &n)
			r.Discoveries[kind] = n
		}
	}
	return r, nil
}

// renderMarkdown produces an engineer-friendly report. Copy-pastes cleanly
// into bug-bounty submissions and renders nicely in any Markdown viewer.
func renderMarkdown(r *scanReport) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# AOBTD scan report — %s\n\n", r.Target)
	fmt.Fprintf(&b, "> Scan `#%d` · status `%s` · started `%s`", r.ScanID, r.Status, r.StartedAt)
	if r.FinishedAt != "" {
		fmt.Fprintf(&b, " · finished `%s`", r.FinishedAt)
	}
	b.WriteString("\n\n")
	b.WriteString("Generated by [AOBTD](https://github.com/ozzyw/aobtd) — an LLM-powered DAST.\n\n")

	// Executive summary
	b.WriteString("## Executive summary\n\n")
	fmt.Fprintf(&b, "- **Target:** `%s`\n", r.Target)
	fmt.Fprintf(&b, "- **Endpoints discovered:** %d\n", r.EndpointCount)
	fmt.Fprintf(&b, "- **Traffic captured:** %d requests\n", r.TrafficCount)
	fmt.Fprintf(&b, "- **Findings:** %d total\n", len(r.Findings))
	confirmed := 0
	critHigh := 0
	for _, f := range r.Findings {
		if strings.EqualFold(fmt.Sprint(f["confidence"]), "confirmed") {
			confirmed++
		}
		sev := strings.ToLower(fmt.Sprint(f["severity"]))
		if sev == "critical" || sev == "high" {
			critHigh++
		}
	}
	fmt.Fprintf(&b, "- **Confirmed findings:** %d\n", confirmed)
	fmt.Fprintf(&b, "- **Critical / High:** %d\n", critHigh)
	fmt.Fprintf(&b, "- **LLM tokens used:** %s · estimated spend: **$%.4f**\n\n",
		fmtNum(r.TotalTokens), r.CostUSD)

	// Application understanding — a high-level "what does this target do"
	// section before findings. Lets a reviewer read the report linearly:
	// context → what was discovered → what's broken.
	if r.AppType != "" || r.AppSummary != "" || len(r.FunctionalAreas) > 0 || len(r.PageTemplates) > 0 {
		b.WriteString("## Application understanding\n\n")
		b.WriteString("The analyzer accumulated this model of the target across the scan:\n\n")
		if r.AppType != "" {
			fmt.Fprintf(&b, "- **App type:** %s\n", r.AppType)
		}
		if r.AppSummary != "" {
			fmt.Fprintf(&b, "- **Summary:** %s\n", r.AppSummary)
		}
		b.WriteString("\n")

		if len(r.FunctionalAreas) > 0 {
			b.WriteString("### Functional areas\n\n")
			b.WriteString("Grouped by role in the application. Higher priority = more security-relevant.\n\n")
			b.WriteString("| Area | Priority | Endpoints |\n")
			b.WriteString("|---|---:|---:|\n")
			for _, a := range r.FunctionalAreas {
				fmt.Fprintf(&b, "| %s | %d | %d |\n", a.Name, a.Priority, a.EndpointCount)
			}
			b.WriteString("\n")
		}

		if len(r.PageTemplates) > 0 {
			b.WriteString("### Page templates\n\n")
			b.WriteString("Pages with identical input structure were treated as one template — the analyzer confirmed on the first hit and quick-verified on repeats.\n\n")
			b.WriteString("| Template | Description | Instances |\n")
			b.WriteString("|---|---|---:|\n")
			for _, t := range r.PageTemplates {
				desc := truncForTable(t.Description, 100)
				fmt.Fprintf(&b, "| `%s` | %s | %d |\n", t.ID, desc, t.EndpointCount)
			}
			b.WriteString("\n")
		}

		if len(r.Recon.Pages)+len(r.Recon.Roles)+len(r.Recon.Objects)+len(r.Recon.Workflows)+len(r.Recon.OwnershipBoundaries)+len(r.Recon.Unknowns) > 0 {
			b.WriteString("### Semantic application model\n\n")
			fmt.Fprintf(&b, "Understanding: **%.0f%% (%s)** · model confidence: **%.0f%%** · %d/%d targets met · %d roles · %d objects · %d workflows · %d ownership boundaries · %d open questions.\n\n",
				r.Recon.Metrics.UnderstandingScore*100, r.Recon.Metrics.UnderstandingLevel,
				r.Recon.Metrics.OverallConfidence*100, r.Recon.Metrics.TargetsMet, r.Recon.Metrics.TargetsTotal,
				len(r.Recon.Roles), len(r.Recon.Objects), len(r.Recon.Workflows), len(r.Recon.OwnershipBoundaries), len(r.Recon.Unknowns))
			if len(r.Recon.Targets) > 0 {
				b.WriteString("#### Target-app understanding goals\n\n")
				b.WriteString("| Target | Current | Goal | Status |\n")
				b.WriteString("|---|---:|---:|---|\n")
				for _, target := range r.Recon.Targets {
					status := "gap"
					if target.Met {
						status = "met"
					}
					fmt.Fprintf(&b, "| %s | %.0f%% | %.0f%% | %s |\n", target.Label, target.Actual*100, target.Target*100, status)
				}
				b.WriteString("\n")
			}
			if len(r.Recon.Workflows) > 0 {
				b.WriteString("#### Human workflows\n\n")
				for _, w := range r.Recon.Workflows {
					fmt.Fprintf(&b, "- **%s** (confidence %.0f%%): %s\n", w.Name, w.Confidence*100, w.Description)
					for i, step := range w.Steps {
						fmt.Fprintf(&b, "  %d. %s", i+1, step.Label)
						if len(step.PageIDs) > 0 {
							fmt.Fprintf(&b, " — `%s`", strings.Join(step.PageIDs, "`, `"))
						}
						b.WriteString("\n")
					}
				}
				b.WriteString("\n")
			}
			if len(r.Recon.OwnershipBoundaries) > 0 {
				b.WriteString("#### Ownership and trust boundaries\n\n")
				for _, boundary := range r.Recon.OwnershipBoundaries {
					fmt.Fprintf(&b, "- **%s:** %s (confidence %.0f%%)\n", boundary.ObjectID, boundary.Rule, boundary.Confidence*100)
				}
				b.WriteString("\n")
			}
			if len(r.Recon.Unknowns) > 0 {
				b.WriteString("#### Open recon questions\n\n")
				for _, unknown := range r.Recon.Unknowns {
					fmt.Fprintf(&b, "- **P%d — %s**", unknown.Priority, unknown.Question)
					if unknown.SuggestedAction != "" {
						fmt.Fprintf(&b, " Next: %s", unknown.SuggestedAction)
					}
					b.WriteString("\n")
				}
				b.WriteString("\n")
			}
		}
	}

	// Changes (only if any)
	if len(r.Changes) > 0 {
		b.WriteString("## Changes since last scan of this target\n\n")
		b.WriteString("The LLM change-detector compared this scan's JS/HTML against the most recent prior scan and flagged the following drift:\n\n")
		for _, c := range r.Changes {
			fmt.Fprintf(&b, "### [%s] %s\n\n", strings.ToUpper(c.Severity), c.URL)
			fmt.Fprintf(&b, "- Previous scan: `#%d`  → current scan: `#%d`\n", c.PrevScanID, c.ScanID)
			fmt.Fprintf(&b, "- Size: %d → %d bytes\n", c.PrevSize, c.NewSize)
			fmt.Fprintf(&b, "- Content-type: `%s`\n\n", c.ContentType)
			if c.LLMComment != "" {
				fmt.Fprintf(&b, "**Comment:** %s\n\n", c.LLMComment)
			}
			if c.DiffSnippet != "" {
				b.WriteString("<details><summary>Diff snippet</summary>\n\n```\n")
				b.WriteString(c.DiffSnippet)
				b.WriteString("\n```\n\n</details>\n\n")
			}
		}
	}

	// Findings — confirmed first
	if len(r.Findings) > 0 {
		b.WriteString("## Findings\n\n")
		for _, f := range r.Findings {
			renderMarkdownFinding(&b, f)
		}
	} else {
		b.WriteString("## Findings\n\n_No findings recorded._\n\n")
	}

	// Notable endpoints — now includes the matched page template and
	// the total distinct input count (LLM + extractor union), so a
	// reviewer can immediately see where the attack surface is.
	if len(r.Profiles) > 0 {
		b.WriteString("## Notable endpoints\n\n")
		b.WriteString("| Method | URL | Template | Purpose | Inputs | Issues | Auth |\n")
		b.WriteString("|---|---|---|---|---:|---:|---|\n")
		for i, p := range r.Profiles {
			if i >= 40 {
				break
			}
			purpose := truncForTable(p.Purpose, 80)
			url := truncForTable(p.URL, 60)
			tmpl := p.TemplateID
			if tmpl == "" {
				tmpl = "—"
			} else {
				tmpl = "`" + truncForTable(tmpl, 40) + "`"
			}
			fmt.Fprintf(&b, "| %s | `%s` | %s | %s | %d | %d | %s |\n",
				p.Method, url, tmpl, purpose, p.InputCount, p.IssueCount, p.AuthRequired)
		}
		b.WriteString("\n")
	}

	// Discovery graph summary
	if len(r.Discoveries) > 0 {
		b.WriteString("## Discovery graph\n\n")
		b.WriteString("How endpoints were found:\n\n")
		for kind, n := range r.Discoveries {
			fmt.Fprintf(&b, "- `%s` — %d edges\n", kind, n)
		}
		b.WriteString("\n")
	}

	// Agent reasoning log
	if len(r.Narrations) > 0 {
		b.WriteString("## Agent reasoning log (most recent)\n\n")
		b.WriteString("Key moments the agents narrated during the scan:\n\n")
		for _, n := range r.Narrations {
			fmt.Fprintf(&b, "- **%s** `[%s]` — %s\n", n.Agent, n.Action, n.Message)
		}
		b.WriteString("\n")
	}

	b.WriteString("---\n\n_End of report_\n")
	return b.String()
}

func renderMarkdownFinding(b *strings.Builder, f map[string]any) {
	severity := strings.ToUpper(fmt.Sprint(f["severity"]))
	confidence := strings.ToUpper(fmt.Sprint(f["confidence"]))
	title := fmt.Sprint(f["title"])
	vuln := fmt.Sprint(f["vuln_type"])
	endpoint := fmt.Sprint(f["endpoint_id"])
	createdAt := fmt.Sprint(f["created_at"])

	fmt.Fprintf(b, "### [%s · %s] %s\n\n", severity, confidence, title)
	if vuln != "" {
		fmt.Fprintf(b, "**Class:** `%s`\n\n", vuln)
	}
	if endpoint != "" {
		fmt.Fprintf(b, "**Endpoint:** `%s`\n\n", endpoint)
	}
	fmt.Fprintf(b, "**Found:** %s\n\n", createdAt)

	if desc := fmt.Sprint(f["description"]); desc != "" && desc != "<nil>" {
		b.WriteString("**Summary**\n\n")
		b.WriteString(desc)
		b.WriteString("\n\n")
	}
	if impact := fmt.Sprint(f["impact"]); impact != "" && impact != "<nil>" {
		b.WriteString("**Impact**\n\n")
		b.WriteString(impact)
		b.WriteString("\n\n")
	}
	if steps := fmt.Sprint(f["steps_to_reproduce"]); steps != "" && steps != "<nil>" {
		b.WriteString("**Steps to reproduce**\n\n")
		b.WriteString(steps)
		b.WriteString("\n\n")
	}
	if pocReq := fmt.Sprint(f["poc_request"]); pocReq != "" && pocReq != "<nil>" {
		b.WriteString("**Proof of exploitation — request**\n\n```http\n")
		b.WriteString(pocReq)
		b.WriteString("\n```\n\n")
	}
	if pocResp := fmt.Sprint(f["poc_response"]); pocResp != "" && pocResp != "<nil>" {
		b.WriteString("**Proof of exploitation — response**\n\n```http\n")
		b.WriteString(pocResp)
		b.WriteString("\n```\n\n")
	}
	if remediation := fmt.Sprint(f["remediation"]); remediation != "" && remediation != "<nil>" {
		b.WriteString("**Remediation**\n\n")
		b.WriteString(remediation)
		b.WriteString("\n\n")
	}
	if evidence := fmt.Sprint(f["evidence"]); evidence != "" && evidence != "<nil>" &&
		fmt.Sprint(f["poc_request"]) == "" {
		b.WriteString("**Evidence**\n\n```\n")
		b.WriteString(evidence)
		b.WriteString("\n```\n\n")
	}
	b.WriteString("---\n\n")
}

// renderHTML wraps the markdown report in a self-contained, Ctrl-P-friendly
// HTML page. Keeps the dark theme so it matches the UI, but includes a
// @media print section so printing produces a clean white-bg PDF.
func renderHTML(r *scanReport) string {
	md := renderMarkdown(r)
	// Very light markdown → HTML conversion — just enough for headings,
	// lists, code blocks, and tables. We don't want a dependency for this.
	html := mdToHTML(md)

	var b strings.Builder
	b.WriteString(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>AOBTD scan report — `)
	b.WriteString(escapeHTML(r.Target))
	b.WriteString(`</title>
<style>
:root { color-scheme: dark; }
body { font-family: -apple-system, Segoe UI, system-ui, sans-serif; background: #0d1117; color: #e6edf3; max-width: 920px; margin: 0 auto; padding: 40px 32px; line-height: 1.6; }
h1 { font-size: 26px; border-bottom: 1px solid #30363d; padding-bottom: 12px; }
h2 { font-size: 20px; margin-top: 36px; border-bottom: 1px solid #30363d; padding-bottom: 8px; }
h3 { font-size: 16px; margin-top: 28px; }
h4 { font-size: 14px; margin-top: 20px; color: #8b949e; text-transform: uppercase; letter-spacing: .5px; }
code { background: #21262d; padding: 1px 6px; border-radius: 3px; font-size: 12.5px; }
pre { background: #0a0d11; border: 1px solid #30363d; border-radius: 6px; padding: 12px; overflow-x: auto; font-size: 12px; line-height: 1.5; }
pre code { background: none; padding: 0; font-size: 12px; }
blockquote { border-left: 3px solid #30363d; padding: 4px 14px; color: #8b949e; margin: 12px 0; }
table { border-collapse: collapse; width: 100%; margin: 12px 0; }
th, td { border: 1px solid #30363d; padding: 6px 10px; text-align: left; font-size: 13px; }
th { background: #161b22; }
hr { border: none; border-top: 1px solid #30363d; margin: 28px 0; }
a { color: #58a6ff; }
details > summary { cursor: pointer; color: #8b949e; margin: 8px 0; }
@media print {
  body { background: #fff; color: #24292f; max-width: none; padding: 24px; }
  h1, h2, h3 { color: #000; border-color: #d0d7de; }
  h4 { color: #57606a; }
  code, pre { background: #f6f8fa; border: 1px solid #d0d7de; color: #24292f; }
  th { background: #f6f8fa; color: #000; }
  a { color: #0969da; }
  blockquote { color: #57606a; }
}
</style></head><body>
`)
	b.WriteString(html)
	b.WriteString(`
</body></html>`)
	return b.String()
}

// mdToHTML is a deliberately tiny markdown→HTML converter. We only handle
// the constructs our own renderMarkdown actually emits so we don't need a
// dependency. Supports: headings, blockquote, code fences, inline code,
// tables, lists, horizontal rules, bold, paragraphs.
func mdToHTML(md string) string {
	lines := strings.Split(md, "\n")
	var out strings.Builder

	inCode := false
	inList := false
	inTable := false

	closeList := func() {
		if inList {
			out.WriteString("</ul>\n")
			inList = false
		}
	}
	closeTable := func() {
		if inTable {
			out.WriteString("</tbody></table>\n")
			inTable = false
		}
	}

	for i := 0; i < len(lines); i++ {
		line := lines[i]

		// Code fence
		if strings.HasPrefix(line, "```") {
			if inCode {
				out.WriteString("</code></pre>\n")
				inCode = false
			} else {
				closeList()
				closeTable()
				out.WriteString("<pre><code>")
				inCode = true
			}
			continue
		}
		if inCode {
			out.WriteString(escapeHTML(line))
			out.WriteString("\n")
			continue
		}

		// Horizontal rule
		if strings.TrimSpace(line) == "---" {
			closeList()
			closeTable()
			out.WriteString("<hr>\n")
			continue
		}

		// Headings
		if strings.HasPrefix(line, "### ") {
			closeList()
			closeTable()
			out.WriteString("<h3>" + renderInline(line[4:]) + "</h3>\n")
			continue
		}
		if strings.HasPrefix(line, "## ") {
			closeList()
			closeTable()
			out.WriteString("<h2>" + renderInline(line[3:]) + "</h2>\n")
			continue
		}
		if strings.HasPrefix(line, "# ") {
			closeList()
			closeTable()
			out.WriteString("<h1>" + renderInline(line[2:]) + "</h1>\n")
			continue
		}

		// Blockquote
		if strings.HasPrefix(line, "> ") {
			closeList()
			closeTable()
			out.WriteString("<blockquote>" + renderInline(line[2:]) + "</blockquote>\n")
			continue
		}

		// Table: header line
		if strings.HasPrefix(line, "| ") && i+1 < len(lines) && strings.HasPrefix(lines[i+1], "|") && strings.Contains(lines[i+1], "---") {
			closeList()
			closeTable()
			out.WriteString("<table><thead><tr>")
			for _, cell := range splitTableRow(line) {
				out.WriteString("<th>" + renderInline(cell) + "</th>")
			}
			out.WriteString("</tr></thead><tbody>\n")
			i++ // skip the separator row
			inTable = true
			continue
		}
		if inTable && strings.HasPrefix(line, "| ") {
			out.WriteString("<tr>")
			for _, cell := range splitTableRow(line) {
				out.WriteString("<td>" + renderInline(cell) + "</td>")
			}
			out.WriteString("</tr>\n")
			continue
		}
		if inTable {
			closeTable()
		}

		// List item
		if strings.HasPrefix(line, "- ") {
			if !inList {
				out.WriteString("<ul>\n")
				inList = true
			}
			out.WriteString("  <li>" + renderInline(line[2:]) + "</li>\n")
			continue
		}
		if inList {
			closeList()
		}

		// Blank line → paragraph break
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			out.WriteString("\n")
			continue
		}

		// Regular paragraph line — pass through with inline markup
		out.WriteString("<p>" + renderInline(line) + "</p>\n")
	}
	closeList()
	closeTable()
	if inCode {
		out.WriteString("</code></pre>\n")
	}
	return out.String()
}

// renderInline handles inline markup: **bold**, `code`, and [text](link).
func renderInline(s string) string {
	s = escapeHTML(s)
	// inline code: `...`
	s = replaceDelim(s, "`", "<code>", "</code>")
	// bold: **...**
	s = replaceDelim(s, "**", "<strong>", "</strong>")
	return s
}

func replaceDelim(s, delim, openTag, closeTag string) string {
	parts := strings.Split(s, delim)
	if len(parts) < 3 {
		return s
	}
	var b strings.Builder
	for i, p := range parts {
		if i > 0 {
			if i%2 == 1 {
				b.WriteString(openTag)
			} else {
				b.WriteString(closeTag)
			}
		}
		b.WriteString(p)
	}
	// If we ended mid-pair, append a closing tag so HTML stays valid.
	if len(parts)%2 == 0 {
		b.WriteString(closeTag)
	}
	return b.String()
}

func splitTableRow(line string) []string {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "|")
	line = strings.TrimSuffix(line, "|")
	raw := strings.Split(line, "|")
	out := make([]string, 0, len(raw))
	for _, c := range raw {
		out = append(out, strings.TrimSpace(c))
	}
	return out
}

// ── helpers ──

func fmtNum(n int) string {
	if n < 1000 {
		return strconv.Itoa(n)
	}
	if n < 1000000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	}
	return fmt.Sprintf("%.2fM", float64(n)/1000000)
}

func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

func truncForTable(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > maxLen {
		return s[:maxLen] + "…"
	}
	return s
}

func sanitizeFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.' || r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := b.String()
	if out == "" {
		return "target"
	}
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}

// Ensure JSON helper is referenced so the build doesn't complain when we
// haven't needed it elsewhere.
var _ = json.Marshal
