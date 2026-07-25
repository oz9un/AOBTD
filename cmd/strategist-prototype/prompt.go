package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// strategistSystemPrompt defines the Sovereign Strategist role. Based on the
// research takeaways:
//   - Batch planner, not ReAct — we emit a plan, we exit
//   - Evidence-grounded — every directive must cite a profile/finding/host
//   - Structured output — enum of valid action types, no free-form tools
//   - Produces an executive summary for the next cycle's context compression
const strategistSystemPrompt = `You are the SOVEREIGN STRATEGIST of a web penetration-testing tool.

You do not interact with the target directly. You look at the current state of an ongoing scan and decide what the specialist agents (Crawler, Explorer, Verifier, Analyzer) should do NEXT. You run periodically — not continuously — so every plan you emit must stand on its own for the next N minutes.

Your output drives real work: directives you emit go into a queue that specialist agents execute against a live target. Bad directives waste time and tokens; blindly-guessed directives get the tool DDoS'd or banned. Be precise.

## How to think

1. **Read the world model.** You will receive a compressed summary of the scan's state: app understanding, hosts, endpoints carrying issues, confirmed findings, and recent agent thoughts.
2. **Form 1-3 hypotheses** about the target. Each hypothesis is a short claim about the application ("This is a Turkish e-commerce SPA with a Laravel-style admin at /nova", "Sequential numeric ids in /orderdetail/{id} suggest IDOR", "Authentication is enforced via a JWT in Authorization header").
3. **Emit grounded directives** that test or advance those hypotheses. Every directive MUST cite the evidence (endpoint IDs, finding IDs, host names) that motivated it via the "grounded_in" field. If you cannot cite evidence, do not emit the directive.
4. **Keep the plan tight.** At most 8 directives per cycle. Prioritize the highest-information-gain probes.
5. **Update the executive summary.** A ~300-character summary of your current understanding that seeds the next cycle.

## Available directive actions

Each directive has an "action" field with one of:

- **"probe_idor"** — probe a URL with different ids to check for authorization bypass.
  Requires: url_template (with "{id}" placeholder), values (4-6 distinct ids).
- **"probe_logic"** — mutate a single body/form field with illegal values to test server validation.
  Requires: url, field (name), values (3-6 test values).
- **"fetch"** — GET a URL to capture new traffic (used to reach suspected endpoints not yet crawled).
  Requires: url.
- **"reanalyze"** — re-run LLM analysis on an endpoint with updated context (use when new information changes understanding).
  Requires: endpoint_id.
- **"stop"** — conclude a line of inquiry as resolved or unproductive.
  Requires: hypothesis_id and reason.

## Grounding rules (strict)

- Every non-"stop" directive must have "grounded_in" pointing to concrete IDs from the world model.
  Valid forms: "endpoint:<profile_id>", "finding:<id>", "host:<hostname>", "thought:<agent>/<action>".
- If the world model doesn't justify a directive, omit it. Do NOT invent endpoints, paths, or ids.

## Output schema

Return STRICT JSON with no prose outside:

{
  "hypotheses": [
    {
      "id": "h1",
      "statement": "one-sentence claim about the target",
      "confidence": 0.0-1.0,
      "supporting_evidence": ["endpoint:POST /login", "thought:analyzer/thought"]
    }
  ],
  "directives": [
    {
      "action": "probe_idor" | "probe_logic" | "fetch" | "reanalyze" | "stop",
      "url": "...",
      "url_template": "...",
      "field": "...",
      "values": ["..."],
      "endpoint_id": "...",
      "reason": "one-sentence first-person rationale",
      "grounded_in": ["endpoint:GET /api/users/{id}", "finding:42"],
      "hypothesis_id": "h1",
      "priority": 1-10
    }
  ],
  "executive_summary": "one-paragraph updated view of the target (max 400 chars)",
  "next_cycle_minutes": 5,
  "stop_if": ["no_new_findings_for_2_cycles"]
}`

// buildPrompt converts the WorldModel into a compact user prompt. Format is
// mostly tables/lists so the Strategist can scan it like a situation report.
func buildPrompt(wm *WorldModel) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# Scan situation report\n\n")
	fmt.Fprintf(&b, "Target: %s\nScan id: %d\nStatus: %s\n", wm.Target, wm.ScanID, wm.Status)
	if wm.Duration != "" {
		fmt.Fprintf(&b, "Duration so far: %s\n", wm.Duration)
	}
	if wm.AppUnderstanding != "" {
		fmt.Fprintf(&b, "App understanding: %s\n", wm.AppUnderstanding)
	}
	fmt.Fprintf(&b, "Counts: %d endpoints · %d profiles (%d with issues) · %d findings · %d narrations\n\n",
		wm.EndpointCount, wm.ProfileCount, wm.ProfilesWithIssues, wm.FindingCount, wm.NarrationCount)

	// Hosts
	if len(wm.Hosts) > 0 {
		b.WriteString("## Hosts crawled (by endpoint count)\n\n")
		for _, h := range wm.Hosts {
			fmt.Fprintf(&b, "- %s — %d endpoints\n", h.Host, h.Endpoints)
		}
		b.WriteString("\n")
	}

	// Top issue clusters
	if len(wm.TopIssues) > 0 {
		b.WriteString("## Issue themes across profiles\n\n")
		for _, c := range wm.TopIssues {
			fmt.Fprintf(&b, "- **%s** — flagged on %d profile(s). Examples: %s\n",
				c.Theme, c.Count, strings.Join(c.ExampleEndpoints, ", "))
		}
		b.WriteString("\n")
	}

	// Interesting endpoints — structured so Strategist can cite them as grounded_in
	if len(wm.InterestingEndpoints) > 0 {
		b.WriteString("## Highest-priority endpoints (ordered by relevance)\n\n")
		for _, e := range wm.InterestingEndpoints {
			fmt.Fprintf(&b, "- `%s` (id=%q)", e.Method+" "+e.Path, e.ID)
			if e.Auth != "" && e.Auth != "unknown" {
				fmt.Fprintf(&b, " · auth=%s", e.Auth)
			}
			if e.HasInput {
				b.WriteString(" · has_input")
			}
			if e.IsAPI {
				b.WriteString(" · api")
			}
			b.WriteString("\n")
			if e.Purpose != "" {
				fmt.Fprintf(&b, "  purpose: %s\n", e.Purpose)
			}
			if len(e.Issues) > 0 {
				fmt.Fprintf(&b, "  issues: %s\n", strings.Join(e.Issues, " · "))
			}
		}
		b.WriteString("\n")
	}

	// Confirmed findings
	if len(wm.ConfirmedFindings) > 0 {
		b.WriteString("## Confirmed findings\n\n")
		for _, f := range wm.ConfirmedFindings {
			fmt.Fprintf(&b, "- finding:%d [%s/%s] %s → endpoint:%q\n",
				f.ID, f.Severity, f.VulnType, f.Title, f.Endpoint)
		}
		b.WriteString("\n")
	}

	if len(wm.DismissedFindings) > 0 {
		b.WriteString("## Analyzer-flagged but unverified issues\n\n")
		for _, f := range wm.DismissedFindings {
			fmt.Fprintf(&b, "- finding:%d [%s] %s → endpoint:%q\n",
				f.ID, f.severityStr(), f.Title, f.Endpoint)
		}
		b.WriteString("\n")
	}

	// Recent agent thoughts (the narrative)
	if len(wm.RecentThoughts) > 0 {
		b.WriteString("## Recent agent thoughts (oldest → newest)\n\n")
		for _, n := range wm.RecentThoughts {
			fmt.Fprintf(&b, "- %s [%s]: %s\n", n.Agent, n.Action, n.Message)
		}
		b.WriteString("\n")
	}

	b.WriteString("\n## Now plan\n\nEmit the JSON per the schema in the system prompt.")
	return b.String()
}

func (f findingCard) severityStr() string {
	if f.Severity == "" {
		return "unknown"
	}
	return f.Severity
}

// ── Output parsing ──

type StrategistOutput struct {
	Hypotheses       []Hypothesis `json:"hypotheses"`
	Directives       []Directive  `json:"directives"`
	ExecutiveSummary string       `json:"executive_summary"`
	NextCycleMinutes int          `json:"next_cycle_minutes"`
	StopIf           []string     `json:"stop_if"`
}

type Hypothesis struct {
	ID                 string   `json:"id"`
	Statement          string   `json:"statement"`
	Confidence         float64  `json:"confidence"`
	SupportingEvidence []string `json:"supporting_evidence"`
}

type Directive struct {
	Action       string   `json:"action"`
	URL          string   `json:"url,omitempty"`
	URLTemplate  string   `json:"url_template,omitempty"`
	Field        string   `json:"field,omitempty"`
	Values       []string `json:"values,omitempty"`
	EndpointID   string   `json:"endpoint_id,omitempty"`
	Reason       string   `json:"reason,omitempty"`
	GroundedIn   []string `json:"grounded_in,omitempty"`
	HypothesisID string   `json:"hypothesis_id,omitempty"`
	Priority     int      `json:"priority,omitempty"`
}

// parseStrategistOutput handles both clean JSON and mixed-text responses.
func parseStrategistOutput(raw string) *StrategistOutput {
	var out StrategistOutput
	if err := json.Unmarshal([]byte(raw), &out); err == nil {
		return &out
	}
	// Try to peel out a JSON object embedded in prose / code fences
	start := strings.Index(raw, "{")
	end := strings.LastIndex(raw, "}")
	if start < 0 || end <= start {
		return nil
	}
	if err := json.Unmarshal([]byte(raw[start:end+1]), &out); err != nil {
		return nil
	}
	return &out
}
