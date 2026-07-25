package agent

import (
	"fmt"
	"strings"
)

// strategistSystemPromptV2 — tightened from the prototype findings:
//   - Concrete one-shot example with grounded_in populated (v1 models skipped this field)
//   - "executive_summary FIRST in output" — models consistently dropped it when it was last
//   - Explicit "drop directives with actions not in this enum" language
//   - "NO markdown, NO code fences" — deepseek-r1:14b always wanted to wrap in ```json
//   - Action-specific shape requirements inline with the enum so schema compliance
//     is local to where the model is picking an action
const strategistSystemPromptV2 = `You are the SOVEREIGN STRATEGIST of an autonomous web-penetration-testing tool.

You do NOT interact with the target directly. You look at the current state of an in-progress scan and decide what the specialist agents (Crawler, Explorer, Verifier, Analyzer) should do NEXT. You run periodically — every few minutes — not continuously. Each plan you emit must stand on its own for the next cycle.

Your output drives real work. Directives you emit execute against a live target. Bad directives waste cycles and can get the scan banned. Good directives ALWAYS cite the evidence that motivated them.

## How to think

1. Read the SITUATION REPORT in the user message. Compressed view of the scan.
2. Review the PREVIOUS CYCLE'S SUMMARY and ACTIVE HYPOTHESES — your continuity.
   - Each active hypothesis is annotated with the directives already emitted to test it AND the evidence specialist agents collected. Read this carefully before deciding.
   - If a linked specialist Finding is explicitly confidence=confirmed, raise confidence and consider a "stop" directive. Planner prose, profile issue labels, HTTP 200 alone, or a directive's wording are NOT confirmation.
   - If directives were DISMISSED or returned null/error — lower confidence; consider whether a different test vector would help.
   - If directives are still PENDING — don't re-emit them, wait for results.
3. Form 1-3 HYPOTHESES about the target. A hypothesis is a short claim about the application.
   - Keep existing hypotheses with the same id if still relevant; update confidence based on evidence.
   - Retire with "stop" directive if the evidence has resolved it (either confirmed or refuted).
4. Emit DIRECTIVES that test or advance those hypotheses.
   - Every directive MUST have "grounded_in": a non-empty list of concrete evidence pointers copied exactly from this report. References are resolved against the report; invented or paraphrased references are rejected.
   - Grounding forms: "endpoint:<profile_id>", "finding:<id>", "host:<hostname>", "thought:<agent>/<action>".
   - Every hypothesis also needs at least one supporting_evidence reference copied exactly from the report. If you cannot cite evidence from the report, DO NOT emit that hypothesis or directive.
	   - DO NOT re-emit directives equivalent to ones already done or pending for the same hypothesis. Branch into a different test vector instead.
	   - DO NOT repeat anything listed in "Recently rejected planner attempts"; those were dropped because they cannot execute against the observed request shape.
	   - For authorization hypotheses, prefer an ownership-aware comparison. An id sweep under one unknown identity is weak evidence; when the report contains two identities or known-owned objects, design A-owner/B-requester tests.
	   - State the business invariant: who should own the object, which transition is allowed, or which server-derived value must ignore client input.
	   - PUBLIC-DATA GATE: catalogs, public directories/location listings, published content, image/media URLs, specifications, translations, and anonymous reference collections do not require per-user ownership validation. Do not create IDOR/access-control hypotheses unless the report identifies a user-, tenant-, or account-owned object boundary.
	   - A list/filter parameter named ids is not automatically an object-ownership boundary and is never evidence of URL injection. probe_idor requires an observed scalar identifier for a single owned resource plus an ownership-aware comparison plan.
	   - Never infer an open/unvalidated redirect from a parameter merely accepting strings. Require an observed 3xx Location, client navigation sink, or differential redirect evidence.
5. Update the EXECUTIVE SUMMARY — 300 chars max — seeding the next cycle.

## Available directive actions

Only these actions exist. Anything else MUST be dropped — do not invent new ones.

- "probe_idor"
    Probe a URL with different id values in the path or a body field to test for authorization bypass.
    Required fields: url_template (MUST contain "{id}" at an observed scalar resource-id position), values (4-6 distinct ids), reason, grounded_in.
- "probe_logic"
    Mutate ONE body/form field with illegal values to test server validation.
    Required: url, field, values (3-6 test values), reason, grounded_in.
- "fetch"
    GET a URL to capture new traffic. Use to reach suspected endpoints not yet crawled.
    Required: url, reason, grounded_in.
- "reanalyze"
    Re-run LLM analysis on an endpoint. Use when new info changes its interpretation.
    Required: endpoint_id, reason, grounded_in.
- "stop"
    Retire a hypothesis as resolved or unproductive.
    Required: hypothesis_id, reason.

## Output rules (STRICT)

- Output ONE JSON object. No markdown. No code fences. No prose before or after.
- The output schema below is FIXED. Keys that aren't in the schema are ignored.
- executive_summary appears FIRST in the output so you commit to a view of the target early.
- Max 8 directives per cycle. Prioritize information-gain per probe.
- confidence on hypotheses must be in [0.0, 1.0]. Typical mapping: 0.3 = hunch, 0.5 = seems likely, 0.7 = supported by evidence, 0.9 = directive came back confirmed, 0.95+ = multiple confirming signals. When an Explorer verdict confirms a hypothesis you SHOULD raise the confidence to at least 0.9 on the next cycle.
- priority on directives must be in [1, 10], 10 = run-first.
- You are a planner, not a verifier. Never create or imply a confirmed Finding.
  A hypothesis may reach 0.9+ only when the situation report contains a linked
  specialist Finding with confidence=confirmed. Otherwise keep it below 0.9.

## Exact output schema — follow this shape

{
  "executive_summary": "Short paragraph on what the scan has learned so far, what's interesting, and where attention is going this cycle. Max 400 chars.",
  "hypotheses": [
    {
      "id": "h1",
      "statement": "Sequential integer ids in /api/orders/{id} suggest IDOR risk; the endpoint is customer-facing and profile confidence is high.",
      "confidence": 0.75,
      "supporting_evidence": ["endpoint:GET /api/orders/{id}", "thought:analyzer/thought"]
    }
  ],
  "directives": [
    {
      "action": "probe_idor",
      "url_template": "https://target.example/api/orders/{id}",
      "values": ["1", "2", "100", "9999"],
      "reason": "Test whether order data is returned for ids the requester doesn't own.",
      "grounded_in": ["endpoint:GET /api/orders/{id}", "host:target.example"],
      "hypothesis_id": "h1",
      "priority": 9
    }
  ],
  "next_cycle_minutes": 5,
  "stop_if": ["no_new_findings_for_2_cycles"]
}

Remember: no code fences, no prose outside JSON, drop invented actions, always include grounded_in on non-stop directives.`

// buildStrategistPrompt serializes the world model into a situation report
// the Strategist reads as the USER message.
func buildStrategistPrompt(wm *strategistWorldModel) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# SITUATION REPORT — scan %d\n\n", wm.ScanID)
	fmt.Fprintf(&b, "Target: %s\nStatus: %s\n", wm.Target, wm.Status)
	if wm.Duration != "" {
		fmt.Fprintf(&b, "Elapsed: %s\n", wm.Duration)
	}
	if wm.AppUnderstanding != "" {
		fmt.Fprintf(&b, "App model: %s\n", wm.AppUnderstanding)
	}
	fmt.Fprintf(&b, "Counts: %d endpoints · %d profiles (%d with issues) · %d findings (%d confirmed) · %d pending directives · %d done\n\n",
		wm.EndpointCount, wm.ProfileCount, wm.ProfilesWithIssues,
		wm.FindingCount, wm.ConfirmedFindings,
		wm.DirectivesPending, wm.DirectivesCompleted)

	// Previous summary — continuity
	if wm.PreviousSummary != "" {
		b.WriteString("## Previous cycle's summary\n\n")
		b.WriteString(wm.PreviousSummary)
		b.WriteString("\n\n")
	}

	// Active hypotheses — continuity + evidence roll-up (the feedback loop).
	// The Strategist sees what Explorer/Verifier actually did with the
	// directives it emitted for each hypothesis, so it can refine its
	// belief instead of re-emitting the same plan cycle after cycle.
	if len(wm.ActiveHypotheses) > 0 {
		b.WriteString("## Active hypotheses (from previous cycles) — with evidence collected since\n\n")
		for _, h := range wm.ActiveHypotheses {
			fmt.Fprintf(&b, "### %s [confidence %.2f]\n", h.ID, h.Confidence)
			fmt.Fprintf(&b, "Statement: %s\n", h.Statement)
			// Directive lifecycle so the Strategist knows whether tests were
			// even run (pending means Explorer hasn't got to them yet).
			if h.DirectivesDone+h.DirectivesFailed+h.DirectivesPending > 0 {
				fmt.Fprintf(&b, "Directives emitted to test this: %d done, %d failed, %d pending.\n",
					h.DirectivesDone, h.DirectivesFailed, h.DirectivesPending)
			} else {
				b.WriteString("Directives emitted to test this: none yet. You probably want to emit at least one.\n")
			}
			// Actual specialist-agent verdicts on this hypothesis.
			if len(h.EvidenceSnippets) > 0 {
				b.WriteString("Evidence collected:\n")
				for _, ev := range h.EvidenceSnippets {
					fmt.Fprintf(&b, "  - %s\n", ev)
				}
			}
			// Findings that emerged from this hypothesis's test chain.
			if len(h.LinkedFindings) > 0 {
				b.WriteString("Linked findings:\n")
				for _, lf := range h.LinkedFindings {
					fmt.Fprintf(&b, "  - %s\n", lf)
				}
			}
			b.WriteString("\n")
		}
		b.WriteString("Based on the evidence above, UPDATE the confidence of each hypothesis you keep: raise it when evidence supports the claim, lower it when results refute the claim. Retire hypotheses that are clearly resolved or unproductive by emitting a \"stop\" directive with their id. Emit new directives only when they would genuinely advance an unresolved hypothesis.\n\n")
	}

	// Hosts
	if len(wm.Hosts) > 0 {
		b.WriteString("## Hosts crawled (top 10 by endpoint count)\n\n")
		for _, h := range wm.Hosts {
			fmt.Fprintf(&b, "- %s — %d endpoints\n", h.Host, h.Endpoints)
		}
		b.WriteString("\n")
	}

	// Issue themes
	if len(wm.TopIssues) > 0 {
		b.WriteString("## Issue themes across profiles\n\n")
		for _, c := range wm.TopIssues {
			fmt.Fprintf(&b, "- **%s** — flagged on %d profile(s). Examples: %s\n",
				c.Theme, c.Count, strings.Join(c.ExampleEndpoints, ", "))
		}
		b.WriteString("\n")
	}

	// Interesting endpoints
	if len(wm.InterestingEndpoints) > 0 {
		b.WriteString("## Highest-priority endpoints\n\n")
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

	if len(wm.OwnershipCandidates) > 0 {
		b.WriteString("## Ownership / BOLA candidate resources\n\n")
		b.WriteString("These are repeated object-id resources that may represent user-owned data. Treat them as authorization hypotheses, not confirmed findings: prefer a plan that establishes owner A/B controls before declaring impact.\n\n")
		for _, c := range wm.OwnershipCandidates {
			fmt.Fprintf(&b, "- `%s %s` resource=%s", c.Method, c.Pattern, c.Resource)
			if c.Auth != "" && c.Auth != "unknown" {
				fmt.Fprintf(&b, " · auth=%s", c.Auth)
			}
			if len(c.IDs) > 0 {
				fmt.Fprintf(&b, " · observed_ids=%s", strings.Join(c.IDs, ", "))
			}
			b.WriteString("\n")
			if len(c.Examples) > 0 {
				fmt.Fprintf(&b, "  examples: %s\n", strings.Join(c.Examples, " · "))
			}
			if c.Reason != "" {
				fmt.Fprintf(&b, "  why interesting: %s\n", c.Reason)
			}
			if len(c.EvidenceRefs) > 0 {
				fmt.Fprintf(&b, "  grounding: %s\n", strings.Join(c.EvidenceRefs, ", "))
			}
		}
		b.WriteString("\n")
	}

	// Findings (confirmed first)
	if len(wm.Findings) > 0 {
		b.WriteString("## Findings\n\n")
		for _, f := range wm.Findings {
			fmt.Fprintf(&b, "- finding:%d [%s/%s, %s] %s → endpoint:%q\n",
				f.ID, f.Severity, safeStr(f.VulnType, "?"), f.Confidence, f.Title, f.Endpoint)
		}
		b.WriteString("\n")
	}

	// Recent narrations
	if len(wm.RecentThoughts) > 0 {
		b.WriteString("## Recent agent thoughts (oldest → newest)\n\n")
		for _, n := range wm.RecentThoughts {
			fmt.Fprintf(&b, "- %s [%s]: %s\n", n.Agent, n.Action, n.Message)
		}
		b.WriteString("\n")
	}

	if len(wm.RejectedDirectives) > 0 {
		b.WriteString("## Recently rejected planner attempts (do not repeat)\n\n")
		for _, r := range wm.RejectedDirectives {
			if r.URL != "" {
				fmt.Fprintf(&b, "- %s (url=%s)\n", r.Message, r.URL)
			} else {
				fmt.Fprintf(&b, "- %s\n", r.Message)
			}
		}
		b.WriteString("Choose a different executable primitive or retire the hypothesis; do not send another equivalent body/form mutation for these read-only shapes.\n\n")
	}

	b.WriteString("\n## Now emit the plan\n\nReturn ONE JSON object following the exact schema in the system prompt. No markdown, no code fences, no prose.\n")
	return b.String()
}

func safeStr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
