package pathlabel

import (
	"encoding/json"
	"fmt"
	"strings"
)

// buildLabelPrompt assembles the per-call user prompt. Format:
//
//   1. Brief framing line.
//   2. Site vocabulary, if learned for this host (terse — full
//      structure is in the Vocabulary, but the prompt only carries
//      the high-signal bits).
//   3. The fallback skeleton + per-position samples.
//   4. Side-channel context (page titles, content-type, discovery,
//      sibling paths) when available.
//   5. The schema reminder. We don't repeat the full system prompt
//      schema here, just the fields we expect populated.
//
// The aim is a 100-300 token user prompt that's enough to label well
// without bloating cost. Vocabulary is what makes follow-up calls
// cheap — once the host's pattern set is learned, individual prompts
// just confirm-or-adjust.
func buildLabelPrompt(fallback Label, varSamples [][]string, lc LabelContext, vocab *Vocabulary) string {
	var b strings.Builder
	b.WriteString("Label this URL pattern.\n\n")

	if lc.Host != "" {
		fmt.Fprintf(&b, "Host: %s\n", lc.Host)
	}
	if lc.Method != "" {
		fmt.Fprintf(&b, "Method: %s\n", lc.Method)
	}
	if lc.ContentType != "" {
		fmt.Fprintf(&b, "Response Content-Type: %s\n", lc.ContentType)
	}
	if lc.Discovery != "" {
		fmt.Fprintf(&b, "Discovered via: %s\n", lc.Discovery)
	}

	if vocab != nil {
		b.WriteString("\nLearned site vocabulary (apply for consistency):\n")
		if vocab.SiteType != "" {
			fmt.Fprintf(&b, "  Site type: %s\n", vocab.SiteType)
		}
		if len(vocab.StableBFFPrefixes) > 0 {
			fmt.Fprintf(&b, "  Stable service-name segments: %s\n",
				strings.Join(vocab.StableBFFPrefixes, ", "))
		}
		if len(vocab.PositionPatterns) > 0 {
			b.WriteString("  Known position patterns:\n")
			for _, pp := range vocab.PositionPatterns {
				fmt.Fprintf(&b, "    %s -> %s\n", pp.Shape, strings.Join(pp.Labels, "/"))
			}
		}
		if len(vocab.VariableTypes) > 0 {
			// Stable order so prompt cache hits don't shift.
			keys := sortedKeys(vocab.VariableTypes)
			b.WriteString("  Variable type hints:\n")
			for _, k := range keys {
				fmt.Fprintf(&b, "    %s: %s\n", k, vocab.VariableTypes[k])
			}
		}
	}

	// The skeleton + per-position samples. We use the fallback's display
	// as the skeleton because it's already cleaned (numeric → {id},
	// UUID → {id}, ambiguous → {seg}). The LLM can choose to
	// reclassify any of these.
	b.WriteString("\nSkeleton (preliminary, please refine): " + fallback.Display + "\n")
	if len(varSamples) > 0 {
		b.WriteString("Variable positions (left-to-right) — distinct values observed:\n")
		// Walk fallback.Segments in order, pulling the corresponding
		// sample list for each variable. This keeps "position" in
		// the prompt aligned with the response's "position" field.
		varIdx := 0
		for _, s := range fallback.Segments {
			if s.Kind != "variable" {
				continue
			}
			if varIdx < len(varSamples) {
				examples := varSamples[varIdx]
				fmt.Fprintf(&b, "  position %d (current: {%s}): %s\n",
					s.Position, s.Label, formatExamples(examples))
				varIdx++
			}
		}
	}

	if len(lc.PageTitles) > 0 {
		b.WriteString("\nPage titles seen at sample URLs:\n")
		for _, t := range capStrings(lc.PageTitles, 5) {
			fmt.Fprintf(&b, "  - %s\n", t)
		}
	}
	if len(lc.Sibling) > 0 {
		b.WriteString("\nSibling paths on the same host (for naming consistency):\n")
		for _, s := range capStrings(lc.Sibling, 5) {
			fmt.Fprintf(&b, "  - %s\n", s)
		}
	}

	b.WriteString(`
Reply with a JSON object: {"display": "...", "purpose": "...", "segments": [...]}.
- For each segment, "kind" is "literal" or "variable".
- For variables, "label" is a snake_case name without braces (e.g. "boutique_id", "lang"); the resolver will wrap it.
- For literals, "label" is the literal segment value (used to render the path).
- "purpose" is one short sentence describing what this endpoint is for; omit if unclear.`)

	return b.String()
}

// formatExamples joins up to 5 sample values with commas, quoting
// values that contain whitespace or commas. Keeps the prompt readable
// without adding fragility.
func formatExamples(values []string) string {
	if len(values) == 0 {
		return "(no samples)"
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if strings.ContainsAny(v, ", \t") {
			vBytes, _ := json.Marshal(v)
			out = append(out, string(vBytes))
		} else {
			out = append(out, v)
		}
	}
	return strings.Join(out, ", ")
}

func capStrings(values []string, n int) []string {
	if len(values) <= n {
		return values
	}
	return values[:n]
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Manual sort to avoid pulling in sort just here; n is small.
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	return keys
}
