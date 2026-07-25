package pathlabel

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ozzyw/aobtd/internal/observation"
)

// regexFallbackLabel produces a Label without involving the LLM. Used
// when no provider is configured, when the budget is exhausted, when
// the LLM call errors, and as the input/baseline that gets handed to
// the LLM (so the LLM can confirm or override).
//
// Behaviour:
//
//   - Single observation: numeric and UUID segments become {id}; long
//     segments become {token} only when they have strong opacity evidence.
//     Human-readable route/service names remain literal.
//
//   - Multiple observations: align position-by-position. Stable
//     positions stay literal (this is the behaviour my earlier
//     buildCorpusTemplate added). Varying positions get classified
//     with the same regex rules; positions that all-numeric → {id},
//     all-UUID → {id}, otherwise → {seg} (the LLM-needs-help marker
//     used by the analyzer when the budget allows refinement).
//
// Returns the label plus a parallel slice of distinct example values
// per VARIABLE position (in display-segment order, skipping literals).
// The examples are what the LLM will see if/when refinement runs.
func regexFallbackLabel(paths []string) (Label, [][]string) {
	if len(paths) == 0 {
		return Label{Source: SourceFallback}, nil
	}
	if len(paths) == 1 {
		return regexFallbackSingle(paths[0]), nil
	}

	first := strings.Split(paths[0], "/")
	segCount := len(first)

	// Bail out and use the per-URL fallback if segment counts disagree
	// — we can't safely align positions across mixed shapes.
	all := make([][]string, 0, len(paths))
	all = append(all, first)
	for _, p := range paths[1:] {
		segs := strings.Split(p, "/")
		if len(segs) != segCount {
			return regexFallbackSingle(paths[0]), nil
		}
		all = append(all, segs)
	}

	displaySegs := make([]string, segCount)
	segments := []SegmentLabel{}
	varSamples := [][]string{}
	displayIdx := 0
	for i := 0; i < segCount; i++ {
		seen := distinctValues(all, i)
		if len(seen) == 1 {
			// Literal — same value across all observations.
			displaySegs[i] = first[i]
			// Skip the synthetic empty leading split for SegmentLabel
			// indexing (the user-facing position is 1-based after the
			// leading slash).
			if first[i] != "" {
				segments = append(segments, SegmentLabel{
					Position: displayIdx,
					Kind:     "literal",
					Label:    first[i],
				})
				displayIdx++
			}
			continue
		}
		switch {
		case allMatch(seen, isNumericID):
			displaySegs[i] = "{id}"
			segments = append(segments, SegmentLabel{
				Position: displayIdx, Kind: "variable", Label: "id",
				Examples: capExamples(seen, 5),
			})
			varSamples = append(varSamples, capExamples(seen, 5))
		case allMatch(seen, isUUID):
			displaySegs[i] = "{id}"
			segments = append(segments, SegmentLabel{
				Position: displayIdx, Kind: "variable", Label: "id",
				Examples: capExamples(seen, 5),
			})
			varSamples = append(varSamples, capExamples(seen, 5))
		default:
			displaySegs[i] = "{seg}"
			segments = append(segments, SegmentLabel{
				Position: displayIdx, Kind: "variable", Label: "seg",
				Examples: capExamples(seen, 5),
			})
			varSamples = append(varSamples, capExamples(seen, 5))
		}
		displayIdx++
	}

	return Label{
		Display:  strings.Join(displaySegs, "/"),
		Segments: segments,
		Source:   SourceFallback,
	}, varSamples
}

// regexFallbackSingle is the per-URL classifier for single-observation
// bundles. Numeric IDs, UUIDs, and strongly opaque tokens are variable;
// readable route names stay literal regardless of length.
func regexFallbackSingle(path string) Label {
	segs := strings.Split(path, "/")
	displaySegs := make([]string, len(segs))
	segments := []SegmentLabel{}
	displayIdx := 0
	for i, s := range segs {
		if s == "" {
			displaySegs[i] = ""
			continue
		}
		switch {
		case isNumericID(s):
			displaySegs[i] = "{id}"
			segments = append(segments, SegmentLabel{
				Position: displayIdx, Kind: "variable", Label: "id",
				Examples: []string{s},
			})
		case isUUID(s):
			displaySegs[i] = "{id}"
			segments = append(segments, SegmentLabel{
				Position: displayIdx, Kind: "variable", Label: "id",
				Examples: []string{s},
			})
		case observation.IsOpaquePathSegment(s):
			// Only mask segments with strong opacity evidence. Long readable
			// route/service names remain literal even without LLM refinement.
			displaySegs[i] = "{token}"
			segments = append(segments, SegmentLabel{
				Position: displayIdx, Kind: "variable", Label: "token",
				Examples: []string{s},
			})
		default:
			displaySegs[i] = s
			segments = append(segments, SegmentLabel{
				Position: displayIdx, Kind: "literal", Label: s,
			})
		}
		displayIdx++
	}
	return Label{
		Display:  strings.Join(displaySegs, "/"),
		Segments: segments,
		Source:   SourceFallback,
	}
}

// semanticRouteFamilyLabel handles route grammars whose variable positions
// are explicit in the URL itself. A model cannot improve on knowing that the
// value after /tag/ is a tag or after /author/ is an author; avoiding those
// calls also keeps large public taxonomies from consuming semantic budget.
func semanticRouteFamilyLabel(paths []string) (Label, bool) {
	if len(paths) == 0 {
		return Label{}, false
	}
	all := make([][]string, 0, len(paths))
	for _, path := range paths {
		segments := splitLabelPath(path)
		if len(segments) == 0 || (len(all) > 0 && len(segments) != len(all[0])) {
			return Label{}, false
		}
		all = append(all, segments)
	}
	first := all[0]
	variableLabels := make(map[int]string)
	categoryTail := false
	categoryDepth := 0
	for index, segment := range first {
		lower := strings.ToLower(strings.TrimSpace(segment))
		previous := ""
		previousIsVariable := false
		if index > 0 {
			previous = strings.ToLower(strings.TrimSpace(first[index-1]))
			_, previousIsVariable = variableLabels[index-1]
		}
		// A marker word can also be a value of an earlier marker, as in
		// /tag/authors/page/1/. Only literal positions are allowed to start
		// a new route grammar; variable values must never reinterpret the tail.
		if !previousIsVariable {
			switch previous {
			case "tag", "tags":
				variableLabels[index] = "tag"
			case "author", "authors":
				variableLabels[index] = "author"
			case "category", "categories":
				categoryTail = true
				categoryDepth = 0
			}
		}
		if categoryTail {
			if lower == "page" || lower == "index.html" || lower == "index.htm" {
				categoryTail = false
			} else {
				label := "category"
				if categoryDepth > 0 {
					label = "subcategory"
					if categoryDepth > 1 {
						label += "_" + strconv.Itoa(categoryDepth)
					}
				}
				variableLabels[index] = label
				categoryDepth++
			}
		}
		if !previousIsVariable && previous == "page" && isNumericID(lower) {
			variableLabels[index] = "page"
		}
	}
	if len(variableLabels) == 0 {
		return Label{}, false
	}
	for index := range first {
		if _, variable := variableLabels[index]; variable {
			continue
		}
		for _, segments := range all[1:] {
			if !strings.EqualFold(first[index], segments[index]) {
				return Label{}, false
			}
		}
	}
	return buildRuleLabel(all, variableLabels, SourceSemanticRule), true
}

func splitLabelPath(path string) []string {
	return strings.FieldsFunc(strings.TrimSpace(path), func(r rune) bool { return r == '/' })
}

func buildRuleLabel(all [][]string, variableLabels map[int]string, source LabelSource) Label {
	first := all[0]
	display := make([]string, len(first))
	segments := make([]SegmentLabel, 0, len(first))
	for index, value := range first {
		label, variable := variableLabels[index]
		if !variable {
			display[index] = value
			segments = append(segments, SegmentLabel{Position: index, Kind: "literal", Label: value})
			continue
		}
		examples := make([]string, 0, len(all))
		seen := make(map[string]bool)
		for _, values := range all {
			if !seen[values[index]] {
				seen[values[index]] = true
				examples = append(examples, values[index])
			}
		}
		sort.Strings(examples)
		display[index] = "{" + label + "}"
		segments = append(segments, SegmentLabel{
			Position: index, Kind: "variable", Label: label, Examples: capExamples(examples, 5),
			Reason: "explicit URL route grammar",
		})
	}
	return Label{Display: "/" + strings.Join(display, "/"), Segments: segments, Source: source}
}

func labelFromVocabulary(paths []string, vocabulary *Vocabulary) (Label, bool) {
	if vocabulary == nil || len(paths) == 0 {
		return Label{}, false
	}
	all := make([][]string, 0, len(paths))
	for _, path := range paths {
		segments := splitLabelPath(path)
		if len(segments) == 0 || (len(all) > 0 && len(segments) != len(all[0])) {
			return Label{}, false
		}
		all = append(all, segments)
	}
	for _, pattern := range vocabulary.PositionPatterns {
		patternSegments := splitLabelPath(pattern.Shape)
		if len(patternSegments) != len(all[0]) {
			continue
		}
		variablePositions := make([]int, 0, len(pattern.Labels))
		matched := true
		for index, patternSegment := range patternSegments {
			placeholder := strings.HasPrefix(patternSegment, "<") && strings.HasSuffix(patternSegment, ">")
			if placeholder {
				variablePositions = append(variablePositions, index)
				continue
			}
			for _, values := range all {
				if !strings.EqualFold(patternSegment, values[index]) {
					matched = false
					break
				}
			}
			if !matched {
				break
			}
		}
		if !matched || len(variablePositions) == 0 || len(pattern.Labels) != len(variablePositions) {
			continue
		}
		labels := make(map[int]string, len(variablePositions))
		for index, position := range variablePositions {
			label := strings.Trim(strings.ToLower(strings.TrimSpace(pattern.Labels[index])), "{}<> ")
			label = strings.ReplaceAll(label, "-", "_")
			if label == "" {
				matched = false
				break
			}
			labels[position] = label
		}
		if matched {
			return buildRuleLabel(all, labels, SourceLLMVocab), true
		}
	}
	return Label{}, false
}

// distinctValues returns the unique segment values at index i across
// every observation in all. Order isn't significant; the caller
// either checks set size or feeds the result into capExamples.
func distinctValues(all [][]string, i int) []string {
	seen := map[string]bool{}
	for _, segs := range all {
		seen[segs[i]] = true
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func allMatch(values []string, pred func(string) bool) bool {
	for _, v := range values {
		if !pred(v) {
			return false
		}
	}
	return true
}

func capExamples(values []string, n int) []string {
	if len(values) <= n {
		// Already sorted by distinctValues — return a copy so caller
		// mutations don't leak back into the resolver's caches.
		out := make([]string, len(values))
		copy(out, values)
		return out
	}
	out := make([]string, n)
	copy(out, values[:n])
	return out
}

func isNumericID(s string) bool {
	if s == "" || len(s) > 10 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func isUUID(s string) bool {
	return uuidRe.MatchString(s)
}
