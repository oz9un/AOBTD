package extract

import (
	"net/url"
	"sort"
	"strings"

	"github.com/ozzyw/aobtd/internal/target"
)

const (
	semanticSketchMinimumScore  = 7
	semanticSketchMinimumMargin = 3
)

// ResponseSemanticSketch is a bounded deterministic routing hint derived from
// already-captured response structure. It is not a page-purpose claim and is
// used only to avoid comparing obviously incompatible templates.
type ResponseSemanticSketch struct {
	Family     string   `json:"family,omitempty"`
	Facet      string   `json:"facet,omitempty"`
	Confidence int      `json:"confidence"`
	Score      int      `json:"score"`
	Signals    []string `json:"signals,omitempty"`
}

// SemanticSketch combines URL semantics with bounded title, meta-description,
// heading, and documentation-structure signals. Global navigation link labels
// are deliberately excluded: shared chrome must not classify every page.
func (b *EndpointBundle) SemanticSketch() ResponseSemanticSketch {
	if b == nil {
		return ResponseSemanticSketch{}
	}
	scores := make(map[string]int)
	facetScores := make(map[string]map[string]int)
	signals := make(map[string][]string)
	add := func(family string, points int, signal string) {
		family = strings.TrimSpace(family)
		if family == "" || points <= 0 {
			return
		}
		scores[family] += points
		if len(signals[family]) < 6 {
			signals[family] = appendUniqueString(signals[family], signal)
		}
	}
	addFacet := func(family, facet string, points int) {
		if family == "" || facet == "" || points <= 0 {
			return
		}
		if facetScores[family] == nil {
			facetScores[family] = make(map[string]int)
		}
		facetScores[family][facet] += points
	}

	pageURL := firstNonEmptyString(b.URLPattern, b.SampleURL)
	routeFamily := target.SurfaceFamily(pageURL, "")
	if routeFamily == "" {
		routeFamily = semanticSketchRouteFamily(pageURL)
	}
	if routeFamily != "" {
		family := routeFamily
		add(family, 9, "route")
		addFacet(family, semanticSketchFacet(pageURL, family), 9)
	}

	documentationLexical := false
	seenText := make(map[string]bool)
	classifyText := func(source, value string, points int) {
		value = strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
		key := strings.ToLower(value)
		if value == "" || seenText[key] {
			return
		}
		seenText[key] = true
		targetFamily := target.SurfaceFamily("", value)
		phraseFamily := semanticSketchPhraseFamily(value)
		if targetFamily != "" {
			add(targetFamily, points, source)
			addFacet(targetFamily, semanticSketchFacet(value, targetFamily), points)
			if targetFamily == "developer" {
				documentationLexical = true
			}
		}
		if phraseFamily != "" && phraseFamily != targetFamily {
			add(phraseFamily, points, source+":phrase")
			addFacet(phraseFamily, semanticSketchFacet(value, phraseFamily), points)
			if phraseFamily == "developer" {
				documentationLexical = true
			}
		}
	}

	if html := b.HTMLExtraction; html != nil {
		classifyText("title", html.Title, 7)
		for _, meta := range html.MetaTags {
			if strings.EqualFold(strings.TrimSpace(meta.Name), "description") {
				classifyText("meta-description", boundedSemanticText(meta.Content, 220), 5)
				break
			}
		}
		for index, heading := range html.Headings {
			if index >= 6 {
				break
			}
			points := 3
			if index == 0 {
				points = 7
			}
			classifyText("heading", heading, points)
		}

		// Structure strengthens an existing documentation signal, but can never
		// classify a page by itself. This keeps code snippets and fragment-heavy
		// marketing pages from becoming developer documentation.
		if documentationLexical {
			if html.PreformattedBlocks > 0 {
				add("developer", 2, "preformatted examples")
			}
			if fragments := samePageFragmentLinkCount(b.SampleURL, html.Links); fragments >= 4 {
				add("developer", 3, "same-page reference index")
			}
		}
	}

	if len(scores) == 0 {
		return ResponseSemanticSketch{}
	}
	type rankedFamily struct {
		family string
		score  int
	}
	ranked := make([]rankedFamily, 0, len(scores))
	for family, score := range scores {
		ranked = append(ranked, rankedFamily{family: family, score: score})
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].score != ranked[j].score {
			return ranked[i].score > ranked[j].score
		}
		return ranked[i].family < ranked[j].family
	})
	top := ranked[0]
	second := 0
	if len(ranked) > 1 {
		second = ranked[1].score
	}
	if top.score < semanticSketchMinimumScore || top.score-second < semanticSketchMinimumMargin {
		return ResponseSemanticSketch{}
	}
	confidence := 45 + top.score*5
	if confidence > 95 {
		confidence = 95
	}
	return ResponseSemanticSketch{
		Family: top.family, Facet: topSemanticSketchFacet(facetScores[top.family]), Confidence: confidence, Score: top.score,
		Signals: append([]string(nil), signals[top.family]...),
	}
}

// These narrow primary-route families cover common technical-site surfaces
// that the broader journey vocabulary intentionally does not label. Matching
// only the first meaningful segment keeps /account/security an account route
// and prevents incidental nested words from becoming page-purpose claims.
func semanticSketchRouteFamily(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	segments := strings.FieldsFunc(strings.ToLower(parsed.EscapedPath()), func(r rune) bool { return r == '/' })
	if len(segments) == 0 {
		return ""
	}
	index := 0
	if len(segments) > 1 && semanticSketchLooksLikeLocale(segments[0]) {
		index = 1
	}
	segment, decodeErr := url.PathUnescape(segments[index])
	if decodeErr != nil {
		segment = segments[index]
	}
	if dot := strings.IndexByte(segment, '.'); dot >= 0 {
		segment = segment[:dot]
	}
	switch strings.TrimSpace(segment) {
	case "security":
		return "security"
	case "download", "downloads":
		return "distribution"
	default:
		return ""
	}
}

func semanticSketchLooksLikeLocale(segment string) bool {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(segment)), "-")
	if len(parts) < 1 || len(parts) > 2 {
		return false
	}
	for _, part := range parts {
		if len(part) != 2 {
			return false
		}
		for _, r := range part {
			if r < 'a' || r > 'z' {
				return false
			}
		}
	}
	return true
}

// Facets are intentionally sparse. Broad families such as developer remain
// compatible because a documentation index can safely be the verification
// candidate for an extension reference. FAQ and paid/professional support are
// kept distinct because they repeatedly share the same site-wide search form
// while representing different page templates.
func semanticSketchFacet(value, family string) string {
	if family != "support" {
		return ""
	}
	normalized := " " + strings.Join(strings.Fields(strings.NewReplacer(
		"/", " ", "-", " ", "_", " ", ".", " ", ":", " ",
	).Replace(strings.ToLower(value))), " ") + " "
	switch {
	case strings.Contains(normalized, " faq ") || strings.Contains(normalized, " frequently asked questions "):
		return "faq"
	case strings.Contains(normalized, " professional support ") || strings.Contains(normalized, " pro support ") || strings.Contains(normalized, " technical support ") || strings.Contains(normalized, " support services "):
		return "service"
	default:
		return ""
	}
}

func topSemanticSketchFacet(scores map[string]int) string {
	best, bestScore := "", 0
	for facet, score := range scores {
		if score > bestScore || (score == bestScore && facet < best) {
			best, bestScore = facet, score
		}
	}
	return best
}

func semanticSketchPhraseFamily(value string) string {
	normalized := strings.NewReplacer(
		"/", " ", "-", " ", "_", " ", ".", " ", ":", " ", ";", " ",
		"(", " ", ")", " ", "[", " ", "]", " ", ",", " ",
	).Replace(strings.ToLower(value))
	text := " " + strings.Join(strings.Fields(normalized), " ") + " "
	phrases := []struct {
		family string
		terms  []string
	}{
		{family: "developer", terms: []string{
			"api reference", "c api", "c interface", "c-language interface", "programming interface",
			"language reference", "function reference", "method reference", "command reference",
			"interface specification", "query language", "virtual table", "database engine",
			"library interface", "configuration options", "extension", "extensions", "module", "syntax",
		}},
		{family: "content", terms: []string{"release notes", "release announcement", "changelog"}},
		{family: "support", terms: []string{"frequently asked questions", "professional support", "technical support"}},
	}
	for _, group := range phrases {
		for _, term := range group.terms {
			if strings.Contains(text, " "+term+" ") {
				return group.family
			}
		}
	}
	return ""
}

func samePageFragmentLinkCount(pageURL string, links []ExtractedLink) int {
	base, err := url.Parse(strings.TrimSpace(pageURL))
	if err != nil || base.Host == "" {
		return 0
	}
	seen := make(map[string]bool)
	for _, link := range links {
		if !link.SameOrigin {
			continue
		}
		parsed, parseErr := url.Parse(strings.TrimSpace(link.Href))
		if parseErr != nil || parsed.Fragment == "" || !strings.EqualFold(parsed.Host, base.Host) || parsed.Path != base.Path {
			continue
		}
		seen[parsed.Fragment] = true
		if len(seen) >= 32 {
			return 32
		}
	}
	return len(seen)
}

func appendUniqueString(values []string, candidate string) []string {
	for _, value := range values {
		if value == candidate {
			return values
		}
	}
	return append(values, candidate)
}
