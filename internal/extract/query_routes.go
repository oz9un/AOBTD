package extract

import (
	"crypto/sha256"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"unicode"

	"github.com/ozzyw/aobtd/pkg/types"
	"golang.org/x/net/html"
)

// QueryRoutedView is a response-backed page type selected through a safe,
// route-shaped query parameter. It intentionally never contains the raw query
// value: Label is a short, sanitized page identity and URL has no query.
type QueryRoutedView struct {
	Path         string
	Parameter    string
	Label        string
	URL          string
	Status       int
	Observations int
	Aliases      int
	ResponseKind string
	ShapeID      string
	TrafficIDs   []int64
}

var queryRouteParameters = map[string]bool{
	"content": true, "page": true, "view": true, "screen": true,
	"route": true, "section": true, "tab": true, "module": true,
}

// SafeQueryRouteLabel turns a route-shaped query value into a display-safe
// page label. Email addresses, nested query strings, tokens, and other values
// that could carry user data are rejected rather than redacted.
func SafeQueryRouteLabel(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 80 {
		return "", false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._-/", r)) {
			return "", false
		}
	}
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == '/' || r == '\\' })
	if len(parts) == 0 {
		return "", false
	}
	label := parts[len(parts)-1]
	if dot := strings.LastIndexByte(label, '.'); dot > 0 {
		label = label[:dot]
	}
	lower := strings.ToLower(label)
	for _, prefix := range []string{"inside_", "page_"} {
		if strings.HasPrefix(lower, prefix) {
			label = label[len(prefix):]
			break
		}
	}
	label = strings.TrimSpace(strings.NewReplacer("_", " ", "-", " ").Replace(label))
	if label == "" || len(label) > 48 {
		return "", false
	}
	return strings.ToLower(label), true
}

type queryRouteCandidate struct {
	QueryRoutedView
	representative types.TrafficEntry
	first          int
	descriptor     routeResponseDescriptor
}

type routeResponseDescriptor struct {
	contentType string
	title       string
	landmarks   string
	bodyDigest  string
	words       []string
	kind        string
	forms       int
	inputs      int
	tables      int
	rows        int
	listItems   int
	articles    int
}

// DiscoverQueryRoutedViews finds distinct response-backed page types hidden
// behind one endpoint path. Repeated captures and aliases that render an
// equivalent response are collapsed. A lone query value is not called a
// router: at least two materially distinct responses must be observed for the
// same path and parameter.
func DiscoverQueryRoutedViews(entries []types.TrafficEntry, maxViews int) []QueryRoutedView {
	if maxViews <= 0 {
		maxViews = 12
	}
	groups := make(map[string]map[string]*queryRouteCandidate)
	order := 0
	for _, entry := range entries {
		method := strings.ToUpper(strings.TrimSpace(entry.Request.Method))
		if method != "GET" && method != "HEAD" {
			continue
		}
		params, err := url.ParseQuery(entry.Request.Query)
		if err != nil {
			continue
		}
		for rawName, values := range params {
			name := strings.ToLower(strings.TrimSpace(rawName))
			if !queryRouteParameters[name] {
				continue
			}
			for _, value := range values {
				label, ok := SafeQueryRouteLabel(value)
				if !ok {
					continue
				}
				pathValue := strings.TrimSpace(entry.Request.Path)
				if pathValue == "" {
					pathValue = "/"
				}
				baseURL := queryRouteBaseURL(entry.Request.URL, entry.Request.Host, pathValue)
				groupKey := baseURL + "\x00" + pathValue + "\x00" + name
				byLabel := groups[groupKey]
				if byLabel == nil {
					byLabel = make(map[string]*queryRouteCandidate)
					groups[groupKey] = byLabel
				}
				candidate := byLabel[label]
				if candidate == nil {
					candidate = &queryRouteCandidate{QueryRoutedView: QueryRoutedView{
						Path: pathValue, Parameter: name, Label: label, URL: baseURL,
					}, first: order}
					order++
					byLabel[label] = candidate
				}
				candidate.Observations++
				if entry.ID > 0 && len(candidate.TrafficIDs) < 3 && !containsTrafficID(candidate.TrafficIDs, entry.ID) {
					candidate.TrafficIDs = append(candidate.TrafficIDs, entry.ID)
				}
				if betterQueryRouteSample(entry, candidate.representative) {
					candidate.representative = entry
					candidate.Status = entry.Response.StatusCode
				}
			}
		}
	}

	groupKeys := make([]string, 0, len(groups))
	for key := range groups {
		groupKeys = append(groupKeys, key)
	}
	sort.Strings(groupKeys)
	out := make([]QueryRoutedView, 0, maxViews)
	for _, groupKey := range groupKeys {
		byLabel := groups[groupKey]
		if len(byLabel) < 2 {
			continue
		}
		candidates := make([]*queryRouteCandidate, 0, len(byLabel))
		for _, candidate := range byLabel {
			candidate.descriptor = describeRouteResponse(candidate.representative)
			if candidate.descriptor.landmarks == "" {
				continue
			}
			candidates = append(candidates, candidate)
		}
		sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].first < candidates[j].first })

		unique := make([]*queryRouteCandidate, 0, len(candidates))
		for _, candidate := range candidates {
			aliasOf := -1
			for i, known := range unique {
				if equivalentRouteResponse(candidate.descriptor, known.descriptor) {
					aliasOf = i
					break
				}
			}
			if aliasOf >= 0 {
				unique[aliasOf].Observations += candidate.Observations
				unique[aliasOf].Aliases++
				unique[aliasOf].TrafficIDs = appendUniqueTrafficIDs(unique[aliasOf].TrafficIDs, candidate.TrafficIDs, 3)
				continue
			}
			unique = append(unique, candidate)
		}
		if len(unique) < 2 {
			continue
		}
		for _, candidate := range unique {
			candidate.descriptor.kind = distinctiveRouteResponseKind(candidate.descriptor, unique)
			candidate.ResponseKind = candidate.descriptor.kind
			candidate.ShapeID = shortRouteShapeID(candidate.descriptor)
			out = append(out, candidate.QueryRoutedView)
			if len(out) >= maxViews {
				return out
			}
		}
	}
	return out
}

func queryRouteBaseURL(rawURL, host, pathValue string) string {
	if parsed, err := url.Parse(strings.TrimSpace(rawURL)); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		parsed.RawQuery = ""
		parsed.ForceQuery = false
		parsed.Fragment = ""
		parsed.User = nil
		return parsed.String()
	}
	if host != "" {
		return "https://" + host + pathValue
	}
	return pathValue
}

func betterQueryRouteSample(next, current types.TrafficEntry) bool {
	if current.ID == 0 && len(current.Response.Body) == 0 {
		return true
	}
	nextGood := next.Response.StatusCode >= 200 && next.Response.StatusCode < 400
	currentGood := current.Response.StatusCode >= 200 && current.Response.StatusCode < 400
	if nextGood != currentGood {
		return nextGood
	}
	return len(next.Response.Body) > len(current.Response.Body)
}

func describeRouteResponse(entry types.TrafficEntry) routeResponseDescriptor {
	contentType := strings.ToLower(strings.TrimSpace(entry.Response.ContentType))
	if cut := strings.IndexByte(contentType, ';'); cut >= 0 {
		contentType = strings.TrimSpace(contentType[:cut])
	}
	if !strings.Contains(contentType, "html") || len(entry.Response.Body) == 0 || entry.Response.StatusCode < 200 || entry.Response.StatusCode >= 400 {
		return routeResponseDescriptor{}
	}

	counts := make(map[string]int)
	wordSet := make(map[string]bool)
	mainWords := make(map[string]bool)
	var titleParts []string
	inBody, inTitle, ignoredDepth, contentDepth := false, false, 0, 0
	z := html.NewTokenizer(strings.NewReader(string(entry.Response.Body)))
	for {
		tokenType := z.Next()
		if tokenType == html.ErrorToken {
			break
		}
		token := z.Token()
		switch tokenType {
		case html.StartTagToken:
			name := strings.ToLower(token.Data)
			if name == "body" {
				inBody = true
			}
			if name == "title" {
				inTitle = true
			}
			if ignoredDepth > 0 || ignoredRouteTextTag(name) {
				ignoredDepth++
				continue
			}
			if name == "main" || name == "article" {
				contentDepth++
			}
			if inBody && routeLandmarkTag(name) {
				counts[name]++
			}
		case html.SelfClosingTagToken:
			name := strings.ToLower(token.Data)
			if ignoredDepth == 0 && inBody && routeLandmarkTag(name) {
				counts[name]++
			}
		case html.EndTagToken:
			name := strings.ToLower(token.Data)
			if ignoredDepth > 0 {
				ignoredDepth--
				continue
			}
			if name == "main" || name == "article" {
				if contentDepth > 0 {
					contentDepth--
				}
			}
			if name == "title" {
				inTitle = false
			}
			if name == "body" {
				inBody = false
			}
		case html.TextToken:
			text := strings.TrimSpace(token.Data)
			if text == "" || ignoredDepth > 0 {
				continue
			}
			if inTitle {
				titleParts = append(titleParts, text)
			}
			if inBody {
				addRouteWords(wordSet, text)
				if contentDepth > 0 {
					addRouteWords(mainWords, text)
				}
			}
		}
	}
	if len(mainWords) >= 4 {
		wordSet = mainWords
	}
	words := make([]string, 0, len(wordSet))
	for word := range wordSet {
		words = append(words, word)
	}
	sort.Strings(words)
	if len(words) > 96 {
		words = words[:96]
	}

	tags := []string{"main", "article", "section", "h1", "h2", "h3", "form", "input", "select", "textarea", "button", "table", "tr", "ul", "ol", "li", "a", "img"}
	parts := make([]string, 0, len(tags))
	for _, tag := range tags {
		parts = append(parts, tag+":"+shapeCountBucket(counts[tag]))
	}
	landmarks := strings.Join(parts, "|")
	kind := "content view"
	switch {
	case counts["form"] > 0 || counts["input"] > 0 || counts["select"] > 0 || counts["textarea"] > 0:
		kind = "form view"
	case counts["table"] > 0:
		kind = "table view"
	case counts["li"] >= 4:
		kind = "list view"
	case counts["article"] > 0:
		kind = "article view"
	}
	canonicalBody := strings.Join(strings.Fields(string(entry.Response.Body)), " ")
	bodySum := sha256.Sum256([]byte(canonicalBody))
	return routeResponseDescriptor{
		contentType: contentType,
		title:       normalizeRouteText(strings.Join(titleParts, " ")),
		landmarks:   landmarks,
		bodyDigest:  fmt.Sprintf("%x", bodySum[:12]),
		words:       words,
		kind:        kind,
		forms:       counts["form"],
		inputs:      counts["input"] + counts["select"] + counts["textarea"],
		tables:      counts["table"],
		rows:        counts["tr"],
		listItems:   counts["li"],
		articles:    counts["article"],
	}
}

// distinctiveRouteResponseKind removes structure shared by every sibling
// response (site chrome, global login/search forms, table-based legacy layout)
// before naming the page type. This prevents a common shell from making every
// routed view look interactive.
func distinctiveRouteResponseKind(current routeResponseDescriptor, group []*queryRouteCandidate) string {
	minForms, minInputs := current.forms, current.inputs
	minTables, minRows := current.tables, current.rows
	minListItems, minArticles := current.listItems, current.articles
	for _, candidate := range group {
		d := candidate.descriptor
		if d.forms < minForms {
			minForms = d.forms
		}
		if d.inputs < minInputs {
			minInputs = d.inputs
		}
		if d.tables < minTables {
			minTables = d.tables
		}
		if d.rows < minRows {
			minRows = d.rows
		}
		if d.listItems < minListItems {
			minListItems = d.listItems
		}
		if d.articles < minArticles {
			minArticles = d.articles
		}
	}
	switch {
	case current.forms > minForms || current.inputs > minInputs:
		return "form view"
	case current.tables > minTables || current.rows >= minRows+2:
		return "table view"
	case current.listItems >= minListItems+3:
		return "list view"
	case current.articles > minArticles:
		return "article view"
	default:
		return "content view"
	}
}

func ignoredRouteTextTag(name string) bool {
	switch name {
	case "script", "style", "noscript", "svg", "nav", "header", "footer", "aside":
		return true
	default:
		return false
	}
}

func routeLandmarkTag(name string) bool {
	switch name {
	case "main", "article", "section", "h1", "h2", "h3", "form", "input", "select", "textarea", "button", "table", "tr", "ul", "ol", "li", "a", "img":
		return true
	default:
		return false
	}
}

var routeStopWords = map[string]bool{
	"and": true, "are": true, "but": true, "for": true, "from": true, "has": true, "have": true,
	"into": true, "not": true, "our": true, "that": true, "the": true, "their": true, "this": true,
	"was": true, "were": true, "will": true, "with": true, "you": true, "your": true,
}

func addRouteWords(dst map[string]bool, text string) {
	for _, word := range strings.FieldsFunc(strings.ToLower(text), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		if len(word) < 3 || len(word) > 28 || routeStopWords[word] || allRouteDigits(word) {
			continue
		}
		dst[word] = true
	}
}

func allRouteDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func normalizeRouteText(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(value), " "))
}

func equivalentRouteResponse(a, b routeResponseDescriptor) bool {
	if a.contentType == "" || b.contentType == "" || a.contentType != b.contentType {
		return false
	}
	if a.bodyDigest != "" && a.bodyDigest == b.bodyDigest {
		return true
	}
	if a.landmarks != b.landmarks || a.title != b.title {
		return false
	}
	return routeWordSimilarity(a.words, b.words) >= .84
}

func routeWordSimilarity(a, b []string) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1
	}
	left := make(map[string]bool, len(a))
	for _, word := range a {
		left[word] = true
	}
	intersection := 0
	for _, word := range b {
		if left[word] {
			intersection++
		}
	}
	union := len(left) + len(b) - intersection
	if union <= 0 {
		return 0
	}
	return float64(intersection) / float64(union)
}

func shortRouteShapeID(descriptor routeResponseDescriptor) string {
	sum := sha256.Sum256([]byte(descriptor.kind + "\x00" + descriptor.landmarks + "\x00" + descriptor.title + "\x00" + strings.Join(descriptor.words, ",")))
	return fmt.Sprintf("%x", sum[:4])
}

func containsTrafficID(ids []int64, want int64) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

func appendUniqueTrafficIDs(dst, src []int64, limit int) []int64 {
	for _, id := range src {
		if id <= 0 || containsTrafficID(dst, id) {
			continue
		}
		dst = append(dst, id)
		if len(dst) >= limit {
			break
		}
	}
	return dst
}
