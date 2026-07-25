package extract

import (
	"net/url"
	"sort"
	"strings"
	"unicode"

	"github.com/ozzyw/aobtd/internal/observation"
)

// ClientRouteEvidence is the small persistence-independent projection needed
// to identify browser-visited hash routes.
type ClientRouteEvidence struct {
	ID  int64
	URL string
}

// ClientRoutedView is a client-side page whose hash route was actually opened
// by the controlled browser. It is route evidence, not an HTTP endpoint and
// not proof that every linked sibling route is reachable.
type ClientRoutedView struct {
	Label        string
	URL          string
	Route        string
	Observations int
	DiscoveryIDs []int64
}

// DiscoverVisitedClientRoutes canonicalizes and deduplicates direct browser
// visits to #/ and #!/ routes. Plain anchors and route queries are withheld.
func DiscoverVisitedClientRoutes(evidence []ClientRouteEvidence, maxViews int) []ClientRoutedView {
	if maxViews <= 0 {
		maxViews = 16
	}
	byRoute := make(map[string]*ClientRoutedView)
	order := make(map[string]int)
	nextOrder := 0
	for _, item := range evidence {
		parsed, err := url.Parse(strings.TrimSpace(item.URL))
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			continue
		}
		route := strings.TrimSpace(parsed.Fragment)
		route = strings.TrimPrefix(route, "!")
		if !strings.HasPrefix(route, "/") {
			continue
		}
		if cut := strings.IndexByte(route, '?'); cut >= 0 {
			route = route[:cut]
		}
		route = strings.TrimRight(route, "/")
		if route == "" {
			route = "/"
		}
		label, ok := safeClientRouteLabel(route)
		if !ok {
			continue
		}
		parsed.RawQuery = ""
		parsed.ForceQuery = false
		parsed.Fragment = route
		parsed.RawFragment = ""
		parsed.User = nil
		canonical := parsed.String()
		key := strings.ToLower(canonical)
		view := byRoute[key]
		if view == nil {
			view = &ClientRoutedView{Label: label, URL: canonical, Route: route}
			byRoute[key] = view
			order[key] = nextOrder
			nextOrder++
		}
		view.Observations++
		if item.ID > 0 && len(view.DiscoveryIDs) < 3 && !containsTrafficID(view.DiscoveryIDs, item.ID) {
			view.DiscoveryIDs = append(view.DiscoveryIDs, item.ID)
		}
	}
	keys := make([]string, 0, len(byRoute))
	for key := range byRoute {
		keys = append(keys, key)
	}
	sort.SliceStable(keys, func(i, j int) bool { return order[keys[i]] < order[keys[j]] })
	out := make([]ClientRoutedView, 0, minInt(maxViews, len(keys)))
	for _, key := range keys {
		out = append(out, *byRoute[key])
		if len(out) >= maxViews {
			break
		}
	}
	return out
}

func safeClientRouteLabel(route string) (string, bool) {
	decoded, err := url.PathUnescape(strings.TrimSpace(route))
	if err != nil || decoded == "" || len(decoded) > 120 {
		return "", false
	}
	segments := strings.FieldsFunc(decoded, func(r rune) bool { return r == '/' })
	if len(segments) == 0 {
		return "", false
	}
	clean := make([]string, 0, len(segments))
	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment == "" || segment == "." || segment == ".." || len(segment) > 48 {
			return "", false
		}
		for _, r := range segment {
			if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == '.') {
				return "", false
			}
		}
		clean = append(clean, segment)
	}
	leaf := clean[len(clean)-1]
	if clientRouteVariableSegment(leaf) && len(clean) > 1 {
		leaf = clean[len(clean)-2] + " detail"
	}
	leaf = strings.TrimSpace(strings.NewReplacer("-", " ", "_", " ", ".", " ").Replace(leaf))
	if leaf == "" || len(leaf) > 48 {
		return "", false
	}
	return strings.ToLower(strings.Join(strings.Fields(leaf), " ")), true
}

func clientRouteVariableSegment(segment string) bool {
	if segment == "" {
		return false
	}
	allDigits := true
	for _, r := range segment {
		if !unicode.IsDigit(r) {
			allDigits = false
			break
		}
	}
	return allDigits || observation.IsOpaquePathSegment(segment)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
