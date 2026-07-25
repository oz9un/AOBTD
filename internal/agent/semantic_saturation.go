package agent

import (
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/ozzyw/aobtd/internal/browser"
)

// SemanticSaturationState is scan-scoped evidence shared by the passive
// crawler and every bounded Navigator pass. It remembers unique application
// routes and redacted response/UI shapes per semantic family; it never stores
// page text, input values, query values, or credentials.
type SemanticSaturationState struct {
	mu       sync.RWMutex
	families map[string]*semanticFamilyEvidence
}

type semanticFamilyEvidence struct {
	routes  map[string]struct{}
	shapes  map[string]struct{}
	sources map[string]struct{}
}

type SemanticSaturationSnapshot struct {
	Family         string   `json:"family"`
	Routes         int      `json:"routes"`
	ResponseShapes int      `json:"response_shapes"`
	Sources        []string `json:"sources"`
}

func NewSemanticSaturationState() *SemanticSaturationState {
	return &SemanticSaturationState{families: make(map[string]*semanticFamilyEvidence)}
}

// Observe records only successful or browser-rendered evidence. HTTP errors
// and redirects must remain individually eligible because their behavior can
// be the novel evidence; status 0 is used for a rendered Navigator state.
func (s *SemanticSaturationState) Observe(rawURL, hint, responseShape, source string, statusCode int) {
	if s == nil || (statusCode != 0 && (statusCode < 200 || statusCode >= 300)) {
		return
	}
	family := semanticSaturationFamily(rawURL, hint)
	route := semanticSaturationRoute(rawURL)
	if family == "" || route == "" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.families == nil {
		s.families = make(map[string]*semanticFamilyEvidence)
	}
	evidence := s.families[family]
	if evidence == nil {
		evidence = &semanticFamilyEvidence{
			routes: make(map[string]struct{}), shapes: make(map[string]struct{}), sources: make(map[string]struct{}),
		}
		s.families[family] = evidence
	}
	evidence.routes[route] = struct{}{}
	if shape := strings.TrimSpace(responseShape); shape != "" && shape != "unknown" {
		evidence.shapes[shape] = struct{}{}
	}
	if source = strings.TrimSpace(source); source != "" {
		evidence.sources[source] = struct{}{}
	}
}

func (s *SemanticSaturationState) Snapshot(family string) SemanticSaturationSnapshot {
	result := SemanticSaturationSnapshot{Family: strings.TrimSpace(family), Sources: []string{}}
	if s == nil || result.Family == "" {
		return result
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	evidence := s.families[result.Family]
	if evidence == nil {
		return result
	}
	result.Routes = len(evidence.routes)
	result.ResponseShapes = len(evidence.shapes)
	for source := range evidence.sources {
		result.Sources = append(result.Sources, source)
	}
	sort.Strings(result.Sources)
	return result
}

func (s *SemanticSaturationState) Saturated(family string) bool {
	snapshot := s.Snapshot(family)
	return snapshot.ResponseShapes >= 2 || snapshot.Routes >= 3
}

// SuppressibleTaxonomy keeps the intentionally narrow deterministic guard
// used by Recon decision inventory. Auth, admin, API, upload, debug, and other
// security-interesting paths always survive even if a taxonomy-looking parent
// happens to be saturated.
func (s *SemanticSaturationState) SuppressibleTaxonomy(rawURL, hint string) bool {
	if s == nil || browser.IsInterestingPath(rawURL) || !navigatorTaxonomyRoute(rawURL) {
		return false
	}
	return s.Saturated(semanticSaturationFamily(rawURL, hint))
}

func semanticSaturationFamily(rawURL, hint string) string {
	// A tag value can itself be a loaded word such as "authors", "login", or
	// "admin". Route grammar is stronger than its label: all tag siblings
	// belong to the same saturation family. Catalog/category routes retain
	// their broader catalog family so existing catalog detail/list evidence
	// can saturate them together.
	if parsed, err := url.Parse(strings.TrimSpace(rawURL)); err == nil {
		path := strings.ToLower(parsed.EscapedPath())
		if strings.Contains(path, "/tag/") || strings.Contains(path, "/tags/") {
			return "taxonomy"
		}
		if strings.Contains(path, "/author/") || strings.Contains(path, "/authors/") {
			return "entity"
		}
	}
	return navigatorSurfaceFamily(rawURL, hint)
}

func semanticSaturationRoute(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() == "" {
		return ""
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if port := parsed.Port(); port != "" {
		host += ":" + port
	}
	path := parsed.EscapedPath()
	if strings.HasPrefix(parsed.Fragment, "/") {
		path = "#" + parsed.Fragment
	}
	path = strings.TrimSuffix(path, "/")
	if path == "" {
		path = "/"
	}
	queryKeys := make([]string, 0)
	for key := range parsed.Query() {
		queryKeys = append(queryKeys, key)
	}
	sort.Strings(queryKeys)
	if len(queryKeys) > 0 {
		path += "?" + strings.Join(queryKeys, ",")
	}
	return host + path
}
