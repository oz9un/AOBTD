package target

import (
	"net/url"
	"sort"
	"strings"
)

// SurfaceFamily maps a discovered URL plus its evidence-backed label/context
// to a small application-area vocabulary. It is deliberately host-agnostic:
// the same ranking rules should recognize a film review, package catalog, or
// account boundary without accumulating brand-specific exceptions.
//
// The result is a routing hint, not a semantic claim. Callers still require an
// exact observed URL and immutable scope/authority approval before navigation.
func SurfaceFamily(rawURL, hint string) string {
	// Exact route/query-key semantics are stronger than incidental chrome in
	// the page purpose. An /api-beta page may embed login and search controls,
	// but it is still primarily a developer surface; /settings/search is still
	// account/settings. Only fall back to the evidence label when the URL is
	// semantically neutral.
	for _, text := range []string{surfacePrimaryRouteText(rawURL), surfaceText(rawURL, ""), surfaceText("", hint)} {
		if text == "" {
			continue
		}
		for _, rule := range surfaceRules {
			for _, term := range rule.terms {
				if surfaceContains(text, term) {
					return rule.family
				}
			}
		}
	}
	return ""
}

func surfacePrimaryRouteText(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return ""
	}
	segments := strings.FieldsFunc(strings.ToLower(parsed.EscapedPath()), func(r rune) bool { return r == '/' })
	if len(segments) == 0 {
		return ""
	}
	index := 0
	if len(segments) > 1 && surfaceLooksLikeLocale(segments[0]) {
		index = 1
	}
	segment := strings.TrimSpace(segments[index])
	// These wrappers do not describe the application surface. Let the full
	// route decide, so /about/film-data becomes catalog rather than marketing.
	for _, generic := range []string{"about", "pages", "page", "www"} {
		if segment == generic {
			return ""
		}
	}
	return strings.Join(strings.Fields(strings.NewReplacer("-", " ", "_", " ", ".", " ").Replace(segment)), " ")
}

func surfaceLooksLikeLocale(segment string) bool {
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

// SurfaceValue is a small, deterministic information-gain prior. It favors
// business objects and human journeys over legal/marketing chrome. Novelty is
// applied separately by callers from evidence already captured in the scan.
func SurfaceValue(family string) int {
	switch strings.TrimSpace(family) {
	case "transaction":
		return 28
	case "review":
		return 26
	case "collection", "community":
		return 24
	case "catalog":
		return 22
	case "search":
		return 20
	case "developer", "administration":
		return 18
	case "content", "jobs", "status":
		return 15
	case "authentication":
		return 13
	case "account":
		return 11
	case "support":
		return 3
	case "marketing":
		return 1
	case "legal":
		return -12
	default:
		return 0
	}
}

// SurfaceFamilies returns the distinct semantic families visible in a set of
// exact URL/label pairs. Sorted output keeps prompts and tests deterministic.
func SurfaceFamilies(values [][2]string) []string {
	seen := make(map[string]struct{})
	for _, value := range values {
		if family := SurfaceFamily(value[0], value[1]); family != "" {
			seen[family] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for family := range seen {
		out = append(out, family)
	}
	sort.Strings(out)
	return out
}

type surfaceRule struct {
	family string
	terms  []string
}

// Order matters. Specific human journeys precede broad terms such as
// "account", "post", and "security" that occur in generic page chrome.
var surfaceRules = []surfaceRule{
	{family: "review", terms: []string{"review", "reviews", "rating", "ratings", "inceleme", "degerlendirme"}},
	{family: "collection", terms: []string{"watchlist", "wishlist", "favorites", "favourites", "playlist", "collection", "collections", "lists", "saved", "favori"}},
	{family: "community", terms: []string{"members", "member", "people", "community", "communities", "followers", "following", "clubs", "groups", "user profile", "profiles"}},
	{family: "transaction", terms: []string{"checkout", "basket", "cart", "orders", "order", "payment", "purchase", "subscription", "sepet", "sepetim", "siparis", "siparislerim", "odeme"}},
	{family: "catalog", terms: []string{"films", "film", "movies", "movie", "catalogue", "catalog", "products", "product", "packages", "package", "models", "model", "datasets", "dataset", "items", "item", "urun"}},
	{family: "search", terms: []string{"search", "discover", "explore", "browse", "find", "ara"}},
	{family: "developer", terms: []string{"api", "graphql", "webhook", "developer", "developers", "reference", "documentation", "docs", "sdk"}},
	{family: "administration", terms: []string{"admin", "moderation", "moderator", "staff", "console", "dashboard", "security center"}},
	{family: "authentication", terms: []string{"login", "log in", "signin", "sign in", "register", "registration", "signup", "sign up", "oauth", "sso", "giris", "kaydol"}},
	{family: "legal", terms: []string{"terms", "privacy policy", "legal", "cookies", "cookie policy", "copyright"}},
	{family: "account", terms: []string{"settings", "preferences", "account", "privacy", "notifications", "profile edit", "hesabim"}},
	{family: "jobs", terms: []string{"jobs", "job", "careers", "career", "vacancies"}},
	{family: "status", terms: []string{"status", "incidents", "incident", "uptime", "availability"}},
	{family: "support", terms: []string{"help", "support", "contact", "faq", "troubleshooting", "yardim", "iletisim"}},
	{family: "content", terms: []string{"news", "articles", "article", "stories", "story", "blog", "topics", "topic", "posts", "post", "rfc", "learn", "academy"}},
	{family: "marketing", terms: []string{"about", "features", "pricing", "company", "press", "partners"}},
}

func surfaceText(rawURL, hint string) string {
	parts := []string{strings.ToLower(strings.TrimSpace(hint))}
	if parsed, err := url.Parse(strings.TrimSpace(rawURL)); err == nil {
		parts = append(parts, strings.ToLower(parsed.EscapedPath()))
		keys := make([]string, 0, len(parsed.Query()))
		for key := range parsed.Query() {
			keys = append(keys, strings.ToLower(key))
		}
		sort.Strings(keys)
		parts = append(parts, strings.Join(keys, " "))
	} else {
		parts = append(parts, strings.ToLower(strings.TrimSpace(rawURL)))
	}
	replacer := strings.NewReplacer("/", " ", "-", " ", "_", " ", ".", " ", "+", " ")
	return strings.Join(strings.Fields(replacer.Replace(strings.Join(parts, " "))), " ")
}

func surfaceContains(text, term string) bool {
	term = strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(term))), " ")
	if term == "" {
		return false
	}
	padded := " " + text + " "
	return strings.Contains(padded, " "+term+" ")
}
