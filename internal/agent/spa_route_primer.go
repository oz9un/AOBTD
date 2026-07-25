package agent

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/ozzyw/aobtd/internal/browser"
	"github.com/ozzyw/aobtd/internal/policy"
	"github.com/ozzyw/aobtd/internal/store"
)

const maxJSUIRoutePrimerVisits = 12

func (o *Orchestrator) runJSRoutePrimer(ctx context.Context) {
	if o.browser == nil || o.executionPolicy == nil {
		return
	}
	endProvenance := o.browser.BeginTrafficProvenance("spa_route_primer", 0, "")
	defer endProvenance()
	candidates, err := o.jsUIRoutePrimerCandidates(maxJSUIRoutePrimerVisits)
	if err != nil {
		o.logger.Warn("SPA route primer candidate query failed", "error", err)
		return
	}
	if len(candidates) == 0 {
		o.logger.Info("SPA route primer found no safe UI route candidates")
		return
	}

	o.logger.Info("=== Phase: SPA Route Primer ===", "candidates", len(candidates))
	o.db.InsertNarration(o.scanID, "orchestrator", "spa_route_primer",
		fmt.Sprintf("JavaScript exposed %d client-side route(s); opening the safe ones in-browser so SPA-only surfaces can make their real API calls.", len(candidates)),
		o.target, map[string]any{"count": len(candidates)})

	nav := browser.NewNavigator(o.browser, o.logger)
	visited := 0
	for _, candidate := range candidates {
		if ctx.Err() != nil {
			return
		}
		decision := o.executionPolicy.Authorize(policy.Action{
			TargetURL: candidate,
			Method:    "GET",
		})
		if !decision.Allowed {
			o.auditPolicyDenial(decision)
			continue
		}
		page, err := o.browser.Navigate(ctx, candidate)
		if err != nil {
			o.logger.Debug("SPA route primer navigation failed", "url", candidate, "error", err)
			continue
		}
		time.Sleep(700 * time.Millisecond)
		state, captureErr := nav.CapturePageState(page)
		_ = page.Close()
		visited++
		o.db.LogAI(o.scanID, "spa_route_primer", "visit",
			"Visited JS-discovered client-side route in the browser", "", candidate, "")
		_ = o.db.InsertDiscovery(o.scanID, store.Discovery{
			TargetURL: candidate,
			SourceURL: "js_discovered_routes",
			Kind:      store.DiscoveryNavigator,
			Detail:    "browser visit from JS-discovered SPA route",
		})
		if captureErr == nil && state != nil {
			o.bus.Publish(Event{
				Type:   EventPageCrawled,
				Source: "spa_route_primer",
				Payload: PageCrawledPayload{
					URL:   state.URL,
					Links: extractLinkURLs(state.Links),
					Forms: len(state.Forms),
				},
			})
		}
	}
	if visited > 0 {
		o.db.InsertNarration(o.scanID, "spa_route_primer", "complete",
			fmt.Sprintf("Opened %d JS-discovered SPA route(s) in-browser and let the app reveal any route-specific traffic.", visited),
			o.target, map[string]any{"visited": visited})
	}
}

func (o *Orchestrator) jsUIRoutePrimerCandidates(limit int) ([]string, error) {
	if limit <= 0 {
		limit = maxJSUIRoutePrimerVisits
	}
	hashMode := o.observedHashRouting()
	rows, err := o.db.Conn().Query(`
		SELECT DISTINCT target_url
		FROM url_discoveries
		WHERE scan_id = ? AND kind = ? AND detail LIKE '%kind=ui%'
		ORDER BY id ASC
		LIMIT 50`, o.scanID, store.DiscoveryJSRoute)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	seen := make(map[string]struct{})
	type routeCandidate struct {
		url   string
		score int
		order int
	}
	var candidates []routeCandidate
	order := 0
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		candidate := normalizeJSUIRouteForBrowser(raw, o.target, hashMode)
		if candidate == "" || unsafeSPAUIRoute(candidate) {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		candidates = append(candidates, routeCandidate{
			url:   candidate,
			score: spaRoutePrimerPriority(candidate),
			order: order,
		})
		order++
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		return candidates[i].order < candidates[j].order
	})

	var out []string
	for _, candidate := range candidates {
		out = append(out, candidate.url)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (o *Orchestrator) observedHashRouting() bool {
	return observedHashRoutingForScan(o.db, o.scanID)
}

func observedHashRoutingForScan(db *store.DB, scanID int64) bool {
	var count int
	err := db.Conn().QueryRow(`
		SELECT COUNT(*)
		FROM url_discoveries
		WHERE scan_id = ? AND (target_url LIKE '%#/%' OR source_url LIKE '%#/%')`,
		scanID).Scan(&count)
	return err == nil && count > 0
}

func normalizeJSUIRouteForBrowser(raw, target string, hashMode bool) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	targetURL, err := url.Parse(target)
	if err != nil || targetURL.Scheme == "" || targetURL.Host == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if parsed.IsAbs() && !strings.EqualFold(parsed.Host, targetURL.Host) {
		return ""
	}
	if parsed.Fragment != "" {
		if strings.HasPrefix(parsed.Fragment, "/") && !routeHasUnboundParameter(parsed.Fragment) {
			parsed.Scheme = targetURL.Scheme
			parsed.Host = targetURL.Host
			return parsed.String()
		}
		return ""
	}
	if !parsed.IsAbs() {
		base := *targetURL
		base.Path = "/"
		base.RawPath = ""
		base.RawQuery = ""
		base.Fragment = ""
		parsed = base.ResolveReference(parsed)
	}
	if routeHasUnboundParameter(parsed.Path) {
		return ""
	}
	if hashMode {
		u := *targetURL
		u.Path = "/"
		u.RawPath = ""
		u.RawQuery = ""
		u.Fragment = parsed.EscapedPath()
		if u.Fragment == "" {
			u.Fragment = parsed.Path
		}
		return u.String()
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func routeHasUnboundParameter(path string) bool {
	for _, segment := range strings.Split(path, "/") {
		if strings.HasPrefix(segment, ":") || strings.Contains(segment, "{") || strings.Contains(segment, "}") || segment == "*" || segment == "**" {
			return true
		}
	}
	return false
}

func unsafeSPAUIRoute(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return true
	}
	text := strings.ToLower(u.Path + "/" + u.Fragment)
	for _, marker := range []string{
		"logout", "signout", "delete", "remove", "checkout", "purchase",
		"order/confirm", "reset-password", "change-password",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func spaRoutePrimerPriority(raw string) int {
	u, err := url.Parse(raw)
	if err != nil {
		return 0
	}
	text := strings.ToLower(u.Path + "/" + u.Fragment)
	score := 0
	groups := []struct {
		points int
		terms  []string
	}{
		{120, []string{"admin", "administration", "manage", "moderator", "console", "dashboard", "score", "board"}},
		{100, []string{"account", "profile", "user", "login", "register", "password", "2fa", "security", "privacy", "policy", "export", "session"}},
		{90, []string{"wallet", "payment", "card", "billing", "invoice", "basket", "cart", "order", "address", "delivery"}},
		{80, []string{"contact", "feedback", "complain", "complaint", "review", "upload", "file", "support", "chat", "conversation"}},
		{70, []string{"search", "track", "report", "history", "audit", "log"}},
		{40, []string{"api-doc", "swagger", "graphql", "docs"}},
	}
	for _, group := range groups {
		for _, term := range group.terms {
			if strings.Contains(text, term) {
				score += group.points
				break
			}
		}
	}
	if strings.Contains(text, ":") || strings.Contains(text, "{") || strings.Contains(text, "}") {
		score -= 50
	}
	if score == 0 {
		score = 10
	}
	return score
}
