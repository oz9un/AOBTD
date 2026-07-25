package ui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	scanproxy "github.com/ozzyw/aobtd/internal/proxy"
	targetresolver "github.com/ozzyw/aobtd/internal/target"
)

// fastGraphRoute is the metadata-only union used by the navigation badge and
// Recon's origin strip. It mirrors the logical-route identity of the full
// Graph without reading response bodies, model prose, graph edge details, or
// constructing the semantic node/edge payload.
type fastGraphRoute struct {
	URL           string
	Host          string
	Path          string
	InScope       bool
	Methods       []string
	KindTags      []string
	Observed      bool
	Analyzed      bool
	FindingCount  int
	WorstSeverity string
	endpointSet   map[string]bool
	profileSet    map[string]bool
}

func (s *Server) collectFastGraphRoutes(scanID int64, scanTarget string, graphScope graphProjectionScope) (map[string]*fastGraphRoute, error) {
	routes := make(map[string]*fastGraphRoute)
	touch := func(raw string) (*fastGraphRoute, bool) {
		canonical, ok := canonicalGraphURL(raw)
		if !ok {
			return nil, false
		}
		identity := discoveryGraphRouteIdentity(canonical)
		if existing := routes[identity]; existing != nil {
			return existing, true
		}
		parsed, err := url.Parse(identity)
		if err != nil {
			return nil, false
		}
		_, inScope, _ := graphScope.MatchURL(canonical)
		route := &fastGraphRoute{
			URL: identity, Host: parsed.Host, Path: parsed.Path, InScope: inScope,
			endpointSet: make(map[string]bool), profileSet: make(map[string]bool),
		}
		routes[identity] = route
		return route, true
	}
	addMethod := func(route *fastGraphRoute, method string) {
		if route == nil {
			return
		}
		method = strings.ToUpper(strings.TrimSpace(method))
		if method != "" {
			route.Methods = appendUnique(route.Methods, method)
		}
	}
	addTag := func(route *fastGraphRoute, tag string) {
		if route != nil && tag != "" {
			route.KindTags = appendUnique(route.KindTags, tag)
		}
	}

	// Keep the same 100K discovery ceiling as the full Graph's default path,
	// but fetch only the three identity columns needed by this projection.
	discoveryRows, err := s.db.Conn().Query(`
		SELECT target_url, COALESCE(source_url, ''), kind
		  FROM url_discoveries
		 WHERE scan_id = ?
		 ORDER BY id DESC
		 LIMIT 100000`, scanID)
	if err != nil {
		return nil, err
	}
	for discoveryRows.Next() {
		var targetURL, sourceURL, kind string
		if err := discoveryRows.Scan(&targetURL, &sourceURL, &kind); err != nil {
			discoveryRows.Close()
			return nil, err
		}
		if route, ok := touch(targetURL); ok {
			addTag(route, kind)
		}
		_, _ = touch(sourceURL)
	}
	if err := discoveryRows.Close(); err != nil {
		return nil, err
	}

	trafficRows, err := s.db.Conn().Query(`
		SELECT endpoint_hash, UPPER(method), url, COUNT(*),
		       MAX(is_ai_analyzed), MAX(is_api),
		       MAX(CASE WHEN lower(request_headers) LIKE '%referer%' THEN request_headers ELSE '' END)
		  FROM traffic
		 WHERE scan_id = ? AND is_filtered = FALSE
		 GROUP BY endpoint_hash, UPPER(method), url`, scanID)
	if err != nil {
		return nil, err
	}
	for trafficRows.Next() {
		var hash, method, rawURL, headersJSON string
		var hits int
		var analyzed, isAPI bool
		if err := trafficRows.Scan(&hash, &method, &rawURL, &hits, &analyzed, &isAPI, &headersJSON); err != nil {
			trafficRows.Close()
			return nil, err
		}
		if route, ok := touch(rawURL); ok {
			route.Observed = true
			route.Analyzed = route.Analyzed || analyzed
			addMethod(route, method)
			addTag(route, "traffic")
			if hash != "" {
				route.endpointSet[hash+"\x00"+strings.ToUpper(strings.TrimSpace(method))] = true
			}
			if isAPI {
				addTag(route, "api-call")
			}
			if discoveryGraphAuthPath(route.Path) {
				addTag(route, "auth-call")
			}
		}
		if referer := discoveryGraphReferer(headersJSON); referer != "" {
			_, _ = touch(referer)
		}
	}
	if err := trafficRows.Close(); err != nil {
		return nil, err
	}

	endpointRows, err := s.db.Conn().Query(`
		SELECT id, method, url_pattern, hit_count, is_ai_analyzed
		  FROM endpoints WHERE scan_id = ?`, scanID)
	if err != nil {
		return nil, err
	}
	for endpointRows.Next() {
		var hash, method, rawURL string
		var hits int
		var analyzed bool
		if err := endpointRows.Scan(&hash, &method, &rawURL, &hits, &analyzed); err != nil {
			endpointRows.Close()
			return nil, err
		}
		if route, ok := touch(rawURL); ok {
			route.Observed = route.Observed || hits > 0 || analyzed
			route.Analyzed = route.Analyzed || analyzed
			addMethod(route, method)
			addTag(route, "endpoint")
			if hash != "" {
				route.endpointSet[hash+"\x00"+strings.ToUpper(strings.TrimSpace(method))] = true
			}
		}
	}
	if err := endpointRows.Close(); err != nil {
		return nil, err
	}

	profileRows, err := s.db.Conn().Query(`
		SELECT id, url, method FROM page_profiles WHERE scan_id = ?`, scanID)
	if err != nil {
		return nil, err
	}
	for profileRows.Next() {
		var id, rawURL, method string
		if err := profileRows.Scan(&id, &rawURL, &method); err != nil {
			profileRows.Close()
			return nil, err
		}
		if route, ok := touch(rawURL); ok {
			route.Observed = true
			route.Analyzed = true
			addMethod(route, method)
			addTag(route, "profile")
			if id != "" {
				route.profileSet[id] = true
			}
		}
	}
	if err := profileRows.Close(); err != nil {
		return nil, err
	}

	severityRank := map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
	findingRows, err := s.db.Conn().Query(`
		SELECT endpoint_id, severity, COALESCE(poc_request, '')
		  FROM findings
		 WHERE scan_id = ? AND confidence = 'confirmed'`, scanID)
	if err != nil {
		return nil, err
	}
	for findingRows.Next() {
		var endpointID, severity, pocRequest string
		if err := findingRows.Scan(&endpointID, &severity, &pocRequest); err != nil {
			findingRows.Close()
			return nil, err
		}
		ctx := graphFindingTargetContext(scanTarget, endpointID, pocRequest)
		method := strings.ToUpper(strings.TrimSpace(ctx.Method))
		matches := make([]*fastGraphRoute, 0, 1)
		for _, route := range routes {
			if ctx.Path != "" && route.Path == ctx.Path && fastGraphRouteHasMethod(route, method) {
				matches = append(matches, route)
			}
		}
		if len(matches) > 1 && ctx.EndpointURL != "" {
			if canonical, ok := canonicalGraphURL(ctx.EndpointURL); ok {
				if exact := routes[discoveryGraphRouteIdentity(canonical)]; exact != nil {
					matches = []*fastGraphRoute{exact}
				}
			}
		}
		if len(matches) == 0 && ctx.EndpointURL != "" {
			if route, ok := touch(ctx.EndpointURL); ok {
				matches = []*fastGraphRoute{route}
			}
		}
		for _, route := range matches {
			route.Observed = true
			route.FindingCount++
			addMethod(route, method)
			addTag(route, "finding")
			if severityRank[strings.ToLower(severity)] > severityRank[strings.ToLower(route.WorstSeverity)] {
				route.WorstSeverity = strings.ToLower(severity)
			}
		}
	}
	if err := findingRows.Close(); err != nil {
		return nil, err
	}

	for _, route := range routes {
		sort.Strings(route.Methods)
		sort.Strings(route.KindTags)
	}
	return routes, nil
}

func fastGraphRouteHasMethod(route *fastGraphRoute, method string) bool {
	if route == nil || method == "" || len(route.Methods) == 0 {
		return true
	}
	for _, candidate := range route.Methods {
		if candidate == method {
			return true
		}
	}
	return false
}

func (s *Server) fastGraphLogicalRouteCount(scanID int64, scanTarget string, graphScope graphProjectionScope) (int, error) {
	// The polling path pays only indexed aggregate checks while the route set is
	// stable. Every source that can add/remove a Graph box participates in the
	// revision; traffic uses the non-filtered count so a policy reclassification
	// invalidates even when no new row advances MAX(id).
	var discoveries, discoveryMax, traffic, trafficMax, endpoints, endpointShape, profiles, profileShape, findings, findingMax int64
	var endpointUpdated, profileUpdated string
	if err := s.db.Conn().QueryRow(`
		SELECT
		  (SELECT COUNT(*) FROM url_discoveries WHERE scan_id = ?),
		  (SELECT COALESCE(MAX(id), 0) FROM url_discoveries WHERE scan_id = ?),
		  (SELECT COUNT(*) FROM traffic WHERE scan_id = ? AND is_filtered = FALSE),
		  (SELECT COALESCE(MAX(id), 0) FROM traffic WHERE scan_id = ? AND is_filtered = FALSE),
		  (SELECT COUNT(*) FROM endpoints WHERE scan_id = ?),
		  (SELECT COALESCE(SUM(LENGTH(id) + LENGTH(method) + LENGTH(url_pattern)), 0) FROM endpoints WHERE scan_id = ?),
		  (SELECT COALESCE(MAX(last_seen_at), '') FROM endpoints WHERE scan_id = ?),
		  (SELECT COUNT(*) FROM page_profiles WHERE scan_id = ?),
		  (SELECT COALESCE(SUM(LENGTH(id) + LENGTH(method) + LENGTH(url)), 0) FROM page_profiles WHERE scan_id = ?),
		  (SELECT COALESCE(MAX(updated_at), '') FROM page_profiles WHERE scan_id = ?),
		  (SELECT COUNT(*) FROM findings WHERE scan_id = ? AND confidence = 'confirmed'),
		  (SELECT COALESCE(MAX(id), 0) FROM findings WHERE scan_id = ? AND confidence = 'confirmed')`,
		scanID, scanID, scanID, scanID, scanID, scanID, scanID, scanID, scanID, scanID, scanID, scanID,
	).Scan(&discoveries, &discoveryMax, &traffic, &trafficMax,
		&endpoints, &endpointShape, &endpointUpdated,
		&profiles, &profileShape, &profileUpdated, &findings, &findingMax); err != nil {
		return 0, err
	}
	revision := strings.Join([]string{
		fmt.Sprint(discoveries), fmt.Sprint(discoveryMax), fmt.Sprint(traffic), fmt.Sprint(trafficMax),
		fmt.Sprint(endpoints), fmt.Sprint(endpointShape), endpointUpdated,
		fmt.Sprint(profiles), fmt.Sprint(profileShape), profileUpdated,
		fmt.Sprint(findings), fmt.Sprint(findingMax), scanTarget, fastGraphScopeFingerprint(graphScope),
	}, ":")

	s.graphRouteCountMu.Lock()
	if s.graphRouteCountCache == nil {
		s.graphRouteCountCache = make(map[int64]*graphRouteCountCacheEntry)
	}
	entry := s.graphRouteCountCache[scanID]
	if entry == nil {
		if len(s.graphRouteCountCache) >= 16 {
			for cachedScanID := range s.graphRouteCountCache {
				delete(s.graphRouteCountCache, cachedScanID)
				break
			}
		}
		entry = &graphRouteCountCacheEntry{}
		s.graphRouteCountCache[scanID] = entry
	}
	s.graphRouteCountMu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.revision == revision {
		return entry.count, nil
	}
	routes, err := s.collectFastGraphRoutes(scanID, scanTarget, graphScope)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, route := range routes {
		if route.InScope {
			count++
		}
	}
	entry.revision = revision
	entry.count = count
	return count, nil
}

func fastGraphScopeFingerprint(scope graphProjectionScope) string {
	parts := make([]string, 0, len(scope.origins)+len(scope.wildcards))
	for origin := range scope.origins {
		parts = append(parts, "o|"+origin.scheme+"|"+origin.host+"|"+origin.port)
	}
	for _, wildcard := range scope.wildcards {
		parts = append(parts, "w|"+wildcard.scheme+"|"+wildcard.host+"|"+wildcard.port)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func (s *Server) writeFastDiscoveryOrigins(w http.ResponseWriter, scanID int64, scanTarget string, graphScope graphProjectionScope) error {
	routes, err := s.collectFastGraphRoutes(scanID, scanTarget, graphScope)
	if err != nil {
		return err
	}
	targetRoot, _ := targetresolver.RegistrableDomain(scanTarget)
	targetOrigin := ""
	if canonical, ok := canonicalGraphURL(scanTarget); ok {
		if parsed, parseErr := url.Parse(canonical); parseErr == nil {
			targetOrigin = parsed.Scheme + "://" + parsed.Host
		}
	}
	type originAccumulator struct {
		discoveryGraphOriginOut
		endpointSet map[string]bool
		profileSet  map[string]bool
	}
	origins := make(map[string]*originAccumulator)
	ensureOrigin := func(rawURL string) (*originAccumulator, bool) {
		canonical, ok := canonicalGraphURL(rawURL)
		if !ok {
			return nil, false
		}
		parsed, parseErr := url.Parse(canonical)
		if parseErr != nil || parsed.Hostname() == "" {
			return nil, false
		}
		origin := parsed.Scheme + "://" + parsed.Host
		if existing := origins[origin]; existing != nil {
			return existing, true
		}
		nodeRoot, _ := targetresolver.RegistrableDomain(origin)
		firstParty := targetRoot != "" && strings.EqualFold(nodeRoot, targetRoot)
		hostname := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
		item := &originAccumulator{
			discoveryGraphOriginOut: discoveryGraphOriginOut{
				Origin: origin, Host: parsed.Host, Hostname: hostname,
				FirstParty: firstParty,
				Subdomain:  firstParty && !strings.EqualFold(hostname, targetRoot) && !strings.EqualFold(hostname, "www."+targetRoot),
				Target:     strings.EqualFold(origin, targetOrigin),
			},
			endpointSet: make(map[string]bool), profileSet: make(map[string]bool),
		}
		origins[origin] = item
		return item, true
	}
	for _, route := range routes {
		item, ok := ensureOrigin(route.URL)
		if !ok {
			continue
		}
		item.URLs++
		item.InScope = item.InScope || route.InScope
		if route.Observed {
			item.Observed++
		}
		if route.Analyzed {
			item.Analyzed++
		}
		item.Findings += route.FindingCount
		for ref := range route.endpointSet {
			item.endpointSet[ref] = true
		}
		for profileID := range route.profileSet {
			item.profileSet[profileID] = true
		}
		for _, method := range route.Methods {
			item.Methods = appendUnique(item.Methods, method)
		}
		for _, tag := range route.KindTags {
			item.KindTags = appendUnique(item.KindTags, tag)
			if tag == "api-call" {
				item.APINodes++
			}
		}
		if discoveryGraphAuthPath(route.Path) {
			item.AuthNodes++
		}
		if fastGraphSeverityRank(route.WorstSeverity) > fastGraphSeverityRank(item.WorstSeverity) {
			item.WorstSeverity = route.WorstSeverity
		}
	}

	// Denied dependency origins are boundary cards only. This query is bounded
	// and never asks the full graph builder to materialize route/profile data.
	boundaryRows, boundaryErr := s.db.Conn().Query(`
		SELECT metadata_json
		  FROM narrations
		 WHERE scan_id=? AND agent='policy' AND action='denied'
		 ORDER BY id ASC
		 LIMIT 200`, scanID)
	if boundaryErr == nil {
		for boundaryRows.Next() {
			var raw string
			if boundaryRows.Scan(&raw) != nil {
				continue
			}
			var meta map[string]any
			if json.Unmarshal([]byte(raw), &meta) != nil {
				continue
			}
			canonical, _ := meta["canonical_origin"].(string)
			canonicalURL, canonicalOK := canonicalGraphURL(strings.TrimSpace(canonical))
			parsed, parseErr := url.Parse(canonicalURL)
			if !canonicalOK || parseErr != nil || parsed.Scheme == "" || parsed.Hostname() == "" || scanproxy.IsBrowserInternalHost(parsed.Hostname()) {
				continue
			}
			item, ok := ensureOrigin(canonicalURL)
			if ok {
				item.KindTags = appendUnique(item.KindTags, "policy-boundary")
			}
		}
		_ = boundaryRows.Close()
	}

	out := make([]discoveryGraphOriginOut, 0, len(origins))
	originStats := map[string]int{"origin_count": len(origins)}
	for _, item := range origins {
		item.EndpointRefs = len(item.endpointSet)
		item.Profiles = len(item.profileSet)
		sort.Strings(item.Methods)
		sort.Strings(item.KindTags)
		if item.InScope {
			originStats["in_scope_origins"]++
		}
		if item.FirstParty {
			originStats["first_party_origins"]++
			if !item.InScope {
				originStats["linked_only_first_party"]++
			}
		} else {
			originStats["external_origins"]++
		}
		if item.Subdomain {
			originStats["first_party_subdomains"]++
		}
		out = append(out, item.discoveryGraphOriginOut)
	}
	sort.Slice(out, func(i, j int) bool {
		left, right := out[i], out[j]
		leftRank, rightRank := fastGraphOriginRank(left), fastGraphOriginRank(right)
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		if left.Observed != right.Observed {
			return left.Observed > right.Observed
		}
		return left.Origin < right.Origin
	})
	jsonResponse(w, map[string]any{
		"schema_version": discoveryGraphSchemaVersion,
		"origins_only":   true,
		"origins":        out,
		"stats":          originStats,
	})
	return nil
}

func fastGraphSeverityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

func fastGraphOriginRank(origin discoveryGraphOriginOut) int {
	switch {
	case origin.Target:
		return 0
	case origin.InScope && origin.FirstParty:
		return 1
	case origin.FirstParty:
		return 2
	case origin.InScope:
		return 3
	default:
		return 4
	}
}
