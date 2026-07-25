package ui

import (
	"strings"
	"testing"
)

func TestTargetAtlasContractsAreEmbedded(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, contract := range []string{
		"async function renderTargetAtlas", "function buildTargetAtlas",
		"function drawAtlasMinimap", "function atlasToggleLayer",
		"function drawAtlasAreaSummary", "function drawAtlasEndpointCard", "function atlasRelationshipSummaryHTML",
		"function atlasHostIdentity", "function atlasLayoutHosts",
		"function drawAtlasHost", "function atlasFocusContainer",
		"TARGET ATLAS", "Logical routes", "atlas-detail", "atlas-minimap",
		"Coverage", "Authorized-target intelligence",
		"Find domain, host, area, logical route", "Whole target",
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("embedded Target Atlas missing %q", contract)
		}
	}
}

func TestTargetTreeIsDefaultOverview(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, contract := range []string{
		"let graphMode = 'tree'", "async function renderTargetTree",
		"function renderTargetTreeBody", "function targetTreeDomainHTML",
		"function targetTreeHostHTML", "function targetTreeDistrictHTML",
		"function targetTreeEndpointHTML", "In-scope linked-only origins",
		"Whole target at a glance", "Show routes", "Hide routes",
		"Target Tree", "Visual Map", "URL Paths",
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("embedded Target Tree missing %q", contract)
		}
	}
}

func TestTargetGraphRequestsOnlyAuthorizedScope(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, contract := range []string{
		"In-scope linked-only origins",
		"query values remain facets, never duplicate boxes",
		"Every in-scope logical route grouped by path",
		"Number.isFinite(stats?.graph_route_count)",
		"same canonical origin+path identity as Graph",
		"function getScopedDiscoveryGraph",
		"function getTargetAtlasModel",
		"function resetGraphDataCache",
		"n.url&&n.in_scope!==false",
		"externalHosts",
		"external ${targetTreeWord(m.externalHosts,'host')} omitted",
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("scope-safe Target Graph missing %q", contract)
		}
	}
	if got := strings.Count(html, "&max_nodes=0&scope=in"); got != 1 {
		t.Fatalf("Target Graph should centralize full scoped graph fetching; got %d full scoped request sites", got)
	}
}

func TestTargetAtlasTreatsHostsAsFirstClassContainers(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, contract := range []string{
		"hostsMap", "districtsMap:new Map()", "hostID:host.id",
		"domainsMap", "atlasRegistrableDomain", "atlasContainerDetailHTML",
		"click to expand", "atlasVisibleBounds",
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("multi-host Target Atlas missing %q", contract)
		}
	}
}

func TestTargetAtlasDoesNotDependOnRemoteGraphRuntime(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, remote := range []string{"cdn.jsdelivr.net/npm/cytoscape", "unpkg.com/sigma", "d3-force.min.js"} {
		if strings.Contains(html, remote) {
			t.Fatalf("Target Atlas unexpectedly depends on remote graph runtime %q", remote)
		}
	}
}

func TestTargetAtlasInteractionIsFrameThrottled(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, contract := range []string{
		"function destroyTargetAtlas", "function atlasRequestDraw",
		"function atlasZoomAt", "function atlasZoomButton",
		"function atlasBuildHitGrid", "requestAnimationFrame(atlasProcessPointer)",
		"minimapDirty", "interactingUntil", "lightweightDraw",
		"Choose an origin → choose a functional area", "Map zoom controls",
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("optimized Target Atlas missing %q", contract)
		}
	}
}

func TestTargetAtlasUsesBoundedReadableEndpointCards(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, contract := range []string{
		"resultLimit:12", "resultOffset:0", "function atlasMatchingEndpoints",
		"function atlasRenderedEndpoints", "function drawAtlasEndpointCard",
		"function atlasPageResults", "visible>shown?`Routes ${start}",
		"id=\"atlasQueryPrevious\"", "id=\"atlasQueryNext\"",
		"CLICK TO INSPECT ROUTES", "atlasState.camera.x=n.resultX||n.x",
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("readable Target Atlas result contract missing %q", contract)
		}
	}
}

func TestTargetAtlasCachesProjectionAndBoundsPointerWork(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, contract := range []string{
		"function atlasResultKey", "function atlasInvalidateResults",
		"function atlasHideTooltip", "atlasHideTooltip();renderAtlasQueryControls",
		"if(atlasState.resultKey===key)return atlasState.matchingEndpoints",
		"atlasState.drawNodes=atlasState.model.nodes.filter(n=>n.kind==='endpoint')",
		"if(atlasResultMode()){for(const n of atlasRenderedEndpoints()",
		"world.x>=n.resultLeft", "if(next!==atlasState.hover)tip.innerHTML",
		"return null;}",
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("Target Atlas performance contract missing %q", contract)
		}
	}
}

func TestTargetAtlasAdaptsDensityToAvailableSurfaceWidth(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, contract := range []string{
		"function atlasSurfaceWidth", "function atlasResultPageSize",
		"atlasSurfaceWidth()<850?6:12", "atlas-root.compact",
		"classList.toggle('compact',compact)", "compact=atlasSurfaceWidth()<850",
		"atlas-query-summary { display:inline", "atlas-query-reset::after",
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("responsive Target Atlas contract missing %q", contract)
		}
	}
}

func TestTargetAtlasEmptyProjectionRemovesIrrelevantMapChrome(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, contract := range []string{
		"atlas-stage.empty-result", "classList.toggle('empty-result',show)",
		"No logical routes match “${atlasState.query}”", "Try a shorter path, host, or area name",
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("empty Target Atlas projection contract missing %q", contract)
		}
	}
}

func TestTargetAtlasExplainsAndQueuesOpenReconQuestions(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, contract := range []string{
		"function atlasReviewUnknowns", "function atlasUnknownDetailHTML",
		"function atlasUnknownEvidenceHTML", "function atlasOpenEvidenceRef",
		"Review unanswered recon questions", "Review queue — not plotted on the map",
		"questionRailX", "anchor?anchor.x+30:questionRailX",
		"It is neither a URL nor a confirmed vulnerability",
		"if(n.kind==='unknown')return false", "id=\"atlasQuestionsButton\"",
		"Why it matters", "Evidence status", "How to answer it",
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("open-question review contract missing %q", contract)
		}
	}
}

func TestTargetAtlasBuildsAProgressiveFilteredGraph(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, contract := range []string{
		"endpointFilter:'structure'", "function atlasOverviewMode",
		"function atlasLayoutHostSummaries", "function drawAtlasHostSummary",
		"function atlasAreaOverviewMode", "function atlasLayoutAreaSummaries",
		"function drawAtlasAreaSummary", "function atlasResultMode",
		"id=\"atlasOriginFilter\"", "id=\"atlasAreaFilter\"",
		"data-atlas-result=\"structure\"", "data-atlas-result=\"risk\"",
		"data-atlas-result=\"unanalyzed\"", "data-atlas-result=\"state\"",
		"function atlasSetOriginFilter", "function atlasSetAreaFilter",
		"function atlasSetEndpointFilter", "function atlasResetProjection",
		"if(n.kind==='host'){atlasSetOriginFilter(n.id);return;}",
		"if(n.kind==='district'){atlasSetAreaFilter(n.id);return;}",
		"atlasState.renderedEndpointIDs.has(n.id)",
		"CLICK TO EXPAND AREAS", "choose one to inspect logical routes",
		"class=\"atlas-workspace\"", ".atlas-detail.open { flex-basis:340px",
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("progressive Target Atlas contract missing %q", contract)
		}
	}
}

func TestTargetGraphKeepsEvidenceAndURLVariantsTruthful(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, contract := range []string{
		"function graphNodeMethods", "endpoint_refs", "profile_ids",
		"host.origin===targetIdentity.origin", "materializeEndpointRecords",
		"raws: []", "'@url:'+raw.url", "function openGraphEndpointRefs",
		"Same-method records keep a short evidence fingerprint",
		"evidence ${position}/${totals[method]} · ${fingerprint}",
		"method-URL", "observed endpoints", "fetchScopedDiscoveryGraphPages",
		"GRAPH_DISCOVERY_PAGE_SIZE", "function collectSiteMapRows",
		"function loadMoreGraphRows", "e.type||e.kind",
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("truthful Target Graph missing %q", contract)
		}
	}
	for _, fabricatedMethod := range []string{"raw.method||'GET'", "node.raw.method || 'GET'"} {
		if strings.Contains(html, fabricatedMethod) {
			t.Fatalf("Target Graph still fabricates a method via %q", fabricatedMethod)
		}
	}
}

func TestTargetGraphRendersLogicalRouteFacetsAndRedirectEvidence(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, contract := range []string{
		"function graphNodeQueryVariants", "function graphNodeRouteUnverified",
		"function graphNodeEvidenceBadge", "method evidence differs", "query responses differ",
		"function graphMethodEvidenceSummary", "exact query variants:",
		"function graphNodeEvidenceNote", "function graphLogicalRouteURL", "u.search=''",
		"byURL.get(graphLogicalRouteURL(p.url))", "query variants", "Query facets · one logical route",
		"redirect unverified", "not a verified page", "redirect_unverified:'#d29922'",
		"Logical routes <strong id=\"gtEndpointCount\"", "exact query URLs stay as evidence specimens",
		"routeFacetSuffix", "raw.query_keys", "raw.url_samples",
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("logical-route evidence UI missing %q", contract)
		}
	}
}

func TestFindingDetailCallsOutWeakLegacyAuthProof(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, contract := range []string{
		"function renderFindingVerificationNotes",
		"Auth success signal:",
		"HTTP 200 alone is not enough",
		"The stored response preview is HTML",
		"same status and length",
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("finding verification note contract missing %q", contract)
		}
	}
}

func TestURLPathsStaysInsideGraphLayout(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	start := strings.Index(html, ".sm-root {")
	if start < 0 {
		t.Fatal("URL Paths root styles missing")
	}
	end := strings.Index(html[start:], "}")
	if end < 0 {
		t.Fatal("URL Paths root styles are malformed")
	}
	rootBlock := html[start : start+end]
	if strings.Contains(rootBlock, "margin:") {
		t.Fatalf("URL Paths root must not escape and overlap Graph tabs: %s", rootBlock)
	}
	for _, contract := range []string{"Logical routes", "sm-actions", "authorized target first", "const originKey = u.origin"} {
		if !strings.Contains(html, contract) {
			t.Fatalf("compact URL Paths missing %q", contract)
		}
	}
}

func TestScanStartUIDefaultPathIsPlainAndIncludesDiscoveredSubdomains(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, contract := range []string{
		`placeholder="https://app.example.com"`,
		`id="scanIncludeSubdomains" checked`,
		"Smart discovery (recommended)",
		"function scanTargetInterpretation()",
		"Google, Gmail, analytics, ads, and other external domains stay out",
		"AI prioritizes endpoints inside this boundary; it never expands authorization by itself",
		"Advanced settings",
		"Limits, model, authority, extra scope, and login",
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("scan-start UI missing %q", contract)
		}
	}
	if strings.Contains(html, `placeholder="https://partner.example.com"`) {
		t.Fatal("scan-start UI must not use a real company domain as its placeholder")
	}
}
