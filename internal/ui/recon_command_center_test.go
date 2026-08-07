package ui

import (
	"strings"
	"testing"
)

func TestReconCommandCenterIsFirstClassWorkspace(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, contract := range []string{
		`data-view="recon"`,
		`'home','live','overview','recon','endpoints'`,
		`case 'recon': renderResult = renderReconCommandCenter(vc)`,
		`async function renderReconCommandCenter`,
		`Recon command center // grounded application model`,
		`UNDERSTANDING / 100`,
		`Current recon objective`,
		`Objective queue`,
		`Discovery journal`,
		`Recon briefing`,
		`Target DNA`,
		`Evidence gates`,
		`Origin &amp; subdomain map`,
		`External recon`,
		`Source provenance // candidates // confirmed assets`,
		`function rcRenderExternalRecon`,
		`api('/api/recon-assets')`,
		`continuous · every`,
		`newAssets`,
		`promotedAssets`,
		`Path to 100`,
		`Discovery lens`,
		`Novelty-first sampling`,
		`Analysis &amp; learning loop`,
		`capture → understand → change priority`,
		`followCounts.skipped`,
		`held for Active`,
		`Learning memory`,
		`Starvation prevented`,
		`Semantic call saved`,
		`compacted · call saved`,
		`AI calls saved`,
		`semantic_calls_saved`,
		`protection_calls_saved`,
		`protection shape`,
		`recovered application route remains analyzable`,
		`aging_boost`,
		`evidence_gain`,
		`Likely advances:`,
		`predicted, not guaranteed`,
		`Evidence-directed`,
		`bounded evidence priority`,
		`outcome_status`,
		`Model feedback`,
		`batch-scoped feedback, not proof that one route caused the movement`,
		`one batch cannot`,
		`calibration`,
		`function rcRenderPentesterBrief`,
		`Direct evidence · ${inputCount} total captured field`,
		`Inference, not proof`,
		`function rcLeadLifecycle`,
		`function rcProfileInputLeadRows`,
		`executed lifecycle first · user-facing controls next`,
		`Observed signal`,
		`Active test completed`,
		`function rcDirectiveIsSecurityTest`,
		`A matching fetch/reanalysis completed; no active probe ran`,
		`Detected automatically; no matching active-test directive is queued`,
		`A pentester queue, not a vulnerability list`,
		`api('/api/strategy')`,
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("embedded Recon Command Center missing %q", contract)
		}
	}
}

func TestReconCommandCenterUsesMeasuredGroundedEvidence(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, contract := range []string{
		`metrics.understanding_score`,
		`score >= 85 && storedLevel === 'developing'`,
		`metrics.targets_met`,
		`rcArray(recon.targets)`,
		`rcBuildObjectives(recon)`,
		`api('/api/surface')`,
		`api('/api/narrations?latest=1&limit=60')`,
		`api('/api/discovery-graph?origins_only=1')`,
		`function rcRenderOrigins`,
		`first_party_subdomains`,
		`const coverageBase = observed || Number(origin.endpoint_refs) || total`,
		`of observed surface analyzed`,
		`LINKED ONLY`,
		`EXTERNAL REF`,
		`blocked dependency`,
		`function rcToggleOrigins`,
		`Show all ${allOrigins.length} origins`,
		`function rcEstimatePathTo100`,
		`EVIDENCE TARGET ACHIEVED`,
		`PATH TO 100 · ${accessConstrained ? 'ACCESS PREREQUISITE'`,
		`TIME UNKNOWN`,
		`function rcLoadPriorComparison`,
		`function rcRuntimeMinutes`,
		`function rcRuntimeMs`,
		`scan time · ${fmtDuration(scanRuntimeMs)}`,
		`Since prior Recon #`,
		`id="rcPriorDelta"`,
		`currentTargetOrigins`,
		`newOriginLabels`,
		`['prerequisites'`,
		`bounded evidence pass in progress`,
		`COLLECTING NOW`,
		`OPERATOR PREREQUISITE`,
		`needsOperatorPrerequisite`,
		`longest,item`,
		`authenticated or second-persona evidence`,
		`Actors // objects // workflows // boundaries`,
		`Evidence, not guesses`,
		`function openReconEvidence`,
		`showEndpointDetail(exactEndpoint.hash)`,
		`String(ref).toLowerCase() !== 'gap'`,
		`hasReconTargets ? reconScore + '%'`,
		`function rcJournalDigest`,
		`scanner events collapsed`,
		`queries hidden`,
		`PENTESTER NOTE //`,
		`function rcRenderTargetStory`,
		`function rcObservedStackSignals`,
		`Observed stack &amp; controls`,
		`Django Oscar`,
		`Gravity Forms`,
		`USWDS`,
		`X-Frame-Options`,
		`function rcClaimTruth`,
		`const groundedStepRefs = rcArray(item?.steps)`,
		`submi(?:t|ts|tted|ssion)`,
		`a.source === 'target' ? -1 : 1`,
		`evidence_ceiling`,
		`u.access`,
		`Target evidence is incomplete.`,
		`authenticated_request_observed`,
		`state_changing_request_observed`,
		`rc-truth`,
		`function rcTargetShortLabel`,
		`claim_confidence:'Confidence'`,
		`Query-routed page types`,
		`Routed views`,
		`TRANSPORT TRUST`,
		`Authentication was mapped without using credentials`,
		`function rcJournalBrowserNoiseHost`,
		`function rcJournalAuthRoute`,
		`pathSegments.some(segment => authSegments.has(segment))`,
		`Authentication boundary inspected`,
		`EXTERNAL NAVIGATION`,
		`without mislabeling an ordinary external reference as an identity handoff`,
		`phase_breakdown`,
		`function rcModelPhaseLabel`,
		`model time · ${Number(ai.llm_calls)} calls`,
		`Math.round((Number(phase.duration_ms)||0) * 100 / totalModelMs)`,
		`rcCommandRenderSignature === reconRenderSignature`,
		`rcNarrationSignature(narrations)`,
		`el.querySelector('.rc-root')`,
		`brute[- ]?force`,
		`separate operator-authorized active`,
		`This is an evidence-backed testing lead, not authorization.`,
		`function rcRenderDiscoveryLens`,
		`u.discovery_quality`,
		`semantic areas`,
		`response shapes`,
		`rank exact observed links by new application surface, route family, and captured response-shape diversity`,
		`function showReconPageInsight`,
		`Why a pentester cares`,
		`Application relationships`,
		`Learn this next`,
		`function askReconPage`,
		`function askReconGap`,
		`askReconGap('object'`,
		`askReconGap('target'`,
		`context.gap`,
		`Server resolves this pointer again before model use`,
		`Click to ask Copilot for one grounded next action`,
		`Use only the server-resolved gap packet and exact scan-owned candidates. Never invent or repair a URL.`,
		`Keep AI analysis separate from execution`,
		`function rcRenderLearningLoop`,
		`api('/api/recon-learning-queue')`,
		`real endpoint-family backlog`,
		`Enumeration re-shaped`,
		`Noise suppressed`,
		`without spending AI calls`,
		`Recon analysis does not imply active probing.`,
		`id="scanExternalRecon"`,
		`id="scanReconVHost"`,
		`Virtual-host enumeration (explicit opt-in)`,
		`id="scanContinuousRecon"`,
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("Recon evidence contract missing %q", contract)
		}
	}
	if strings.Contains(html, `const authLike = /auth|`) {
		t.Fatal("Recon journal still classifies authentication routes with substring matching")
	}
}

func TestReconDemoEntryIsCompactAndStartsAtTheTop(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, contract := range []string{
		`class="rc-gate-grid"`,
		`class="rc-story-grid"`,
		`What the robot can now reason about`,
		`Grounded journeys`,
		`Trust rules`,
		`viewContainer.scrollTo({top:0,left:0,behavior:'auto'})`,
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("Recon demo contract missing %q", contract)
		}
	}
}

func TestScanScopedAPIHelperNeverReusesStaleRunningState(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	if !strings.Contains(html, `{ cache: 'no-store' }`) {
		t.Fatal("scan-scoped API helper can reuse stale browser-cached scan state")
	}
}

func TestReconRefreshesRunningInternalsAndSemanticCorrections(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, contract := range []string{
		`let rcAgentInternalsFetchedAt = 0`,
		`let rcAgentInternalsLoadingKey = ''`,
		`let rcAgentInternalsRequestSerial = 0`,
		`let rcDeferredRequestSerial = 0`,
		`function rcAgentInternalsRunning`,
		`function rcAgentInternalsCacheFresh`,
		`rcAgentInternalsRunning(scanStatus) ? 5000 : Infinity`,
		`rcAgentInternalsFetchedAt = Date.now()`,
		`activeKey !== key || requestSerial !== rcAgentInternalsRequestSerial`,
		`activeScanKey !== reconScanKey || deferredRequestSerial !== rcDeferredRequestSerial`,
		`rcLoadAgentInternals(sc.status, rcAgentInternalsRunning(sc.status))`,
		`appType, rawIdentitySummary, identitySummary`,
		`access.state || '', access.label || '', access.detail || ''`,
		`objectives.map(item => [item.id, item.met, item.priority, item.question, item.next])`,
		`areas.map(item => [item.id || item.name, item.priority, rcArray(item.endpoints).length])`,
		`targets.map(item => [item.id, item.met, item.actual, item.target, item.label])`,
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("Recon refresh contract missing %q", contract)
		}
	}
}

func TestReconLandingPrioritizesActionableSignalsOverInventory(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, contract := range []string{
		`function rcConciseIdentitySummary`,
		`candidate route${routeCount === 1 ? '' : 's'} still need direct response evidence`,
		`Priority testing leads`,
		`Unconfirmed input and reflection signals only.`,
		`Review in Findings`,
		`const visibleRows = actionableRows.map((lead,index)`,
		`directivePaths.includes(route)`,
		`telemetry/system field`,
		`a lead is only “tested” when a matching active-test directive completes`,
		`<div id="rcSurfaceSummary">${rcRenderSurfaceBrief`,
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("compact Recon landing contract missing %q", contract)
		}
	}

	start := strings.Index(html, "async function renderReconCommandCenter")
	end := strings.Index(html[start:], "function rcRenderSurfaceBrief")
	if start < 0 || end < 0 {
		t.Fatal("could not isolate Recon renderer")
	}
	renderer := html[start : start+end]
	leads := strings.Index(renderer, `<div id="rcLeads">`)
	surfaceDisclosure := strings.Index(renderer, `id="rcSurfaceDisclosure"`)
	surfaceSummary := strings.Index(renderer, `id="rcSurfaceSummary"`)
	if leads < 0 || surfaceDisclosure < 0 || surfaceSummary < 0 || surfaceSummary < surfaceDisclosure {
		t.Fatal("surface inventory must remain behind the Observed surface disclosure")
	}
}

func TestReconRefreshPreservesScrollAndOpenDisclosures(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, contract := range []string{
		`const savedScrollTop = isReRender ? vc.scrollTop : 0`,
		`vc.scrollTo({top:savedScrollTop,left:0,behavior:'auto'})`,
		`el.querySelectorAll('.rc-disclosure[id][open]')`,
		`id="rcUnderstandingDisclosure"`,
		`id="rcSurfaceDisclosure"`,
		`id="rcAgentThinkingDisclosure"`,
		`if (disclosure) disclosure.open = true`,
		`if (agentDisclosure?.open)`,
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("Recon refresh-state contract missing %q", contract)
		}
	}
	if strings.Contains(html, `const savedScrollY = isReRender ? window.pageYOffset : 0`) {
		t.Fatal("same-view refresh still captures document scroll instead of viewContainer scroll")
	}
}

func TestReconCommandCenterKeepsRawInventoryBehindDrillDowns(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	start := strings.Index(html, "async function renderReconCommandCenter")
	end := strings.Index(html[start:], "function rcRenderSurface")
	if start < 0 || end < 0 {
		t.Fatal("could not isolate Recon Command Center renderer")
	}
	renderer := html[start : start+end]
	for _, forbidden := range []string{
		`<table`,
		`poc_request`,
		`sendRawToRepeater`,
		`fetch(sc.target`,
	} {
		if strings.Contains(renderer, forbidden) {
			t.Fatalf("Recon renderer duplicates or mutates low-level surface via %q", forbidden)
		}
	}
	for _, drilldown := range []string{
		`navigateToView('graph')`,
		`navigateToView('endpoints')`,
		`openReconEvidence`,
	} {
		if !strings.Contains(renderer, drilldown) {
			t.Fatalf("Recon renderer missing drill-down %q", drilldown)
		}
	}
}

func TestReconDiscoveryLocateUsesDecodedExactGraphFocus(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, contract := range []string{
		`data-copilot-url="${escAttr(url)}"`,
		`function decodeGraphFocusValue(raw)`,
		`function graphFocusCanonicalURL(raw)`,
		`function graphFocusDisplayQuery(raw)`,
		`function focusTargetTree(raw)`,
		`targetTreeState.selected=exact.id`,
		`focusTargetTree(query)`,
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("Recon discovery Graph focus missing %q", contract)
		}
	}
	if strings.Contains(html, `openCopilotEvidence('discovery','${Number(d.id)||id}','${encodedURL}')`) {
		t.Fatal("Locate in target graph still passes an encodeURIComponent value as the visible search query")
	}
}
