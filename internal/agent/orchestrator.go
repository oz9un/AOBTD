package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/ozzyw/aobtd/internal/browser"
	"github.com/ozzyw/aobtd/internal/filter"
	"github.com/ozzyw/aobtd/internal/llm"
	"github.com/ozzyw/aobtd/internal/pathlabel"
	"github.com/ozzyw/aobtd/internal/policy"
	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

// Orchestrator coordinates all agents during a scan.
type Orchestrator struct {
	bus      *Bus
	state    *SharedState
	db       *store.DB
	browser  *browser.Controller
	scanID   int64
	target   string
	scope    []string
	logger   *slog.Logger
	provider llm.Provider // nil if no LLM configured
	// reasoningProvider handles high-value semantic work (domain reasoning,
	// attack-chain planning). Endpoint analysis stays on provider so hosted
	// scans can keep the high-volume profiler fast and cheap.
	reasoningProvider llm.Provider
	budget            *llm.Budget
	interactor        Interactor
	// testingAuthority is the operator-selected profile transported from the
	// CLI/UI. Day 3B will apply it at each execution boundary.
	testingAuthority policy.TestingAuthority
	executionPolicy  *policy.Engine
	policyErr        error
	policyAuditMu    sync.Mutex
	policyAuditCount map[string]int
	// reconCopilotVisit is an injectable browser-visit boundary used by the
	// lifecycle integration fixture. Production leaves it nil and uses the
	// real Rod controller below; the hook keeps queue/policy/provenance/storage
	// behavior testable without making the unit suite depend on local Chrome.
	reconCopilotVisit func(context.Context, string) error

	// Strategist — optional; nil if Period is zero or no provider
	strategistProvider llm.Provider
	strategistPeriod   time.Duration
	strategist         *StrategistAgent // set during Run()

	// Config
	maxDepth              int
	maxPages              int
	seedURLs              []string
	analysisEndpointLimit int

	// Final convergence is intentionally bounded. These fields are private so
	// production uses the conservative defaults below while package tests can
	// exercise terminal-state behavior without waiting minutes.
	finalConvergenceRounds int
	finalConvergenceBudget time.Duration
	finalExplorerBudget    time.Duration

	// authAlreadyConfigured gates the interactive login-found notification.
	// Set by the CLI when credentials came in via flags/env/session-cookie.
	authAlreadyConfigured bool
	authLoginURL          string
	authLoginUser         string
	authLoginPass         string
	bolaPersonas          []BOLAPersonaConfig

	// pathLabel is the shared path-label resolver. The orchestrator
	// constructs one Resolver per scan and passes it to every agent
	// that names URLs (crawler for saturation narrations, analyzer for
	// endpoint cluster labels, etc.). Sharing the resolver means one
	// LLM-labelled pattern is reused across the whole pipeline — no
	// duplicate calls, consistent labels in every UI surface.
	pathLabel          pathlabel.Resolver
	semanticSaturation *SemanticSaturationState
}

const (
	defaultFinalConvergenceRounds = 4
	defaultFinalConvergenceBudget = 5 * time.Minute
	defaultFinalExplorerBudget    = 90 * time.Second
)

// OrchestratorConfig holds configuration for the orchestrator.
type OrchestratorConfig struct {
	Target   string
	ScanID   int64
	MaxDepth int
	MaxPages int
	SeedURLs []string
	Scope    []string // crawler host/domain roots; empty = derive from target
	// AnalysisEndpointLimit bounds per-pass Analyzer endpoint families. Zero
	// keeps normal unlimited behavior.
	AnalysisEndpointLimit int
	// PolicyScope contains exact or explicitly wildcarded origins used by the
	// central enforcement boundary. It is kept separate from crawler roots so
	// discovery convenience can never silently broaden active-testing scope.
	PolicyScope []string
	Provider    llm.Provider
	// ReasoningProvider is an optional stronger model for domain reasoners.
	// If nil, Provider is used for every task.
	ReasoningProvider llm.Provider
	Budget            *llm.Budget
	OutputDir         string
	Interactor        Interactor

	// StrategistProvider is an optional separate LLM used by the Sovereign
	// Strategist. Keeping it separate from the main Provider lets users run
	// a stronger model for strategic reasoning (e.g. qwen2.5:14b or Claude)
	// while using a smaller one for per-endpoint analysis. If nil, falls
	// back to Provider.
	StrategistProvider llm.Provider
	// StrategistPeriod controls how often the Strategist wakes up. Zero
	// disables the Strategist entirely.
	StrategistPeriod time.Duration

	// AuthAlreadyConfigured reports whether the scan was launched with
	// credentials (CLI flags / session cookie). When true, the crawler
	// suppresses login-form notifications — the user already told us
	// what to do about auth.
	AuthAlreadyConfigured bool
	// AuthLoginURL/AuthLoginUser/AuthLoginPass are optional non-interactive
	// form-login details passed by the CLI/UI. They let the auth phase retry a
	// configured login page if the pre-crawl attempt failed or was blocked by
	// a transient SPA modal.
	AuthLoginURL  string
	AuthLoginUser string
	AuthLoginPass string
	// BOLAPersonas carries optional two-account ownership context. Passwords
	// stay in process memory only; they are used by the reasoner executor after
	// the LLM proposes an ownership-aware BOLA plan.
	BOLAPersonas []BOLAPersonaConfig

	// TestingAuthority is selected by the operator. Empty retains the
	// recommended Active Pentest default for older programmatic callers.
	TestingAuthority policy.TestingAuthority
}

type BOLAPersonaConfig struct {
	Label       string
	LoginURL    string
	Username    string
	Password    string
	OwnerMarker string
	ObjectURL   string
}

// NewOrchestrator creates a scan orchestrator.
func NewOrchestrator(
	db *store.DB,
	ctrl *browser.Controller,
	cfg OrchestratorConfig,
	logger *slog.Logger,
) *Orchestrator {
	scope := cfg.Scope
	if len(scope) == 0 {
		parsed, err := url.Parse(cfg.Target)
		if err == nil {
			scope = []string{strings.ToLower(parsed.Hostname())}
		}
	}

	reasoningProv := cfg.ReasoningProvider
	if reasoningProv == nil {
		reasoningProv = cfg.Provider
	}
	stratProv := cfg.StrategistProvider
	if stratProv == nil {
		stratProv = cfg.Provider
	}
	pl := pathlabel.NewResolver(cfg.Provider, cfg.Budget, logger)
	testingAuthority := cfg.TestingAuthority
	if testingAuthority == "" {
		testingAuthority = policy.AuthorityActive
	}
	policyScope := cfg.PolicyScope
	if len(policyScope) == 0 {
		policyScope = policyOrigins(cfg.Target, scope)
	}
	executionPolicy, policyErr := policy.New(testingAuthority, policyScope)
	return &Orchestrator{
		bus:                    NewBus(logger),
		state:                  NewSharedState(cfg.Target),
		db:                     db,
		browser:                ctrl,
		scanID:                 cfg.ScanID,
		target:                 cfg.Target,
		scope:                  scope,
		logger:                 logger,
		provider:               cfg.Provider,
		reasoningProvider:      reasoningProv,
		budget:                 cfg.Budget,
		interactor:             cfg.Interactor,
		testingAuthority:       testingAuthority,
		executionPolicy:        executionPolicy,
		policyErr:              policyErr,
		policyAuditCount:       make(map[string]int),
		strategistProvider:     stratProv,
		strategistPeriod:       cfg.StrategistPeriod,
		authAlreadyConfigured:  cfg.AuthAlreadyConfigured,
		authLoginURL:           cfg.AuthLoginURL,
		authLoginUser:          cfg.AuthLoginUser,
		authLoginPass:          cfg.AuthLoginPass,
		bolaPersonas:           cfg.BOLAPersonas,
		maxDepth:               cfg.MaxDepth,
		maxPages:               cfg.MaxPages,
		seedURLs:               append([]string(nil), cfg.SeedURLs...),
		analysisEndpointLimit:  cfg.AnalysisEndpointLimit,
		finalConvergenceRounds: defaultFinalConvergenceRounds,
		finalConvergenceBudget: defaultFinalConvergenceBudget,
		finalExplorerBudget:    defaultFinalExplorerBudget,
		pathLabel:              pl,
		semanticSaturation:     NewSemanticSaturationState(),
	}
}

// PathLabel exposes the orchestrator's resolver. Used by tests + by
// the CLI when it needs to seed vocabulary from a previous scan of
// the same host (future feature).
func (o *Orchestrator) PathLabel() pathlabel.Resolver { return o.pathLabel }

// TestingAuthority exposes the operator-selected profile for Day 3B agent
// wiring without requiring agents to re-read persisted configuration.
func (o *Orchestrator) TestingAuthority() policy.TestingAuthority { return o.testingAuthority }

func (o *Orchestrator) newAnalyzerAgent() *AnalyzerAgent {
	return o.newAnalyzerAgentWithLimit(o.analysisEndpointLimit)
}

func (o *Orchestrator) newPostExplorerAnalyzerAgent() *AnalyzerAgent {
	limit := postExplorerAnalysisEndpointLimit(o.analysisEndpointLimit)
	if o.testingAuthority == policy.AuthorityRecon {
		limit = reconFocusedAnalysisEndpointLimit(limit, o.maxPages)
	}
	return o.newAnalyzerAgentWithLimit(limit)
}

func (o *Orchestrator) newReconFollowUpAnalyzerAgent() *AnalyzerAgent {
	limit := postExplorerAnalysisEndpointLimit(o.analysisEndpointLimit)
	if o.testingAuthority == policy.AuthorityRecon {
		limit = reconFollowUpAnalysisEndpointLimit(limit, o.maxPages)
	}
	return o.newAnalyzerAgentWithLimit(limit)
}

func (o *Orchestrator) newAnalyzerAgentWithLimit(limit int) *AnalyzerAgent {
	analyzer := NewAnalyzerAgent(o.db, o.provider, o.budget, o.bus, o.state, o.scanID, o.pathLabel, o.logger)
	analyzer.SetMaxEndpoints(limit)
	if o.testingAuthority == policy.AuthorityRecon {
		analyzer.SetAppSummaryEnabled(false)
	}
	return analyzer
}

func postExplorerAnalysisEndpointLimit(initial int) int {
	if initial <= 0 {
		return 0
	}
	if initial <= 6 {
		return initial
	}
	return 6
}

func reconFocusedAnalysisEndpointLimit(limit, maxPages int) int {
	if limit <= 0 {
		return limit
	}
	if maxPages > 0 && maxPages <= 3 && limit > 4 {
		return 4
	}
	return limit
}

func reconFollowUpAnalysisEndpointLimit(limit, maxPages int) int {
	if limit <= 0 {
		return limit
	}
	if maxPages > 0 && maxPages <= 3 && limit > 2 {
		return 2
	}
	return limit
}

func reconPrimaryNavigationStepLimit(maxPages int) int {
	if maxPages > 0 && maxPages <= 3 {
		return 3
	}
	return 6
}

func earlyNavigationStepLimit(authority policy.TestingAuthority, maxPages int) int {
	if authority == policy.AuthorityRecon && maxPages > 0 && maxPages <= 3 {
		return 4
	}
	return 8
}

// reconFollowUpNavigationStepLimit keeps the second objective pass materially
// shorter than the first one. The follow-up exists to close one or two newly
// exposed knowledge gaps, not to repeat a full six-step tour.
func reconFollowUpNavigationStepLimit(initial int) int {
	if initial <= 0 {
		return 0
	}
	if initial <= 2 {
		return initial
	}
	return 2
}
func policyOrigins(target string, legacyScope []string) []string {
	origins := []string{target}
	targetURL, err := url.Parse(target)
	if err != nil || targetURL.Scheme == "" || targetURL.Host == "" {
		return origins
	}
	for _, raw := range legacyScope {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.EqualFold(raw, targetURL.Host) || strings.EqualFold(raw, targetURL.Hostname()) {
			continue
		}
		if strings.Contains(raw, "://") {
			origins = append(origins, raw)
			continue
		}
		host := raw
		if parsedHost, parseErr := url.Parse("//" + raw); parseErr == nil && parsedHost.Port() == "" && targetURL.Port() != "" {
			host = parsedHost.Hostname() + ":" + targetURL.Port()
		}
		origins = append(origins, targetURL.Scheme+"://"+host)
	}
	return origins
}

func (o *Orchestrator) auditPolicyDenial(decision policy.Decision) {
	if decision.Allowed {
		return
	}
	key := strings.Join([]string{string(decision.Code), decision.CanonicalOrigin, decision.Reason}, "|")
	o.policyAuditMu.Lock()
	o.policyAuditCount[key]++
	count := o.policyAuditCount[key]
	o.policyAuditMu.Unlock()
	if count != 1 && count != 10 && count != 50 {
		return
	}
	_, _ = o.db.InsertNarration(o.scanID, "policy", "denied",
		decision.Reason, decision.TargetURL, map[string]any{
			"code":              decision.Code,
			"testing_authority": decision.Authority,
			"canonical_origin":  decision.CanonicalOrigin,
			"classes":           decision.Classes,
			"occurrence_count":  count,
		})
}

func shouldRunActiveVerification(authority policy.TestingAuthority) bool {
	return authority != policy.AuthorityRecon
}

func shouldRunExplorerFollowUps(authority policy.TestingAuthority) bool {
	return authority != policy.AuthorityRecon
}

func shouldRunInteractiveAuthentication(authority policy.TestingAuthority) bool {
	return authority != policy.AuthorityRecon
}

const maxPreCrawlSeedDiscoveries = 250

func (o *Orchestrator) visitSeedURLs(ctx context.Context) {
	if o == nil || o.browser == nil || len(o.seedURLs) == 0 {
		return
	}
	seen := map[string]struct{}{}
	queued := map[string]struct{}{}
	queue := make([]string, 0, len(o.seedURLs))
	for _, raw := range o.seedURLs {
		seed := resolveSeedURL(o.target, raw)
		if seed == "" {
			continue
		}
		if _, ok := queued[seed]; ok {
			continue
		}
		queued[seed] = struct{}{}
		queue = append(queue, seed)
	}
	visited := 0
	discovered := 0
	for i := 0; i < len(queue); i++ {
		if ctx.Err() != nil {
			return
		}
		seed := queue[i]
		if _, ok := seen[seed]; ok {
			continue
		}
		seen[seed] = struct{}{}
		decision := o.executionPolicy.Authorize(policy.Action{TargetURL: seed, Method: "GET"})
		if !decision.Allowed {
			o.auditPolicyDenial(decision)
			o.logger.Warn("seed URL denied by policy", "url", seed, "reason", decision.Reason)
			continue
		}
		o.db.InsertNarration(o.scanID, "orchestrator", "seed_url",
			fmt.Sprintf("Pre-crawl seed visit: %s", seed), seed, nil)
		page, err := o.browser.Navigate(ctx, seed)
		if page != nil {
			htmlText, bodyText := seedDocumentText(page)
			for _, link := range browser.ExtractDocumentDiscoveredLinks(seed, htmlText, bodyText, maxPreCrawlSeedDiscoveries-discovered) {
				if discovered >= maxPreCrawlSeedDiscoveries {
					break
				}
				if _, ok := seen[link]; ok {
					continue
				}
				if _, ok := queued[link]; ok {
					continue
				}
				decision := o.executionPolicy.Authorize(policy.Action{TargetURL: link, Method: "GET"})
				if !decision.Allowed {
					o.auditPolicyDenial(decision)
					continue
				}
				queued[link] = struct{}{}
				queue = append(queue, link)
				discovered++
			}
			_ = page.Close()
		}
		if err != nil {
			o.logger.Warn("seed URL visit failed", "url", seed, "error", err)
			continue
		}
		visited++
	}
	if visited > 0 {
		o.logger.Info("seed URLs visited", "count", visited, "discovered", discovered)
		o.db.InsertNarration(o.scanID, "orchestrator", "seed_urls_complete",
			fmt.Sprintf("Visited %d pre-crawl seed URL(s) so known specs or high-value entrypoints enter the normal analysis pipeline.", visited),
			o.target, map[string]any{"count": visited, "discovered": discovered})
	}
}

func seedDocumentText(page *rod.Page) (string, string) {
	if page == nil {
		return "", ""
	}
	evalText := func(js string) string {
		result, err := page.Timeout(1500 * time.Millisecond).Eval(js)
		if err != nil || result == nil {
			return ""
		}
		return result.Value.String()
	}
	htmlText := evalText(`() => document.documentElement ? (document.documentElement.outerHTML || '') : ''`)
	bodyText := evalText(`() => document.body ? (document.body.textContent || '') : ''`)
	return htmlText, bodyText
}

func resolveSeedURL(baseTarget, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		if u, err := url.Parse(raw); err == nil && u.Scheme != "" && u.Host != "" {
			return u.String()
		}
		return ""
	}
	base, err := url.Parse(baseTarget)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return ""
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return base.ResolveReference(ref).String()
}

// Run executes the full scan pipeline.
func (o *Orchestrator) Run(ctx context.Context) error {
	if o.policyErr != nil {
		return fmt.Errorf("execution policy: %w", o.policyErr)
	}
	o.logger.Info("orchestrator starting",
		"target", o.target,
		"scope", o.scope,
		"testing_authority", o.testingAuthority,
		"max_depth", o.maxDepth,
		"max_pages", o.maxPages,
	)

	o.db.InsertNarration(o.scanID, "orchestrator", "start",
		fmt.Sprintf("Kicking off a scan against %s — up to %d pages, depth %d. Let's see what we're dealing with.",
			o.target, o.maxPages, o.maxDepth),
		o.target, map[string]any{"testing_authority": o.testingAuthority})

	// Long-lived planner/drainer workers get their own lifetime. They are
	// stopped and awaited before the terminal convergence pass takes exclusive
	// ownership of the queue, so completion cannot race a half-finished plan or
	// a follow-up that was just popped by the background Explorer.
	backgroundCtx, cancelBackground := context.WithCancel(ctx)
	explorerStop := make(chan struct{})
	var backgroundWG sync.WaitGroup
	var stopBackgroundOnce sync.Once
	stopBackground := func() {
		stopBackgroundOnce.Do(func() {
			// Explorer stops gracefully between drain passes. The planner and
			// primer are safe to cancel immediately because they never claim
			// queue rows before doing work.
			close(explorerStop)
			cancelBackground()
			backgroundWG.Wait()
		})
	}
	defer stopBackground()

	// Start periodic browser-frame capture so the Live view has something to show.
	if o.browser != nil {
		// Browser observability follows the scan/browser lifetime, not the
		// planner-worker lifetime. Recon Copilot, verification, reasoners, and
		// convergence may all drive the same browser after background planning is
		// intentionally stopped.
		frameCapture := o.browser.StartFrameCapture(ctx, o.scanID, o.db.Path())
		if frameCapture != nil {
			// Join on every return path (success, no-surface, convergence error,
			// or cancellation) so the final manifest cannot be left claiming an
			// active session after the scanner process exits.
			defer frameCapture.Stop()
		}
	}

	// Path-label vocabulary primer. Polls captured traffic every 8s; as
	// soon as a host has crossed the priming threshold (~20 distinct
	// paths) it fires one richer LLM call to learn the site's URL
	// conventions and seeds the resolver's vocabulary cache. Subsequent
	// label calls for that host carry the vocabulary in their prompt
	// and produce dramatically more consistent labels.
	//
	// One-shot per host. No-op when no LLM provider is configured.
	if o.provider != nil {
		backgroundWG.Add(1)
		go func() {
			defer backgroundWG.Done()
			o.runVocabularyPrimer(backgroundCtx)
		}()
	}

	// Sovereign Strategist — runs as a background goroutine alongside the
	// phase pipeline. Plans in short bursts every few minutes; emits
	// directives into the follow_ups queue that Explorer picks up.
	// Only started if the user configured a period AND a provider.
	if o.strategistPeriod > 0 && o.strategistProvider != nil {
		o.strategist = NewStrategistAgent(o.db, o.scanID, o.strategistProvider, o.budget,
			StrategistConfig{Period: o.strategistPeriod, PlanOnly: o.testingAuthority == policy.AuthorityRecon}, o.logger)
		strategistMessage := fmt.Sprintf("Sovereign Strategist active (%s every %s). It will plan while the crawler works.",
			o.strategistProvider.ModelInfo().Name, o.strategistPeriod)
		if o.testingAuthority == policy.AuthorityRecon {
			strategistMessage = fmt.Sprintf("Sovereign Strategist uses phase-boundary Recon planning (%s). It will summarize grounded hypotheses after analysis and at final synthesis without competing with target modeling.",
				o.strategistProvider.ModelInfo().Name)
		}
		if o.testingAuthority != policy.AuthorityRecon && o.strategistProvider.Name() == "ollama" {
			strategistMessage = fmt.Sprintf("Sovereign Strategist active (%s at phase boundaries). Local planning is serialized so it does not starve endpoint analysis.",
				o.strategistProvider.ModelInfo().Name)
		}
		o.db.InsertNarration(o.scanID, "orchestrator", "strategist_start", strategistMessage, o.target, nil)
		if shouldRunPeriodicStrategist(o.testingAuthority) {
			backgroundWG.Add(1)
			go func() {
				defer backgroundWG.Done()
				if err := o.strategist.Run(backgroundCtx); err != nil {
					o.logger.Warn("strategist exited", "error", err)
				}
			}()
		}

		// Persistent Explorer — drains the follow_ups queue continuously
		// during the scan instead of waiting for Phase: Explorer. The
		// Strategist typically emits ~100-400 directives per scan; the
		// old phase-gated Explorer only touched ~10% of them. The BG
		// Explorer picks up new directives within 15s of emission.
		//
		// Phase 3.5 (Explorer) still runs for final drain and to handle
		// analyzer-emitted follow-ups; this is additive, not replacement.
		if shouldRunExplorerFollowUps(o.testingAuthority) {
			bgExplorer := NewExplorerAgent(o.db, o.scanID, o.provider, o.budget,
				o.executionPolicy, o.target, o.auditPolicyDenial, o.logger)
			backgroundWG.Add(1)
			go func() {
				defer backgroundWG.Done()
				bgExplorer.PersistentRunUntil(ctx, explorerStop, 15*time.Second)
			}()
			o.db.InsertNarration(o.scanID, "orchestrator", "explorer_bg_start",
				"Explorer background drainer active — directives execute within ~15s of emission instead of waiting for Phase: Explorer.",
				o.target, nil)
		} else {
			o.db.InsertNarration(o.scanID, "orchestrator", "explorer_bg_skipped",
				"Recon Only: Explorer follow-up execution is disabled; generated hypotheses are recorded but not probed.",
				o.target, map[string]any{"testing_authority": o.testingAuthority})
		}
	}

	o.visitSeedURLs(ctx)

	// Phase 1: Discovery — crawl the site
	o.state.SetPhase(PhaseDiscovery)
	o.logger.Info("=== Phase: Discovery ===")
	o.db.InsertNarration(o.scanID, "orchestrator", "phase",
		"Phase 1: Discovery — crawling the target to map out pages, forms, and API calls.",
		o.target, nil)

	if err := o.runDiscovery(ctx); err != nil {
		if ctx.Err() != nil {
			o.logger.Info("scan interrupted during discovery")
		} else {
			return fmt.Errorf("discovery: %w", err)
		}
	}

	// Mark out-of-scope traffic as filtered BEFORE dedup/scoring so the
	// Analyzer never spends tokens on third-party hosts we're not
	// authorized to test. This is the structural fix for the 33across
	// false-positive class — an ad beacon that happened to respond 302
	// was getting analyzed as if it were a target endpoint. The Strategist
	// can still see 3rd-party stats via a separate (is_filtered-aware)
	// query in the world model builder.
	if n, err := o.db.MarkOutOfScopeFiltered(o.scanID, o.scope); err != nil {
		o.logger.Warn("scope filter error", "error", err)
	} else if n > 0 {
		o.logger.Info("marked out-of-scope traffic as filtered",
			"rows", n, "scope", o.scope)
	}
	if stats, statsErr := o.db.GetTrafficStats(o.scanID); statsErr != nil {
		o.logger.Warn("post-discovery traffic stats error", "error", statsErr)
	} else if stats.UniqueEndpoints == 0 {
		message := "Discovery produced no in-scope endpoints. Check the reachable start URL, redirect destination, and scope rules; later analysis and generic verification were skipped."
		o.db.InsertNarration(o.scanID, "orchestrator", "no_surface", message, o.target,
			map[string]any{"traffic_total": stats.Total, "traffic_filtered": stats.Filtered})
		return &NoSurfaceError{Target: o.target, TrafficTotal: stats.Total, Filtered: stats.Filtered}
	}

	// Run deduplication on captured traffic
	o.logger.Info("running deduplication...")
	dedup := filter.NewDeduplicator(o.db, o.logger)
	dupCount, err := dedup.Run(o.scanID)
	if err != nil {
		o.logger.Warn("dedup error", "error", err)
	} else {
		o.logger.Info("deduplication done", "duplicates", dupCount)
	}

	// Run relevance scoring
	o.logger.Info("running relevance scoring...")
	scorer := filter.NewRelevanceScorer(o.db, o.logger)
	scored, err := scorer.Run(o.scanID)
	if err != nil {
		o.logger.Warn("scoring error", "error", err)
	} else {
		o.logger.Info("scoring done", "scored", scored)
	}

	if summary, err := scorer.Summary(o.scanID); err == nil {
		o.logger.Info(summary)
	}

	// Phase 2: Recon — analyze headers and fingerprint tech stack
	o.logger.Info("=== Phase: Recon ===")

	reconAgent := NewReconAgent(o.db, o.bus, o.state, o.scanID, o.logger)
	if err := reconAgent.Start(ctx); err != nil {
		o.logger.Warn("recon error", "error", err)
	}

	// Store discovered endpoints in DB
	o.persistEndpoints()

	// Phase 2.5: JS Analysis — extract hidden API and UI routes from
	// JavaScript. Regex extraction is deterministic and free, so it should run
	// even when no LLM provider is configured; the provider only adds an
	// optional semantic pass for complex dynamic construction.
	o.logger.Info("=== Phase: JS Analysis ===")
	jsAnalyzer := NewJSAnalyzer(o.db, o.provider, o.budget, o.bus, o.state, o.scanID, o.logger)
	if err := jsAnalyzer.Start(ctx); err != nil && ctx.Err() == nil {
		o.logger.Warn("JS analysis error", "error", err)
	}
	o.runJSRoutePrimer(ctx)
	if _, err := o.db.MarkOutOfScopeFiltered(o.scanID, o.scope); err != nil {
		o.logger.Warn("post-SPA-primer scope filter error", "error", err)
	}
	if _, err := filter.NewDeduplicator(o.db, o.logger).Run(o.scanID); err != nil {
		o.logger.Warn("post-SPA-primer dedup error", "error", err)
	}
	if _, err := filter.NewRelevanceScorer(o.db, o.logger).Run(o.scanID); err != nil {
		o.logger.Warn("post-SPA-primer scoring error", "error", err)
	}

	// Phase 2.6: Attack Surface Mapping
	o.logger.Info("=== Phase: Attack Surface Mapping ===")
	surfaceMapper := NewSurfaceMapper(o.db, o.bus, o.state, o.scanID, o.logger)
	if err := surfaceMapper.Start(ctx); err != nil && ctx.Err() == nil {
		o.logger.Warn("surface mapping error", "error", err)
	}

	// Phase 2.7: Interactive UI Tour. Run this before the slower endpoint-by-
	// endpoint LLM analysis so operators can watch the browser explore while
	// the scan is still visually active. The Navigator deliberately samples
	// distinct workflows and page types; it does not click every repeated card
	// or activate destructive/financial controls.
	var earlyNavigationTargets []string
	var earlyObservedNavigationTargets []string
	if o.provider != nil && ctx.Err() == nil && o.budget.Level() != llm.BudgetExhausted {
		o.state.SetPhase(PhaseDeepCrawl)
		o.logger.Info("=== Phase: Interactive UI Tour ===")
		o.db.InsertNarration(o.scanID, "orchestrator", "phase",
			"Phase 2.7: Interactive UI Tour — opening the application and exercising representative safe controls before the long analysis pass.",
			o.target, nil)
		uiTour := NewNavigatorAgent(o.browser, o.provider, o.budget, o.bus, o.state, o.db, o.scanID, o.interactor, o.testingAuthority, o.logger)
		uiTour.SetSemanticSaturation(o.semanticSaturation)
		uiTour.SetExecutionPolicy(o.executionPolicy, o.auditPolicyDenial)
		uiTour.SetMaxSteps(earlyNavigationStepLimit(o.testingAuthority, o.maxPages))
		if err := uiTour.Start(ctx); err != nil && ctx.Err() == nil {
			o.logger.Warn("interactive UI tour error", "error", err)
		}
		earlyNavigationTargets = uiTour.VisitedNavigationTargets()
		earlyObservedNavigationTargets = uiTour.ObservedNavigationTargets()

		// Fold requests triggered by the UI tour into the surface that the main
		// analyzer sees. This avoids paying for an analysis pass that predates the
		// most valuable browser interactions.
		o.db.MarkOutOfScopeFiltered(o.scanID, o.scope)
		filter.NewDeduplicator(o.db, o.logger).Run(o.scanID)
		filter.NewRelevanceScorer(o.db, o.logger).Run(o.scanID)
		o.persistEndpoints()
	}

	// Phase 3: LLM Analysis (if provider configured)
	reconFinalSynthesisDeferred := false
	if o.provider != nil {
		var reconFinalSummaryReservation *llm.BudgetReservation
		if o.testingAuthority == policy.AuthorityRecon && o.budget != nil {
			if reservation, ok := o.budget.Reserve(o.provider.ModelInfo().Name, 0, appSummaryTokenAllowance(o.provider)); ok {
				reconFinalSummaryReservation = reservation
				defer func() {
					if reconFinalSummaryReservation != nil {
						reconFinalSummaryReservation.Release()
					}
				}()
			} else {
				o.logger.Warn("could not reserve terminal Recon synthesis output")
			}
		}

		o.state.SetPhase(PhaseAnalysis)
		o.logger.Info("=== Phase: LLM Analysis ===")
		o.db.InsertNarration(o.scanID, "orchestrator", "phase",
			"Phase 3: LLM Analysis — reading captured traffic endpoint by endpoint, building an understanding of what each one does.",
			"", nil)

		analyzerAgent := o.newAnalyzerAgent()
		if err := analyzerAgent.Start(ctx); err != nil && ctx.Err() == nil {
			o.logger.Warn("analyzer error", "error", err)
		}

		// Print knowledge base stats
		if pStats, err := o.db.GetProfileStats(o.scanID); err == nil {
			o.logger.Info("knowledge base",
				"profiles", pStats.Total,
				"with_issues", pStats.WithIssues,
				"with_input", pStats.WithInput,
			)
		}
		o.logger.Info(o.budget.Summary())

		// Strategist gets a trigger now — there's new analyzer data it can
		// plan against. Cheaper than waiting for the next periodic timer.
		if o.strategist != nil {
			if o.testingAuthority == policy.AuthorityRecon || o.strategistProvider.Name() == "ollama" {
				if err := o.strategist.RunCycle(ctx, "post_analysis"); err != nil && ctx.Err() == nil {
					o.logger.Warn("phase-boundary strategist cycle failed", "error", err)
				}
			} else {
				o.strategist.Trigger("post_analysis")
			}
		}

		if shouldRunExplorerFollowUps(o.testingAuthority) {
			// Phase 3.5: Explorer — consume the follow-ups the analyzer queued.
			// This closes the loop: the LLM's "worth checking X" thoughts become
			// real HTTP requests, whose responses feed the next analyzer pass.
			o.logger.Info("=== Phase: Explorer ===")
			o.db.InsertNarration(o.scanID, "orchestrator", "phase",
				"Phase 3.5: Explorer — chasing down everything the analyzer flagged as worth investigating.",
				"", nil)
			explorer := NewExplorerAgent(o.db, o.scanID, o.provider, o.budget,
				o.executionPolicy, o.target, o.auditPolicyDenial, o.logger)
			if err := explorer.Start(ctx); err != nil && ctx.Err() == nil {
				o.logger.Warn("explorer error", "error", err)
			}

			// If Explorer generated new traffic, re-score + re-analyze so the
			// new findings flow into the knowledge base before auth/nav.
			o.logger.Info("post-explorer dedup + scoring...")
			o.db.MarkOutOfScopeFiltered(o.scanID, o.scope) // catch any 3rd-party traffic the Explorer pulled in
			dedupE := filter.NewDeduplicator(o.db, o.logger)
			dedupE.Run(o.scanID)
			scorerE := filter.NewRelevanceScorer(o.db, o.logger)
			scorerE.Run(o.scanID)

			analyzerPostExplorer := o.newPostExplorerAnalyzerAgent()
			analyzerPostExplorer.Start(ctx)
		} else {
			o.logger.Info("skipping Explorer follow-up execution for recon-only scan")
			o.db.InsertNarration(o.scanID, "orchestrator", "explorer_skipped",
				"Recon Only: Analyzer follow-ups were recorded but Explorer did not execute probe traffic.",
				"", map[string]any{"testing_authority": o.testingAuthority})
		}

		// Phase 4: Authentication
		o.state.SetPhase(PhaseAuth)
		o.logger.Info("=== Phase: Authentication ===")
		if !shouldRunInteractiveAuthentication(o.testingAuthority) {
			o.logger.Info("skipping interactive authentication for recon-only scan")
			o.db.InsertNarration(o.scanID, "orchestrator", "auth_boundary",
				"Recon Only: login and account boundaries were mapped, but no credentials were requested or submitted.",
				"", map[string]any{"testing_authority": o.testingAuthority})
		} else {
			o.db.InsertNarration(o.scanID, "orchestrator", "phase",
				"Phase 4: Authentication — checking whether the discovered application exposes a login workflow or can use supplied credentials.",
				"", nil)

			authAgent := NewAuthAgent(o.db, o.browser, o.provider, o.bus, o.state, o.scanID, o.interactor, o.logger)
			authAgent.SetBudget(o.budget)
			authAgent.SetCandidateLoginURLs(o.authLoginURL)
			if o.authLoginUser != "" && o.authLoginPass != "" {
				authAgent.SetCredentials(o.authLoginUser, o.authLoginPass, nil)
			}
			if err := authAgent.Start(ctx); err != nil && ctx.Err() == nil {
				o.logger.Warn("auth error", "error", err)
			}
		}

		// Phase 5: LLM-Guided Deep Crawl
		o.state.SetPhase(PhaseDeepCrawl)
		o.logger.Info("=== Phase: LLM-Guided Navigation ===")
		o.db.InsertNarration(o.scanID, "orchestrator", "phase",
			"Phase 5: Objective-led Navigation — revisiting the browser for focused gaps the first UI tour and analyzer left unresolved.",
			"", nil)

		reconPlanner := NewReconPlanner(o.db, o.scanID)
		reconObjectives, plannerErr := reconPlanner.Plan(3)
		if plannerErr != nil {
			o.logger.Warn("recon planner could not load objectives", "error", plannerErr)
		} else if len(reconObjectives) > 0 {
			o.db.InsertNarration(o.scanID, "recon-planner", "objectives",
				fmt.Sprintf("Deep navigation is targeting %d explicit knowledge gap(s): %s.", len(reconObjectives), reconObjectiveIDs(reconObjectives)),
				"", map[string]any{"objective_ids": reconObjectiveIDs(reconObjectives)})
		}
		profilesBeforeNavigation := 0
		if stats, err := o.db.GetProfileStats(o.scanID); err == nil {
			profilesBeforeNavigation = stats.Total
		}
		navAgent := NewNavigatorAgent(o.browser, o.provider, o.budget, o.bus, o.state, o.db, o.scanID, o.interactor, o.testingAuthority, o.logger)
		navAgent.SetSemanticSaturation(o.semanticSaturation)
		navAgent.SetExecutionPolicy(o.executionPolicy, o.auditPolicyDenial)
		navAgent.SetReconObjectives(reconObjectives)
		navAgent.SetAvoidNavigationTargets(earlyNavigationTargets)
		navAgent.SetObservedNavigationTargets(earlyObservedNavigationTargets)
		navAgent.SetMaxSteps(reconPrimaryNavigationStepLimit(o.maxPages))
		if err := navAgent.Start(ctx); err != nil && ctx.Err() == nil {
			o.logger.Warn("navigator error", "error", err)
		}
		visitedNavigationTargets := append([]string{}, earlyNavigationTargets...)
		visitedNavigationTargets = append(visitedNavigationTargets, navAgent.VisitedNavigationTargets()...)
		observedNavigationTargets := append([]string{}, earlyObservedNavigationTargets...)
		observedNavigationTargets = append(observedNavigationTargets, navAgent.ObservedNavigationTargets()...)

		// Run dedup + scoring again on newly discovered traffic
		o.logger.Info("running post-navigation dedup + scoring...")
		o.db.MarkOutOfScopeFiltered(o.scanID, o.scope) // LLM-guided nav may have followed links outside scope
		dedup2 := filter.NewDeduplicator(o.db, o.logger)
		dedup2.Run(o.scanID)
		scorer2 := filter.NewRelevanceScorer(o.db, o.logger)
		scorer2.Run(o.scanID)

		// Run analyzer again on new traffic
		o.logger.Info("=== Phase: Post-Navigation Analysis ===")
		analyzerAgent2 := o.newPostExplorerAnalyzerAgent()
		analyzerAgent2.Start(ctx)

		// One bounded feedback iteration: if objective-led navigation produced
		// new semantic profiles and important gaps remain, give Navigator a
		// shorter second pass with the refreshed objectives. This closes recon
		// gaps without creating an open-ended agent loop.
		profilesAfterNavigation := profilesBeforeNavigation
		if stats, err := o.db.GetProfileStats(o.scanID); err == nil {
			profilesAfterNavigation = stats.Total
		}
		refreshedObjectives, _ := reconPlanner.Plan(3)
		if profilesAfterNavigation > profilesBeforeNavigation && len(refreshedObjectives) > 0 && ctx.Err() == nil && o.budget.Level() != llm.BudgetExhausted {
			o.logger.Info("=== Phase: Recon Objective Follow-up ===", "new_profiles", profilesAfterNavigation-profilesBeforeNavigation, "objectives", len(refreshedObjectives))
			o.db.InsertNarration(o.scanID, "recon-planner", "iterate",
				fmt.Sprintf("Navigation added %d semantic profile(s); running one short follow-up pass against the remaining gaps.", profilesAfterNavigation-profilesBeforeNavigation),
				"", map[string]any{"objective_ids": reconObjectiveIDs(refreshedObjectives)})
			trafficBeforeFollowUp := o.scanTrafficCount()
			navFollowUp := NewNavigatorAgent(o.browser, o.provider, o.budget, o.bus, o.state, o.db, o.scanID, o.interactor, o.testingAuthority, o.logger)
			navFollowUp.SetSemanticSaturation(o.semanticSaturation)
			navFollowUp.SetExecutionPolicy(o.executionPolicy, o.auditPolicyDenial)
			navFollowUp.SetReconObjectives(refreshedObjectives)
			navFollowUp.SetAvoidNavigationTargets(visitedNavigationTargets)
			navFollowUp.SetObservedNavigationTargets(observedNavigationTargets)
			navFollowUp.SetMaxSteps(reconFollowUpNavigationStepLimit(6))
			if err := navFollowUp.Start(ctx); err != nil && ctx.Err() == nil {
				o.logger.Warn("recon follow-up navigation error", "error", err)
			}
			trafficAfterFollowUp := o.scanTrafficCount()
			if shouldAnalyzeReconFollowUp(trafficBeforeFollowUp, trafficAfterFollowUp) {
				o.db.MarkOutOfScopeFiltered(o.scanID, o.scope)
				filter.NewDeduplicator(o.db, o.logger).Run(o.scanID)
				filter.NewRelevanceScorer(o.db, o.logger).Run(o.scanID)
				o.newReconFollowUpAnalyzerAgent().Start(ctx)
			} else {
				o.db.InsertNarration(o.scanID, "recon-planner", "no_new_evidence",
					"The focused follow-up produced no new target traffic, so Recon skipped a redundant analysis pass.",
					"", nil)
			}
		}

		if o.testingAuthority == policy.AuthorityRecon && ctx.Err() == nil {
			if reconFinalSummaryReservation != nil {
				reconFinalSummaryReservation.Release()
				reconFinalSummaryReservation = nil
			}
			pendingCopilot, _ := o.pendingReconCopilotDirectiveCount()
			if shouldDeferReconFinalSynthesis(o.testingAuthority, pendingCopilot) {
				reconFinalSynthesisDeferred = true
				o.logger.Info("deferring final Recon synthesis until approved Copilot steering completes", "directives", pendingCopilot)
				o.db.InsertNarration(o.scanID, "orchestrator", "synthesis_deferred",
					"Final target synthesis is waiting for the already-approved Recon steering action, so the model is built once from the complete evidence set.",
					"", map[string]any{"pending_copilot_directives": pendingCopilot})
			} else {
				o.logger.Info("=== Phase: Final Recon Synthesis ===")
				o.db.InsertNarration(o.scanID, "orchestrator", "phase",
					"Final Recon Synthesis — combining the complete bounded evidence set into the application model.",
					"", nil)
				if err := o.newPostExplorerAnalyzerAgent().SynthesizeApp(ctx); err != nil && ctx.Err() == nil {
					o.logger.Warn("final Recon synthesis skipped", "error", err)
				}
			}
		}

		// Print knowledge base stats
		if pStats, err := o.db.GetProfileStats(o.scanID); err == nil {
			o.logger.Info("final knowledge base",
				"profiles", pStats.Total,
				"with_issues", pStats.WithIssues,
				"with_input", pStats.WithInput,
			)
		}
		o.logger.Info(o.budget.Summary())

	} else {
		o.logger.Info("no LLM provider configured, skipping analysis")
	}

	if !shouldRunActiveVerification(o.testingAuthority) {
		// Recon is deliberately passive. Verifier, reasoners, and convergence all
		// execute fresh probes, so scheduling them only creates policy-denial noise
		// and can never produce a recon-authorized proof.
		o.logger.Info("skipping active verification for recon-only scan")
		// Stop the background planner before taking ownership of the directive
		// queue. This gives Recon one deterministic terminal drain: Strategist may
		// record its final ideas, unsupported/active ideas are closed with an
		// honest hand-off, and operator-approved read-only Copilot steering runs.
		stopBackground()
		if o.strategist != nil {
			if err := o.strategist.RunCycle(ctx, "recon_final_model"); err != nil &&
				!errors.Is(err, ErrStrategistBudgetLimited) && ctx.Err() == nil {
				o.logger.Warn("final recon strategist cycle failed", "error", err)
			}
		}
		copilotSynthesisCompleted := false
		if processed, err := o.runReconCopilotDirectives(ctx); err != nil {
			o.logger.Warn("Recon Copilot directive drain incomplete", "error", err)
		} else if processed > 0 && ctx.Err() == nil {
			o.logger.Info("refreshing application model after Copilot steering", "directives", processed)
			if _, err := o.db.MarkOutOfScopeFiltered(o.scanID, o.scope); err != nil {
				o.logger.Warn("post-Copilot scope filter failed", "error", err)
			}
			if _, err := filter.NewDeduplicator(o.db, o.logger).Run(o.scanID); err != nil {
				o.logger.Warn("post-Copilot dedup failed", "error", err)
			}
			if _, err := filter.NewRelevanceScorer(o.db, o.logger).Run(o.scanID); err != nil {
				o.logger.Warn("post-Copilot relevance scoring failed", "error", err)
			}
			if o.provider != nil && (o.budget == nil || o.budget.Level() != llm.BudgetExhausted) {
				analyzer := o.newPostExplorerAnalyzerAgent()
				if err := analyzer.Start(ctx); err != nil && ctx.Err() == nil {
					o.logger.Warn("post-Copilot Analyzer failed", "error", err)
				}
				if err := analyzer.SynthesizeApp(ctx); err != nil && ctx.Err() == nil {
					o.logger.Warn("post-Copilot application synthesis failed", "error", err)
				} else if err == nil {
					copilotSynthesisCompleted = true
				}
			}
		}
		if reconFinalSynthesisDeferred && !copilotSynthesisCompleted && ctx.Err() == nil && o.provider != nil && (o.budget == nil || o.budget.Level() != llm.BudgetExhausted) {
			o.logger.Info("running deferred final Recon synthesis without a completed Copilot refresh")
			if err := o.newPostExplorerAnalyzerAgent().SynthesizeApp(ctx); err != nil && ctx.Err() == nil {
				o.logger.Warn("deferred final Recon synthesis failed", "error", err)
			}
		}
		// The post-Copilot Analyzer may generate fresh active follow-ups from the
		// newly captured page. Close those after the refresh as well so a Recon
		// scan can never finish with work it is not authorized to execute.
		if _, err := o.closeReconActiveFollowUps(); err != nil {
			o.logger.Warn("final Recon follow-up handoff failed", "error", err)
		}
		o.db.InsertNarration(o.scanID, "orchestrator", "verification_skipped",
			"Recon Only: active verification, reasoner execution, and attack-chain convergence were skipped by policy.",
			"", map[string]any{"testing_authority": o.testingAuthority})
	} else {
		// Phase 6: Verification — test flagged issues with real payloads.
		// Runs regardless of LLM presence: the Verifier's proactive-probe phase
		// is pure HTTP and requires no model.
		o.state.SetPhase(PhaseVerification)
		o.logger.Info("=== Phase: Verification ===")
		o.db.InsertNarration(o.scanID, "orchestrator", "phase",
			"Phase 6: Verification — time to actually test every issue the analyzer flagged. Real payloads, real responses.",
			"", nil)

		verifier := NewVerifierAgent(o.db, o.scanID, o.executionPolicy, o.target, o.auditPolicyDenial, o.logger)
		verifier.SetBrowser(o.browser)
		if err := verifier.Start(ctx); err != nil && ctx.Err() == nil {
			o.logger.Warn("verifier error", "error", err)
		}

		// Hand queue ownership over before domain reasoners start. The awaited
		// Strategist pass in final convergence still gets the final word.
		stopBackground()

		if o.provider != nil || len(o.bolaPersonas) >= 2 {
			o.runReasonerPhase(ctx)
		}

		if err := o.runFinalConvergence(ctx); err != nil {
			return err
		}
	}

	// Phase 7: Change Detection — diff against prior scans of the same target.
	// Runs regardless of LLM presence (hashing is free); LLM commentary is
	// skipped if no provider is configured.
	o.logger.Info("=== Phase: Change Detection ===")
	o.db.InsertNarration(o.scanID, "orchestrator", "phase",
		"Phase 7: Change Detection — diffing JS/HTML assets against the previous scan of this target to catch evolution.",
		"", nil)
	changeDetector := NewChangeDetector(o.db, o.scanID, o.target, o.provider, o.budget, o.logger)
	if err := changeDetector.Start(ctx); err != nil && ctx.Err() == nil {
		o.logger.Warn("change detector error", "error", err)
	}

	// Mark complete
	o.state.SetPhase(PhaseComplete)
	o.logger.Info("=== Scan Complete ===")
	o.db.InsertNarration(o.scanID, "orchestrator", "complete",
		"Scan complete. Check the findings tab for what made it past verification.",
		"", nil)

	model := o.state.ReadModel()
	o.printSummary(&model)

	return nil
}

func shouldRunPeriodicStrategist(authority policy.TestingAuthority) bool {
	return authority != policy.AuthorityRecon
}

func shouldDeferReconFinalSynthesis(authority policy.TestingAuthority, pendingCopilot int) bool {
	return authority == policy.AuthorityRecon && pendingCopilot > 0
}

func shouldAnalyzeReconFollowUp(beforeTraffic, afterTraffic int) bool {
	return afterTraffic > beforeTraffic
}

func (o *Orchestrator) scanTrafficCount() int {
	if o == nil || o.db == nil {
		return 0
	}
	var count int
	_ = o.db.Conn().QueryRow(`SELECT COUNT(*) FROM traffic WHERE scan_id=?`, o.scanID).Scan(&count)
	return count
}

func (o *Orchestrator) pendingReconCopilotDirectiveCount() (int, error) {
	if o == nil || o.db == nil {
		return 0, nil
	}
	var count int
	err := o.db.Conn().QueryRow(`
		SELECT COUNT(*) FROM follow_ups
		WHERE scan_id=? AND source_agent='copilot' AND status IN ('pending','running')`, o.scanID).Scan(&count)
	return count, err
}

// reconCopilotActionSupported is deliberately smaller than the global
// follow-up vocabulary. Recon steering may only add bounded, read-only
// evidence or ask the analyzer to reconsider evidence already captured.
func reconCopilotActionSupported(sourceAgent, action string) bool {
	if !strings.EqualFold(strings.TrimSpace(sourceAgent), "copilot") {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "fetch", "visit", "reanalyze":
		return true
	default:
		return false
	}
}

// runReconCopilotDirectives closes the UI approval loop while preserving the
// Recon authority ceiling. Every URL is re-authorized immediately before a
// GET-only browser visit, and provenance links captured traffic to the exact
// approved directive. No form submission or active probe vocabulary reaches
// this consumer.
func (o *Orchestrator) runReconCopilotDirectives(ctx context.Context) (int, error) {
	if o.testingAuthority != policy.AuthorityRecon || o.db == nil || o.browser == nil || o.executionPolicy == nil {
		return 0, nil
	}
	_, err := o.closeReconActiveFollowUps()
	if err != nil {
		return 0, err
	}

	tasks, err := o.db.ClaimFollowUps(o.scanID, 12, 5*time.Minute)
	if err != nil {
		return 0, err
	}
	processed := 0
	for _, task := range tasks {
		if ctx.Err() != nil {
			return processed, ctx.Err()
		}
		if !reconCopilotActionSupported(task.SourceAgent, task.Action) {
			_ = o.db.CompleteFollowUp(o.scanID, task.ID, task.LeaseToken, store.FollowUpSkipped,
				"Separate operator-authorized Active run required under the selected Recon authority.")
			continue
		}

		action := strings.ToLower(strings.TrimSpace(task.Action))
		if action == "reanalyze" {
			result, execErr := o.db.Conn().Exec(`
				UPDATE traffic
				SET is_ai_analyzed=FALSE, analysis_batch=0
				WHERE scan_id=? AND url=?`, o.scanID, strings.TrimSpace(task.URL))
			if execErr != nil {
				_ = o.db.CompleteFollowUp(o.scanID, task.ID, task.LeaseToken, store.FollowUpFailed, execErr.Error())
				continue
			}
			rows, _ := result.RowsAffected()
			if rows == 0 {
				_ = o.db.CompleteFollowUp(o.scanID, task.ID, task.LeaseToken, store.FollowUpFailed,
					"No captured traffic matched the approved profile URL.")
				continue
			}
			message := fmt.Sprintf("Queued %d captured request(s) for fresh analysis.", rows)
			if err := o.db.CompleteFollowUp(o.scanID, task.ID, task.LeaseToken, store.FollowUpDone, message); err != nil {
				return processed, err
			}
			processed++
			_, _ = o.db.InsertNarration(o.scanID, "copilot", "directive_complete", message, task.URL,
				map[string]any{"follow_up_id": task.ID, "action": action, "rows": rows})
			continue
		}

		decision := o.executionPolicy.Authorize(policy.Action{TargetURL: strings.TrimSpace(task.URL), Method: "GET"})
		if !decision.Allowed {
			o.auditPolicyDenial(decision)
			_ = o.db.CompleteFollowUp(o.scanID, task.ID, task.LeaseToken, store.FollowUpSkipped, decision.Reason)
			continue
		}
		cleanup := o.browser.BeginTrafficProvenance("copilot", task.ID, task.HypothesisID)
		var visitErr error
		if o.reconCopilotVisit != nil {
			visitErr = o.reconCopilotVisit(ctx, decision.TargetURL)
		} else {
			page, err := o.browser.Navigate(ctx, decision.TargetURL)
			visitErr = err
			if page != nil {
				_ = page.Close()
			}
		}
		cleanup()
		if visitErr != nil {
			_ = o.db.CompleteFollowUp(o.scanID, task.ID, task.LeaseToken, store.FollowUpFailed, visitErr.Error())
			continue
		}
		message := fmt.Sprintf("Completed approved read-only %s of %s.", strings.ToUpper(action), decision.TargetURL)
		if err := o.db.CompleteFollowUp(o.scanID, task.ID, task.LeaseToken, store.FollowUpDone, message); err != nil {
			return processed, err
		}
		processed++
		_, _ = o.db.InsertNarration(o.scanID, "copilot", "directive_complete", message, decision.TargetURL,
			map[string]any{"follow_up_id": task.ID, "action": action})
	}
	return processed, nil
}

func (o *Orchestrator) closeReconActiveFollowUps() (int64, error) {
	if o == nil || o.db == nil || o.testingAuthority != policy.AuthorityRecon {
		return 0, nil
	}
	skipped, err := o.db.SkipNonCopilotReconFollowUps(o.scanID)
	if err != nil {
		return 0, err
	}
	if skipped > 0 {
		_, _ = o.db.InsertNarration(o.scanID, "orchestrator", "directive_handoff",
			fmt.Sprintf("Closed %d active or unsupported follow-up(s); they require a separate operator-authorized Active run.", skipped),
			"", map[string]any{"skipped": skipped, "testing_authority": o.testingAuthority})
	}
	return skipped, nil
}

// ConvergenceError reports why the scan could not establish a truthful fixed
// point. The CLI maps it to an "incomplete" scan status instead of silently
// writing "completed" while queue work is still runnable.
type ConvergenceError struct {
	Reason  string
	Round   int
	Pending int
	Running int
}

// NoSurfaceError stops a scan before speculative phases when the browser did
// not produce any in-scope endpoint. Treating this as incomplete preserves the
// truthful audit trail without manufacturing generic probes against an invalid
// or unreachable host.
type NoSurfaceError struct {
	Target       string
	TrafficTotal int
	Filtered     int
}

func (e *NoSurfaceError) Error() string {
	return fmt.Sprintf("discovery produced no in-scope endpoints for %s (traffic=%d filtered=%d)",
		e.Target, e.TrafficTotal, e.Filtered)
}

func (e *ConvergenceError) Error() string {
	return fmt.Sprintf("final convergence stopped: %s (round=%d pending=%d running=%d)",
		e.Reason, e.Round, e.Pending, e.Running)
}

// runFinalConvergence closes the Strategist -> Explorer -> Analyzer ->
// Verifier feedback loop synchronously. A round is successful only when an
// awaited plan cycle leaves no pending/running directives. Any work produced
// by Explorer analysis or verification must therefore survive one more plan
// boundary before the scan can complete.
func (o *Orchestrator) runFinalConvergence(ctx context.Context) error {
	maxRounds := o.finalConvergenceRounds
	if maxRounds <= 0 {
		maxRounds = defaultFinalConvergenceRounds
	}
	maxDuration := o.finalConvergenceBudget
	if maxDuration <= 0 {
		maxDuration = defaultFinalConvergenceBudget
	}
	explorerBudget := o.finalExplorerBudget
	if explorerBudget <= 0 {
		explorerBudget = defaultFinalExplorerBudget
	}

	convergenceCtx, cancel := context.WithTimeout(ctx, maxDuration)
	defer cancel()

	o.logger.Info("=== Phase: Final Convergence ===",
		"max_rounds", maxRounds, "budget", maxDuration)
	o.db.InsertNarration(o.scanID, "orchestrator", "convergence_start",
		fmt.Sprintf("Final convergence: up to %d awaited planner/explorer/verifier round(s) within %s.",
			maxRounds, maxDuration),
		"", map[string]any{"max_rounds": maxRounds, "budget_seconds": maxDuration.Seconds()})

	limitReason := ""
	if o.provider != nil && o.budget != nil && o.budget.Level() == llm.BudgetExhausted {
		limitReason = "LLM budget was exhausted before final convergence"
	}

	for round := 1; round <= maxRounds; round++ {
		if err := convergenceCtx.Err(); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return o.convergenceStopped(round, "wall-clock convergence budget "+maxDuration.String()+" elapsed")
		}

		// The final Strategist cycle is deliberately direct and awaited. Once a
		// budget limit is observed we still drain already-runnable work, but do
		// not pretend another complete planning pass occurred.
		if o.strategist != nil && limitReason == "" {
			if err := o.strategist.RunCycle(convergenceCtx, fmt.Sprintf("final_convergence_%d", round)); err != nil {
				switch {
				case errors.Is(err, ErrStrategistBudgetLimited):
					limitReason = err.Error()
				case convergenceCtx.Err() != nil:
					if ctx.Err() != nil {
						return ctx.Err()
					}
					return o.convergenceStopped(round, "wall-clock convergence budget "+maxDuration.String()+" elapsed during Strategist cycle")
				default:
					return o.convergenceStopped(round, "awaited Strategist cycle failed: "+err.Error())
				}
			}
		}

		counts, err := o.db.CountFollowUpsByStatus(o.scanID)
		if err != nil {
			return o.convergenceStopped(round, "could not count follow-ups: "+err.Error())
		}
		pending := counts[store.FollowUpPending]
		running := counts[store.FollowUpRunning]

		if pending == 0 && running == 0 {
			if limitReason != "" {
				return o.convergenceStoppedWithCounts(round, limitReason, 0, 0)
			}
			o.db.InsertNarration(o.scanID, "orchestrator", "convergence_complete",
				fmt.Sprintf("Final convergence reached after %d round(s): no pending or running follow-ups remain after an awaited planning pass.", round),
				"", map[string]any{"round": round, "pending": 0, "running": 0})
			o.logger.Info("final convergence reached", "round", round)
			return nil
		}

		o.logger.Info("final convergence draining follow-ups",
			"round", round, "pending", pending, "running", running, "limit_reason", limitReason)
		explorer := NewExplorerAgent(o.db, o.scanID, o.provider, o.budget,
			o.executionPolicy, o.target, o.auditPolicyDenial, o.logger)
		explorer.maxPerPass = 100
		explorer.perPassBudget = explorerBudget
		if err := explorer.Start(convergenceCtx); err != nil {
			return o.convergenceStopped(round, "Explorer final drain failed: "+err.Error())
		}
		if err := convergenceCtx.Err(); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return o.convergenceStopped(round, "wall-clock convergence budget "+maxDuration.String()+" elapsed during Explorer drain")
		}
		postDrainCounts, err := o.db.CountFollowUpsByStatus(o.scanID)
		if err != nil {
			return o.convergenceStopped(round, "could not recount follow-ups after Explorer drain: "+err.Error())
		}
		// ClaimFollowUps reclaims expired and legacy running rows. If only
		// non-expired running leases remain after a foreground drain, no live
		// worker owns them now; report that exact terminal condition.
		if postDrainCounts[store.FollowUpPending] == 0 && postDrainCounts[store.FollowUpRunning] > 0 {
			return o.convergenceStoppedWithCounts(round,
				fmt.Sprintf("%d non-expired follow-up lease(s) remain running without a live worker",
					postDrainCounts[store.FollowUpRunning]),
				0, postDrainCounts[store.FollowUpRunning])
		}

		// Explorer observations become ordinary analyzer input before Verifier
		// gets another chance to act on any newly learned issue.
		if _, err := o.db.MarkOutOfScopeFiltered(o.scanID, o.scope); err != nil {
			o.logger.Warn("final convergence scope filter failed", "round", round, "error", err)
		}
		if _, err := filter.NewDeduplicator(o.db, o.logger).Run(o.scanID); err != nil {
			o.logger.Warn("final convergence dedup failed", "round", round, "error", err)
		}
		if _, err := filter.NewRelevanceScorer(o.db, o.logger).Run(o.scanID); err != nil {
			o.logger.Warn("final convergence scoring failed", "round", round, "error", err)
		}

		if o.provider != nil {
			if o.budget != nil && o.budget.Level() == llm.BudgetExhausted {
				limitReason = "LLM budget exhausted before Explorer observations could be fully analyzed"
			} else {
				analyzer := o.newPostExplorerAnalyzerAgent()
				if err := analyzer.Start(convergenceCtx); err != nil {
					return o.convergenceStopped(round, "post-Explorer Analyzer failed: "+err.Error())
				}
				if o.budget != nil && o.budget.Level() == llm.BudgetExhausted {
					limitReason = "LLM budget exhausted during final Analyzer pass"
				}
			}
		}

		finalVerifier := NewVerifierAgent(o.db, o.scanID, o.executionPolicy, o.target, o.auditPolicyDenial, o.logger)
		finalVerifier.SetBrowser(o.browser)
		finalVerifier.proactive = false
		if err := finalVerifier.Start(convergenceCtx); err != nil {
			return o.convergenceStopped(round, "final Verifier pass failed: "+err.Error())
		}
		if round == maxRounds {
			finalCounts, err := o.db.CountFollowUpsByStatus(o.scanID)
			if err != nil {
				return o.convergenceStopped(round, "could not recount follow-ups after final Verifier pass: "+err.Error())
			}
			pending := finalCounts[store.FollowUpPending]
			running := finalCounts[store.FollowUpRunning]
			if pending == 0 && running == 0 {
				o.db.InsertNarration(o.scanID, "orchestrator", "convergence_complete",
					fmt.Sprintf("Final convergence drained all follow-ups at the configured round limit (%d).", maxRounds),
					"", map[string]any{"round": round, "pending": 0, "running": 0, "max_rounds": maxRounds})
				o.logger.Info("final convergence reached at round limit", "round", round)
				return nil
			}
		}
	}

	return o.convergenceStopped(maxRounds,
		fmt.Sprintf("maximum convergence rounds (%d) reached before an empty awaited planning pass", maxRounds))
}

func (o *Orchestrator) convergenceStopped(round int, reason string) error {
	counts, err := o.db.CountFollowUpsByStatus(o.scanID)
	if err != nil {
		reason += "; follow-up recount failed: " + err.Error()
		return o.convergenceStoppedWithCounts(round, reason, -1, -1)
	}
	return o.convergenceStoppedWithCounts(round, reason,
		counts[store.FollowUpPending], counts[store.FollowUpRunning])
}

func (o *Orchestrator) convergenceStoppedWithCounts(round int, reason string, pending, running int) error {
	err := &ConvergenceError{Reason: reason, Round: round, Pending: pending, Running: running}
	o.logger.Warn("final convergence stopped",
		"reason", reason, "round", round, "pending", pending, "running", running)
	o.db.InsertNarration(o.scanID, "orchestrator", "convergence_stopped",
		err.Error(), "", map[string]any{
			"reason": reason, "round": round, "pending": pending, "running": running,
		})
	return err
}

func (o *Orchestrator) runDiscovery(ctx context.Context) error {
	crawlerAgent := NewCrawlerAgent(
		o.browser, o.bus, o.state,
		o.db, o.scanID,
		o.scope, o.maxDepth, o.maxPages,
		o.db.Path(),
		o.provider, o.budget,
		o.pathLabel,
		o.logger,
	)
	// Tell the crawler whether auth is already configured so it knows
	// whether to surface "login form found" notifications.
	crawlerAgent.SetAuthConfigured(o.authAlreadyConfigured)
	crawlerAgent.SetTestingAuthority(o.testingAuthority)
	crawlerAgent.SetSemanticSaturation(o.semanticSaturation)

	// Set up a timeout for the crawl phase
	crawlCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	return crawlerAgent.Start(crawlCtx)
}

func (o *Orchestrator) persistEndpoints() {
	model := o.state.ReadModel()
	for _, ep := range model.Endpoints {
		_, err := o.db.Conn().Exec(`
			INSERT INTO endpoints (id, scan_id, method, url_pattern, params_json, hit_count,
			                       has_params, has_input, is_api)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(scan_id, id) DO UPDATE SET
				hit_count = hit_count + 1,
				last_seen_at = datetime('now')`,
			ep.ID, o.scanID, ep.Method, ep.URLPattern,
			"[]", ep.HitCount,
			len(ep.Parameters) > 0,
			len(ep.Parameters) > 0,
			false,
		)
		if err != nil {
			o.logger.Debug("persist endpoint", "error", err)
		}
	}
}

func (o *Orchestrator) printSummary(model *types.AppModel) {
	fmt.Println()
	fmt.Println("=== AOBTD Scan Results ===")
	fmt.Printf("Target: %s\n", model.Target)
	fmt.Printf("Endpoints discovered: %d\n", len(model.Endpoints))

	if model.TechStack.Server != "" {
		fmt.Printf("\nTech Stack:\n")
		fmt.Printf("  Server:    %s\n", model.TechStack.Server)
	}
	if model.TechStack.Framework != "" {
		fmt.Printf("  Framework: %s\n", model.TechStack.Framework)
	}
	if model.TechStack.Language != "" {
		fmt.Printf("  Language:  %s\n", model.TechStack.Language)
	}
	if model.TechStack.CDN != "" {
		fmt.Printf("  CDN:       %s\n", model.TechStack.CDN)
	}
	if model.TechStack.WAF != "" {
		fmt.Printf("  WAF:       %s\n", model.TechStack.WAF)
	}
	if len(model.TechStack.JSLibraries) > 0 {
		fmt.Printf("  JS Libs:   %s\n", strings.Join(model.TechStack.JSLibraries, ", "))
	}

	findings, err := o.db.ListFindings(o.scanID)
	source := "persisted"
	if err != nil {
		o.logger.Warn("list persisted findings for summary failed", "error", err)
		findings = model.Findings
		source = "in-memory"
	}
	if len(findings) > 0 {
		confirmed := 0
		for _, f := range findings {
			if f.Confidence == types.ConfidenceConfirmed {
				confirmed++
			}
		}
		fmt.Printf("\nFindings: %d %s (%d confirmed)\n", len(findings), source, confirmed)
		const maxSummaryFindings = 20
		for i, f := range findings {
			if i >= maxSummaryFindings {
				fmt.Printf("  ... %d more findings in the UI/report\n", len(findings)-maxSummaryFindings)
				break
			}
			confidence := string(f.Confidence)
			if confidence == "" {
				confidence = "unknown"
			}
			fmt.Printf("  [%s/%s] %s\n", f.Severity, confidence, f.Title)
		}
	}

	fmt.Println()
}

// vocabPrimingThreshold is how many distinct URL paths a host needs
// before we spend an LLM call learning its URL conventions. Below this
// the priming pass would generalize from too little signal — most
// sites need 15-25 representative URLs to expose their conventions.
const vocabPrimingThreshold = 20

// vocabPrimingPollInterval is how often we re-check the per-host
// distinct-path counts. Tight enough that priming fires within a
// minute of a busy crawl reaching threshold, loose enough that the
// query cost is negligible (one indexed SELECT every 8s).
const vocabPrimingPollInterval = 8 * time.Second

// runVocabularyPrimer is the orchestrator's per-scan path-label
// vocabulary primer. Started once at scan launch (when a provider is
// configured), it polls the traffic table for distinct paths grouped
// by host and fires pathlabel.PrimeVocabulary once a host crosses the
// threshold. One-shot per host: once primed, that host is skipped on
// subsequent ticks.
//
// The actual PrimeVocabulary call is fired on its own goroutine so
// the primer's tick loop never blocks on the LLM. Errors are logged
// but never propagated — vocabulary is a labelling-quality multiplier,
// not a correctness requirement, and we don't want a transient LLM
// hiccup to take down the scan.
func (o *Orchestrator) runVocabularyPrimer(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			o.logger.Warn("vocabulary primer panic recovered", "err", r)
		}
	}()

	primed := map[string]bool{}
	ticker := time.NewTicker(vocabPrimingPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		sets, err := o.db.DistinctPathsByHost(o.scanID, 100)
		if err != nil {
			o.logger.Debug("vocab primer: distinct paths query failed", "error", err)
			continue
		}
		for _, set := range sets {
			// Traffic capture sees every browser request, including third-party
			// assets that may arrive before the first DB scope-filter pass. Never
			// send those paths to the vocabulary model merely because their
			// is_filtered flag has not been updated yet.
			if !hostMatchesScope(set.Host, o.scope) {
				continue
			}
			if primed[set.Host] {
				continue
			}
			if len(set.Paths) < vocabPrimingThreshold {
				continue
			}
			primed[set.Host] = true
			host := set.Host
			paths := set.Paths
			go func() {
				v, err := o.pathLabel.PrimeVocabulary(ctx, host, paths)
				if err != nil {
					o.logger.Info("vocab priming skipped", "host", host, "error", err)
					return
				}
				o.logger.Info("vocab primed",
					"host", host,
					"site_type", v.SiteType,
					"bff_prefixes", len(v.StableBFFPrefixes),
					"position_patterns", len(v.PositionPatterns),
				)
				// Surface the priming as a narration so the operator
				// sees AOBTD learning the site shape — same pane the
				// Strategist's "I'm learning X" lines appear in.
				summary := v.SiteType
				if summary == "" {
					summary = fmt.Sprintf("%d service prefixes, %d position patterns",
						len(v.StableBFFPrefixes), len(v.PositionPatterns))
				}
				o.db.InsertNarration(o.scanID, "orchestrator", "vocab_primed",
					fmt.Sprintf("Learned URL conventions for %s — %s. Subsequent path labels will use this vocabulary.",
						host, summary),
					"", map[string]any{
						"host":              host,
						"site_type":         v.SiteType,
						"bff_prefixes":      v.StableBFFPrefixes,
						"position_patterns": len(v.PositionPatterns),
					})
			}()
		}
	}
}

func hostMatchesScope(hostPort string, allowedHosts []string) bool {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostPort), "."))
	if parsed, err := url.Parse("//" + hostPort); err == nil && parsed.Hostname() != "" {
		host = strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	}
	for _, allowed := range allowedHosts {
		allowed = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(allowed), "."))
		if parsed, err := url.Parse("//" + allowed); err == nil && parsed.Hostname() != "" {
			allowed = strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
		}
		if allowed != "" && (host == allowed || strings.HasSuffix(host, "."+allowed)) {
			return true
		}
	}
	return false
}

// State returns the shared state for external access.
func (o *Orchestrator) State() *SharedState {
	return o.state
}

// Bus returns the event bus for external subscription.
func (o *Orchestrator) Bus() *Bus {
	return o.bus
}
