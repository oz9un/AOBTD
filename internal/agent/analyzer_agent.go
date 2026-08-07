package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/internal/llm"
	"github.com/ozzyw/aobtd/internal/llm/prompts"
	"github.com/ozzyw/aobtd/internal/observation"
	"github.com/ozzyw/aobtd/internal/pathlabel"
	"github.com/ozzyw/aobtd/internal/policy"
	"github.com/ozzyw/aobtd/internal/protection"
	"github.com/ozzyw/aobtd/internal/reconprojection"
	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

// AnalyzerAgent uses an LLM to analyze captured traffic and build the knowledge base.
// It works endpoint-by-endpoint (not random batches) and builds an evolving
// understanding of the application.
type AnalyzerAgent struct {
	db       *store.DB
	provider llm.Provider
	budget   *llm.Budget
	bus      *Bus
	state    *SharedState
	scanID   int64
	logger   *slog.Logger

	understanding *extract.AppUnderstanding

	// pathLabel is the shared resolver. The analyzer routes URL-pattern
	// labelling through it instead of running its own bespoke
	// refinement pass — same cache the crawler uses, so the same
	// pattern never costs two LLM calls site-wide.
	pathLabel pathlabel.Resolver

	// analysisFingerprints tracks endpoint families that already had a deep
	// analysis pass. Final convergence often generates several concrete
	// values for the same route family (for example /orders/1, /orders/-1,
	// /orders/999999). The evidence stays in traffic, but an identical
	// analysis fingerprint should not buy another LLM call.
	analysisFingerprints map[string]string

	// templateFingerprints is a looser cache for template verification. When
	// an endpoint already matches a known template, a different follow-up
	// source alone is not enough reason to spend another verification call;
	// meaningful deltas are still captured by status, input, schema, flags,
	// content type, method and canonical path.
	templateFingerprints map[string]string

	// protectionShapes remembers response-backed WAF/browser challenge shapes
	// separately from application route families. The first shape is retained
	// as a grounded protection specimen; equivalent mechanics on other routes
	// are compacted without hiding a changed challenge or recovered app page.
	protectionShapes map[string]string

	// maxEndpoints bounds the number of endpoint families this Analyzer pass
	// will spend LLM budget on. Zero means unlimited. Benchmark runs can use a
	// small cap to reach Explorer/Verifier before documentation/login tails
	// consume the whole hosted-model token budget.
	maxEndpoints int

	// appSummaryEnabled controls whether this endpoint pass also spends the
	// terminal semantic-synthesis call. Recon scans defer that one expensive
	// call until all bounded navigation is complete.
	appSummaryEnabled bool
}

type appSummarySynthesis struct {
	AppType             string                      `json:"app_type"`
	Summary             string                      `json:"summary"`
	HighPriorityAreas   []string                    `json:"high_priority_areas"`
	Roles               []extract.ReconRole         `json:"roles"`
	Objects             []extract.BusinessObject    `json:"objects"`
	Workflows           []extract.BusinessWorkflow  `json:"workflows"`
	OwnershipBoundaries []extract.OwnershipBoundary `json:"ownership_boundaries"`
	Unknowns            []extract.ReconUnknown      `json:"unknowns"`
}

// Keep enough output room for the one scan-level semantic synthesis after
// endpoint analysis. A complete compact model is more valuable to Recon than
// spending the last tokens on one additional endpoint profile.
const appSummaryMaxTokens = 6144

// Re-rank a bounded captured-candidate window after every small analysis batch.
// Five profiles are enough to refresh the deterministic Recon targets, so an
// eight-item batch gives the scanner frequent learning checkpoints without
// turning queue reads into per-endpoint database churn. Five hundred families
// covers the largest saved public backlogs while remaining an explicit ceiling.
const (
	AnalysisCandidateWindowSize = 500
	AnalysisLearningBatchSize   = 8
)

// NewAnalyzerAgent creates an analyzer agent. pathLabel may be nil —
// in that case the analyzer falls back to whatever URLPattern the
// bundle was built with (corpus-aligned regex template). Pass a real
// Resolver to get LLM-labelled patterns in narrations / Endpoints.
func NewAnalyzerAgent(
	db *store.DB,
	provider llm.Provider,
	budget *llm.Budget,
	bus *Bus,
	state *SharedState,
	scanID int64,
	pathLabel pathlabel.Resolver,
	logger *slog.Logger,
) *AnalyzerAgent {
	return &AnalyzerAgent{
		db:                db,
		provider:          provider,
		budget:            budget,
		bus:               bus,
		state:             state,
		scanID:            scanID,
		logger:            logger,
		pathLabel:         pathLabel,
		appSummaryEnabled: true,
	}
}

func (a *AnalyzerAgent) Name() string { return "analyzer" }

func (a *AnalyzerAgent) Capabilities() []EventType {
	return []EventType{EventTrafficCaptured}
}

func (a *AnalyzerAgent) SetMaxEndpoints(limit int) {
	if limit < 0 {
		limit = 0
	}
	a.maxEndpoints = limit
}

func (a *AnalyzerAgent) SetAppSummaryEnabled(enabled bool) {
	a.appSummaryEnabled = enabled
}

// Start runs the endpoint-based analysis loop.
func (a *AnalyzerAgent) Start(ctx context.Context) error {
	a.logger.Info("analyzer agent starting",
		"provider", a.provider.Name(),
		"model", a.provider.ModelInfo().Name,
	)

	// Load existing app understanding from DB
	a.loadUnderstanding()
	a.loadAnalysisFingerprints()

	// Endpoint calls share the same hard output-token budget as the terminal
	// application model. Hold its worst-case output allowance up front so a
	// dense site cannot consume the final synthesis slot. The reservation is
	// released immediately before summarizeApp dispatches.
	var summaryReservation *llm.BudgetReservation
	if a.appSummaryEnabled {
		summaryReservation = a.reserveAppSummaryOutput()
	}
	defer func() {
		if summaryReservation != nil {
			summaryReservation.Release()
		}
	}()

	endpointNum := 0
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		if a.budget.Level() == llm.BudgetExhausted {
			a.logger.Info("budget exhausted, stopping analysis")
			break
		}

		if acknowledged, ackErr := a.db.AcknowledgeEquivalentAnalyzedEvidence(a.scanID); ackErr != nil {
			a.logger.Warn("analysis evidence watermark unavailable", "error", ackErr)
		} else if acknowledged > 0 {
			a.logger.Debug("equivalent recaptures acknowledged without reanalysis", "rows", acknowledged)
		}

		// Get a wider capture-prioritized window, then let the current semantic
		// application model reshape which small batch the AI reads next.
		threshold := a.budget.RelevanceThreshold()
		queue, err := a.db.GetUnanalyzedEndpointQueue(a.scanID, threshold, AnalysisCandidateWindowSize)
		if err != nil {
			return fmt.Errorf("get analysis queue: %w", err)
		}
		if len(queue) == 0 {
			a.logger.Info("no more endpoints to analyze")
			break
		}
		ages, ageErr := a.db.GetAnalysisQueueAges(a.scanID)
		if ageErr != nil {
			a.logger.Warn("analysis queue age unavailable", "error", ageErr)
			ages = nil
		}
		gapState := AnalysisGapStateSnapshot(a.understanding.Recon)
		if _, feedbackErr := a.db.ResolveLatestAnalysisImpactOutcomes(a.scanID, gapState); feedbackErr != nil {
			a.logger.Warn("analysis impact outcome unavailable", "error", feedbackErr)
		}
		calibration, calibrationErr := a.db.ListAnalysisImpactCalibration(a.scanID)
		if calibrationErr != nil {
			a.logger.Warn("analysis impact calibration unavailable", "error", calibrationErr)
			calibration = nil
		}
		queue = RankAnalysisQueueWithFeedback(queue, a.understanding.Recon, ages, AnalysisImpactCalibrationMap(calibration))
		batchSize := analysisLearningBatchSize(len(queue), endpointNum, a.maxEndpoints)
		if batchSize <= 0 {
			break
		}
		batch := SelectAnalysisLearningBatch(queue, batchSize)
		checkpoint, checkpointErr := a.db.RecordAnalysisLearningCheckpoint(
			a.scanID,
			AnalysisReconFingerprint(a.understanding.Recon),
			AnalysisQueueFocusIDs(a.understanding.Recon),
			gapState,
			queue,
			batch,
		)
		if checkpointErr != nil {
			a.logger.Warn("analysis learning checkpoint not persisted", "error", checkpointErr)
		}
		var fairness *store.AnalysisQueueItem
		for index := range batch {
			if batch[index].FairnessLane {
				fairness = &batch[index]
				break
			}
		}
		if top := batch[0]; top.LearnedBoost > 0 || top.AgingBoost > 0 || fairness != nil {
			path := firstNonEmpty(firstNonEmpty(top.Path, top.URL), top.EndpointHash)
			reason := strings.Join(top.LearnedReasons, ", ")
			if reason == "" {
				reason = "captured relevance and the current semantic evidence gaps"
			}
			fairnessText := ""
			if fairness != nil {
				fairnessPath := firstNonEmpty(firstNonEmpty(fairness.Path, fairness.URL), fairness.EndpointHash)
				fairnessText = fmt.Sprintf(" One slot advanced %s %s after %d deferred checkpoint(s).",
					fairness.Method, fairnessPath, fairness.QueueAge)
			}
			impactIDs := make([]string, 0, len(top.Impact))
			for _, impact := range top.Impact {
				impactIDs = append(impactIDs, impact.Kind+":"+impact.ID)
			}
			otherSemanticBoost := top.LearnedBoost - top.EvidenceGain
			a.db.InsertNarration(a.scanID, "analyzer", "queue_reprioritized",
				fmt.Sprintf("Learning checkpoint %d ranked %d captured families and selected %d. %s %s received +%d bounded evidence, +%d novelty, and +%d fairness priority because %s.%s",
					checkpoint.Sequence, len(queue), len(batch), top.Method, path,
					top.EvidenceGain, otherSemanticBoost, top.AgingBoost, reason, fairnessText),
				top.URL, map[string]any{
					"endpoint_hash": top.EndpointHash,
					"base_score":    top.BaseScore, "learned_boost": top.LearnedBoost,
					"evidence_gain": top.EvidenceGain, "impact": impactIDs,
					"aging_boost": top.AgingBoost, "priority_score": top.PriorityScore,
					"reasons": top.LearnedReasons, "batch_size": len(batch),
					"checkpoint_id": checkpoint.ID, "checkpoint_sequence": checkpoint.Sequence,
					"candidate_count": len(queue), "focus": checkpoint.Focus,
					"fairness_endpoint": func() string {
						if fairness != nil {
							return fairness.EndpointHash
						}
						return ""
					}(),
				})
		}

		a.logger.Info("endpoints to analyze",
			"batch_count", len(batch),
			"candidate_window", len(queue),
			"threshold", threshold,
			"budget", a.budget.Summary(),
		)

		for _, queued := range batch {
			hash := queued.EndpointHash
			select {
			case <-ctx.Done():
				return nil
			default:
			}

			if a.budget.Level() == llm.BudgetExhausted {
				a.logger.Info("budget exhausted mid-batch")
				break
			}
			if a.maxEndpoints > 0 && endpointNum >= a.maxEndpoints {
				a.logger.Info("analysis endpoint limit reached",
					"limit", a.maxEndpoints,
					"remaining_batch", len(batch))
				break
			}

			endpointNum++
			if err := a.analyzeEndpoint(ctx, hash, endpointNum, queued.Reanalysis); err != nil {
				a.logger.Warn("endpoint analysis failed",
					"hash", hash[:8],
					"error", err,
				)
				// Mark as analyzed to avoid infinite retry
				a.db.MarkEndpointAnalyzed(a.scanID, hash, endpointNum)
			}
		}
		if a.maxEndpoints > 0 && endpointNum >= a.maxEndpoints {
			break
		}
		// Refresh the normalized model at every learning boundary. This makes
		// the next checkpoint compare its predictions with the whole prior
		// batch instead of an arbitrary every-fifth-endpoint partial view.
		a.saveUnderstanding()
	}

	// One-shot pass: ask the LLM to label the app and summarize what we
	// learned. Without this, the Knowledge view's "App type" and "Summary"
	// fields stay empty for the entire scan even though the templates and
	// areas are populated. Cheap (~500 in / ~200 out) and runs exactly
	// once at the end of analysis. Failure is non-fatal — operator just
	// sees the structural data without the narrative.
	profileCount := 0
	if profiles, err := a.db.GetAllProfiles(a.scanID); err == nil {
		for _, p := range profiles {
			if p.ID != "attack_surface" && p.ID != "js_discovered_routes" {
				profileCount++
			}
		}
	}
	if a.appSummaryEnabled && a.shouldSummarizeApp(profileCount) {
		if summaryReservation != nil {
			summaryReservation.Release()
			summaryReservation = nil
		}
		if err := a.summarizeApp(ctx); err != nil {
			a.logger.Warn("app summary skipped", "error", err)
		}
	}

	// Persist final understanding
	a.saveUnderstanding()
	if _, err := a.db.ResolveLatestAnalysisImpactOutcomes(a.scanID, AnalysisGapStateSnapshot(a.understanding.Recon)); err != nil {
		a.logger.Warn("final analysis impact outcome unavailable", "error", err)
	}

	a.logger.Info("analyzer complete",
		"endpoints_analyzed", endpointNum,
		"templates", len(a.understanding.PageTemplates),
		"areas", len(a.understanding.FunctionalAreas),
	)

	return nil
}

func analysisLearningBatchSize(queueLength, processed, maxEndpoints int) int {
	if queueLength <= 0 {
		return 0
	}
	batchSize := AnalysisLearningBatchSize
	if queueLength < batchSize {
		batchSize = queueLength
	}
	if maxEndpoints > 0 {
		remaining := maxEndpoints - processed
		if remaining <= 0 {
			return 0
		}
		if remaining < batchSize {
			batchSize = remaining
		}
	}
	return batchSize
}

func (a *AnalyzerAgent) reserveAppSummaryOutput() *llm.BudgetReservation {
	if a == nil || a.budget == nil || a.provider == nil {
		return nil
	}
	reservation, ok := a.budget.Reserve(a.provider.ModelInfo().Name, 0, appSummaryTokenAllowance(a.provider))
	if !ok {
		return nil
	}
	return reservation
}

func appSummaryTokenAllowance(provider llm.Provider) int {
	limit := llm.StructuredOutputTokenLimit(provider, appSummaryMaxTokens, 10240)
	if provider != nil {
		if providerLimit := provider.ModelInfo().MaxOutputTokens; providerLimit > 0 && providerLimit < limit {
			limit = providerLimit
		}
	}
	return limit
}

// SynthesizeApp performs only the scan-level semantic model call. Recon uses
// it after all bounded navigation so the protected output slot describes the
// freshest evidence instead of an intermediate snapshot.
func (a *AnalyzerAgent) SynthesizeApp(ctx context.Context) error {
	if a == nil || a.provider == nil || a.budget == nil {
		return fmt.Errorf("analyzer synthesis is not configured")
	}
	a.loadUnderstanding()
	if err := a.summarizeApp(ctx); err != nil {
		return err
	}
	a.saveUnderstanding()
	return nil
}

// summarizeApp asks the LLM to label the application and produce a 2-3
// sentence summary. Sets u.AppType and u.Summary on the in-memory
// understanding; saveUnderstanding picks them up on the next persist.
//
// Why a separate single call instead of building this incrementally as
// each endpoint is analyzed: the per-endpoint AnalyzerSystemPrompt focuses
// on issues + inputs + relationships for THAT endpoint — adding "and also
// keep updating an app-level type and summary" pollutes the JSON contract
// and wastes tokens on every call. One terminal call against the assembled
// understanding is cheaper, more coherent, and easier to debug.
func (a *AnalyzerAgent) summarizeApp(ctx context.Context) error {
	if a.understanding == nil {
		return fmt.Errorf("understanding not initialized")
	}
	if a.budget != nil && a.budget.Level() == llm.BudgetExhausted {
		return fmt.Errorf("budget exhausted")
	}

	if profiles, err := a.db.GetAllProfiles(a.scanID); err == nil {
		a.understanding.RefreshPagePurposeCards(profiles)
	}
	a.refreshQueryRoutedPagePurposeCards()
	a.refreshClientRoutedPagePurposeCards()
	rendered := a.appSummaryContext()
	if strings.TrimSpace(rendered) == "" {
		return fmt.Errorf("understanding empty — nothing to summarize")
	}

	start := time.Now()
	// This is the one scan-level synthesis call. The structured semantic
	// model needs enough room for roles, objects, workflows, boundaries and
	// unknowns; truncating this JSON is both wasteful and misleading.
	req := &llm.Request{
		SystemPrompt: prompts.AppSummaryPrompt,
		Messages: []llm.Message{
			{Role: "user", Content: rendered},
		},
		Temperature: 0.2,
		MaxTokens:   appSummaryTokenAllowance(a.provider),
		JSONMode:    true,
	}
	resp, err := llm.CompleteBudgeted(ctx, a.provider, a.budget, req, 0)
	durationMs := time.Since(start).Milliseconds()
	if err != nil {
		return fmt.Errorf("LLM call: %w", err)
	}
	modelID := llm.ResponseModel(resp, a.provider)
	costUcents := llm.CostMicroCents(modelID, resp.Usage)
	a.db.LogAIFull(a.scanID, "analyzer", "app_summary",
		"summarize app understanding", "", "",
		truncate(resp.Content, 200),
		resp.Usage.InputTokens, resp.Usage.OutputTokens, durationMs, costUcents, modelID,
		llm.RenderPrompt(req), resp.Content)

	var parsed appSummarySynthesis
	body := strings.TrimSpace(resp.Content)
	// JSON mode usually returns a clean object, but some providers wrap it
	// in markdown fences. Strip them defensively before unmarshal.
	if strings.HasPrefix(body, "```") {
		body = extractJSON(body)
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		if salvaged, ok := salvageAppSynthesisFromPartial(body, rendered); ok {
			a.understanding.AppType = salvaged.AppType
			a.understanding.Summary = salvaged.Summary
			if salvaged.Roles != nil {
				a.understanding.Recon.Roles = salvaged.Roles
			}
			if salvaged.Objects != nil {
				a.understanding.Recon.Objects = salvaged.Objects
			}
			if salvaged.Workflows != nil {
				a.understanding.Recon.Workflows = salvaged.Workflows
			}
			if salvaged.OwnershipBoundaries != nil {
				a.understanding.Recon.OwnershipBoundaries = salvaged.OwnershipBoundaries
			}
			if salvaged.Unknowns != nil {
				a.understanding.Recon.Unknowns = salvaged.Unknowns
			}
			a.understanding.NormalizeReconModel()
			a.understanding.Recon.Metrics.SynthesizedPageCount = len(a.understanding.Recon.Pages)
			if salvaged.Summary != "" {
				msg := fmt.Sprintf("App profile: %s — %s", a.understanding.AppType, a.understanding.Summary)
				a.db.InsertNarration(a.scanID, "analyzer", "app_summary", msg, "", nil)
			}
			a.logger.Warn("app model salvaged from partial JSON",
				"app_type", a.understanding.AppType,
				"summary_len", len(a.understanding.Summary),
				"roles", len(a.understanding.Recon.Roles),
				"objects", len(a.understanding.Recon.Objects),
				"workflows", len(a.understanding.Recon.Workflows),
				"boundaries", len(a.understanding.Recon.OwnershipBoundaries),
				"unknowns", len(a.understanding.Recon.Unknowns),
				"body_len", len(body))
			return nil
		}
		// Log preview AND length so we can distinguish empty-response
		// (provider returned nothing — MaxTokens too low?) from
		// malformed-but-present (real parse problem).
		return fmt.Errorf("parse JSON (len=%d, preview=%q): %w",
			len(body), truncate(body, 200), err)
	}

	a.understanding.AppType = extract.NormalizeReconAppTypeForTarget(
		parsed.AppType, parsed.Summary, rendered, a.state.ReadModel().Target)
	a.understanding.Summary = strings.TrimSpace(parsed.Summary)
	a.understanding.Recon.Roles = parsed.Roles
	a.understanding.Recon.Objects = parsed.Objects
	a.understanding.Recon.Workflows = parsed.Workflows
	a.understanding.Recon.OwnershipBoundaries = parsed.OwnershipBoundaries
	a.understanding.Recon.Unknowns = parsed.Unknowns
	a.understanding.NormalizeReconModel()
	a.understanding.Recon.Metrics.SynthesizedPageCount = len(a.understanding.Recon.Pages)

	// Surface in the live narration so demo viewers see the moment the
	// agent forms a high-level take on the target.
	if a.understanding.Summary != "" {
		msg := fmt.Sprintf("App profile: %s — %s", a.understanding.AppType, a.understanding.Summary)
		a.db.InsertNarration(a.scanID, "analyzer", "app_summary", msg, "", nil)
	}

	a.logger.Info("app summary generated",
		"app_type", a.understanding.AppType,
		"summary_len", len(a.understanding.Summary),
		"input_tokens", resp.Usage.InputTokens,
		"output_tokens", resp.Usage.OutputTokens,
		"cost_cents", costUcents/10_000,
	)
	return nil
}

func (a *AnalyzerAgent) refreshQueryRoutedPagePurposeCards() {
	if a == nil || a.db == nil || a.understanding == nil {
		return
	}
	entries, err := a.db.GetQueryRouteCandidates(a.scanID, 160, 192*1024)
	if err != nil {
		a.logger.Debug("query-routed page classification unavailable", "error", err)
		return
	}
	views := extract.DiscoverQueryRoutedViews(entries, 12)
	a.understanding.RefreshQueryRoutedPagePurposeCards(views)
	if len(views) > 0 {
		a.logger.Info("query-routed page types grounded", "views", len(views))
	}
}

func (a *AnalyzerAgent) refreshClientRoutedPagePurposeCards() {
	if a == nil || a.db == nil || a.understanding == nil {
		return
	}
	discoveries, err := a.db.GetVisitedClientRoutes(a.scanID, 80)
	if err != nil {
		a.logger.Debug("client-routed page classification unavailable", "error", err)
		return
	}
	evidence := make([]extract.ClientRouteEvidence, 0, len(discoveries))
	for _, discovery := range discoveries {
		evidence = append(evidence, extract.ClientRouteEvidence{ID: discovery.ID, URL: discovery.TargetURL})
	}
	views := extract.DiscoverVisitedClientRoutes(evidence, 16)
	a.understanding.RefreshClientRoutedPagePurposeCards(views)
	if len(views) > 0 {
		a.logger.Info("browser-visited client page types grounded", "views", len(views))
	}
}

func (a *AnalyzerAgent) shouldSummarizeApp(profileCount int) bool {
	if a == nil || a.understanding == nil {
		return false
	}
	if strings.TrimSpace(a.understanding.AppType) == "" || strings.TrimSpace(a.understanding.Summary) == "" {
		return true
	}
	synthesized := a.understanding.Recon.Metrics.SynthesizedPageCount
	if synthesized <= 0 {
		return true
	}
	delta := profileCount - synthesized
	if delta <= 0 {
		return false
	}
	// A small amount of evidence can be decisive when it directly addresses a
	// missing actor, workflow, object, or ownership boundary. Do not wait for a
	// generic page-count threshold before rebuilding a model with a known
	// high-priority understanding gap.
	for _, target := range a.understanding.Recon.Targets {
		if !target.Met && target.Priority >= 8 {
			return true
		}
	}
	threshold := 6
	if synthesized < 10 {
		threshold = 4
	} else if synthesized >= 30 {
		threshold = 10
	}
	return delta >= threshold
}

func salvageAppSummaryFromPartial(body, evidence string) (appType, summary string, ok bool) {
	summary = partialJSONStringField(body, "summary")
	if summary == "" {
		return "", "", false
	}
	appType = normalizeAppTypeFromEvidence(partialJSONStringField(body, "app_type"), summary, evidence)
	if strings.TrimSpace(appType) == "" {
		appType = "other"
	}
	return appType, summary, true
}

func salvageAppSynthesisFromPartial(body, evidence string) (appSummarySynthesis, bool) {
	var out appSummarySynthesis
	appType, summary, ok := salvageAppSummaryFromPartial(body, evidence)
	if !ok {
		return out, false
	}
	out.AppType = appType
	out.Summary = summary
	partialJSONArrayField(body, "high_priority_areas", &out.HighPriorityAreas)
	partialJSONArrayField(body, "roles", &out.Roles)
	partialJSONArrayField(body, "objects", &out.Objects)
	partialJSONArrayField(body, "workflows", &out.Workflows)
	partialJSONArrayField(body, "ownership_boundaries", &out.OwnershipBoundaries)
	partialJSONArrayField(body, "unknowns", &out.Unknowns)
	return out, true
}

// partialJSONArrayField recovers a complete array that appears before a
// provider-truncated JSON tail. It is string/escape aware, so nested evidence
// arrays and bracket characters inside prose do not terminate the value.
func partialJSONArrayField(body, key string, dest any) bool {
	idx := strings.Index(body, `"`+key+`"`)
	if idx < 0 {
		return false
	}
	rest := body[idx+len(key)+2:]
	colon := strings.IndexByte(rest, ':')
	if colon < 0 {
		return false
	}
	rest = strings.TrimLeft(rest[colon+1:], " \t\r\n")
	if !strings.HasPrefix(rest, "[") {
		return false
	}
	depth := 0
	inString := false
	escaped := false
	for i := 0; i < len(rest); i++ {
		ch := rest[i]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '"' {
				inString = false
			}
			continue
		}
		switch ch {
		case '"':
			inString = true
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return json.Unmarshal([]byte(rest[:i+1]), dest) == nil
			}
		}
	}
	return false
}

func partialJSONStringField(body, key string) string {
	idx := strings.Index(body, `"`+key+`"`)
	if idx < 0 {
		return ""
	}
	rest := body[idx+len(key)+2:]
	colon := strings.IndexByte(rest, ':')
	if colon < 0 {
		return ""
	}
	rest = strings.TrimLeft(rest[colon+1:], " \t\r\n")
	if !strings.HasPrefix(rest, `"`) {
		return ""
	}
	escaped := false
	for i := 1; i < len(rest); i++ {
		ch := rest[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if ch == '"' {
			var out string
			if err := json.Unmarshal([]byte(rest[:i+1]), &out); err != nil {
				return ""
			}
			return strings.TrimSpace(out)
		}
	}
	return ""
}

func normalizeAppTypeFromEvidence(appType, summary, evidence string) string {
	return extract.NormalizeReconAppType(appType, summary, evidence)
}

func (a *AnalyzerAgent) appSummaryContext() string {
	var sb strings.Builder
	if rendered := a.understanding.RenderForLLM(); strings.TrimSpace(rendered) != "" {
		sb.WriteString(rendered)
		sb.WriteString("\n")
	}
	if evidence := a.understanding.RenderReconEvidenceForLLM(); strings.TrimSpace(evidence) != "" {
		sb.WriteString(evidence)
		sb.WriteString("\n")
	}

	if pages := a.observedHTMLPagesForSummary(20); len(pages) > 0 {
		sb.WriteString("## Observed HTML Pages\n")
		for _, p := range pages {
			fmt.Fprintf(&sb, "  - %s %s [%d]\n", p.Method, p.Path, p.StatusCode)
		}
		sb.WriteString("\n")
	}

	if links := a.discoveredTargetsForSummary(30); len(links) > 0 {
		sb.WriteString("## Discovered Navigation and Forms\n")
		for _, d := range links {
			if d.Detail != "" {
				fmt.Fprintf(&sb, "  - %s %s (%s)\n", d.Kind, d.Target, d.Detail)
			} else {
				fmt.Fprintf(&sb, "  - %s %s\n", d.Kind, d.Target)
			}
		}
		sb.WriteString("\n")
	}

	return strings.TrimSpace(sb.String())
}

type observedSummaryPage struct {
	Method     string
	Path       string
	StatusCode int
}

func (a *AnalyzerAgent) observedHTMLPagesForSummary(limit int) []observedSummaryPage {
	rows, err := a.db.Conn().Query(`
		SELECT method, path, MIN(status_code) AS status_code
		FROM traffic
		WHERE scan_id = ?
		  AND is_filtered = FALSE
		  AND is_duplicate = FALSE
		  AND lower(content_type) LIKE '%text/html%'
		GROUP BY method, path
		ORDER BY
			CASE WHEN status_code BETWEEN 200 AND 399 THEN 0 ELSE 1 END,
			MIN(id)
		LIMIT ?`,
		a.scanID, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []observedSummaryPage
	for rows.Next() {
		var p observedSummaryPage
		if err := rows.Scan(&p.Method, &p.Path, &p.StatusCode); err == nil {
			out = append(out, p)
		}
	}
	return out
}

type discoveredSummaryTarget struct {
	Target string
	Kind   string
	Detail string
}

func (a *AnalyzerAgent) discoveredTargetsForSummary(limit int) []discoveredSummaryTarget {
	rows, err := a.db.Conn().Query(`
		SELECT target_url, kind, COALESCE(detail, '')
		FROM url_discoveries
		WHERE scan_id = ?
		  AND kind IN ('html-link', 'form-action', 'js-route', 'explorer', 'seed')
		ORDER BY id
		LIMIT ?`,
		a.scanID, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()

	seen := make(map[string]struct{})
	var out []discoveredSummaryTarget
	for rows.Next() {
		var d discoveredSummaryTarget
		if err := rows.Scan(&d.Target, &d.Kind, &d.Detail); err != nil {
			continue
		}
		d.Target = compactSummaryURL(d.Target)
		key := d.Kind + "\x00" + d.Target
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, d)
	}
	return out
}

func compactSummaryURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Path == "" {
		return raw
	}
	if parsed.RawQuery != "" {
		return parsed.Path + "?" + parsed.RawQuery
	}
	return parsed.Path
}

func (a *AnalyzerAgent) analyzeEndpoint(ctx context.Context, endpointHash string, batchNum int, reanalysis bool) error {
	// 1. Load all traffic for this endpoint
	entries, err := a.db.GetTrafficByEndpointHash(a.scanID, endpointHash)
	if err != nil {
		return fmt.Errorf("get traffic: %w", err)
	}
	if len(entries) == 0 {
		return nil
	}

	// 2. Build the endpoint bundle (structured extraction)
	bundle := extract.BuildEndpointBundle(entries, 20)
	if bundle == nil {
		return nil
	}
	// Path-label refinement mutates bundle.URLPattern later in this method.
	// Remember the evidence fingerprint from the raw captured bundle so the
	// next raw route is compared with the same representation. Without this,
	// replay could compact a family that the live analyzer missed immediately
	// after refining its representative.
	rawAnalysisFingerprint := analysisFingerprint(entries, bundle)

	a.logger.Info("analyzing endpoint",
		"method", bundle.Method,
		"pattern", bundle.URLPattern,
		"entries", bundle.EntryCount,
		"has_input", bundle.HasInput,
		"is_api", bundle.IsAPI,
		"reanalysis", reanalysis,
	)

	// 3. Store extracted inputs immediately (zero LLM cost)
	a.storeExtractedInputs(bundle, entries)
	a.enqueueOpenAPIFollowUps(entries, bundle)
	a.enqueueGraphQLFollowUps(bundle)

	if disposition, reason, handled := a.protectionAnalysisDisposition(entries, endpointHash); handled {
		a.logger.Info("closing protection interstitial before semantic analysis",
			"method", bundle.Method,
			"pattern", bundle.URLPattern,
			"disposition", disposition,
			"reason", reason,
		)
		a.understanding.MarkAnalyzed(endpointHash, "")
		a.rememberAnalysisFingerprintValue(rawAnalysisFingerprint, endpointHash)
		a.resolveAnalysisMovement(endpointHash, disposition, reason)
		return a.db.MarkEndpointAnalyzed(a.scanID, endpointHash, batchNum)
	}

	// Browser reloads produce large volumes of 304s, localization assets and
	// Socket.IO handshakes. They remain in the evidence store, but spending a
	// deep reasoning call on each one adds cost without application semantics.
	// Security signals and traffic produced by an active hypothesis override
	// the passive-resource filter.
	if reason := deepAnalysisSkipReason(entries, bundle); reason != "" {
		a.logger.Info("skipping deep endpoint analysis",
			"method", bundle.Method,
			"pattern", bundle.URLPattern,
			"reason", reason,
		)
		a.understanding.MarkAnalyzed(endpointHash, "")
		a.rememberAnalysisFingerprintValue(rawAnalysisFingerprint, endpointHash)
		a.resolveAnalysisMovement(endpointHash, "closed", reason)
		return a.db.MarkEndpointAnalyzed(a.scanID, endpointHash, batchNum)
	}

	if !reanalysis {
		if reason := a.repeatedAnalysisSkipReason(entries, bundle, endpointHash); reason != "" {
			a.logger.Info("skipping repeated endpoint analysis",
				"method", bundle.Method,
				"pattern", bundle.URLPattern,
				"reason", reason,
			)
			a.understanding.MarkAnalyzed(endpointHash, "")
			a.rememberAnalysisFingerprintValue(rawAnalysisFingerprint, endpointHash)
			a.resolveAnalysisMovement(endpointHash, "compacted", reason)
			return a.db.MarkEndpointAnalyzed(a.scanID, endpointHash, batchNum)
		}
	}

	if reason := a.lessonValidationSchemaReuseSkipReason(bundle); reason != "" {
		a.logger.Info("skipping repeated lesson validation schema analysis",
			"method", bundle.Method,
			"pattern", bundle.URLPattern,
			"reason", reason,
		)
		a.understanding.MarkAnalyzed(endpointHash, "")
		a.understanding.AddToFunctionalArea(endpointHash, bundle.URLPattern)
		a.rememberAnalysisFingerprintValue(rawAnalysisFingerprint, endpointHash)
		a.resolveAnalysisMovement(endpointHash, "compacted", reason)
		return a.db.MarkEndpointAnalyzed(a.scanID, endpointHash, batchNum)
	}

	// 4. Check template match
	templateID, isTemplateMatch := "", false
	if !reanalysis {
		templateID, isTemplateMatch = a.understanding.MatchTemplate(bundle)
	}
	rawTemplateFingerprint := ""
	if isTemplateMatch {
		rawTemplateFingerprint = templateAnalysisFingerprint(entries, bundle, templateID)
	}
	if isTemplateMatch {
		if reason := a.repeatedTemplateAnalysisSkipReason(entries, bundle, templateID, endpointHash); reason != "" {
			a.logger.Info("skipping repeated template analysis",
				"method", bundle.Method,
				"pattern", bundle.URLPattern,
				"template", templateID,
				"reason", reason,
			)
			a.understanding.IncrementTemplate(templateID, bundle.SampleURL)
			a.understanding.MarkAnalyzed(endpointHash, templateID)
			a.understanding.AddToFunctionalArea(endpointHash, bundle.URLPattern)
			a.rememberAnalysisFingerprintValue(rawAnalysisFingerprint, endpointHash)
			a.rememberTemplateAnalysisFingerprintValue(rawTemplateFingerprint, endpointHash)
			a.resolveAnalysisMovement(endpointHash, "compacted", reason)
			return a.db.MarkEndpointAnalyzed(a.scanID, endpointHash, batchNum)
		}
	}

	// 5. Build prompt and call LLM
	var profile *types.PageProfile
	if isTemplateMatch && a.budget.Level() != llm.BudgetOK {
		// Budget is tight and this is a known template — skip LLM, just register
		a.logger.Info("skipping LLM (template match, budget tight)",
			"template", templateID,
			"pattern", bundle.URLPattern,
		)
		a.understanding.IncrementTemplate(templateID, bundle.SampleURL)
		a.understanding.MarkAnalyzed(endpointHash, templateID)
		a.understanding.AddToFunctionalArea(endpointHash, bundle.URLPattern)
		a.rememberAnalysisFingerprintValue(rawAnalysisFingerprint, endpointHash)
		a.rememberTemplateAnalysisFingerprintValue(rawTemplateFingerprint, endpointHash)
		a.db.MarkEndpointAnalyzed(a.scanID, endpointHash, batchNum)
		return nil
	}

	if isTemplateMatch {
		profile, err = a.templateVerify(ctx, bundle, templateID)
	} else {
		profile, err = a.fullAnalysis(ctx, bundle)
	}

	if err != nil {
		a.db.MarkEndpointAnalyzed(a.scanID, endpointHash, batchNum)
		return fmt.Errorf("LLM analysis: %w", err)
	}

	// 6. Merge LLM profile with extracted data and store
	if profile != nil {
		merged := a.mergeProfile(profile, bundle)
		sanitizeProfileAuthRequirement(merged, bundle)
		// Apply the shared direct-response ceiling before either persistence or
		// finding publication. Redirects, negative/empty responses, and generic
		// auth/error shells cannot carry model-invented issues or page semantics
		// into any downstream surface.
		a.applyAnalyzerProfileEvidenceCeiling(merged, entries)
		sanitizePublicReferenceIssues(merged, bundle)
		sanitizeFrameworkSerializationIssues(merged)
		if err := a.upsertEvidenceBoundProfile(merged); err != nil {
			a.logger.Warn("failed to store profile", "id", merged.ID, "error", err)
		} else {
			a.logger.Info("profile written",
				"id", merged.ID,
				"purpose", truncate(merged.Purpose, 60),
				"inputs", len(merged.Inputs),
				"issues", len(merged.Issues),
			)

			// (metrics already logged in fullAnalysis / templateVerify)
		}

		// Publish finding events
		for _, issue := range merged.Issues {
			a.bus.Publish(Event{
				Type:   EventFindingDetected,
				Source: a.Name(),
				Payload: types.Finding{
					Title:      issue,
					EndpointID: merged.ID,
					Severity:   types.SeverityMedium,
					Confidence: types.ConfidencePossible,
				},
			})
		}
	}

	// 7. Update app understanding
	if isTemplateMatch {
		a.understanding.IncrementTemplate(templateID, bundle.SampleURL)
		a.understanding.MarkAnalyzed(endpointHash, templateID)
	} else {
		// Register new template if this has a meaningful input signature
		sig := bundle.InputSignature()
		if sig != "" && profile != nil {
			newTemplateID := generateTemplateID(bundle)
			a.understanding.RegisterTemplate(newTemplateID, profile.Purpose, bundle)
			a.understanding.MarkAnalyzed(endpointHash, newTemplateID)
			if profile != nil {
				profile.TemplateID = newTemplateID
			}
		} else {
			a.understanding.MarkAnalyzed(endpointHash, "")
		}
	}
	a.understanding.AddToFunctionalArea(endpointHash, bundle.URLPattern)

	// 8. Mark traffic as analyzed
	a.db.MarkEndpointAnalyzed(a.scanID, endpointHash, batchNum)
	a.rememberAnalysisFingerprintValue(rawAnalysisFingerprint, endpointHash)
	if isTemplateMatch {
		a.rememberTemplateAnalysisFingerprintValue(rawTemplateFingerprint, endpointHash)
	}

	// 9. Periodically save understanding
	if batchNum%5 == 0 {
		a.saveUnderstanding()
	}

	return nil
}

func (a *AnalyzerAgent) resolveAnalysisMovement(endpointHash, disposition, reason string) {
	if a == nil || a.db == nil {
		return
	}
	if err := a.db.ResolveAnalysisPriorityMovement(a.scanID, endpointHash, disposition, reason); err != nil {
		a.logger.Debug("analysis learning outcome unavailable", "hash", endpointHash, "error", err)
	}
}

// sanitizeProfileAuthRequirement keeps ambient browser state separate from an
// observed authentication boundary. Anonymous applications commonly assign a
// session cookie to every visitor; that cookie riding on a public 200 response
// does not prove the page requires an authenticated identity.
func sanitizeProfileAuthRequirement(profile *types.PageProfile, bundle *extract.EndpointBundle) {
	if profile == nil || bundle == nil {
		return
	}
	location := ""
	for key, value := range bundle.ResponseHeaders {
		if strings.EqualFold(key, "location") {
			location = strings.TrimSpace(value)
			break
		}
	}
	has2xx := false
	hasChallenge := false
	for _, status := range bundle.StatusCodes {
		if status >= 200 && status < 300 {
			has2xx = true
		}
		if status == 401 || status == 403 {
			hasChallenge = true
		}
	}
	redirectsToAuth := location != "" && isLikelyAuthPageURL(location)
	if hasChallenge || redirectsToAuth {
		if analyzerHeaderValue(bundle.RequestHeaders, "authorization") != "" {
			profile.AuthRequired = "bearer_token"
		} else if analyzerHeaderValue(bundle.RequestHeaders, "x-api-key") != "" {
			profile.AuthRequired = "api_key"
		} else {
			profile.AuthRequired = "session_cookie"
		}
		return
	}
	if has2xx && (isLikelyAuthPageURL(bundle.URLPattern) || isLikelyAuthPageURL(bundle.SampleURL)) {
		// Login/register pages establish identity; viewing the form itself is
		// not evidence that authentication is already required.
		profile.AuthRequired = "none"
		return
	}
	if has2xx && (strings.EqualFold(profile.AuthRequired, "session_cookie") ||
		strings.EqualFold(profile.AuthRequired, "bearer_token") ||
		strings.EqualFold(profile.AuthRequired, "api_key")) {
		profile.AuthRequired = "unknown"
	}
}

// applyAnalyzerProfileEvidenceCeiling is the persistence boundary for model
// output. The implementation deliberately delegates to reconprojection so the
// write path and every read surface use exactly the same response verdict.
func applyAnalyzerProfileEvidenceCeiling(profile *types.PageProfile, entries []types.TrafficEntry) {
	if profile == nil {
		return
	}
	exact := reconprojection.EntriesForExactSpecimen(entries, profile.Method, profile.URL)
	reconprojection.AnnotateProfile(profile, exact)
	reconprojection.ApplyQueryVariantCeiling(profile, entries, nil)
}

func (a *AnalyzerAgent) applyAnalyzerProfileEvidenceCeiling(profile *types.PageProfile, entries []types.TrafficEntry) {
	applyAnalyzerProfileEvidenceCeiling(profile, entries)
	if a == nil || a.db == nil {
		return
	}
	if index, err := a.db.GetCatchAllIndex(a.scanID); err == nil {
		reconprojection.ApplyCatchAllCeiling(profile, index)
		reconprojection.ApplyQueryVariantCeiling(profile, entries, index)
	}
}

func (a *AnalyzerAgent) upsertEvidenceBoundProfile(profile *types.PageProfile) error {
	// UpsertProfile applies the same evidence-state ceiling atomically while it
	// merges the row, including clearing unsupported templates and extracted
	// inputs. Keeping this boundary as one write avoids a transient stale claim
	// and an unnecessary second SQLite round trip for every unverified profile.
	return a.db.UpsertProfile(a.scanID, profile)
}

func analyzerHeaderValue(headers map[string]string, want string) string {
	for key, value := range headers {
		if strings.EqualFold(key, want) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func sanitizePublicReferenceIssues(profile *types.PageProfile, bundle *extract.EndpointBundle) {
	if profile == nil || bundle == nil || len(profile.Issues) == 0 {
		return
	}
	context := strings.ToLower(strings.Join([]string{bundle.URLPattern, bundle.SampleURL, profile.Purpose}, " "))
	for _, marker := range []string{
		"/account", "/profile", "/users", "/user/", "/tenant", "/orders", "/order/",
		"/basket", "/admin", "/secure", "/billing", "/payment", "/wallet", "/messages",
	} {
		if strings.Contains(context, marker) {
			return
		}
	}
	publicReference := false
	for _, marker := range []string{
		"catalog", "collection", "store", "location", "directory", "product", "media", "image",
		"translation", "i18n", "geolocation", "currency", "country", "ipstack", "published content",
	} {
		if strings.Contains(context, marker) {
			publicReference = true
			break
		}
	}
	if !publicReference {
		return
	}

	kept := profile.Issues[:0]
	for _, issue := range profile.Issues {
		lower := strings.ToLower(issue)
		ownershipClaim := strings.Contains(lower, "ownership") || strings.Contains(lower, "idor") ||
			strings.Contains(lower, "access control") || strings.Contains(lower, "authorization") ||
			strings.Contains(lower, "sensitive data") || strings.Contains(lower, "sensitive geolocation")
		if !ownershipClaim {
			kept = append(kept, issue)
		}
	}
	profile.Issues = kept
}

func sanitizeFrameworkSerializationIssues(profile *types.PageProfile) {
	if profile == nil || len(profile.Issues) == 0 {
		return
	}
	kept := profile.Issues[:0]
	for _, issue := range profile.Issues {
		if !frameworkSerializationNoise(issue) {
			kept = append(kept, issue)
		}
	}
	profile.Issues = kept
}

func frameworkSerializationNoise(value string) bool {
	lower := strings.ToLower(value)
	if !strings.Contains(lower, "html comment") && !strings.Contains(lower, "comment block") {
		return false
	}
	serializationMarker := false
	for _, marker := range []string{
		"array structure", "array indices", "nested indices", "variable reference",
		"component name", "vendor name", "stripe reference", "serialized state",
		"server-side rendering", "hydration", "react flight",
	} {
		if strings.Contains(lower, marker) {
			serializationMarker = true
			break
		}
	}
	if !serializationMarker {
		return false
	}
	for _, sensitive := range []string{
		"api key", "access token", "secret value", "private key", "password",
		"session token", "credit card number", "private customer", "customer record",
	} {
		if strings.Contains(lower, sensitive) {
			return false
		}
	}
	return true
}

func (a *AnalyzerAgent) fullAnalysis(ctx context.Context, bundle *extract.EndpointBundle) (*types.PageProfile, error) {
	// Build context
	model := a.state.ReadModel()
	endpointIndex := llm.BuildEndpointIndex(model.Endpoints)
	bundleContext := llm.BuildBundleContext(bundle)
	appContext := llm.BuildAppUnderstandingContext(a.understanding)

	userPrompt := fmt.Sprintf(`Analyze this endpoint and produce a PageProfile JSON.

%s

%s

%s

Respond with a single PageProfile JSON object.`,
		appContext, endpointIndex, bundleContext)

	// Check budget
	totalPrompt := prompts.AnalyzerSystemPrompt + userPrompt
	estimatedTokens := a.provider.CountTokens(totalPrompt)

	if !a.budget.CanSpend(estimatedTokens) {
		a.logger.Warn("not enough budget for full analysis",
			"estimated_tokens", estimatedTokens,
			"pattern", bundle.URLPattern,
		)
		return nil, nil
	}

	a.logger.Info("LLM full analysis",
		"model", a.provider.ModelInfo().Name,
		"estimated_tokens", estimatedTokens,
	)

	// Refine the URL pattern via the shared pathlabel.Resolver. Same
	// cache the crawler's saturation handler uses, so a pattern
	// labelled there is reused here for free. Falls back to the
	// bundle's existing URLPattern (corpus-aligned regex template) if
	// no resolver is wired or the LLM call doesn't improve on it.
	a.refineBundleURLPattern(ctx, bundle)

	// Narrate: what the analyzer is about to do
	a.db.InsertNarration(a.scanID, "analyzer", "inspect",
		fmt.Sprintf("Taking a closer look at %s %s — %d sample request(s) to learn from.",
			bundle.Method, bundle.URLPattern, bundle.EntryCount),
		bundle.SampleURL, nil)

	start := time.Now()
	req := &llm.Request{
		SystemPrompt: prompts.AnalyzerSystemPrompt,
		Messages: []llm.Message{
			{Role: "user", Content: userPrompt},
		},
		Temperature: 0.2,
		MaxTokens:   llm.StructuredOutputTokenLimit(a.provider, 2048, 10240),
		JSONMode:    true,
	}
	resp, err := llm.CompleteBudgeted(ctx, a.provider, a.budget, req, estimatedTokens)
	durationMs := time.Since(start).Milliseconds()
	if err != nil {
		return nil, err
	}

	modelID := llm.ResponseModel(resp, a.provider)
	costUcents := llm.CostMicroCents(modelID, resp.Usage)
	a.logger.Info("LLM response",
		"input_tokens", resp.Usage.InputTokens,
		"output_tokens", resp.Usage.OutputTokens,
		"duration_ms", durationMs,
		"cost_cents", costUcents/10_000,
	)

	a.db.LogAIFull(a.scanID, "analyzer", "full_analysis",
		fmt.Sprintf("%s %s", bundle.Method, bundle.URLPattern),
		"", bundle.SampleURL, truncate(resp.Content, 200),
		resp.Usage.InputTokens, resp.Usage.OutputTokens, durationMs, costUcents, modelID,
		llm.RenderPrompt(req), resp.Content)

	// Narrate: what the LLM actually thought (extracted from its own response).
	// Framework hydration markers are common transport metadata, so keep a
	// model's "debug leak" overreaction out of the pentester-facing journal.
	if thought := extractNarration(resp.Content); thought != "" && !frameworkSerializationNoise(thought) {
		a.db.InsertNarration(a.scanID, "analyzer", "thought", thought, bundle.SampleURL, nil)
	}

	profile := a.parseProfile(resp.Content)

	// Harvest any follow-up tasks the LLM wants us to run. These get queued
	// and consumed by the Explorer agent. One narration summarizes the batch.
	profileID := ""
	if profile != nil {
		profileID = profile.ID
	}
	a.harvestFollowUps(resp.Content, profileID)

	return profile, nil
}

func deepAnalysisSkipReason(entries []types.TrafficEntry, bundle *extract.EndpointBundle) string {
	if len(entries) == 0 || bundle == nil {
		return "empty endpoint bundle"
	}

	allNotModified := true
	allNotFound := true
	activeEvidence := false
	explicitHypothesis := false
	for _, entry := range entries {
		if entry.Response.StatusCode != 304 {
			allNotModified = false
		}
		if entry.Response.StatusCode != 404 && entry.Response.StatusCode != 410 {
			allNotFound = false
		}
		if entry.HypothesisID != "" {
			explicitHypothesis = true
		}
		if entry.SourceActionID != 0 || entry.HypothesisID != "" ||
			entry.SourceAgent == "explorer" || entry.SourceAgent == "verifier" {
			activeEvidence = true
		}
	}
	if allNotModified {
		return "all responses were HTTP 304"
	}
	// A navigator click can mark a request as scanner-produced without giving
	// a generic 404 any semantic value. Keep 404/410 responses only when an
	// explicit hypothesis names the negative result as evidence.
	if allNotFound && !explicitHypothesis {
		return "only generic HTTP 404/410 responses were observed"
	}
	redirectEvidence := observation.SummarizeRedirectEvidence(entries)
	if !explicitHypothesis && redirectEvidence.PathPreservingAuthGate {
		return "redirect-only route entered a path-preserving authentication gate; backing route unverified"
	}
	// SourceActionID proves the browser intentionally reached a route; it does
	// not make a slash-only same-origin redirect semantically interesting. The
	// canonical destination remains captured and analyzed. Only an explicit
	// hypothesis can promote this transport normalization back to deep review.
	if !explicitHypothesis && allBoringCanonicalRedirects(entries) {
		return "canonical redirect with no new response body"
	}

	lowerPath := strings.ToLower(entries[0].Request.Path)
	if hasSocketIOPathSegment(lowerPath) {
		// Cookies, transport query fields and 400s caused by a stale Engine.IO
		// session are protocol mechanics, not business-level security signals.
		// Analyze the transport only when another agent names a concrete
		// hypothesis for it.
		if explicitHypothesis {
			return ""
		}
		return "repeated Socket.IO transport handshake"
	}
	if strings.Contains(lowerPath, "/assets/i18n/") {
		if explicitHypothesis || bundle.HasErrors {
			return ""
		}
		return "localization resource"
	}
	if containsInvalidPathIdentifier(entries[0].Request.Path) || containsInvalidPathIdentifier(bundle.SampleURL) || containsInvalidPathIdentifier(bundle.URLPattern) {
		if explicitHypothesis {
			return ""
		}
		return "invalid client-side placeholder identifier"
	}
	if hasSyntheticInvalidRouteSegment(lowerPath) {
		if explicitHypothesis {
			return ""
		}
		return "synthetic invalid route"
	}
	if (strings.HasPrefix(lowerPath, "/cdn-cgi/challenge-platform/") || strings.HasPrefix(lowerPath, "/.well-known/captcha/")) &&
		!explicitHypothesis && !staticResourceHasServerFailure(entries) {
		return "browser protection/interstitial mechanic"
	}
	if !explicitHypothesis && trafficLooksLikeProtectionInterstitial(entries) {
		return "browser protection/interstitial response"
	}

	// Some CMS asset combiners use extensionless paths such as /_static/ and
	// place the real resource list in the query. Response content type is the
	// stronger signal there: browser-loaded JS/CSS/media remains captured for
	// endpoint extraction, but does not need an LLM PageProfile unless an
	// explicit hypothesis or server failure promotes it.
	if (bundle.Method == "GET" || bundle.Method == "HEAD") && allPassiveResponseContentTypes(entries) {
		if explicitHypothesis || staticResourceHasServerFailure(entries) || bundle.HasFileUpload {
			return ""
		}
		return "passive response content type"
	}

	if (bundle.Method == "GET" || bundle.Method == "HEAD") && isPassiveStaticResource(lowerPath) {
		// Auth cookies or bearer headers often ride along with static assets in
		// SPAs. Treating that ambient auth as a semantic signal burns LLM budget
		// on scripts, images and fonts. Keep explicit hypotheses, inputs, errors
		// and uploads analyzable because those are active security evidence.
		if explicitHypothesis || bundle.HasInput || staticResourceHasServerFailure(entries) || bundle.HasFileUpload {
			return ""
		}
		return "passive static resource"
	}
	if (bundle.Method == "GET" || bundle.Method == "HEAD") && isBenchmarkMetadataPath(lowerPath) {
		if explicitHypothesis || bundle.HasInput || bundle.HasAuth || bundle.HasErrors || bundle.HasFileUpload {
			return ""
		}
		return "benchmark metadata/index document"
	}

	// Any meaningful request/response signal deserves analysis even when its
	// path resembles a resource. This protects odd endpoints hidden behind
	// misleading extensions and hypothesis-driven verification traffic.
	if activeEvidence || bundle.HasInput || bundle.HasAuth || bundle.HasErrors || bundle.HasFileUpload {
		return ""
	}

	return ""
}

func trafficLooksLikeProtectionInterstitial(entries []types.TrafficEntry) bool {
	return protection.SummarizeTraffic(entries).ChallengeOnly
}

// protectionAnalysisDisposition is the response-aware protection guard. It
// handles only challenge-only families: an explicit hypothesis, a server
// failure, or eventual non-interstitial application content falls through to
// ordinary semantic analysis. New challenge shapes become retained specimens;
// already represented shapes become measurable saved calls.
func (a *AnalyzerAgent) protectionAnalysisDisposition(entries []types.TrafficEntry, endpointHash string) (string, string, bool) {
	explicitHypothesis := false
	for _, entry := range entries {
		if strings.TrimSpace(entry.HypothesisID) != "" {
			explicitHypothesis = true
		}
	}
	summary := protection.SummarizeTraffic(entries)
	if summary.InterstitialResponses == 0 || len(summary.Fingerprints) == 0 {
		return "", "", false
	}
	if a.protectionShapes == nil {
		a.protectionShapes = make(map[string]string)
	}
	vendor := strings.TrimSpace(summary.PrimaryVendor)
	if vendor == "" {
		vendor = "browser/WAF"
	}
	newShapes := make([]string, 0, len(summary.Fingerprints))
	for _, fingerprint := range summary.Fingerprints {
		if a.protectionShapes[fingerprint] == "" {
			newShapes = append(newShapes, fingerprint)
		}
	}
	for _, fingerprint := range summary.Fingerprints {
		a.protectionShapes[fingerprint] = endpointHash
	}
	// A recovered application, server failure, or explicit hypothesis remains
	// analyzable, but its protection shape still becomes the representative.
	// A later challenge-only route can therefore reuse it instead of retaining
	// a redundant specimen.
	if !summary.ChallengeOnly || explicitHypothesis {
		return "", "", false
	}
	if len(newShapes) == 0 {
		return "compacted", fmt.Sprintf("equivalent %s protection interstitial already retained", vendor), true
	}
	reason := fmt.Sprintf("protection specimen retained: %s interstitial shape %s", vendor, strings.Join(newShapes, ","))
	if a.db != nil {
		a.db.InsertNarration(a.scanID, "analyzer", "protection_specimen",
			fmt.Sprintf("Retained one response-backed %s protection specimen and will reuse it for equivalent challenge mechanics without treating the interstitial as target application content.", vendor),
			entries[0].Request.URL, map[string]any{
				"endpoint_hash": endpointHash, "vendor": vendor,
				"fingerprints": newShapes, "captures": summary.InterstitialResponses,
			})
	}
	return "closed", reason, true
}

func allPassiveResponseContentTypes(entries []types.TrafficEntry) bool {
	if len(entries) == 0 {
		return false
	}
	for _, entry := range entries {
		contentType := strings.ToLower(strings.TrimSpace(entry.Response.ContentType))
		if split := strings.IndexByte(contentType, ';'); split >= 0 {
			contentType = strings.TrimSpace(contentType[:split])
		}
		if strings.HasPrefix(contentType, "image/") || strings.HasPrefix(contentType, "font/") ||
			strings.HasPrefix(contentType, "audio/") || strings.HasPrefix(contentType, "video/") {
			continue
		}
		switch contentType {
		case "application/javascript", "application/x-javascript", "text/javascript", "text/css":
			continue
		default:
			return false
		}
	}
	return true
}

func isBenchmarkMetadataPath(lowerPath string) bool {
	lowerPath = strings.TrimSpace(strings.ToLower(lowerPath))
	if lowerPath == "" {
		return false
	}
	lowerPath = strings.TrimRight(lowerPath, "/")
	return strings.HasSuffix(lowerPath, "/sitemap.xml") ||
		strings.HasSuffix(lowerPath, "/allendpointjson") ||
		strings.HasSuffix(lowerPath, "/scanner") ||
		strings.HasSuffix(lowerPath, "/scanner/benchmark")
}

func (a *AnalyzerAgent) loadAnalysisFingerprints() {
	a.analysisFingerprints = make(map[string]string)
	a.templateFingerprints = make(map[string]string)
	a.protectionShapes = make(map[string]string)
	if a.understanding == nil || len(a.understanding.AnalyzedHashes) == 0 {
		return
	}
	for hash, templateID := range a.understanding.AnalyzedHashes {
		entries, err := a.db.GetAnalyzedTrafficByEndpointHash(a.scanID, hash)
		if err != nil || len(entries) == 0 {
			continue
		}
		bundle := extract.BuildEndpointBundle(entries, 20)
		a.rememberAnalysisFingerprint(entries, bundle, hash)
		for _, fingerprint := range protection.SummarizeTraffic(entries).Fingerprints {
			if fingerprint != "" {
				a.protectionShapes[fingerprint] = hash
			}
		}
		if templateID != "" && templateID != "unique" {
			a.rememberTemplateAnalysisFingerprint(entries, bundle, templateID, hash)
		}
	}
}

func (a *AnalyzerAgent) repeatedAnalysisSkipReason(entries []types.TrafficEntry, bundle *extract.EndpointBundle, endpointHash string) string {
	if a.analysisFingerprints == nil {
		a.analysisFingerprints = make(map[string]string)
	}
	fp := analysisFingerprint(entries, bundle)
	if fp == "" {
		return ""
	}
	previousHash, ok := a.analysisFingerprints[fp]
	if !ok || previousHash == "" {
		return ""
	}
	if previousHash == endpointHash {
		return "same endpoint family already analyzed with no new status, input, schema, or source-intent signal"
	}
	return fmt.Sprintf("equivalent endpoint family already analyzed via %s", shortHash(previousHash))
}

func (a *AnalyzerAgent) rememberAnalysisFingerprint(entries []types.TrafficEntry, bundle *extract.EndpointBundle, endpointHash string) {
	a.rememberAnalysisFingerprintValue(analysisFingerprint(entries, bundle), endpointHash)
}

func (a *AnalyzerAgent) rememberAnalysisFingerprintValue(fingerprint, endpointHash string) {
	if a.analysisFingerprints == nil {
		a.analysisFingerprints = make(map[string]string)
	}
	if fingerprint != "" {
		a.analysisFingerprints[fingerprint] = endpointHash
	}
}

func (a *AnalyzerAgent) repeatedTemplateAnalysisSkipReason(entries []types.TrafficEntry, bundle *extract.EndpointBundle, templateID, endpointHash string) string {
	if a.templateFingerprints == nil {
		a.templateFingerprints = make(map[string]string)
	}
	fp := templateAnalysisFingerprint(entries, bundle, templateID)
	if fp == "" {
		return ""
	}
	previousHash, ok := a.templateFingerprints[fp]
	if !ok || previousHash == "" {
		return ""
	}
	if previousHash == endpointHash {
		return "same template family already verified with no new status, input, schema, or response-shape signal"
	}
	return fmt.Sprintf("equivalent template family already verified via %s", shortHash(previousHash))
}

func (a *AnalyzerAgent) lessonValidationSchemaReuseSkipReason(bundle *extract.EndpointBundle) string {
	if a == nil || a.understanding == nil || bundle == nil || bundle.JSONSchema == nil {
		return ""
	}
	if bundle.HasInput || bundle.HasFileUpload || bundle.HTMLExtraction != nil {
		return ""
	}
	if !bundlePathHasLessonLevel(bundle) {
		return ""
	}
	sig := strings.TrimSpace(bundle.InputSignature())
	if sig == "" {
		return ""
	}
	for _, tmpl := range a.understanding.PageTemplates {
		if strings.TrimSpace(tmpl.InputSignature) != sig {
			continue
		}
		if strings.TrimSpace(tmpl.Method) != "" && strings.TrimSpace(bundle.Method) != "" &&
			!strings.EqualFold(strings.TrimSpace(tmpl.Method), strings.TrimSpace(bundle.Method)) {
			continue
		}
		return fmt.Sprintf("same no-input lesson validation schema already analyzed via template %s", firstNonBlank(tmpl.ID, "unknown"))
	}
	return ""
}

func bundlePathHasLessonLevel(bundle *extract.EndpointBundle) bool {
	if bundle == nil {
		return false
	}
	path := firstNonBlank(bundle.URLPattern, bundle.SampleURL)
	if path == "" {
		return false
	}
	if parsed, err := url.Parse(path); err == nil && parsed.Path != "" {
		path = parsed.Path
	} else if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "" {
			continue
		}
		if decoded, err := url.PathUnescape(segment); err == nil {
			segment = decoded
		}
		if isLessonLevelPathSegment(strings.ToLower(strings.TrimSpace(segment))) {
			return true
		}
	}
	return false
}

func (a *AnalyzerAgent) rememberTemplateAnalysisFingerprint(entries []types.TrafficEntry, bundle *extract.EndpointBundle, templateID, endpointHash string) {
	a.rememberTemplateAnalysisFingerprintValue(templateAnalysisFingerprint(entries, bundle, templateID), endpointHash)
}

func (a *AnalyzerAgent) rememberTemplateAnalysisFingerprintValue(fingerprint, endpointHash string) {
	if a.templateFingerprints == nil {
		a.templateFingerprints = make(map[string]string)
	}
	if fingerprint != "" {
		a.templateFingerprints[fingerprint] = endpointHash
	}
}

func analysisFingerprint(entries []types.TrafficEntry, bundle *extract.EndpointBundle) string {
	if len(entries) == 0 || bundle == nil {
		return ""
	}
	return strings.Join(analysisFingerprintParts(entries, bundle, true, ""), "|")
}

func templateAnalysisFingerprint(entries []types.TrafficEntry, bundle *extract.EndpointBundle, templateID string) string {
	if len(entries) == 0 || bundle == nil || strings.TrimSpace(templateID) == "" {
		return ""
	}
	return strings.Join(analysisFingerprintParts(entries, bundle, false, templateID), "|")
}

func analysisFingerprintParts(entries []types.TrafficEntry, bundle *extract.EndpointBundle, includeSource bool, templateID string) []string {
	pathSource := firstNonEmpty(bundle.URLPattern, entries[0].Request.Path)
	pathSource = firstNonEmpty(pathSource, bundle.SampleURL)
	parts := []string{
		"method:" + strings.ToUpper(strings.TrimSpace(bundle.Method)),
		"path:" + canonicalAnalysisPath(pathSource),
		"status:" + statusSignature(bundle.StatusCodes, entries),
		"params:" + paramSignature(bundle),
		"flags:" + boolSignature(bundle.HasAuth, bundle.HasFileUpload, bundle.HasErrors, bundle.IsAPI),
		"content:" + contentTypeSignature(entries),
	}
	if includeSource {
		parts = append(parts, "source:"+sourceIntentSignature(entries))
	}
	if strings.TrimSpace(templateID) != "" {
		parts = append(parts, "template:"+strings.TrimSpace(templateID))
	}
	if bundle.JSONSchema != nil {
		if rendered, err := json.Marshal(bundle.JSONSchema.Shape); err == nil {
			parts = append(parts, "json:"+shortDigest(string(rendered)))
		}
		if len(bundle.JSONSchema.SensitiveFields) > 0 {
			fields := append([]string(nil), bundle.JSONSchema.SensitiveFields...)
			sort.Strings(fields)
			parts = append(parts, "sensitive:"+strings.Join(fields, ","))
		}
	}
	if sig := strings.TrimSpace(bundle.InputSignature()); sig != "" {
		parts = append(parts, "inputsig:"+shortDigest(sig))
	}
	if shape := strings.TrimSpace(bundle.ResponseShapeSignature()); shape != "" {
		parts = append(parts, "responseshape:"+shortDigest(shape))
	}
	return parts
}

func canonicalAnalysisPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	path := raw
	if parsed, err := url.Parse(raw); err == nil {
		if parsed.Path != "" {
			path = parsed.Path
		}
	} else if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if traversal := canonicalTraversalAnalysisPath(path); traversal != "" {
		return traversal
	}
	segments := strings.Split(path, "/")
	taxonomyTail := false
	for i, segment := range segments {
		if segment == "" {
			continue
		}
		decoded, err := url.PathUnescape(segment)
		if err == nil {
			segment = decoded
		}
		lower := strings.ToLower(strings.TrimSpace(segment))
		previous := ""
		if i > 0 {
			previous = strings.ToLower(strings.TrimSpace(segments[i-1]))
		}
		if previous == "tag" || previous == "tags" {
			segments[i] = "{taxonomy}"
			continue
		}
		if previous == "author" || previous == "authors" {
			segments[i] = "{entity}"
			continue
		}
		if previous == "category" || previous == "categories" {
			taxonomyTail = true
		}
		if taxonomyTail {
			if lower == "page" || lower == "index.html" || lower == "index.htm" {
				taxonomyTail = false
			} else {
				segments[i] = "{taxonomy}"
				continue
			}
		}
		switch {
		case strings.HasPrefix(lower, "{") && strings.HasSuffix(lower, "}"):
			segments[i] = "{var}"
		case isLessonLevelPathSegment(lower):
			segments[i] = "{level}"
		case isSignedInteger(lower), looksLikeUUID(lower):
			segments[i] = "{var}"
		case lower == "nan" || lower == "null" || lower == "undefined":
			segments[i] = "{invalid}"
		case looksLikeAttackPayloadSegment(lower):
			segments[i] = "{payload}"
		case looksLikeOpaqueToken(lower):
			segments[i] = "{var}"
		default:
			segments[i] = lower
		}
	}
	return strings.Join(segments, "/")
}

func isLessonLevelPathSegment(segment string) bool {
	for _, prefix := range []string{"level_", "level-", "level"} {
		if strings.HasPrefix(segment, prefix) && allASCIIDigits(segment[len(prefix):]) {
			return true
		}
	}
	return false
}

func allASCIIDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func canonicalTraversalAnalysisPath(path string) string {
	if path == "" {
		return ""
	}
	decoded := path
	for i := 0; i < 2; i++ {
		next, err := url.PathUnescape(decoded)
		if err != nil || next == decoded {
			break
		}
		decoded = next
	}
	decoded = strings.ReplaceAll(decoded, "\\", "/")
	lower := strings.ToLower(decoded)
	segments := strings.Split(lower, "/")
	firstTraversal := -1
	for i, segment := range segments {
		if segment == ".." || segment == "." || strings.Contains(segment, "..") {
			firstTraversal = i
			break
		}
	}
	if firstTraversal < 0 {
		return ""
	}
	prefix := segments[:firstTraversal]
	if len(prefix) == 0 || prefix[0] != "" {
		prefix = append([]string{""}, prefix...)
	}
	for len(prefix) > 1 && prefix[len(prefix)-1] == "" {
		prefix = prefix[:len(prefix)-1]
	}
	return strings.Join(append(prefix, "{path_traversal}"), "/")
}

func looksLikeAttackPayloadSegment(lower string) bool {
	if lower == "" {
		return false
	}
	for _, marker := range []string{
		"<script", "</script", "<iframe", "javascript:", "onerror=", "onload=", "alert(",
		"%3cscript", "%3ciframe", "%22%3e", "' or ", "\" or ", " union select ", "../", "..\\",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func statusSignature(statusCodes []int, entries []types.TrafficEntry) string {
	seen := make(map[int]struct{})
	for _, code := range statusCodes {
		if code > 0 {
			seen[code] = struct{}{}
		}
	}
	for _, entry := range entries {
		if entry.Response.StatusCode > 0 {
			seen[entry.Response.StatusCode] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return "unknown"
	}
	codes := make([]int, 0, len(seen))
	for code := range seen {
		codes = append(codes, code)
	}
	sort.Ints(codes)
	out := make([]string, 0, len(codes))
	for _, code := range codes {
		out = append(out, fmt.Sprintf("%d", code))
	}
	return strings.Join(out, ",")
}

func paramSignature(bundle *extract.EndpointBundle) string {
	if bundle == nil {
		return ""
	}
	parts := make([]string, 0, len(bundle.QueryParams)+len(bundle.BodyParams))
	for _, p := range bundle.QueryParams {
		parts = append(parts, "query:"+strings.ToLower(p.Name)+":"+strings.ToLower(p.Type))
	}
	for _, p := range bundle.BodyParams {
		parts = append(parts, "body:"+strings.ToLower(p.Name)+":"+strings.ToLower(p.Type))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func sourceIntentSignature(entries []types.TrafficEntry) string {
	hypotheses := make(map[string]struct{})
	active := false
	for _, entry := range entries {
		if entry.HypothesisID != "" {
			hypotheses[entry.HypothesisID] = struct{}{}
		}
		switch strings.ToLower(entry.SourceAgent) {
		case "explorer", "verifier", "reasoner", "strategist", "copilot":
			active = true
		}
	}
	if len(hypotheses) > 0 {
		ids := make([]string, 0, len(hypotheses))
		for id := range hypotheses {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		return "hypothesis:" + strings.Join(ids, ",")
	}
	if active {
		return "active"
	}
	return "passive"
}

func contentTypeSignature(entries []types.TrafficEntry) string {
	seen := make(map[string]struct{})
	for _, entry := range entries {
		ct := strings.ToLower(strings.TrimSpace(entry.Response.ContentType))
		if i := strings.Index(ct, ";"); i >= 0 {
			ct = strings.TrimSpace(ct[:i])
		}
		if ct != "" {
			seen[ct] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return "unknown"
	}
	types := make([]string, 0, len(seen))
	for ct := range seen {
		types = append(types, ct)
	}
	sort.Strings(types)
	return strings.Join(types, ",")
}

func boolSignature(values ...bool) string {
	var b strings.Builder
	for _, value := range values {
		if value {
			b.WriteByte('1')
		} else {
			b.WriteByte('0')
		}
	}
	return b.String()
}

func isSignedInteger(s string) bool {
	if s == "" {
		return false
	}
	if s[0] == '-' || s[0] == '+' {
		s = s[1:]
	}
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
				return false
			}
		}
	}
	return true
}

func looksLikeOpaqueToken(s string) bool {
	if len(s) < 24 {
		return false
	}
	var alnum int
	for _, r := range s {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || r == '_' || r == '-' {
			alnum++
			continue
		}
		return false
	}
	return alnum >= 24
}

func shortDigest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum[:8])
}

func shortHash(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:8]
}

func staticResourceHasServerFailure(entries []types.TrafficEntry) bool {
	for _, entry := range entries {
		if entry.Response.StatusCode >= 500 {
			return true
		}
	}
	return false
}

func hasSocketIOPathSegment(lowerPath string) bool {
	for _, segment := range strings.Split(lowerPath, "/") {
		if segment == "socket.io" {
			return true
		}
	}
	return false
}

func hasSyntheticInvalidRouteSegment(lowerPath string) bool {
	for _, segment := range strings.Split(lowerPath, "/") {
		switch segment {
		case "unknown", "unknownpath", "not-found", "notfound", "nonexistent", "does-not-exist":
			return true
		}
	}
	return false
}

func isPassiveStaticResource(lowerPath string) bool {
	for _, suffix := range []string{
		".js", ".mjs", ".css", ".map",
		".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
		".woff", ".woff2", ".ttf", ".eot",
		".mp3", ".mp4", ".webm",
	} {
		if strings.HasSuffix(lowerPath, suffix) {
			return true
		}
	}
	if isPassiveRootDocumentationResource(lowerPath) {
		return true
	}
	return isPassivePublicArtifactPath(lowerPath)
}

func allBoringCanonicalRedirects(entries []types.TrafficEntry) bool {
	if len(entries) == 0 {
		return false
	}
	for _, entry := range entries {
		if !boringCanonicalRedirect(entry) {
			return false
		}
	}
	return true
}

func boringCanonicalRedirect(entry types.TrafficEntry) bool {
	status := entry.Response.StatusCode
	if status < 300 || status > 399 {
		return false
	}
	location := strings.TrimSpace(headerValue(entry.Response.Headers, "Location"))
	if location == "" {
		return false
	}
	from, err := url.Parse(entry.Request.URL)
	if err != nil || from.Scheme == "" || from.Host == "" {
		return false
	}
	to, err := url.Parse(location)
	if err != nil {
		return false
	}
	if !to.IsAbs() {
		to = from.ResolveReference(to)
	}
	fromOrigin, fromOriginErr := policy.CanonicalOrigin(from.String())
	toOrigin, toOriginErr := policy.CanonicalOrigin(to.String())
	if fromOriginErr != nil || toOriginErr != nil || fromOrigin != toOrigin {
		return false
	}
	if from.RawQuery != to.RawQuery {
		return false
	}
	fromPath := strings.TrimRight(from.EscapedPath(), "/")
	toPath := strings.TrimRight(to.EscapedPath(), "/")
	if fromPath == "" {
		fromPath = "/"
	}
	if toPath == "" {
		toPath = "/"
	}
	return fromPath == toPath
}

func isPassiveRootDocumentationResource(lowerPath string) bool {
	path := strings.TrimSpace(lowerPath)
	if path == "" {
		return false
	}
	if parsed, err := url.Parse(path); err == nil && parsed.Path != "" {
		path = parsed.Path
	}
	if decoded, err := url.PathUnescape(path); err == nil {
		path = strings.ToLower(decoded)
	}
	path = strings.Trim(path, "/")
	if path == "" || strings.Contains(path, "/") {
		return false
	}
	for _, prefix := range []string{"readme", "license", "licence", "changelog", "changes", "contributing", "authors", "credits", "install", "installation"} {
		if strings.HasPrefix(path, prefix+".") || strings.HasPrefix(path, prefix+"-") || strings.HasPrefix(path, prefix+"_") {
			return true
		}
	}
	for _, exact := range []string{"license", "licence", "copying", "notice"} {
		if path == exact {
			return true
		}
	}
	return false
}

func isPassivePublicArtifactPath(lowerPath string) bool {
	path := strings.TrimSpace(lowerPath)
	if path == "" {
		return false
	}
	if parsed, err := url.Parse(path); err == nil && parsed.Path != "" {
		path = parsed.Path
	}
	if decoded, err := url.PathUnescape(path); err == nil {
		path = strings.ToLower(decoded)
	}
	if decoded, err := url.PathUnescape(path); err == nil {
		path = strings.ToLower(decoded)
	}
	if i := strings.IndexByte(path, 0); i >= 0 {
		path = path[:i]
	}
	for _, marker := range []string{"%00", "%2500"} {
		if i := strings.Index(path, marker); i >= 0 {
			path = path[:i]
		}
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	inPublicArtifactArea := false
	for _, prefix := range []string{
		"/ftp/", "/files/", "/file/", "/download/", "/downloads/",
		"/assets/", "/public/", "/static/", "/uploads/", "/upload/",
		"/backup/", "/backups/", "/logs/", "/docs/", "/documentation/",
	} {
		if strings.HasPrefix(path, prefix) {
			inPublicArtifactArea = true
			break
		}
	}
	if !inPublicArtifactArea {
		return false
	}
	for _, suffix := range []string{
		".md", ".markdown", ".txt", ".log", ".csv", ".tsv",
		".yml", ".yaml", ".xml", ".pdf", ".doc", ".docx",
		".bak", ".backup", ".old", ".orig", ".swp", ".swo",
		".zip", ".tar", ".gz", ".tgz", ".7z", ".rar",
	} {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}

func (a *AnalyzerAgent) templateVerify(ctx context.Context, bundle *extract.EndpointBundle, templateID string) (*types.PageProfile, error) {
	bundleContext := llm.BuildBundleContext(bundle)
	appContext := llm.BuildAppUnderstandingContext(a.understanding)

	userPrompt := fmt.Sprintf(`This endpoint appears to match template "%s".
Verify the match and flag any differences.

%s

%s

Respond with the verification JSON.`,
		templateID, appContext, bundleContext)

	totalPrompt := prompts.TemplateVerifyPrompt + userPrompt
	estimatedTokens := a.provider.CountTokens(totalPrompt)

	if !a.budget.CanSpend(estimatedTokens) {
		return nil, nil
	}

	a.logger.Info("LLM template verify",
		"template", templateID,
		"estimated_tokens", estimatedTokens,
	)

	// Narrate: template match check
	a.db.InsertNarration(a.scanID, "analyzer", "template_check",
		fmt.Sprintf("This looks like the '%s' template — quick check for anything new.", templateID),
		bundle.SampleURL, nil)

	start := time.Now()
	req := &llm.Request{
		SystemPrompt: prompts.TemplateVerifyPrompt,
		Messages: []llm.Message{
			{Role: "user", Content: userPrompt},
		},
		Temperature: 0.1,
		MaxTokens:   llm.StructuredOutputTokenLimit(a.provider, 1024, 4096),
		JSONMode:    true,
	}
	resp, err := llm.CompleteBudgeted(ctx, a.provider, a.budget, req, estimatedTokens)
	durationMs := time.Since(start).Milliseconds()
	if err != nil {
		return nil, err
	}

	modelID := llm.ResponseModel(resp, a.provider)
	costUcents := llm.CostMicroCents(modelID, resp.Usage)

	// AI-log detail — the labelled URL pattern is enough on its own.
	// The internal templateID (e.g. "get_tr-tr_ipad") is still stored
	// in the profile + understanding maps for clustering, but it
	// doesn't belong in user-facing detail text — the human label IS
	// the human-readable identifier we want here.
	a.db.LogAIFull(a.scanID, "analyzer", "template_verify",
		fmt.Sprintf("%s %s", bundle.Method, bundle.URLPattern),
		"", bundle.SampleURL, "",
		resp.Usage.InputTokens, resp.Usage.OutputTokens, durationMs, costUcents, modelID,
		llm.RenderPrompt(req), resp.Content)

	// Narrate the LLM's own thought on the match
	if thought := extractNarration(resp.Content); thought != "" {
		a.db.InsertNarration(a.scanID, "analyzer", "thought", thought, bundle.SampleURL, nil)
	}

	// Parse verification response
	var verification struct {
		TemplateMatch bool     `json:"template_match"`
		ID            string   `json:"id"`
		URL           string   `json:"url"`
		Method        string   `json:"method"`
		Purpose       string   `json:"purpose"`
		TemplateID    string   `json:"template_id"`
		NewIssues     []string `json:"new_issues"`
		Confidence    float64  `json:"confidence"`
		Reason        string   `json:"reason"`
	}

	content := extractJSON(resp.Content)
	if err := json.Unmarshal([]byte(content), &verification); err != nil {
		// Preserve a bounded preview of the actual content so we can see
		// what MiniMax / other models emit on failure. Without this the
		// only signal is a generic "unexpected end of JSON input" which
		// tells us nothing. Bounded at 400 chars since TemplateVerify
		// responses are typically short.
		preview := content
		if preview == "" {
			preview = resp.Content
		}
		if len(preview) > 400 {
			preview = preview[:400] + "…"
		}
		a.logger.Warn("failed to parse verification response",
			"error", err,
			"content_length", len(resp.Content),
			"content_preview", preview)
		// Fall back to full analysis — better to double-pay the tokens than
		// drop the endpoint's profile entirely. TemplateVerify is a cost
		// optimization; failing to it should degrade gracefully, not silently
		// skip the endpoint.
		a.logger.Info("template-verify failed, falling back to full analysis",
			"template", templateID)
		return a.fullAnalysis(ctx, bundle)
	}

	if !verification.TemplateMatch {
		// Template doesn't actually match — do full analysis
		a.logger.Info("template mismatch, doing full analysis", "reason", verification.Reason)
		return a.fullAnalysis(ctx, bundle)
	}

	// Build a profile from the verification
	profile := &types.PageProfile{
		ID:         verification.ID,
		URL:        verification.URL,
		Method:     verification.Method,
		Purpose:    verification.Purpose,
		Issues:     verification.NewIssues,
		Confidence: verification.Confidence,
		TemplateID: templateID,
	}

	if profile.ID == "" {
		profile.ID = fmt.Sprintf("%s %s", bundle.Method, bundle.URLPattern)
	}
	if profile.URL == "" {
		profile.URL = bundle.SampleURL
	}
	if profile.Method == "" {
		profile.Method = bundle.Method
	}

	return profile, nil
}

// storeExtractedInputs saves the zero-cost extracted inputs into the profile immediately.
// Every input gets its Label + Explanation populated via extract.ExplainInput so
// the UI can render "what does this input do?" without spending an LLM call.
func (a *AnalyzerAgent) storeExtractedInputs(bundle *extract.EndpointBundle, entries []types.TrafficEntry) {
	inputs := extractInputsFromBundle(bundle)

	// Store as ExtractedInputs in the profile
	profileID := fmt.Sprintf("%s %s", bundle.Method, bundle.URLPattern)
	if existing, err := a.db.GetProfile(a.scanID, profileID); err == nil {
		if len(inputs) == 0 {
			// Preserve the old no-input fast path for substantive pages, while
			// still allowing newly observed negative/shell evidence to retire an
			// already persisted semantic profile.
			a.applyAnalyzerProfileEvidenceCeiling(existing, entries)
			if strings.HasSuffix(strings.ToLower(strings.TrimSpace(existing.EvidenceState)), "_unverified") {
				_ = a.upsertEvidenceBoundProfile(existing)
			}
			return
		}
		// A convergence pass can revisit an endpoint after its LLM profile was
		// already written. Union newly observed zero-cost inputs and flags, then
		// apply the same response ceiling used by final model output. Substantive
		// content preserves prior semantics; non-content evidence deliberately
		// removes claims that cannot remain persisted.
		seen := make(map[string]bool, len(existing.ExtractedInputs)+len(inputs))
		mergedInputs := make([]types.Input, 0, len(existing.ExtractedInputs)+len(inputs))
		for _, input := range append(existing.ExtractedInputs, inputs...) {
			key := input.Name + "\x00" + input.Location + "\x00" + input.Type
			if seen[key] {
				continue
			}
			seen[key] = true
			mergedInputs = append(mergedInputs, input)
		}
		existing.ExtractedInputs = mergedInputs
		existing.HasInput = existing.HasInput || bundle.HasInput || len(mergedInputs) > 0
		existing.HasFileUpload = existing.HasFileUpload || bundle.HasFileUpload
		existing.HasAuth = existing.HasAuth || bundle.HasAuth
		existing.HasErrors = existing.HasErrors || bundle.HasErrors
		existing.IsAPI = existing.IsAPI || bundle.IsAPI
		if existing.Confidence < 0.1 {
			existing.Confidence = 0.1
		}
		a.applyAnalyzerProfileEvidenceCeiling(existing, entries)
		_ = a.upsertEvidenceBoundProfile(existing)
		return
	}
	if len(inputs) == 0 {
		return
	}
	profile := &types.PageProfile{
		ID:              profileID,
		URL:             bundle.SampleURL,
		Method:          bundle.Method,
		ExtractedInputs: inputs,
		Confidence:      0.1, // low confidence until LLM analyzes
		HasInput:        bundle.HasInput,
		HasFileUpload:   bundle.HasFileUpload,
		HasAuth:         bundle.HasAuth,
		HasErrors:       bundle.HasErrors,
		IsAPI:           bundle.IsAPI,
	}

	a.applyAnalyzerProfileEvidenceCeiling(profile, entries)
	_ = a.upsertEvidenceBoundProfile(profile)
}

// extractInputsFromBundle flattens the bundle's HTML forms + standalone
// inputs + hidden fields + query/body params into a single []Input slice
// with Label + Explanation populated. Used by both storeExtractedInputs
// (pre-LLM snapshot) and mergeProfile (post-LLM merge) so both paths
// share the same enrichment logic.
func extractInputsFromBundle(bundle *extract.EndpointBundle) []types.Input {
	var inputs []types.Input

	appendInput := func(name, inpType, location, label, placeholder, defaultValue string, required bool) {
		inputs = append(inputs, types.Input{
			Name:         name,
			Type:         inpType,
			Location:     location,
			Required:     required,
			DefaultValue: defaultValue,
			Label:        label,
			Explanation:  extract.ExplainInput(name, inpType, location, label, placeholder),
		})
	}

	if bundle.HTMLExtraction != nil {
		for _, form := range bundle.HTMLExtraction.Forms {
			for _, inp := range form.Inputs {
				appendInput(inp.Name, inp.Type, "form", inp.Label, inp.Placeholder, inp.Value, inp.Required)
			}
		}
		for _, inp := range bundle.HTMLExtraction.StandaloneInputs {
			appendInput(inp.Name, inp.Type, "form", inp.Label, inp.Placeholder, inp.Value, inp.Required)
		}
		for _, inp := range bundle.HTMLExtraction.HiddenFields {
			appendInput(inp.Name, "hidden", "form", inp.Label, inp.Placeholder, inp.Value, false)
		}
	}

	for _, p := range bundle.QueryParams {
		appendInput(p.Name, p.Type, "query", "", "", "", p.Required)
	}
	for _, p := range bundle.BodyParams {
		appendInput(p.Name, p.Type, "body", "", "", "", p.Required)
	}

	return inputs
}

// mergeProfile combines the LLM-generated profile with extracted data.
func (a *AnalyzerAgent) mergeProfile(llmProfile *types.PageProfile, bundle *extract.EndpointBundle) *types.PageProfile {
	// Start with LLM profile
	merged := *llmProfile

	// Ground endpoint identity in observed traffic, not model prose. The LLM
	// may describe purpose/issues, but it must not rewrite a concrete endpoint
	// like /openapi.json into a phantom /openapi. path. If path-label
	// refinement improved the bundle pattern, that improved-but-observed
	// pattern is already in bundle.URLPattern.
	merged.ID = fmt.Sprintf("%s %s", bundle.Method, bundle.URLPattern)
	merged.URL = bundle.SampleURL
	merged.Method = bundle.Method
	merged.HasInput = bundle.HasInput
	merged.HasFileUpload = bundle.HasFileUpload
	merged.HasAuth = bundle.HasAuth
	merged.HasErrors = bundle.HasErrors
	merged.IsAPI = bundle.IsAPI

	// Build extracted inputs list — same enrichment as storeExtractedInputs
	// so both pre-LLM and post-LLM profiles carry Label + Explanation.
	extractedInputs := extractInputsFromBundle(bundle)

	merged.ExtractedInputs = extractedInputs

	// Merge: union of LLM inputs and extracted inputs (extracted wins for
	// completeness AND for enrichment — the LLM often returns a bare name
	// without the Explanation heuristic we already computed). If the LLM
	// genuinely adds an input we didn't extract (JS-only, dynamic), keep
	// its version but still fill a heuristic explanation if it didn't.
	inputMap := make(map[string]types.Input)
	for _, inp := range extractedInputs {
		key := inp.Name + ":" + inp.Location
		inputMap[key] = inp
	}
	for _, inp := range llmProfile.Inputs {
		key := inp.Name + ":" + inp.Location
		if _, exists := inputMap[key]; !exists {
			if inp.Explanation == "" {
				inp.Explanation = extract.ExplainInput(inp.Name, inp.Type, inp.Location, inp.Label, "")
			}
			inputMap[key] = inp
		}
	}

	merged.Inputs = make([]types.Input, 0, len(inputMap))
	for _, inp := range inputMap {
		merged.Inputs = append(merged.Inputs, inp)
	}

	// Add JSON schema info to data_exposed if present
	if bundle.JSONSchema != nil && len(bundle.JSONSchema.SensitiveFields) > 0 {
		for _, sf := range bundle.JSONSchema.SensitiveFields {
			merged.DataExposed = append(merged.DataExposed, "field: "+sf)
		}
		merged.DataExposed = deduplicateStrings(merged.DataExposed)
	}

	return &merged
}

func (a *AnalyzerAgent) loadUnderstanding() {
	appType, templatesJSON, areasJSON, hashesJSON, summary, err := a.db.GetAppUnderstanding(a.scanID)
	if err != nil {
		a.understanding = extract.NewAppUnderstanding()
		return
	}
	a.understanding = extract.LoadAppUnderstanding(appType, templatesJSON, areasJSON, hashesJSON, summary)
	if reconJSON, reconErr := a.db.GetReconModel(a.scanID); reconErr == nil {
		a.understanding.LoadReconJSON(reconJSON)
	}
	a.state.SetAppUnderstanding(a.understanding)
}

// refineBundleURLPattern asks the shared resolver to label the
// bundle's URL pattern. The bundle already carries the cluster's
// per-position sample values (computed by extract.buildCorpusTemplate
// when the bundle was built); we synthesize a representative path per
// example value so the resolver can align positions and produce a
// labelled template like "/api/{lang}/products" or
// "/butik/liste/{boutique_id}/{gender}".
//
// No-op when no resolver is wired or when the bundle's pattern has
// no variable positions to label.
func (a *AnalyzerAgent) refineBundleURLPattern(ctx context.Context, bundle *extract.EndpointBundle) {
	if a.pathLabel == nil || bundle == nil {
		return
	}
	// Synthesize sample paths from the bundle's skeleton + per-position
	// distinct values. We need raw paths because that's what the
	// resolver's API expects; the synthesis is faithful to what the
	// crawler actually saw because SegmentSamples carries the observed
	// values (capped at 5/position by buildCorpusTemplate).
	samples := synthesizeSamplePaths(bundle)
	if len(samples) == 0 {
		// Single-observation bundle (or no variable positions). Use
		// the SampleURL so the resolver can still label literals.
		if bundle.SampleURL != "" {
			samples = []string{bundle.SampleURL}
		} else {
			return
		}
	}

	host := ""
	if bundle.SampleURL != "" {
		// Extract host without pulling in net/url at the top level —
		// the path-label LabelContext just needs a string.
		host = hostFromURL(bundle.SampleURL)
	}

	contentType := ""
	for k, v := range bundle.ResponseHeaders {
		if strings.EqualFold(k, "content-type") {
			contentType = v
			break
		}
	}

	label := a.pathLabel.Label(ctx, samples, pathlabel.LabelContext{
		Host:        host,
		Method:      bundle.Method,
		ContentType: contentType,
		Discovery:   "analyzer-cluster",
	})
	if label.Display != "" && label.Display != bundle.URLPattern {
		a.logger.Info("path label refined",
			"before", bundle.URLPattern,
			"after", label.Display,
			"source", label.Source,
		)
		bundle.URLPattern = label.Display
	}
	// Copy per-position metadata onto the bundle so the UI can render
	// hoverable chips (variable positions show their LLM reason +
	// observed example values on hover). Empty when the resolver
	// didn't have segment data — UI falls back to plain text.
	if len(label.Segments) > 0 {
		bundle.URLSegments = make([]extract.BundleSegmentLabel, len(label.Segments))
		for i, s := range label.Segments {
			bundle.URLSegments[i] = extract.BundleSegmentLabel{
				Position: s.Position,
				Kind:     s.Kind,
				Label:    s.Label,
				Examples: s.Examples,
				Reason:   s.Reason,
			}
		}
	}
}

// synthesizeSamplePaths reconstructs raw paths from the bundle's
// skeleton + per-position samples. For a skeleton "/api/{seg}/products"
// with samples [["en","tr","de"]], returns ["/api/en/products",
// "/api/tr/products", "/api/de/products"].
//
// The reconstruction lets the resolver re-derive a corpus template
// and decide which positions are stable vs. variable, even though we
// only have aggregated samples (not the original raw URLs) at this
// layer. This is faithful enough for labelling because the resolver
// only cares about distinct values per position.
func synthesizeSamplePaths(bundle *extract.EndpointBundle) []string {
	if len(bundle.SegmentSamples) == 0 || len(bundle.SegmentPositions) == 0 {
		return nil
	}
	if len(bundle.SegmentSamples) != len(bundle.SegmentPositions) {
		return nil
	}
	// Walk the skeleton's segments. For every variable position
	// (matching one of bundle.SegmentPositions) substitute one example
	// at a time and keep the literal segments otherwise.
	skelSegs := strings.Split(bundle.URLPattern, "/")
	maxSamples := 1
	for _, s := range bundle.SegmentSamples {
		if len(s) > maxSamples {
			maxSamples = len(s)
		}
	}
	if maxSamples > 5 {
		maxSamples = 5
	}
	out := make([]string, 0, maxSamples)
	for i := 0; i < maxSamples; i++ {
		segs := make([]string, len(skelSegs))
		copy(segs, skelSegs)
		for j, pos := range bundle.SegmentPositions {
			if pos < 0 || pos >= len(segs) {
				continue
			}
			vals := bundle.SegmentSamples[j]
			if len(vals) == 0 {
				continue
			}
			// Cycle through samples — if one position has 5 distinct
			// values and another has 2, the second repeats. The
			// resolver only cares about distinct values per position
			// after deduping, so this is fine.
			segs[pos] = vals[i%len(vals)]
		}
		out = append(out, strings.Join(segs, "/"))
	}
	return out
}

// hostFromURL extracts a host without pulling net/url into call
// sites that don't need it. Tolerates path-only inputs (returns "").
func hostFromURL(s string) string {
	const httpsPrefix = "https://"
	const httpPrefix = "http://"
	rest := ""
	if strings.HasPrefix(s, httpsPrefix) {
		rest = s[len(httpsPrefix):]
	} else if strings.HasPrefix(s, httpPrefix) {
		rest = s[len(httpPrefix):]
	} else {
		return ""
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		return rest[:i]
	}
	return rest
}

func (a *AnalyzerAgent) saveUnderstanding() {
	if a.understanding == nil {
		return
	}
	if profiles, err := a.db.GetAllProfiles(a.scanID); err == nil {
		a.understanding.RefreshPagePurposeCards(profiles)
	}
	templatesJSON, areasJSON, hashesJSON := a.understanding.Serialize()
	a.db.UpsertAppUnderstanding(a.scanID,
		a.understanding.AppType,
		templatesJSON, areasJSON, hashesJSON,
		a.understanding.Summary,
	)
	_ = a.db.UpsertReconModel(a.scanID, a.understanding.ReconJSON())
	a.state.SetAppUnderstanding(a.understanding)
}

// harvestFollowUps parses any "follow_ups" array from the analyzer's LLM
// response and queues each as a pending task. A single narration summarizes
// the batch so the user sees what's about to be explored.
func (a *AnalyzerAgent) harvestFollowUps(content, sourceProfileID string) {
	type followUpJSON struct {
		Action      string   `json:"action"`
		URL         string   `json:"url"`
		URLTemplate string   `json:"url_template"` // used by probe_idor for path substitution
		Param       string   `json:"param"`
		Values      []string `json:"values"`
		Field       string   `json:"field"`       // probe_logic: which body/form field to mutate
		TestValues  []string `json:"test_values"` // probe_logic: values to try
		Reason      string   `json:"reason"`
		// Catch-all for unexpected fields — we stash them in params
		Extra map[string]any `json:"-"`
	}
	type bag struct {
		Method string `json:"method"`
		Inputs []struct {
			Name     string `json:"name"`
			Location string `json:"location"`
		} `json:"inputs"`
		FollowUps []followUpJSON `json:"follow_ups"`
	}

	var b bag
	if err := json.Unmarshal([]byte(content), &b); err != nil {
		cleaned := extractJSON(content)
		if cleaned != content {
			_ = json.Unmarshal([]byte(cleaned), &b)
		}
	}
	if len(b.FollowUps) == 0 {
		return
	}

	// Cap at 5 per analysis to avoid a single rogue response flooding the queue.
	if len(b.FollowUps) > 5 {
		b.FollowUps = b.FollowUps[:5]
	}

	var queued int
	var samples []string
	inputLocations := make(map[string]string, len(b.Inputs))
	for _, input := range b.Inputs {
		inputLocations[strings.ToLower(strings.TrimSpace(input.Name))] = strings.ToLower(strings.TrimSpace(input.Location))
	}
	method := strings.ToUpper(strings.TrimSpace(b.Method))
	for _, fu := range b.FollowUps {
		if fu.Action == "" {
			continue
		}
		if (fu.Action == "probe_logic" && businessLogicFieldIsCSRFToken(fu.Field)) ||
			(fu.Action == "probe_param" && businessLogicFieldIsCSRFToken(fu.Param)) {
			a.logger.Debug("rejecting token/anti-forgery follow_up as business-logic probe",
				"action", fu.Action, "url", fu.URL, "field", firstNonEmpty(fu.Field, fu.Param), "reason", fu.Reason)
			continue
		}
		if fu.Action == "probe_logic" && businessLogicFieldIsTransportControl(fu.Field) {
			a.logger.Debug("rejecting transport/header follow_up as business-logic probe",
				"action", fu.Action, "url", fu.URL, "field", fu.Field, "reason", fu.Reason)
			continue
		}
		// probe_logic mutates request bodies/forms. Local models sometimes
		// select it for a GET query parameter. Convert that plan to the
		// query-aware primitive; a read-only request cannot carry a body
		// mutation, but the planner's intent ("try this field with these
		// values") is still executable as a query-param probe.
		if fu.Action == "probe_logic" {
			location := inputLocations[strings.ToLower(strings.TrimSpace(fu.Field))]
			if location == "query" || (method == "GET" || method == "HEAD" || method == "OPTIONS") {
				fu.Action = "probe_param"
				fu.Param = fu.Field
				fu.Values = append([]string(nil), fu.TestValues...)
				fu.Field = ""
				fu.TestValues = nil
			}
		}
		if !validFollowUpAction(fu.Action) {
			a.logger.Debug("rejecting unknown follow_up action",
				"action", fu.Action, "reason", fu.Reason)
			continue
		}
		targetForGrounding := firstNonEmpty(fu.URL, fu.URLTemplate)
		if strings.TrimSpace(targetForGrounding) == "" {
			a.logger.Debug("rejecting follow_up with no target URL",
				"action", fu.Action, "reason", fu.Reason)
			continue
		}
		if followUpTargetsBenchmarkMetadata(targetForGrounding) {
			a.logger.Debug("rejecting benchmark metadata/index follow_up target",
				"action", fu.Action, "url", targetForGrounding, "reason", fu.Reason)
			continue
		}
		if followUpTargetsPublicStaticAsset(targetForGrounding) &&
			(fu.Action == "probe_param" || fu.Action == "probe_idor" || fu.Action == "probe_logic") {
			a.logger.Debug("rejecting active probe against public/static asset follow_up target",
				"action", fu.Action, "url", targetForGrounding, "reason", fu.Reason)
			continue
		}
		if (fu.Action == "fetch" || fu.Action == "visit" || fu.Action == "reanalyze") && !followUpTargetLooksGrounded(targetForGrounding) {
			a.logger.Debug("rejecting synthetic-looking follow_up target",
				"action", fu.Action, "url", targetForGrounding, "reason", fu.Reason)
			continue
		}
		if (fu.Action == "fetch" || fu.Action == "visit" || fu.Action == "reanalyze") && followUpTargetContainsPlaceholder(targetForGrounding) {
			a.logger.Debug("rejecting placeholder follow_up target outside a probe template",
				"action", fu.Action, "url", targetForGrounding, "reason", fu.Reason)
			continue
		}
		if fu.Action == "fetch" && followUpFetchLooksLikeAttackProbe(fu.URL) {
			a.logger.Debug("rejecting payload-bearing fetch follow_up; use a probe/visit primitive instead",
				"url", fu.URL, "reason", fu.Reason)
			continue
		}
		if fu.Action == "probe_param" && followUpUploadExecutableProbeLooksNoisy(fu.URL, fu.Param, fu.Values) {
			a.logger.Debug("rejecting executable upload follow_up; verifier owns benign upload validation",
				"url", fu.URL, "param", fu.Param, "reason", fu.Reason)
			continue
		}
		if (fu.Action == "fetch" || fu.Action == "visit" || fu.Action == "reanalyze") && a.followUpTargetAlreadyObserved(targetForGrounding) {
			a.logger.Debug("rejecting already-observed follow_up target",
				"action", fu.Action, "url", targetForGrounding, "reason", fu.Reason)
			continue
		}
		if fu.Action == "probe_idor" {
			fu.Values = cleanIDORProbeValues(fu.Values)
			if len(fu.Values) < 2 {
				a.logger.Debug("rejecting probe_idor follow_up with no usable scalar identifiers",
					"url_template", fu.URLTemplate, "reason", fu.Reason)
				continue
			}
			target := firstNonEmpty(fu.URLTemplate, fu.URL)
			if !strings.Contains(target, "{id}") {
				a.logger.Debug("rejecting probe_idor follow_up without {id} placeholder",
					"url_template", fu.URLTemplate, "url", fu.URL, "reason", fu.Reason)
				continue
			}
			if !idorPlaceholderLooksScalar(target) || !idorTargetLooksOwnedObject(target, fu.Param, fu.Field) {
				a.logger.Debug("rejecting probe_idor follow_up without owned-object target",
					"url_template", fu.URLTemplate, "url", fu.URL, "reason", fu.Reason)
				continue
			}
		}
		if fu.Action == "probe_param" && reasonMentionsAccessControl(fu.Reason) &&
			!idorTargetLooksOwnedObject(fu.URL, fu.Param, fu.Field) {
			a.logger.Debug("rejecting access-control probe_param without owned-object target",
				"url", fu.URL, "param", fu.Param, "reason", fu.Reason)
			continue
		}
		if fu.Action == "probe_param" && (strings.TrimSpace(fu.Param) == "" || len(fu.Values) == 0) {
			a.logger.Debug("rejecting incomplete probe_param follow_up",
				"url", fu.URL, "param", fu.Param, "values", len(fu.Values), "reason", fu.Reason)
			continue
		}
		if fu.Action == "probe_logic" && (strings.TrimSpace(fu.Field) == "" || len(fu.TestValues) == 0) {
			a.logger.Debug("rejecting incomplete probe_logic follow_up",
				"url", fu.URL, "field", fu.Field, "test_values", len(fu.TestValues), "reason", fu.Reason)
			continue
		}
		// Build params payload — whatever's specific to this action kind.
		params := map[string]any{}
		if fu.Param != "" {
			params["param"] = fu.Param
		}
		if len(fu.Values) > 0 {
			params["values"] = fu.Values
		}
		if fu.URLTemplate != "" {
			params["url_template"] = fu.URLTemplate
		}
		if fu.Field != "" {
			params["field"] = fu.Field
		}
		if len(fu.TestValues) > 0 {
			params["test_values"] = fu.TestValues
		}

		// probe_idor uses url_template as the target — if the LLM put it in
		// url_template, use that as the URL field for queue/display purposes.
		urlField := fu.URL
		if urlField == "" && fu.URLTemplate != "" {
			urlField = fu.URLTemplate
		}

		id, err := a.db.InsertFollowUp(a.scanID, store.FollowUp{
			SourceAgent:     "analyzer",
			SourceProfileID: sourceProfileID,
			Action:          fu.Action,
			URL:             urlField,
			Params:          params,
			Reason:          fu.Reason,
			Priority:        priorityForAction(fu.Action),
		})
		if err != nil {
			a.logger.Debug("failed to queue follow_up", "error", err, "url", fu.URL)
			continue
		}
		if id > 0 {
			queued++
			if len(samples) < 3 {
				samples = append(samples, describeFollowUp(fu))
			}
		}
	}

	if queued == 0 {
		return
	}

	summary := fmt.Sprintf("Queued %d follow-up task(s): %s",
		queued, strings.Join(samples, "; "))
	a.db.InsertNarration(a.scanID, "analyzer", "queued_followups",
		summary, "", map[string]any{"count": queued})
	a.logger.Info("queued follow-ups", "count", queued)
}

func followUpTargetsBenchmarkMetadata(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	target := raw
	if parsed, err := url.Parse(raw); err == nil {
		target = parsed.Path
	}
	return isBenchmarkMetadataPath(strings.ToLower(target))
}

func businessLogicFieldIsTransportControl(field string) bool {
	field = strings.ToLower(strings.TrimSpace(field))
	field = strings.ReplaceAll(field, "-", "_")
	switch field {
	case "method", "_method", "method_override", "http_method", "x_http_method_override",
		"content_type", "contenttype", "accept", "host", "origin", "referer", "user_agent":
		return true
	default:
		return false
	}
}

func followUpUploadExecutableProbeLooksNoisy(rawURL string, param string, values []string) bool {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	path := strings.ToLower(strings.TrimSpace(rawURL))
	if err == nil {
		path = strings.ToLower(parsed.Path)
	}
	if !strings.Contains(path, "upload") {
		return false
	}
	param = strings.ToLower(strings.TrimSpace(param))
	switch param {
	case "file", "filename", "file_name", "upload", "attachment", "document", "image":
	default:
		return false
	}
	for _, value := range values {
		lower := strings.ToLower(strings.TrimSpace(value))
		if decoded, err := url.QueryUnescape(lower); err == nil {
			lower = decoded
		}
		for _, marker := range []string{".php", ".phtml", ".jsp", ".jspx", ".asp", ".aspx", ".html", ".svg", ".sh", "webshell", "shell"} {
			if strings.Contains(lower, marker) {
				return true
			}
		}
	}
	return false
}

func (a *AnalyzerAgent) followUpTargetAlreadyObserved(raw string) bool {
	if a == nil || a.db == nil || a.scanID == 0 {
		return false
	}
	for _, candidate := range followUpObservedURLCandidates(raw) {
		var n int
		err := a.db.Conn().QueryRow(`
			SELECT COUNT(*)
			FROM traffic
			WHERE scan_id = ?
			  AND url = ?
			  AND is_filtered = FALSE
			  AND status_code < 400`, a.scanID, candidate).Scan(&n)
		if err == nil && n > 0 {
			return true
		}
	}
	return false
}

func followUpObservedURLCandidates(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	add(raw)
	parsed, err := url.Parse(raw)
	if err != nil {
		return out
	}
	parsed.Fragment = ""
	add(parsed.String())
	if parsed.RawQuery == "" && parsed.Path != "" && parsed.Path != "/" {
		without := *parsed
		without.Path = strings.TrimRight(without.Path, "/")
		if without.Path == "" {
			without.Path = "/"
		}
		add(without.String())
		with := *parsed
		if !strings.HasSuffix(with.Path, "/") {
			with.Path += "/"
		}
		add(with.String())
	}
	return out
}

func followUpTargetContainsPlaceholder(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	parsed, err := url.Parse(raw)
	target := raw
	if err == nil {
		target = parsed.Path
		if parsed.RawQuery != "" {
			target += "?" + parsed.RawQuery
		}
	}
	return strings.Contains(target, "{") || strings.Contains(target, "}")
}

func followUpFetchLooksLikeAttackProbe(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	check := func(value string) bool {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			return false
		}
		if decoded, err := url.QueryUnescape(value); err == nil {
			value = strings.ToLower(decoded)
		}
		return looksLikeAttackPayloadSegment(value)
	}
	if check(raw) {
		return true
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if check(parsed.Path) || check(parsed.RawQuery) {
		return true
	}
	for key, values := range parsed.Query() {
		if check(key) {
			return true
		}
		for _, value := range values {
			if check(value) {
				return true
			}
		}
	}
	return false
}

// validFollowUpAction keeps the analyzer honest — only recognized actions
// make it into the queue.
func validFollowUpAction(a string) bool {
	switch a {
	case "fetch", "visit", "probe_param", "probe_idor", "probe_logic", "reanalyze":
		return true
	}
	return false
}

// priorityForAction ranks task types so quick/cheap ones run first.
func priorityForAction(action string) int {
	switch action {
	case "probe_idor":
		return 7 // highest-signal authorization probe
	case "probe_logic":
		return 6 // business-logic probes — same tier of demo value
	case "fetch":
		return 5
	case "probe_param":
		return 4
	case "visit":
		return 3
	case "reanalyze":
		return 1
	}
	return 0
}

// describeFollowUp returns a short human summary for the batch narration.
func describeFollowUp(fu struct {
	Action      string         `json:"action"`
	URL         string         `json:"url"`
	URLTemplate string         `json:"url_template"`
	Param       string         `json:"param"`
	Values      []string       `json:"values"`
	Field       string         `json:"field"`
	TestValues  []string       `json:"test_values"`
	Reason      string         `json:"reason"`
	Extra       map[string]any `json:"-"`
}) string {
	switch fu.Action {
	case "fetch", "visit":
		return fmt.Sprintf("%s %s", fu.Action, fu.URL)
	case "probe_param":
		return fmt.Sprintf("probe '%s' on %s", fu.Param, fu.URL)
	case "probe_idor":
		t := fu.URLTemplate
		if t == "" {
			t = fu.URL
		}
		return fmt.Sprintf("probe IDOR on %s (%d id values)", t, len(fu.Values))
	case "probe_logic":
		return fmt.Sprintf("probe business-logic on %s field='%s' (%d values)",
			fu.URL, fu.Field, len(fu.TestValues))
	case "reanalyze":
		return fmt.Sprintf("reanalyze %s", fu.URL)
	}
	return fu.Action
}

// extractNarration pulls the "narration" field out of an LLM JSON response
// without fully parsing into a PageProfile. Returns "" if not present.
func extractNarration(content string) string {
	var bag struct {
		Narration string `json:"narration"`
	}
	if err := json.Unmarshal([]byte(content), &bag); err == nil && bag.Narration != "" {
		return bag.Narration
	}
	cleaned := extractJSON(content)
	if cleaned != content {
		if err := json.Unmarshal([]byte(cleaned), &bag); err == nil && bag.Narration != "" {
			return bag.Narration
		}
	}
	return ""
}

func (a *AnalyzerAgent) parseProfile(content string) *types.PageProfile {
	// Try parsing as single profile
	var profile types.PageProfile
	if err := json.Unmarshal([]byte(content), &profile); err == nil && profile.ID != "" {
		return &profile
	}

	// Try extracting JSON from mixed content
	cleaned := extractJSON(content)
	if cleaned != content {
		if err := json.Unmarshal([]byte(cleaned), &profile); err == nil && profile.ID != "" {
			return &profile
		}
	}

	// Try parsing as array and take the first
	var profiles []types.PageProfile
	if err := json.Unmarshal([]byte(content), &profiles); err == nil && len(profiles) > 0 {
		return &profiles[0]
	}
	if cleaned != content {
		if err := json.Unmarshal([]byte(cleaned), &profiles); err == nil && len(profiles) > 0 {
			return &profiles[0]
		}
	}

	// Wrapper tolerance — some models (qwen3:8b in particular) emit
	// `{"pageProfile": {...actual profile...}}` instead of the bare profile.
	// Look for a single top-level object key whose value parses as a
	// PageProfile. This handles LLM-idiosyncratic wrapping without
	// requiring a new prompt iteration.
	if p := tryUnwrapProfile(content); p != nil {
		return p
	}
	if cleaned != content {
		if p := tryUnwrapProfile(cleaned); p != nil {
			return p
		}
	}

	// Reasoning models occasionally embed JavaScript-style string helpers in
	// otherwise valid JSON test values (for example "A".repeat(10000)). Keep
	// the intent as a short descriptive literal rather than expanding a large
	// active payload, then retry the complete profile before falling back to a
	// low-confidence partial salvage.
	for _, candidate := range []string{
		repairDroppedProfileIDPrefix(content),
		repairDroppedProfileIDPrefix(cleaned),
		repairModelJSONExpressions(content),
		repairModelJSONExpressions(cleaned),
	} {
		if candidate == content || candidate == cleaned {
			continue
		}
		var repairedProfile types.PageProfile
		if err := json.Unmarshal([]byte(candidate), &repairedProfile); err == nil && repairedProfile.ID != "" {
			return &repairedProfile
		}
		var repairedProfiles []types.PageProfile
		if err := json.Unmarshal([]byte(candidate), &repairedProfiles); err == nil && len(repairedProfiles) > 0 {
			return &repairedProfiles[0]
		}
		if p := tryUnwrapProfile(candidate); p != nil {
			return p
		}
		if p := salvagePageProfileFromPartial(candidate); p != nil {
			a.logger.Info("salvaged profile after repairing dropped id prefix",
				"id", p.ID,
				"url", p.URL,
				"confidence", p.Confidence,
			)
			return p
		}
	}

	// Hosted models can hit an output ceiling after completing the core page
	// identity but before closing a trailing array (usually follow_ups or
	// relationships). Preserve only values whose JSON value is demonstrably
	// complete. Grounded endpoint identity and extracted inputs are still
	// overlaid later by mergeProfile, and the deliberately low confidence keeps
	// this recovery from masquerading as a complete model response.
	if p := salvagePageProfileFromPartial(content); p != nil {
		a.logger.Info("salvaged profile from provider-truncated JSON",
			"id", p.ID,
			"url", p.URL,
			"confidence", p.Confidence,
		)
		return p
	}

	// Debug: when this fires we want the actual content so we can see what
	// shape the model is emitting. Cap at 800 chars to avoid log spam.
	preview := content
	if len(preview) > 800 {
		preview = preview[:800] + "…"
	}
	a.logger.Warn("failed to parse LLM response as profile",
		"content_length", len(content), "content_preview", preview)
	return nil
}

var modelJSONStringRepeatRE = regexp.MustCompile(`"((?:\\.|[^"\\])*)"\.repeat\((\d{1,6})\)`)
var modelDroppedProfileIDPrefixRE = regexp.MustCompile(`(?is)^\s*\{?\s*"?:\s*"(?:\\.|[^"\\])+"\s*,`)

func repairModelJSONExpressions(content string) string {
	return modelJSONStringRepeatRE.ReplaceAllString(content, `"$1 (repeat $2 times)"`)
}

func repairDroppedProfileIDPrefix(content string) string {
	trimmed := strings.TrimSpace(content)
	if !modelDroppedProfileIDPrefixRE.MatchString(trimmed) ||
		!strings.Contains(trimmed, `"url"`) ||
		!strings.Contains(trimmed, `"method"`) ||
		!strings.Contains(trimmed, `"purpose"`) {
		return content
	}
	if strings.HasPrefix(trimmed, `{`) {
		return `{"id` + strings.TrimPrefix(trimmed, `{`)
	}
	return `{"id` + trimmed
}

// salvagePageProfileFromPartial recovers the minimum useful PageProfile from
// a provider-truncated object. It never guesses unfinished values: scalar
// strings must have a closing quote and arrays must have their closing bracket.
// A complete id, URL and purpose are required so arbitrary JSON fragments are
// not promoted into the knowledge base.
func salvagePageProfileFromPartial(content string) *types.PageProfile {
	id := partialJSONStringField(content, "id")
	pageURL := partialJSONStringField(content, "url")
	purpose := partialJSONStringField(content, "purpose")
	if id == "" || pageURL == "" || purpose == "" {
		return nil
	}

	profile := &types.PageProfile{
		ID:           id,
		URL:          pageURL,
		Method:       partialJSONStringField(content, "method"),
		Purpose:      purpose,
		AuthRequired: partialJSONStringField(content, "auth_required"),
		TechNotes:    partialJSONStringField(content, "tech_notes"),
		Confidence:   0.35,
	}
	partialJSONArrayField(content, "inputs", &profile.Inputs)
	partialJSONArrayField(content, "data_exposed", &profile.DataExposed)
	partialJSONArrayField(content, "apis_called", &profile.APIsCalled)
	partialJSONArrayField(content, "behaviors", &profile.Behaviors)
	partialJSONArrayField(content, "relationships", &profile.Relationships)
	partialJSONArrayField(content, "issues", &profile.Issues)
	return profile
}

// tryUnwrapProfile handles LLM outputs that wrap the profile in a single
// outer key, e.g. `{"pageProfile": {...}}` or `{"profile": {...}}` or
// `{"result": {...}}`. Iterates top-level keys; the first value that
// unmarshals to a PageProfile with a non-empty ID wins.
func tryUnwrapProfile(content string) *types.PageProfile {
	var wrapper map[string]json.RawMessage
	if err := json.Unmarshal([]byte(content), &wrapper); err != nil {
		return nil
	}
	for _, raw := range wrapper {
		var p types.PageProfile
		if err := json.Unmarshal(raw, &p); err == nil && p.ID != "" {
			return &p
		}
	}
	return nil
}

func generateTemplateID(bundle *extract.EndpointBundle) string {
	// Generate a readable template ID from the URL pattern
	pattern := bundle.URLPattern
	pattern = strings.ReplaceAll(pattern, "/", "_")
	pattern = strings.ReplaceAll(pattern, "{", "")
	pattern = strings.ReplaceAll(pattern, "}", "")
	pattern = strings.TrimLeft(pattern, "_")
	if len(pattern) > 40 {
		pattern = pattern[:40]
	}
	if pattern == "" {
		pattern = "root"
	}
	return strings.ToLower(bundle.Method) + "_" + pattern
}

func deduplicateStrings(ss []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// extractJSON returns the first balanced top-level JSON value (object or
// array) found in s. Used to pull structured output out of LLM responses
// that may include prose, multiple objects, or markdown fences. Brace-
// counting handles the common reasoning-model failure of emitting
// `{profile}\n{follow_ups}` as two concatenated objects — the old
// "first { to last }" heuristic produced `{profile}\n{follow_ups}` which
// isn't valid JSON.
func extractJSON(s string) string {
	// Strip common code fences first so we don't count braces inside them.
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")

	start := -1
	var openCh, closeCh byte
	for i := 0; i < len(s); i++ {
		if s[i] == '{' || s[i] == '[' {
			start = i
			openCh = s[i]
			if openCh == '{' {
				closeCh = '}'
			} else {
				closeCh = ']'
			}
			break
		}
	}
	if start < 0 {
		return s
	}

	depth := 0
	inString := false
	escaped := false
	for i := start; i < len(s); i++ {
		c := s[i]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == '"' {
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			continue
		}
		if c == openCh {
			depth++
		} else if c == closeCh {
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	// Unbalanced — return what we have, let the caller fail loud.
	return s[start:]
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
