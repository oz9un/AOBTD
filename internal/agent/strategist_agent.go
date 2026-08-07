package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ozzyw/aobtd/internal/llm"
	"github.com/ozzyw/aobtd/internal/store"
)

// StrategistAgent is the Sovereign Strategist — a batch planner that runs
// periodically (not continuously) over the scan's state, forms hypotheses
// about the target, and emits directives into the queue for specialist
// agents to execute.
//
// Design decisions crystallized from the research & prototype phase:
//  1. Batch, not ReAct — each cycle is stateless; reconstruct context from DB.
//  2. Evidence-grounded — every directive must cite profile / finding / host ids.
//  3. Structured output with strict validation — we drop invented actions.
//  4. Observability-first — every cycle's raw prompt/response persisted
//     to strategist_cycles for the reasoning-trace UI.
type StrategistAgent struct {
	db       *store.DB
	scanID   int64
	provider llm.Provider
	budget   *llm.Budget
	logger   *slog.Logger

	// Cycle cadence. The Strategist wakes up every `period` to read state
	// and emit directives. Additional cycles can be triggered externally
	// via Trigger().
	period time.Duration
	// planOnly keeps the reasoning/hypothesis loop alive while withholding
	// executable directives. Recon scans use this to explain what a pentester
	// would test next without turning those ideas into target traffic.
	planOnly bool

	// Trigger channel — orchestrator pushes on this to fire an
	// off-schedule cycle (e.g. right after a verifier confirms a finding).
	triggerCh chan string

	// State
	mu         sync.Mutex
	cycleRunMu sync.Mutex
	cycleNum   int
	stopped    bool
	lastRunAt  time.Time
	// lastWorldRevision fingerprints evidence produced outside the
	// Strategist. Periodic ticks with no new evidence are skipped so a local
	// model cannot burn time re-planning the same world while another agent
	// (notably Navigator) is waiting for the same Ollama runtime.
	lastWorldRevision string
}

// ErrStrategistBudgetLimited means a requested planning cycle could not run
// because the configured LLM budget had no room for it. Callers that need a
// truthful terminal state (notably the orchestrator's final convergence
// phase) can distinguish this from a transient provider or persistence error.
var ErrStrategistBudgetLimited = errors.New("strategist cycle blocked by LLM budget")

// StrategistConfig configures the agent.
type StrategistConfig struct {
	Period   time.Duration // how often the Strategist wakes; default 3 min
	PlanOnly bool          // persist beliefs, withhold executable directives
}

// Frontier reasoning providers can spend close to two minutes on a dense
// final synthesis even after the world model is compacted. Keep this below
// the five-minute convergence budget while leaving room for one transient
// provider retry instead of converting a healthy scan into "incomplete".
const strategistCallTimeout = 3 * time.Minute

func strategistMaxOutputTokens(provider llm.Provider, reason string) int {
	if reason == "recon_final_model" {
		return llm.StructuredOutputTokenLimit(provider, 1600, 4096)
	}
	return llm.StructuredOutputTokenLimit(provider, 2400, 10240)
}

// NewStrategistAgent creates a Strategist. The provider should be a model
// capable of structured-output + multi-hundred-token reasoning. Based on
// the prototype bench, qwen2.5:14b (local) or Claude Sonnet (API) are the
// targets. qwen3:8b is NOT sufficient — it invents its own schema.
func NewStrategistAgent(db *store.DB, scanID int64, provider llm.Provider, budget *llm.Budget, cfg StrategistConfig, logger *slog.Logger) *StrategistAgent {
	if cfg.Period <= 0 {
		cfg.Period = 3 * time.Minute
	}
	return &StrategistAgent{
		db:        db,
		scanID:    scanID,
		provider:  provider,
		budget:    budget,
		logger:    logger,
		period:    cfg.Period,
		planOnly:  cfg.PlanOnly,
		triggerCh: make(chan string, 4),
	}
}

func (s *StrategistAgent) Name() string { return "strategist" }

// Trigger requests an off-schedule cycle. The reason is recorded in the
// cycle log so we can tell the UI why a particular plan was generated.
// Non-blocking; drops triggers if the queue is full (which only happens
// if the previous cycle is still running).
func (s *StrategistAgent) Trigger(reason string) {
	select {
	case s.triggerCh <- reason:
	default:
	}
}

// Run is the main loop. Blocks until ctx is cancelled. Every Strategist
// cycle is ~45-90s on qwen2.5:14b local, so we don't queue them up — if
// a cycle is in flight, additional triggers are coalesced.
func (s *StrategistAgent) Run(ctx context.Context) error {
	s.logger.Info("strategist agent starting",
		"period", s.period,
		"model", s.provider.ModelInfo().Name,
	)
	// Fire an initial cycle at startup so the first plan is ready right
	// after crawl/recon kick off.
	s.runCycleSafely(ctx, "startup")
	// A local Ollama runtime commonly has one inference slot. Periodic planner
	// calls would queue behind endpoint analysis (or starve it) while reporting
	// misleading multi-minute durations. Local planning is triggered explicitly
	// at phase boundaries and during final convergence instead.
	if s.provider.Name() == "ollama" {
		for {
			select {
			case <-ctx.Done():
				return nil
			case reason := <-s.triggerCh:
				s.runCycleSafely(ctx, reason)
			}
		}
	}

	timer := time.NewTicker(s.period)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case reason := <-s.triggerCh:
			s.runCycleSafely(ctx, reason)
		case <-timer.C:
			s.runCycleSafely(ctx, "periodic")
		}
	}
}

// runCycleSafely wraps runCycle with panic recovery + state locking.
// A misbehaving LLM response must never crash the scan.
func (s *StrategistAgent) runCycleSafely(ctx context.Context, reason string) {
	if err := s.RunCycle(ctx, reason); err != nil && !errors.Is(err, ErrStrategistBudgetLimited) {
		s.logger.Warn("strategist cycle failed", "trigger", reason, "error", err)
	}
}

// RunCycle executes one complete Strategist cycle and does not return until
// its hypotheses and directives have been persisted. Cycles are serialized:
// a final, awaited cycle can never race a periodic or externally-triggered
// cycle and observe only half of its plan.
func (s *StrategistAgent) RunCycle(ctx context.Context, reason string) (err error) {
	s.cycleRunMu.Lock()
	defer s.cycleRunMu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("strategist cycle panicked: %v", r)
			s.logger.Warn("strategist cycle panicked; recovered", "err", r, "trigger", reason)
		}
	}()
	return s.runCycle(ctx, reason)
}

// runCycle executes one plan cycle end-to-end: build world model, call LLM,
// validate + parse, persist hypotheses + directives, log the cycle.
func (s *StrategistAgent) runCycle(ctx context.Context, reason string) error {
	s.mu.Lock()
	s.cycleNum++
	cycleNum := s.cycleNum
	s.mu.Unlock()

	if s.budget != nil && s.budget.Level() == llm.BudgetExhausted {
		s.logger.Info("strategist skipping cycle — budget exhausted", "cycle", cycleNum)
		return fmt.Errorf("%w: exhausted", ErrStrategistBudgetLimited)
	}

	// 1. World model
	wm, err := buildStrategistWorldModel(s.db, s.scanID)
	if err != nil {
		return fmt.Errorf("world model: %w", err)
	}
	// Skip cycles where there's literally nothing to reason about yet.
	// Saves LLM calls during the quiet early minutes of a scan.
	if wm.EndpointCount < 5 && wm.ProfileCount == 0 {
		s.logger.Debug("strategist skipping cycle — insufficient state", "cycle", cycleNum)
		return nil
	}
	worldRevision := strategistWorldRevision(wm)
	if reason == "periodic" {
		s.mu.Lock()
		unchanged := s.lastWorldRevision != "" && s.lastWorldRevision == worldRevision
		s.mu.Unlock()
		if unchanged {
			s.logger.Debug("strategist skipping periodic cycle — no new evidence", "cycle", cycleNum)
			return nil
		}
	}

	userPrompt := buildStrategistCyclePrompt(wm, reason, s.planOnly)

	// Budget check
	estTokens := s.provider.CountTokens(strategistSystemPromptV2 + userPrompt)
	if s.budget != nil && !s.budget.CanSpend(estTokens) {
		s.logger.Info("strategist skipping cycle — would exceed budget",
			"estimated_tokens", estTokens)
		return fmt.Errorf("%w: estimated cycle needs %d input tokens", ErrStrategistBudgetLimited, estTokens)
	}

	// 2. LLM call
	start := time.Now()
	req := &llm.Request{
		SystemPrompt: strategistSystemPromptV2,
		Messages:     []llm.Message{{Role: "user", Content: userPrompt}},
		Temperature:  0.15,
		MaxTokens:    strategistMaxOutputTokens(s.provider, reason),
		JSONMode:     true,
	}
	callCtx, cancel := context.WithTimeout(ctx, strategistCallTimeout)
	defer cancel()
	resp, err := llm.CompleteBudgeted(callCtx, s.provider, s.budget, req, estTokens)
	duration := time.Since(start)
	if err != nil {
		usage, modelID, billed := llm.UsageFromError(err)
		if modelID == "" {
			modelID = s.provider.ModelInfo().Name
		}
		cost := int64(0)
		if billed {
			cost = llm.CostMicroCents(modelID, usage)
		}
		// Still log the failed cycle for observability
		s.db.InsertStrategistCycle(store.StrategistCycle{
			ScanID:         s.scanID,
			TriggerReason:  reason,
			ModelID:        modelID,
			WorldModelSize: len(userPrompt),
			TokensIn:       usage.InputTokens,
			TokensOut:      usage.OutputTokens,
			DurationMs:     duration.Milliseconds(),
			CostUcents:     cost,
			Error:          err.Error(),
		})
		if billed {
			_ = s.db.LogAIFull(s.scanID, "strategist", "plan_failed",
				fmt.Sprintf("cycle %d (%s)", cycleNum, reason),
				"", "", err.Error(),
				usage.InputTokens, usage.OutputTokens,
				duration.Milliseconds(), cost, modelID,
				llm.RenderPrompt(req), "")
		}
		if errors.Is(err, llm.ErrBudgetExceeded) {
			return fmt.Errorf("%w: %v", ErrStrategistBudgetLimited, err)
		}
		return fmt.Errorf("LLM call: %w", err)
	}
	// 3. Parse + validate
	parsed, validErrs := parseStrategistOutputV2(resp.Content)
	if parsed == nil {
		// Log the failed parse with the raw output so we can diagnose later
		modelID := llm.ResponseModel(resp, s.provider)
		cost := llm.CostMicroCents(modelID, resp.Usage)
		s.db.InsertStrategistCycle(store.StrategistCycle{
			ScanID:         s.scanID,
			TriggerReason:  reason,
			ModelID:        modelID,
			WorldModelSize: len(userPrompt),
			RawOutput:      resp.Content,
			TokensIn:       resp.Usage.InputTokens,
			TokensOut:      resp.Usage.OutputTokens,
			DurationMs:     duration.Milliseconds(),
			CostUcents:     cost,
			Error:          "could not parse JSON output",
		})
		return fmt.Errorf("parse LLM output: %s", strings.Join(validErrs, "; "))
	}
	groundingRejections := validateStrategistGrounding(parsed, wm)
	validErrs = append(validErrs, groundingRejections...)

	// 4. Persist the cycle log FIRST so we have an id to reference
	modelID := llm.ResponseModel(resp, s.provider)
	cost := llm.CostMicroCents(modelID, resp.Usage)
	cycleID, err := s.db.InsertStrategistCycle(store.StrategistCycle{
		ScanID:           s.scanID,
		TriggerReason:    reason,
		ModelID:          modelID,
		WorldModelSize:   len(userPrompt),
		RawOutput:        resp.Content,
		ExecutiveSummary: parsed.ExecutiveSummary,
		HypothesisCount:  len(parsed.Hypotheses),
		DirectiveCount:   len(parsed.Directives),
		RejectedCount:    parsed.RejectedCount,
		TokensIn:         resp.Usage.InputTokens,
		TokensOut:        resp.Usage.OutputTokens,
		DurationMs:       duration.Milliseconds(),
		CostUcents:       cost,
	})
	if err != nil {
		return fmt.Errorf("log cycle: %w", err)
	}
	if len(groundingRejections) > 0 {
		_, _ = s.db.InsertNarration(s.scanID, "strategist", "grounding_rejected",
			fmt.Sprintf("Rejected %d ungrounded planning item(s): %s", len(groundingRejections), strings.Join(groundingRejections, "; ")),
			"", map[string]any{"cycle_id": cycleID, "rejected": len(groundingRejections)})
	}

	// 5. Persist hypotheses + directives
	for _, h := range parsed.Hypotheses {
		var confirmedFindingCount int
		if h.ID != "" {
			_ = s.db.Conn().QueryRow(`
				SELECT COUNT(*) FROM findings
				WHERE scan_id = ? AND hypothesis_id = ? AND confidence = 'confirmed'`,
				s.scanID, h.ID).Scan(&confirmedFindingCount)
		}
		h.Confidence = groundedHypothesisConfidence(h.Confidence, confirmedFindingCount > 0)
		if err := s.db.UpsertHypothesis(store.Hypothesis{
			ID:                 h.ID,
			ScanID:             s.scanID,
			CycleID:            cycleID,
			Statement:          h.Statement,
			Confidence:         h.Confidence,
			Status:             store.HypothesisActive,
			SupportingEvidence: h.SupportingEvidence,
		}); err != nil {
			s.logger.Warn("strategist hypothesis upsert failed",
				"id", h.ID, "error", err)
		}
	}
	queued := 0
	retired := 0
	withheld := 0
	for _, d := range parsed.Directives {
		var executable bool
		d, executable = normalizeStrategistDirective(d)
		if !executable {
			parsed.RejectedCount++
			message := rejectedStrategistDirectiveMessage(d)
			s.logger.Info("strategist rejected incompatible directive",
				"action", d.Action, "url", d.URL, "field", d.Field,
				"reason", message)
			_, _ = s.db.InsertNarration(s.scanID, "strategist", "rejected_directive",
				message, d.URL, map[string]any{
					"action":        d.Action,
					"field":         d.Field,
					"endpoint_id":   d.EndpointID,
					"hypothesis_id": d.HypothesisID,
					"grounded_in":   d.GroundedIn,
				})
			continue
		}
		// "stop" is a meta-directive: it doesn't queue work for Explorer. A
		// planner is not an evidence source, so its wording can never create a
		// Finding or confirm a hypothesis. Only a confirmed specialist finding
		// may perform that transition (store.InsertFinding). Here we merely
		// retire unresolved work as stale; the store preserves any terminal
		// status already established by real evidence.
		if d.Action == "stop" {
			if d.HypothesisID == "" {
				continue
			}
			resolvedBy := fmt.Sprintf("strategist/cycle-%d", cycleID)
			if err := s.db.SetHypothesisStatus(s.scanID, d.HypothesisID, store.HypothesisStale, resolvedBy); err != nil {
				s.logger.Warn("strategist stop directive failed",
					"hypothesis_id", d.HypothesisID, "error", err)
			} else {
				retired++
				s.logger.Info("strategist retired hypothesis",
					"hypothesis_id", d.HypothesisID, "reason", d.Reason,
					"status", store.HypothesisStale)
			}
			continue
		}
		if s.planOnly {
			withheld++
			_, _ = s.db.InsertNarration(s.scanID, "strategist", "directive_withheld",
				fmt.Sprintf("Recon Only: I would %s next to test %s, but I am withholding the probe under the current authority. %s",
					d.Action, d.HypothesisID, d.Reason),
				firstNonEmpty(d.URL, d.URLTemplate), map[string]any{
					"action": d.Action, "hypothesis_id": d.HypothesisID,
					"grounded_in": d.GroundedIn, "testing_authority": "recon",
				})
			continue
		}
		params := map[string]any{
			"url_template": d.URLTemplate,
			"values":       d.Values,
			"endpoint_id":  d.EndpointID,
		}
		if d.Action == "probe_param" {
			params["param"] = d.Field
		} else {
			params["field"] = d.Field
		}
		fu := store.FollowUp{
			SourceAgent: "strategist",
			Action:      d.Action,
			URL:         firstNonEmpty(d.URL, d.URLTemplate),
			Reason:      d.Reason,
			Priority:    d.Priority,
			Params:      params,
		}
		id, err := s.db.InsertDirective(s.scanID, fu, d.GroundedIn, d.HypothesisID, "strategist")
		if err != nil {
			s.logger.Warn("strategist directive insert failed",
				"action", d.Action, "url", fu.URL, "error", err)
			continue
		}
		if id > 0 {
			queued++
		}
	}
	_ = retired // recorded via logger.Info above; passed to the narration below via queued context

	// 6. Narration — surface the plan to the Live view
	s.narrateCycle(cycleNum, reason, parsed, queued, duration)
	s.logger.Info("strategist cycle complete",
		"cycle", cycleNum,
		"trigger", reason,
		"hypotheses", len(parsed.Hypotheses),
		"directives", len(parsed.Directives),
		"queued", queued,
		"withheld", withheld,
		"rejected", parsed.RejectedCount,
		"duration", duration.Round(time.Millisecond),
		"cost_cents", cost/10000,
	)

	// Log cost to ai_log for the per-scan spend tally
	s.db.LogAIFull(s.scanID, "strategist", "plan",
		fmt.Sprintf("cycle %d (%s)", cycleNum, reason),
		"", "", parsed.ExecutiveSummary,
		resp.Usage.InputTokens, resp.Usage.OutputTokens,
		duration.Milliseconds(), cost, modelID,
		llm.RenderPrompt(req), resp.Content)

	// Rebuild after persistence so the revision also includes queue mutations
	// made by this cycle. Otherwise the next periodic tick would interpret the
	// Strategist's own newly queued directives as fresh external evidence.
	committedRevision := worldRevision
	if committedWorld, refreshErr := buildStrategistWorldModel(s.db, s.scanID); refreshErr == nil {
		committedRevision = strategistWorldRevision(committedWorld)
	}
	s.mu.Lock()
	s.lastRunAt = time.Now()
	s.lastWorldRevision = committedRevision
	s.mu.Unlock()
	return nil
}

// strategistWorldRevision deliberately excludes time, the previous
// Strategist summary, Strategist-authored hypothesis details, and the total
// narration counter. Those fields change simply because a cycle ran. The
// remaining snapshot represents evidence supplied by discovery and specialist
// agents; a change there is a reason to plan again.
func strategistWorldRevision(wm *strategistWorldModel) string {
	evidence := struct {
		EndpointCount       int
		ProfileCount        int
		ProfilesWithIssues  int
		FindingCount        int
		ConfirmedFindings   int
		DirectivesPending   int
		DirectivesCompleted int
		Hosts               []wmHost
		TopIssues           []wmIssueCluster
		Interesting         []wmEndpointCard
		OwnershipCandidates []wmOwnershipCandidate
		Findings            []wmFindingCard
		RecentThoughts      []wmNarrationCard
		RejectedDirectives  []wmRejectedDirectiveCard
		AppUnderstanding    string
	}{
		EndpointCount:       wm.EndpointCount,
		ProfileCount:        wm.ProfileCount,
		ProfilesWithIssues:  wm.ProfilesWithIssues,
		FindingCount:        wm.FindingCount,
		ConfirmedFindings:   wm.ConfirmedFindings,
		DirectivesPending:   wm.DirectivesPending,
		DirectivesCompleted: wm.DirectivesCompleted,
		Hosts:               wm.Hosts,
		TopIssues:           wm.TopIssues,
		Interesting:         wm.InterestingEndpoints,
		OwnershipCandidates: wm.OwnershipCandidates,
		Findings:            wm.Findings,
		RecentThoughts:      wm.RecentThoughts,
		RejectedDirectives:  wm.RejectedDirectives,
		AppUnderstanding:    wm.AppUnderstanding,
	}
	b, _ := json.Marshal(evidence)
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

func (s *StrategistAgent) narrateCycle(cycleNum int, reason string, out *strategistOutput, queued int, dur time.Duration) {
	// Summary narration
	var summary string
	if queued > 0 {
		summary = fmt.Sprintf("Strategist cycle %d (%s): %d new directive(s) queued from %d hypothesis(es). %s",
			cycleNum, reason, queued, len(out.Hypotheses), out.ExecutiveSummary)
	} else if len(out.Hypotheses) > 0 {
		summary = fmt.Sprintf("Strategist cycle %d (%s): %d hypothesis(es) tracked; no new directives. %s",
			cycleNum, reason, len(out.Hypotheses), out.ExecutiveSummary)
	} else {
		summary = fmt.Sprintf("Strategist cycle %d (%s): nothing actionable this pass. %s",
			cycleNum, reason, out.ExecutiveSummary)
	}
	s.db.InsertNarration(s.scanID, "strategist", "plan", summary, "", map[string]any{
		"cycle":      cycleNum,
		"trigger":    reason,
		"directives": queued,
		"duration_s": dur.Seconds(),
	})

	// One narration per top-3 hypotheses so the thinking shows up in the Live feed
	for i, h := range out.Hypotheses {
		if i >= 3 {
			break
		}
		s.db.InsertNarration(s.scanID, "strategist", "hypothesis",
			fmt.Sprintf("[%.0f%%] %s — %s", h.Confidence*100, h.ID, h.Statement),
			"", map[string]any{"hypothesis_id": h.ID, "confidence": h.Confidence})
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// normalizeStrategistDirective keeps the planner's intent while selecting an
// execution primitive compatible with the observed request shape. A common
// local-model error is requesting body mutation (`probe_logic`) for a GET
// query parameter; that can never execute successfully and used to strand
// every such hypothesis in a failed directive loop.
func normalizeStrategistDirective(d strategistDirective) (strategistDirective, bool) {
	target := firstNonEmpty(d.URLTemplate, d.URL)
	if followUpTargetsPublicStaticAsset(target) &&
		(d.Action == "probe_param" || d.Action == "probe_idor" || d.Action == "probe_logic") {
		return d, false
	}
	if (d.Action == "probe_logic" || d.Action == "probe_param") && businessLogicFieldIsCSRFToken(d.Field) {
		return d, false
	}
	if d.Action == "probe_idor" {
		d.Values = cleanIDORProbeValues(d.Values)
		if len(d.Values) < 2 || !idorPlaceholderLooksScalar(d.URLTemplate) || !idorTargetLooksOwnedObject(d.URLTemplate, d.Field) {
			return d, false
		}
		return d, true
	}
	if d.Action != "probe_logic" {
		return d, true
	}

	method := directiveHTTPMethod(d)
	field := strings.TrimSpace(d.Field)
	if field != "" {
		if parsed, err := url.Parse(d.URL); err == nil {
			for key := range parsed.Query() {
				if strings.EqualFold(key, field) {
					d.Action = "probe_param"
					return d, true
				}
			}
		}
		// A body/form mutation is incompatible with a read-only request, but
		// the planner's intent is still useful: "try this field with these
		// values". For GET-like endpoints, reinterpret that as a query-param
		// probe even when the parameter was not present in the original URL.
		// This keeps the solution general: we are selecting an HTTP primitive
		// that matches the observed method, not hard-coding any target app.
		if method == "GET" || method == "HEAD" || method == "OPTIONS" {
			d.Action = "probe_param"
			return d, true
		}
	}

	if method == "GET" || method == "HEAD" || method == "OPTIONS" {
		return d, false
	}
	return d, true
}

func idorPlaceholderLooksScalar(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	for key, values := range parsed.Query() {
		containsPlaceholder := false
		for _, value := range values {
			if hasPlaceholder(value) {
				containsPlaceholder = true
				break
			}
		}
		if !containsPlaceholder {
			continue
		}
		normalized := strings.ToLower(strings.TrimSpace(key))
		if normalized == "ids" || strings.HasSuffix(normalized, "_ids") || strings.HasSuffix(normalized, "ids[]") {
			return false
		}
	}
	return true
}

func groundedHypothesisConfidence(requested float64, hasConfirmedFinding bool) float64 {
	if requested < 0 {
		return 0
	}
	if requested > 1 {
		requested = 1
	}
	if !hasConfirmedFinding && requested >= 0.9 {
		return 0.85
	}
	return requested
}

// validateStrategistGrounding resolves the model's citations against the
// compact world model it actually received. Merely writing a plausible-looking
// `endpoint:` string is not evidence: hypotheses and executable directives
// must cite a host, endpoint, finding, or specialist thought present in the
// situation report. Existing hypothesis citations remain valid for continuity
// even when their endpoint has fallen out of the top-K display.
func validateStrategistGrounding(out *strategistOutput, wm *strategistWorldModel) []string {
	if out == nil || wm == nil {
		return nil
	}
	knownRefs := strategistGroundingRefs(wm)
	knownHypotheses := make(map[string]struct{}, len(wm.ActiveHypotheses)+len(out.Hypotheses))
	for _, h := range wm.ActiveHypotheses {
		knownHypotheses[h.ID] = struct{}{}
	}

	var rejected []string
	keptHypotheses := out.Hypotheses[:0]
	for _, h := range out.Hypotheses {
		h.ID = strings.TrimSpace(h.ID)
		h.Statement = strings.TrimSpace(h.Statement)
		h.SupportingEvidence = validatedGroundingRefs(h.SupportingEvidence, knownRefs)
		if h.ID == "" || h.Statement == "" || len(h.SupportingEvidence) == 0 {
			label := h.ID
			if label == "" {
				label = "unnamed hypothesis"
			}
			rejected = append(rejected, label+" has no resolvable evidence")
			out.RejectedCount++
			continue
		}
		knownHypotheses[h.ID] = struct{}{}
		keptHypotheses = append(keptHypotheses, h)
	}
	out.Hypotheses = keptHypotheses

	keptDirectives := out.Directives[:0]
	for _, d := range out.Directives {
		d.HypothesisID = strings.TrimSpace(d.HypothesisID)
		if d.Action == "stop" {
			if _, ok := knownHypotheses[d.HypothesisID]; !ok || d.HypothesisID == "" {
				rejected = append(rejected, "stop references an unknown hypothesis")
				out.RejectedCount++
				continue
			}
			keptDirectives = append(keptDirectives, d)
			continue
		}
		if _, ok := knownHypotheses[d.HypothesisID]; !ok || d.HypothesisID == "" {
			rejected = append(rejected, d.Action+" is not attached to a known hypothesis")
			out.RejectedCount++
			continue
		}
		d.GroundedIn = validatedGroundingRefs(d.GroundedIn, knownRefs)
		if len(d.GroundedIn) == 0 {
			rejected = append(rejected, d.Action+" has no resolvable evidence")
			out.RejectedCount++
			continue
		}
		keptDirectives = append(keptDirectives, d)
	}
	out.Directives = keptDirectives
	return rejected
}

func strategistGroundingRefs(wm *strategistWorldModel) map[string]struct{} {
	refs := make(map[string]struct{})
	add := func(ref string) {
		ref = strings.TrimSpace(ref)
		if ref != "" {
			refs[strings.ToLower(ref)] = struct{}{}
		}
	}
	for _, host := range wm.Hosts {
		add("host:" + host.Host)
	}
	for _, endpoint := range wm.InterestingEndpoints {
		add("endpoint:" + endpoint.ID)
		add("endpoint:" + strings.TrimSpace(endpoint.Method+" "+endpoint.Path))
	}
	for _, candidate := range wm.OwnershipCandidates {
		for _, ref := range candidate.EvidenceRefs {
			add(ref)
		}
		add("endpoint:" + strings.TrimSpace(candidate.Method+" "+candidate.Pattern))
	}
	for _, finding := range wm.Findings {
		add(fmt.Sprintf("finding:%d", finding.ID))
	}
	for _, thought := range wm.RecentThoughts {
		add("thought:" + thought.Agent + "/" + thought.Action)
	}
	for _, hypothesis := range wm.ActiveHypotheses {
		for _, ref := range hypothesis.SupportingEvidence {
			add(ref)
		}
	}
	return refs
}

func validatedGroundingRefs(candidates []string, known map[string]struct{}) []string {
	seen := make(map[string]struct{}, len(candidates))
	valid := make([]string, 0, len(candidates))
	for _, ref := range candidates {
		ref = strings.TrimSpace(ref)
		key := strings.ToLower(ref)
		if _, ok := known[key]; !ok || ref == "" {
			continue
		}
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		valid = append(valid, ref)
	}
	return valid
}

func directiveHTTPMethod(d strategistDirective) string {
	candidates := append([]string{d.EndpointID}, d.GroundedIn...)
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(strings.TrimPrefix(candidate, "endpoint:"))
		fields := strings.Fields(candidate)
		if len(fields) == 0 {
			continue
		}
		method := strings.ToUpper(fields[0])
		switch method {
		case "GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE":
			return method
		}
	}
	return ""
}

func rejectedStrategistDirectiveMessage(d strategistDirective) string {
	target := firstNonEmpty(d.URLTemplate, d.URL)
	if followUpTargetsPublicStaticAsset(target) &&
		(d.Action == "probe_param" || d.Action == "probe_idor" || d.Action == "probe_logic") {
		return fmt.Sprintf("Skipped %s on %s: the target is a public/static asset path, so mutating invented file names or IDs would create noisy synthetic probes. Revisit only after observing a real upload handler, directory listing, or server-side file-read behavior.", d.Action, target)
	}
	if d.Action == "probe_idor" && !idorPlaceholderLooksScalar(d.URLTemplate) {
		return fmt.Sprintf("Skipped probe_idor on %s: the placeholder occupies a plural/list filter rather than an observed scalar owned-resource identifier. Use reanalysis or stop unless an ownership boundary is established.", d.URLTemplate)
	}
	if d.Action == "probe_idor" && !idorTargetLooksOwnedObject(d.URLTemplate, d.Field) {
		return fmt.Sprintf("Skipped probe_idor on %s: the target looks like public metadata/configuration/catalog/docs rather than a single owned object. Use reanalysis or stop unless stronger ownership evidence appears.", d.URLTemplate)
	}
	if (d.Action == "probe_logic" || d.Action == "probe_param") && businessLogicFieldIsCSRFToken(d.Field) {
		return fmt.Sprintf("Skipped %s on %s for field %q: token/anti-forgery fields are request integrity controls, not business-logic parameters. Revisit only with a CSRF-specific verifier or stronger evidence of token leakage/reuse.", d.Action, firstNonEmpty(d.URL, d.URLTemplate), d.Field)
	}
	method := directiveHTTPMethod(d)
	if method == "" {
		method = "read-only"
	}
	target = firstNonEmpty(d.URL, d.URLTemplate)
	if target == "" {
		target = d.EndpointID
	}
	field := strings.TrimSpace(d.Field)
	if field == "" {
		field = "(unknown field)"
	}
	return fmt.Sprintf("Skipped %s on %s for field %q: body/form mutation is incompatible with observed %s request shape. Do not repeat this exact body-mutation plan; use fetch/reanalyze, probe_param for real query parameters, or stop the hypothesis.",
		d.Action, target, field, method)
}

// ── Parsed-output types (internal; see strategist_prompt.go for the LLM schema) ──

type strategistOutput struct {
	Hypotheses       []strategistHypothesis `json:"hypotheses"`
	Directives       []strategistDirective  `json:"directives"`
	ExecutiveSummary string                 `json:"executive_summary"`
	NextCycleMinutes int                    `json:"next_cycle_minutes"`
	StopIf           []string               `json:"stop_if"`
	RejectedCount    int                    `json:"-"`
}

type strategistHypothesis struct {
	ID                 string   `json:"id"`
	Statement          string   `json:"statement"`
	Confidence         float64  `json:"confidence"`
	SupportingEvidence []string `json:"supporting_evidence"`
}

type strategistDirective struct {
	Action       string   `json:"action"`
	URL          string   `json:"url,omitempty"`
	URLTemplate  string   `json:"url_template,omitempty"`
	Field        string   `json:"field,omitempty"`
	Values       []string `json:"values,omitempty"`
	EndpointID   string   `json:"endpoint_id,omitempty"`
	Reason       string   `json:"reason,omitempty"`
	GroundedIn   []string `json:"grounded_in,omitempty"`
	HypothesisID string   `json:"hypothesis_id,omitempty"`
	Priority     int      `json:"priority,omitempty"`
}

// parseStrategistOutputV2 parses the LLM's JSON into the typed output AND
// validates every directive against the schema + grounding rules. Directives
// that fail validation are dropped and counted in RejectedCount rather than
// rejecting the whole response (partial plans are still useful).
func parseStrategistOutputV2(raw string) (*strategistOutput, []string) {
	var errs []string
	var out strategistOutput

	// Tolerate code fences + leading/trailing prose — some models (looking at
	// deepseek-r1) can't help themselves even with JSONMode on.
	body := extractJSONObject(raw)
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		return nil, []string{"json: " + err.Error()}
	}

	validActions := map[string]bool{
		"probe_idor": true, "probe_logic": true, "fetch": true,
		"reanalyze": true, "stop": true,
	}

	kept := out.Directives[:0]
	for _, d := range out.Directives {
		if !validActions[d.Action] {
			errs = append(errs, "dropped directive with invalid action: "+d.Action)
			out.RejectedCount++
			continue
		}
		// Grounding rule: every non-stop directive must cite evidence.
		if d.Action != "stop" && len(d.GroundedIn) == 0 {
			errs = append(errs, "dropped "+d.Action+" directive without grounded_in")
			out.RejectedCount++
			continue
		}
		// Action-specific shape checks
		switch d.Action {
		case "probe_idor":
			// Accept any {word} placeholder — {id}, {order_id}, {user_id}, etc.
			// The Explorer normalizes to the first placeholder it finds.
			if d.URLTemplate == "" || !hasPlaceholder(d.URLTemplate) || len(d.Values) < 2 {
				errs = append(errs, "dropped probe_idor (bad url_template or <2 values)")
				out.RejectedCount++
				continue
			}
			// Normalize placeholder to {id} for consistent Explorer behavior.
			d.URLTemplate = normalizePlaceholder(d.URLTemplate)
		case "probe_logic":
			if d.URL == "" || d.Field == "" || len(d.Values) < 1 {
				errs = append(errs, "dropped probe_logic (missing url/field/values)")
				out.RejectedCount++
				continue
			}
		case "fetch":
			if d.URL == "" {
				errs = append(errs, "dropped fetch (missing url)")
				out.RejectedCount++
				continue
			}
		case "reanalyze":
			if d.EndpointID == "" {
				errs = append(errs, "dropped reanalyze (missing endpoint_id)")
				out.RejectedCount++
				continue
			}
		}
		// Default priority if the model forgot
		if d.Priority == 0 {
			d.Priority = 5
		}
		kept = append(kept, d)
	}
	out.Directives = kept
	return &out, errs
}

// hasPlaceholder returns true if the string contains a {word} style
// placeholder. Models tend to use semantic names like {order_id} instead
// of literal {id}; we accept either.
func hasPlaceholder(s string) bool {
	start := strings.Index(s, "{")
	if start < 0 {
		return false
	}
	end := strings.Index(s[start:], "}")
	return end > 1 // need at least one char between braces
}

// normalizePlaceholder replaces the FIRST {word} placeholder with {id} so
// the Explorer's existing substitution logic keeps working. If there are
// multiple placeholders we only rewrite the first — the model probably
// intended all of them to be the same id.
func normalizePlaceholder(s string) string {
	start := strings.Index(s, "{")
	if start < 0 {
		return s
	}
	end := strings.Index(s[start:], "}")
	if end < 2 {
		return s
	}
	return s[:start] + "{id}" + s[start+end+1:]
}

// extractJSONObject peels a JSON object out of possibly-prose-wrapped output.
func extractJSONObject(s string) string {
	s = strings.TrimSpace(s)
	// strip common code fences
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "{") {
		return s
	}
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start < 0 || end <= start {
		return s
	}
	return s[start : end+1]
}
