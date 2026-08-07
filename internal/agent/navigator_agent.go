package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/ozzyw/aobtd/internal/browser"
	"github.com/ozzyw/aobtd/internal/llm"
	"github.com/ozzyw/aobtd/internal/llm/prompts"
	"github.com/ozzyw/aobtd/internal/policy"
	"github.com/ozzyw/aobtd/internal/store"
	targetmodel "github.com/ozzyw/aobtd/internal/target"
	"github.com/ozzyw/aobtd/internal/workflow"
)

// NavigatorAgent uses an LLM to explore the target site beyond what
// traditional crawling discovers. It reads the page, decides actions,
// and executes them through the browser.
type NavigatorAgent struct {
	ctrl       *browser.Controller
	nav        *browser.Navigator
	provider   llm.Provider
	budget     *llm.Budget
	bus        *Bus
	state      *SharedState
	db         *store.DB
	scanID     int64
	logger     *slog.Logger
	interactor Interactor
	authority  policy.TestingAuthority
	policy     *policy.Engine
	auditDeny  func(policy.Decision)

	maxSteps                  int // max LLM-guided actions per session
	reconObjectives           []ReconObjective
	visitedNavigationTargets  map[string]struct{}
	avoidNavigationTargets    map[string]struct{}
	observedNavigationTargets map[string]struct{}
	visitedSurfaceFamilies    map[string]int
	visitedSurfaceShapes      map[string]map[string]struct{}
	semanticSaturation        *SemanticSaturationState
}

// SetExecutionPolicy installs the same immutable scope/authority boundary
// used by crawler, proxy, Explorer, and Copilot. Navigator's observed-link
// rule proves that a URL came from the page; it does not prove the operator
// authorized that origin, so both checks are required before navigation.
func (a *NavigatorAgent) SetExecutionPolicy(engine *policy.Engine, auditDeny func(policy.Decision)) {
	a.policy = engine
	a.auditDeny = auditDeny
}

func (a *NavigatorAgent) SetReconObjectives(objectives []ReconObjective) {
	a.reconObjectives = append([]ReconObjective(nil), objectives...)
}

func (a *NavigatorAgent) SetAvoidNavigationTargets(targets []string) {
	if len(targets) == 0 {
		return
	}
	a.ensureNavigationMemory()
	base := ""
	if a.state != nil {
		base = a.state.ReadModel().Target
	}
	for _, target := range targets {
		if canonical := canonicalNavigatorURL(target, base); canonical != "" {
			a.avoidNavigationTargets[canonical] = struct{}{}
			a.rememberNavigatorSurface(canonical, "", "")
		}
	}
}

// SetObservedNavigationTargets carries exact browser-observed links across
// the orchestrator's bounded Navigator phases. It does not broaden scope or
// mark a URL visited: every imported target is re-canonicalized, checked by
// the immutable policy, and still passes the normal authority guard before a
// GET navigation can execute.
func (a *NavigatorAgent) SetObservedNavigationTargets(targets []string) {
	if len(targets) == 0 {
		return
	}
	a.ensureNavigationMemory()
	base := a.stateTarget()
	for _, raw := range targets {
		canonical := canonicalNavigatorURL(raw, base)
		if canonical == "" || !a.navigationURLAllowed(canonical) || !navigatorApplicationLinkCandidate(canonical) {
			continue
		}
		a.observedNavigationTargets[canonical] = struct{}{}
	}
}

func (a *NavigatorAgent) ObservedNavigationTargets() []string {
	a.ensureNavigationMemory()
	out := make([]string, 0, len(a.observedNavigationTargets))
	for target := range a.observedNavigationTargets {
		out = append(out, target)
	}
	sort.Strings(out)
	return out
}

func (a *NavigatorAgent) VisitedNavigationTargets() []string {
	a.ensureNavigationMemory()
	out := make([]string, 0, len(a.visitedNavigationTargets))
	for target := range a.visitedNavigationTargets {
		out = append(out, target)
	}
	sort.Strings(out)
	return out
}

func (a *NavigatorAgent) SetMaxSteps(steps int) {
	if steps > 0 && steps <= 20 {
		a.maxSteps = steps
	}
}

func (a *NavigatorAgent) SetSemanticSaturation(state *SemanticSaturationState) {
	a.semanticSaturation = state
}

// NewNavigatorAgent creates a navigator agent.
func NewNavigatorAgent(
	ctrl *browser.Controller,
	provider llm.Provider,
	budget *llm.Budget,
	bus *Bus,
	state *SharedState,
	db *store.DB,
	scanID int64,
	interactor Interactor,
	authority policy.TestingAuthority,
	logger *slog.Logger,
) *NavigatorAgent {
	maxSteps := 10
	if authority == policy.AuthorityRecon {
		maxSteps = 6
	}
	return &NavigatorAgent{
		ctrl:       ctrl,
		nav:        browser.NewNavigator(ctrl, logger),
		provider:   provider,
		budget:     budget,
		bus:        bus,
		state:      state,
		db:         db,
		scanID:     scanID,
		logger:     logger,
		interactor: interactor,
		authority:  authority,
		maxSteps:   maxSteps,
	}
}

func (a *NavigatorAgent) Name() string { return "navigator" }

func (a *NavigatorAgent) Capabilities() []EventType {
	return []EventType{EventScanPhaseChanged}
}

// Start runs the LLM-guided navigation loop.
func (a *NavigatorAgent) Start(ctx context.Context) error {
	endProvenance := a.ctrl.BeginTrafficProvenance(a.Name(), 0, "")
	defer endProvenance()

	a.logger.Info("navigator agent starting", "max_steps", a.maxSteps)
	if len(a.reconObjectives) > 0 {
		a.logger.Info("navigator recon objectives", "count", len(a.reconObjectives), "ids", reconObjectiveIDs(a.reconObjectives))
	}
	a.ensureNavigationMemory()

	target := a.state.ReadModel().Target
	_, _ = a.db.InsertNarration(a.scanID, "navigator", "tour_start",
		fmt.Sprintf("Opening an interactive UI tour of %s. I’ll sample distinct safe workflows and skip repeated cards or risky business actions.", target),
		target, map[string]any{"max_steps": a.maxSteps})

	// Open a page at the target
	page, err := a.ctrl.Navigate(ctx, target)
	if err != nil {
		return fmt.Errorf("create page: %w", err)
	}
	defer page.Close()

	// SPAs (juice-shop, modern Angular/React/Vue) need more than the
	// 1s baseline to hydrate before the first CapturePageState is useful.
	// 3s is the sweet spot: long enough for Angular's bootstrap and
	// router-outlet first paint, short enough that operators don't think
	// the agent has hung at the start of the demo.
	time.Sleep(3 * time.Second)

	// Track recent failures so the LLM doesn't repeat them
	var recentFailures []string
	consecutiveFailures := 0
	// A successful DOM click is not necessarily progress. Menus and other
	// toggles often accept the same click forever, which can trap a local LLM
	// in a 20-step loop. Remember actions per page URL and feed exact repeats
	// through the existing no-progress/failure circuit breaker.
	attemptedActions := make(map[string]struct{})
	formMemory := make(map[string]*navigatorFormMemory)

	for step := 0; step < a.maxSteps; step++ {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		// Check budget
		if a.budget.Level() == llm.BudgetExhausted {
			a.logger.Info("budget exhausted, stopping navigation")
			return nil
		}

		// Too many consecutive failures = stop
		if consecutiveFailures >= 3 {
			a.logger.Info("3 consecutive failures, stopping navigation")
			break
		}

		// Capture current page state
		pageState, err := a.nav.CapturePageState(page)
		if err != nil {
			a.logger.Warn("capture state failed", "error", err)
			consecutiveFailures++
			continue
		}
		// The page currently in the browser is already explored even when it was
		// opened as the initial target rather than through a Navigator action.
		// Remember it without incrementing semantic-shape counters; the normal
		// observation immediately below owns that evidence.
		a.rememberCurrentNavigationTarget(pageState.URL)
		// Keep exact, evidence-backed links from every page sampled during this
		// navigator session. Sparse destinations such as login pages often omit
		// the useful route map from the landing page; forgetting that map made
		// Recon spend model turns guessing paths it had already observed.
		a.observeNavigationTargets(pageState)
		a.observeNavigatorSurface(pageState)
		decisionState := a.navigationDecisionState(pageState)

		// First apply a deterministic "junior pentester reflex": if a page
		// has visible safe inputs, exercise the workflow as a short macro
		// before asking the LLM to keep navigating. This turns login/search
		// pages into "fill → submit → observe traffic" instead of burning
		// one whole LLM navigation step per field.
		if a.authority != policy.AuthorityRecon {
			if handled, newState, err := a.executeSafeFormWorkflow(ctx, page, pageState, formMemory, step+1); handled {
				if err != nil {
					a.logger.Warn("safe form workflow failed", "error", err)
					recentFailures = appendNavigatorFailure(recentFailures, err.Error())
					consecutiveFailures++
					continue
				}
				recentFailures = appendNavigatorFailure(recentFailures, "safe form workflow already filled and submitted the visible form; do not fill the same fields again, observe the result or navigate to a different area")
				consecutiveFailures = 0
				if newState != nil {
					a.bus.Publish(Event{
						Type:   EventPageCrawled,
						Source: a.Name(),
						Payload: PageCrawledPayload{
							URL:   newState.URL,
							Links: extractLinkURLs(newState.Links),
							Forms: len(newState.Forms),
						},
					})
				}
				continue
			}
		}

		// Take an exact observed core-business route deterministically when its
		// semantic/response-shape family is still under-sampled. This is the
		// browser equivalent of a junior pentester's first reflex: understand
		// what users actually do before spending a model call on API/settings
		// chrome. The normal exact-link, authority, and policy guards below still
		// revalidate the action before execution.
		action := a.reconNoveltyAction(decisionState)
		if action != nil {
			a.db.LogAI(a.scanID, "navigator", "novelty_route_selected", action.Reason, pageState.URL, action.URL, "planned")
		} else {
			action, err = a.decideAction(ctx, decisionState, step, recentFailures)
			if err != nil {
				a.logger.Warn("LLM decision failed", "error", err)
				recentFailures = appendNavigatorFailure(recentFailures, "the previous model response was invalid; return one complete JSON object")
				consecutiveFailures++
				continue
			}
		}
		if before, after, normalized := normalizeNavigatorNavigationURL(action, pageState); normalized {
			a.logger.Info("navigator resolved relative navigation URL", "from", before, "to", after)
		}
		if before, after, normalized := normalizeNavigatorActionForHashRouting(action, pageState); normalized {
			a.logger.Info("navigator normalized plain SPA route to hash route", "from", before, "to", after)
			if a.db != nil {
				a.db.LogAI(a.scanID, "navigator", "navigation_hash_route_normalized",
					"Hash-routed SPA detected; rewrote a plain UI path to the equivalent hash route to avoid server fallback noise.",
					pageState.URL, after, "normalized")
			}
		}
		if err := validateNavigatorAction(action, pageState); err != nil {
			failureMsg := "rejected model action: " + err.Error()
			a.logger.Info("navigator rejected invalid action", "error", err)
			recentFailures = appendNavigatorFailure(recentFailures, failureMsg)
			consecutiveFailures++
			continue
		}
		if err := a.validateActionForAuthority(action, decisionState); err != nil {
			failureMsg := "rejected by testing authority: " + err.Error()
			if repeatedNavigatorAction(attemptedActions, action, pageState.URL) {
				failureMsg += "; this same held-back action was already proposed on the current page"
			}
			a.logger.Info("navigator held back action", "authority", a.authority, "error", err)
			_, _ = a.db.InsertNarration(a.scanID, "navigator", "authority_guard",
				failureMsg, pageState.URL, map[string]any{"testing_authority": a.authority, "action": action.Action, "selector": action.Selector})
			recentFailures = appendNavigatorFailure(recentFailures, failureMsg)
			// An authority rejection is still a planning failure. Stop after the
			// normal bounded failure threshold instead of buying six model calls
			// for the same guessed route or forbidden interaction.
			consecutiveFailures++
			continue
		}
		if err := a.authorizeNavigationAction(action); err != nil {
			failureMsg := "rejected by scan policy: " + err.Error()
			a.logger.Info("navigator held back out-of-scope action", "error", err, "url", action.URL)
			_, _ = a.db.InsertNarration(a.scanID, "navigator", "scope_guard",
				failureMsg, pageState.URL, map[string]any{"testing_authority": a.authority, "action": action.Action, "url": action.URL})
			recentFailures = appendNavigatorFailure(recentFailures, failureMsg)
			consecutiveFailures++
			continue
		}

		a.logger.Info("LLM decided",
			"step", step+1,
			"action", action.Action,
			"reason", action.Reason,
		)
		_, _ = a.db.InsertNarration(a.scanID, "navigator", "plan",
			navigatorPlanNarration(action, pageState, step+1, a.maxSteps),
			pageState.URL, map[string]any{
				"step": step + 1, "max_steps": a.maxSteps,
				"action": action.Action, "selector": action.Selector,
				"url": action.URL, "value": redactNavigatorActionValue(action),
			})

		// Handle special actions
		if action.Action == "done" {
			a.logger.Info("navigator decided to stop", "reason", action.Reason)
			break
		}

		if action.Action == "ask_human" {
			if !navigatorMayAskHuman(a.authority) {
				message := "Recon could not safely progress from the current page without operator guidance. Recording an evidence-unavailable boundary and continuing the scan without pausing."
				a.logger.Info("recon navigator declined operator pause", "reason", action.Question)
				_, _ = a.db.InsertNarration(a.scanID, "navigator", "evidence_unavailable",
					message, pageState.URL, map[string]any{"testing_authority": a.authority, "reason": action.Question})
				break
			}
			if a.interactor != nil {
				answer, err := a.interactor.Ask(fmt.Sprintf("Navigator needs help: %s", action.Question))
				if err == nil {
					a.logger.Info("human answered", "answer", answer)
				}
			}
			continue
		}

		// Execute the action
		beforeURL := ""
		if info, err := page.Info(); err == nil {
			beforeURL = info.URL
		}
		if strings.EqualFold(strings.TrimSpace(action.Action), "navigate") {
			if target, known := a.navigationTargetAlreadyExplored(action.URL, beforeURL); known {
				failureMsg := fmt.Sprintf("navigation target %q was already explored in this scan; choose a different observed route or respond with done", target)
				a.logger.Info("navigator rejected explored navigation",
					"target", target,
					"url", beforeURL,
				)
				a.db.LogAI(a.scanID, "navigator", "navigation_already_explored",
					failureMsg, beforeURL, target, "skipped")
				recentFailures = appendNavigatorFailure(recentFailures, failureMsg)
				continue
			}
			if a.authority == policy.AuthorityRecon &&
				a.navigatorFamilySaturated(navigatorSurfaceFamily(action.URL, action.Reason), action.URL, action.Reason) {
				target := canonicalNavigatorURL(action.URL, beforeURL)
				failureMsg := fmt.Sprintf("navigation target %q belongs to an already representative semantic family; choose a different observed surface or respond with done", target)
				a.logger.Info("navigator skipped saturated navigation", "target", target)
				a.db.LogAI(a.scanID, "navigator", "navigation_family_saturated",
					failureMsg, beforeURL, target, "compacted")
				a.avoidNavigationTargets[target] = struct{}{}
				recentFailures = appendNavigatorFailure(recentFailures, failureMsg)
				continue
			}
		}
		if repeatedNavigatorAction(attemptedActions, action, beforeURL) {
			repeatTarget := navigatorActionRepeatTarget(action, beforeURL)
			failureMsg := fmt.Sprintf("%s on %q was already attempted on this page; choose a different action or set a different navigate URL", action.Action, repeatTarget)
			a.logger.Info("navigator rejected repeated action",
				"action", action.Action,
				"selector", action.Selector,
				"target", repeatTarget,
				"url", beforeURL,
			)
			a.db.LogAI(a.scanID, "navigator", "action_repeated",
				failureMsg, beforeURL, repeatTarget, "skipped")
			recentFailures = appendNavigatorFailure(recentFailures, failureMsg)
			// Repeats are planning misses, not browser/target failures. Keep
			// them in the model feedback, but do not let them prematurely stop
			// navigation before the remaining step budget can try alternatives.
			continue
		}

		if err := a.nav.ExecuteAction(ctx, page, action); err != nil {
			a.logger.Warn("action failed", "error", err)
			_, _ = a.db.InsertNarration(a.scanID, "navigator", "action_failed",
				fmt.Sprintf("%s did not complete: %s", navigatorActionLabel(action, pageState), err),
				beforeURL, map[string]any{"action": action.Action, "selector": action.Selector})
			// Dynamic applications can re-render between the captured state and
			// the click. If that happened, this was a stale observation rather
			// than three independent action failures. Refresh the world view and
			// let the next step re-plan from the new DOM without tripping the
			// consecutive-failure circuit breaker.
			freshState, captureErr := a.nav.CapturePageState(page)
			if captureErr == nil && navigatorMadeProgress(pageState, freshState) {
				failureMsg := fmt.Sprintf("page state changed before %s on %q could complete; re-plan from the refreshed controls", action.Action, action.Selector)
				a.db.LogAI(a.scanID, "navigator", "stale_action_replan",
					failureMsg, beforeURL, freshState.URL, "replanned")
				recentFailures = appendNavigatorFailure(recentFailures, failureMsg)
				consecutiveFailures = 0
				continue
			}
			a.db.LogAI(a.scanID, "navigator", "action_failed",
				fmt.Sprintf("%s: %s (reason: %s)", action.Action, err, action.Reason),
				beforeURL, action.Selector, "failed")
			failMsg := fmt.Sprintf("%s on %q failed: %s", action.Action, action.Selector, err)
			recentFailures = appendNavigatorFailure(recentFailures, failMsg)
			consecutiveFailures++
			continue
		}

		// A click that leaves both the URL and observable page state unchanged
		// is not progress. Count it as a failure so menu toggles and no-op
		// handlers cannot consume the full navigation budget.
		afterURL := ""
		if info, err := page.Info(); err == nil {
			afterURL = info.URL
		}
		newState, _ := a.nav.CapturePageState(page)
		if strings.EqualFold(strings.TrimSpace(action.Action), "navigate") && navigatorStateLooksLikeProtectionInterstitial(newState) {
			if settled := a.waitForNavigatorInterstitial(ctx, page, newState, 6*time.Second); settled != nil {
				newState = settled
			}
		}
		if action.Action != "fill" && !navigatorMadeProgress(pageState, newState) {
			failureMsg := fmt.Sprintf("%s on %q completed but revealed no new page state", action.Action, action.Selector)
			a.db.LogAI(a.scanID, "navigator", "action_no_progress", failureMsg, beforeURL, afterURL, "failed")
			_, _ = a.db.InsertNarration(a.scanID, "navigator", "no_progress",
				fmt.Sprintf("%s completed but revealed no new UI state, so I’m moving on instead of repeating it.", navigatorActionLabel(action, pageState)),
				beforeURL, map[string]any{"action": action.Action, "selector": action.Selector})
			recentFailures = appendNavigatorFailure(recentFailures, failureMsg)
			// Treat no-progress clicks like repeated actions: useful feedback
			// for the next plan, but not a hard browser/target failure. The
			// step budget still bounds loops.
			continue
		}

		a.db.LogAI(a.scanID, "navigator", action.Action,
			action.Reason, beforeURL, afterURL, "success")
		_, _ = a.db.InsertNarration(a.scanID, "navigator", "action_complete",
			navigatorResultNarration(action, pageState, beforeURL, afterURL),
			afterURL, map[string]any{"action": action.Action, "selector": action.Selector})
		// A successful navigate may land on a different URL (for example,
		// /account redirecting to /login). Remember both the requested route and
		// the landing page so the planner cannot spend another global step on the
		// same redirect boundary from a different page.
		if strings.EqualFold(strings.TrimSpace(action.Action), "navigate") {
			a.rememberNavigationTarget(action.URL, beforeURL)
		}
		if afterURL != "" && afterURL != beforeURL {
			a.rememberNavigationTarget(afterURL, beforeURL)
			a.recordNavigatorDiscovery(beforeURL, afterURL, action)
		}

		// Reset on success
		consecutiveFailures = 0

		// Brief pause to let traffic capture
		time.Sleep(500 * time.Millisecond)

		// Publish that we navigated
		if newState != nil {
			a.bus.Publish(Event{
				Type:   EventPageCrawled,
				Source: a.Name(),
				Payload: PageCrawledPayload{
					URL:   newState.URL,
					Links: extractLinkURLs(newState.Links),
					Forms: len(newState.Forms),
				},
			})
		}
	}

	a.logger.Info("navigator agent finished")
	_, _ = a.db.InsertNarration(a.scanID, "navigator", "tour_complete",
		fmt.Sprintf("Interactive UI tour paused after sampling %d distinct navigation target(s). The scan will keep analyzing captured traffic.", len(a.VisitedNavigationTargets())),
		target, map[string]any{"visited_navigation_targets": a.VisitedNavigationTargets()})
	return nil
}

func navigatorStateLooksLikeProtectionInterstitial(state *browser.PageState) bool {
	if state == nil {
		return false
	}
	text := strings.ToLower(strings.TrimSpace(state.Title + " " + state.VisibleText))
	for _, marker := range []string{
		"just a moment", "performing security verification", "verify you are human",
		"checking your browser", "security challenge", "enable javascript and cookies",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	for _, link := range state.Links {
		if parsed, err := url.Parse(canonicalNavigatorURL(link.Href, state.URL)); err == nil &&
			strings.HasPrefix(strings.ToLower(parsed.Path), "/cdn-cgi/challenge-platform/") {
			return true
		}
	}
	return false
}

func (a *NavigatorAgent) waitForNavigatorInterstitial(ctx context.Context, page *rod.Page, initial *browser.PageState, maxWait time.Duration) *browser.PageState {
	if a == nil || page == nil || !navigatorStateLooksLikeProtectionInterstitial(initial) || maxWait <= 0 {
		return initial
	}
	deadline := time.Now().Add(maxWait)
	latest := initial
	for time.Now().Before(deadline) {
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return latest
		case <-timer.C:
		}
		fresh, err := a.nav.CapturePageState(page)
		if err != nil {
			continue
		}
		latest = fresh
		if !navigatorStateLooksLikeProtectionInterstitial(fresh) {
			if a.db != nil {
				a.db.LogAI(a.scanID, "navigator", "interstitial_settled",
					"The observed protection interstitial resolved within the bounded settle window; continuing with the target application state.",
					initial.URL, fresh.URL, "success")
			}
			return fresh
		}
	}
	return latest
}

func navigatorMayAskHuman(authority policy.TestingAuthority) bool {
	return authority != policy.AuthorityRecon
}

func navigatorPlanNarration(action *browser.NavigatorAction, state *browser.PageState, step, maxSteps int) string {
	label := navigatorActionLabel(action, state)
	reason := strings.TrimSpace(action.Reason)
	if reason == "" {
		return fmt.Sprintf("UI step %d/%d: %s.", step, maxSteps, label)
	}
	return fmt.Sprintf("UI step %d/%d: %s — %s", step, maxSteps, label, reason)
}

func navigatorResultNarration(action *browser.NavigatorAction, state *browser.PageState, beforeURL, afterURL string) string {
	label := navigatorActionLabel(action, state)
	if afterURL != "" && afterURL != beforeURL {
		return fmt.Sprintf("%s completed; the browser moved to %s.", label, afterURL)
	}
	return label + " completed and exposed a new UI state."
}

func navigatorActionLabel(action *browser.NavigatorAction, state *browser.PageState) string {
	if action == nil {
		return "Browser action"
	}
	verb := strings.ToLower(strings.TrimSpace(action.Action))
	switch verb {
	case "click", "submit":
		if button, ok := navigatorButtonBySelector(state, action.Selector); ok && strings.TrimSpace(button.Text) != "" {
			return fmt.Sprintf("%s %q", strings.ToUpper(verb[:1])+verb[1:], strings.TrimSpace(button.Text))
		}
		return fmt.Sprintf("%s %s", strings.ToUpper(verb[:1])+verb[1:], strings.TrimSpace(action.Selector))
	case "navigate":
		return "Navigate to " + strings.TrimSpace(action.URL)
	case "fill":
		return "Fill " + strings.TrimSpace(action.Selector)
	case "scroll":
		return "Scroll for more controls"
	case "done":
		return "Finish this representative UI pass"
	case "ask_human":
		return "Ask the operator for guidance"
	default:
		if verb == "" {
			return "Browser action"
		}
		return strings.ToUpper(verb[:1]) + verb[1:]
	}
}

func appendNavigatorFailure(failures []string, failure string) []string {
	failures = append(failures, failure)
	if len(failures) > 5 {
		failures = failures[len(failures)-5:]
	}
	return failures
}

func (a *NavigatorAgent) ensureNavigationMemory() {
	if a.visitedNavigationTargets == nil {
		a.visitedNavigationTargets = make(map[string]struct{})
	}
	if a.avoidNavigationTargets == nil {
		a.avoidNavigationTargets = make(map[string]struct{})
	}
	if a.observedNavigationTargets == nil {
		a.observedNavigationTargets = make(map[string]struct{})
	}
	if a.visitedSurfaceFamilies == nil {
		a.visitedSurfaceFamilies = make(map[string]int)
	}
	if a.visitedSurfaceShapes == nil {
		a.visitedSurfaceShapes = make(map[string]map[string]struct{})
	}
}

func (a *NavigatorAgent) observeNavigationTargets(state *browser.PageState) {
	if state == nil {
		return
	}
	a.ensureNavigationMemory()
	for _, link := range state.Links {
		if canonical := canonicalNavigatorURL(link.Href, state.URL); canonical != "" {
			if !a.navigationURLAllowed(canonical) || !navigatorApplicationLinkCandidate(canonical) {
				continue
			}
			a.observedNavigationTargets[canonical] = struct{}{}
		}
	}
}

// navigationDecisionState gives the model only links that the immutable scan
// policy could execute. The original page state remains available to capture
// and evidence code; this copy merely prevents out-of-scope links from
// competing for expensive planning turns.
func (a *NavigatorAgent) navigationDecisionState(state *browser.PageState) *browser.PageState {
	if state == nil || a == nil {
		return state
	}
	filtered := *state
	filtered.Forms = compactNavigatorForms(state.Forms, 6, 8)
	filtered.Buttons = append([]browser.ButtonInfo(nil), state.Buttons...)
	if len(filtered.Buttons) > 24 {
		filtered.Buttons = filtered.Buttons[:24]
	}
	filtered.Inputs = compactNavigatorInputs(state.Inputs, 12)
	filtered.Links = make([]browser.LinkInfo, 0, len(state.Links))
	for _, link := range state.Links {
		canonical := canonicalNavigatorURL(link.Href, state.URL)
		if canonical == "" || canonical == canonicalNavigatorURL(state.URL, "") || !a.navigationURLAllowed(canonical) || !navigatorApplicationLinkCandidate(canonical) {
			continue
		}
		if _, explored := a.visitedNavigationTargets[canonical]; explored {
			continue
		}
		if _, avoided := a.avoidNavigationTargets[canonical]; avoided {
			continue
		}
		family := navigatorSurfaceFamily(canonical, link.Text)
		if a.authority == policy.AuthorityRecon && navigatorTaxonomyRoute(canonical) &&
			a.navigatorFamilySaturated(family, canonical, link.Text) {
			continue
		}
		modelLink := link
		modelLink.Text = navigatorModelLinkLabel(canonical, link.Text)
		filtered.Links = append(filtered.Links, modelLink)
	}
	sort.SliceStable(filtered.Links, func(i, j int) bool {
		left := a.navigatorLinkDecisionScore(filtered.Links[i], state.URL)
		right := a.navigatorLinkDecisionScore(filtered.Links[j], state.URL)
		if left != right {
			return left > right
		}
		return canonicalNavigatorURL(filtered.Links[i].Href, state.URL) < canonicalNavigatorURL(filtered.Links[j].Href, state.URL)
	})
	if len(filtered.Links) > 24 {
		filtered.Links = filtered.Links[:24]
	}
	return &filtered
}

func navigatorTaxonomyRoute(canonical string) bool {
	parsed, err := url.Parse(strings.TrimSpace(canonical))
	if err != nil {
		return false
	}
	path := strings.ToLower(parsed.EscapedPath())
	return strings.Contains(path, "/category/") || strings.Contains(path, "/categories/") ||
		strings.Contains(path, "/tag/") || strings.Contains(path, "/tags/")
}

func navigatorSurfaceFamily(rawURL, hint string) string {
	if family := targetmodel.SurfaceFamily(rawURL, hint); family != "" {
		return family
	}
	if navigatorTaxonomyRoute(rawURL) {
		return "taxonomy"
	}
	return ""
}

// navigatorModelLinkLabel adds a small evidence boundary when route structure
// is stronger than an attractive taxonomy label. Catalogs commonly contain
// categories named "Add a comment", "Login", or "History"; those words do not
// prove an action, auth boundary, or workflow. The exact original label remains
// visible, but the model is told what the observed route shape actually proves.
func navigatorModelLinkLabel(canonical, label string) string {
	parsed, err := url.Parse(strings.TrimSpace(canonical))
	if err != nil {
		return label
	}
	path := strings.ToLower(parsed.EscapedPath())
	if strings.Contains(path, "/catalogue/category/") || strings.Contains(path, "/catalog/category/") {
		clean := strings.TrimSpace(label)
		if clean == "" {
			clean = "unnamed"
		}
		return fmt.Sprintf("Catalog category: %s [taxonomy label, not evidence of an action or workflow]", clean)
	}
	return label
}

func navigatorApplicationLinkCandidate(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	path := strings.ToLower(strings.TrimSpace(parsed.EscapedPath()))
	// These are browser/WAF interstitial mechanics, not target application
	// areas. Preserve their traffic and policy narrations as evidence, but do
	// not spend a bounded model-guided tour following help/orchestration links
	// that commonly redirect to an external vendor knowledge base.
	for _, prefix := range []string{
		"/cdn-cgi/challenge-platform/",
		"/.well-known/captcha/",
	} {
		if strings.HasPrefix(path, prefix) {
			return false
		}
	}
	return true
}

func (a *NavigatorAgent) reconNoveltyAction(state *browser.PageState) *browser.NavigatorAction {
	if a == nil || a.authority != policy.AuthorityRecon || state == nil {
		return nil
	}
	a.ensureNavigationMemory()
	type candidate struct {
		url             string
		family          string
		score           int
		label           string
		objectiveBoost  int
		objectiveReason string
	}
	seen := make(map[string]struct{})
	candidates := make([]candidate, 0, len(state.Links)+len(a.observedNavigationTargets))
	add := func(raw, label, base string) {
		canonical := canonicalNavigatorURL(raw, base)
		if canonical == "" || canonical == canonicalNavigatorURL(state.URL, "") || !navigatorApplicationLinkCandidate(canonical) {
			return
		}
		if _, ok := seen[canonical]; ok {
			return
		}
		seen[canonical] = struct{}{}
		if _, ok := a.visitedNavigationTargets[canonical]; ok {
			return
		}
		if _, ok := a.avoidNavigationTargets[canonical]; ok {
			return
		}
		family := targetmodel.SurfaceFamily(canonical, label)
		objectiveBoost, objectiveReason := a.reconObjectiveNavigationBoost(canonical, family, label)
		if !navigatorCoreBusinessSurface(family) && objectiveBoost == 0 {
			return
		}
		// One homepage/shell sample should not suppress the first real entity
		// or journey page. Two distinct response-state shapes are enough for
		// deterministic routing to defer back to the objective-aware model.
		if a.navigatorFamilySaturated(family, canonical, label) {
			return
		}
		link := browser.LinkInfo{Text: label, Href: canonical}
		candidates = append(candidates, candidate{
			url: canonical, family: family, label: label,
			score:          a.navigatorLinkDecisionScore(link, state.URL) + objectiveBoost,
			objectiveBoost: objectiveBoost, objectiveReason: objectiveReason,
		})
	}
	for _, link := range state.Links {
		add(link.Href, link.Text, state.URL)
	}
	for raw := range a.observedNavigationTargets {
		add(raw, "", state.URL)
	}
	if len(candidates) == 0 {
		return nil
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		return candidates[i].url < candidates[j].url
	})
	best := candidates[0]
	if best.score < 35 {
		return nil
	}
	label := strings.TrimSpace(best.label)
	if label == "" {
		label = best.family + " surface"
	}
	reason := fmt.Sprintf("Novelty-first Recon selected the exact observed %s link %q before another security-adjacent page; this under-sampled %s surface should add a distinct business journey or response shape.", best.family, truncate(label, 80), best.family)
	if best.objectiveBoost > 0 {
		reason = fmt.Sprintf("Learning loop promoted the exact observed %s link %q by +%d because %s. The scanner is re-shaping its bounded read-only enumeration from the current target model, without guessing a route.",
			best.family, truncate(label, 80), best.objectiveBoost, best.objectiveReason)
	}
	return &browser.NavigatorAction{
		Action: "navigate",
		URL:    best.url,
		Reason: reason,
	}
}

func (a *NavigatorAgent) reconObjectiveNavigationBoost(rawURL, family, label string) (int, string) {
	if a == nil || len(a.reconObjectives) == 0 {
		return 0, ""
	}
	text := strings.ToLower(rawURL + " " + label)
	bestScore := 0
	bestReason := ""
	for _, objective := range a.reconObjectives {
		if objective.Priority < 6 {
			continue
		}
		matched := false
		switch objective.Kind {
		case "privilege":
			matched = family == "authentication" || family == "account" || family == "administration"
		case "workflow":
			matched = family == "transaction" || family == "review" || family == "collection" || family == "search"
		case "ownership":
			matched = family == "account" || family == "community" || family == "transaction" || navigatorContainsAny(text, "owner", "member", "profile", "order", "account", "tenant")
		case "sensitive_data":
			matched = family == "account" || family == "administration" || family == "developer"
		}
		if !matched {
			continue
		}
		score := objective.Priority * 3
		if score > bestScore {
			bestScore = score
			bestReason = fmt.Sprintf("P%d %s objective %q", objective.Priority, objective.Kind, truncate(objective.Question, 110))
		}
	}
	return bestScore, bestReason
}

func navigatorCoreBusinessSurface(family string) bool {
	switch family {
	case "catalog", "review", "collection", "community", "transaction", "search", "content", "jobs", "status":
		return true
	default:
		return false
	}
}

func compactNavigatorForms(forms []browser.FormInfo, formLimit, inputLimit int) []browser.FormInfo {
	if formLimit <= 0 || len(forms) == 0 {
		return nil
	}
	if len(forms) < formLimit {
		formLimit = len(forms)
	}
	out := make([]browser.FormInfo, 0, formLimit)
	for _, source := range forms[:formLimit] {
		form := source
		form.Inputs = compactNavigatorInputs(source.Inputs, inputLimit)
		out = append(out, form)
	}
	return out
}

func compactNavigatorInputs(inputs []browser.InputInfo, limit int) []browser.InputInfo {
	if limit <= 0 || len(inputs) == 0 {
		return nil
	}
	out := append([]browser.InputInfo(nil), inputs...)
	for i := range out {
		// Input values are capture evidence, not navigation instructions. Never
		// place ambient tokens, hidden state, or filled credentials in a model
		// routing prompt.
		out[i].Value = ""
	}
	sort.SliceStable(out, func(i, j int) bool {
		return navigatorInputDecisionScore(out[i]) > navigatorInputDecisionScore(out[j])
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func navigatorInputDecisionScore(input browser.InputInfo) int {
	typeName := strings.ToLower(strings.TrimSpace(input.Type))
	name := strings.ToLower(strings.TrimSpace(input.Name))
	score := 0
	if typeName != "hidden" {
		score += 20
	}
	switch typeName {
	case "submit", "button", "file", "password", "search", "email":
		score += 12
	}
	if navigatorContainsAny(name, "csrf", "token", "redirect", "return", "state") {
		score += 8
	}
	if input.Required {
		score += 2
	}
	return score
}

func navigatorLinkDecisionScore(link browser.LinkInfo, currentURL string) int {
	return navigatorLinkDecisionScoreWithNovelty(link, currentURL, nil, nil, false)
}

func (a *NavigatorAgent) navigatorLinkDecisionScore(link browser.LinkInfo, currentURL string) int {
	if a == nil {
		return navigatorLinkDecisionScore(link, currentURL)
	}
	a.ensureNavigationMemory()
	return navigatorLinkDecisionScoreWithNovelty(link, currentURL, a.visitedSurfaceFamilies, a.visitedSurfaceShapes, a.authority == policy.AuthorityRecon)
}

func navigatorLinkDecisionScoreWithNovelty(link browser.LinkInfo, currentURL string, visitedFamilies map[string]int, visitedShapes map[string]map[string]struct{}, reconOnly bool) int {
	canonical := canonicalNavigatorURL(link.Href, currentURL)
	if canonical == "" {
		return -1000
	}
	if canonical == canonicalNavigatorURL(currentURL, "") {
		return -500
	}
	parsed, _ := url.Parse(canonical)
	pathText := strings.ToLower(parsed.EscapedPath() + " " + link.Text)
	score := 0
	for _, signal := range []string{
		"login", "sign in", "register", "account", "profile", "settings", "admin",
		"search", "upload", "api", "graphql", "webhook", "security", "checkout", "cart",
		// Common Turkish commerce/auth vocabulary keeps localized high-value
		// surfaces from losing to generic menu order on Example-class targets.
		"giris", "kaydol", "hesabim", "sepet", "favori", "siparis", "urun", "odeme",
	} {
		if strings.Contains(pathText, signal) {
			score += 24
			break
		}
	}
	for _, signal := range []string{
		"/product", "/item", "/detail", "/topic", "/post", "/article", "/story", "/job", "/catalogue/",
	} {
		if strings.Contains(pathText, signal) {
			score += 16
			break
		}
	}
	if strings.Contains(pathText, "/category/") || strings.Contains(pathText, "/tag/") {
		score += 5
	}
	segments := len(strings.FieldsFunc(strings.Trim(parsed.EscapedPath(), "/"), func(r rune) bool { return r == '/' }))
	if segments > 5 {
		segments = 5
	}
	score += segments * 2
	if strings.TrimSpace(link.Text) != "" {
		score += 2
	}
	// Brand-agnostic surface classification prevents a small link budget from
	// being monopolized by account/help chrome. A previously unseen review,
	// catalog, collection, community, transaction, or search area should reach
	// the decision prompt before another route from a sampled family.
	family := targetmodel.SurfaceFamily(canonical, link.Text)
	if family != "" {
		score += targetmodel.SurfaceValue(family)
		if visitedFamilies[family] == 0 {
			score += 30
		} else {
			score -= 12
			// Two or more distinct response-state shapes in the same semantic
			// family make another same-family route less likely to buy a new
			// application area within a bounded Recon tour.
			if len(visitedShapes[family]) >= 2 {
				score -= 8
			}
		}
		if reconOnly {
			switch family {
			case "authentication", "account", "developer", "administration":
				// These remain visible, but generic pentest keywords must not
				// outrank a previously unseen core business journey during the
				// small read-only tour.
				score -= 20
			}
		}
	}
	if navigatorContainsAny(pathText, "next", "previous", "pagination", "page=") {
		score -= 18
	}
	switch workflow.ClassifyControl(canonical) {
	case workflow.ControlDestructive, workflow.ControlFinancial, workflow.ControlSensitiveStateChange:
		score -= 200
	}
	return score
}

func (a *NavigatorAgent) navigationURLAllowed(raw string) bool {
	if a == nil || a.policy == nil {
		return true
	}
	return a.policy.Authorize(policy.Action{TargetURL: strings.TrimSpace(raw), Method: "GET"}).Allowed
}

func (a *NavigatorAgent) observedNavigationSnapshot(limit int) []string {
	a.ensureNavigationMemory()
	out := make([]string, 0, len(a.observedNavigationTargets))
	for target := range a.observedNavigationTargets {
		if _, visited := a.visitedNavigationTargets[target]; visited {
			continue
		}
		if _, avoided := a.avoidNavigationTargets[target]; avoided {
			continue
		}
		if a.authority == policy.AuthorityRecon &&
			a.navigatorFamilySaturated(navigatorSurfaceFamily(target, ""), target, "") {
			continue
		}
		out = append(out, target)
	}
	sort.SliceStable(out, func(i, j int) bool {
		left := a.navigatorLinkDecisionScore(browser.LinkInfo{Href: out[i]}, a.stateTarget())
		right := a.navigatorLinkDecisionScore(browser.LinkInfo{Href: out[j]}, a.stateTarget())
		if left != right {
			return left > right
		}
		return out[i] < out[j]
	})
	if limit > 0 && len(out) > limit {
		return out[:limit]
	}
	return out
}

func renderNavigatorObservedTargets(targets []string) string {
	if len(targets) == 0 {
		return ""
	}
	return "- Exact links observed earlier and still unexplored, ordered by expected semantic/response-shape novelty: " + strings.Join(targets, ", ") + ". These remain valid Recon navigate targets even when the current page is sparse."
}

func (a *NavigatorAgent) rememberNavigationTarget(raw, base string) {
	a.ensureNavigationMemory()
	if canonical := canonicalNavigatorURL(raw, base); canonical != "" {
		a.visitedNavigationTargets[canonical] = struct{}{}
		a.rememberNavigatorSurface(canonical, "", "")
	}
}

func (a *NavigatorAgent) rememberCurrentNavigationTarget(raw string) {
	a.ensureNavigationMemory()
	if canonical := canonicalNavigatorURL(raw, ""); canonical != "" {
		a.visitedNavigationTargets[canonical] = struct{}{}
	}
}

func (a *NavigatorAgent) stateTarget() string {
	if a == nil || a.state == nil {
		return ""
	}
	return a.state.ReadModel().Target
}

func (a *NavigatorAgent) observeNavigatorSurface(state *browser.PageState) {
	if state == nil {
		return
	}
	a.rememberNavigatorSurface(state.URL, state.Title, navigatorSemanticStateShape(state))
}

func (a *NavigatorAgent) rememberNavigatorSurface(rawURL, hint, shape string) {
	a.ensureNavigationMemory()
	family := semanticSaturationFamily(rawURL, hint)
	if family == "" {
		return
	}
	if a.semanticSaturation != nil {
		a.semanticSaturation.Observe(rawURL, hint, shape, "navigator", 0)
	}
	a.visitedSurfaceFamilies[family]++
	if strings.TrimSpace(shape) == "" {
		return
	}
	if a.visitedSurfaceShapes[family] == nil {
		a.visitedSurfaceShapes[family] = make(map[string]struct{})
	}
	a.visitedSurfaceShapes[family][shape] = struct{}{}
}

func (a *NavigatorAgent) navigatorFamilySaturated(family, rawURL, hint string) bool {
	family = semanticSaturationFamily(rawURL, hint)
	if browser.IsInterestingPath(rawURL) {
		return false
	}
	if len(a.visitedSurfaceShapes[family]) >= 2 || a.visitedSurfaceFamilies[family] >= 3 {
		return true
	}
	if a.semanticSaturation == nil {
		return false
	}
	if navigatorTaxonomyRoute(rawURL) {
		return a.semanticSaturation.SuppressibleTaxonomy(rawURL, hint)
	}
	return a.semanticSaturation.Saturated(family)
}

// navigatorSemanticStateShape is a redacted response-state fingerprint. It
// describes the UI affordance shape without copying page text, input values,
// tokens, or target data into memory. It is used only to avoid buying another
// model turn for a semantic family whose representative states are already
// well sampled.
func navigatorSemanticStateShape(state *browser.PageState) string {
	if state == nil {
		return ""
	}
	parts := make([]string, 0, len(state.Forms)+len(state.Buttons)+len(state.Links)+4)
	for _, form := range state.Forms {
		inputTypes := make([]string, 0, len(form.Inputs))
		for _, input := range form.Inputs {
			inputTypes = append(inputTypes, strings.ToLower(strings.TrimSpace(input.Type)))
		}
		sort.Strings(inputTypes)
		parts = append(parts, "form:"+strings.ToUpper(strings.TrimSpace(form.Method))+":"+strings.Join(inputTypes, ","))
	}
	for _, button := range state.Buttons {
		parts = append(parts, "button:"+string(navigatorControlRiskForButton(button)))
	}
	linkFamilies := make(map[string]struct{})
	for _, link := range state.Links {
		if family := targetmodel.SurfaceFamily(link.Href, link.Text); family != "" {
			linkFamilies[family] = struct{}{}
		}
	}
	for family := range linkFamilies {
		parts = append(parts, "link:"+family)
	}
	sort.Strings(parts)
	return strings.Join(parts, "|")
}

func (a *NavigatorAgent) navigationTargetAlreadyExplored(raw, base string) (string, bool) {
	a.ensureNavigationMemory()
	target := canonicalNavigatorURL(raw, base)
	if target == "" {
		return "", false
	}
	if _, ok := a.avoidNavigationTargets[target]; ok {
		return target, true
	}
	if _, ok := a.visitedNavigationTargets[target]; ok {
		return target, true
	}
	return target, false
}

func (a *NavigatorAgent) navigationAvoidanceSnapshot(limit int) []string {
	a.ensureNavigationMemory()
	seen := make(map[string]struct{})
	for target := range a.avoidNavigationTargets {
		seen[target] = struct{}{}
	}
	for target := range a.visitedNavigationTargets {
		seen[target] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for target := range seen {
		out = append(out, target)
	}
	sort.Strings(out)
	if limit > 0 && len(out) > limit {
		return out[:limit]
	}
	return out
}

func renderNavigatorAvoidance(targets []string) string {
	if len(targets) == 0 {
		return ""
	}
	return "- Already explored navigator routes this scan: " + strings.Join(targets, ", ") + ". Prefer a different observed route/control, or respond with done when no useful gap remains."
}

func (a *NavigatorAgent) recordNavigatorDiscovery(sourceURL, targetURL string, action *browser.NavigatorAction) {
	if a.db == nil || a.scanID == 0 {
		return
	}
	source := canonicalNavigatorURL(sourceURL, "")
	target := canonicalNavigatorURL(targetURL, sourceURL)
	if source == "" || target == "" || source == target {
		return
	}
	detailParts := []string{strings.TrimSpace(action.Action)}
	if strings.TrimSpace(action.Selector) != "" {
		detailParts = append(detailParts, strings.TrimSpace(action.Selector))
	}
	if strings.TrimSpace(action.Reason) != "" {
		detailParts = append(detailParts, truncate(strings.TrimSpace(action.Reason), 140))
	}
	_ = a.db.InsertDiscovery(a.scanID, store.Discovery{
		TargetURL: target,
		SourceURL: source,
		Kind:      store.DiscoveryNavigator,
		Detail:    strings.Join(detailParts, " — "),
	})
}

func (a *NavigatorAgent) executeSafeFormWorkflow(
	ctx context.Context,
	page *rod.Page,
	initial *browser.PageState,
	formMemory map[string]*navigatorFormMemory,
	step int,
) (bool, *browser.PageState, error) {
	current := initial
	executed := false

	for actionCount := 0; actionCount < 4; actionCount++ {
		action := nextSafeFormAction(current, formMemory)
		if action == nil {
			return executed, current, nil
		}
		executed = true

		if err := validateNavigatorAction(action, current); err != nil {
			return true, current, fmt.Errorf("safe form action rejected: %w", err)
		}

		a.logger.Info("navigator chose safe form action",
			"step", step,
			"macro_action", actionCount+1,
			"action", action.Action,
			"selector", action.Selector,
			"reason", action.Reason)
		a.db.LogAI(a.scanID, "navigator", "safe_form_plan",
			action.Reason, current.URL, action.Selector, "planned")
		_, _ = a.db.InsertNarration(a.scanID, "navigator", "safe_form_plan",
			action.Reason, current.URL, map[string]any{
				"action":       action.Action,
				"selector":     action.Selector,
				"value":        redactNavigatorActionValue(action),
				"macro_action": actionCount + 1,
			})

		beforeURL := ""
		if info, err := page.Info(); err == nil {
			beforeURL = info.URL
		}
		if err := a.nav.ExecuteAction(ctx, page, action); err != nil {
			a.db.LogAI(a.scanID, "navigator", "safe_form_failed",
				fmt.Sprintf("%s: %s (reason: %s)", action.Action, err, action.Reason),
				beforeURL, action.Selector, "failed")
			return true, current, fmt.Errorf("%s on %q failed: %w", action.Action, action.Selector, err)
		}

		time.Sleep(500 * time.Millisecond)
		afterURL := ""
		if info, err := page.Info(); err == nil {
			afterURL = info.URL
		}
		a.db.LogAI(a.scanID, "navigator", "safe_form_action",
			action.Reason, beforeURL, afterURL, "success")

		fresh, err := a.nav.CapturePageState(page)
		if err != nil {
			return true, current, fmt.Errorf("capture state after safe form action: %w", err)
		}
		current = fresh

		// Stop the macro after a click/submit-style action. The app may now
		// be processing auth, search, or validation; let the next outer
		// navigator turn observe the result and decide where to go next.
		if action.Action == "click" || action.Action == "submit" {
			return true, current, nil
		}
	}

	return executed, current, nil
}

func validateNavigatorAction(action *browser.NavigatorAction, state *browser.PageState) error {
	switch action.Action {
	case "done", "ask_human", "scroll":
		return nil
	case "navigate":
		if strings.TrimSpace(action.URL) == "" {
			return fmt.Errorf("navigate requires a URL")
		}
		risk := workflow.ClassifyControl(action.URL)
		if risk == workflow.ControlDestructive || risk == workflow.ControlFinancial || risk == workflow.ControlSensitiveStateChange {
			return fmt.Errorf("navigation target %q is a %s business action; discover the link but do not activate it automatically", action.URL, risk)
		}
		return nil
	case "click", "fill", "submit":
		if strings.TrimSpace(action.Selector) == "" {
			return fmt.Errorf("%s requires a selector", action.Action)
		}
		if action.Action == "click" || action.Action == "submit" {
			if button, ok := navigatorButtonBySelector(state, action.Selector); ok {
				risk := navigatorControlRiskForButton(button)
				if risk == workflow.ControlDestructive ||
					risk == workflow.ControlFinancial ||
					risk == workflow.ControlSensitiveStateChange {
					return fmt.Errorf("selector %q is a %s business action; discover the surface but do not activate it automatically", action.Selector, risk)
				}
			}
		}
		if selectorObserved(action.Selector, state) {
			return nil
		}
		return fmt.Errorf("selector %q was not present in captured page state", action.Selector)
	default:
		return fmt.Errorf("unknown action %q", action.Action)
	}
}

func normalizeNavigatorNavigationURL(action *browser.NavigatorAction, state *browser.PageState) (before string, after string, changed bool) {
	if action == nil || !strings.EqualFold(strings.TrimSpace(action.Action), "navigate") || state == nil {
		return "", "", false
	}
	raw := strings.TrimSpace(action.URL)
	if raw == "" {
		return "", "", false
	}
	target, err := url.Parse(raw)
	if err != nil || target.IsAbs() {
		return "", "", false
	}
	base, err := url.Parse(strings.TrimSpace(state.URL))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return "", "", false
	}
	resolved := base.ResolveReference(target).String()
	if resolved == "" || resolved == raw {
		return "", "", false
	}
	action.URL = resolved
	return raw, resolved, true
}

func normalizeNavigatorActionForHashRouting(action *browser.NavigatorAction, state *browser.PageState) (before string, after string, changed bool) {
	if action == nil || !strings.EqualFold(strings.TrimSpace(action.Action), "navigate") || state == nil || !navigatorStateShowsHashRouting(state) {
		return "", "", false
	}
	raw := strings.TrimSpace(action.URL)
	if raw == "" || navigatorObservedPlainNavigationTarget(raw, state) {
		return "", "", false
	}
	target, err := url.Parse(raw)
	if err != nil {
		return "", "", false
	}
	base, err := url.Parse(state.URL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return "", "", false
	}
	if !target.IsAbs() {
		target = base.ResolveReference(target)
	}
	if target.Scheme == "" || target.Host == "" || !strings.EqualFold(target.Host, base.Host) {
		return "", "", false
	}
	if navigatorFragmentIsRoute(target.Fragment) {
		return "", "", false
	}
	if target.Path == "" || target.Path == "/" || navigatorPlainRouteShouldStayServerPath(target.Path) {
		return "", "", false
	}
	route := target.EscapedPath()
	if route == "" {
		route = target.Path
	}
	if !strings.HasPrefix(route, "/") {
		route = "/" + route
	}
	if target.RawQuery != "" {
		route += "?" + target.RawQuery
	}
	rewritten := *base
	if rewritten.Path == "" {
		rewritten.Path = "/"
	}
	rewritten.RawQuery = ""
	rewritten.Fragment = route
	before = raw
	after = rewritten.String()
	if canonicalNavigatorURL(before, state.URL) == canonicalNavigatorURL(after, state.URL) {
		return "", "", false
	}
	action.URL = after
	return before, after, true
}

func navigatorObservedPlainNavigationTarget(raw string, state *browser.PageState) bool {
	if state == nil {
		return false
	}
	target := canonicalNavigatorURL(raw, state.URL)
	if target == "" {
		return false
	}
	for _, link := range state.Links {
		href := strings.TrimSpace(link.Href)
		if href == "" || strings.Contains(href, "#/") || strings.Contains(href, "#!") {
			continue
		}
		if canonicalNavigatorURL(href, state.URL) == target {
			return true
		}
	}
	return false
}

func navigatorPlainRouteShouldStayServerPath(path string) bool {
	lower := strings.ToLower(strings.TrimSpace(path))
	if lower == "" || lower == "/" {
		return true
	}
	serverPrefixes := []string{
		"/api", "/rest", "/graphql", "/metrics", "/ftp", "/socket.io",
		"/assets", "/asset", "/static", "/public", "/vendor", "/dist",
		"/api-docs", "/swagger", "/openapi",
	}
	for _, prefix := range serverPrefixes {
		if lower == prefix || strings.HasPrefix(lower, prefix+"/") || strings.HasPrefix(lower, prefix+".") {
			return true
		}
	}
	lastSlash := strings.LastIndex(lower, "/")
	lastDot := strings.LastIndex(lower, ".")
	if lastDot > lastSlash {
		switch lower[lastDot:] {
		case ".js", ".mjs", ".css", ".map", ".json", ".xml", ".txt", ".md", ".pdf",
			".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2", ".ttf":
			return true
		}
	}
	return false
}

func validateNavigatorActionForAuthority(action *browser.NavigatorAction, state *browser.PageState, authority policy.TestingAuthority) error {
	return validateNavigatorActionForAuthorityWithObserved(action, state, authority, nil)
}

func (a *NavigatorAgent) validateActionForAuthority(action *browser.NavigatorAction, state *browser.PageState) error {
	if a == nil {
		return validateNavigatorActionForAuthority(action, state, policy.AuthorityActive)
	}
	a.ensureNavigationMemory()
	return validateNavigatorActionForAuthorityWithObserved(action, state, a.authority, a.observedNavigationTargets)
}

func (a *NavigatorAgent) authorizeNavigationAction(action *browser.NavigatorAction) error {
	if a == nil || a.policy == nil || action == nil || !strings.EqualFold(strings.TrimSpace(action.Action), "navigate") {
		return nil
	}
	decision := a.policy.Authorize(policy.Action{TargetURL: strings.TrimSpace(action.URL), Method: "GET"})
	if decision.Allowed {
		return nil
	}
	if a.auditDeny != nil {
		a.auditDeny(decision)
	}
	return fmt.Errorf("%s", decision.Reason)
}

func validateNavigatorActionForAuthorityWithObserved(action *browser.NavigatorAction, state *browser.PageState, authority policy.TestingAuthority, observed map[string]struct{}) error {
	if authority != policy.AuthorityRecon || action == nil {
		return nil
	}
	if action.Action == "fill" || action.Action == "submit" {
		return fmt.Errorf("Recon Only observes forms but does not fill or submit them")
	}
	if action.Action == "navigate" && !reconNavigationTargetObservedInSet(action.URL, state, observed) {
		return fmt.Errorf("Recon Only navigation must use an exact link observed during this browser tour; refusing guessed URL %q", strings.TrimSpace(action.URL))
	}
	if action.Action != "click" {
		return nil
	}
	button, ok := navigatorButtonBySelector(state, action.Selector)
	if !ok {
		return nil
	}
	text := navigatorControlText(button)
	if strings.EqualFold(strings.TrimSpace(button.Type), "submit") || navigatorContainsAny(text,
		"login", "log in", "sign in", "register", "sign up", "google", "facebook", "oauth", "continue with") {
		return fmt.Errorf("Recon Only does not activate authentication or form workflow control %q", strings.TrimSpace(button.Text))
	}
	return nil
}

func reconNavigationTargetObserved(rawTarget string, state *browser.PageState) bool {
	return reconNavigationTargetObservedInSet(rawTarget, state, nil)
}

func reconNavigationTargetObservedInSet(rawTarget string, state *browser.PageState, observed map[string]struct{}) bool {
	if state == nil {
		return false
	}
	target := canonicalNavigatorURL(rawTarget, state.URL)
	if target == "" {
		return false
	}
	for _, link := range state.Links {
		if canonicalNavigatorURL(link.Href, state.URL) == target {
			return true
		}
	}
	_, ok := observed[target]
	if ok {
		return true
	}
	return false
}

func canonicalNavigatorURL(raw, base string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if !parsed.IsAbs() {
		if base == "" {
			return ""
		}
		baseURL, baseErr := url.Parse(base)
		if baseErr != nil {
			return ""
		}
		parsed = baseURL.ResolveReference(parsed)
	}
	if !navigatorFragmentIsRoute(parsed.Fragment) {
		parsed.Fragment = ""
	}
	return parsed.String()
}

func navigatorFragmentIsRoute(fragment string) bool {
	fragment = strings.TrimSpace(fragment)
	return strings.HasPrefix(fragment, "/") || strings.HasPrefix(fragment, "!/")
}

func navigatorContainsAny(text string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(text, needle) {
			return true
		}
	}
	return false
}

func selectorObserved(selector string, state *browser.PageState) bool {
	if state == nil || selector == "" {
		return false
	}
	for _, button := range state.Buttons {
		if selector == button.Selector {
			return true
		}
	}
	for _, input := range state.Inputs {
		if selector == input.Selector && input.Selector != "" {
			return true
		}
	}
	for _, form := range state.Forms {
		for _, input := range form.Inputs {
			if selector == input.Selector && input.Selector != "" {
				return true
			}
		}
	}
	return false
}

func navigatorButtonBySelector(state *browser.PageState, selector string) (browser.ButtonInfo, bool) {
	if state == nil || selector == "" {
		return browser.ButtonInfo{}, false
	}
	for _, button := range state.Buttons {
		if button.Selector == selector {
			return button, true
		}
	}
	return browser.ButtonInfo{}, false
}

func navigatorMadeProgress(before, after *browser.PageState) bool {
	if before == nil || after == nil {
		return false
	}
	if before.URL != after.URL || before.Title != after.Title || before.VisibleText != after.VisibleText {
		return true
	}
	beforeShape, _ := json.Marshal(struct {
		Forms   []browser.FormInfo
		Links   []browser.LinkInfo
		Buttons []browser.ButtonInfo
		Inputs  []browser.InputInfo
	}{before.Forms, before.Links, before.Buttons, before.Inputs})
	afterShape, _ := json.Marshal(struct {
		Forms   []browser.FormInfo
		Links   []browser.LinkInfo
		Buttons []browser.ButtonInfo
		Inputs  []browser.InputInfo
	}{after.Forms, after.Links, after.Buttons, after.Inputs})
	return string(beforeShape) != string(afterShape)
}

// repeatedNavigatorAction records an action and reports whether the same
// action was already attempted on the current page. Values and destination
// URLs are part of the identity so trying a different input or route remains
// possible; revisiting the same selector after real navigation is also allowed.
func repeatedNavigatorAction(seen map[string]struct{}, action *browser.NavigatorAction, currentURL string) bool {
	key := navigatorActionRepeatKey(action, currentURL)
	if _, ok := seen[key]; ok {
		return true
	}
	seen[key] = struct{}{}
	return false
}

func navigatorActionRepeatKey(action *browser.NavigatorAction, currentURL string) string {
	if action == nil {
		return ""
	}
	current := canonicalNavigatorURL(currentURL, "")
	target := strings.TrimSpace(action.URL)
	if strings.EqualFold(strings.TrimSpace(action.Action), "navigate") {
		if canonical := canonicalNavigatorURL(action.URL, currentURL); canonical != "" {
			target = canonical
		}
	}
	return strings.Join([]string{
		strings.ToLower(strings.TrimSpace(action.Action)),
		current,
		strings.TrimSpace(action.Selector),
		strings.TrimSpace(action.Value),
		target,
	}, "\x00")
}

func navigatorActionRepeatTarget(action *browser.NavigatorAction, currentURL string) string {
	if action == nil {
		return ""
	}
	if strings.EqualFold(strings.TrimSpace(action.Action), "navigate") {
		if target := canonicalNavigatorURL(action.URL, currentURL); target != "" {
			return target
		}
		if strings.TrimSpace(action.URL) != "" {
			return strings.TrimSpace(action.URL)
		}
	}
	if strings.TrimSpace(action.Selector) != "" {
		return strings.TrimSpace(action.Selector)
	}
	if strings.TrimSpace(action.URL) != "" {
		return strings.TrimSpace(action.URL)
	}
	return strings.TrimSpace(currentURL)
}

type navigatorFormMemory struct {
	Filled    map[string]struct{}
	Submitted bool
}

func nextSafeFormAction(state *browser.PageState, byURL map[string]*navigatorFormMemory) *browser.NavigatorAction {
	if state == nil {
		return nil
	}
	memoryKey := navigatorFormMemoryKey(state.URL)
	mem := byURL[memoryKey]
	if mem == nil {
		mem = &navigatorFormMemory{Filled: make(map[string]struct{})}
		byURL[memoryKey] = mem
	}

	inputs := navigatorFillableInputs(state)
	for _, input := range inputs {
		if _, ok := mem.Filled[input.Selector]; ok {
			continue
		}
		value, ok := safeNavigatorInputValue(input)
		if !ok {
			continue
		}
		mem.Filled[input.Selector] = struct{}{}
		return &browser.NavigatorAction{
			Action:   "fill",
			Selector: input.Selector,
			Value:    value,
			Reason:   fmt.Sprintf("Visible %s input %q is part of the current workflow; filling it with a safe synthetic value before navigating away.", navigatorInputRole(input), input.Selector),
		}
	}

	if len(inputs) == 0 || mem.Submitted {
		return nil
	}
	button, ok := navigatorSafeSubmitButton(state.Buttons, inputs)
	if !ok {
		return nil
	}
	mem.Submitted = true
	return &browser.NavigatorAction{
		Action:   "click",
		Selector: button.Selector,
		Reason:   fmt.Sprintf("Inputs on this page were filled; clicking observed %q button to exercise the workflow and capture resulting API traffic.", strings.TrimSpace(button.Text)),
	}
}

func navigatorFormMemoryKey(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return rawURL
	}
	// Search controls commonly synchronize their value into the URL after
	// every keystroke. Query values are page state, not a new workflow. Keep
	// the hash-route path because /#/login and /#/search are distinct forms,
	// but discard the hash query for the same reason.
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	if fragmentPath, _, found := strings.Cut(parsed.Fragment, "?"); found {
		parsed.Fragment = fragmentPath
	}
	return parsed.String()
}

func navigatorFillableInputs(state *browser.PageState) []browser.InputInfo {
	if state == nil {
		return nil
	}
	seen := make(map[string]struct{})
	var out []browser.InputInfo
	add := func(input browser.InputInfo) {
		if strings.TrimSpace(input.Selector) == "" || !navigatorInputIsFillable(input) {
			return
		}
		if _, ok := seen[input.Selector]; ok {
			return
		}
		seen[input.Selector] = struct{}{}
		out = append(out, input)
	}
	for _, input := range state.Inputs {
		add(input)
	}
	for _, form := range state.Forms {
		for _, input := range form.Inputs {
			add(input)
		}
	}
	return out
}

func safeNavigatorInputValue(input browser.InputInfo) (string, bool) {
	role := navigatorInputRole(input)
	switch role {
	case "password":
		return "Password1!", true
	case "email":
		return "aobtd-nav@example.test", true
	case "search":
		return "aobtd-test", true
	case "number":
		return "1", true
	case "url":
		return "https://example.test/aobtd", true
	case "tel":
		return "5550100", true
	case "text":
		return "aobtd-test", true
	default:
		return "", false
	}
}

func navigatorSafeSubmitButton(buttons []browser.ButtonInfo, inputs []browser.InputInfo) (browser.ButtonInfo, bool) {
	hasSearchInput := false
	hasAuthInput := false
	for _, input := range inputs {
		switch navigatorInputRole(input) {
		case "search":
			hasSearchInput = true
		case "email", "password":
			hasAuthInput = true
		}
	}
	bestScore := 0
	var best browser.ButtonInfo
	for _, button := range buttons {
		text := navigatorControlText(button)
		if text == "" {
			continue
		}
		if navigatorControlRiskForButton(button) != workflow.ControlSafe {
			continue
		}
		if navigatorButtonLooksLikeChrome(button) {
			continue
		}
		score := 0
		switch {
		case strings.Contains(text, "login") ||
			strings.Contains(text, "log in") ||
			strings.Contains(text, "sign in"):
			if hasAuthInput {
				score = 100
			}
		case strings.Contains(text, "register") ||
			strings.Contains(text, "sign up"):
			if hasAuthInput {
				score = 90
			}
		case strings.Contains(text, "search") || strings.EqualFold(strings.TrimSpace(button.Text), "ara"):
			if hasSearchInput {
				score = 100
			}
		case strings.Contains(text, "submit"):
			score = 70
		case strings.Contains(text, "continue"):
			if hasAuthInput {
				score = 60
			}
		}
		if score > bestScore {
			bestScore = score
			best = button
		}
	}
	return best, bestScore > 0
}

func navigatorButtonLooksLikeChrome(button browser.ButtonInfo) bool {
	text := navigatorControlText(button)
	for _, phrase := range []string{
		"open search",
		"close search",
		"open sidenav",
		"close sidenav",
		"navbar",
		"menu",
		"hamburger",
		"account",
		"basket",
		"cart",
	} {
		if strings.Contains(text, phrase) {
			return true
		}
	}
	return false
}

func navigatorControlRiskForButton(button browser.ButtonInfo) workflow.ControlRisk {
	return workflow.ClassifyControl(navigatorControlText(button))
}

func navigatorControlText(button browser.ButtonInfo) string {
	return strings.ToLower(strings.TrimSpace(button.Text + " " + button.Type + " " + button.Selector))
}

func navigatorButtonLooksDestructive(text string) bool {
	return workflow.ClassifyControl(text) != workflow.ControlSafe
}

func redactNavigatorActionValue(action *browser.NavigatorAction) string {
	if action == nil || action.Value == "" {
		return ""
	}
	if action.Action == "fill" && strings.Contains(strings.ToLower(action.Selector), "password") {
		return "<redacted-password>"
	}
	return action.Value
}

func (a *NavigatorAgent) decideAction(ctx context.Context, state *browser.PageState, step int, failures []string) (*browser.NavigatorAction, error) {
	stateJSON, _ := json.MarshalIndent(state, "", "  ")

	// Build context about what we already know
	model := a.state.ReadModel()
	knownEndpoints := len(model.Endpoints)
	affordanceHints := navigatorAffordanceHints(state)
	reconObjectives := renderReconObjectives(a.reconObjectives)
	avoidanceHints := renderNavigatorAvoidance(a.navigationAvoidanceSnapshot(8))
	observedHints := renderNavigatorObservedTargets(a.observedNavigationSnapshot(8))

	failureContext := ""
	if len(failures) > 0 {
		failureContext = "\n\nRECENT FAILURES (do NOT repeat these actions):\n"
		for _, f := range failures {
			failureContext += "  - " + f + "\n"
		}
		failureContext += "\nYou MUST try a DIFFERENT action. If all interactive elements fail, use 'navigate' to go to a different URL, or 'done' to stop.\n"
	}

	authorityHint := ""
	formHint := "If visible forms or inputs exist, prefer filling them with safe semantic test values and then submitting/clicking an observed submit button before navigating away."
	if a.authority == policy.AuthorityRecon {
		formHint = "Visible forms are evidence only: describe their purpose and boundaries, but do not fill or submit them."
		authorityHint = "\nRECON ONLY: never fill, submit, log in, register, log out, or activate OAuth/social-login controls. For navigate actions, choose only exact URLs copied from the current page state's links or the previously observed exact-link list; do not guess /admin, /api, /settings, or other unobserved paths. Prefer read-only navigation, scrolling, menus, and links."
	}
	focusHint := "Focus on: finding new page types, admin areas, settings, search functionality, file uploads, or API endpoints."
	if a.authority == policy.AuthorityRecon {
		focusHint = "Recon discovery order: first ground the target's primary public business objects and human journeys (catalog/content/detail, reviews, lists, members/community, search, or transactions). Prefer a new semantic surface over another login, registration, settings, API, help, or legal variant. Sample security-adjacent pages after the core application purpose is represented, unless an explicit Recon objective requires one."
	}
	prompt := fmt.Sprintf(`Current page state (step %d of %d):

%s

Known endpoints so far: %d
Target: %s
Navigation hints:
%s
%s
%s
%s
%s
What should I do next to discover more of this application?
%s
%s
%s
Use representative UI sampling: exercise controls that reveal a distinct workflow or page type, but skip repeated product/course/article cards and equivalent pagination items.
Treat URL route structure as stronger evidence than an attractive link label. In particular, a catalog/category taxonomy label is not evidence that an action or workflow exists.
Avoid: revisiting pages we've already seen, clicking on repeated listings, or navigating to the current URL again.
For navigate actions, set "url" to a non-empty href copied from page state links, including "#/..." SPA routes when present; never leave "url" blank.
If elements keep failing, navigate to a completely different URL or respond with "done".

Respond with a single JSON action object.`,
		step+1, a.maxSteps,
		string(stateJSON),
		knownEndpoints,
		model.Target,
		affordanceHints,
		avoidanceHints,
		observedHints,
		formHint,
		reconObjectives,
		focusHint,
		authorityHint,
		failureContext)

	llmStart := time.Now()
	req := &llm.Request{
		SystemPrompt: navigatorSystemPromptForAuthority(a.authority),
		Messages:     []llm.Message{{Role: "user", Content: prompt}},
		Temperature:  0.3,
		MaxTokens:    llm.StructuredOutputTokenLimit(a.provider, 768, 2048),
		JSONMode:     true,
	}
	resp, err := llm.CompleteBudgeted(ctx, a.provider, a.budget, req, 0)
	llmDuration := time.Since(llmStart).Milliseconds()
	if err != nil {
		return nil, err
	}

	modelID := llm.ResponseModel(resp, a.provider)
	costUcents := llm.CostMicroCents(modelID, resp.Usage)
	a.db.LogAIFull(a.scanID, "navigator", "decide_action",
		fmt.Sprintf("step %d/%d", step+1, a.maxSteps),
		"", "", truncate(resp.Content, 150),
		resp.Usage.InputTokens, resp.Usage.OutputTokens, llmDuration, costUcents, modelID,
		llm.RenderPrompt(req), resp.Content)

	action, err := browser.ParseAction(resp.Content)
	if err != nil {
		return nil, fmt.Errorf("parse action: %w (raw: %s)", err, resp.Content[:min(len(resp.Content), 200)])
	}

	return action, nil
}

func navigatorSystemPromptForAuthority(authority policy.TestingAuthority) string {
	if authority == policy.AuthorityRecon {
		return prompts.NavigatorReconSystemPrompt
	}
	return prompts.NavigatorSystemPrompt
}

func navigatorAffordanceHints(state *browser.PageState) string {
	if state == nil {
		return "- Page state unavailable; choose a conservative action."
	}
	var hints []string
	if navigatorStateShowsHashRouting(state) {
		samples := navigatorHashRouteSamples(state, 5)
		sampleText := ""
		if len(samples) > 0 {
			sampleText = " Observed hash routes: " + strings.Join(samples, ", ") + "."
		}
		hints = append(hints,
			"- Hash-routed SPA detected. For navigate actions, prefer observed '#/...' routes and avoid guessing plain app paths like /admin, /settings, or /account unless they appear as real links; plain fallback paths can create noisy nested asset/socket URLs."+sampleText,
		)
	}
	fillable := make([]browser.InputInfo, 0)
	for _, input := range state.Inputs {
		if input.Selector != "" && navigatorInputIsFillable(input) {
			fillable = append(fillable, input)
		}
	}
	for _, form := range state.Forms {
		for _, input := range form.Inputs {
			if input.Selector != "" && navigatorInputIsFillable(input) {
				fillable = append(fillable, input)
			}
		}
	}
	if len(fillable) > 0 {
		limit := min(len(fillable), 5)
		selectors := make([]string, 0, limit)
		for i := 0; i < limit; i++ {
			input := fillable[i]
			selectors = append(selectors, fmt.Sprintf("%s(%s)", input.Selector, navigatorInputRole(input)))
		}
		hints = append(hints,
			"- Visible fillable inputs exist: "+strings.Join(selectors, ", ")+". Prefer filling one of these before another navigate action.",
			"- Safe test values: search/text='aobtd-test', email='aobtd-nav@example.test', password='Password1!'.",
			"- After required fields are filled, click or submit an observed submit/login/register/search button.",
		)
	}
	if len(state.Buttons) > 0 {
		var labels []string
		var guarded []string
		for _, button := range state.Buttons {
			text := strings.TrimSpace(button.Text)
			if text == "" {
				continue
			}
			labels = append(labels, text)
			risk := navigatorControlRiskForButton(button)
			if risk == workflow.ControlDestructive ||
				risk == workflow.ControlFinancial ||
				risk == workflow.ControlSensitiveStateChange {
				guarded = append(guarded, fmt.Sprintf("%s(%s)", text, risk))
			}
			if len(labels) >= 6 {
				break
			}
		}
		if len(labels) > 0 {
			hints = append(hints, "- Visible button labels: "+strings.Join(labels, ", ")+".")
		}
		if len(guarded) > 0 {
			hints = append(hints, "- Sensitive business controls visible but should not be activated automatically: "+strings.Join(guarded, ", ")+".")
		}
	}
	if len(hints) == 0 {
		return "- No obvious visible form inputs; discover new app areas with links/buttons or a different on-target URL."
	}
	return strings.Join(hints, "\n")
}

func navigatorStateShowsHashRouting(state *browser.PageState) bool {
	if state == nil {
		return false
	}
	if strings.Contains(state.URL, "#/") || strings.Contains(state.URL, "#!") {
		return true
	}
	for _, link := range state.Links {
		if strings.Contains(link.Href, "#/") || strings.Contains(link.Href, "#!") {
			return true
		}
	}
	return false
}

func navigatorHashRouteSamples(state *browser.PageState, limit int) []string {
	if state == nil || limit <= 0 {
		return nil
	}
	seen := make(map[string]struct{})
	var samples []string
	add := func(raw string) {
		if len(samples) >= limit {
			return
		}
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		idx := strings.Index(raw, "#")
		if idx < 0 {
			return
		}
		route := raw[idx:]
		if !strings.HasPrefix(route, "#/") && !strings.HasPrefix(route, "#!") {
			return
		}
		if _, ok := seen[route]; ok {
			return
		}
		seen[route] = struct{}{}
		samples = append(samples, route)
	}
	add(state.URL)
	for _, link := range state.Links {
		add(link.Href)
	}
	return samples
}

func navigatorInputIsFillable(input browser.InputInfo) bool {
	switch strings.ToLower(strings.TrimSpace(input.Type)) {
	case "", "text", "search", "email", "password", "number", "tel", "url":
		return true
	default:
		return false
	}
}

func navigatorInputRole(input browser.InputInfo) string {
	joined := strings.ToLower(strings.Join([]string{input.Type, input.Name, input.Value, input.Selector}, " "))
	switch {
	case strings.Contains(joined, "password"):
		return "password"
	case strings.Contains(joined, "email") || strings.Contains(joined, "user"):
		return "email"
	case strings.Contains(joined, "search") || strings.Contains(joined, "query") || strings.Contains(joined, "q"):
		return "search"
	default:
		if strings.TrimSpace(input.Type) != "" {
			return strings.ToLower(strings.TrimSpace(input.Type))
		}
		return "text"
	}
}

func extractLinkURLs(links []browser.LinkInfo) []string {
	urls := make([]string, len(links))
	for i, l := range links {
		urls[i] = l.Href
	}
	return urls
}

func (a *NavigatorAgent) handleHumanHelp(page *rod.Page, question string) {
	if a.interactor == nil {
		return
	}

	a.bus.Publish(Event{
		Type:    EventHumanHelpNeeded,
		Source:  a.Name(),
		Payload: question,
	})
}
