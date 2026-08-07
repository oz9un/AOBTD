package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/internal/llm"
	"github.com/ozzyw/aobtd/internal/policy"
	"github.com/ozzyw/aobtd/internal/proxy"
	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

// ExplorerAgent consumes the follow_ups queue produced by the analyzer (and
// eventually other agents) and executes each task — fetching URLs, probing
// parameters, etc. Responses are stored as real traffic entries so the next
// analyzer pass can pick them up naturally. For IDOR probes specifically,
// the Explorer also calls an LLM to reason about whether the response set
// represents distinct resources being leaked — that judgement is the thesis
// moment of the whole tool.
type ExplorerAgent struct {
	db       *store.DB
	scanID   int64
	logger   *slog.Logger
	client   *http.Client
	provider llm.Provider // may be nil — probe_idor is a no-op without it
	budget   *llm.Budget  // may be nil

	// Budget on how many tasks to run in a single Explorer pass. Prevents a
	// single enthusiastic analyzer response from driving up cost forever.
	maxPerPass int
	// perPassBudget caps wall-clock time spent in a single Start() call.
	// Protects Verification from being starved behind a huge queue.
	perPassBudget time.Duration
}

// NewExplorerAgent creates an explorer. Pass provider=nil and budget=nil to
// get a no-LLM explorer (IDOR probes will be skipped).
func NewExplorerAgent(db *store.DB, scanID int64, provider llm.Provider, budget *llm.Budget,
	executionPolicy *policy.Engine, credentialOrigin string, audit policy.DecisionAudit, logger *slog.Logger,
) *ExplorerAgent {
	baseClient := &http.Client{
		Timeout: 12 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
	return &ExplorerAgent{
		db:       db,
		scanID:   scanID,
		logger:   logger,
		provider: provider,
		budget:   budget,
		client: policy.ProtectHTTPClient(baseClient, executionPolicy, policy.HTTPOptions{
			CredentialOrigin: credentialOrigin,
			Audit:            audit,
		}),
		// Upper bound to prevent runaway cost/time on a single Start() call.
		// Scan 27 had 382 pending directives when Explorer phase started; the
		// old cap of 20 meant 362 were never touched. 500 gives us room to
		// drain typical scans while still protecting against pathological
		// runaway analyzer output. The per-pass time budget (see Start) is
		// the real guard on runtime.
		maxPerPass: 500,
		// Wall-clock guard — when the Explorer phase enters with a huge queue,
		// we don't want to block Verification forever. At ~5-10s per LLM-
		// assisted probe, 10 minutes covers ~60-120 probes which matches the
		// maxPerPass cap under realistic MiniMax-M2 latency. Phase 3 (the
		// "persistent Explorer running in parallel" goal) will obsolete
		// this cap — for now it makes the phase-based Explorer drain a lot
		// more of the queue without hanging the scan.
		perPassBudget: 10 * time.Minute,
	}
}

func (e *ExplorerAgent) Name() string { return "explorer" }

// Start pulls pending tasks and drains the queue aggressively. Exits when
// the queue is empty, ctx is cancelled, maxPerPass is reached, OR the
// wall-clock budget (perPassBudget) elapses. The time budget is the
// important guard — large scans now routinely queue 200-500 directives
// and the old cap of 20 meant most were never executed.
func (e *ExplorerAgent) Start(ctx context.Context) error {
	counts, _ := e.db.CountFollowUpsByStatus(e.scanID)
	pending := counts[store.FollowUpPending]
	running := counts[store.FollowUpRunning]
	if pending == 0 && running == 0 {
		e.logger.Info("explorer: no follow-ups to process")
		return nil
	}

	e.db.InsertNarration(e.scanID, "explorer", "start",
		fmt.Sprintf("%d thing(s) to investigate. Working through them.", pending),
		"", nil)
	e.logger.Info("explorer agent starting", "pending", pending,
		"max_per_pass", e.maxPerPass, "budget", e.perPassBudget)

	deadline := time.Now().Add(e.perPassBudget)
	passCtx, cancelPass := explorerPassContext(ctx, deadline)
	defer cancelPass()
	done := 0
	timedOut := false
	for done < e.maxPerPass {
		if passCtx.Err() != nil {
			timedOut = ctx.Err() == nil
			break
		}
		// Claim one task at a time. Claiming a batch before executing it left
		// the unstarted tail running when the pass budget or context expired.
		batch, err := e.db.PopPendingFollowUps(e.scanID, 1)
		if err != nil || len(batch) == 0 {
			break
		}
		for _, task := range batch {
			if passCtx.Err() != nil {
				timedOut = ctx.Err() == nil
				break
			}
			// The pass deadline must reach in-flight HTTP and LLM calls. A
			// loop-only time check let one MiniMax judgement run for minutes
			// after a foreground convergence drain advertised a 90s budget.
			e.executeTask(passCtx, task)
			done++
			if passCtx.Err() != nil {
				timedOut = ctx.Err() == nil
				break
			}
			if done >= e.maxPerPass {
				break
			}
		}
	}

	finalCounts, _ := e.db.CountFollowUpsByStatus(e.scanID)
	stopReason := "queue drained"
	switch {
	case ctx.Err() != nil:
		stopReason = "scan cancelled"
	case timedOut:
		stopReason = fmt.Sprintf("wall-clock budget %s elapsed", e.perPassBudget)
	case done >= e.maxPerPass:
		stopReason = fmt.Sprintf("hit per-pass cap %d", e.maxPerPass)
	}
	e.db.InsertNarration(e.scanID, "explorer", "complete",
		fmt.Sprintf("Executed %d follow-up(s). %d still pending, %d failed. Stopped: %s.",
			done, finalCounts[store.FollowUpPending], finalCounts[store.FollowUpFailed], stopReason),
		"", nil)
	e.logger.Info("explorer complete",
		"executed", done,
		"stop_reason", stopReason,
		"pending_after", finalCounts[store.FollowUpPending],
		"failed_after", finalCounts[store.FollowUpFailed])
	return nil
}

// PersistentRun runs the Explorer as a background drainer for the entire
// lifetime of a scan. It wakes every `period` (default 15s), and if any
// directives are pending it drains them up to a short per-tick budget.
//
// Design rationale: the phase-based Explorer (Start) only ran during
// Phase: Explorer, so 300+ directives queued during LLM Analysis had to
// wait their turn. In practice Phase: Explorer has a budget and most
// directives starved. With this background runner, directives the
// Strategist emits during any phase get picked up within ~15s.
//
// The per-tick budget is intentionally small so the BG Explorer never
// blocks the single-writer DB connection for more than a couple of
// seconds at a time — Analyzer + Verifier + Strategist all share it.
func (e *ExplorerAgent) PersistentRun(ctx context.Context, period time.Duration) {
	e.PersistentRunUntil(ctx, nil, period)
}

// PersistentRunUntil is the graceful-stop variant used by the orchestrator.
// A stop request is observed between drain passes, while the scan context is
// still used for in-flight HTTP/LLM work. This prevents shutdown from popping
// a batch and abandoning its unstarted rows in the running state.
func (e *ExplorerAgent) PersistentRunUntil(ctx context.Context, stop <-chan struct{}, period time.Duration) {
	if period <= 0 {
		period = 15 * time.Second
	}
	e.logger.Info("explorer background drainer starting", "period", period)
	timer := time.NewTicker(period)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			e.logger.Info("explorer background drainer stopping")
			return
		case <-stop:
			e.logger.Info("explorer background drainer stopped before final convergence")
			return
		case <-timer.C:
			counts, err := e.db.CountFollowUpsByStatus(e.scanID)
			if err != nil {
				continue
			}
			if counts[store.FollowUpPending] == 0 && counts[store.FollowUpRunning] == 0 {
				continue
			}
			e.drainPass(ctx, 90*time.Second, 30)
		}
	}
}

// drainPass executes up to `limit` tasks with a wall-clock budget. Used by
// PersistentRun so the BG worker releases the connection quickly and
// doesn't starve other agents.
func (e *ExplorerAgent) drainPass(ctx context.Context, budget time.Duration, limit int) {
	deadline := time.Now().Add(budget)
	passCtx, cancelPass := explorerPassContext(ctx, deadline)
	defer cancelPass()
	done := 0
	for done < limit {
		if passCtx.Err() != nil {
			return
		}
		batch, err := e.db.PopPendingFollowUps(e.scanID, 1)
		if err != nil || len(batch) == 0 {
			return
		}
		for _, task := range batch {
			if passCtx.Err() != nil {
				return
			}
			e.executeTask(passCtx, task)
			done++
			if done >= limit {
				return
			}
		}
	}
}

func explorerPassContext(parent context.Context, deadline time.Time) (context.Context, context.CancelFunc) {
	return context.WithDeadline(parent, deadline)
}

func (e *ExplorerAgent) executeTask(ctx context.Context, task store.FollowUp) {
	// Some LLM-emitted directives carry relative URLs like "/api/Challenges/"
	// instead of "http://localhost:3000/api/Challenges/". Resolve them
	// against the scan's target so Go's http client doesn't fail with
	// "unsupported protocol scheme" before we even send a request. Also
	// handles url_template for probe_idor.
	if task.URL != "" && !strings.HasPrefix(strings.ToLower(task.URL), "http") {
		if resolved := e.resolveAgainstTarget(task.URL); resolved != "" {
			task.URL = resolved
		}
	}
	if tmpl, ok := task.Params["url_template"].(string); ok && tmpl != "" &&
		!strings.HasPrefix(strings.ToLower(tmpl), "http") {
		if resolved := e.resolveAgainstTarget(tmpl); resolved != "" {
			task.Params["url_template"] = resolved
		}
	}

	e.db.InsertNarration(e.scanID, "explorer", "investigate",
		fmt.Sprintf("Checking %s %s — %s",
			strings.ToUpper(task.Action),
			shortenURL(task.URL),
			shortenReason(task.Reason)),
		task.URL, map[string]any{"follow_up_id": task.ID})

	switch task.Action {
	case "fetch":
		e.runFetch(ctx, task)
	case "graphql_introspect":
		e.runGraphQLIntrospect(ctx, task)
	case "probe_param":
		e.runProbeParam(ctx, task)
	case "probe_idor":
		e.runProbeIDOR(ctx, task)
	case "probe_logic":
		e.runProbeLogic(ctx, task)
	case "visit":
		// For MVP we treat "visit" the same as "fetch" — it still goes through
		// our HTTP client and stores traffic. A future version can route it
		// through the real browser for JS-rendered pages.
		e.runFetch(ctx, task)
	case "reanalyze":
		// Simple: mark the profile for re-analysis by flipping its confidence.
		// The analyzer's main loop will pick it up next pass.
		e.runReanalyze(ctx, task)
	default:
		e.completeFollowUp(task, store.FollowUpSkipped,
			fmt.Sprintf("unknown action: %s", task.Action))
	}
}

func (e *ExplorerAgent) completeFollowUp(task store.FollowUp, status, result string) {
	if err := e.db.CompleteFollowUp(e.scanID, task.ID, task.LeaseToken, status, result); err != nil {
		e.logger.Warn("follow-up completion rejected",
			"id", task.ID, "status", status, "error", err)
	}
}

// idorProbe holds one probe result — what we asked, what came back.
type idorProbe struct {
	ID         string
	URL        string
	StatusCode int
	BodyBytes  []byte
	Err        error
}

// runProbeIDOR is the thesis-moment action. It substitutes each value into
// the URL template's {id} placeholder, fires the requests, stores them as
// traffic, then asks the LLM to reason about whether the response set
// represents distinct resources leaking — the classic IDOR signal.
func (e *ExplorerAgent) runProbeIDOR(ctx context.Context, task store.FollowUp) {
	template, _ := task.Params["url_template"].(string)
	if template == "" {
		template = task.URL
	}
	if template == "" {
		e.completeFollowUp(task, store.FollowUpFailed, "missing url_template")
		return
	}
	if !strings.Contains(template, "{id}") {
		e.completeFollowUp(task, store.FollowUpFailed, "url_template must contain {id} placeholder")
		return
	}
	valuesRaw, _ := task.Params["values"].([]any)
	values := cleanIDORProbeValuesAny(valuesRaw)
	if len(values) < 2 {
		e.completeFollowUp(task, store.FollowUpFailed, "need at least 2 id values to probe IDOR")
		return
	}
	// Cap probes so we don't hammer the target.
	if len(values) > 6 {
		values = values[:6]
	}

	// 1. Look up auth headers from the most recent captured request that
	// matched this pattern. This is the fix for unauth-Explorer on auth-
	// gated APIs (e.g. Juice Shop's /rest/basket/:id). Without this,
	// every Strategist-emitted probe_idor against an authenticated endpoint
	// returned 401 and falsely dismissed the hypothesis.
	authHeaders := e.authHeadersForTemplate(template, values)

	// 2. Send the probes
	var probes []idorProbe
	for _, id := range values {
		if ctx.Err() != nil {
			break
		}
		probedURL := strings.ReplaceAll(template, "{id}", escapePathSegmentPayload(id))
		resp, body, reqHeaders, err := e.sendGET(ctx, probedURL, authHeaders)
		if err != nil {
			probes = append(probes, idorProbe{ID: id, URL: probedURL, Err: err})
			continue
		}
		// Store each probe as traffic for provenance + the analyzer loop
		e.db.InsertDiscovery(e.scanID, store.Discovery{
			TargetURL: probedURL,
			SourceURL: task.SourceProfileID,
			Kind:      store.DiscoveryExplorer,
			Detail:    fmt.Sprintf("IDOR probe id=%s — %s", id, task.Reason),
		})
		e.storeAsTraffic(probedURL, "GET", resp, body, reqHeaders, nil, task.ID, task.HypothesisID)
		probes = append(probes, idorProbe{ID: id, URL: probedURL, StatusCode: resp.StatusCode, BodyBytes: body})
	}

	// 2. Need at least 2 successful probes to reason about
	successful := 0
	for _, p := range probes {
		if p.Err == nil {
			successful++
		}
	}
	if successful < 2 {
		e.completeFollowUp(task, store.FollowUpFailed,
			fmt.Sprintf("only %d/%d probes succeeded — not enough to compare", successful, len(probes)))
		return
	}

	// 3. Without an LLM we can't make the semantic call; store a pending finding
	if e.provider == nil || e.budget == nil {
		e.completeFollowUp(task, store.FollowUpDone,
			fmt.Sprintf("%d probes captured — no LLM configured, skipping semantic judgement", successful))
		return
	}

	// 4. Ask the LLM to judge
	verdict, err := e.judgeIDOR(ctx, template, task.Reason, probes)
	if err != nil {
		e.completeFollowUp(task, store.FollowUpFailed, "judgement failed: "+err.Error())
		return
	}

	// 5. Store the verdict
	statusMsg := fmt.Sprintf("%d probes tested → %s (confidence %.2f)",
		successful, ternary(verdict.IsIDOR, "CONFIRMED IDOR", "not IDOR"), verdict.Confidence)
	e.completeFollowUp(task, store.FollowUpDone, statusMsg)

	e.db.InsertNarration(e.scanID, "explorer", "result",
		fmt.Sprintf("%s on %s — %s", ternary(verdict.IsIDOR, "IDOR CONFIRMED", "IDOR dismissed"),
			shortenURL(template), verdict.Reasoning),
		template, map[string]any{
			"is_idor":    verdict.IsIDOR,
			"confidence": verdict.Confidence,
			"severity":   verdict.Severity,
		})

	if verdict.IsIDOR {
		e.storeIDORFinding(task, template, probes, verdict)
	}
}

func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

// runFetch sends a GET to task.URL and stores the response as a traffic entry.
func (e *ExplorerAgent) runFetch(ctx context.Context, task store.FollowUp) {
	if task.URL == "" {
		e.completeFollowUp(task, store.FollowUpFailed, "missing URL")
		return
	}
	// Reuse auth headers from the browser's captured request if we have one
	// for this URL. Lets authenticated re-fetches actually come back with
	// user-specific data instead of a redirect-to-login.
	authHeaders := e.authHeadersForURL(task.URL)
	resp, body, reqHeaders, err := e.sendGET(ctx, task.URL, authHeaders)
	if err != nil {
		e.completeFollowUp(task, store.FollowUpFailed, err.Error())
		e.db.InsertNarration(e.scanID, "explorer", "result",
			fmt.Sprintf("Fetch %s failed: %s", shortenURL(task.URL), err.Error()),
			task.URL, nil)
		return
	}
	// Record the discovery edge: Explorer (acting on behalf of the source
	// profile if any) led us to this URL.
	e.db.InsertDiscovery(e.scanID, store.Discovery{
		TargetURL: task.URL,
		SourceURL: task.SourceProfileID,
		Kind:      store.DiscoveryExplorer,
		Detail:    task.Reason,
	})
	// Store as traffic so the next analyzer pass sees it naturally.
	e.storeAsTraffic(task.URL, "GET", resp, body, reqHeaders, nil, task.ID, task.HypothesisID)

	summary := fmt.Sprintf("HTTP %d, %d bytes", resp.StatusCode, len(body))
	e.completeFollowUp(task, store.FollowUpDone, summary)
	e.db.InsertNarration(e.scanID, "explorer", "result",
		fmt.Sprintf("Fetched %s — %s", shortenURL(task.URL), summary),
		task.URL, map[string]any{"status": resp.StatusCode, "size": len(body)})
}

func (e *ExplorerAgent) runGraphQLIntrospect(ctx context.Context, task store.FollowUp) {
	if task.URL == "" {
		e.completeFollowUp(task, store.FollowUpFailed, "missing URL")
		return
	}
	endpointURL := graphQLEndpointURL(task.URL)
	if endpointURL == "" {
		e.completeFollowUp(task, store.FollowUpSkipped, "not a GraphQL endpoint URL")
		return
	}

	bodyBytes, _ := json.Marshal(map[string]string{"query": graphQLIntrospectionQuery})
	authHeaders := e.authHeadersForURL(endpointURL)
	resp, body, reqHeaders, err := e.sendJSONPOST(ctx, endpointURL, bodyBytes, authHeaders)
	if err != nil {
		e.completeFollowUp(task, store.FollowUpFailed, err.Error())
		e.db.InsertNarration(e.scanID, "explorer", "result",
			fmt.Sprintf("GraphQL introspection %s failed: %s", shortenURL(endpointURL), err.Error()),
			endpointURL, nil)
		return
	}

	e.db.InsertDiscovery(e.scanID, store.Discovery{
		TargetURL: endpointURL,
		SourceURL: task.SourceProfileID,
		Kind:      store.DiscoveryExplorer,
		Detail:    task.Reason,
	})
	e.storeAsTraffic(endpointURL, "POST", resp, body, reqHeaders, bodyBytes, task.ID, task.HypothesisID)

	if !graphqlSchemaExposed(body) {
		e.completeFollowUp(task, store.FollowUpDone,
			fmt.Sprintf("HTTP %d, schema not exposed", resp.StatusCode))
		e.db.InsertNarration(e.scanID, "explorer", "result",
			fmt.Sprintf("GraphQL introspection on %s did not expose a schema (HTTP %d).",
				shortenURL(endpointURL), resp.StatusCode),
			endpointURL, nil)
		return
	}

	typeCount := graphqlSchemaTypeCount(body)
	e.completeFollowUp(task, store.FollowUpDone,
		fmt.Sprintf("HTTP %d, schema exposed (%d types)", resp.StatusCode, typeCount))
	e.db.InsertNarration(e.scanID, "explorer", "result",
		fmt.Sprintf("GraphQL introspection exposed the schema on %s (%d type(s)).",
			shortenURL(endpointURL), typeCount),
		endpointURL, map[string]any{"types": typeCount})

	endpointID := task.SourceProfileID
	if endpointID == "" {
		if parsed, err := url.Parse(endpointURL); err == nil && parsed.Path != "" {
			endpointID = "POST " + parsed.Path
		} else {
			endpointID = "POST " + endpointURL
		}
	}
	pocReq := buildRawPOSTRequest(endpointURL, "application/json", bodyBytes, reqHeaders)
	pocResp := fmt.Sprintf("HTTP/1.1 %d\nContent-Type: %s\n\n%s",
		resp.StatusCode, resp.Header.Get("Content-Type"), truncateString(string(body), 1200))
	steps := fmt.Sprintf(
		"1. Send a POST request to %s with Content-Type: application/json.\n"+
			"2. Use this body:\n\n%s\n\n"+
			"3. The server returns a JSON response containing `data.__schema` with %d schema type(s).",
		endpointURL, string(bodyBytes), typeCount)
	e.db.InsertFinding(e.scanID, types.Finding{
		Title:            "GraphQL introspection enabled",
		Description:      fmt.Sprintf("POST %s accepts the standard GraphQL introspection query and returns `data.__schema`, exposing the API schema including queries, mutations, types, and fields.", endpointURL),
		Severity:         types.SeverityInfo,
		Confidence:       types.ConfidenceConfirmed,
		EndpointID:       endpointID,
		VulnType:         "graphql_introspection",
		ParamName:        "query",
		Payload:          graphQLIntrospectionQuery,
		PocRequest:       pocReq,
		PocResponse:      pocResp,
		StepsToReproduce: steps,
		Impact:           "Schema introspection gives testers and attackers a complete map of GraphQL operations and object fields. In production, this often accelerates discovery of sensitive queries, mutations, and authorization weaknesses.",
		Remediation:      "Disable GraphQL introspection in production unless it is explicitly required, and ensure authorization is enforced per resolver regardless of schema visibility.",
		Evidence: fmt.Sprintf("URL: %s\nHTTP: %d\nSchema types: %d\nResponse preview: %s",
			endpointURL, resp.StatusCode, typeCount, truncateString(string(body), 600)),
		HypothesisID: task.HypothesisID,
	})
}

// runProbeParam sends one GET per value to see how the endpoint reacts.
func (e *ExplorerAgent) runProbeParam(ctx context.Context, task store.FollowUp) {
	if task.URL == "" {
		e.completeFollowUp(task, store.FollowUpFailed, "missing URL")
		return
	}
	paramName, _ := task.Params["param"].(string)
	if paramName == "" {
		e.completeFollowUp(task, store.FollowUpFailed, "missing param name")
		return
	}
	valuesRaw, _ := task.Params["values"].([]any)
	if len(valuesRaw) == 0 {
		e.completeFollowUp(task, store.FollowUpFailed, "no values to probe")
		return
	}
	// Cap probes so a runaway analyzer doesn't DoS the target.
	if len(valuesRaw) > 5 {
		valuesRaw = valuesRaw[:5]
	}

	authHeaders := e.authHeadersForURL(task.URL)
	var responses []string
	for _, v := range valuesRaw {
		vs, _ := v.(string)
		if vs == "" {
			continue
		}
		if formProbe, ok := e.observedFormProbe(ctx, task.URL, paramName, vs, authHeaders); ok {
			switch formProbe.Method {
			case http.MethodPost:
				resp, body, reqHeaders, err := e.sendFormPOST(ctx, formProbe.URL, formProbe.Values, authHeaders)
				if err != nil {
					responses = append(responses, fmt.Sprintf("FORM POST %s→err", vs))
					continue
				}
				e.db.InsertDiscovery(e.scanID, store.Discovery{
					TargetURL: formProbe.URL,
					SourceURL: task.URL,
					Kind:      store.DiscoveryExplorer,
					Detail:    fmt.Sprintf("form probe %s=%s — %s", paramName, vs, task.Reason),
				})
				e.storeAsTraffic(formProbe.URL, http.MethodPost, resp, body, reqHeaders, []byte(formProbe.Values.Encode()), task.ID, task.HypothesisID)
				e.maybeStoreCommandInjectionParamFinding(task, paramName, http.MethodPost, formProbe.URL, vs, []byte(formProbe.Values.Encode()), resp, body)
				e.maybeStoreSQLInjectionParamFinding(task, paramName, http.MethodPost, formProbe.URL, vs, []byte(formProbe.Values.Encode()), resp, body)
				e.maybeStoreFileInclusionSourceDisclosureFinding(task, paramName, http.MethodPost, formProbe.URL, vs, []byte(formProbe.Values.Encode()), resp, body)
				responses = append(responses, fmt.Sprintf("FORM POST %s→%d/%db", vs, resp.StatusCode, len(body)))
			default:
				resp, body, reqHeaders, err := e.sendGET(ctx, formProbe.URL, authHeaders)
				if err != nil {
					responses = append(responses, fmt.Sprintf("FORM GET %s→err", vs))
					continue
				}
				e.db.InsertDiscovery(e.scanID, store.Discovery{
					TargetURL: formProbe.URL,
					SourceURL: task.URL,
					Kind:      store.DiscoveryExplorer,
					Detail:    fmt.Sprintf("form probe %s=%s — %s", paramName, vs, task.Reason),
				})
				e.storeAsTraffic(formProbe.URL, http.MethodGet, resp, body, reqHeaders, nil, task.ID, task.HypothesisID)
				e.maybeStoreCommandInjectionParamFinding(task, paramName, http.MethodGet, formProbe.URL, vs, nil, resp, body)
				e.maybeStoreSQLInjectionParamFinding(task, paramName, http.MethodGet, formProbe.URL, vs, nil, resp, body)
				e.maybeStoreFileInclusionSourceDisclosureFinding(task, paramName, http.MethodGet, formProbe.URL, vs, nil, resp, body)
				responses = append(responses, fmt.Sprintf("FORM GET %s→%d/%db", vs, resp.StatusCode, len(body)))
			}
			continue
		}
		probedURL := injectQueryParam(task.URL, paramName, vs)
		resp, body, reqHeaders, err := e.sendGET(ctx, probedURL, authHeaders)
		if err != nil {
			responses = append(responses, fmt.Sprintf("%s→err", vs))
			continue
		}
		e.db.InsertDiscovery(e.scanID, store.Discovery{
			TargetURL: probedURL,
			SourceURL: task.URL,
			Kind:      store.DiscoveryExplorer,
			Detail:    fmt.Sprintf("probe %s=%s — %s", paramName, vs, task.Reason),
		})
		e.storeAsTraffic(probedURL, "GET", resp, body, reqHeaders, nil, task.ID, task.HypothesisID)
		e.maybeStoreCommandInjectionParamFinding(task, paramName, http.MethodGet, probedURL, vs, nil, resp, body)
		e.maybeStoreSQLInjectionParamFinding(task, paramName, http.MethodGet, probedURL, vs, nil, resp, body)
		e.maybeStoreFileInclusionSourceDisclosureFinding(task, paramName, http.MethodGet, probedURL, vs, nil, resp, body)
		responses = append(responses, fmt.Sprintf("%s→%d/%db", vs, resp.StatusCode, len(body)))
		if resp.StatusCode == http.StatusMethodNotAllowed {
			postURL, postBody := formPOSTProbe(task.URL, paramName, vs)
			postResp, postRespBody, postReqHeaders, postErr := e.sendFormPOST(ctx, postURL, postBody, authHeaders)
			if postErr != nil {
				responses = append(responses, fmt.Sprintf("POST %s→err", vs))
				continue
			}
			e.db.InsertDiscovery(e.scanID, store.Discovery{
				TargetURL: postURL,
				SourceURL: task.URL,
				Kind:      store.DiscoveryExplorer,
				Detail:    fmt.Sprintf("POST fallback probe %s=%s after GET returned 405 — %s", paramName, vs, task.Reason),
			})
			e.storeAsTraffic(postURL, "POST", postResp, postRespBody, postReqHeaders, []byte(postBody.Encode()), task.ID, task.HypothesisID)
			e.maybeStoreCommandInjectionParamFinding(task, paramName, http.MethodPost, postURL, vs, []byte(postBody.Encode()), postResp, postRespBody)
			e.maybeStoreSQLInjectionParamFinding(task, paramName, http.MethodPost, postURL, vs, []byte(postBody.Encode()), postResp, postRespBody)
			e.maybeStoreFileInclusionSourceDisclosureFinding(task, paramName, http.MethodPost, postURL, vs, []byte(postBody.Encode()), postResp, postRespBody)
			responses = append(responses, fmt.Sprintf("POST %s→%d/%db", vs, postResp.StatusCode, len(postRespBody)))

			if missing := missingRequiredFormParameter(postRespBody); missing != "" && postBody.Get(missing) == "" {
				retryBody := cloneFormValues(postBody)
				retryBody.Set(missing, defaultRequiredFormParameterValue(missing))
				retryResp, retryRespBody, retryReqHeaders, retryErr := e.sendFormPOST(ctx, postURL, retryBody, authHeaders)
				if retryErr == nil {
					e.db.InsertDiscovery(e.scanID, store.Discovery{
						TargetURL: postURL,
						SourceURL: task.URL,
						Kind:      store.DiscoveryExplorer,
						Detail:    fmt.Sprintf("POST fallback retry added required form field %s — %s", missing, task.Reason),
					})
					e.storeAsTraffic(postURL, "POST", retryResp, retryRespBody, retryReqHeaders, []byte(retryBody.Encode()), task.ID, task.HypothesisID)
					e.maybeStoreCommandInjectionParamFinding(task, paramName, http.MethodPost, postURL, vs, []byte(retryBody.Encode()), retryResp, retryRespBody)
					e.maybeStoreSQLInjectionParamFinding(task, paramName, http.MethodPost, postURL, vs, []byte(retryBody.Encode()), retryResp, retryRespBody)
					e.maybeStoreFileInclusionSourceDisclosureFinding(task, paramName, http.MethodPost, postURL, vs, []byte(retryBody.Encode()), retryResp, retryRespBody)
					responses = append(responses, fmt.Sprintf("POST %s+%s→%d/%db", vs, missing, retryResp.StatusCode, len(retryRespBody)))
				}
			}
			if shouldProbeRawXMLPOST(task.URL, vs) {
				rawResp, rawRespBody, rawReqHeaders, rawErr := e.sendRawPOST(ctx, postURL, []byte(vs), "application/xml", authHeaders)
				if rawErr == nil {
					e.db.InsertDiscovery(e.scanID, store.Discovery{
						TargetURL: postURL,
						SourceURL: task.URL,
						Kind:      store.DiscoveryExplorer,
						Detail:    fmt.Sprintf("Raw XML POST probe after form fallback for %s — %s", paramName, task.Reason),
					})
					e.storeAsTraffic(postURL, "POST", rawResp, rawRespBody, rawReqHeaders, []byte(vs), task.ID, task.HypothesisID)
					responses = append(responses, fmt.Sprintf("POST raw-xml→%d/%db", rawResp.StatusCode, len(rawRespBody)))
				}
			}
		}
	}
	summary := strings.Join(responses, ", ")
	e.completeFollowUp(task, store.FollowUpDone, summary)
	e.db.InsertNarration(e.scanID, "explorer", "result",
		fmt.Sprintf("Probed '%s' on %s with %d value(s): %s",
			paramName, shortenURL(task.URL), len(responses), summary),
		task.URL, nil)
}

func formPOSTProbe(rawURL, paramName, value string) (string, url.Values) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		values := url.Values{}
		values.Set(paramName, value)
		return rawURL, values
	}
	values := parsed.Query()
	values.Set(paramName, value)
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), values
}

type observedFormProbe struct {
	Method string
	URL    string
	Values url.Values
}

func (e *ExplorerAgent) observedFormProbe(ctx context.Context, rawURL, paramName, value string, authHeaders map[string]string) (observedFormProbe, bool) {
	if rawURL == "" || paramName == "" {
		return observedFormProbe{}, false
	}
	if probe, ok := e.liveObservedFormProbe(ctx, rawURL, paramName, value, authHeaders); ok {
		return probe, true
	}
	return e.storedObservedFormProbe(rawURL, paramName, value)
}

func (e *ExplorerAgent) liveObservedFormProbe(ctx context.Context, rawURL, paramName, value string, authHeaders map[string]string) (observedFormProbe, bool) {
	resp, body, _, err := e.sendGET(ctx, rawURL, authHeaders)
	if err != nil || resp == nil || len(body) == 0 {
		return observedFormProbe{}, false
	}
	pageURL := rawURL
	if resp.Request != nil && resp.Request.URL != nil {
		pageURL = resp.Request.URL.String()
	}
	return buildObservedFormProbeFromHTML(body, pageURL, paramName, value)
}

func (e *ExplorerAgent) storedObservedFormProbe(rawURL, paramName, value string) (observedFormProbe, bool) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return observedFormProbe{}, false
	}
	rows, err := e.db.Conn().Query(`
		SELECT url, response_body
		FROM traffic
		WHERE scan_id = ?
		  AND is_filtered = FALSE
		  AND response_body IS NOT NULL
		  AND (url = ? OR (host = ? AND path = ?))
		ORDER BY id DESC
		LIMIT 8`, e.scanID, rawURL, parsed.Host, parsed.Path)
	if err != nil {
		return observedFormProbe{}, false
	}
	defer rows.Close()

	for rows.Next() {
		var pageURL string
		var body []byte
		if err := rows.Scan(&pageURL, &body); err != nil {
			continue
		}
		if probe, ok := buildObservedFormProbeFromHTML(body, pageURL, paramName, value); ok {
			return probe, true
		}
	}
	return observedFormProbe{}, false
}

func buildObservedFormProbeFromHTML(body []byte, pageURL, paramName, value string) (observedFormProbe, bool) {
	ext := extract.ExtractHTML(body, pageURL)
	if ext == nil || len(ext.Forms) == 0 {
		return observedFormProbe{}, false
	}
	for _, form := range ext.Forms {
		values := url.Values{}
		hasParam := false
		for _, input := range form.Inputs {
			name := strings.TrimSpace(input.Name)
			if name == "" {
				continue
			}
			inputType := strings.ToLower(strings.TrimSpace(input.Type))
			switch {
			case name == paramName:
				values.Set(name, value)
				hasParam = true
			case inputType == "submit":
				submitValue := input.Value
				if submitValue == "" {
					submitValue = "Submit"
				}
				values.Set(name, submitValue)
			case inputType == "button" || inputType == "reset" || inputType == "file":
				continue
			case input.Value != "":
				values.Set(name, input.Value)
			case inputType == "hidden":
				values.Set(name, "")
			case len(input.Options) > 0:
				values.Set(name, input.Options[0])
			}
		}
		if !hasParam {
			continue
		}
		action := form.Action
		if action == "" {
			action = pageURL
		}
		if parsed, err := url.Parse(action); err == nil {
			parsed.Fragment = ""
			action = parsed.String()
		}
		method := strings.ToUpper(strings.TrimSpace(form.Method))
		if method == "" {
			method = http.MethodGet
		}
		if method != http.MethodPost {
			parsed, err := url.Parse(action)
			if err != nil {
				return observedFormProbe{}, false
			}
			query := parsed.Query()
			for key, vals := range values {
				query.Del(key)
				for _, v := range vals {
					query.Add(key, v)
				}
			}
			parsed.RawQuery = query.Encode()
			return observedFormProbe{Method: http.MethodGet, URL: parsed.String(), Values: values}, true
		}
		return observedFormProbe{Method: http.MethodPost, URL: action, Values: values}, true
	}
	return observedFormProbe{}, false
}

func (e *ExplorerAgent) maybeStoreCommandInjectionParamFinding(task store.FollowUp, paramName, method, rawURL, payload string, reqBody []byte, resp *http.Response, body []byte) {
	if resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return
	}
	reasonLower := strings.ToLower(task.Reason)
	if !commandInjectionParamNameLooksUseful(paramName) {
		return
	}
	if !commandInjectionPathLooksUseful(parsed.Path) &&
		!strings.Contains(reasonLower, "command injection") &&
		!strings.Contains(reasonLower, "shell") &&
		!strings.Contains(reasonLower, "os command") {
		return
	}
	signal := commandInjectionProbeEvidenceSignal(string(body), payload)
	if signal == "" {
		return
	}

	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = http.MethodGet
	}
	endpointID := method + " " + parsed.Path
	var pocReq string
	if method == http.MethodPost {
		pocReq = buildRawPOSTRequest(rawURL, "application/x-www-form-urlencoded", reqBody, nil)
	} else {
		pocReq = buildRawGETRequest(rawURL, nil)
	}
	pocResp := fmt.Sprintf("HTTP/1.1 %d\nContent-Type: %s\n\n%s",
		resp.StatusCode, resp.Header.Get("Content-Type"), truncateString(string(body), 1200))
	steps := fmt.Sprintf(
		"1. Send the same %s request to %s with `%s` set to `%s`.\n"+
			"2. Observe command-output evidence in the HTTP response: %s.\n"+
			"3. Repeat with a benign baseline such as `127.0.0.1` and confirm the command-output marker is absent.",
		method, rawURL, paramName, payload, signal)
	_, _ = e.db.InsertFinding(e.scanID, types.Finding{
		Title: fmt.Sprintf("OS command injection via %s on %s", paramName, parsed.Path),
		Description: fmt.Sprintf("%s %s executed shell metacharacter payload `%s` in parameter `%s`. %s",
			method, rawURL, payload, paramName, signal),
		Severity:         types.SeverityCritical,
		Confidence:       types.ConfidenceConfirmed,
		EndpointID:       endpointID,
		VulnType:         "command_injection",
		ParamName:        paramName,
		Payload:          payload,
		PocRequest:       pocReq,
		PocResponse:      pocResp,
		StepsToReproduce: steps,
		Impact:           "Attackers can execute operating-system commands in the web server context. This can lead to source disclosure, credential theft, lateral movement inside the container/host network, data destruction, or full server compromise.",
		Remediation:      "Do not pass client input to shell commands. Use safe library calls instead of shell execution; if command execution is unavoidable, use argument-array APIs without shell interpretation plus strict server-side allowlists.",
		Evidence: fmt.Sprintf("URL: %s\nMethod: %s\nParam: %s\nPayload: %s\nSignal: %s\nResponse preview: %s",
			rawURL, method, paramName, payload, signal, truncateString(string(body), 700)),
		HypothesisID: task.HypothesisID,
	})
}

func commandInjectionProbeEvidenceSignal(body, payload string) string {
	payload = strings.TrimSpace(payload)
	if payload == "" || !strings.ContainsAny(payload, ";|&`$") {
		return ""
	}
	if commandInjectionLooksLikeReflection(body, payload) {
		return ""
	}
	lowerPayload := strings.ToLower(payload)
	lowerBody := strings.ToLower(body)
	switch {
	case strings.Contains(lowerPayload, "/etc/passwd") &&
		strings.Contains(lowerBody, "root:x:0:0") &&
		strings.Contains(lowerBody, "/bin/bash"):
		return "response contains `/etc/passwd` account entries such as `root:x:0:0`"
	case strings.Contains(lowerPayload, "whoami") &&
		(strings.Contains(lowerBody, ">www-data<") ||
			strings.Contains(lowerBody, "\nwww-data\n") ||
			strings.Contains(lowerBody, "\r\nwww-data\r\n") ||
			strings.Contains(lowerBody, "www-data")):
		return "response contains the web-server user `www-data` from a `whoami` command"
	case strings.Contains(lowerPayload, " id") || strings.Contains(lowerPayload, "`id") || strings.Contains(lowerPayload, "$(id"):
		if strings.Contains(lowerBody, "uid=") && strings.Contains(lowerBody, "gid=") {
			return "response contains `uid=`/`gid=` output from an `id` command"
		}
	case strings.Contains(lowerPayload, " ls") || strings.Contains(lowerPayload, ";ls") || strings.Contains(lowerPayload, "|ls"):
		if strings.Contains(lowerBody, "\nindex.php") && strings.Contains(lowerBody, "\nsource") {
			return "response contains directory-listing entries such as `index.php` and `source`"
		}
	}
	return ""
}

func (e *ExplorerAgent) maybeStoreFileInclusionSourceDisclosureFinding(task store.FollowUp, paramName, method, rawURL, payload string, reqBody []byte, resp *http.Response, body []byte) {
	if resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return
	}
	if !strings.Contains(strings.ToLower(payload), "php://filter") {
		return
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return
	}
	reasonLower := strings.ToLower(task.Reason)
	if !fileReadPathLooksUseful(parsed.Path) &&
		!strings.Contains(reasonLower, "file inclusion") &&
		!strings.Contains(reasonLower, "lfi") &&
		!strings.Contains(reasonLower, "path traversal") {
		return
	}
	signal := fileReadSensitiveContentSignal(string(body))
	if signal != "PHP source disclosure via local file inclusion" {
		return
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = http.MethodGet
	}
	endpointID := method + " " + parsed.Path
	title := fmt.Sprintf("Local file inclusion/source disclosure via %s on %s", paramName, parsed.Path)
	if e.db.FindingExists(e.scanID, title, endpointID) {
		return
	}
	var pocReq string
	if method == http.MethodPost {
		pocReq = buildRawPOSTRequest(rawURL, "application/x-www-form-urlencoded", reqBody, nil)
	} else {
		pocReq = buildRawGETRequest(rawURL, nil)
	}
	pocResp := fmt.Sprintf("HTTP/1.1 %d\nContent-Type: %s\n\n%s",
		resp.StatusCode, resp.Header.Get("Content-Type"), truncateString(string(body), 1200))
	_, _ = e.db.InsertFinding(e.scanID, types.Finding{
		Title: title,
		Description: fmt.Sprintf("%s %s accepted `%s=%s` and returned base64-encoded PHP source. Signal: %s.",
			method, rawURL, paramName, payload, signal),
		Severity:    types.SeverityHigh,
		Confidence:  types.ConfidenceConfirmed,
		EndpointID:  endpointID,
		VulnType:    "file_inclusion",
		ParamName:   paramName,
		Payload:     payload,
		PocRequest:  pocReq,
		PocResponse: pocResp,
		StepsToReproduce: fmt.Sprintf("1. Send the same %s request to %s with `%s` set to `%s`.\n2. Base64-decode the response body.\n3. Observe PHP source code, proving local file inclusion/source disclosure.",
			method, rawURL, paramName, payload),
		Impact:      "Attackers can read PHP source through the inclusion primitive. Source disclosure can reveal implementation details, include paths, secrets, and follow-on exploit paths.",
		Remediation: "Do not include files directly from user-controlled parameters. Replace dynamic includes with a strict allowlist of server-side identifiers and block stream wrappers such as php://filter.",
		Evidence: fmt.Sprintf("URL: %s\nMethod: %s\nParam: %s\nPayload: %s\nSignal: %s\nResponse preview: %s",
			rawURL, method, paramName, payload, signal, truncateString(string(body), 700)),
		HypothesisID: task.HypothesisID,
	})
}

func (e *ExplorerAgent) maybeStoreSQLInjectionParamFinding(task store.FollowUp, paramName, method, rawURL, payload string, reqBody []byte, resp *http.Response, body []byte) {
	if resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return
	}
	reasonLower := strings.ToLower(task.Reason)
	if !sqlInjectionParamNameLooksUseful(paramName) &&
		!strings.Contains(strings.ToLower(parsed.Path), "sqli") &&
		!strings.Contains(reasonLower, "sql injection") &&
		!strings.Contains(reasonLower, "sqli") {
		return
	}
	signal := sqlInjectionProbeEvidenceSignal(string(body), payload)
	if signal == "" {
		return
	}

	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = http.MethodGet
	}
	endpointID := method + " " + parsed.Path
	var pocReq string
	if method == http.MethodPost {
		pocReq = buildRawPOSTRequest(rawURL, "application/x-www-form-urlencoded", reqBody, nil)
	} else {
		pocReq = buildRawGETRequest(rawURL, nil)
	}
	pocResp := fmt.Sprintf("HTTP/1.1 %d\nContent-Type: %s\n\n%s",
		resp.StatusCode, resp.Header.Get("Content-Type"), truncateString(string(body), 1200))
	_, _ = e.db.InsertFinding(e.scanID, types.Finding{
		Title: fmt.Sprintf("SQL injection via %s on %s", paramName, parsed.Path),
		Description: fmt.Sprintf("%s %s returned database error evidence after parameter `%s` was set to `%s`. %s",
			method, rawURL, paramName, payload, signal),
		Severity:         types.SeverityHigh,
		Confidence:       types.ConfidenceConfirmed,
		EndpointID:       endpointID,
		VulnType:         "sqli",
		ParamName:        paramName,
		Payload:          payload,
		PocRequest:       pocReq,
		PocResponse:      pocResp,
		StepsToReproduce: fmt.Sprintf("1. Send the same %s request to %s with `%s` set to `%s`.\n2. Observe the SQL/database error in the HTTP response.\n3. Repeat with a benign value and confirm the database error is absent.", method, rawURL, paramName, payload),
		Impact:           "Attackers can manipulate SQL queries through user-controlled input. Depending on database permissions and query context, this can lead to authentication bypass, data exfiltration, data modification, or full database compromise.",
		Remediation:      "Use parameterized queries/prepared statements for all SQL access. Do not concatenate request parameters into SQL strings. Add server-side validation and return generic error pages without database diagnostics.",
		Evidence: fmt.Sprintf("URL: %s\nMethod: %s\nParam: %s\nPayload: %s\nSignal: %s\nResponse preview: %s",
			rawURL, method, paramName, payload, signal, truncateString(string(body), 700)),
		HypothesisID: task.HypothesisID,
	})
}

func sqlInjectionParamNameLooksUseful(param string) bool {
	switch strings.ToLower(strings.TrimSpace(param)) {
	case "id", "user_id", "uid", "userid", "username", "email", "q", "query", "search", "filter", "sort", "category":
		return true
	default:
		return false
	}
}

func sqlInjectionProbeEvidenceSignal(body, payload string) string {
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return ""
	}
	lowerPayload := strings.ToLower(payload)
	if !strings.ContainsAny(lowerPayload, `'"`) &&
		!strings.Contains(lowerPayload, " union ") &&
		!strings.Contains(lowerPayload, " sleep(") &&
		!strings.Contains(lowerPayload, " or ") &&
		!strings.Contains(lowerPayload, " and ") {
		return ""
	}
	lowerBody := strings.ToLower(body)
	switch {
	case strings.Contains(lowerBody, "mysqli_sql_exception") &&
		strings.Contains(lowerBody, "you have an error in your sql syntax"):
		return "response contains a `mysqli_sql_exception` SQL syntax error"
	case strings.Contains(lowerBody, "you have an error in your sql syntax"):
		return "response contains a SQL syntax error from the database"
	case strings.Contains(lowerBody, "mariadb server version") && strings.Contains(lowerBody, "sql syntax"):
		return "response leaks MariaDB SQL syntax diagnostics"
	case strings.Contains(lowerBody, "mysql_fetch") || strings.Contains(lowerBody, "mysql_num_rows"):
		return "response contains MySQL runtime error output"
	}
	return ""
}

func missingRequiredFormParameter(body []byte) string {
	text := string(body)
	const marker = "Required request parameter '"
	idx := strings.Index(text, marker)
	if idx < 0 {
		return ""
	}
	rest := text[idx+len(marker):]
	end := strings.IndexByte(rest, '\'')
	if end <= 0 {
		return ""
	}
	name := strings.TrimSpace(rest[:end])
	if name == "" || strings.ContainsAny(name, " \t\r\n&=?/\\") {
		return ""
	}
	return name
}

func cloneFormValues(values url.Values) url.Values {
	cloned := make(url.Values, len(values)+1)
	for key, vals := range values {
		cloned[key] = append([]string(nil), vals...)
	}
	return cloned
}

func defaultRequiredFormParameterValue(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	switch {
	case strings.Contains(lower, "count"), strings.Contains(lower, "id"), strings.Contains(lower, "number"):
		return "1"
	default:
		return "test"
	}
}

func shouldProbeRawXMLPOST(rawURL, value string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	path := strings.ToLower(parsed.Path)
	if !strings.Contains(path, "/xxe/") {
		return false
	}
	payload := strings.ToLower(strings.TrimSpace(value))
	return strings.HasPrefix(payload, "<?xml") &&
		(strings.Contains(payload, "<!doctype") || strings.Contains(payload, "<!entity"))
}

// runReanalyze resolves the planner's endpoint reference to one or more
// scan-local traffic hashes, then flips their analyzed flags so the next
// analyzer loop revisits them. Planner directives usually carry a human-
// readable profile ID ("GET /orders/{id}"), while traffic is keyed by an
// origin-aware hash; treating those as the same value made reanalyze a silent
// no-op before this resolver existed.
func (e *ExplorerAgent) runReanalyze(ctx context.Context, task store.FollowUp) {
	endpointID, _ := task.Params["endpoint_id"].(string)
	if endpointID == "" && task.SourceProfileID != "" {
		endpointID = task.SourceProfileID
	}
	if endpointID == "" {
		e.completeFollowUp(task, store.FollowUpFailed, "no endpoint to reanalyze")
		return
	}
	hashes, err := e.db.ResolveEndpointHashes(e.scanID, endpointID)
	if err != nil {
		e.completeFollowUp(task, store.FollowUpFailed, err.Error())
		return
	}
	if len(hashes) == 0 {
		e.completeFollowUp(task, store.FollowUpFailed,
			fmt.Sprintf("endpoint reference %q did not resolve to scan traffic", endpointID))
		return
	}

	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(hashes)), ",")
	args := make([]any, 0, len(hashes)+1)
	args = append(args, e.scanID)
	for _, hash := range hashes {
		args = append(args, hash)
	}
	result, err := e.db.Conn().Exec(`
		UPDATE traffic SET is_ai_analyzed = FALSE
		WHERE scan_id = ? AND endpoint_hash IN (`+placeholders+`)`, args...)
	if err != nil {
		e.completeFollowUp(task, store.FollowUpFailed, err.Error())
		return
	}
	count, _ := result.RowsAffected()
	e.completeFollowUp(task, store.FollowUpDone,
		fmt.Sprintf("marked %d observation(s) across %d endpoint group(s) for reanalysis", count, len(hashes)))
}

// logicProbe holds one business-logic probe attempt.
type logicProbe struct {
	TestValue  string
	StatusCode int
	BodyBytes  []byte
	Err        error
}

// runProbeLogic mutates ONE field on an endpoint's original captured request
// with illegal/boundary values and replays each. Then the LLM judges whether
// the server accepted values it shouldn't have (classic price-manipulation,
// quantity-bypass, role-escalation patterns).
func (e *ExplorerAgent) runProbeLogic(ctx context.Context, task store.FollowUp) {
	if task.URL == "" {
		e.completeFollowUp(task, store.FollowUpFailed, "missing url")
		return
	}
	field, _ := task.Params["field"].(string)
	if field == "" {
		e.completeFollowUp(task, store.FollowUpFailed, "missing field name")
		return
	}
	if businessLogicFieldIsCSRFToken(field) {
		e.completeFollowUp(task, store.FollowUpDone,
			fmt.Sprintf("skipped generic business-logic probe for CSRF/token field %q", field))
		e.db.InsertNarration(e.scanID, "explorer", "skipped",
			"Skipped generic business-logic judgement for a CSRF/token field; token validation belongs to the dedicated CSRF verifier and must not be confirmed from HTTP 200 alone.",
			task.URL, map[string]any{"field": field})
		return
	}
	// Accept both "test_values" (analyzer emits this) and "values" (Strategist
	// emits this). The naming diverged historically and every Strategist
	// probe_logic was failing "no test values provided" because we only
	// looked for test_values. Prefer test_values for compatibility.
	valuesRaw, _ := task.Params["test_values"].([]any)
	if len(valuesRaw) == 0 {
		valuesRaw, _ = task.Params["values"].([]any)
	}
	if len(valuesRaw) < 1 {
		e.completeFollowUp(task, store.FollowUpFailed, "no test values provided")
		return
	}
	if len(valuesRaw) > 6 {
		valuesRaw = valuesRaw[:6]
	}

	// 1. Find the original captured request for this URL. We need its method,
	//    headers, and body so we can replay it with a single field mutated.
	orig, err := e.originalRequestFor(task.URL)
	if err != nil {
		e.completeFollowUp(task, store.FollowUpFailed,
			"no captured request to mutate: "+err.Error())
		return
	}
	baselineValue := extractFieldValue(orig.Body, orig.ContentType, field)

	// 2. Send one mutated request per test value
	var probes []logicProbe
	for _, v := range valuesRaw {
		if ctx.Err() != nil {
			break
		}
		tv, _ := v.(string)
		if tv == "" {
			continue
		}
		mutatedBody, ok := replaceFieldValue(orig.Body, orig.ContentType, field, tv)
		if !ok {
			probes = append(probes, logicProbe{TestValue: tv,
				Err: fmt.Errorf("could not locate field '%s' in original body", field)})
			continue
		}
		resp, body, reqHeaders, err := e.sendMutated(ctx, orig, mutatedBody)
		if err != nil {
			probes = append(probes, logicProbe{TestValue: tv, Err: err})
			continue
		}
		e.db.InsertDiscovery(e.scanID, store.Discovery{
			TargetURL: task.URL,
			SourceURL: task.SourceProfileID,
			Kind:      store.DiscoveryExplorer,
			Detail:    fmt.Sprintf("business-logic probe %s=%s — %s", field, tv, task.Reason),
		})
		e.storeAsTraffic(task.URL, orig.Method, resp, body, reqHeaders, mutatedBody, task.ID, task.HypothesisID)
		probes = append(probes, logicProbe{TestValue: tv, StatusCode: resp.StatusCode, BodyBytes: body})
	}

	successful := 0
	for _, p := range probes {
		if p.Err == nil {
			successful++
		}
	}
	if successful < 1 {
		e.completeFollowUp(task, store.FollowUpFailed,
			fmt.Sprintf("0/%d probes succeeded", len(probes)))
		return
	}
	if logicProbesAllCSRFRejected(probes) {
		e.completeFollowUp(task, store.FollowUpDone,
			fmt.Sprintf("%d probes captured — all were rejected by CSRF/token validation", successful))
		e.db.InsertNarration(e.scanID, "explorer", "skipped",
			"Skipped business-logic judgement because every replayed probe was rejected by CSRF/token validation.",
			task.URL, map[string]any{"field": field})
		return
	}
	if graphQLIntrospectionLogicProbe(task.URL, field, probes) {
		e.storeGraphQLIntrospectionProbeFinding(task, probes)
		return
	}
	if genericGraphQLQueryLogicProbe(task.URL, field) {
		e.completeFollowUp(task, store.FollowUpDone,
			fmt.Sprintf("%d probes captured — skipped generic business-logic judgement for GraphQL query field", successful))
		e.db.InsertNarration(e.scanID, "explorer", "skipped",
			"Skipped generic business-logic judgement for GraphQL `query`; arbitrary query text is part of the protocol, and GraphQL-specific findings are handled by dedicated probes.",
			task.URL, map[string]any{"field": field})
		return
	}

	if e.provider == nil || e.budget == nil {
		e.completeFollowUp(task, store.FollowUpDone,
			fmt.Sprintf("%d probes captured — no LLM configured, skipping judgement", successful))
		return
	}

	// 3. LLM judgement
	verdict, err := e.judgeBusinessLogic(ctx, task.URL, orig.Method, field, baselineValue, task.Reason, probes)
	if err != nil {
		e.completeFollowUp(task, store.FollowUpFailed, "judgement failed: "+err.Error())
		return
	}

	statusMsg := fmt.Sprintf("%d probes → %s (confidence %.2f)",
		successful, ternary(verdict.IsVuln, "CONFIRMED business-logic vuln", "not vulnerable"),
		verdict.Confidence)
	e.completeFollowUp(task, store.FollowUpDone, statusMsg)

	e.db.InsertNarration(e.scanID, "explorer", "result",
		fmt.Sprintf("%s on %s field='%s' — %s",
			ternary(verdict.IsVuln, "BUSINESS-LOGIC VULN", "business-logic dismissed"),
			shortenURL(task.URL), field, verdict.Reasoning),
		task.URL, map[string]any{
			"is_vuln":    verdict.IsVuln,
			"confidence": verdict.Confidence,
			"severity":   verdict.Severity,
			"field":      field,
		})

	if verdict.IsVuln {
		e.storeBusinessLogicFinding(task, orig.Method, field, baselineValue, probes, verdict)
	}
}

func graphQLIntrospectionLogicProbe(rawURL, field string, probes []logicProbe) bool {
	if !strings.EqualFold(strings.TrimSpace(field), "query") {
		return false
	}
	if graphQLEndpointURL(rawURL) == "" {
		return false
	}
	for _, probe := range probes {
		if probe.Err == nil && graphqlSchemaExposed(probe.BodyBytes) {
			return true
		}
	}
	return false
}

func genericGraphQLQueryLogicProbe(rawURL, field string) bool {
	return strings.EqualFold(strings.TrimSpace(field), "query") && graphQLEndpointURL(rawURL) != ""
}

func businessLogicFieldIsCSRFToken(field string) bool {
	norm := strings.ToLower(strings.TrimSpace(field))
	norm = strings.ReplaceAll(norm, "-", "_")
	switch norm {
	case "csrf", "csrf_token", "_csrf", "token", "_token", "user_token", "authenticity_token", "nonce":
		return true
	}
	return strings.HasSuffix(norm, "_csrf") || strings.HasSuffix(norm, "_token")
}

func (e *ExplorerAgent) storeGraphQLIntrospectionProbeFinding(task store.FollowUp, probes []logicProbe) {
	var matched logicProbe
	for _, probe := range probes {
		if probe.Err == nil && graphqlSchemaExposed(probe.BodyBytes) {
			matched = probe
			break
		}
	}
	typeCount := graphqlSchemaTypeCount(matched.BodyBytes)
	e.completeFollowUp(task, store.FollowUpDone,
		fmt.Sprintf("GraphQL introspection exposed schema (%d types)", typeCount))
	e.db.InsertNarration(e.scanID, "explorer", "result",
		fmt.Sprintf("GraphQL introspection exposed the schema on %s (%d type(s)); recorded as info, not business-logic severity.",
			shortenURL(task.URL), typeCount),
		task.URL, map[string]any{"types": typeCount})

	endpointID := task.SourceProfileID
	if endpointID == "" {
		endpointID = "POST " + task.URL
	}
	bodyBytes, _ := json.Marshal(map[string]string{"query": matched.TestValue})
	pocReq := buildRawPOSTRequest(task.URL, "application/json", bodyBytes, nil)
	pocResp := fmt.Sprintf("HTTP/1.1 %d\n\n%s", matched.StatusCode, truncateString(string(matched.BodyBytes), 1200))
	e.db.InsertFinding(e.scanID, types.Finding{
		Title:            "GraphQL introspection enabled",
		Description:      fmt.Sprintf("POST %s accepts a GraphQL introspection query and returns `data.__schema`, exposing the API schema.", task.URL),
		Severity:         types.SeverityInfo,
		Confidence:       types.ConfidenceConfirmed,
		EndpointID:       endpointID,
		VulnType:         "graphql_introspection",
		ParamName:        "query",
		Payload:          matched.TestValue,
		PocRequest:       pocReq,
		PocResponse:      pocResp,
		StepsToReproduce: fmt.Sprintf("1. Send POST %s with JSON body `%s`.\n2. Observe the response contains `data.__schema` with %d type(s).", task.URL, string(bodyBytes), typeCount),
		Impact:           "Schema introspection exposes the GraphQL operation and type map. This is usually informational by itself, but it can accelerate discovery of sensitive queries, mutations, and authorization flaws.",
		Remediation:      "Disable GraphQL introspection in production unless explicitly required, and enforce authorization in resolvers.",
		Evidence: fmt.Sprintf("URL: %s\nHTTP: %d\nSchema types: %d\nResponse preview: %s",
			task.URL, matched.StatusCode, typeCount, truncateString(string(matched.BodyBytes), 600)),
		HypothesisID: task.HypothesisID,
	})
}

type idorVerdict struct {
	IsIDOR      bool                `json:"is_idor"`
	Confidence  float64             `json:"confidence"`
	Severity    string              `json:"severity"`
	Evidence    string              `json:"evidence"`
	AffectedIDs flexibleStringSlice `json:"affected_ids"`
	Reasoning   string              `json:"first_person_reasoning"`
}

// flexibleStringSlice accepts both the requested JSON string ids and numeric
// ids that reasoning models commonly emit. Resource identifiers are rendered
// into reports as text either way, so rejecting an otherwise valid verdict
// over this harmless representation difference loses confirmed evidence.
type flexibleStringSlice []string

func (s *flexibleStringSlice) UnmarshalJSON(data []byte) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		var text string
		if err := json.Unmarshal(item, &text); err == nil {
			out = append(out, text)
			continue
		}
		var number json.Number
		if err := json.Unmarshal(item, &number); err == nil && number.String() != "" {
			out = append(out, number.String())
			continue
		}
		return fmt.Errorf("affected id must be a string or number: %s", string(item))
	}
	*s = out
	return nil
}

// idorJudgePrompt — the whole point of the tool. The LLM reads the responses
// and decides whether we're looking at different users' data being leaked
// without authorization. Traditional DAST cannot do this because the signal
// is semantic, not syntactic.
const idorJudgePrompt = `You are a pentester reviewing the results of an IDOR probe. You will receive responses to the SAME endpoint with DIFFERENT id values substituted in. Your job is to decide: is this endpoint leaking resources for ids the requester shouldn't have access to?

Decision rules:
1. If responses contain CONCRETE, DIFFERENT per-resource data across ids (distinct names, emails, order details, message bodies, account numbers, etc.) AND the server returned 200 for all → strong IDOR signal
2. If all responses are 401 / 403 / "not authorized" / "access denied" / redirects to login → authz enforced, NOT an IDOR
3. If all responses are the SAME generic error page or "not found" → no resources were served, NOT confirmed
4. If all responses are the SAME content → probably a cached/shared page, NOT an IDOR
5. If a mix: some 200 with distinct data, some 403/404 — still IDOR on the ones that returned data (authz inconsistent)

Severity guide:
  - "critical": returning full PII (names, emails, addresses, payment info) across distinct resources
  - "high":     returning distinct user-owned resources without PII exposure (order ids, session info, configs)
  - "medium":   behavior differs by id but leak is limited (boolean info, usernames only)
  - "low":      marginal signal you'd include only for completeness

You MUST output strict JSON, no prose outside:
{
  "is_idor": true|false,
  "confidence": 0.0 to 1.0,
  "severity": "critical"|"high"|"medium"|"low",
  "evidence": "2-3 sentence explanation citing CONCRETE content from the responses (e.g. 'id=1 returned user alice@example.com with address 123 Oak St; id=2 returned user bob@example.com with address 456 Pine St — distinct PII, no authorization check observed')",
  "affected_ids": ["list of ids that returned resource data"],
  "first_person_reasoning": "one-sentence pentester thought"
}`

// judgeIDOR asks the LLM whether the probed response set is an IDOR.
func (e *ExplorerAgent) judgeIDOR(ctx context.Context, urlTemplate, reason string, probes []idorProbe) (*idorVerdict, error) {
	// Build the user prompt — include snippet per probe, capped to keep tokens bounded.
	var sb strings.Builder
	fmt.Fprintf(&sb, "Endpoint template: %s\nAnalyzer's reason to probe: %s\n\nProbe results:\n", urlTemplate, reason)
	const snippetMax = 500
	for _, p := range probes {
		fmt.Fprintf(&sb, "\n--- id=%s ---\n", p.ID)
		if p.Err != nil {
			fmt.Fprintf(&sb, "request error: %s\n", p.Err.Error())
			continue
		}
		fmt.Fprintf(&sb, "HTTP %d, %d bytes\n", p.StatusCode, len(p.BodyBytes))
		fmt.Fprintf(&sb, "body snippet:\n%s\n", truncateBody(p.BodyBytes, snippetMax))
	}
	sb.WriteString("\nJudge this probe set.")

	user := sb.String()
	est := e.provider.CountTokens(idorJudgePrompt + user)
	if !e.budget.CanSpend(est) {
		return nil, fmt.Errorf("budget exhausted")
	}

	start := time.Now()
	req := &llm.Request{
		SystemPrompt: idorJudgePrompt,
		Messages:     []llm.Message{{Role: "user", Content: user}},
		Temperature:  0.1,
		MaxTokens:    llm.StructuredOutputTokenLimit(e.provider, 512, 2048),
		JSONMode:     true,
	}
	resp, err := llm.CompleteBudgeted(ctx, e.provider, e.budget, req, est)
	dur := time.Since(start).Milliseconds()
	if err != nil {
		return nil, err
	}
	modelID := llm.ResponseModel(resp, e.provider)
	costU := llm.CostMicroCents(modelID, resp.Usage)

	// Use the shared brace-counting extractJSON (defined in analyzer_agent.go)
	// instead of the old naive "first { to last }" heuristic, so MiniMax-M2's
	// multi-object + prose-wrapped output parses reliably. The old code dropped
	// ~30% of scan 27's IDOR verdicts on this same bug.
	var v idorVerdict
	if err := unmarshalSingleModelObject(resp.Content, &v); err != nil {
		_ = e.db.LogAIFull(e.scanID, "explorer", "idor_judge_failed",
			urlTemplate, "", urlTemplate, err.Error(),
			resp.Usage.InputTokens, resp.Usage.OutputTokens, dur, costU, modelID,
			llm.RenderPrompt(req), resp.Content)
		return nil, fmt.Errorf("parse verdict: %w", err)
	}
	_ = e.db.LogAIFull(e.scanID, "explorer", "idor_judge",
		urlTemplate, "", urlTemplate, truncateString(resp.Content, 200),
		resp.Usage.InputTokens, resp.Usage.OutputTokens, dur, costU, modelID,
		llm.RenderPrompt(req), resp.Content)
	// Sanity defaults
	if v.Severity == "" {
		if v.IsIDOR {
			v.Severity = "high"
		} else {
			v.Severity = "low"
		}
	}
	return &v, nil
}

// storeIDORFinding writes a bounty-report-grade Finding for a confirmed IDOR,
// including PoC request/response snippets so the detail panel has everything.
func (e *ExplorerAgent) storeIDORFinding(task store.FollowUp, template string, probes []idorProbe, verdict *idorVerdict) {
	// Build a PoC that shows the SAME request pattern with TWO distinct ids
	// side by side. That's the tightest proof of IDOR there is.
	var req1, req2, resp1, resp2 string
	var id1, id2 string
	for _, p := range probes {
		if p.Err != nil {
			continue
		}
		if id1 == "" {
			id1 = p.ID
			req1 = fmt.Sprintf("GET %s HTTP/1.1\nHost: <target>\n\n", p.URL)
			resp1 = fmt.Sprintf("HTTP/1.1 %d\n\n%s", p.StatusCode, truncateBody(p.BodyBytes, 800))
		} else if id2 == "" {
			id2 = p.ID
			req2 = fmt.Sprintf("GET %s HTTP/1.1\nHost: <target>\n\n", p.URL)
			resp2 = fmt.Sprintf("HTTP/1.1 %d\n\n%s", p.StatusCode, truncateBody(p.BodyBytes, 800))
			break
		}
	}

	pocReq := fmt.Sprintf("# Attempt 1 (id=%s)\n%s\n# Attempt 2 (id=%s)\n%s", id1, req1, id2, req2)
	pocResp := fmt.Sprintf("# Response for id=%s\n%s\n\n# Response for id=%s\n%s", id1, resp1, id2, resp2)

	steps := fmt.Sprintf(
		"1. Observe that %s uses a resource id in the path (the {id} component).\n"+
			"2. Authenticate as one user (or unauthenticated, if permitted).\n"+
			"3. Request the endpoint twice with different id values you don't own:\n\n%s\n"+
			"4. Compare responses — if they return distinct resource data (see below), authorization is not being enforced on ownership.",
		template, pocReq)

	impact := "An attacker who learns the endpoint can enumerate arbitrary resource ids and read data belonging to other users. " +
		"Sequential integer ids make full-scale scraping trivial. Impact scales with the sensitivity of the data served " +
		"— PII, order history, private messages, configuration, payment details, etc. " +
		"Combined with bulk scripting, this commonly leads to mass data exfiltration and regulatory exposure (GDPR/CCPA)."

	remediation := "Enforce ownership on every request that targets a specific resource id: verify the authenticated user owns or has explicit authorization to view that id BEFORE serving the resource. " +
		"Prefer server-side session/user-scoped queries (`WHERE owner_id = current_user`) over trusting client-supplied ids. " +
		"Consider unguessable identifiers (UUIDs) as defense in depth, but these alone are not a substitute for authorization checks."

	severity := types.Severity(strings.ToLower(verdict.Severity))
	switch severity {
	case types.SeverityCritical, types.SeverityHigh, types.SeverityMedium, types.SeverityLow, types.SeverityInfo:
		// ok
	default:
		severity = types.SeverityHigh
	}

	e.db.InsertFinding(e.scanID, types.Finding{
		Title:            fmt.Sprintf("IDOR — %s exposes other users' resources", template),
		Description:      fmt.Sprintf("Automated probe of %s with multiple id values returned distinct resource data for ids the requester should not own. The LLM reviewed the responses and judged this a confirmed IDOR (confidence %.2f). %s", template, verdict.Confidence, verdict.Evidence),
		Severity:         severity,
		Confidence:       types.ConfidenceConfirmed,
		EndpointID:       task.SourceProfileID,
		VulnType:         "idor",
		PocRequest:       pocReq,
		PocResponse:      pocResp,
		StepsToReproduce: steps,
		Impact:           impact,
		Remediation:      remediation,
		Evidence: fmt.Sprintf("Template: %s\nConfidence: %.2f\nAffected ids: %s\n\nLLM evidence: %s",
			template, verdict.Confidence, strings.Join(verdict.AffectedIDs, ", "), verdict.Evidence),
		// Trace back to the Strategist hypothesis that motivated this probe.
		// InsertFinding uses this to auto-confirm the hypothesis.
		HypothesisID: task.HypothesisID,
	})
}

// truncateBody cuts a response body to maxLen chars, adding an ellipsis when
// truncated. Used for LLM-prompt snippets and PoC display.
func truncateBody(body []byte, maxLen int) string {
	s := string(body)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "\n... [truncated]"
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// unmarshalSingleModelObject accepts the ordinary object form and the common
// one-element array form emitted by some reasoning models in JSON mode. It
// rejects ambiguous multi-verdict responses instead of silently choosing a
// result that may refer to another probe.
func unmarshalSingleModelObject[T any](content string, dst *T) error {
	content = repairDroppedVerdictPrefix(content)
	cleaned := extractJSON(content)
	objectErr := json.Unmarshal([]byte(cleaned), dst)
	if objectErr == nil {
		return nil
	}
	// If the extracted value is clearly an object, retain the useful field-
	// level error instead of replacing it with "cannot unmarshal object into
	// []RawMessage" from the array fallback.
	if strings.HasPrefix(strings.TrimSpace(cleaned), "{") {
		return objectErr
	}
	var items []json.RawMessage
	if err := json.Unmarshal([]byte(cleaned), &items); err != nil {
		return err
	}
	if len(items) != 1 {
		return fmt.Errorf("expected one verdict object, got %d", len(items))
	}
	return json.Unmarshal(items[0], dst)
}

func repairDroppedVerdictPrefix(content string) string {
	trimmed := strings.TrimSpace(content)
	// Observed MiniMax JSON-mode variants after dropping the opening {"is
	// bytes from {"is_idor":...} or {"is_vuln":...}. Keep the repair exact:
	// arbitrary prose and other missing fields remain parse failures.
	if strings.HasPrefix(trimmed, `_idor"`) || strings.HasPrefix(trimmed, `_vuln"`) {
		return `{"is` + trimmed
	}
	return content
}

// Note: the old extractAnyJSON helper was removed — it used a naive first-{
// to last-} heuristic that broke on MiniMax-M2's multi-object responses.
// Callers now use the shared extractJSON from analyzer_agent.go which does
// proper brace counting with string-escape awareness.

// businessLogicVerdict is the LLM's judgement on a business-logic probe set.
type businessLogicVerdict struct {
	IsVuln         bool     `json:"is_vuln"`
	Confidence     float64  `json:"confidence"`
	Severity       string   `json:"severity"`
	VulnClass      string   `json:"vuln_class"` // "price-manipulation", "privilege-escalation", "quantity-bypass", "user-enumeration", etc.
	Evidence       string   `json:"evidence"`
	AcceptedValues []string `json:"accepted_values"` // illegal values the server accepted
	Reasoning      string   `json:"first_person_reasoning"`
}

// businessLogicJudgePrompt — the LLM reasons about whether the server accepted
// illegal values for a field it should have been validating server-side.
// This catches price manipulation, quantity bypass, role escalation,
// workflow-state jumps — the "traditional DAST can't do this" category.
const businessLogicJudgePrompt = `You are a pentester reviewing the results of a business-logic probe. An automated probe took a captured request, mutated ONE field's value with illegal/boundary values, and replayed each. Your job is to decide: is the server accepting values it shouldn't?

Decision rules:
1. If the server ACCEPTED an illegal value (returned 200 + a success response when the value was clearly invalid — negative price, zero quantity, admin role, etc.) → CONFIRMED business-logic vuln
2. If every illegal value was REJECTED (400/422/403 with validation error) → server is properly validating, NOT a vuln
3. If the server accepted the value but SANITIZED it server-side (e.g., clamped negative price to 0) → partially validated, flag as "low" severity or not a vuln
4. If responses are identical across values → server might be ignoring the field entirely (suspicious but not auto-vuln)
5. If some illegal values accepted and some rejected → PARTIAL vuln; report with the accepted ones
6. If this is an auth/login/register/password-reset identifier field (email/username/login) and all attempts fail, but the status/body/timing clearly differs between registered and unregistered accounts (for example "Email is not registered" vs "Invalid credentials") → CONFIRMED "user-enumeration", not generic business logic
7. If this is an auth/login identifier field and the only observation is "different invalid input produced a different 4xx" without a clear account-existence signal → NOT a vuln
8. If the endpoint is GraphQL and the mutated field is named "query", arbitrary query text is part of the GraphQL protocol; do NOT report "query is not server-validated" as business logic. Only report a GraphQL vulnerability when the response proves a specific security failure such as unauthorized object access, sensitive data exposure, introspection, or missing depth/complexity limits.

Vuln classes to consider:
  - "price-manipulation"    (price/amount/total accepted as negative, zero, tiny)
  - "quantity-bypass"       (quantity/qty accepted as negative or zero)
  - "privilege-escalation"  (role/is_admin/permission accepted elevated value)
  - "cross-tenant"          (user_id/owner_id accepted other users' ids — note: use probe_idor for paths)
  - "discount-abuse"        (discount/coupon/percentage accepted >100%, negative, infinite)
  - "workflow-skip"         (status/state accepted out-of-sequence value)
  - "integer-overflow"      (numeric field accepted huge value that broke downstream calc)
  - "user-enumeration"      (auth/account recovery endpoint reveals whether an email/username exists)
  - "other"

Severity guide:
  - "critical": real financial impact likely (accepting $0 orders, 100% discount, negative prices that become credits)
  - "high":     clearly exploitable with direct security impact (privilege escalation, cross-tenant leakage)
  - "medium":   server accepted illegal value but impact is narrow or speculative
  - "low":      suspicious but unclear exploit path (maybe the field is ignored)

Output strict JSON, no prose outside:
{
  "is_vuln": true|false,
  "confidence": 0.0 to 1.0,
  "severity": "critical"|"high"|"medium"|"low",
  "vuln_class": "one of the classes above",
  "evidence": "2-3 sentence explanation grounded in the ACTUAL response content (cite specific status codes, body fields, numeric values)",
  "accepted_values": ["list of test values the server accepted when it should have rejected"],
  "first_person_reasoning": "one-sentence pentester thought"
}`

// judgeBusinessLogic asks the LLM whether the probe set indicates a
// business-logic vulnerability.
func (e *ExplorerAgent) judgeBusinessLogic(ctx context.Context, targetURL, method, field, baseline, reason string, probes []logicProbe) (*businessLogicVerdict, error) {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Endpoint: %s %s\nField mutated: %s\n", method, targetURL, field)
	if baseline != "" {
		fmt.Fprintf(&sb, "Baseline value (from the captured original request): %s\n", baseline)
	}
	fmt.Fprintf(&sb, "Analyzer's reason to probe: %s\n\nProbe results:\n", reason)

	const snippetMax = 500
	for _, p := range probes {
		fmt.Fprintf(&sb, "\n--- %s=%s ---\n", field, p.TestValue)
		if p.Err != nil {
			fmt.Fprintf(&sb, "request error: %s\n", p.Err.Error())
			continue
		}
		fmt.Fprintf(&sb, "HTTP %d, %d bytes\n", p.StatusCode, len(p.BodyBytes))
		fmt.Fprintf(&sb, "body snippet:\n%s\n", truncateBody(p.BodyBytes, snippetMax))
	}
	sb.WriteString("\nJudge this probe set.")
	user := sb.String()

	est := e.provider.CountTokens(businessLogicJudgePrompt + user)
	if !e.budget.CanSpend(est) {
		return nil, fmt.Errorf("budget exhausted")
	}

	start := time.Now()
	req := &llm.Request{
		SystemPrompt: businessLogicJudgePrompt,
		Messages:     []llm.Message{{Role: "user", Content: user}},
		Temperature:  0.1,
		MaxTokens:    llm.StructuredOutputTokenLimit(e.provider, 512, 2048),
		JSONMode:     true,
	}
	resp, err := llm.CompleteBudgeted(ctx, e.provider, e.budget, req, est)
	dur := time.Since(start).Milliseconds()
	if err != nil {
		return nil, err
	}
	modelID := llm.ResponseModel(resp, e.provider)
	costU := llm.CostMicroCents(modelID, resp.Usage)

	// Same parser fix as judgeIDOR — share the brace-counting extractor.
	var v businessLogicVerdict
	if err := unmarshalSingleModelObject(resp.Content, &v); err != nil {
		_ = e.db.LogAIFull(e.scanID, "explorer", "logic_judge_failed",
			fmt.Sprintf("%s field='%s'", targetURL, field), "", targetURL,
			err.Error(),
			resp.Usage.InputTokens, resp.Usage.OutputTokens, dur, costU, modelID,
			llm.RenderPrompt(req), resp.Content)
		return nil, fmt.Errorf("parse verdict: %w", err)
	}
	_ = e.db.LogAIFull(e.scanID, "explorer", "logic_judge",
		fmt.Sprintf("%s field='%s'", targetURL, field), "", targetURL,
		truncateString(resp.Content, 200),
		resp.Usage.InputTokens, resp.Usage.OutputTokens, dur, costU, modelID,
		llm.RenderPrompt(req), resp.Content)
	if v.Severity == "" {
		if v.IsVuln {
			v.Severity = "medium"
		} else {
			v.Severity = "low"
		}
	}
	if v.VulnClass == "" {
		v.VulnClass = "other"
	}
	return &v, nil
}

// storeBusinessLogicFinding writes a bounty-report-grade Finding for a
// confirmed business-logic vuln.
func (e *ExplorerAgent) storeBusinessLogicFinding(task store.FollowUp, method, field, baseline string, probes []logicProbe, verdict *businessLogicVerdict) {
	// Build side-by-side PoC: baseline-accepting vs. illegal-accepting request.
	// We grab the first successful probe's mutated response as Attempt 1
	// and, if there's a second, use it as Attempt 2.
	var req1, resp1, req2, resp2 string
	var val1, val2 string
	for _, p := range probes {
		if p.Err != nil {
			continue
		}
		if val1 == "" {
			val1 = p.TestValue
			req1 = buildPlaceholderHTTPRequest(method, task.URL,
				fmt.Sprintf("<original body with %s=%s>", field, p.TestValue))
			resp1 = fmt.Sprintf("HTTP/1.1 %d\n\n%s", p.StatusCode, truncateBody(p.BodyBytes, 800))
		} else if val2 == "" {
			val2 = p.TestValue
			req2 = buildPlaceholderHTTPRequest(method, task.URL,
				fmt.Sprintf("<original body with %s=%s>", field, p.TestValue))
			resp2 = fmt.Sprintf("HTTP/1.1 %d\n\n%s", p.StatusCode, truncateBody(p.BodyBytes, 800))
			break
		}
	}

	pocReq := fmt.Sprintf("# Attempt 1 (%s=%s)\n%s\n", field, val1, req1)
	if req2 != "" {
		pocReq += fmt.Sprintf("\n# Attempt 2 (%s=%s)\n%s", field, val2, req2)
	}
	pocResp := fmt.Sprintf("# Response to %s=%s\n%s", field, val1, resp1)
	if resp2 != "" {
		pocResp += fmt.Sprintf("\n\n# Response to %s=%s\n%s", field, val2, resp2)
	}

	if businessLogicLooksLikeUserEnumeration(task.URL, field, probes, verdict) {
		if pair1, pair2, ok := userEnumerationProbePair(probes); ok {
			val1, val2 = pair1.TestValue, pair2.TestValue
			req1 = buildPlaceholderHTTPRequest(method, task.URL,
				fmt.Sprintf("<original body with %s=%s>", field, pair1.TestValue))
			req2 = buildPlaceholderHTTPRequest(method, task.URL,
				fmt.Sprintf("<original body with %s=%s>", field, pair2.TestValue))
			resp1 = fmt.Sprintf("HTTP/1.1 %d\n\n%s", pair1.StatusCode, truncateBody(pair1.BodyBytes, 800))
			resp2 = fmt.Sprintf("HTTP/1.1 %d\n\n%s", pair2.StatusCode, truncateBody(pair2.BodyBytes, 800))
			pocReq = fmt.Sprintf("# Attempt 1 (%s=%s)\n%s\n\n# Attempt 2 (%s=%s)\n%s",
				field, val1, req1, field, val2, req2)
			pocResp = fmt.Sprintf("# Response to %s=%s\n%s\n\n# Response to %s=%s\n%s",
				field, val1, resp1, field, val2, resp2)
		}
		steps := fmt.Sprintf(
			"1. Send the same %s request to %s with one email/username value that is not registered (for example %s).\n"+
				"2. Replay the request with a candidate registered value (for example %s), keeping the password/body shape the same.\n"+
				"3. Compare the responses. Different messages/status/body shapes reveal whether the account exists.",
			method, task.URL, val1, val2)
		if val2 == "" {
			steps = fmt.Sprintf(
				"1. Send the same %s request to %s with multiple email/username values.\n"+
					"2. Keep the password/body shape the same for each request.\n"+
					"3. Compare the responses. Different messages/status/body shapes reveal whether the account exists.",
				method, task.URL)
		}
		severity := types.Severity(strings.ToLower(verdict.Severity))
		switch severity {
		case types.SeverityCritical, types.SeverityHigh:
			severity = types.SeverityMedium
		case types.SeverityMedium, types.SeverityLow, types.SeverityInfo:
			// ok
		default:
			severity = types.SeverityMedium
		}
		path := task.URL
		if u, err := url.Parse(task.URL); err == nil && u.Path != "" {
			path = u.Path
		}
		e.db.InsertFinding(e.scanID, types.Finding{
			Title: fmt.Sprintf("User enumeration on %s %s via %s response differences",
				method, path, field),
			Description: fmt.Sprintf("Automated replay of %s %s with different %s values produced distinguishable authentication failure responses. %s",
				method, task.URL, field, verdict.Evidence),
			Severity:         severity,
			Confidence:       types.ConfidenceConfirmed,
			EndpointID:       task.SourceProfileID,
			VulnType:         "user_enumeration",
			ParamName:        field,
			PocRequest:       pocReq,
			PocResponse:      pocResp,
			StepsToReproduce: steps,
			Impact:           "Attackers can enumerate valid user accounts, then focus password-spraying, credential-stuffing, phishing, or account recovery abuse against confirmed accounts.",
			Remediation:      "Return the same status code, body shape, and user-facing message for registered and unregistered accounts. Add rate limiting, lockout/backoff, monitoring, and normalize response timing where practical.",
			Evidence: fmt.Sprintf("Endpoint: %s %s\nField: %s\nConfidence: %.2f\nObserved values: %s\n\nLLM evidence: %s",
				method, task.URL, field, verdict.Confidence, businessLogicProbeValues(probes), verdict.Evidence),
			HypothesisID: task.HypothesisID,
		})
		return
	}

	if businessLogicLooksLikeCommandInjection(field, probes, verdict) {
		severity := types.Severity(strings.ToLower(verdict.Severity))
		switch severity {
		case types.SeverityCritical, types.SeverityHigh:
			// ok
		default:
			severity = types.SeverityCritical
		}
		path := task.URL
		if u, err := url.Parse(task.URL); err == nil && u.Path != "" {
			path = u.Path
		}
		e.db.InsertFinding(e.scanID, types.Finding{
			Title: fmt.Sprintf("OS command injection via %s on %s %s", field, method, path),
			Description: fmt.Sprintf("Automated replay of %s %s with shell metacharacter payloads in `%s` produced command-output evidence. %s",
				method, task.URL, field, verdict.Evidence),
			Severity:    severity,
			Confidence:  types.ConfidenceConfirmed,
			EndpointID:  task.SourceProfileID,
			VulnType:    "command_injection",
			ParamName:   field,
			PocRequest:  pocReq,
			PocResponse: pocResp,
			StepsToReproduce: fmt.Sprintf("1. Send the same %s request to %s with `%s` set to `%s`.\n2. Observe command-output evidence in the HTTP response.\n3. Repeat with a benign baseline value and confirm the command output disappears.",
				method, task.URL, field, val1),
			Impact:      "Attackers can execute operating-system commands in the web server context. This can lead to source disclosure, credential theft, pivoting inside the container/host network, data destruction, or full server compromise.",
			Remediation: "Do not pass client input to shell commands. Use safe library calls instead of shell execution; if command execution is unavoidable, use strict allowlists, argument arrays without shell interpretation, and server-side validation for exact expected formats.",
			Evidence: fmt.Sprintf("Endpoint: %s %s\nField: %s\nPayloads: %s\nConfidence: %.2f\n\nLLM evidence: %s",
				method, task.URL, field, businessLogicProbeValues(probes), verdict.Confidence, verdict.Evidence),
			HypothesisID: task.HypothesisID,
		})
		return
	}

	steps := fmt.Sprintf(
		"1. Capture a legitimate request to %s %s (baseline %s=%s).\n"+
			"2. Replay the request with '%s' changed to an illegal value (e.g. %s).\n"+
			"3. Observe the response — the server accepts the value instead of rejecting it, "+
			"which means ownership of %s is effectively delegated to the client.",
		method, task.URL, field, baseline, field, val1, field)

	impactMap := map[string]string{
		"price-manipulation":   "Orders can be placed at attacker-chosen prices (including zero or negative), bypassing payment. Repeated exploitation leads to direct financial loss proportional to the number of orders processed.",
		"quantity-bypass":      "Quantity controls can be bypassed — inventory reservation, rate limiting, and bulk-purchase restrictions all fail. Enables free or oversized orders.",
		"privilege-escalation": "Attacker can set their own role/permission without admin authorization. Full account takeover and tenant-wide data access become possible.",
		"cross-tenant":         "An attacker can set resource ownership to another user's id, accessing or modifying data they don't own. Classic multi-tenant breach pattern.",
		"discount-abuse":       "Discounts/coupons can be set to values the business never intended — 100%, negative (credits the attacker), or infinite — directly reducing revenue.",
		"workflow-skip":        "Workflow state can be advanced without completing prior steps (skipping payment, KYC, verification). The business process the server was meant to enforce is bypassed.",
		"integer-overflow":     "Large numeric inputs may overflow downstream calculations or storage. Depending on the flow, this can result in free orders, negative balances, or denial of service.",
	}
	impact := impactMap[verdict.VulnClass]
	if impact == "" {
		impact = "The server is accepting client-supplied values that should be validated server-side, letting an attacker drive business logic with inputs outside the intended range. Impact depends on how downstream systems use the field."
	}

	remediation := "Validate this field ON THE SERVER against the business rules that govern it — don't trust any value the client supplies. " +
		"For prices/amounts, recompute from the authoritative source (e.g. a server-side product lookup). " +
		"For roles/permissions, verify the authenticated user has authority to set that value. " +
		"For workflow state, check the transition is legal from the current state. " +
		"Reject invalid values with 400/422 and log for abuse detection."

	severity := types.Severity(strings.ToLower(verdict.Severity))
	switch severity {
	case types.SeverityCritical, types.SeverityHigh, types.SeverityMedium, types.SeverityLow, types.SeverityInfo:
		// ok
	default:
		severity = types.SeverityMedium
	}

	e.db.InsertFinding(e.scanID, types.Finding{
		Title: fmt.Sprintf("Business-logic vulnerability — '%s' field is not server-validated on %s %s",
			field, method, task.URL),
		Description: fmt.Sprintf("Automated probe replayed %s %s with illegal values for the '%s' field. "+
			"The LLM reviewed the response set and judged this a confirmed business-logic vulnerability "+
			"(class: %s, confidence %.2f). %s",
			method, task.URL, field, verdict.VulnClass, verdict.Confidence, verdict.Evidence),
		Severity:         severity,
		Confidence:       types.ConfidenceConfirmed,
		EndpointID:       task.SourceProfileID,
		VulnType:         verdict.VulnClass,
		ParamName:        field,
		PocRequest:       pocReq,
		PocResponse:      pocResp,
		StepsToReproduce: steps,
		Impact:           impact,
		Remediation:      remediation,
		Evidence: fmt.Sprintf("Endpoint: %s %s\nField: %s (baseline %s)\nClass: %s\nConfidence: %.2f\n"+
			"Accepted illegal values: %s\n\nLLM evidence: %s",
			method, task.URL, field, baseline, verdict.VulnClass, verdict.Confidence,
			strings.Join(verdict.AcceptedValues, ", "), verdict.Evidence),
		HypothesisID: task.HypothesisID,
	})
}

func businessLogicLooksLikeUserEnumeration(targetURL, field string, probes []logicProbe, verdict *businessLogicVerdict) bool {
	if verdict == nil {
		return false
	}
	class := strings.ToLower(strings.TrimSpace(verdict.VulnClass))
	if strings.Contains(class, "user-enumeration") || strings.Contains(class, "enumeration") {
		return true
	}
	fieldLower := strings.ToLower(strings.TrimSpace(field))
	if fieldLower != "email" && fieldLower != "username" && fieldLower != "login" && fieldLower != "user" {
		return false
	}
	urlLower := strings.ToLower(targetURL)
	if !strings.Contains(urlLower, "login") &&
		!strings.Contains(urlLower, "auth") &&
		!strings.Contains(urlLower, "register") &&
		!strings.Contains(urlLower, "reset") &&
		!strings.Contains(urlLower, "forgot") {
		return false
	}
	text := strings.ToLower(verdict.Evidence + " " + verdict.Reasoning)
	if !strings.Contains(text, "enumerat") &&
		!strings.Contains(text, "registered") &&
		!strings.Contains(text, "not registered") &&
		!strings.Contains(text, "invalid credentials") &&
		!strings.Contains(text, "account exists") {
		return false
	}
	seenStatus := map[int]bool{}
	seenBodies := map[string]bool{}
	for _, p := range probes {
		if p.Err != nil {
			continue
		}
		seenStatus[p.StatusCode] = true
		body := strings.TrimSpace(strings.ToLower(truncateBody(p.BodyBytes, 300)))
		if body != "" {
			seenBodies[body] = true
		}
	}
	return len(seenStatus) > 0 && len(seenBodies) > 1
}

func businessLogicLooksLikeCommandInjection(field string, probes []logicProbe, verdict *businessLogicVerdict) bool {
	if verdict == nil || !verdict.IsVuln {
		return false
	}
	payloadLike := false
	outputLike := false
	for _, probe := range probes {
		lowerValue := strings.ToLower(probe.TestValue)
		if strings.ContainsAny(lowerValue, ";|`") ||
			strings.Contains(lowerValue, "&&") ||
			strings.Contains(lowerValue, "$(") ||
			strings.Contains(lowerValue, "whoami") ||
			strings.Contains(lowerValue, "uname") ||
			strings.Contains(lowerValue, "/etc/passwd") {
			payloadLike = true
		}
		body := strings.ToLower(string(probe.BodyBytes))
		if strings.Contains(body, "uid=") ||
			strings.Contains(body, "gid=") ||
			strings.Contains(body, "www-data") ||
			strings.Contains(body, "root:x:0:0") ||
			strings.Contains(body, "linux") ||
			strings.Contains(body, "darwin") {
			outputLike = true
		}
	}
	return payloadLike && outputLike
}

func logicProbesAllCSRFRejected(probes []logicProbe) bool {
	checked := 0
	for _, probe := range probes {
		if probe.Err != nil {
			continue
		}
		checked++
		body := strings.ToLower(string(probe.BodyBytes))
		if !strings.Contains(body, "csrf token is incorrect") &&
			!strings.Contains(body, "invalid csrf") &&
			!strings.Contains(body, "csrf validation") &&
			!strings.Contains(body, "token is incorrect") &&
			!strings.Contains(body, "invalid token") {
			return false
		}
	}
	return checked > 0
}

func businessLogicProbeValues(probes []logicProbe) string {
	var vals []string
	seen := map[string]bool{}
	for _, p := range probes {
		v := strings.TrimSpace(p.TestValue)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		vals = append(vals, v)
	}
	if len(vals) == 0 {
		return "(none)"
	}
	return strings.Join(vals, ", ")
}

func userEnumerationProbePair(probes []logicProbe) (logicProbe, logicProbe, bool) {
	var clean []logicProbe
	for _, p := range probes {
		if p.Err == nil && strings.TrimSpace(p.TestValue) != "" {
			clean = append(clean, p)
		}
	}
	for i := 0; i < len(clean); i++ {
		for j := i + 1; j < len(clean); j++ {
			if clean[i].StatusCode != clean[j].StatusCode ||
				string(clean[i].BodyBytes) != string(clean[j].BodyBytes) {
				return clean[i], clean[j], true
			}
		}
	}
	if len(clean) >= 2 {
		return clean[0], clean[1], true
	}
	return logicProbe{}, logicProbe{}, false
}

// ── Business-logic probe helpers ──

// originalRequest is a snapshot of a captured request we'll mutate.
type originalRequest struct {
	URL         string
	Method      string
	ContentType string
	Headers     map[string]string
	Body        []byte
}

// originalRequestFor fetches the most recent captured request for a URL so
// we can replay it with a mutated body. Prefers POST/PUT/PATCH over GET.
func (e *ExplorerAgent) originalRequestFor(rawURL string) (*originalRequest, error) {
	// Prefer state-changing methods — those are what business-logic probes care about.
	row := e.db.Conn().QueryRow(`
		SELECT method, request_headers, request_body, COALESCE(content_type,'')
		FROM traffic
		WHERE scan_id = ? AND url = ? AND is_filtered = FALSE
		ORDER BY
		  CASE method WHEN 'POST' THEN 0 WHEN 'PUT' THEN 0 WHEN 'PATCH' THEN 0 ELSE 1 END,
		  id DESC
		LIMIT 1`, e.scanID, rawURL)

	var method, headersJSON, contentType string
	var body []byte
	if err := row.Scan(&method, &headersJSON, &body, &contentType); err != nil {
		return nil, err
	}
	headers := map[string]string{}
	if headersJSON != "" && headersJSON != "{}" {
		json.Unmarshal([]byte(headersJSON), &headers)
	}
	if contentType == "" {
		for k, v := range headers {
			if strings.EqualFold(k, "Content-Type") {
				contentType = v
				break
			}
		}
	}
	return &originalRequest{
		URL:         rawURL,
		Method:      method,
		ContentType: contentType,
		Headers:     headers,
		Body:        body,
	}, nil
}

// sendMutated replays the captured request with a new body, preserving method
// and (most) headers.
func (e *ExplorerAgent) sendMutated(ctx context.Context, orig *originalRequest, newBody []byte) (*http.Response, []byte, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, orig.Method, orig.URL, strings.NewReader(string(newBody)))
	if err != nil {
		return nil, nil, nil, err
	}
	for k, v := range orig.Headers {
		lower := strings.ToLower(k)
		if lower == "host" || lower == "content-length" || lower == "accept-encoding" {
			continue
		}
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", "AOBTD/Explorer (a pentest tool)")
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	hdrs := make(map[string]string, len(req.Header))
	for k, vs := range req.Header {
		if len(vs) > 0 {
			hdrs[k] = vs[0]
		}
	}
	return resp, body, hdrs, nil
}

// extractFieldValue pulls the current value of a top-level JSON key or a
// form-encoded field from a request body. Used to record the baseline for
// the LLM prompt ("current price is 19.99 — see how the server handles -1").
func extractFieldValue(body []byte, contentType, field string) string {
	s := string(body)
	if strings.Contains(strings.ToLower(contentType), "json") || (len(s) > 0 && (s[0] == '{' || s[0] == '[')) {
		var m map[string]any
		if err := json.Unmarshal(body, &m); err == nil {
			if v, ok := m[field]; ok {
				return fmt.Sprintf("%v", v)
			}
		}
		return ""
	}
	// form-encoded
	if values, err := url.ParseQuery(s); err == nil {
		return values.Get(field)
	}
	return ""
}

// replaceFieldValue substitutes a field's value in a request body. Returns
// (newBody, true) on success, (original, false) if the field wasn't found.
// Handles top-level JSON keys and form-encoded fields.
func replaceFieldValue(body []byte, contentType, field, newValue string) ([]byte, bool) {
	s := string(body)
	// JSON body (detect via content-type OR body shape)
	if strings.Contains(strings.ToLower(contentType), "json") || (len(s) > 0 && (s[0] == '{' || s[0] == '[')) {
		var m map[string]any
		if err := json.Unmarshal(body, &m); err == nil {
			if _, ok := m[field]; !ok {
				return body, false
			}
			// Try to preserve number-ness vs string-ness of the new value so
			// we don't surprise the server with an unexpected type
			m[field] = coerceValue(newValue)
			out, err := json.Marshal(m)
			if err != nil {
				return body, false
			}
			return out, true
		}
		return body, false
	}
	// form-encoded
	values, err := url.ParseQuery(s)
	if err != nil {
		return body, false
	}
	if _, ok := values[field]; !ok {
		return body, false
	}
	values.Set(field, newValue)
	return []byte(values.Encode()), true
}

// coerceValue picks the most natural JSON type for a string. Numbers become
// numbers, "true"/"false" become booleans, everything else stays a string.
// Keeps the mutation honest when replaying into JSON bodies.
func coerceValue(s string) any {
	if s == "true" {
		return true
	}
	if s == "false" {
		return false
	}
	// Try integer then float
	var iv int64
	if _, err := fmt.Sscanf(s, "%d", &iv); err == nil && fmt.Sprintf("%d", iv) == s {
		return iv
	}
	var fv float64
	if _, err := fmt.Sscanf(s, "%g", &fv); err == nil {
		// Only coerce to float if string looks numeric (contains . or e)
		if strings.ContainsAny(s, ".eE") {
			return fv
		}
	}
	return s
}

func graphqlSchemaExposed(body []byte) bool {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return false
	}
	data, ok := doc["data"].(map[string]any)
	if !ok {
		return false
	}
	_, ok = data["__schema"]
	return ok
}

func graphqlSchemaTypeCount(body []byte) int {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return 0
	}
	data, ok := doc["data"].(map[string]any)
	if !ok {
		return 0
	}
	schema, ok := data["__schema"].(map[string]any)
	if !ok {
		return 0
	}
	types, ok := schema["types"].([]any)
	if !ok {
		return 0
	}
	return len(types)
}

func buildRawPOSTRequest(rawURL, contentType string, body []byte, headers map[string]string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Sprintf("POST %s HTTP/1.1\nContent-Type: %s\n\n%s", rawURL, contentType, string(body))
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	if parsed.RawQuery != "" {
		path += "?" + parsed.RawQuery
	}
	var b strings.Builder
	fmt.Fprintf(&b, "POST %s HTTP/1.1\nHost: %s\n", path, parsed.Host)
	if contentType != "" {
		fmt.Fprintf(&b, "Content-Type: %s\n", contentType)
	}
	for k, v := range headers {
		lower := strings.ToLower(k)
		if lower == "host" || lower == "content-length" || lower == "content-type" {
			continue
		}
		fmt.Fprintf(&b, "%s: %s\n", k, v)
	}
	fmt.Fprintf(&b, "Content-Length: %d\n\n%s", len(body), string(body))
	return b.String()
}

func buildRawGETRequest(rawURL string, headers map[string]string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Sprintf("GET %s HTTP/1.1\n\n", rawURL)
	}
	requestURI := parsed.RequestURI()
	if requestURI == "" {
		requestURI = "/"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "GET %s HTTP/1.1\n", requestURI)
	if parsed.Host != "" {
		fmt.Fprintf(&b, "Host: %s\n", parsed.Host)
	}
	for k, v := range headers {
		lower := strings.ToLower(k)
		if lower == "host" || lower == "content-length" || lower == "cookie" || lower == "authorization" {
			continue
		}
		fmt.Fprintf(&b, "%s: %s\n", k, v)
	}
	b.WriteString("\n")
	return b.String()
}

func buildPlaceholderHTTPRequest(method, rawURL, bodyDescription string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Sprintf("%s %s HTTP/1.1\n\n%s", method, rawURL, bodyDescription)
	}
	requestURI := parsed.RequestURI()
	if requestURI == "" {
		requestURI = "/"
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Sprintf("%s %s HTTP/1.1\n\n%s", method, requestURI, bodyDescription)
	}
	return fmt.Sprintf("%s %s HTTP/1.1\nHost: %s\n\n%s",
		method, requestURI, parsed.Host, bodyDescription)
}

// ── helpers ──

func (e *ExplorerAgent) sendGET(ctx context.Context, rawURL string, extraHeaders map[string]string) (*http.Response, []byte, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	req.Header.Set("User-Agent", "AOBTD/Explorer (a pentest tool)")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	// Snapshot request headers for the traffic record
	hdrs := make(map[string]string, len(req.Header))
	for k, vs := range req.Header {
		if len(vs) > 0 {
			hdrs[k] = vs[0]
		}
	}
	return resp, body, hdrs, nil
}

func (e *ExplorerAgent) sendJSONPOST(ctx context.Context, rawURL string, bodyBytes []byte, extraHeaders map[string]string) (*http.Response, []byte, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", rawURL, strings.NewReader(string(bodyBytes)))
	if err != nil {
		return nil, nil, nil, err
	}
	req.Header.Set("User-Agent", "AOBTD/Explorer (a pentest tool)")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	for k, v := range extraHeaders {
		lower := strings.ToLower(k)
		if lower == "host" || lower == "content-length" {
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	hdrs := make(map[string]string, len(req.Header))
	for k, vs := range req.Header {
		if len(vs) > 0 {
			hdrs[k] = vs[0]
		}
	}
	return resp, body, hdrs, nil
}

func (e *ExplorerAgent) sendFormPOST(ctx context.Context, rawURL string, values url.Values, extraHeaders map[string]string) (*http.Response, []byte, map[string]string, error) {
	bodyString := values.Encode()
	req, err := http.NewRequestWithContext(ctx, "POST", rawURL, strings.NewReader(bodyString))
	if err != nil {
		return nil, nil, nil, err
	}
	req.Header.Set("User-Agent", "AOBTD/Explorer (a pentest tool)")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range extraHeaders {
		lower := strings.ToLower(k)
		if lower == "host" || lower == "content-length" || lower == "content-type" {
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	hdrs := make(map[string]string, len(req.Header))
	for k, vs := range req.Header {
		if len(vs) > 0 {
			hdrs[k] = vs[0]
		}
	}
	return resp, body, hdrs, nil
}

func (e *ExplorerAgent) sendRawPOST(ctx context.Context, rawURL string, bodyBytes []byte, contentType string, extraHeaders map[string]string) (*http.Response, []byte, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", rawURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, nil, nil, err
	}
	req.Header.Set("User-Agent", "AOBTD/Explorer (a pentest tool)")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range extraHeaders {
		lower := strings.ToLower(k)
		if lower == "host" || lower == "content-length" || lower == "content-type" {
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	hdrs := make(map[string]string, len(req.Header))
	for k, vs := range req.Header {
		if len(vs) > 0 {
			hdrs[k] = vs[0]
		}
	}
	return resp, body, hdrs, nil
}

// storeAsTraffic persists an Explorer-initiated request/response as a traffic
// entry so the analyzer's relevance scorer + LLM loop pick it up naturally.
func (e *ExplorerAgent) storeAsTraffic(rawURL, method string, resp *http.Response, body []byte, reqHeaders map[string]string, reqBody []byte, sourceActionID int64, hypothesisID string) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return
	}
	respHeaders := make(map[string]string, len(resp.Header))
	for k, vs := range resp.Header {
		if len(vs) > 0 {
			respHeaders[k] = vs[0]
		}
	}
	if reqHeaders == nil {
		reqHeaders = map[string]string{}
	}

	entry := &types.TrafficEntry{
		Request: types.CapturedRequest{
			Method:  method,
			URL:     rawURL,
			Host:    parsed.Host,
			Path:    parsed.Path,
			Query:   parsed.RawQuery,
			Headers: reqHeaders,
			Body:    reqBody,
		},
		Response: types.CapturedResponse{
			StatusCode: resp.StatusCode,
			Headers:    respHeaders,
			Body:       body,
		},
		EndpointHash:   proxy.ComputeEndpointHash(method, rawURL),
		SourceAgent:    "explorer",
		SourceActionID: sourceActionID,
		HypothesisID:   hypothesisID,
		Timestamp:      time.Now(),
	}
	if _, err := e.db.InsertTraffic(e.scanID, entry); err != nil {
		e.logger.Debug("failed to persist explorer traffic", "error", err)
	}
}

func injectQueryParam(rawURL, param, value string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := parsed.Query()
	q.Set(param, value)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

func shortenURL(u string) string {
	if len(u) <= 60 {
		return u
	}
	return u[:57] + "..."
}

func shortenReason(r string) string {
	r = strings.TrimSpace(r)
	if r == "" {
		return "no reason given"
	}
	if len(r) > 80 {
		return r[:77] + "..."
	}
	return r
}

// escapePathSegmentPayload normalizes a caller-supplied path payload before
// encoding it as one URL segment. Analyzer/Strategist tasks may already carry
// URL-encoded IDs or probes (for example "%3Ciframe%3E"); escaping those again
// mutates the test into "%253Ciframe%253E". Decode once when possible, then
// escape exactly once for safe substitution into a {id} path segment.
func escapePathSegmentPayload(value string) string {
	if strings.Contains(value, "%") {
		if decoded, err := url.PathUnescape(value); err == nil && decoded != "" {
			value = decoded
		}
	}
	return url.PathEscape(value)
}

// resolveAgainstTarget takes a relative URL ("/api/users" or "api/users")
// and joins it against the scan's target URL. Returns "" if we can't
// resolve — caller falls back to the original input.
//
// This is a band-aid for LLM-emitted directives that drop the host. The
// proper fix is to teach the Strategist prompt to always emit absolute
// URLs, but the band-aid keeps probes from dying at the HTTP client with
// "unsupported protocol scheme" while we refine the prompt.
func (e *ExplorerAgent) resolveAgainstTarget(rawPath string) string {
	var target string
	if err := e.db.Conn().QueryRow(
		`SELECT target FROM scans WHERE id = ?`, e.scanID).Scan(&target); err != nil {
		return ""
	}
	base, err := url.Parse(target)
	if err != nil || base.Scheme == "" {
		return ""
	}
	// Accept "/api/x", "api/x", "//host/x" — all get normalized via url.Parse.
	ref, err := url.Parse(rawPath)
	if err != nil {
		return ""
	}
	return base.ResolveReference(ref).String()
}

// ── Session replay helpers ──
//
// Pentesting auth-gated endpoints requires replaying captured session
// headers. Without these, Explorer probes against /api/orders/:id or
// /rest/basket hit an unauth-redirect and look like "not vulnerable" when
// really we never actually tested the authenticated flow. The MITM proxy
// already captured the browser's real session cookies + bearer tokens
// during Phase: Authentication — we just need to reuse them.

// authHeadersForURL returns a small set of auth-style headers (Cookie,
// Authorization, X-Auth-Token, etc.) from captured traffic suitable for
// replaying rawURL. It prefers an exact URL match, then falls back to the
// best same-origin credential headers. Empty map if no prior capture.
func (e *ExplorerAgent) authHeadersForURL(rawURL string) map[string]string {
	if rawURL == "" {
		return nil
	}
	var headersJSON string
	err := e.db.Conn().QueryRow(`
		SELECT request_headers
		FROM traffic
		WHERE scan_id = ? AND url = ? AND is_filtered = FALSE
		ORDER BY id DESC
		LIMIT 1`, e.scanID, rawURL).Scan(&headersJSON)
	if err != nil || headersJSON == "" {
		headers, _, bestErr := e.db.BestCredentialHeaders(e.scanID, rawURL)
		if bestErr != nil || len(headers) == 0 {
			return nil
		}
		return headers
	}
	headers := pickAuthHeaders(headersJSON)
	if len(headers) > 0 {
		return headers
	}
	fallback, _, bestErr := e.db.BestCredentialHeaders(e.scanID, rawURL)
	if bestErr != nil || len(fallback) == 0 {
		return nil
	}
	return fallback
}

// authHeadersForTemplate looks up auth headers for a URL template with
// {id} substitution. Tries the first substituted value first (likely the
// original id the analyzer observed); falls back to pattern-matching via
// LIKE on the fixed prefix+suffix of the template.
func (e *ExplorerAgent) authHeadersForTemplate(template string, values []string) map[string]string {
	// Fast path: try the first value, which is usually the id we actually
	// saw during capture.
	for _, v := range values {
		if v != "" {
			u := strings.ReplaceAll(template, "{id}", escapePathSegmentPayload(v))
			if h := e.authHeadersForURL(u); h != nil {
				return h
			}
			break
		}
	}
	// Slow path: LIKE-match the template pattern. "https://x.com/orders/{id}"
	// becomes "https://x.com/orders/%". Any captured URL with that prefix
	// + the suffix after {id} will do.
	idx := strings.Index(template, "{id}")
	if idx < 0 {
		return nil
	}
	prefix := template[:idx]
	suffix := template[idx+len("{id}"):]
	var headersJSON string
	err := e.db.Conn().QueryRow(`
		SELECT request_headers
		FROM traffic
		WHERE scan_id = ?
		  AND url LIKE ? || '%' || ?
		  AND is_filtered = FALSE
		ORDER BY id DESC
		LIMIT 1`, e.scanID, prefix, suffix).Scan(&headersJSON)
	if err != nil || headersJSON == "" {
		return nil
	}
	return pickAuthHeaders(headersJSON)
}

// pickAuthHeaders decodes the captured request_headers JSON and returns
// only auth/session-carrying headers. We intentionally DON'T copy User-Agent,
// Accept, etc. — those are set fresh on each Explorer request.
func pickAuthHeaders(headersJSON string) map[string]string {
	var all map[string]string
	if err := json.Unmarshal([]byte(headersJSON), &all); err != nil || len(all) == 0 {
		return nil
	}
	out := map[string]string{}
	// Explicit allowlist of session-carrying headers. Case-insensitive match
	// against the captured set.
	wanted := map[string]bool{
		"cookie":              true,
		"authorization":       true,
		"x-auth-token":        true,
		"x-api-key":           true,
		"x-csrf-token":        true, // Explorer replays the original CSRF token — won't break CSRF-protected probe targets
		"x-xsrf-token":        true,
		"x-session-token":     true,
		"x-access-token":      true,
		"bearer":              true,
		"proxy-authorization": true,
	}
	for k, v := range all {
		if wanted[strings.ToLower(k)] {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
