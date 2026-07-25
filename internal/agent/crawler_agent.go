package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/ozzyw/aobtd/internal/browser"
	"github.com/ozzyw/aobtd/internal/llm"
	"github.com/ozzyw/aobtd/internal/pathlabel"
	"github.com/ozzyw/aobtd/internal/policy"
	"github.com/ozzyw/aobtd/internal/proxy"
	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

// CrawlerAgent drives the browser to discover pages and endpoints.
type CrawlerAgent struct {
	crawler *browser.Crawler
	bus     *Bus
	state   *SharedState
	db      *store.DB
	scanID  int64
	logger  *slog.Logger

	// Optional LLM provider + budget — used to give shape-saturation events
	// a semantic label (e.g. "phone-category" instead of "/SLUG"). When nil
	// we fall back to the regex-based structural shape.
	provider llm.Provider
	budget   *llm.Budget

	// pathLabel is the shared resolver. The crawler routes saturation
	// narrations through it so the operator sees a labelled URL pattern
	// (`/us/iphone/{model}/{slug}`) instead of the bare structural shape
	// (`/us/WORD/WORD/WORD`). Cache + vocabulary are shared with the
	// analyzer so the same pattern is never labelled twice.
	pathLabel          pathlabel.Resolver
	semanticSaturation *SemanticSaturationState

	// seenForms tracks forms we've already narrated (method|action) to avoid spam
	// when the same form appears on every page (e.g., site-wide search/signup).
	seenForms map[string]bool

	// authAlreadyConfigured is set when the scan was launched with explicit
	// credentials (CLI flags or session cookie). When true, we skip the
	// login-prompt notification path — no point asking the user for creds
	// they've already provided.
	authAlreadyConfigured bool
	testingAuthority      policy.TestingAuthority

	// promptedLoginURLs de-dupes the "login form found" notification so
	// we don't spam the operator every time the same form recurs across
	// pages (e.g. a site-wide header login form).
	promptedLoginURLs map[string]bool
}

// SetAuthConfigured tells the crawler whether the scan was launched with
// credentials already in hand. Controls whether we surface login-form
// notifications.
func (a *CrawlerAgent) SetAuthConfigured(configured bool) {
	a.authAlreadyConfigured = configured
}

// SetTestingAuthority prevents passive Recon runs from offering an
// interactive credential workflow in the UI. The form remains mapped as
// evidence, but only Active/Full Control scans may invite a login attempt.
func (a *CrawlerAgent) SetTestingAuthority(authority policy.TestingAuthority) {
	a.testingAuthority = authority
}

func (a *CrawlerAgent) SetSemanticSaturation(state *SemanticSaturationState) {
	a.semanticSaturation = state
}

// NewCrawlerAgent creates a crawler agent.
func NewCrawlerAgent(
	ctrl *browser.Controller,
	bus *Bus,
	state *SharedState,
	db *store.DB,
	scanID int64,
	scope []string,
	maxDepth, maxPages int,
	outputDir string,
	provider llm.Provider,
	budget *llm.Budget,
	pathLabel pathlabel.Resolver,
	logger *slog.Logger,
) *CrawlerAgent {
	crawler := browser.NewCrawler(ctrl, scope, maxDepth, maxPages, 15*time.Second, outputDir, logger)

	return &CrawlerAgent{
		crawler:           crawler,
		bus:               bus,
		state:             state,
		db:                db,
		scanID:            scanID,
		logger:            logger,
		provider:          provider,
		budget:            budget,
		pathLabel:         pathLabel,
		testingAuthority:  policy.AuthorityActive,
		seenForms:         make(map[string]bool),
		promptedLoginURLs: make(map[string]bool),
	}
}

func (a *CrawlerAgent) Name() string { return "crawler" }

func (a *CrawlerAgent) Capabilities() []EventType {
	return []EventType{EventScanPhaseChanged}
}

// Start runs the crawler. It crawls the target and publishes discovered pages/endpoints.
func (a *CrawlerAgent) Start(ctx context.Context) error {
	target := a.state.ReadModel().Target

	// Seed the discovery graph with the scan's starting URL so it's never
	// orphaned when the provenance API looks it up.
	a.db.InsertDiscovery(a.scanID, store.Discovery{
		TargetURL: target,
		Kind:      store.DiscoverySeed,
		Detail:    "user-provided scan target",
	})

	// When the crawler decides a URL shape has saturated (N pages of the same
	// structural shape all returning the same template), surface it as a
	// human-readable narration. We label the pattern via the shared
	// pathlabel.Resolver — same cache the analyzer uses, so the same
	// pattern is never labelled twice across the whole scan.
	a.crawler.OnSaturation(func(ev browser.SaturationEvent) {
		// Immediate narration uses the structural shape — it fires before the
		// LLM call so the user sees *something* instantly. The async upgrade
		// below replaces this with the labelled version.
		shapeNarrationID, _ := a.db.InsertNarration(a.scanID, "crawler", "saturated",
			narrateSaturation(ev),
			"", map[string]any{
				"shape":    ev.Shape,
				"examples": ev.Examples,
				"count":    ev.Count,
			})
		a.logger.Info("shape saturated — skipping further URLs",
			"shape", ev.Shape, "count", ev.Count,
		)

		// Resolver-based label upgrade. Runs in the background so we
		// don't block the crawler. When it completes, the narration is
		// updated in place from "/us/WORD/WORD" to "/us/iphone/{model}".
		if a.pathLabel != nil && a.provider != nil &&
			a.budget != nil && a.budget.Level() != llm.BudgetExhausted {
			go a.upgradeSaturationNarration(ctx, ev, shapeNarrationID)
		}
	})

	a.crawler.OnResult(func(result browser.CrawlResult) {
		if a.semanticSaturation != nil {
			a.semanticSaturation.Observe(result.URL, "", result.TemplateHash, "crawler", result.StatusCode)
		}
		// Log the discovery
		detail := fmt.Sprintf("Found %d links, %d forms, %d scripts",
			len(result.Links), len(result.Forms), len(result.Scripts))
		a.db.LogAI(a.scanID, "crawler", "page_visited", detail, "", result.URL, "")

		// Narrate: what the crawler just saw
		a.db.InsertNarration(a.scanID, "crawler", "visit",
			narrateVisit(result.URL, len(result.Links), len(result.Forms), len(result.Scripts)),
			result.URL, map[string]any{
				"links": len(result.Links), "forms": len(result.Forms), "scripts": len(result.Scripts),
			})

		// Record every link as a discovery edge — this is our real provenance
		// source, independent of the unreliable Referer header. `result.URL`
		// is the page whose DOM we scraped; each entry in Links is a href
		// we pulled from that page.
		for _, link := range result.Links {
			a.db.InsertDiscovery(a.scanID, store.Discovery{
				TargetURL: link,
				SourceURL: result.URL,
				Kind:      store.DiscoveryHTMLLink,
			})
		}

		for _, form := range result.Forms {
			formDetail := fmt.Sprintf("Form: %s %s (%d inputs)", form.Method, form.Action, len(form.Inputs))
			a.db.LogAI(a.scanID, "crawler", "form_discovered", formDetail, result.URL, form.Action, "")

			// Form action is also a discovery — the page containing the form
			// led us to the endpoint the form POSTs to.
			if form.Action != "" && form.Action != "#" {
				a.db.InsertDiscovery(a.scanID, store.Discovery{
					TargetURL: resolveFormAction(result.URL, form.Action),
					SourceURL: result.URL,
					Kind:      store.DiscoveryFormAction,
					Detail:    fmt.Sprintf("%s form, %d input(s)", strings.ToUpper(form.Method), len(form.Inputs)),
				})
			}

			// Dedupe: same (method|action) form across pages — narrate once.
			key := strings.ToUpper(form.Method) + "|" + form.Action
			if a.seenForms[key] {
				continue
			}
			a.seenForms[key] = true

			target := form.Action
			if target == "" || target == "#" {
				target = "this page"
			}
			a.db.InsertNarration(a.scanID, "crawler", "form_found",
				fmt.Sprintf("Spotted a %s form submitting to %s with %d input(s) — queuing for analysis.",
					strings.ToUpper(form.Method), target, len(form.Inputs)),
				result.URL, nil)

			// Interactive-login notification: when we spot a form that
			// looks like a login (has a password-type input) AND the scan
			// wasn't launched with credentials, emit a prompt. The user
			// sees a notification bell, can click it, enter creds, and
			// the scanner's poll-loop picks those up and runs the login
			// inline. The scanner NEVER blocks — no creds provided means
			// we just keep scanning unauthenticated.
			if a.shouldSurfaceLoginPrompt() && a.looksLikeLoginForm(form) {
				submitURL := resolveFormAction(result.URL, form.Action)
				if !a.promptedLoginURLs[submitURL] {
					a.promptedLoginURLs[submitURL] = true
					a.emitLoginPrompt(result.URL, submitURL, form)
				}
			}
		}

		// Publish page crawled event
		a.bus.Publish(Event{
			Type:   EventPageCrawled,
			Source: a.Name(),
			Payload: PageCrawledPayload{
				URL:     result.URL,
				Links:   result.Links,
				Forms:   len(result.Forms),
				Scripts: len(result.Scripts),
			},
		})

		// Register discovered endpoints from forms
		for _, form := range result.Forms {
			actionURL := resolveFormAction(result.URL, form.Action)
			epHash := proxy.ComputeEndpointHash(form.Method, actionURL)

			hasFileUpload := false
			var params []types.Parameter
			for _, inp := range form.Inputs {
				if inp.Type == "file" {
					hasFileUpload = true
				}
				params = append(params, types.Parameter{
					Name:     inp.Name,
					Location: "body",
					Type:     inp.Type,
					Example:  inp.Value,
				})
			}

			ep := types.Endpoint{
				ID:         epHash,
				Method:     form.Method,
				URLPattern: actionURL,
				Parameters: params,
				HitCount:   1,
			}
			a.state.AddEndpoint(ep)

			a.bus.Publish(Event{
				Type:   EventEndpointDiscovered,
				Source: a.Name(),
				Payload: EndpointPayload{
					Method:     form.Method,
					URLPattern: actionURL,
					HasParams:  len(params) > 0,
					HasInput:   true,
					IsAPI:      false,
				},
			})

			_ = hasFileUpload // will be used in knowledge base
		}
	})

	a.logger.Info("crawler agent starting", "target", target)
	_, err := a.crawler.Crawl(ctx, target)
	if err != nil && ctx.Err() == nil {
		return err
	}

	a.logger.Info("crawler agent finished",
		"pages_visited", a.crawler.Visited(),
		"endpoints", a.state.EndpointCount(),
	)
	return nil
}

func (a *CrawlerAgent) shouldSurfaceLoginPrompt() bool {
	return !a.authAlreadyConfigured && a.testingAuthority != policy.AuthorityRecon
}

// shapeClassifyPrompt is the system prompt used to label a saturated URL shape.
// The crawler has already captured response bodies; we feed the LLM the URL,
// page title, and a body snippet for each example so it can decide based on
// actual content — not just URL structure.
const shapeClassifyPrompt = `You are a pentester watching an automated crawler decide whether to stop visiting more URLs of a given pattern. You will see a handful of example pages that share a structural URL shape: URL, <title>, and a snippet of the HTML body for each.

Your job is to judge, from the ACTUAL CONTENT (not just the URLs):
  1. Are these genuinely the same KIND of page (same template, same purpose)?
  2. Or does the set contain outliers that would be a mistake to skip — an auth/admin/API/settings page masquerading under the same URL shape as a bunch of boring product listings?

Give the pattern a SHORT kebab-case semantic label — the kind of page a pentester would name it. Examples: "phone-category", "brand-landing", "product-detail", "blog-post", "user-profile", "static-asset", "search-results", "mixed-content".

Also give a ONE-sentence first-person thought explaining what you actually observed in the snippets.

Output strict JSON, no prose outside:
{
  "label": "short-kebab-case-name",
  "reason": "first-person one-sentence thought grounded in what you saw in the snippets",
  "confirm_skip": true|false
}

"confirm_skip" MUST be false if ANY of the following is true:
  - The snippets are noticeably different kinds of pages (even just one outlier)
  - You see auth/login/admin UI in any snippet
  - The set looks like it spans more than one template (e.g., product pages AND a checkout page)
  - The titles suggest heterogeneous content
Otherwise true.`

// upgradeSaturationNarration is the new resolver-based path. It runs in
// the background after a saturation event, asks the shared
// pathlabel.Resolver to label the shape, and rewrites the original
// narration in place — same row id, no second narration to dedupe.
//
// The old `classifyAndNarrateShape` below is retained for its
// un-saturate behaviour (LLM disagrees with the heuristic → reopen
// the shape). Both run in parallel; the upgrade replaces the bare
// "/WORD/WORD" message with a labelled version like
// "/us/iphone/{model}/{slug}", and the classifier handles the
// reopen-the-bucket decision and emits its own analyzer "thought"
// narration.
func (a *CrawlerAgent) upgradeSaturationNarration(
	ctx context.Context,
	ev browser.SaturationEvent,
	narrationID int64,
) {
	defer func() {
		if r := recover(); r != nil {
			a.logger.Debug("saturation upgrade panic recovered", "err", r)
		}
	}()
	if len(ev.Examples) == 0 || narrationID == 0 || a.pathLabel == nil {
		return
	}
	// Strip query strings and host prefixes — the resolver works on
	// path-space. Keep up to 8 examples to give the LLM enough to
	// align positions without bloating the prompt.
	paths := make([]string, 0, len(ev.Examples))
	host := ""
	for _, ex := range ev.Examples {
		u, err := url.Parse(ex)
		if err != nil || u.Path == "" {
			continue
		}
		if host == "" {
			host = u.Host
		}
		paths = append(paths, u.Path)
		if len(paths) >= 8 {
			break
		}
	}
	if len(paths) == 0 {
		return
	}

	// Best-effort: pull a couple of titles from captured traffic so the
	// LLM sees what the pages actually contain. Reuses the sampler the
	// legacy classifier already had.
	titles := []string{}
	for _, s := range a.fetchShapeSamples(ev.Examples) {
		if s.Title != "" {
			titles = append(titles, s.Title)
		}
		if len(titles) >= 5 {
			break
		}
	}

	label := a.pathLabel.Label(ctx, paths, pathlabel.LabelContext{
		Host:       host,
		Method:     "GET",
		PageTitles: titles,
		Discovery:  "crawler-saturation",
	})
	if label.Display == "" {
		return
	}

	// Compose the upgraded message. Same shape as narrateSaturation
	// but with the labelled pattern in place of the bare shape.
	msg := fmt.Sprintf(
		"%d pages of pattern %s — %s. Skipping further URLs of this shape to save time.",
		ev.Count, label.Display, summaryFromLabel(label),
	)
	if label.Purpose != "" {
		msg = fmt.Sprintf("%d pages of %s (%s) — skipping further URLs of this shape.",
			ev.Count, label.Display, label.Purpose)
	}

	meta := map[string]any{
		"shape":    ev.Shape,
		"label":    label.Display,
		"purpose":  label.Purpose,
		"source":   string(label.Source),
		"examples": ev.Examples,
		"count":    ev.Count,
		"upgraded": true,
	}
	if err := a.db.UpdateNarrationMessage(narrationID, msg, meta); err != nil {
		a.logger.Debug("saturation narration upgrade failed",
			"narration_id", narrationID, "error", err)
		return
	}
	a.logger.Info("saturation narration upgraded",
		"shape", ev.Shape, "label", label.Display, "source", label.Source,
	)
}

// summaryFromLabel produces a short clause describing the labelled
// pattern, used to pad out the upgrade message when no Purpose was
// provided. Falls back to listing the variable position labels.
func summaryFromLabel(l pathlabel.Label) string {
	if l.Purpose != "" {
		return l.Purpose
	}
	var vars []string
	for _, s := range l.Segments {
		if s.Kind == "variable" {
			vars = append(vars, s.Label)
		}
	}
	if len(vars) == 0 {
		return "structurally identical pages"
	}
	if len(vars) == 1 {
		return fmt.Sprintf("varies by %s", vars[0])
	}
	return fmt.Sprintf("varies by %s", strings.Join(vars, ", "))
}

// classifyAndNarrateShape makes a single LLM call to label a saturated shape
// semantically, then emits a follow-up narration with the friendly label.
// Runs in a goroutine from the saturation callback so it never blocks crawling.
func (a *CrawlerAgent) classifyAndNarrateShape(ctx context.Context, ev browser.SaturationEvent) {
	// Defensive: never panic from a stray parse
	defer func() {
		if r := recover(); r != nil {
			a.logger.Debug("shape classify panic recovered", "err", r)
		}
	}()

	if len(ev.Examples) == 0 {
		return
	}

	// Pull actual page content (title + body snippet) for each example URL
	// so the classifier can judge based on what the pages ACTUALLY contain,
	// not just their paths.
	samples := a.fetchShapeSamples(ev.Examples)

	var sb strings.Builder
	fmt.Fprintf(&sb, "The crawler has saturated URL shape \"%s\" after %d visits.\n\nHere are the pages it saw:\n\n", ev.Shape, ev.Count)
	for _, s := range samples {
		fmt.Fprintf(&sb, "URL: %s\nTitle: %s\nSnippet:\n%s\n---\n", s.URL, s.Title, s.Snippet)
	}
	sb.WriteString("\nClassify this pattern based on the actual content above.")
	userPrompt := sb.String()

	estTokens := a.provider.CountTokens(shapeClassifyPrompt + userPrompt)
	if !a.budget.CanSpend(estTokens) {
		return
	}

	req := &llm.Request{
		SystemPrompt: shapeClassifyPrompt,
		Messages:     []llm.Message{{Role: "user", Content: userPrompt}},
		Temperature:  0.1,
		MaxTokens:    256,
		JSONMode:     true,
	}
	resp, err := llm.CompleteBudgeted(ctx, a.provider, a.budget, req, estTokens)
	if err != nil || resp == nil {
		a.logger.Debug("shape classify failed", "error", err)
		return
	}
	// Log the cost + tokens for this tiny call.
	modelID := llm.ResponseModel(resp, a.provider)
	costU := llm.CostMicroCents(modelID, resp.Usage)
	a.db.LogAIFull(a.scanID, "crawler", "classify_shape",
		ev.Shape, "", "", "",
		resp.Usage.InputTokens, resp.Usage.OutputTokens, 0, costU, modelID,
		llm.RenderPrompt(req), resp.Content)

	// Parse the classifier's reply
	var parsed struct {
		Label       string `json:"label"`
		Reason      string `json:"reason"`
		ConfirmSkip bool   `json:"confirm_skip"`
	}
	if err := json.Unmarshal([]byte(resp.Content), &parsed); err != nil {
		// Try extracting JSON from mixed output
		cleaned := extractJSON(resp.Content)
		if cleaned != resp.Content {
			_ = json.Unmarshal([]byte(cleaned), &parsed)
		}
	}
	if parsed.Label == "" {
		return
	}

	// If the LLM disagrees with the heuristic ("wait, these might differ"),
	// un-saturate the shape so the crawler resumes following it.
	if !parsed.ConfirmSkip {
		a.crawler.UnmarkSaturated(ev.Shape)
		a.db.InsertNarration(a.scanID, "analyzer", "thought",
			fmt.Sprintf("{%s} — actually, %s. Keeping this shape open.",
				parsed.Label, strOrDefault(parsed.Reason, "these might actually differ")),
			"", map[string]any{
				"shape": ev.Shape, "label": parsed.Label, "resumed": true,
			})
		a.logger.Info("saturation reversed by LLM classifier", "shape", ev.Shape)
		return
	}

	// Otherwise confirm the skip with the semantic label.
	msg := parsed.Reason
	if msg == "" {
		msg = fmt.Sprintf("These look like %s pages — skipping further ones of this type.", parsed.Label)
	}
	metadata := map[string]any{
		"shape":        ev.Shape,
		"label":        parsed.Label,
		"examples":     ev.Examples,
		"confirm_skip": parsed.ConfirmSkip,
	}
	a.db.InsertNarration(a.scanID, "analyzer", "thought",
		fmt.Sprintf("{%s} — %s", parsed.Label, msg),
		"", metadata)
}

func strOrDefault(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// narrateSaturation crafts a first-person thought explaining why we're
// giving up on further URLs of a given shape.
func narrateSaturation(ev browser.SaturationEvent) string {
	// Show up to 3 example paths, shortened to their pathname.
	var shortPaths []string
	for i, ex := range ev.Examples {
		if i >= 3 {
			break
		}
		if u, err := url.Parse(ex); err == nil && u.Path != "" {
			shortPaths = append(shortPaths, u.Path)
		} else {
			shortPaths = append(shortPaths, ex)
		}
	}
	examples := strings.Join(shortPaths, ", ")

	switch {
	case ev.Shape == "/WORD":
		return fmt.Sprintf("I've crawled %d single-slug pages (%s...) — they're all returning the same template. Looks like category/brand landing pages. Skipping further /{word} URLs.", ev.Count, examples)
	case strings.HasPrefix(ev.Shape, "/WORD/INT"), strings.HasPrefix(ev.Shape, "/WORD/MONGO"), strings.HasPrefix(ev.Shape, "/WORD/UUID"):
		return fmt.Sprintf("%d pages of shape '%s' and they all look structurally identical (%s...) — likely a detail-page template. I've seen enough, skipping the rest.", ev.Count, ev.Shape, examples)
	case strings.Contains(ev.Shape, "FILE."):
		return fmt.Sprintf("%d static assets matching shape '%s' — nothing to learn from more of these. Skipping.", ev.Count, ev.Shape)
	default:
		return fmt.Sprintf("%d URLs matching shape '%s' all return the same template (%s...). Skipping further URLs of this shape to save time.", ev.Count, ev.Shape, examples)
	}
}

// narrateVisit crafts a human-friendly description of a page visit.
func narrateVisit(pageURL string, links, forms, scripts int) string {
	shortURL := pageURL
	if u, err := url.Parse(pageURL); err == nil && u.Path != "" {
		shortURL = u.Path
		if u.RawQuery != "" {
			shortURL += "?" + u.RawQuery
		}
	}

	switch {
	case forms > 0 && links > 10:
		return fmt.Sprintf("Landed on %s — lots going on here: %d links and %d form(s). Worth a closer look.", shortURL, links, forms)
	case forms > 0:
		return fmt.Sprintf("Landed on %s — has %d form(s), those are interesting for input testing.", shortURL, forms)
	case links > 20:
		return fmt.Sprintf("Visiting %s — heavy navigation hub with %d links branching out.", shortURL, links)
	case links == 0 && forms == 0:
		return fmt.Sprintf("Fetched %s — dead-end page, no new links or forms to follow.", shortURL)
	default:
		return fmt.Sprintf("Visiting %s — %d link(s) discovered, mapping the path forward.", shortURL, links)
	}
}

func resolveFormAction(pageURL, action string) string {
	if action == "" || action == "#" {
		return pageURL
	}
	base, err := url.Parse(pageURL)
	if err != nil {
		return action
	}
	ref, err := url.Parse(action)
	if err != nil {
		return action
	}
	resolved := base.ResolveReference(ref)
	return strings.TrimRight(resolved.String(), "/")
}

// shapeSample is a compact summary of a single example URL: URL + page
// title + a snippet of the response body. Used to ground the LLM shape
// classifier in real content.
type shapeSample struct {
	URL     string
	Title   string
	Snippet string
}

// fetchShapeSamples pulls title + body snippet for each URL from the traffic
// table so we can ship them to the classifier. We LIMIT the snippet so the
// prompt stays bounded.
func (a *CrawlerAgent) fetchShapeSamples(urls []string) []shapeSample {
	const snippetLen = 600
	var out []shapeSample
	for _, u := range urls {
		if len(out) >= 5 {
			break // cap total prompt size
		}
		var body []byte
		err := a.db.Conn().QueryRow(`
			SELECT response_body FROM traffic_resolved
			WHERE url = ? AND is_filtered = FALSE
			ORDER BY id DESC LIMIT 1`, u).Scan(&body)
		if err != nil {
			// Fall back: URL only
			out = append(out, shapeSample{URL: u, Title: "(no content captured)", Snippet: ""})
			continue
		}
		title := extractHTMLTitle(body)
		snippet := extractHTMLSnippet(body, snippetLen)
		out = append(out, shapeSample{URL: u, Title: title, Snippet: snippet})
	}
	return out
}

// extractHTMLTitle returns the contents of the first <title>...</title> tag.
func extractHTMLTitle(body []byte) string {
	s := string(body)
	lower := strings.ToLower(s)
	i := strings.Index(lower, "<title")
	if i < 0 {
		return ""
	}
	gt := strings.Index(s[i:], ">")
	if gt < 0 {
		return ""
	}
	start := i + gt + 1
	end := strings.Index(lower[start:], "</title>")
	if end < 0 {
		return ""
	}
	title := strings.TrimSpace(s[start : start+end])
	if len(title) > 160 {
		title = title[:160] + "..."
	}
	return title
}

// extractHTMLSnippet strips basic tags and returns the first N chars of
// visible-ish text. Good enough for grounding an LLM.
func extractHTMLSnippet(body []byte, maxLen int) string {
	s := string(body)
	for _, tag := range []string{"script", "style", "noscript"} {
		s = stripBlock(s, tag)
	}
	var b strings.Builder
	inTag := false
	lastSpace := false
	for _, r := range s {
		if r == '<' {
			inTag = true
			continue
		}
		if r == '>' {
			inTag = false
			continue
		}
		if inTag {
			continue
		}
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			if !lastSpace {
				b.WriteByte(' ')
				lastSpace = true
			}
			continue
		}
		lastSpace = false
		b.WriteRune(r)
		if b.Len() >= maxLen {
			break
		}
	}
	snippet := strings.TrimSpace(b.String())
	if len(snippet) > maxLen {
		snippet = snippet[:maxLen]
	}
	return snippet
}

// stripBlock removes all <tag>...</tag> blocks (case-insensitive).
func stripBlock(s, tag string) string {
	lower := strings.ToLower(s)
	openMarker := "<" + tag
	closeMarker := "</" + tag + ">"
	var out strings.Builder
	i := 0
	for i < len(s) {
		start := strings.Index(lower[i:], openMarker)
		if start < 0 {
			out.WriteString(s[i:])
			break
		}
		out.WriteString(s[i : i+start])
		end := strings.Index(lower[i+start:], closeMarker)
		if end < 0 {
			break
		}
		i += start + end + len(closeMarker)
	}
	return out.String()
}

// looksLikeLoginForm returns true when the form looks like a credential-
// entering one: at least one `password` input, and at least one text-like
// input (username / email / handle). Keeps the false-positive rate low —
// we don't want to pester the operator about search boxes.
func (a *CrawlerAgent) looksLikeLoginForm(form browser.FormInfo) bool {
	hasPassword := false
	hasText := false
	for _, in := range form.Inputs {
		t := strings.ToLower(in.Type)
		if t == "password" {
			hasPassword = true
		}
		if t == "text" || t == "email" || t == "tel" || t == "" {
			hasText = true
		}
	}
	return hasPassword && hasText
}

// emitLoginPrompt inserts a `login_found` prompt into the DB and writes
// a matching narration so the Live feed has a trail too. The payload
// carries enough detail for the UI modal to render an inline login form
// without another round-trip.
func (a *CrawlerAgent) emitLoginPrompt(pageURL, submitURL string, form browser.FormInfo) {
	var userField, passField string
	for _, in := range form.Inputs {
		t := strings.ToLower(in.Type)
		if t == "password" && passField == "" {
			passField = in.Name
		}
		if (t == "text" || t == "email" || t == "") && userField == "" && in.Name != "" {
			userField = in.Name
		}
	}

	payload := map[string]any{
		"page_url":   pageURL,
		"submit_url": submitURL,
		"method":     strings.ToUpper(form.Method),
		"user_field": userField,
		"pass_field": passField,
		// Full inputs so the UI can render every field if user wants to edit.
		"inputs": form.Inputs,
		// Screenshot of the form element captured at extraction time,
		// surfaced as a web path the UI can drop into an <img src>. Empty
		// when capture failed or the crawler's outputDir was unset.
		"screenshot_url": form.ScreenshotPath,
	}
	id, err := a.db.InsertPrompt(a.scanID, "login_found", payload)
	if err != nil {
		a.logger.Warn("failed to emit login-found prompt", "error", err)
		return
	}
	a.logger.Info("login-form notification emitted",
		"prompt_id", id, "submit_url", submitURL)

	// Parallel narration so the Live feed tells the same story.
	a.db.InsertNarration(a.scanID, "crawler", "login_found",
		fmt.Sprintf("Found a login form at %s. Click the notification bell to log in — I'll keep scanning unauthenticated in the meantime.", pageURL),
		pageURL, map[string]any{"prompt_id": id, "submit_url": submitURL})
}
