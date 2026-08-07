package browser

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/ozzyw/aobtd/internal/observation"
)

// CrawlResult holds discovered data from a single page visit.
type CrawlResult struct {
	URL            string
	Links          []string   // discovered href links
	Forms          []FormInfo // discovered forms
	Scripts        []string   // JS src URLs
	StatusCode     int
	ScreenshotPath string // path to screenshot file (empty if template already captured)
	TemplateHash   string // DOM template fingerprint
}

// FormInfo describes a discovered HTML form.
type FormInfo struct {
	Action string      `json:"action"`
	Method string      `json:"method"`
	Inputs []InputInfo `json:"inputs,omitempty"`
	// ScreenshotPath is a web-relative path (e.g. "/screenshots/prompts/
	// login-abcd1234.png") to a rendered image of the form element. Only
	// populated for login-ish forms — i.e. forms that carry a password
	// input — so the interactive login prompt can show the operator what
	// they're about to sign into. Empty for other forms and whenever the
	// screenshot capture fails (e.g. detached / invisible element).
	ScreenshotPath string `json:"screenshot_path,omitempty"`
}

// InputInfo describes an input field within a form.
type InputInfo struct {
	Name     string `json:"name,omitempty"`
	Type     string `json:"type"` // text, password, email, file, hidden, etc.
	Value    string `json:"value,omitempty"`
	Required bool   `json:"required,omitempty"`
	// Selector is populated for live navigator page state. Crawl-time form
	// extraction may leave it empty because crawlers do not execute actions.
	Selector string `json:"selector,omitempty"`
}

// Crawler performs BFS crawling through a target site.
type Crawler struct {
	controller *Controller
	logger     *slog.Logger
	scope      []string // allowed hostnames
	maxDepth   int
	maxPages   int
	timeout    time.Duration

	mu       sync.Mutex
	visited  map[string]bool
	queued   map[string]bool
	queue    []crawlItem
	results  []CrawlResult
	callback func(CrawlResult) // called for each page visited
	// visitPageFn is an internal test seam for exercising the scheduler without
	// launching Chrome. Production crawls leave it nil and use visitPage.
	visitPageFn func(context.Context, string) (CrawlResult, error)
	// maxConcurrency bounds simultaneous browser tabs. Results are processed in
	// BFS order after each batch so callbacks and saturation remain deterministic.
	maxConcurrency int

	// Template detection — stop crawling pages that look the same
	patternHits    map[string]int // URL pattern -> times seen
	templateHits   map[string]int // DOM fingerprint -> times seen
	maxSamePattern int            // max pages per URL pattern before skipping

	// Shape-based saturation: bucket URLs by structural "shape" and the DOM
	// fingerprints they produce. When N+ URLs of the same shape have all
	// returned the same fingerprint, we mark the shape as saturated and skip
	// further URLs of that shape without even visiting them.
	shapeVisits        map[string][]string // shape -> list of DOM fingerprints observed
	shapeSaturated     map[string]bool     // shape -> true once the saturation test trips
	shapeExamples      map[string][]string // shape -> up to 5 example URLs we visited
	shapeTriggered     map[string]bool     // shape -> callback already fired
	saturationCallback func(SaturationEvent)
	minShapeSamples    int // minimum shape visits before we evaluate saturation
	// shapeSkipsSinceSample counts skips per saturated shape. Every N skips
	// we let one URL through as a sanity check — the classifier can then
	// confirm the saturation still holds or signal us to re-open the shape.
	shapeSkipsSinceSample map[string]int

	// Screenshots
	outputDir     string          // directory for screenshot PNGs
	screenshotted map[string]bool // template hash -> already captured

	// SPA mode — set once any page on this crawl presents Angular / React /
	// Nuxt / Vue markers. Tells the link extractor to be far more
	// conservative since SPA routes are client-side and URL-crawling
	// generally re-visits the same index.html. LLM-Guided Navigation picks
	// up from here.
	spaDetected bool

	// Adaptive convergence is opt-in. UI-launched "no page cap" scans use it
	// to stop after the observed surface stops changing, while CLI callers can
	// leave it disabled for a truly unlimited crawl.
	adaptiveEnabled         bool
	adaptiveMinPages        int
	adaptiveStagnationPages int
	adaptiveMaxDuration     time.Duration
	adaptiveStartedAt       time.Time
	adaptiveStalePages      int
	adaptiveSeenShapes      map[string]bool
	adaptiveSeenTemplates   map[string]bool
	adaptiveSeenForms       map[string]bool
	adaptiveStopReason      string
}

// SaturationEvent fires the first time a URL shape saturates. The agent layer
// turns this into a human-readable narration in the Live view.
type SaturationEvent struct {
	Shape    string   // e.g. "WORD" for /swarovski, /derimod, ...
	Examples []string // up to 5 URLs that led us to conclude
	Count    int      // number of visits that triggered the saturation
}

// sampleEveryNSkips controls how often a saturated shape gets a "peek" —
// every Nth would-be-skipped URL is instead visited as a sanity check so
// the classifier can confirm the cluster hasn't drifted. Low enough that
// shape drift is caught within a few dozen URLs, high enough that
// saturation still saves real work on big sites.
const sampleEveryNSkips = 25

type crawlItem struct {
	url   string
	depth int
}

// NewCrawler creates a BFS crawler scoped to the given hostnames.
func NewCrawler(ctrl *Controller, scope []string, maxDepth, maxPages int, timeout time.Duration, outputDir string, logger *slog.Logger) *Crawler {
	return &Crawler{
		controller:            ctrl,
		logger:                logger,
		scope:                 scope,
		maxDepth:              maxDepth,
		maxPages:              maxPages,
		timeout:               timeout,
		visited:               make(map[string]bool),
		queued:                make(map[string]bool),
		patternHits:           make(map[string]int),
		templateHits:          make(map[string]int),
		maxSamePattern:        3,
		shapeVisits:           make(map[string][]string),
		shapeSaturated:        make(map[string]bool),
		shapeExamples:         make(map[string][]string),
		shapeTriggered:        make(map[string]bool),
		shapeSkipsSinceSample: make(map[string]int),
		minShapeSamples:       5,
		maxConcurrency:        3,
		outputDir:             outputDir,
		screenshotted:         make(map[string]bool),
		adaptiveSeenShapes:    make(map[string]bool),
		adaptiveSeenTemplates: make(map[string]bool),
		adaptiveSeenForms:     make(map[string]bool),
	}
}

// EnableAdaptiveConvergence turns an otherwise unbounded crawl into a
// novelty-bounded one. A zero maxDuration keeps only the novelty rule.
func (c *Crawler) EnableAdaptiveConvergence(maxDuration time.Duration, minPages, stagnationPages int) {
	if minPages < 1 {
		minPages = 20
	}
	if stagnationPages < 1 {
		stagnationPages = 12
	}
	c.mu.Lock()
	c.adaptiveEnabled = true
	c.adaptiveMaxDuration = maxDuration
	c.adaptiveMinPages = minPages
	c.adaptiveStagnationPages = stagnationPages
	c.mu.Unlock()
}

// AdaptiveStopReason explains a graceful novelty/time convergence stop.
func (c *Crawler) AdaptiveStopReason() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.adaptiveStopReason
}

// OnResult sets a callback for each crawled page.
func (c *Crawler) OnResult(fn func(CrawlResult)) {
	c.callback = fn
}

// OnSaturation sets a callback fired the first time a URL shape is marked
// saturated. Agents use it to emit a "thought" narration.
func (c *Crawler) OnSaturation(fn func(SaturationEvent)) {
	c.saturationCallback = fn
}

// Crawl starts BFS crawling from the given URL. Blocks until done or ctx cancelled.
func (c *Crawler) Crawl(ctx context.Context, startURL string) ([]CrawlResult, error) {
	endProvenance := c.controller.BeginTrafficProvenance("crawler", 0, "")
	defer endProvenance()

	start := normalizeURL(startURL)
	c.mu.Lock()
	c.adaptiveStartedAt = time.Now()
	c.mu.Unlock()
	c.queue = append(c.queue, crawlItem{url: start, depth: 0})
	c.queued[start] = true
	parallelism := c.maxConcurrency
	if parallelism < 1 {
		parallelism = 1
	}
	type crawlWork struct {
		item  crawlItem
		shape string
	}
	type crawlOutcome struct {
		index  int
		work   crawlWork
		result CrawlResult
		err    error
	}

crawlLoop:
	for len(c.queue) > 0 {
		select {
		case <-ctx.Done():
			return c.results, ctx.Err()
		default:
		}
		if c.maxPages > 0 && len(c.results) >= c.maxPages {
			break crawlLoop
		}
		if c.adaptiveTimeLimitReached() {
			break crawlLoop
		}

		batch := make([]crawlWork, 0, parallelism)
		for len(c.queue) > 0 && len(batch) < parallelism {
			if c.maxPages > 0 && len(c.results)+len(batch) >= c.maxPages {
				break
			}
			item := c.queue[0]
			c.queue = c.queue[1:]
			delete(c.queued, item.url)
			if c.isVisited(item.url) || item.depth > c.maxDepth || !c.inScope(item.url) || !shouldCrawlURL(item.url) {
				continue
			}

			shape := urlShape(item.url)
			c.mu.Lock()
			saturatedAlready := c.shapeSaturated[shape]
			skipsSince := c.shapeSkipsSinceSample[shape]
			c.mu.Unlock()
			sampleForReCheck := saturatedAlready && skipsSince >= sampleEveryNSkips
			if saturatedAlready && !IsInterestingPath(item.url) && !sampleForReCheck {
				c.mu.Lock()
				c.shapeSkipsSinceSample[shape]++
				c.mu.Unlock()
				continue
			}
			if sampleForReCheck {
				c.mu.Lock()
				c.shapeSkipsSinceSample[shape] = 0
				c.mu.Unlock()
			}

			urlPattern := normalizeURLPattern(item.url)
			c.mu.Lock()
			c.patternHits[urlPattern]++
			c.mu.Unlock()
			c.markVisited(item.url)
			batch = append(batch, crawlWork{item: item, shape: shape})
		}
		if len(batch) == 0 {
			continue
		}

		outcomeCh := make(chan crawlOutcome, len(batch))
		visit := c.visitPage
		if c.visitPageFn != nil {
			visit = c.visitPageFn
		}
		for index, work := range batch {
			go func(index int, work crawlWork) {
				result, err := visit(ctx, work.item.url)
				outcomeCh <- crawlOutcome{index: index, work: work, result: result, err: err}
			}(index, work)
		}
		outcomes := make([]crawlOutcome, len(batch))
		for range batch {
			outcome := <-outcomeCh
			outcomes[outcome.index] = outcome
		}

		adaptiveStop := false
		for _, outcome := range outcomes {
			if outcome.err != nil {
				c.logger.Warn("crawl error", "url", outcome.work.item.url, "error", outcome.err)
				continue
			}
			result := outcome.result
			c.mu.Lock()
			c.results = append(c.results, result)
			total := len(c.results)
			c.mu.Unlock()
			if c.callback != nil {
				c.callback(result)
			}
			c.recordShapeVisit(outcome.work.shape, outcome.work.item.url, result.TemplateHash)
			if c.observeAdaptiveNovelty(result, outcome.work.shape) {
				adaptiveStop = true
			}
			c.logger.Info("crawled page", "url", outcome.work.item.url,
				"links", len(result.Links), "forms", len(result.Forms),
				"depth", outcome.work.item.depth, "total", total)

			for _, link := range result.Links {
				normalized := normalizeURL(link)
				if normalized == "" || c.isVisited(normalized) || c.queued[normalized] || !c.inScope(normalized) || !shouldCrawlURL(normalized) {
					continue
				}
				if !IsInterestingPath(normalized) {
					linkShape := urlShape(normalized)
					c.mu.Lock()
					linkSaturated := c.shapeSaturated[linkShape]
					c.mu.Unlock()
					if linkSaturated {
						continue
					}
				}
				c.queued[normalized] = true
				c.queue = append(c.queue, crawlItem{url: normalized, depth: outcome.work.item.depth + 1})
			}
		}
		if adaptiveStop {
			break crawlLoop
		}
	}

	c.logger.Info("crawl complete", "pages_visited", len(c.results))
	return c.results, nil
}

// observeAdaptiveNovelty returns true after a sufficiently broad sample has
// produced no new page/link shapes, response templates, or form actions for
// the configured number of consecutive pages.
func (c *Crawler) observeAdaptiveNovelty(result CrawlResult, pageShape string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.adaptiveEnabled {
		return false
	}
	novel := false
	remember := func(seen map[string]bool, key string) {
		key = strings.TrimSpace(key)
		if key != "" && !seen[key] {
			seen[key] = true
			novel = true
		}
	}
	remember(c.adaptiveSeenShapes, pageShape)
	remember(c.adaptiveSeenTemplates, result.TemplateHash)
	for _, form := range result.Forms {
		remember(c.adaptiveSeenForms, strings.ToUpper(strings.TrimSpace(form.Method))+" "+strings.TrimSpace(form.Action))
	}
	for _, link := range result.Links {
		remember(c.adaptiveSeenShapes, urlShape(link))
	}
	if novel {
		c.adaptiveStalePages = 0
	} else {
		c.adaptiveStalePages++
	}
	if len(c.results) < c.adaptiveMinPages || c.adaptiveStalePages < c.adaptiveStagnationPages {
		return false
	}
	c.adaptiveStopReason = fmt.Sprintf("surface converged after %d pages: the last %d pages added no new route shape, response template, or form action", len(c.results), c.adaptiveStalePages)
	return true
}

func (c *Crawler) adaptiveTimeLimitReached() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.adaptiveEnabled || c.adaptiveMaxDuration <= 0 || c.adaptiveStartedAt.IsZero() || time.Since(c.adaptiveStartedAt) < c.adaptiveMaxDuration {
		return false
	}
	c.adaptiveStopReason = fmt.Sprintf("adaptive crawl time limit reached after %s", c.adaptiveMaxDuration.Round(time.Second))
	return true
}

// Visited returns the number of pages visited so far.
func (c *Crawler) Visited() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.results)
}

func (c *Crawler) visitPage(ctx context.Context, targetURL string) (result CrawlResult, err error) {
	result = CrawlResult{URL: targetURL}
	var page *rod.Page
	finishAction := c.controller.beginTrafficAction("navigate", "crawl page", "", targetURL)
	defer func() {
		finalURL := result.URL
		if page != nil {
			if info, infoErr := page.Info(); infoErr == nil && info.URL != "" {
				finalURL = info.URL
			}
		}
		finishAction(err, finalURL)
	}()

	// Recover from panics in Rod/page operations
	defer func() {
		if r := recover(); r != nil {
			c.logger.Warn("page visit panic recovered", "url", targetURL, "panic", r)
			err = fmt.Errorf("panic: %v", r)
		}
	}()

	// Check context before starting
	if ctx.Err() != nil {
		return result, ctx.Err()
	}

	// Per-visit overall budget. WaitLoad has its own c.timeout, but the
	// follow-up operations (Screenshot, Eval, page.Has, Elements, …) have
	// NO timeout of their own — they inherit whatever the page handle
	// carries. A stuck page on a big site (bWAPP's login.php waiting for
	// Chrome's password-leak-check to settle, SPAs with rogue long-poll
	// fetches, etc.) would otherwise hang the crawler indefinitely.
	//
	// Budget: 3× WaitLoad timeout — enough slack for the screenshot +
	// DOM-fingerprint + link/form extraction rounds on slow pages,
	// still tight enough to keep BFS moving on hostile targets.
	visitTimeout := 3 * c.timeout
	if visitTimeout < 30*time.Second {
		visitTimeout = 30 * time.Second
	}
	visitCtx, visitCancel := context.WithTimeout(ctx, visitTimeout)
	defer visitCancel()

	page, err = c.controller.browser.Context(visitCtx).Page(proto.TargetCreateTarget{URL: targetURL})
	if err != nil {
		return result, fmt.Errorf("create page: %w", err)
	}
	// All subsequent operations through `page` inherit visitCtx — once
	// the budget blows they return errors instead of blocking forever.
	page = page.Context(visitCtx)
	defer page.Close()
	// Publish the target immediately, then take one bounded last-chance frame
	// before page.Close. Both are event-driven: there is no per-page sleep, and
	// the capture session rate-limits pixels while always retaining URL/action
	// metadata for tabs shorter than its periodic sampling interval.
	c.controller.AnnounceLiveBrowserPage(page, targetURL, "crawl_navigate")
	defer func() {
		fallbackURL := result.URL
		if strings.TrimSpace(fallbackURL) == "" {
			fallbackURL = targetURL
		}
		c.controller.ObserveLiveBrowserPage(page, fallbackURL, "crawl_last_seen")
	}()

	// Wait for page load with timeout — use a goroutine so we can respect ctx cancellation
	loadDone := make(chan error, 1)
	go func() {
		loadDone <- page.Timeout(c.timeout).WaitLoad()
	}()
	select {
	case <-visitCtx.Done():
		c.logger.Warn("page-visit budget exhausted during load — skipping page",
			"url", targetURL, "budget", visitTimeout)
		return result, visitCtx.Err()
	case err := <-loadDone:
		if err != nil {
			c.logger.Debug("page load slow", "url", targetURL, "err", err)
		}
	}

	// Give client-rendered pages a short settling window without imposing a
	// fixed delay on pages whose DOM is already stable.
	if err := page.Timeout(750*time.Millisecond).WaitDOMStable(150*time.Millisecond, 0.02); err != nil {
		c.logger.Debug("DOM did not settle before extraction", "url", targetURL, "err", err)
	}
	if visitCtx.Err() != nil {
		c.logger.Warn("page-visit budget exhausted post-load — skipping", "url", targetURL)
		return result, visitCtx.Err()
	}

	// Off-scope landing check. The URL we queued (e.g. /redirect?to=github.com)
	// can navigate the browser somewhere off-domain via 30x, meta-refresh,
	// or JS. If we then extract links from github.com we pollute the BFS
	// queue with off-target URLs and burn page-budget on irrelevant content.
	// Compare actual landed URL's host against scope; on mismatch, log and
	// return without link/form extraction so the off-domain DOM is ignored.
	if info, infoErr := page.Info(); infoErr == nil && info != nil && info.URL != "" {
		landed := info.URL
		if !c.inScope(landed) {
			c.logger.Info("off-scope landing — discarding extracted content",
				"queued_url", targetURL,
				"landed_url", landed,
				"hint", "open redirect or off-domain navigation; not enqueueing landed page's links")
			result.URL = landed
			return result, nil
		}
	}

	// Check DOM fingerprint — if we've seen this template too many times, skip deep extraction
	fp := c.domFingerprint(page)
	result.TemplateHash = fp

	// Detect SPA markers on every visit; first detection flips a flag so
	// subsequent link extraction is aggressively capped. The app-root /
	// data-reactroot / etc. selectors are cheap — no network I/O.
	c.mu.Lock()
	spaDetected := c.spaDetected
	c.mu.Unlock()
	if !spaDetected {
		if c.detectSPAMarkers(page) {
			c.mu.Lock()
			firstDetection := !c.spaDetected
			c.spaDetected = true
			c.mu.Unlock()
			if firstDetection {
				c.logger.Info("SPA markers detected — reducing URL-based crawl aggressiveness",
					"url", targetURL)
			}
		}
	}

	templateCount := 0
	shouldCaptureScreenshot := false
	if fp != "" {
		c.mu.Lock()
		c.templateHits[fp]++
		templateCount = c.templateHits[fp]
		if !c.screenshotted[fp] && c.outputDir != "" {
			// Reserve the fingerprint before doing I/O so concurrent visits do
			// not write duplicate screenshots for the same template.
			c.screenshotted[fp] = true
			shouldCaptureScreenshot = true
		}
		c.mu.Unlock()
	}

	// Take screenshot for first occurrence of each template
	if shouldCaptureScreenshot {
		ssPath := c.captureScreenshot(page, fp)
		if ssPath != "" {
			result.ScreenshotPath = ssPath
		} else {
			// Allow a later visit to retry if this page became detached or the
			// capture otherwise failed.
			c.mu.Lock()
			delete(c.screenshotted, fp)
			c.mu.Unlock()
		}
	}

	if templateCount > c.maxSamePattern+2 {
		fpShort := fp
		if len(fpShort) > 12 {
			fpShort = fpShort[:12]
		}
		c.logger.Info("template saturated, skipping link extraction",
			"url", targetURL,
			"fingerprint", fpShort,
			"seen", templateCount,
		)
		return result, nil // return without extracting links to stop spreading
	}

	// Extract links
	result.Links = c.extractLinks(page, targetURL)

	// Extract forms
	result.Forms = c.extractForms(page)

	// Extract script sources
	result.Scripts = c.extractScripts(page)

	return result, nil
}

// maxLinksPerPage caps how many links we harvest from a single page.
// Rationale: well-designed pages typically have 20-60 navigational links.
// Pages that expose 300+ links are almost always marketplaces with product
// grids, or pages that embed a third-party widget (GitHub repo-funding,
// social-sharing banners, etc.) that links outward into nonsense paths.
// The Juice Shop preview at preview.owasp-juice.shop returned 310 links
// from the Angular SPA's embedded sponsors widget, every one of which
// produced the same DOM template when visited — saturation worked, but not
// before we'd queued and briefly visited ~60 dead ends.
//
// The cap is deliberately per-page, not per-domain. A 40-link navigational
// menu on every page of a big site is fine; a one-page 300-link dump is
// the failure mode we're killing.
const maxLinksPerPage = 60
const maxScriptDiscoveredLinksPerPage = 30
const maxJSONDiscoveredLinksPerPage = 60
const maxJSONDiscoveryDocumentBytes = 2 * 1024 * 1024
const maxSitemapDiscoveredLinksPerPage = 500

var (
	scriptAbsoluteURLRe  = regexp.MustCompile(`https?://[^\s"'<>\\)]+`)
	scriptQuotedPathRe   = regexp.MustCompile(`["'](/[^"'<>\\\s]+)["']`)
	sitemapLocRe         = regexp.MustCompile(`(?is)<loc>\s*([^<]+?)\s*</loc>`)
	sitemapAbsoluteURLRe = regexp.MustCompile(`https?://[^\s<>"']+`)
)

// spaMarkerSelectors are DOM selectors that strongly indicate a Single
// Page Application. When any of these is present on the first page we
// visit, we know URL-based crawling will mostly produce the same DOM
// template; we shift budget toward the Navigator instead of chasing every
// <a href>.
var spaMarkerSelectors = []string{
	"app-root",         // Angular
	"[ng-version]",     // Angular (detected version attribute)
	"[data-reactroot]", // React
	"#__next",          // Next.js
	"#root",            // React (common convention)
	"[data-n-head]",    // Nuxt.js
	"#__nuxt",          // Nuxt
	"[data-vue-meta]",  // Vue
}

func (c *Crawler) extractLinks(page *rod.Page, baseURL string) []string {
	var links []string
	seen := make(map[string]bool)

	elements, err := page.Elements("a[href]")
	if err != nil {
		return links
	}

	base, _ := url.Parse(baseURL)

	for _, el := range elements {
		href, err := el.Attribute("href")
		if err != nil || href == nil || *href == "" {
			continue
		}

		resolved := resolveURL(base, *href)
		if resolved == "" || seen[resolved] {
			continue
		}

		// Skip non-HTTP links
		if strings.HasPrefix(resolved, "javascript:") ||
			strings.HasPrefix(resolved, "mailto:") ||
			strings.HasPrefix(resolved, "tel:") ||
			strings.HasPrefix(resolved, "#") ||
			strings.HasPrefix(resolved, "data:") {
			continue
		}

		seen[resolved] = true
		links = append(links, resolved)
		// Hard cap before we even return to the caller so noisy pages
		// can't blow up the BFS queue. Sites with real pagination will
		// still find their other pages via subsequent crawls — the cap
		// hurts a marketplace's crawl depth but not its coverage.
		//
		// SPAs get a tighter cap because their navigation links mostly
		// resolve to the same index.html anyway; the Navigator agent is
		// the right tool for exploring SPA routes.
		cap := maxLinksPerPage
		c.mu.Lock()
		isSPA := c.spaDetected
		c.mu.Unlock()
		if isSPA {
			cap = 15
		}
		if len(links) >= cap {
			c.logger.Info("link extraction capped",
				"url", baseURL,
				"cap", cap,
				"spa_mode", isSPA,
				"hint", "page returned more links than the per-page cap; remaining skipped")
			break
		}
	}

	if len(links) < maxLinksPerPage {
		scriptLinks := c.extractInlineScriptLinks(page, baseURL, seen, maxScriptDiscoveredLinksPerPage)
		links = append(links, scriptLinks...)
	}
	if len(links) < maxLinksPerPage {
		jsonLimit := maxJSONDiscoveredLinksPerPage
		if remaining := maxLinksPerPage - len(links); remaining > 0 && remaining < jsonLimit {
			jsonLimit = remaining
		}
		jsonLinks := c.extractJSONLinks(page, baseURL, seen, jsonLimit)
		links = append(links, jsonLinks...)
	}
	sitemapLinks := c.extractSitemapLinks(page, baseURL, seen, maxSitemapDiscoveredLinksPerPage)
	if len(sitemapLinks) > 0 {
		links = append(links, sitemapLinks...)
	}

	return links
}

func (c *Crawler) extractInlineScriptLinks(page *rod.Page, baseURL string, seen map[string]bool, limit int) []string {
	if limit <= 0 {
		return nil
	}
	js := `() => Array.from(document.scripts || [])
		.filter(s => !s.src)
		.map(s => s.textContent || '')
		.join('\n')`
	result, err := page.Timeout(1500 * time.Millisecond).Eval(js)
	if err != nil {
		c.logger.Debug("inline script URL extraction failed", "error", err)
		return nil
	}
	return extractScriptDiscoveredLinks(baseURL, result.Value.String(), seen, limit)
}

func (c *Crawler) extractSitemapLinks(page *rod.Page, baseURL string, seen map[string]bool, limit int) []string {
	if limit <= 0 {
		return nil
	}
	js := `() => {
		const root = document.documentElement;
		const body = document.body;
		return [
			root ? (root.outerHTML || '') : '',
			body ? (body.textContent || '') : ''
		].join('\n');
	}`
	result, err := page.Timeout(1500 * time.Millisecond).Eval(js)
	if err != nil {
		c.logger.Debug("sitemap URL extraction failed", "error", err)
		return nil
	}
	return extractSitemapDiscoveredLinks(baseURL, result.Value.String(), seen, limit)
}

func (c *Crawler) extractJSONLinks(page *rod.Page, baseURL string, seen map[string]bool, limit int) []string {
	if limit <= 0 {
		return nil
	}
	js := `() => document.body ? (document.body.textContent || '') : ''`
	result, err := page.Timeout(1500 * time.Millisecond).Eval(js)
	if err != nil {
		c.logger.Debug("JSON route extraction failed", "error", err)
		return nil
	}
	return extractJSONDiscoveredLinks(baseURL, result.Value.String(), seen, limit)
}

// ExtractDocumentDiscoveredLinks extracts high-signal routes from a seed
// document body. It is used outside the BFS crawler for pre-crawl seeds such as
// sitemap.xml, OpenAPI-ish JSON indexes, and benchmark route manifests.
func ExtractDocumentDiscoveredLinks(baseURL, documentHTML, bodyText string, limit int) []string {
	if limit <= 0 {
		return nil
	}
	seen := make(map[string]bool)
	var links []string
	addAll := func(values []string) {
		for _, value := range values {
			if len(links) >= limit {
				return
			}
			if value == "" || seen[value] {
				continue
			}
			seen[value] = true
			links = append(links, value)
		}
	}

	sitemapText := strings.TrimSpace(documentHTML + "\n" + bodyText)
	addAll(extractSitemapDiscoveredLinks(baseURL, sitemapText, nil, limit))
	if len(links) >= limit {
		return links
	}
	remaining := limit - len(links)
	addAll(extractJSONDiscoveredLinks(baseURL, bodyText, nil, remaining))
	if len(links) >= limit {
		return links
	}
	addAll(extractJSONDiscoveredLinks(baseURL, documentHTML, nil, limit-len(links)))
	return links
}

func extractScriptDiscoveredLinks(baseURL, scriptText string, seen map[string]bool, limit int) []string {
	if seen == nil {
		seen = make(map[string]bool)
	}
	base, _ := url.Parse(baseURL)
	var links []string
	add := func(raw string) {
		if len(links) >= limit {
			return
		}
		raw = strings.TrimSpace(strings.TrimRight(raw, ".,;"))
		if raw == "" {
			return
		}
		resolved := resolveURL(base, raw)
		if resolved == "" || seen[resolved] || !shouldCrawlURL(resolved) {
			return
		}
		seen[resolved] = true
		links = append(links, resolved)
	}

	for _, match := range scriptAbsoluteURLRe.FindAllString(scriptText, -1) {
		if !isInterestingScriptURL(match) {
			continue
		}
		add(match)
	}
	for _, match := range scriptQuotedPathRe.FindAllStringSubmatch(scriptText, -1) {
		if len(match) < 2 || !isInterestingScriptPath(match[1]) {
			continue
		}
		add(match[1])
	}
	return links
}

func extractJSONDiscoveredLinks(baseURL, documentText string, seen map[string]bool, limit int) []string {
	if limit <= 0 {
		return nil
	}
	decoded := strings.TrimSpace(html.UnescapeString(documentText))
	if decoded == "" || len(decoded) > maxJSONDiscoveryDocumentBytes {
		return nil
	}
	first := decoded[0]
	if first != '{' && first != '[' {
		return nil
	}

	var doc any
	if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
		return nil
	}

	base, err := url.Parse(baseURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil
	}
	if seen == nil {
		seen = make(map[string]bool)
	}

	var links []string
	add := func(raw, key string) {
		if len(links) >= limit {
			return
		}
		candidate, ok := normalizeJSONRouteCandidate(raw, key)
		if !ok {
			return
		}
		resolved := resolveURL(base, candidate)
		if resolved == "" {
			return
		}
		parsed, err := url.Parse(resolved)
		if err != nil || !sameOriginURL(base, parsed) {
			return
		}
		normalized := normalizeURL(resolved)
		if normalized == "" || seen[normalized] || !shouldCrawlURL(normalized) {
			return
		}
		seen[normalized] = true
		links = append(links, normalized)
	}

	var walk func(value any, parentKey string)
	walk = func(value any, parentKey string) {
		if len(links) >= limit {
			return
		}
		switch v := value.(type) {
		case map[string]any:
			for key, child := range v {
				walk(child, key)
				if len(links) >= limit {
					return
				}
			}
		case []any:
			for _, child := range v {
				walk(child, parentKey)
				if len(links) >= limit {
					return
				}
			}
		case string:
			if isJSONRouteKey(parentKey) {
				add(v, parentKey)
			}
		}
	}
	walk(doc, "")
	return links
}

func extractSitemapDiscoveredLinks(baseURL, documentText string, seen map[string]bool, limit int) []string {
	if limit <= 0 {
		return nil
	}
	decoded := html.UnescapeString(documentText)
	if !looksLikeSitemapDocument(baseURL, decoded) {
		return nil
	}
	if seen == nil {
		seen = make(map[string]bool)
	}
	base, _ := url.Parse(baseURL)
	var links []string
	add := func(raw string) {
		if len(links) >= limit {
			return
		}
		raw = strings.TrimSpace(strings.TrimRight(raw, ".,;"))
		if raw == "" {
			return
		}
		resolved := resolveURL(base, raw)
		if resolved == "" || seen[resolved] || !shouldCrawlURL(resolved) {
			return
		}
		seen[resolved] = true
		links = append(links, resolved)
	}

	locMatches := sitemapLocRe.FindAllStringSubmatch(decoded, limit)
	for _, match := range locMatches {
		if len(match) > 1 {
			add(match[1])
		}
	}
	if len(links) > 0 {
		return links
	}
	for _, match := range sitemapAbsoluteURLRe.FindAllString(decoded, limit) {
		add(match)
	}
	return links
}

func looksLikeSitemapDocument(baseURL, documentText string) bool {
	if parsed, err := url.Parse(baseURL); err == nil {
		name := strings.ToLower(path.Base(parsed.Path))
		if strings.Contains(name, "sitemap") && strings.HasSuffix(name, ".xml") {
			return true
		}
	}
	lower := strings.ToLower(documentText)
	return strings.Contains(lower, "<urlset") ||
		strings.Contains(lower, "<sitemapindex") ||
		strings.Contains(lower, "<loc>")
}

func isJSONRouteKey(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	key = strings.Trim(key, "_-. ")
	switch key {
	case "path", "paths", "url", "urls", "uri", "uris", "href", "hrefs",
		"link", "links", "endpoint", "endpoints", "route", "routes",
		"action", "actions", "api", "apis", "resource", "resources",
		"location", "locations", "redirect", "redirects", "target", "targets":
		return true
	default:
		return strings.HasSuffix(key, "url") ||
			strings.HasSuffix(key, "uri") ||
			strings.HasSuffix(key, "path") ||
			strings.HasSuffix(key, "href") ||
			strings.HasSuffix(key, "endpoint")
	}
}

func normalizeJSONRouteCandidate(raw, key string) (string, bool) {
	raw = strings.TrimSpace(html.UnescapeString(raw))
	raw = strings.TrimRight(raw, ".,;")
	if raw == "" || len(raw) > 2048 {
		return "", false
	}
	if strings.ContainsAny(raw, " \t\r\n<>\"'{}") {
		return "", false
	}
	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "javascript:") ||
		strings.HasPrefix(lower, "mailto:") ||
		strings.HasPrefix(lower, "tel:") ||
		strings.HasPrefix(lower, "data:") {
		return "", false
	}
	if strings.HasPrefix(lower, "http://") ||
		strings.HasPrefix(lower, "https://") ||
		strings.HasPrefix(raw, "//") ||
		strings.HasPrefix(raw, "/") ||
		strings.HasPrefix(raw, "./") ||
		strings.HasPrefix(raw, "../") ||
		strings.HasPrefix(raw, "#/") {
		return raw, true
	}
	if isJSONRouteKey(key) && strings.Contains(raw, "/") && !strings.Contains(raw, ":") && !strings.HasPrefix(raw, ".") {
		return "/" + strings.TrimLeft(raw, "/"), true
	}
	return "", false
}

func sameOriginURL(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

func isInterestingScriptPath(path string) bool {
	path = strings.ToLower(path)
	if strings.Contains(path, "/auth/logout") || strings.Contains(path, "/logout") {
		return false
	}
	if strings.Contains(path, "/api") || strings.Contains(path, "/graphql") ||
		strings.Contains(path, "/auth/login") || strings.Contains(path, "/login") ||
		strings.Contains(path, "/signin") || strings.Contains(path, "/sign-in") {
		return true
	}
	return false
}

func isInterestingScriptURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	lower := strings.ToLower(parsed.Hostname() + parsed.EscapedPath())
	if strings.Contains(lower, "logout") || strings.Contains(lower, "signout") {
		return false
	}
	return strings.Contains(lower, "api") ||
		strings.Contains(lower, "graphql") ||
		strings.Contains(lower, "bff") ||
		strings.Contains(lower, "-service") ||
		strings.Contains(lower, "/auth/login") ||
		strings.Contains(lower, "/login")
}

// detectSPAMarkers returns true if the page contains any DOM marker
// typical of a Single Page Application. Called once per crawled page; the
// caller may choose to short-circuit further URL-based crawling once the
// first SPA marker is seen — since SPA routing happens client-side, every
// path on the origin tends to return the same index.html and URL-crawling
// adds no signal over one visit plus a Navigator pass.
//
// IMPORTANT: uses page.Has, NOT page.Element. Rod's page.Element blocks
// until the selector matches or the page context deadline hits — on a
// non-SPA page, every selector would wait the full deadline, which meant
// bWAPP's login.php took ~45s to "detect no SPA markers." page.Has is a
// synchronous querySelector that returns immediately.
func (c *Crawler) detectSPAMarkers(page *rod.Page) bool {
	for _, sel := range spaMarkerSelectors {
		if has, _, _ := page.Has(sel); has {
			return true
		}
	}
	return false
}

func (c *Crawler) extractForms(page *rod.Page) []FormInfo {
	var forms []FormInfo

	formEls, err := page.Elements("form")
	if err != nil {
		return forms
	}

	pageURL := ""
	if info, err := page.Info(); err == nil && info != nil {
		pageURL = info.URL
	}

	for _, formEl := range formEls {
		fi := FormInfo{}

		if action, _ := formEl.Attribute("action"); action != nil {
			fi.Action = *action
		}
		if method, _ := formEl.Attribute("method"); method != nil {
			fi.Method = strings.ToUpper(*method)
		} else {
			fi.Method = "GET"
		}

		// Extract inputs within this form
		hasPassword := false
		inputs, err := formEl.Elements("input, textarea, select")
		if err == nil {
			for _, inp := range inputs {
				ii := InputInfo{}
				if name, _ := inp.Attribute("name"); name != nil {
					ii.Name = *name
				}
				if typ, _ := inp.Attribute("type"); typ != nil {
					ii.Type = strings.ToLower(*typ)
				} else {
					ii.Type = "text"
				}
				if val, _ := inp.Attribute("value"); val != nil {
					ii.Value = *val
				}
				if req, _ := inp.Attribute("required"); req != nil {
					ii.Required = true
				}
				if ii.Type == "password" {
					hasPassword = true
				}
				if ii.Name != "" {
					fi.Inputs = append(fi.Inputs, ii)
				}
			}
		}

		// Snapshot just the form element for the interactive-login prompt.
		// Only login-ish forms (those with a password input) get a picture
		// — no need to litter the screenshots dir with every search-box on
		// the internet. Failures are swallowed: the prompt still renders
		// fine without an image.
		if hasPassword && c.outputDir != "" {
			if p := c.captureFormScreenshot(formEl, pageURL, fi.Action); p != "" {
				fi.ScreenshotPath = p
			}
		}

		forms = append(forms, fi)
	}

	return forms
}

// captureFormScreenshot snapshots a single form element to PNG and returns
// the web-relative path that the UI uses to fetch it (served by the UI's
// /screenshots/ file server). Returns "" if the capture failed — the
// caller treats that as "no screenshot" and the modal renders without one.
//
// Filename is content-addressed (md5 of pageURL|action) so repeated
// crawls of the same login page overwrite the same file rather than
// spraying duplicates.
func (c *Crawler) captureFormScreenshot(el *rod.Element, pageURL, action string) string {
	ssDir := filepath.Join(c.outputDir, "screenshots", "prompts")
	if err := os.MkdirAll(ssDir, 0o755); err != nil {
		c.logger.Debug("prompts screenshot dir mkdir failed", "error", err)
		return ""
	}

	shot, err := el.Screenshot(proto.PageCaptureScreenshotFormatPng, 0)
	if err != nil {
		c.logger.Debug("form element screenshot failed", "error", err)
		return ""
	}

	hash := fmt.Sprintf("%x", md5.Sum([]byte(pageURL+"|"+action)))[:12]
	name := "login-" + hash + ".png"
	fullPath := filepath.Join(ssDir, name)
	if err := os.WriteFile(fullPath, shot, 0o644); err != nil {
		c.logger.Debug("save form screenshot failed", "error", err)
		return ""
	}
	c.logger.Info("login form screenshot captured", "path", fullPath, "bytes", len(shot))
	return "/screenshots/prompts/" + name
}

func (c *Crawler) extractScripts(page *rod.Page) []string {
	var scripts []string
	seen := make(map[string]bool)

	elements, err := page.Elements("script[src]")
	if err != nil {
		return scripts
	}

	for _, el := range elements {
		src, err := el.Attribute("src")
		if err != nil || src == nil || *src == "" {
			continue
		}
		if !seen[*src] {
			seen[*src] = true
			scripts = append(scripts, *src)
		}
	}

	return scripts
}

func (c *Crawler) isVisited(u string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.visited[u]
}

func (c *Crawler) markVisited(u string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.visited[u] = true
}

func (c *Crawler) inScope(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	host := strings.ToLower(parsed.Hostname())
	for _, allowed := range c.scope {
		if host == allowed || strings.HasSuffix(host, "."+allowed) {
			return true
		}
	}
	return false
}

// normalizeURL strips fragments and trailing slashes for dedup.
func normalizeURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	// Strip plain anchors (#section1) but PRESERVE hash routes (#/login,
	// #/score-board) — Angular/Vue/React-router hash mode encodes the
	// real navigation target there. Without this, every hash-route link
	// on an SPA collapses to the bare host and BFS visits exactly one page.
	if !isHashRoute(parsed.Fragment) {
		parsed.Fragment = ""
	}
	stripLowValueQueryParams(parsed)
	result := parsed.String()
	// Remove trailing slash for consistency (except root)
	if len(result) > 1 && strings.HasSuffix(result, "/") && parsed.Path != "/" {
		result = strings.TrimRight(result, "/")
	}
	return result
}

// isHashRoute returns true when a URL fragment looks like a client-side
// route rather than a plain in-page anchor. The contract is intentionally
// strict: the fragment must START with `/` (so `#/login`, `#/products/3`
// match — and `#section1`, `#top`, `#contact-form` don't). We deliberately
// don't try to be clever about hash-bang (`#!/foo`) or other dialects;
// when those show up we'll add them as concrete cases.
func isHashRoute(frag string) bool {
	return strings.HasPrefix(frag, "/")
}

// resolveURL resolves a potentially relative URL against a base. Hash-mode
// SPA routes (#/login, #/products/3) are preserved; plain in-page anchors
// (#section, #top) are stripped. See isHashRoute / normalizeURL.
func resolveURL(base *url.URL, href string) string {
	ref, err := url.Parse(href)
	if err != nil {
		return ""
	}
	resolved := base.ResolveReference(ref)
	if !isHashRoute(resolved.Fragment) {
		resolved.Fragment = ""
	}
	return resolved.String()
}

func shouldCrawlURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}
	if isBrowserTransportURL(parsed) || isInjectedProbeURL(parsed) {
		return false
	}
	if isWildcardTemplateURL(parsed) || isLogoutLikeURL(parsed) {
		return false
	}
	if isStaticCrawlResourceURL(parsed) {
		return false
	}
	return true
}

func isWildcardTemplateURL(parsed *url.URL) bool {
	if parsed == nil {
		return false
	}
	return strings.Contains(parsed.EscapedPath(), "*")
}

func isLogoutLikeURL(parsed *url.URL) bool {
	if parsed == nil {
		return false
	}
	for _, segment := range strings.Split(strings.ToLower(parsed.EscapedPath()), "/") {
		segment = strings.TrimSpace(segment)
		if idx := strings.IndexByte(segment, '.'); idx > 0 {
			segment = segment[:idx]
		}
		switch segment {
		case "logout", "log-out", "signout", "sign-out", "signed-out":
			return true
		}
	}
	return false
}

func stripLowValueQueryParams(parsed *url.URL) {
	if parsed == nil || parsed.RawQuery == "" {
		return
	}
	q := parsed.Query()
	changed := false
	for key := range q {
		lower := strings.ToLower(strings.TrimSpace(key))
		if strings.HasPrefix(lower, "utm_") {
			q.Del(key)
			changed = true
			continue
		}
		switch lower {
		case "fbclid", "gclid", "dclid", "msclkid", "mc_cid", "mc_eid", "_ga", "_gl":
			q.Del(key)
			changed = true
		}
	}
	if changed {
		parsed.RawQuery = q.Encode()
	}
}

func isBrowserTransportURL(parsed *url.URL) bool {
	if parsed == nil {
		return false
	}
	lowerPath := strings.ToLower(parsed.EscapedPath())
	if strings.Contains(lowerPath, "socket.io") {
		return true
	}
	q := parsed.Query()
	transport := strings.ToLower(q.Get("transport"))
	if q.Get("EIO") != "" && (transport == "polling" || transport == "websocket") {
		return true
	}
	if transport == "websocket" && q.Get("sid") != "" {
		return true
	}
	return false
}

func isInjectedProbeURL(parsed *url.URL) bool {
	if parsed == nil || parsed.RawQuery == "" {
		return false
	}
	decoded, err := url.QueryUnescape(parsed.RawQuery)
	if err != nil {
		decoded = parsed.RawQuery
	}
	lower := strings.ToLower(decoded)
	for _, marker := range []string{
		"<script", "<iframe", "<svg", "<img", "javascript:", "onerror=", "onload=",
		"aobtd_xss_", "aobtd-stored-xss", "alert(`xss`)", "alert('aobtd')",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func isStaticCrawlResourceURL(parsed *url.URL) bool {
	if parsed == nil {
		return false
	}
	lowerPath := strings.ToLower(parsed.EscapedPath())
	ext := strings.ToLower(path.Ext(parsed.Path))
	switch ext {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".svg", ".ico", ".bmp", ".tiff",
		".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".webm", ".mov", ".avi", ".mp3",
		".wav", ".ogg", ".css", ".js", ".mjs", ".map", ".wasm", ".pdf", ".doc", ".docx",
		".xls", ".xlsx", ".ppt", ".pptx", ".zip", ".tar", ".gz", ".rar", ".7z":
		return true
	}
	host := strings.ToLower(parsed.Hostname())
	mediaHost := strings.Contains(host, "cdn") || strings.Contains(host, "media") ||
		strings.Contains(host, "image") || strings.Contains(host, "asset")
	mediaPath := strings.Contains(lowerPath, "/is/image/") ||
		strings.Contains(lowerPath, "/image/") ||
		strings.Contains(lowerPath, "/images/") ||
		strings.Contains(lowerPath, "/img/") ||
		strings.Contains(lowerPath, "/media/") ||
		strings.Contains(lowerPath, "/video/") ||
		strings.Contains(lowerPath, "/assets/") ||
		strings.Contains(lowerPath, "/static/")
	if mediaHost && mediaPath {
		return true
	}
	q := parsed.Query()
	imageTransformQuery := q.Get("fmt") != "" || q.Get("wid") != "" || q.Get("hei") != "" ||
		q.Get("dpr") != "" || q.Get("size") != ""
	return mediaPath && imageTransformQuery
}

// captureScreenshot takes a PNG screenshot of the page.
func (c *Crawler) captureScreenshot(page *rod.Page, templateHash string) string {
	ssDir := filepath.Join(c.outputDir, "screenshots")
	os.MkdirAll(ssDir, 0o755)

	filename := fmt.Sprintf("%s.png", templateHash)
	ssPath := filepath.Join(ssDir, filename)

	data, err := page.Screenshot(true, nil)
	if err != nil {
		c.logger.Debug("screenshot failed", "error", err)
		return ""
	}

	if err := os.WriteFile(ssPath, data, 0o644); err != nil {
		c.logger.Debug("save screenshot failed", "error", err)
		return ""
	}

	hashShort := templateHash
	if len(hashShort) > 8 {
		hashShort = hashShort[:8]
	}
	c.logger.Info("screenshot captured", "template", hashShort, "path", ssPath)
	return filename // return just the filename, not full path
}

// normalizeURLPattern turns /products/nike-air-max-123 into /products/{slug}
// so we can group structurally identical pages.
func normalizeURLPattern(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	segments := strings.Split(parsed.Path, "/")
	for i, seg := range segments {
		switch {
		case isAllDigits(seg), rxUUID.MatchString(seg), rxMongoID.MatchString(seg), observation.IsOpaquePathSegment(seg):
			segments[i] = "{id}"
		// If a segment has 2+ dashes and is long, it's likely a product slug.
		case strings.Count(seg, "-") >= 2 && len(seg) > 15:
			segments[i] = "{slug}"
		}
	}

	return strings.Join(segments, "/")
}

// domFingerprint creates a structural hash of the page's DOM.
// Two pages with the same template but different data will have the same fingerprint.
func (c *Crawler) domFingerprint(page *rod.Page) string {
	// Extract structural elements: tag names + class names at depth 3
	js := `(() => {
		function fp(el, depth) {
			if (depth > 3 || !el || !el.tagName) return '';
			let s = el.tagName;
			if (el.className && typeof el.className === 'string') {
				s += '.' + el.className.split(' ').sort().join('.');
			}
			if (el.id) s += '#' + el.id;
			let children = Array.from(el.children || [])
				.slice(0, 10)
				.map(c => fp(c, depth + 1))
				.filter(x => x);
			if (children.length) s += '{' + children.join(',') + '}';
			return s;
		}
		return fp(document.body, 0);
	})()`

	result, err := page.Eval(js)
	if err != nil {
		return ""
	}

	raw := result.Value.String()
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	// Hash it — we don't need the full string, just a fingerprint
	hash := fmt.Sprintf("%x", md5.Sum([]byte(raw)))
	return hash
}

// UnmarkSaturated clears the saturation flag for a shape so future URLs of
// that shape get visited again. Called by the LLM classifier when it
// disagrees with the heuristic — e.g. "those look similar but some might be
// admin panels; don't skip."
func (c *Crawler) UnmarkSaturated(shape string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.shapeSaturated, shape)
	c.logger.Info("shape un-saturated by classifier", "shape", shape)
}

// recordShapeVisit logs a shape->fingerprint association. When N visits with
// the same shape have mostly converged on a single fingerprint, the shape is
// marked saturated and future URLs of that shape are skipped.
//
// We use "mostly" rather than "exactly" so a shape like WORD (single-slug
// pages) can saturate even if one of the early samples was /admin (different
// fingerprint) — the 4 following samples that all match would still saturate.
// Concretely: ≥ (minShapeSamples * 0.6) of the visits share a fingerprint.
func (c *Crawler) recordShapeVisit(shape, visitURL, fingerprint string) {
	if strings.TrimSpace(fingerprint) == "" || fingerprint == "unknown" {
		return
	}
	c.mu.Lock()
	c.shapeVisits[shape] = append(c.shapeVisits[shape], fingerprint)
	if len(c.shapeExamples[shape]) < 5 {
		c.shapeExamples[shape] = append(c.shapeExamples[shape], visitURL)
	}

	total := len(c.shapeVisits[shape])
	alreadySaturated := c.shapeSaturated[shape]
	alreadyFired := c.shapeTriggered[shape]

	var shouldSaturate bool
	var event SaturationEvent
	if !alreadySaturated && total >= c.minShapeSamples {
		// Count the most-common fingerprint in this shape's visit log.
		counts := make(map[string]int, total)
		for _, fp := range c.shapeVisits[shape] {
			counts[fp]++
		}
		var topFP string
		var topCount int
		for fp, n := range counts {
			if n > topCount {
				topFP = fp
				topCount = n
			}
		}
		_ = topFP

		// Require ≥ 60% convergence on a single fingerprint.
		if float64(topCount)/float64(total) >= 0.6 {
			c.shapeSaturated[shape] = true
			shouldSaturate = true
			examples := append([]string(nil), c.shapeExamples[shape]...)
			event = SaturationEvent{Shape: shape, Examples: examples, Count: total}
			c.shapeTriggered[shape] = true
		}
	}
	cb := c.saturationCallback
	c.mu.Unlock()

	if shouldSaturate && !alreadyFired && cb != nil {
		cb(event)
	}
}

// PatternStats returns the URL pattern hit counts for debugging.
func (c *Crawler) PatternStats() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	stats := make(map[string]int, len(c.patternHits))
	for k, v := range c.patternHits {
		stats[k] = v
	}
	return stats
}

// TemplateStats returns the DOM template hit counts for debugging.
func (c *Crawler) TemplateStats() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Return sorted by count descending
	stats := make(map[string]int, len(c.templateHits))
	type kv struct {
		k string
		v int
	}
	var sorted []kv
	for k, v := range c.templateHits {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].v > sorted[j].v })
	for _, item := range sorted {
		stats[item.k] = item.v
	}
	return stats
}
