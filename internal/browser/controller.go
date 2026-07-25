package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/ozzyw/aobtd/internal/observation"
)

// Controller manages a Rod-controlled browser instance.
type Controller struct {
	browser  *rod.Browser
	launcher *launcher.Launcher
	logger   *slog.Logger
	proxyURL string
	headless bool
	traffic  *observation.ProvenanceTracker

	// browserLifecycleMu serializes launch/relaunch/final shutdown. The runtime
	// mutex makes the Rod connection replaceable without racing frame capture,
	// which deliberately survives a transient Chrome process replacement.
	browserLifecycleMu sync.Mutex
	browserRuntimeMu   sync.RWMutex
	browserClosed      bool

	actionRecorderMu sync.RWMutex
	actionRecorder   TrafficActionRecorder

	liveInteractionMu sync.RWMutex
	liveInteractions  map[string]liveBrowserInteraction

	frameCaptureMu sync.RWMutex
	frameCapture   *FrameCaptureSession
}

type browserRuntime struct {
	browser  *rod.Browser
	launcher *launcher.Launcher
}

// TrafficActionCompletion persists the terminal action state.
type TrafficActionCompletion func(status, result, toURL string) error

// TrafficActionRecorder creates an action record before browser execution.
type TrafficActionRecorder func(sourceAgent, action, reason, fromURL, toURL, hypothesisID string) (int64, TrafficActionCompletion, error)

// NewController creates a browser controller that routes traffic through the given proxy.
func NewController(proxyAddr string, headless bool, logger *slog.Logger) *Controller {
	return &Controller{
		proxyURL: fmt.Sprintf("http://%s", proxyAddr),
		headless: headless,
		logger:   logger,
		traffic:  observation.NewProvenanceTracker(),
	}
}

// BeginTrafficProvenance attributes requests started by the current browser
// operation. The returned cleanup function is safe to call more than once.
func (c *Controller) BeginTrafficProvenance(sourceAgent string, sourceActionID int64, hypothesisID string) func() {
	if c == nil || c.traffic == nil {
		return func() {}
	}
	return c.traffic.Begin(observation.Provenance{
		SourceAgent:    sourceAgent,
		SourceActionID: sourceActionID,
		HypothesisID:   hypothesisID,
	})
}

// TrafficProvenance snapshots attribution for the proxy request boundary.
func (c *Controller) TrafficProvenance() observation.Provenance {
	if c == nil || c.traffic == nil {
		return observation.Provenance{}.Normalize()
	}
	return c.traffic.Snapshot()
}

// TrafficProvenanceForRequest resolves concurrent action scopes for the proxy.
func (c *Controller) TrafficProvenanceForRequest(requestURL, referer string) observation.Provenance {
	if c == nil || c.traffic == nil {
		return observation.Provenance{}.Normalize()
	}
	return c.traffic.SnapshotForRequest(requestURL, referer)
}

// SetTrafficActionRecorder wires persistent action storage into the browser.
func (c *Controller) SetTrafficActionRecorder(recorder TrafficActionRecorder) {
	if c == nil {
		return
	}
	c.actionRecorderMu.Lock()
	c.actionRecorder = recorder
	c.actionRecorderMu.Unlock()
}

func (c *Controller) beginTrafficAction(action, reason, fromURL, toURL string) func(error, string) {
	if c == nil || c.traffic == nil {
		return func(error, string) {}
	}
	provenance := c.traffic.AgentSnapshot()
	if provenance.SourceAgent == "capture" || provenance.SourceActionID != 0 {
		return func(error, string) {}
	}
	c.actionRecorderMu.RLock()
	recorder := c.actionRecorder
	c.actionRecorderMu.RUnlock()
	if recorder == nil {
		return func(error, string) {}
	}
	actionID, complete, err := recorder(
		provenance.SourceAgent, action, reason, fromURL, toURL, provenance.HypothesisID,
	)
	if err != nil || actionID == 0 {
		c.logger.Warn("begin traffic action failed", "agent", provenance.SourceAgent, "action", action, "error", err)
		return func(error, string) {}
	}
	end := c.traffic.BeginTargeted(observation.Provenance{
		SourceAgent:    provenance.SourceAgent,
		SourceActionID: actionID,
		HypothesisID:   provenance.HypothesisID,
	}, toURL)
	var once sync.Once
	return func(actionErr error, finalURL string) {
		once.Do(func() {
			end()
			if complete == nil {
				return
			}
			status, result := "succeeded", "completed"
			if actionErr != nil {
				status, result = "failed", actionErr.Error()
			}
			if err := complete(status, result, finalURL); err != nil {
				c.logger.Warn("complete traffic action failed", "id", actionID, "error", err)
			}
		})
	}
}

// Launch starts the browser process. The browser routes all traffic through the proxy.
func (c *Controller) Launch(ctx context.Context) error {
	c.browserLifecycleMu.Lock()
	defer c.browserLifecycleMu.Unlock()
	// An explicit Launch starts a new controller lifetime. Automatic NewPage
	// recovery uses ensureBrowser/relaunchBrowser and will never reopen a
	// controller after final Close.
	c.browserClosed = false
	if c.browserSnapshot() != nil {
		return nil
	}
	return c.launchBrowserLocked(ctx)
}

func (c *Controller) ensureBrowser(ctx context.Context) (*rod.Browser, error) {
	if browser := c.browserSnapshot(); browser != nil {
		return browser, nil
	}
	c.browserLifecycleMu.Lock()
	defer c.browserLifecycleMu.Unlock()
	if c.browserClosed {
		return nil, fmt.Errorf("browser controller is closed")
	}
	if browser := c.browserSnapshot(); browser != nil {
		return browser, nil
	}
	if err := c.launchBrowserLocked(ctx); err != nil {
		return nil, err
	}
	return c.browserSnapshot(), nil
}

// launchBrowserLocked creates and connects a complete runtime before publishing
// it. Callers must hold browserLifecycleMu. Frame capture therefore sees either
// the previous connection, no connection during replacement, or the fully
// connected replacement; it never observes a half-initialized Rod browser.
func (c *Controller) launchBrowserLocked(ctx context.Context) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	l := launcher.New().
		Leakless(false). // Disable leakless — Windows Defender flags it
		Set("proxy-server", c.proxyURL).
		// Chrome bypasses the proxy for localhost/loopback by default, which
		// means targets like http://localhost:3000 (a Docker Juice Shop,
		// dev-server app, etc.) send NO traffic through the MITM proxy and
		// the analyzer sees zero API calls. "<-loopback>" explicitly removes
		// loopback from the bypass list so we capture everything.
		Set("proxy-bypass-list", "<-loopback>").
		Set("ignore-certificate-errors"). // Trust MITM CA
		Set("disable-web-security").      // Allow cross-origin for analysis
		// The crawler intentionally keeps several tabs alive at once. Chromium
		// normally deprioritizes or stops painting background/occluded tabs,
		// which made Page.captureScreenshot return a perfectly valid but fully
		// white JPEG for the Live view. Keep every analysis tab renderable.
		Set("disable-backgrounding-occluded-windows").
		Set("disable-renderer-backgrounding").
		Set("disable-background-timer-throttling").
		Set("no-first-run").
		Set("no-default-browser-check")

	if c.headless {
		l = l.Headless(true)
	} else {
		l = l.Headless(false)
	}

	controlURL, err := l.Launch()
	if err != nil {
		return fmt.Errorf("launch browser: %w", err)
	}

	browser := rod.New().ControlURL(controlURL)
	if err := browser.Connect(); err != nil {
		l.Kill()
		return fmt.Errorf("connect to browser: %w", err)
	}
	c.publishBrowserRuntime(browserRuntime{browser: browser, launcher: l})

	c.logger.Info("browser launched", "proxy", c.proxyURL, "headless", c.headless)
	return nil
}

func (c *Controller) browserSnapshot() *rod.Browser {
	if c == nil {
		return nil
	}
	c.browserRuntimeMu.RLock()
	browser := c.browser
	c.browserRuntimeMu.RUnlock()
	return browser
}

func (c *Controller) publishBrowserRuntime(runtime browserRuntime) {
	c.browserRuntimeMu.Lock()
	c.browser = runtime.browser
	c.launcher = runtime.launcher
	c.browserRuntimeMu.Unlock()
}

// detachBrowserRuntime atomically makes a stale runtime invisible to frame
// capture. When expected is non-nil, a concurrently installed replacement is
// left untouched and returned as not detached.
func (c *Controller) detachBrowserRuntime(expected *rod.Browser) (browserRuntime, bool) {
	c.browserRuntimeMu.Lock()
	defer c.browserRuntimeMu.Unlock()
	if expected != nil && c.browser != expected {
		return browserRuntime{}, false
	}
	runtime := browserRuntime{browser: c.browser, launcher: c.launcher}
	c.browser = nil
	c.launcher = nil
	return runtime, runtime.browser != nil || runtime.launcher != nil
}

func shutdownBrowserRuntime(runtime browserRuntime) {
	// Preserve the original shutdown order: terminating the process first makes
	// the subsequent transport close bounded even when the websocket is stale.
	if runtime.launcher != nil {
		runtime.launcher.Kill()
	}
	if runtime.browser != nil {
		closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = runtime.browser.Context(closeCtx).Close()
	}
}

// Navigate opens a URL in a new page and returns the page handle.
func (c *Controller) Navigate(ctx context.Context, targetURL string) (page *rod.Page, err error) {
	finishAction := c.beginTrafficAction("navigate", "open browser page", "", targetURL)
	defer func() {
		finalURL := targetURL
		if page != nil {
			if info, infoErr := page.Info(); infoErr == nil && info.URL != "" {
				finalURL = info.URL
			}
		}
		finishAction(err, finalURL)
	}()

	page, err = c.NewPage(ctx, targetURL)
	if err != nil {
		return nil, fmt.Errorf("create page: %w", err)
	}

	if err := page.Timeout(15 * time.Second).WaitLoad(); err != nil {
		c.logger.Warn("page load timeout", "url", targetURL, "error", err)
	}
	// Capture is event-driven as well as periodic. This call is a no-op when
	// the scan has no active frame session, and is rate-limited by that session
	// when one exists.
	c.ObserveLiveBrowserPage(page, targetURL, "navigate_last_seen")

	c.logger.Info("navigated", "url", targetURL)
	return page, nil
}

// NewPage opens a browser tab, relaunching Chrome once when the Rod transport
// has gone stale during a long scan. This keeps later phases such as
// objective-led navigation from disappearing after an idle auth prompt or
// a transient browser disconnect.
func (c *Controller) NewPage(ctx context.Context, targetURL string) (*rod.Page, error) {
	return c.newPageWithReconnect(ctx, targetURL, openRodPage, c.relaunchBrowser)
}

type browserPageOpener func(context.Context, *rod.Browser, string) (*rod.Page, error)
type browserReconnect func(context.Context, *rod.Browser) error

func openRodPage(ctx context.Context, browser *rod.Browser, targetURL string) (*rod.Page, error) {
	if ctx != nil {
		browser = browser.Context(ctx)
	}
	return browser.Page(proto.TargetCreateTarget{URL: targetURL})
}

// newPageWithReconnect contains the retry policy separately from the Rod I/O,
// allowing the disconnect transition to be regression-tested without starting
// Chrome. There is exactly one retry, and only transport-closure failures are
// eligible; application/navigation failures remain untouched.
func (c *Controller) newPageWithReconnect(ctx context.Context, targetURL string, open browserPageOpener, reconnect browserReconnect) (*rod.Page, error) {
	browser := c.browserSnapshot()
	if browser == nil {
		var err error
		browser, err = c.ensureBrowser(ctx)
		if err != nil {
			return nil, err
		}
	}
	if browser == nil {
		return nil, fmt.Errorf("browser launch returned no connection")
	}
	page, err := open(ctx, browser, targetURL)
	if err == nil {
		c.AnnounceLiveBrowserPage(page, targetURL, "navigate")
		return page, nil
	}
	if !browserConnectionClosed(err) {
		return nil, err
	}
	c.logger.Warn("browser connection closed while opening page; relaunching", "url", targetURL, "error", err)
	if err := reconnect(ctx, browser); err != nil {
		return nil, fmt.Errorf("relaunch browser: %w", err)
	}
	browser = c.browserSnapshot()
	if browser == nil {
		return nil, fmt.Errorf("relaunch browser returned no connection")
	}
	page, err = open(ctx, browser, targetURL)
	if err == nil {
		c.AnnounceLiveBrowserPage(page, targetURL, "navigate")
	}
	return page, err
}

// relaunchBrowser replaces only Chrome/Rod runtime state. It intentionally
// does not call Close or StopFrameCapture: the capture session belongs to the
// scan, retains prior replay frames, and starts sampling the newly published
// browser automatically. Concurrent reconnect attempts collapse into one
// relaunch by comparing the failed browser pointer under the lifecycle lock.
func (c *Controller) relaunchBrowser(ctx context.Context, failedBrowser *rod.Browser) error {
	c.browserLifecycleMu.Lock()
	defer c.browserLifecycleMu.Unlock()
	if c.browserClosed {
		return fmt.Errorf("browser controller is closed")
	}

	current := c.browserSnapshot()
	if current != nil && current != failedBrowser {
		return nil // another caller already installed a healthy replacement
	}
	if runtime, detached := c.detachBrowserRuntime(failedBrowser); detached {
		shutdownBrowserRuntime(runtime)
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return c.launchBrowserLocked(ctx)
}

func browserConnectionClosed(err error) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "use of closed network connection") ||
		strings.Contains(lower, "websocket: close") ||
		strings.Contains(lower, "connection reset by peer") ||
		strings.Contains(lower, "broken pipe")
}

// Browser returns the underlying Rod browser for advanced operations.
func (c *Controller) Browser() *rod.Browser {
	return c.browserSnapshot()
}

// SetSessionCookies parses a raw cookie header value and applies each
// name=value pair to the browser's cookie jar scoped to the target URL's
// domain. Supports either a bare "name=value; name=value" string OR a
// header-style "Cookie: name=value; ..." form.
//
// Returns the number of cookies successfully applied.
func (c *Controller) SetSessionCookies(ctx context.Context, targetURL, rawCookie string) (int, error) {
	browser := c.browserSnapshot()
	if browser == nil {
		return 0, fmt.Errorf("browser not launched")
	}
	parsed, err := url.Parse(targetURL)
	if err != nil || parsed.Host == "" {
		return 0, fmt.Errorf("invalid target URL: %s", targetURL)
	}

	// Strip optional "Cookie:" header prefix
	raw := strings.TrimSpace(rawCookie)
	if idx := strings.IndexByte(raw, ':'); idx > 0 && strings.EqualFold(strings.TrimSpace(raw[:idx]), "Cookie") {
		raw = strings.TrimSpace(raw[idx+1:])
	}

	// Split pairs — same format browsers send on the wire
	var cookies []*proto.NetworkCookieParam
	domain := cookieDomainForTarget(parsed.Hostname())

	for _, pair := range strings.Split(raw, ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		eq := strings.IndexByte(pair, '=')
		if eq <= 0 {
			continue // skip malformed
		}
		name := strings.TrimSpace(pair[:eq])
		value := strings.TrimSpace(pair[eq+1:])
		if name == "" {
			continue
		}
		cookies = append(cookies, &proto.NetworkCookieParam{
			Name:   name,
			Value:  value,
			Domain: domain,
			Path:   "/",
			Secure: parsed.Scheme == "https",
		})
	}

	if len(cookies) == 0 {
		return 0, fmt.Errorf("no valid cookies parsed from input")
	}

	if err := browser.SetCookies(cookies); err != nil {
		return 0, fmt.Errorf("set cookies: %w", err)
	}
	return len(cookies), nil
}

func cookieDomainForTarget(hostname string) string {
	domain := strings.Trim(strings.ToLower(strings.TrimSpace(hostname)), ".")
	if domain == "" {
		return hostname
	}
	if net.ParseIP(domain) != nil || domain == "localhost" {
		return domain
	}
	// Also set cookies against the apex domain ("example.com") so they
	// apply to subdomains the crawler may traverse. Do not apply this to
	// literal IPs: splitting 127.0.0.1 into an "apex" of 0.1 stores cookies
	// for the wrong domain and silently breaks authenticated localhost scans.
	if parts := strings.Split(domain, "."); len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return domain
}

// SeedLocalStorage writes key/value pairs into localStorage and sessionStorage
// for the target origin. It opens a short-lived page on the target so the
// browser's storage partition is scoped exactly like the crawler's later tabs.
func (c *Controller) SeedLocalStorage(ctx context.Context, targetURL string, values map[string]string) error {
	if c.browserSnapshot() == nil {
		return fmt.Errorf("browser not launched")
	}
	if len(values) == 0 {
		return fmt.Errorf("no localStorage values provided")
	}
	parsed, err := url.Parse(targetURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("invalid target URL: %s", targetURL)
	}
	originURL := parsed.Scheme + "://" + parsed.Host + "/"
	page, err := c.Navigate(ctx, originURL)
	if err != nil {
		return err
	}
	defer page.Close()

	payload, _ := json.Marshal(values)
	js := fmt.Sprintf(`() => {
		const values = %s;
		for (const [key, value] of Object.entries(values)) {
			localStorage.setItem(key, String(value));
			sessionStorage.setItem(key, String(value));
		}
		return Object.keys(values).length;
	}`, string(payload))
	if _, err := page.Eval(js); err != nil {
		return fmt.Errorf("seed localStorage: %w", err)
	}
	return nil
}

// HardenSessionCookies re-applies every cookie currently in the browser's
// jar with an explicit Expires timestamp 1 day in the future. This
// converts any session cookies (no Max-Age / no Expires) into persistent
// ones, guaranteeing they survive page Close() / new-tab creation.
//
// Why this matters: Rod's auth flow closes the login page after a
// successful submit. In headless Chromium, closing the last page of a
// browser context can drop session cookies under some circumstances —
// observed on bWAPP's PHPSESSID, where the cookie was present on the
// login page but gone by the time the crawler opened its first tab.
// Hardening sidesteps the quirk entirely.
//
// Call this right after a successful auth submit, before the crawler
// starts opening pages.
func (c *Controller) HardenSessionCookies(ctx context.Context) (int, error) {
	browser := c.browserSnapshot()
	if browser == nil {
		return 0, fmt.Errorf("browser not launched")
	}
	cookies, err := browser.GetCookies()
	if err != nil {
		return 0, fmt.Errorf("get cookies: %w", err)
	}
	if len(cookies) == 0 {
		return 0, nil
	}
	// Re-apply each cookie with an explicit Expires 24h in the future.
	// Persistent flag gets flipped automatically by CDP when Expires is set.
	params := make([]*proto.NetworkCookieParam, 0, len(cookies))
	expiresAt := proto.TimeSinceEpoch(float64(time.Now().Add(24 * time.Hour).Unix()))
	hardened := 0
	for _, c := range cookies {
		// Skip already-persistent cookies — they're fine as is.
		if c.Expires > 0 {
			continue
		}
		params = append(params, &proto.NetworkCookieParam{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     c.Path,
			Secure:   c.Secure,
			HTTPOnly: c.HTTPOnly,
			SameSite: c.SameSite,
			Expires:  expiresAt,
		})
		hardened++
	}
	if hardened == 0 {
		return 0, nil
	}
	if err := browser.SetCookies(params); err != nil {
		return 0, fmt.Errorf("re-set cookies: %w", err)
	}
	return hardened, nil
}

// Close shuts down the browser process.
func (c *Controller) Close() error {
	// Cancel capture before detaching Chromium, but do not wait on its writer
	// until the runtime has been killed. A stale CDP enumeration must never
	// prevent the shutdown that unblocks it. Stop remains idempotent and writes
	// the terminal replay manifest after the browser is detached.
	session := c.currentFrameCapture()
	if session != nil {
		session.requestStop()
	}
	c.browserLifecycleMu.Lock()
	c.browserClosed = true
	if runtime, detached := c.detachBrowserRuntime(nil); detached {
		shutdownBrowserRuntime(runtime)
	}
	c.browserLifecycleMu.Unlock()
	if session != nil {
		session.Stop()
	}
	c.logger.Info("browser closed")
	return nil
}
