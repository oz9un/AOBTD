package browser

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-rod/rod"
)

// NavigatorAction is the LLM's decision about what to do next.
type NavigatorAction struct {
	Action   string `json:"action"`   // click, fill, navigate, submit, scroll, done, ask_human
	Selector string `json:"selector"` // CSS selector for click/fill/submit
	Value    string `json:"value"`    // text for fill
	URL      string `json:"url"`      // URL for navigate
	Reason   string `json:"reason"`   // why this action
	Question string `json:"question"` // question for ask_human
}

// PageState captures the current state of a page for LLM context.
type PageState struct {
	URL         string       `json:"url"`
	Title       string       `json:"title"`
	Forms       []FormInfo   `json:"forms,omitempty"`
	Links       []LinkInfo   `json:"links,omitempty"`
	Buttons     []ButtonInfo `json:"buttons,omitempty"`
	Inputs      []InputInfo  `json:"inputs,omitempty"`
	VisibleText string       `json:"visible_text,omitempty"`
}

// LinkInfo describes a link on the page.
type LinkInfo struct {
	Text string `json:"text"`
	Href string `json:"href"`
}

// ButtonInfo describes a clickable button.
type ButtonInfo struct {
	Text     string `json:"text"`
	Selector string `json:"selector"`
	Type     string `json:"type"` // submit, button, etc.
}

// Navigator uses LLM decisions to drive browser actions.
type Navigator struct {
	controller *Controller
	logger     *slog.Logger
	timeout    time.Duration
}

// NewNavigator creates a new LLM-driven navigator.
//
// timeout leaves enough room for a hydrated SPA to accept an action, while
// bounding bad model-selected selectors. A 15s timeout made three guessed
// selectors consume almost a minute without discovering any surface.
// targets is dominated by hydration, not network — the LLM picks #navbarAccount
// the moment Angular renders the chrome, but its (click) handler isn't bound
// until the bootstrap module finishes a few hundred ms later. A 10s budget
// was tight enough to fail 3-in-a-row on juice-shop and tripped the
// consecutive-failure stopper. WaitInteractable in PageAction does the
// real waiting; this is just the upper bound.
func NewNavigator(ctrl *Controller, logger *slog.Logger) *Navigator {
	return &Navigator{
		controller: ctrl,
		logger:     logger,
		timeout:    8 * time.Second,
	}
}

// CapturePageState extracts the current page state for LLM context.
func (n *Navigator) CapturePageState(page *rod.Page) (*PageState, error) {
	state := &PageState{}

	// URL and title
	info, err := page.Info()
	if err == nil {
		state.URL = info.URL
		state.Title = info.Title
	}

	// Extract forms
	state.Forms = extractFormsFromPage(page)

	// Extract links (top 30)
	// Capture a wider raw inventory, then let NavigatorAgent apply scope and
	// semantic ranking before it enters an LLM prompt. DOM-order truncation at
	// 30 hid product/topic/detail links behind long category menus.
	state.Links = n.extractLinks(page, 120)

	// Extract buttons
	state.Buttons = n.extractButtons(page)

	// Extract standalone inputs (outside forms)
	state.Inputs = n.extractStandaloneInputs(page)

	// Extract visible text summary (first 500 chars)
	state.VisibleText = n.extractVisibleText(page, 500)

	return state, nil
}

// ExecuteAction performs a navigator action on the page.
func (n *Navigator) ExecuteAction(ctx context.Context, page *rod.Page, action *NavigatorAction) (err error) {
	if action == nil {
		return fmt.Errorf("navigator action is nil")
	}
	beforeURL := ""
	if page != nil {
		if info, infoErr := page.Info(); infoErr == nil {
			beforeURL = info.URL
		}
	}
	targetURL := ""
	if strings.EqualFold(strings.TrimSpace(action.Action), "navigate") {
		targetURL = action.URL
	}
	finishAction := n.controller.beginTrafficAction(action.Action, action.Reason, beforeURL, targetURL)
	defer func() {
		afterURL := targetURL
		if page != nil {
			if info, infoErr := page.Info(); infoErr == nil && info.URL != "" {
				afterURL = info.URL
			}
		}
		finishAction(err, afterURL)
	}()
	finishLiveInteraction := n.controller.beginLiveBrowserInteraction(page, action)
	defer func() { finishLiveInteraction(err) }()

	n.logger.Info("executing action",
		"action", action.Action,
		"selector", action.Selector,
		"reason", action.Reason,
	)

	pa := NewPageAction(page, n.timeout)

	switch action.Action {
	case "click":
		if action.Selector == "" {
			return fmt.Errorf("click requires a selector")
		}
		if err := pa.Click(action.Selector); err != nil {
			return fmt.Errorf("click %q: %w", action.Selector, err)
		}
		// SPA clicks often do not produce a new document load. Waiting for a
		// load event here burns the full action timeout on every successful
		// menu toggle. Give reactive DOM handlers a short settle window; the
		// caller captures and compares page state immediately afterwards.
		time.Sleep(500 * time.Millisecond)

	case "fill":
		if action.Selector == "" || action.Value == "" {
			return fmt.Errorf("fill requires selector and value")
		}
		if err := pa.Fill(action.Selector, action.Value); err != nil {
			return fmt.Errorf("fill %q: %w", action.Selector, err)
		}

	case "submit":
		if action.Selector == "" {
			return fmt.Errorf("submit requires a selector")
		}
		if err := pa.Submit(action.Selector); err != nil {
			return fmt.Errorf("submit %q: %w", action.Selector, err)
		}
		time.Sleep(750 * time.Millisecond)

	case "navigate":
		if action.URL == "" {
			return fmt.Errorf("navigate requires a URL")
		}
		if err := page.Navigate(action.URL); err != nil {
			return fmt.Errorf("navigate %q: %w", action.URL, err)
		}
		page.Timeout(n.timeout).WaitLoad()

	case "scroll":
		page.Mouse.Scroll(0, 300, 1)
		time.Sleep(500 * time.Millisecond)

	case "done", "ask_human":
		// Handled by the caller
		return nil

	default:
		return fmt.Errorf("unknown action: %s", action.Action)
	}

	return nil
}

// ParseAction parses an LLM response into a NavigatorAction.
func ParseAction(response string) (*NavigatorAction, error) {
	// Try direct JSON parse
	var action NavigatorAction
	if err := json.Unmarshal([]byte(response), &action); err == nil && strings.TrimSpace(action.Action) != "" {
		return &action, nil
	}

	// Accept the first complete object when a model emits a valid decision
	// followed by the beginning of a second JSON object.
	action = NavigatorAction{}
	decoder := json.NewDecoder(bytes.NewReader([]byte(response)))
	if err := decoder.Decode(&action); err == nil && strings.TrimSpace(action.Action) != "" {
		return &action, nil
	}

	// Try extracting JSON from mixed content
	action = NavigatorAction{}
	cleaned := extractJSONFromText(response)
	if err := json.Unmarshal([]byte(cleaned), &action); err == nil && strings.TrimSpace(action.Action) != "" {
		return &action, nil
	}

	// Some reasoning-heavy models occasionally finish the bounded decision
	// fields, then hit their output ceiling halfway through the optional reason.
	// Recover only an absolute HTTP(S) navigate decision here. The caller still
	// applies exact observed-link and immutable scope-policy checks before the
	// browser moves, so this avoids a duplicate LLM turn without weakening the
	// execution boundary.
	if action, ok := recoverTruncatedNavigateAction(response); ok {
		return action, nil
	}
	// MiniMax can likewise drop only the opening {"action":"click", prefix
	// while preserving a complete selector and reason. Recover this narrowly
	// when selector is the very first field. The NavigatorAgent still requires
	// an exact selector captured from the current DOM and applies its control-
	// risk/authority checks before execution.
	if action, ok := recoverDroppedSelectorActionPrefix(response); ok {
		return action, nil
	}

	return nil, fmt.Errorf("could not parse action from LLM response")
}

var (
	navigatorJSONStringFieldRE       = regexp.MustCompile(`"([a-z_]+)"\s*:\s*("(?:\\.|[^"\\])*")`)
	navigatorDroppedNavigatePrefixRE = regexp.MustCompile(`(?i)^\{?\s*"?navigate"\s*,`)
	navigatorMissingActionKeyRE      = regexp.MustCompile(`(?i)^\{?\s*"?:\s*"navigate"\s*,`)
	navigatorMissingOpeningQuoteRE   = regexp.MustCompile(`(?i)^\{?\s*action"\s*:\s*"navigate"\s*,`)
)

func recoverTruncatedNavigateAction(response string) (*NavigatorAction, bool) {
	fields := make(map[string]string)
	for _, match := range navigatorJSONStringFieldRE.FindAllStringSubmatch(response, -1) {
		value, err := strconv.Unquote(match[2])
		if err == nil {
			fields[match[1]] = value
		}
	}
	actionName := fields["action"]
	if actionName == "" && navigatorLooksLikeDroppedNavigatePrefix(response) {
		actionName = "navigate"
	}
	if actionName != "navigate" || fields["url"] == "" {
		return nil, false
	}
	parsed, err := url.Parse(fields["url"])
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, false
	}
	reason := strings.TrimSpace(fields["reason"])
	if reason == "" {
		reason = "Recovered the completed bounded navigation decision after the optional explanation was truncated."
	}
	return &NavigatorAction{
		Action: "navigate",
		URL:    fields["url"],
		Reason: reason,
	}, true
}

func navigatorLooksLikeDroppedNavigatePrefix(response string) bool {
	trimmed := strings.TrimSpace(response)
	if strings.HasPrefix(trimmed, `"url"`) {
		return true
	}
	return navigatorDroppedNavigatePrefixRE.MatchString(trimmed) ||
		navigatorMissingActionKeyRE.MatchString(trimmed) ||
		navigatorMissingOpeningQuoteRE.MatchString(trimmed)
}

func recoverDroppedSelectorActionPrefix(response string) (*NavigatorAction, bool) {
	trimmed := strings.TrimSpace(response)
	if !strings.HasPrefix(trimmed, `"selector"`) &&
		!strings.HasPrefix(trimmed, `{"selector"`) {
		return nil, false
	}

	fields := make(map[string]string)
	for _, match := range navigatorJSONStringFieldRE.FindAllStringSubmatch(response, -1) {
		value, err := strconv.Unquote(match[2])
		if err == nil {
			fields[match[1]] = value
		}
	}
	selector := strings.TrimSpace(fields["selector"])
	if selector == "" {
		return nil, false
	}
	actionName := "click"
	if strings.TrimSpace(fields["value"]) != "" {
		actionName = "fill"
	}
	reason := strings.TrimSpace(fields["reason"])
	if reason == "" {
		reason = "Recovered the completed bounded selector decision after its opening action field was dropped."
	}
	return &NavigatorAction{
		Action:   actionName,
		Selector: selector,
		Value:    fields["value"],
		Reason:   reason,
	}, true
}

func (n *Navigator) extractLinks(page *rod.Page, limit int) []LinkInfo {
	var links []LinkInfo

	elements, err := page.Elements("a[href]")
	if err != nil {
		return links
	}

	seen := make(map[string]bool)
	for _, el := range elements {
		if len(links) >= limit {
			break
		}

		href, _ := el.Attribute("href")
		if href == nil || !shouldCaptureNavigatorHref(*href) {
			continue
		}
		rawHref := strings.TrimSpace(*href)

		text, _ := el.Text()
		text = strings.TrimSpace(text)
		if len(text) > 50 {
			text = text[:50]
		}

		if !seen[rawHref] {
			seen[rawHref] = true
			links = append(links, LinkInfo{Text: text, Href: rawHref})
		}
	}

	return links
}

func shouldCaptureNavigatorHref(href string) bool {
	href = strings.TrimSpace(href)
	if href == "" {
		return false
	}
	lower := strings.ToLower(href)
	if strings.HasPrefix(lower, "javascript:") {
		return false
	}
	// Plain same-page anchors are usually intra-document noise. Hash-routed
	// SPAs, however, encode real application pages as #/route or #!/route;
	// those must stay visible to the LLM or it will guess paths blindly.
	if strings.HasPrefix(href, "#") &&
		!strings.HasPrefix(href, "#/") &&
		!strings.HasPrefix(href, "#!") {
		return false
	}
	return true
}

func (n *Navigator) extractButtons(page *rod.Page) []ButtonInfo {
	// Build selectors in the live DOM so every selector we expose is both
	// valid and unique at capture time. A page-global `button:nth-of-type(N)`
	// is not a stable identity: nth-of-type is scoped to each parent, and a
	// late-rendered SPA component can change the ordinal between capture and
	// click. When a button has no unique attribute of its own, scope it under
	// the nearest uniquely-addressable ancestor. Swagger UI, for example,
	// becomes `#operations-default-post_orders button.opblock-summary-control`
	// instead of an unreliable ordinal selector.
	const script = `() => {
		const all = Array.from(document.querySelectorAll("button, input[type='submit'], [role='button']"));
		const unique = (selector) => {
			try { return document.querySelectorAll(selector).length === 1; }
			catch (_) { return false; }
		};
		const quoted = (value) => JSON.stringify(String(value));
		const stableClasses = (el) => Array.from(el.classList || [])
			.filter(c => c && c.length <= 64 && !/^(ng-|css-|jsx-|sc-|_[a-z0-9])/.test(c));
		const candidates = (el, includeBareTag) => {
			const tag = (el.tagName || '').toLowerCase();
			const out = [];
			if (el.id) out.push('#' + CSS.escape(el.id));
			for (const attr of ['data-testid', 'data-test', 'data-cy', 'aria-label', 'name', 'title']) {
				const value = el.getAttribute && el.getAttribute(attr);
				if (value) {
					out.push(tag + '[' + attr + '=' + quoted(value) + ']');
					out.push('[' + attr + '=' + quoted(value) + ']');
				}
			}
			const classes = stableClasses(el);
			if (tag && classes.length) {
				out.push(tag + classes.slice(0, 3).map(c => '.' + CSS.escape(c)).join(''));
				out.push(tag + '.' + CSS.escape(classes[0]));
			}
			if (includeBareTag && tag) out.push(tag);
			return Array.from(new Set(out));
		};
		const selectorFor = (el) => {
			const own = candidates(el, false);
			for (const selector of own) {
				if (unique(selector)) return selector;
			}
			const tag = (el.tagName || '').toLowerCase();
			let ancestor = el.parentElement;
			for (let depth = 0; ancestor && depth < 7; depth++, ancestor = ancestor.parentElement) {
				for (const anchor of candidates(ancestor, false)) {
					if (!unique(anchor)) continue;
					for (const relative of own.concat(tag ? [tag] : [])) {
						const scoped = anchor + ' ' + relative;
						if (unique(scoped)) return scoped;
					}
				}
			}
			return '';
		};
		return all.slice(0, 40).map(el => {
			let text = String(el.innerText || el.value || el.getAttribute('aria-label') || '').trim();
			if (text.length > 80) text = text.slice(0, 80);
			return {
				text,
				selector: selectorFor(el),
				type: String(el.getAttribute('type') || 'button').toLowerCase()
			};
		}).filter(button => button.text && button.selector).slice(0, 20);
	}`

	result, err := page.Eval(script)
	if err != nil {
		return nil
	}
	var buttons []ButtonInfo
	if err := json.Unmarshal([]byte(result.Value.JSON("", "")), &buttons); err != nil {
		return nil
	}
	return buttons
}

func (n *Navigator) extractStandaloneInputs(page *rod.Page) []InputInfo {
	var inputs []InputInfo

	// Find inputs not inside forms
	elements, err := page.Elements("input:not(form input), textarea:not(form textarea)")
	if err != nil {
		return inputs
	}

	for i, el := range elements {
		if i >= 15 {
			break
		}

		ii := InputInfo{}
		if id, _ := el.Attribute("id"); id != nil && *id != "" {
			ii.Selector = "#" + *id
		} else if name, _ := el.Attribute("name"); name != nil && *name != "" {
			ii.Selector = fmt.Sprintf(`[name=%q]`, *name)
		}
		if name, _ := el.Attribute("name"); name != nil {
			ii.Name = *name
		}
		if typ, _ := el.Attribute("type"); typ != nil {
			ii.Type = strings.ToLower(*typ)
		} else {
			ii.Type = "text"
		}
		if ph, _ := el.Attribute("placeholder"); ph != nil {
			ii.Value = *ph // use placeholder as hint
		}

		if ii.Name != "" || ii.Selector != "" || ii.Type == "search" || ii.Type == "text" ||
			ii.Type == "email" || ii.Type == "password" {
			inputs = append(inputs, ii)
		}
	}

	return inputs
}

func (n *Navigator) extractVisibleText(page *rod.Page, maxLen int) string {
	js := `(() => {
		const el = document.body;
		if (!el) return '';
		const text = el.innerText || el.textContent || '';
		return text.substring(0, ` + fmt.Sprintf("%d", maxLen) + `);
	})()`

	result, err := page.Eval(js)
	if err != nil {
		return ""
	}

	text := result.Value.String()
	// Collapse whitespace
	lines := strings.Split(text, "\n")
	var cleaned []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			cleaned = append(cleaned, trimmed)
		}
	}
	return strings.Join(cleaned, "\n")
}

func extractFormsFromPage(page *rod.Page) []FormInfo {
	var forms []FormInfo

	formEls, err := page.Elements("form")
	if err != nil {
		return forms
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

		inputs, _ := formEl.Elements("input, textarea, select")
		for _, inp := range inputs {
			ii := InputInfo{}
			if id, _ := inp.Attribute("id"); id != nil && *id != "" {
				ii.Selector = "#" + *id
			} else if name, _ := inp.Attribute("name"); name != nil && *name != "" {
				ii.Selector = fmt.Sprintf(`[name=%q]`, *name)
			}
			if name, _ := inp.Attribute("name"); name != nil {
				ii.Name = *name
			}
			if typ, _ := inp.Attribute("type"); typ != nil {
				ii.Type = strings.ToLower(*typ)
			} else {
				ii.Type = "text"
			}
			if ii.Name != "" || ii.Selector != "" || ii.Type == "email" || ii.Type == "password" {
				fi.Inputs = append(fi.Inputs, ii)
			}
		}

		forms = append(forms, fi)
	}

	return forms
}

func extractJSONFromText(s string) string {
	start := -1
	end := -1
	for i, c := range s {
		if c == '{' {
			start = i
			break
		}
	}
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '}' {
			end = i + 1
			break
		}
	}
	if start >= 0 && end > start {
		return s[start:end]
	}
	return s
}
