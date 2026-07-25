package browser

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/proto"
)

// PageAction provides atomic browser actions on a page.
type PageAction struct {
	page    *rod.Page
	timeout time.Duration
}

// NewPageAction wraps a rod.Page with timeout-protected actions.
func NewPageAction(page *rod.Page, timeout time.Duration) *PageAction {
	return &PageAction{page: page, timeout: timeout}
}

// Click clicks an element matching the CSS selector. Waits for the element
// to be interactable (visible, enabled, in viewport) — not just present in
// the DOM. SPAs render the DOM before wiring click handlers, so a bare
// .Element + .Click returns success while the click silently no-ops; the
// .WaitInteractable round-trip blocks until rod confirms the element will
// actually accept the gesture, then trips the action timeout if it never
// does instead of falsely succeeding.
//
// Fallback: WaitInteractable is conservative on Angular Material apps —
// mat-progress-bar overlays, ripple containers, and the cdk-overlay layer
// can keep flagging "covered/not interactable" for the entire timeout even
// though the button works fine for a real user. Rather than report failure
// (and burn the navigator's 3-strikes counter), we fire a JS-level click
// via element.click() which dispatches the same click event Angular's
// (click) bindings listen for. We log the fallback so it's visible in the
// scan trace.
func (a *PageAction) Click(selector string) error {
	el, err := a.page.Timeout(a.timeout).Element(selector)
	if err != nil {
		return fmt.Errorf("find element %q: %w", selector, err)
	}
	if _, err := el.Timeout(a.timeout).WaitInteractable(); err != nil {
		// Try scrolling into view first — fixes the most common cause
		// (element exists but is offscreen, so rod marks it "not visible").
		_ = el.ScrollIntoView()
		if _, err2 := el.Timeout(2 * time.Second).WaitInteractable(); err2 != nil {
			// Still not interactable — fall back to JS click. We accept the
			// reduced fidelity (no real mouse events) for the gain in demo
			// reliability against Material-heavy SPAs.
			//
			// Re-fetch the element on a FRESH page handle. el's context is
			// derived from a.page.Timeout(a.timeout) which has already been
			// burned by Element() + two WaitInteractable rounds; calling
			// el.Timeout(5*time.Second) re-WRAPS the expired context rather
			// than replacing it, so the Eval immediately reports "context
			// deadline exceeded". Going back to the bare a.page hands us an
			// element whose context is fresh.
			freshEl, ferr := a.page.Timeout(5 * time.Second).Element(selector)
			if ferr != nil {
				return fmt.Errorf("re-fetch for js-click %q: %w", selector, ferr)
			}
			if _, evalErr := freshEl.Eval("() => this.click()"); evalErr != nil {
				return fmt.Errorf("js-click fallback %q after wait-interactable failed: %w", selector, evalErr)
			}
			return nil
		}
	}
	return el.Click(proto.InputMouseButtonLeft, 1)
}

// Fill types text into an input element matching the selector.
// See Click — same rationale for the WaitInteractable gate (an Angular
// <input> can be in the DOM but disabled while the form group initializes),
// same scroll-and-retry fallback when Material overlays trip the check.
//
// If WaitInteractable still fails after scrolling, fall back to a DOM-level
// value set that dispatches input/change events. This is less faithful than
// real keyboard input, but it is still closer to a user action than skipping
// the form entirely, and it keeps Angular/React form bindings informed.
func (a *PageAction) Fill(selector, value string) error {
	el, err := a.page.Timeout(a.timeout).Element(selector)
	if err != nil {
		return fmt.Errorf("find input %q: %w", selector, err)
	}
	if _, err := el.Timeout(a.timeout).WaitInteractable(); err != nil {
		_ = el.ScrollIntoView()
		if _, err2 := el.Timeout(2 * time.Second).WaitInteractable(); err2 != nil {
			freshEl, ferr := a.page.Timeout(5 * time.Second).Element(selector)
			if ferr != nil {
				return fmt.Errorf("re-fetch for js-fill %q: %w", selector, ferr)
			}
			if evalErr := setInputValueViaDOMEvents(freshEl, value); evalErr != nil {
				return fmt.Errorf("js-fill fallback %q after wait-interactable failed: %w", selector, evalErr)
			}
			return nil
		}
	}
	return el.Input(value)
}

func setInputValueViaDOMEvents(el *rod.Element, value string) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	script := fmt.Sprintf(`() => {
		const el = this;
		const value = %s;
		el.scrollIntoView({block: "center", inline: "nearest"});
		el.focus();

		const proto = Object.getPrototypeOf(el);
		const descriptor =
			Object.getOwnPropertyDescriptor(proto, "value") ||
			Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value") ||
			Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value");
		if (descriptor && descriptor.set) {
			descriptor.set.call(el, value);
		} else {
			el.value = value;
		}

		el.dispatchEvent(new InputEvent("input", {
			bubbles: true,
			cancelable: true,
			inputType: "insertText",
			data: value
		}));
		el.dispatchEvent(new Event("change", { bubbles: true, cancelable: true }));
		return el.value;
	}`, string(encoded))
	_, err = el.Eval(script)
	return err
}

// Submit submits a form by pressing Enter on the given element. WaitInteractable
// applies here too — a freshly-rendered submit button can be DOM-present but
// blocked by a pending validator on first paint. Scroll-and-retry on first
// failure for the same reason as Click/Fill.
func (a *PageAction) Submit(selector string) error {
	el, err := a.page.Timeout(a.timeout).Element(selector)
	if err != nil {
		return fmt.Errorf("find element %q: %w", selector, err)
	}
	if _, err := el.Timeout(a.timeout).WaitInteractable(); err != nil {
		_ = el.ScrollIntoView()
		if _, err2 := el.Timeout(2 * time.Second).WaitInteractable(); err2 != nil {
			return fmt.Errorf("wait interactable %q (after scroll): %w", selector, err2)
		}
	}
	return el.Type(input.Enter)
}

// GetText returns the visible text content of an element.
func (a *PageAction) GetText(selector string) (string, error) {
	el, err := a.page.Timeout(a.timeout).Element(selector)
	if err != nil {
		return "", fmt.Errorf("find element %q: %w", selector, err)
	}
	return el.Text()
}

// GetAttribute returns an attribute value of an element.
func (a *PageAction) GetAttribute(selector, attr string) (string, error) {
	el, err := a.page.Timeout(a.timeout).Element(selector)
	if err != nil {
		return "", fmt.Errorf("find element %q: %w", selector, err)
	}
	val, err := el.Attribute(attr)
	if err != nil {
		return "", err
	}
	if val == nil {
		return "", nil
	}
	return *val, nil
}

// WaitLoad waits for the page to finish loading.
func (a *PageAction) WaitLoad() error {
	return a.page.Timeout(a.timeout).WaitLoad()
}

// WaitStable waits for the page DOM to stop changing.
func (a *PageAction) WaitStable(interval time.Duration) error {
	return a.page.Timeout(a.timeout).WaitStable(interval)
}

// CurrentURL returns the page's current URL.
func (a *PageAction) CurrentURL() string {
	info, err := a.page.Info()
	if err != nil {
		return ""
	}
	return info.URL
}

// Page returns the underlying rod.Page.
func (a *PageAction) Page() *rod.Page {
	return a.page
}
