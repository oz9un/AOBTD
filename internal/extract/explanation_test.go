package extract

import (
	"strings"
	"testing"
)

// TestExplainInput_TypeBased — HTML type attribute drives the explanation
// for the common cases.
func TestExplainInput_TypeBased(t *testing.T) {
	cases := []struct {
		name, typ, loc string
		wantContains   string
	}{
		{"pw", "password", "form", "Password field"},
		{"em", "email", "form", "Email address"},
		{"avatar", "file", "form", "File upload"},
		{"q", "search", "query", "Search box"},
		{"next", "url", "query", "URL field"},
		{"dob", "date", "form", "Date/time"},
		{"n", "number", "body", "Numeric"},
	}
	for _, c := range cases {
		got := ExplainInput(c.name, c.typ, c.loc, "", "")
		if !strings.Contains(got, c.wantContains) {
			t.Errorf("ExplainInput(%q,%q): got %q, want substring %q",
				c.name, c.typ, got, c.wantContains)
		}
	}
}

// TestExplainInput_HiddenSecurity — the hidden-input specialisation
// must pick the right security frame for each pattern.
func TestExplainInput_HiddenSecurity(t *testing.T) {
	cases := []struct {
		name, want string
	}{
		{"csrf_token", "CSRF"},
		{"authenticity_token", "CSRF"},
		{"state", "state/nonce"},
		{"returnTo", "redirect"},
		{"next", "redirect"},
		{"callback_url", "redirect"},
		{"user_id", "IDOR"},
		{"tenantId", "tenant-crossing"},
		{"price", "price/amount"},
		{"discount", "price/amount"},
		{"signature", "token/signature"},
	}
	for _, c := range cases {
		got := ExplainInput(c.name, "hidden", "form", "", "")
		if !strings.Contains(strings.ToLower(got), strings.ToLower(c.want)) {
			t.Errorf("hidden %q: got %q, want substring %q", c.name, got, c.want)
		}
	}
}

// TestExplainInput_KeywordFallback — when type isn't decisive (empty or
// "text"), name/label keywords drive the explanation.
func TestExplainInput_KeywordFallback(t *testing.T) {
	cases := []struct {
		name, typ, label, wantContains string
	}{
		{"username", "text", "", "Username"},
		{"api_key", "text", "", "API credential"},
		{"order_id", "text", "", "IDOR on finance"},
		{"coupon", "text", "Promo code", "Price / amount"},
		{"phone", "text", "", "Phone"},
		{"ssn", "text", "", "Government identifier"},
		{"credit_card_number", "text", "", "Payment card"},
	}
	for _, c := range cases {
		got := ExplainInput(c.name, c.typ, "form", c.label, "")
		if !strings.Contains(got, c.wantContains) {
			t.Errorf("ExplainInput(%q): got %q, want substring %q",
				c.name, got, c.wantContains)
		}
	}
}

// TestExplainInput_LocationHint — query/body/path locations append a
// human clause so the viewer knows where the input lives.
func TestExplainInput_LocationHint(t *testing.T) {
	out := ExplainInput("q", "search", "query", "", "")
	if !strings.Contains(out, "query param") {
		t.Errorf("expected 'query param' hint, got %q", out)
	}

	out = ExplainInput("body_field", "text", "body", "", "")
	if !strings.Contains(out, "request body") {
		t.Errorf("expected 'request body' hint, got %q", out)
	}

	// Form location is the default HTML case — no trailing hint
	out = ExplainInput("email", "email", "form", "", "")
	if strings.Contains(out, "(query") || strings.Contains(out, "(request body") {
		t.Errorf("form location should add no hint, got %q", out)
	}
}

// TestExplainInput_PlaceholderFallback — when we have nothing else, use
// the placeholder as signal.
func TestExplainInput_PlaceholderFallback(t *testing.T) {
	out := ExplainInput("mystery_field", "", "form", "", "Enter your favorite color")
	if !strings.Contains(out, "placeholder") {
		t.Errorf("expected placeholder fallback, got %q", out)
	}
	if !strings.Contains(out, "favorite color") {
		t.Errorf("placeholder text should appear, got %q", out)
	}
}

// TestExplainInput_LabelFallback — label works as fallback when placeholder
// is empty.
func TestExplainInput_LabelFallback(t *testing.T) {
	out := ExplainInput("mystery_field", "", "form", "Your custom answer", "")
	if !strings.Contains(out, "labelled") {
		t.Errorf("expected 'labelled' fallback, got %q", out)
	}
	if !strings.Contains(out, "custom answer") {
		t.Errorf("label text should appear, got %q", out)
	}
}

// TestExplainInput_Unknown — nothing identifiable; the explanation should
// still be non-empty and honest.
func TestExplainInput_Unknown(t *testing.T) {
	out := ExplainInput("x", "", "form", "", "")
	if out == "" {
		t.Fatal("explanation should never be empty")
	}
	// Should NOT claim to know the purpose
	if strings.Contains(strings.ToLower(out), "password") ||
		strings.Contains(strings.ToLower(out), "email") ||
		strings.Contains(strings.ToLower(out), "search") {
		t.Errorf("unknown input should not claim specific purpose, got %q", out)
	}
}

// TestExplainInput_Length — outputs stay under a reasonable length so UI
// rendering doesn't bloat.
func TestExplainInput_Length(t *testing.T) {
	cases := []struct{ name, typ, loc, label, placeholder string }{
		{"email", "email", "form", "Your email address", "you@example.com"},
		{"csrf_token", "hidden", "form", "", ""},
		{"x", "", "query", strings.Repeat("a", 200), strings.Repeat("b", 200)},
	}
	for _, c := range cases {
		out := ExplainInput(c.name, c.typ, c.loc, c.label, c.placeholder)
		if len(out) > 200 {
			t.Errorf("explanation too long (%d chars): %q", len(out), out)
		}
		if strings.HasSuffix(out, ".") {
			t.Errorf("explanation should not end with period (style rule): %q", out)
		}
	}
}

// TestExplainInput_IDPatterns — suffix-based id detection.
func TestExplainInput_IDPatterns(t *testing.T) {
	cases := []struct{ name, want string }{
		{"id", "identifier"},
		{"session_id", "IDOR"},            // more specific: matches user_id family? Actually session_id is just an id suffix
		{"product_id", "Generic identifier"}, // matches _id suffix fallback
	}
	for _, c := range cases {
		got := ExplainInput(c.name, "text", "query", "", "")
		if !strings.Contains(strings.ToLower(got), strings.ToLower(c.want)) {
			t.Errorf("name %q: got %q, want substring %q", c.name, got, c.want)
		}
	}
}
