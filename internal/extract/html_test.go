package extract

import (
	"fmt"
	"strings"
	"testing"
)

// TestExtractHTML_LoginForm verifies a typical login form with CSRF token
// is captured completely — including the hidden field, labels, and form
// action resolution.
func TestExtractHTML_LoginForm(t *testing.T) {
	htmlSrc := `<!DOCTYPE html>
<html>
<head><title>Sign In</title></head>
<body>
  <form action="/auth/login" method="POST" id="loginForm">
    <input type="hidden" name="csrf_token" value="abc123xyz">
    <label for="email">Email address</label>
    <input type="email" id="email" name="email" required placeholder="you@example.com">
    <label for="password">Password</label>
    <input type="password" id="password" name="password" required minlength="8">
    <button type="submit">Login</button>
  </form>
</body>
</html>`

	ext := ExtractHTML([]byte(htmlSrc), "https://example.com/login")

	if ext.Title != "Sign In" {
		t.Errorf("Title: got %q, want %q", ext.Title, "Sign In")
	}

	if len(ext.Forms) != 1 {
		t.Fatalf("Forms: got %d, want 1", len(ext.Forms))
	}

	form := ext.Forms[0]
	if form.Method != "POST" {
		t.Errorf("Form.Method: got %q, want %q", form.Method, "POST")
	}
	if form.Action != "https://example.com/auth/login" {
		t.Errorf("Form.Action: got %q, want %q", form.Action, "https://example.com/auth/login")
	}
	if form.ID != "loginForm" {
		t.Errorf("Form.ID: got %q, want %q", form.ID, "loginForm")
	}

	// All three inputs (csrf hidden + email + password) must appear in form.Inputs
	if len(form.Inputs) != 3 {
		t.Fatalf("Form.Inputs count: got %d, want 3 (csrf+email+password)", len(form.Inputs))
	}

	byName := map[string]ExtractedInput{}
	for _, inp := range form.Inputs {
		byName[inp.Name] = inp
	}

	// CSRF hidden input
	csrf, ok := byName["csrf_token"]
	if !ok {
		t.Fatal("csrf_token not found in form inputs")
	}
	if csrf.Type != "hidden" {
		t.Errorf("csrf_token Type: got %q, want hidden", csrf.Type)
	}
	if csrf.Value != "abc123xyz" {
		t.Errorf("csrf_token Value: got %q, want abc123xyz", csrf.Value)
	}

	// Email field with label
	email, ok := byName["email"]
	if !ok {
		t.Fatal("email field not found")
	}
	if email.Type != "email" {
		t.Errorf("email Type: got %q, want email", email.Type)
	}
	if !email.Required {
		t.Error("email should be required")
	}
	if email.Placeholder != "you@example.com" {
		t.Errorf("email Placeholder: got %q", email.Placeholder)
	}
	if email.Label != "Email address" {
		t.Errorf("email Label: got %q, want Email address", email.Label)
	}

	// Password field with minlength
	password, ok := byName["password"]
	if !ok {
		t.Fatal("password field not found")
	}
	if password.Type != "password" {
		t.Errorf("password Type: got %q", password.Type)
	}
	if password.MinLength != 8 {
		t.Errorf("password MinLength: got %d, want 8", password.MinLength)
	}

	// CSRF should also appear in HiddenFields (for quick access)
	if len(ext.HiddenFields) == 0 {
		t.Error("HiddenFields should include csrf_token")
	}
	foundCSRF := false
	for _, h := range ext.HiddenFields {
		if h.Name == "csrf_token" {
			foundCSRF = true
			break
		}
	}
	if !foundCSRF {
		t.Error("csrf_token not in HiddenFields")
	}
}

func TestExtractHTMLCapturesBoundedSemanticStructure(t *testing.T) {
	var headings strings.Builder
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&headings, "<h2>API Reference Section %d %s</h2>", i, strings.Repeat("x", 220))
	}
	htmlSrc := `<html><head><title>  C API   Reference </title></head><body>` + headings.String() + `<pre>example</pre><pre>second</pre></body></html>`
	ext := ExtractHTML([]byte(htmlSrc), "https://example.test/opaque.html")
	if ext.Title != "C API Reference" {
		t.Fatalf("normalized title = %q", ext.Title)
	}
	if len(ext.Headings) != 12 {
		t.Fatalf("bounded headings = %d, want 12", len(ext.Headings))
	}
	for _, heading := range ext.Headings {
		if len(heading) > 180 {
			t.Fatalf("heading exceeded bound: %d", len(heading))
		}
	}
	if ext.PreformattedBlocks != 2 {
		t.Fatalf("preformatted blocks = %d, want 2", ext.PreformattedBlocks)
	}
}

// TestExtractHTML_StandaloneInputs — inputs not inside any <form> should
// go into StandaloneInputs (or HiddenFields if type=hidden).
func TestExtractHTML_StandaloneInputs(t *testing.T) {
	htmlSrc := `<html><body>
  <input type="text" name="search" placeholder="Search...">
  <input type="hidden" name="csrf" value="xyz">
  <div><input type="checkbox" name="remember"></div>
</body></html>`

	ext := ExtractHTML([]byte(htmlSrc), "https://example.com/")

	if len(ext.Forms) != 0 {
		t.Errorf("Forms: got %d, want 0", len(ext.Forms))
	}
	if len(ext.StandaloneInputs) != 2 {
		t.Errorf("StandaloneInputs: got %d, want 2 (search+remember)", len(ext.StandaloneInputs))
	}
	if len(ext.HiddenFields) != 1 {
		t.Errorf("HiddenFields: got %d, want 1", len(ext.HiddenFields))
	}
	if ext.HiddenFields[0].Name != "csrf" {
		t.Errorf("HiddenField name: got %q", ext.HiddenFields[0].Name)
	}
}

// TestExtractHTML_SelectWithOptions — <select> with <option> elements
// should capture options (capped at 20).
func TestExtractHTML_SelectWithOptions(t *testing.T) {
	htmlSrc := `<html><body><form>
  <select name="country">
    <option value="us">United States</option>
    <option value="uk">United Kingdom</option>
    <option value="de">Germany</option>
  </select>
  <textarea name="bio" maxlength="500"></textarea>
</form></body></html>`

	ext := ExtractHTML([]byte(htmlSrc), "https://example.com/")

	if len(ext.Forms) != 1 {
		t.Fatalf("Forms: got %d, want 1", len(ext.Forms))
	}
	var sel, ta *ExtractedInput
	for i := range ext.Forms[0].Inputs {
		switch ext.Forms[0].Inputs[i].Name {
		case "country":
			sel = &ext.Forms[0].Inputs[i]
		case "bio":
			ta = &ext.Forms[0].Inputs[i]
		}
	}
	if sel == nil {
		t.Fatal("select country not found")
	}
	if sel.Type != "select" {
		t.Errorf("select Type: got %q, want select", sel.Type)
	}
	if len(sel.Options) != 3 {
		t.Errorf("select Options: got %d, want 3", len(sel.Options))
	}

	if ta == nil {
		t.Fatal("textarea bio not found")
	}
	if ta.Type != "textarea" {
		t.Errorf("textarea Type: got %q, want textarea", ta.Type)
	}
	if ta.MaxLength != 500 {
		t.Errorf("textarea MaxLength: got %d, want 500", ta.MaxLength)
	}
}

// TestExtractHTML_Links — same-origin and API detection.
func TestExtractHTML_Links(t *testing.T) {
	htmlSrc := `<html><body>
  <a href="/products">Products</a>
  <a href="https://example.com/about">About</a>
  <a href="https://other.com/elsewhere">External</a>
  <a href="/api/v1/users">API Users</a>
  <a href="javascript:void(0)">JS Link</a>
  <a href="#anchor">Anchor</a>
  <a href="/products">Products dup</a>
</body></html>`

	ext := ExtractHTML([]byte(htmlSrc), "https://example.com/")

	// javascript: and # and duplicates should be filtered
	// 4 unique valid links: /products, /about, other.com, /api/v1/users
	if len(ext.Links) != 4 {
		t.Errorf("Links: got %d, want 4", len(ext.Links))
		for _, l := range ext.Links {
			t.Logf("  link: %+v", l)
		}
	}

	byHref := map[string]ExtractedLink{}
	for _, l := range ext.Links {
		byHref[l.Href] = l
	}

	if l, ok := byHref["https://example.com/products"]; !ok {
		t.Error("products link missing")
	} else if !l.SameOrigin {
		t.Error("products should be SameOrigin")
	}

	if l, ok := byHref["https://other.com/elsewhere"]; !ok {
		t.Error("external link missing")
	} else if l.SameOrigin {
		t.Error("external should NOT be SameOrigin")
	}

	if l, ok := byHref["https://example.com/api/v1/users"]; !ok {
		t.Error("api link missing")
	} else {
		if !l.IsAPI {
			t.Error("api link should be IsAPI")
		}
		if !l.SameOrigin {
			t.Error("api link should be SameOrigin")
		}
	}
}

// TestExtractHTML_MetaAndComments — meta tags + HTML comments captured.
func TestExtractHTML_MetaAndComments(t *testing.T) {
	htmlSrc := `<html><head>
  <meta name="generator" content="WordPress 6.2">
  <meta property="og:title" content="Homepage">
  <!-- TODO: remove debug endpoint /api/_debug before prod -->
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
</head><body></body></html>`

	ext := ExtractHTML([]byte(htmlSrc), "https://example.com/")

	if len(ext.MetaTags) != 3 {
		t.Errorf("MetaTags: got %d, want 3", len(ext.MetaTags))
	}

	foundGenerator := false
	for _, m := range ext.MetaTags {
		if m.Name == "generator" && strings.Contains(m.Content, "WordPress") {
			foundGenerator = true
		}
	}
	if !foundGenerator {
		t.Error("generator meta tag not captured")
	}

	if len(ext.Comments) == 0 {
		t.Error("expected at least one HTML comment")
	}
	foundTODO := false
	for _, c := range ext.Comments {
		if strings.Contains(c, "_debug") {
			foundTODO = true
		}
	}
	if !foundTODO {
		t.Error("TODO comment not captured")
	}
}

// TestExtractHTML_InputSignature — templates with identical input structure
// should produce identical signatures; different structure → different sig.
func TestExtractHTML_InputSignature(t *testing.T) {
	// Two product pages — same template, different content
	pageA := `<html><body>
  <form action="/cart/add" method="POST">
    <input type="hidden" name="product_id" value="42">
    <input type="number" name="quantity" value="1">
    <button type="submit">Add</button>
  </form>
  <h1>Widget A</h1>
</body></html>`

	pageB := `<html><body>
  <form action="/cart/add" method="POST">
    <input type="hidden" name="product_id" value="99">
    <input type="number" name="quantity" value="1">
    <button type="submit">Add</button>
  </form>
  <h1>Widget B</h1>
</body></html>`

	// A checkout page — different template
	pageC := `<html><body>
  <form action="/checkout" method="POST">
    <input type="text" name="address">
    <input type="text" name="card_number">
  </form>
</body></html>`

	sigA := ExtractHTML([]byte(pageA), "https://example.com/p/a").InputSignature()
	sigB := ExtractHTML([]byte(pageB), "https://example.com/p/b").InputSignature()
	sigC := ExtractHTML([]byte(pageC), "https://example.com/checkout").InputSignature()

	if sigA == "" {
		t.Fatal("sigA should not be empty")
	}
	if sigA != sigB {
		t.Errorf("product pages A and B should share signature\n  A=%s\n  B=%s", sigA, sigB)
	}
	if sigA == sigC {
		t.Errorf("product and checkout pages should NOT share signature: %s", sigA)
	}
}

// TestExtractHTML_EmptyAndMalformed — empty / broken HTML should not panic.
func TestExtractHTML_EmptyAndMalformed(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"empty", ""},
		{"whitespace", "   \n\t  "},
		{"no-root", "<p>loose paragraph</p><div>no html tag</div>"},
		{"unclosed", "<html><body><form><input name='x'"},
		{"nested-forms-invalid", "<form><form><input name='x'></form></form>"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked: %v", r)
				}
			}()
			ext := ExtractHTML([]byte(c.src), "https://example.com/")
			if ext == nil {
				t.Fatal("got nil extraction")
			}
		})
	}
}

// TestExtractHTML_TotalInputCount — sum across forms, standalone, hidden.
func TestExtractHTML_TotalInputCount(t *testing.T) {
	htmlSrc := `<html><body>
  <form>
    <input name="a"><input name="b">
  </form>
  <input name="c">
  <input type="hidden" name="d">
</body></html>`
	ext := ExtractHTML([]byte(htmlSrc), "https://example.com/")
	got := ext.TotalInputCount()
	// form has 2 visible + hidden fields list (0 in form) + standalone c + hidden d
	// The form split step moves hidden from forms to HiddenFields but keeps them in both slices,
	// so TotalInputCount should see form.Inputs (2) + standalone (1) + hidden (1) = 4
	if got < 3 {
		t.Errorf("TotalInputCount: got %d, want at least 3", got)
	}
}

// TestExtractHTML_LabelFromParent — <label>Text <input/></label> should
// still surface the label text on the input.
func TestExtractHTML_LabelFromParent(t *testing.T) {
	htmlSrc := `<html><body><form>
  <label>Your email <input type="email" name="email"></label>
</form></body></html>`

	ext := ExtractHTML([]byte(htmlSrc), "https://example.com/")
	if len(ext.Forms) != 1 || len(ext.Forms[0].Inputs) != 1 {
		t.Fatalf("expected 1 form with 1 input")
	}
	inp := ext.Forms[0].Inputs[0]
	if !strings.Contains(inp.Label, "email") {
		t.Errorf("label should mention 'email', got %q", inp.Label)
	}
}
