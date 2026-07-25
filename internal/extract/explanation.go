package extract

import (
	"fmt"
	"strings"
)

// ExplainInput produces a short, human-readable description of what an
// input is for. It combines three signals, in order:
//
//  1. HTML input `type` attribute (email → "email field", file → "file
//     upload", password → "password field", hidden → "hidden field")
//  2. Field name / label keywords (csrf/token/state → "anti-forgery token",
//     redirect/returnTo/next → "post-action redirect target", query/search
//     /q → "search query", id/_id → "identifier")
//  3. Placeholder text and <label> fallback ("placeholder: 'Enter coupon code'")
//
// Output is a single sentence, ≤ 140 chars, no trailing period. The
// analyzer stores this on Input.Explanation so the UI can render "what
// does this input do" without spending an LLM call. The LLM can still
// overwrite it for nuanced cases (business-logic fields).
//
// Intentionally conservative — we prefer "string parameter" over making
// things up. If we don't recognise the field, we say so.
func ExplainInput(name, inputType, location, label, placeholder string) string {
	// Normalised lookup keys
	lName := strings.ToLower(strings.TrimSpace(name))
	lType := strings.ToLower(strings.TrimSpace(inputType))
	lLabel := strings.ToLower(strings.TrimSpace(label))
	locHint := locationHint(location)
	// We intentionally don't lowercase the placeholder for the output
	// (user-facing text keeps its original case); it's only checked via
	// the placeholder-fallback branch below.

	// ---- 1. Strong signals from HTML type attribute ----
	switch lType {
	case "password":
		return "Password field — credential; commonly paired with username/email for authentication" + locHint
	case "email":
		return "Email address — user identifier or contact field; common login input" + locHint
	case "file":
		return "File upload — binary payload; check accepted types, server-side validation, storage path" + locHint
	case "hidden":
		return explainHidden(lName, name)
	case "checkbox":
		return "Checkbox — boolean toggle" + explainLabel(label, placeholder)
	case "radio":
		return "Radio button — one-of-many selection" + explainLabel(label, placeholder)
	case "color":
		return "Color picker — hex/named color value" + locHint
	case "date", "datetime-local", "time":
		return "Date/time value — validate format and range server-side" + locHint
	case "url":
		return "URL field — user-supplied URL; check for SSRF / open-redirect on server" + locHint
	case "tel":
		return "Phone number — text-ish, not strictly validated by the tag" + locHint
	case "number", "range":
		return "Numeric input — check bounds and integer-vs-float expectations" + locHint
	case "search":
		return "Search box — free-text query; commonly reflected into results page (XSS candidate)" + locHint
	case "submit", "button", "reset", "image":
		return "Form action button — not user data per se, but fires the form submit" + locHint
	case "select":
		return "Dropdown selection — one of an enumerated set; server should validate against the list" + locHint
	case "textarea":
		return "Multi-line text — free-form user input; validate length and HTML/script content" + locHint
	}

	// ---- 2. Name / label keyword heuristics ----
	// matchKeyword checks both the name (for exact-suffix patterns like
	// "_id") and the combined string (for substring patterns like "email"
	// appearing in a label). We pass both so it can choose.
	if h := matchKeyword(lName, strings.TrimSpace(lName+" "+lLabel)); h != "" {
		return h + locHint
	}

	// ---- 3. Placeholder / label fallback ----
	if placeholder != "" {
		return fmt.Sprintf("Free-text input (placeholder: %q)%s", truncateFor(placeholder, 60), locHint)
	}
	if label != "" {
		return fmt.Sprintf("Input labelled %q%s", truncateFor(label, 60), locHint)
	}

	// ---- 4. Last resort: describe by type + location ----
	if lType != "" && lType != "text" {
		return strings.Title(lType) + " parameter" + locHint
	}
	return "Free-text parameter — purpose not explicit" + locHint
}

// explainHidden describes hidden inputs, which carry the richest
// security signal (CSRF tokens, state, tenant ids).
func explainHidden(lName, origName string) string {
	switch {
	case containsAny(lName, "csrf", "xsrf", "authenticity_token", "anti_forgery"):
		return "Hidden anti-CSRF token — per-request/session value that should be verified on POST"
	case containsAny(lName, "state", "nonce", "challenge"):
		return "Hidden state/nonce — often used in OAuth/OIDC flows; tampering breaks the handshake"
	case containsAny(lName, "returnto", "return_to", "redirect", "next", "continue", "callback"):
		return "Hidden post-action redirect target — high-value for open-redirect / chained XSS"
	case containsAny(lName, "userid", "user_id", "uid", "tenant", "org", "company"):
		return "Hidden identifier — changing it often exposes IDOR / tenant-crossing"
	case containsAny(lName, "token", "secret", "sig", "signature", "hmac"):
		return "Hidden token/signature — worth checking for reuse, weak secret, or replay"
	case containsAny(lName, "price", "amount", "total", "qty", "quantity", "discount"):
		return "Hidden commerce value — business-logic tamper candidate (price/amount manipulation)"
	case origName == "":
		return "Hidden field — no name attribute; unusual, inspect manually"
	}
	return "Hidden form field — may carry server-controlled state; inspect value across requests"
}

// matchKeyword returns the most specific keyword-based description for a
// field name + label, or "" if nothing matches. The first match wins, so
// the cases are ordered most-specific first.
//
// `name` is the lowercased bare field name — used for exact-suffix checks
// like "_id". `s` is the combined "name label" string used for substring
// matches ("email" may appear in a label even if the name is opaque).
func matchKeyword(name, s string) string {
	switch {
	// Auth / identity
	case containsAny(s, "username", "user_name", "login", "handle", "account_name"):
		return "Username field — user identifier for authentication"
	case containsAny(s, "password", "passwd", "pwd"):
		return "Password field — credential (even if type wasn't 'password')"
	case containsAny(s, "email", "mail"):
		return "Email address field"
	case containsAny(s, "otp", "two_factor", "2fa", "totp", "mfa_code"):
		return "MFA / OTP code — time-bound one-time value"

	// Anti-forgery
	case containsAny(s, "csrf", "xsrf", "authenticity_token"):
		return "Anti-CSRF token"
	case containsAny(s, "nonce", "state_token"):
		return "Single-use nonce / state token"

	// Redirects
	case containsAny(s, "redirect", "return_to", "returnto", "next_url", "callback_url", "continue"):
		return "Redirect target URL — open-redirect / SSRF candidate"
	case containsAny(s, "url", "link", "href", "uri"):
		return "URL parameter — check for SSRF and open-redirect"

	// IDs & ownership
	case containsAny(s, "user_id", "userid", "uid", "account_id"):
		return "User identifier — IDOR / authorization-boundary candidate"
	case containsAny(s, "tenant", "org_id", "workspace", "company_id"):
		return "Tenant identifier — cross-tenant / BOLA candidate"
	case containsAny(s, "order_id", "invoice_id", "transaction_id"):
		return "Transactional identifier — IDOR on finance-adjacent data"
	case strings.HasSuffix(name, "_id") || name == "id":
		return "Generic identifier — sequential-id IDOR candidate"

	// Commerce
	case containsAny(s, "price", "amount", "total", "subtotal", "discount", "coupon"):
		return "Price / amount — business-logic tamper candidate"
	case containsAny(s, "qty", "quantity", "count"):
		return "Quantity — check for negative values, overflow, stock bypass"

	// Search / reflected — bare "q" is the universal search param name
	case name == "q" || name == "query" || name == "search" || name == "keyword" || name == "term":
		return "Search query — commonly reflected into results (XSS) or passed to a DB LIKE (SQLi)"
	case containsAny(s, "search", "query", "keyword"):
		return "Search query — commonly reflected into results (XSS) or passed to a DB LIKE (SQLi)"
	case containsAny(s, "filter", "sort", "order_by", "orderby"):
		return "Query shaping parameter — injection candidate if passed raw to the DB"

	// File / upload
	case containsAny(s, "file", "upload", "attachment", "document"):
		return "File reference — check upload path, stored location, MIME validation"
	case containsAny(s, "filename", "file_name"):
		return "Filename — path-traversal / overwrite candidate if stored as-is"

	// Tokens
	case containsAny(s, "api_key", "apikey", "access_token", "bearer"):
		return "API credential — leak risk, should not be in a form POST"
	case containsAny(s, "jwt", "id_token"):
		return "JWT bearer token"
	case containsAny(s, "token"):
		return "Opaque token — validate server-side, check for replay / reuse"

	// PII
	case containsAny(s, "phone", "mobile", "tel"):
		return "Phone number (PII)"
	case containsAny(s, "address", "street", "city", "zip", "postal"):
		return "Address (PII)"
	case containsAny(s, "ssn", "social_security", "national_id"):
		return "Government identifier — high-sensitivity PII"
	case containsAny(s, "dob", "birthdate", "date_of_birth"):
		return "Date of birth (PII)"
	case containsAny(s, "card", "cvv", "cvc"):
		return "Payment card data — PCI scope"
	}
	return ""
}

// locationHint produces a compact trailing clause like " (query param)"
// so readers can see where the input lives without a second field.
func locationHint(location string) string {
	switch strings.ToLower(location) {
	case "query":
		return " (query param)"
	case "body":
		return " (request body)"
	case "path":
		return " (URL path segment)"
	case "form":
		return "" // form is the default HTML case; no suffix
	}
	return ""
}

// explainLabel appends any useful user-facing label/placeholder context
// without repeating information we've already said.
func explainLabel(label, placeholder string) string {
	if label != "" {
		return ": " + truncateFor(label, 60)
	}
	if placeholder != "" {
		return " (placeholder: " + truncateFor(placeholder, 60) + ")"
	}
	return ""
}

func truncateFor(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
