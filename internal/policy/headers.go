package policy

import (
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/net/http/httpguts"
)

// Headers that would break request framing or routing if overridden.
var forbiddenInjectedHeaders = map[string]bool{
	"Host":              true,
	"Content-Length":    true,
	"Transfer-Encoding": true,
	"Connection":        true,
}

// ParseHeaders turns "Name: value" lines into an http.Header.
func ParseHeaders(lines []string) (http.Header, error) {
	out := http.Header{}
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if !ok || !httpguts.ValidHeaderFieldName(name) {
			// Don't echo the line: it may hold the token.
			return nil, fmt.Errorf("header line %d: want \"Name: value\"", i+1)
		}
		if !httpguts.ValidHeaderFieldValue(value) {
			return nil, fmt.Errorf("invalid value for header %q", name)
		}
		name = http.CanonicalHeaderKey(name)
		if forbiddenInjectedHeaders[name] {
			return nil, fmt.Errorf("header %q cannot be set", name)
		}
		out.Add(name, value)
	}
	return out, nil
}

// SetInjectedHeaders binds headers to the target's origin. Call before the
// scan starts. Like other credentials, they never cross to another origin.
func (e *Engine) SetInjectedHeaders(targetURL string, headers http.Header) error {
	if len(headers) == 0 {
		return nil
	}
	origin, err := CanonicalOrigin(targetURL)
	if err != nil {
		return fmt.Errorf("custom headers need a concrete target URL: %w", err)
	}
	e.headerOrigin = origin
	e.headers = headers.Clone()
	return nil
}

// WithInjectedHeaders returns req with the operator headers added when it
// targets the bound origin, cloning only if something is added. Headers already
// on the request win, so probes that set their own Authorization (e.g. a second
// BOLA persona) are left untouched.
func (e *Engine) WithInjectedHeaders(req *http.Request) *http.Request {
	if e == nil || len(e.headers) == 0 || req == nil || req.URL == nil {
		return req
	}
	rawURL, err := absoluteRequestURL(req)
	if err != nil {
		return req
	}
	if origin, err := CanonicalOrigin(rawURL); err != nil || origin != e.headerOrigin {
		return req
	}
	var out *http.Request
	for name, values := range e.headers {
		if _, exists := req.Header[name]; exists {
			continue
		}
		if out == nil {
			out = req.Clone(req.Context()) // never mutate the caller's request
			if out.Header == nil {
				out.Header = http.Header{}
			}
		}
		out.Header[name] = append([]string(nil), values...)
	}
	if out == nil {
		return req
	}
	return out
}
