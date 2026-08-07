package target

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

const canonicalResolveTimeout = 8 * time.Second

// ResolveCanonical follows the target's initial redirect chain without
// credentials and returns the canonical landing URL. Redirects are limited to
// the exact host or its conventional apex <-> www alias. This lets a target
// such as https://example.com establish https://www.example.com as its real
// scan origin without turning every sibling subdomain into active scope.
func ResolveCanonical(ctx context.Context, raw string) (string, error) {
	client := &http.Client{Timeout: canonicalResolveTimeout}
	return resolveCanonicalWithClient(ctx, raw, client)
}

func resolveCanonicalWithClient(ctx context.Context, raw string, base *http.Client) (string, error) {
	start, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || start.Scheme == "" || start.Host == "" {
		return "", fmt.Errorf("invalid target URL %q", raw)
	}
	if start.Scheme != "http" && start.Scheme != "https" {
		return "", fmt.Errorf("unsupported target scheme %q", start.Scheme)
	}

	client := *base
	previousRedirect := base.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 6 {
			return fmt.Errorf("too many canonical target redirects")
		}
		if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
			return fmt.Errorf("canonical target redirect uses unsupported scheme %q", req.URL.Scheme)
		}
		if !CanonicalWebAlias(start.Hostname(), req.URL.Hostname()) {
			return fmt.Errorf("canonical target redirect left apex/www boundary: %s", req.URL.Redacted())
		}
		if previousRedirect != nil {
			return previousRedirect(req, via)
		}
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, start.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "AOBTD/1.0 canonical-target-resolution")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.Request == nil || resp.Request.URL == nil {
		return start.String(), nil
	}
	if shouldRecoverAuthStart(start, resp.Request.URL) {
		if recovered, ok := recoverAuthStartCandidate(ctx, resp.Request.URL, &client); ok {
			return recovered, nil
		}
	}
	return resp.Request.URL.String(), nil
}

func shouldRecoverAuthStart(start, landed *url.URL) bool {
	if start == nil || landed == nil {
		return false
	}
	if start.Path != "" && start.Path != "/" {
		return false
	}
	return looksLikeAuthDeadEnd(landed.Path)
}

func looksLikeAuthDeadEnd(path string) bool {
	path = strings.ToLower(strings.TrimSpace(path))
	if path == "" {
		return false
	}
	deadEnds := []string{
		"/logout",
		"/log-out",
		"/signout",
		"/sign-out",
		"/auth/logout",
		"/auth/signout",
		"/auth/signed-out",
		"/signed-out",
	}
	for _, marker := range deadEnds {
		if path == marker || strings.HasPrefix(path, marker+"/") {
			return true
		}
	}
	return false
}

func recoverAuthStartCandidate(ctx context.Context, landed *url.URL, client *http.Client) (string, bool) {
	if landed == nil || client == nil {
		return "", false
	}
	candidates := []string{
		"/auth/login",
		"/login",
		"/signin",
		"/sign-in",
		"/account/login",
	}
	for _, path := range candidates {
		candidate := *landed
		candidate.Path = path
		candidate.RawPath = ""
		candidate.RawQuery = ""
		candidate.Fragment = ""
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, candidate.String(), nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "AOBTD/1.0 auth-start-recovery")
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		finalURL := candidate.String()
		if resp.Request != nil && resp.Request.URL != nil {
			finalURL = resp.Request.URL.String()
		}
		status := resp.StatusCode
		_ = resp.Body.Close()
		if status >= 200 && status < 400 {
			parsed, err := url.Parse(finalURL)
			if err == nil && parsed.Hostname() == landed.Hostname() && !looksLikeAuthDeadEnd(parsed.Path) {
				return parsed.String(), true
			}
		}
	}
	return "", false
}

// CanonicalWebAlias reports whether two hosts are the same host or the
// conventional apex/www pair for one registrable domain. Other subdomains are
// deliberately excluded.
func CanonicalWebAlias(left, right string) bool {
	left = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(left), "."))
	right = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(right), "."))
	if left == "" || right == "" {
		return false
	}
	if left == right {
		return true
	}

	leftRoot, leftOK := apexOrWWWRoot(left)
	rightRoot, rightOK := apexOrWWWRoot(right)
	return leftOK && rightOK && leftRoot == rightRoot
}

// RegistrableDomain returns the public-suffix-aware root domain for a target
// URL. IP addresses and single-label development hosts intentionally return an
// error because a wildcard subdomain scope would be ambiguous for them.
func RegistrableDomain(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() == "" {
		return "", fmt.Errorf("invalid target URL %q", raw)
	}
	root, err := publicsuffix.EffectiveTLDPlusOne(strings.ToLower(parsed.Hostname()))
	if err != nil {
		return "", fmt.Errorf("target has no registrable domain: %w", err)
	}
	return root, nil
}

// IsIPLiteral reports whether a target URL names an IPv4 or IPv6 address.
// IP literals are concrete hosts and cannot establish a wildcard subdomain
// boundary for Smart discovery.
func IsIPLiteral(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() == "" {
		return false
	}
	return net.ParseIP(strings.Trim(parsed.Hostname(), "[]")) != nil
}

func apexOrWWWRoot(host string) (string, bool) {
	registrable, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return "", false
	}
	if host == registrable || host == "www."+registrable {
		return registrable, true
	}
	return "", false
}
