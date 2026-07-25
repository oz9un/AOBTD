package ask

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ozzyw/aobtd/internal/policy"
)

// ReplayResult is the outcome of issuing one live HTTP request.
type ReplayResult struct {
	StatusCode  int    `json:"status_code"`
	DurationMs  int64  `json:"duration_ms"`
	BodySize    int    `json:"body_size"`
	RawResponse string `json:"raw_response"`
}

// BuildRawRequest renders a structured request into a raw HTTP/1.1 request
// string — the exact bytes the pentester sees and approves before it's sent.
func BuildRawRequest(method, target string, headers map[string]string, body string) (string, error) {
	if method == "" {
		method = "GET"
	}
	u, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("invalid target url: %w", err)
	}
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", strings.ToUpper(method), path)
	fmt.Fprintf(&b, "Host: %s\r\n", u.Host)
	for k, v := range headers {
		if strings.EqualFold(k, "host") || strings.EqualFold(k, "content-length") {
			continue
		}
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.String(), nil
}

// ExecuteRawRequest issues the request to target and returns the raw
// response. Mirrors the UI repeater's behavior (TLS-insecure, 30s timeout,
// 512KB body cap, redirect-limited) so replays from the Ask worker behave
// identically to manual repeater sends.
func ExecuteRawRequest(ctx context.Context, method, target string, headers map[string]string, body string,
	executionPolicy *policy.Engine, credentialOrigin string, audit policy.DecisionAudit,
) (*ReplayResult, error) {
	httpReq, err := http.NewRequestWithContext(ctx, strings.ToUpper(method), target, bytes.NewBufferString(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	for k, v := range headers {
		if strings.EqualFold(k, "host") || strings.EqualFold(k, "content-length") {
			continue
		}
		httpReq.Header.Set(k, v)
	}

	baseClient := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
	client := policy.ProtectHTTPClient(baseClient, executionPolicy, policy.HTTPOptions{
		CredentialOrigin: credentialOrigin,
		Audit:            audit,
	})

	start := time.Now()
	resp, err := client.Do(httpReq)
	dur := time.Since(start).Milliseconds()
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))

	var raw strings.Builder
	fmt.Fprintf(&raw, "HTTP/%d.%d %s\r\n", resp.ProtoMajor, resp.ProtoMinor, resp.Status)
	for k, vals := range resp.Header {
		for _, v := range vals {
			fmt.Fprintf(&raw, "%s: %s\r\n", k, v)
		}
	}
	raw.WriteString("\r\n")
	raw.Write(respBody)

	return &ReplayResult{
		StatusCode:  resp.StatusCode,
		DurationMs:  dur,
		BodySize:    len(respBody),
		RawResponse: raw.String(),
	}, nil
}
