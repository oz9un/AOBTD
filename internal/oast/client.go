// Package oast implements the scanner-side client for AOBTD's controlled
// out-of-band HTTP callback service.
package oast

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	EnvBaseURL    = "AOBTD_OAST_BASE_URL"
	EnvAPIToken   = "AOBTD_OAST_API_TOKEN"
	EnvSigningKey = "AOBTD_OAST_SIGNING_KEY"
)

type Client struct {
	baseURL    string
	apiToken   string
	signingKey string
	httpClient *http.Client
	pollEvery  time.Duration
}

type Event struct {
	ID           int64             `json:"id"`
	ReceivedAtMS int64             `json:"received_at_ms"`
	Method       string            `json:"method"`
	Path         string            `json:"path"`
	RawQuery     string            `json:"raw_query"`
	SourceIP     string            `json:"source_ip"`
	Colo         string            `json:"colo"`
	Headers      map[string]string `json:"headers"`
}

type pollResponse struct {
	ProbeToken string  `json:"probe_token"`
	Events     []Event `json:"events"`
}

func FromEnv() (*Client, error) {
	baseURL := strings.TrimSpace(os.Getenv(EnvBaseURL))
	apiToken := os.Getenv(EnvAPIToken)
	signingKey := os.Getenv(EnvSigningKey)
	if baseURL == "" && apiToken == "" && signingKey == "" {
		return nil, nil
	}
	return New(baseURL, apiToken, signingKey, nil)
}

func New(baseURL, apiToken, signingKey string, httpClient *http.Client) (*Client, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" || apiToken == "" || signingKey == "" {
		return nil, fmt.Errorf("OAST requires %s, %s, and %s", EnvBaseURL, EnvAPIToken, EnvSigningKey)
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid OAST base URL %q", baseURL)
	}
	if parsed.Scheme != "https" && !isLoopbackHost(parsed.Hostname()) {
		return nil, fmt.Errorf("OAST base URL must use HTTPS outside loopback")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 8 * time.Second}
	}
	return &Client{
		baseURL: baseURL, apiToken: apiToken, signingKey: signingKey,
		httpClient: httpClient, pollEvery: time.Second,
	}, nil
}

func (c *Client) NewProbe() (token, callbackURL string, err error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", "", fmt.Errorf("generate OAST probe id: %w", err)
	}
	randomHex := hex.EncodeToString(random)
	mac := hmac.New(sha256.New, []byte(c.signingKey))
	_, _ = mac.Write([]byte(randomHex))
	signature := hex.EncodeToString(mac.Sum(nil))[:32]
	token = "v1." + randomHex + "." + signature
	return token, c.baseURL + "/c/" + token, nil
}

func (c *Client) WaitForEvent(ctx context.Context, token string, after time.Time, wait time.Duration) (*Event, error) {
	if wait <= 0 {
		wait = 12 * time.Second
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	ticker := time.NewTicker(c.pollEvery)
	defer ticker.Stop()

	for {
		events, err := c.Events(ctx, token, after)
		if err != nil {
			return nil, err
		}
		if len(events) > 0 {
			return &events[0], nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, nil
		case <-ticker.C:
		}
	}
}

func (c *Client) Events(ctx context.Context, token string, after time.Time) ([]Event, error) {
	pollURL := fmt.Sprintf("%s/api/v1/probes/%s/events?after=%d",
		c.baseURL, url.PathEscape(token), after.UnixMilli())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pollURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "AOBTD/OAST poller")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("poll OAST service: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("poll OAST service: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var payload pollResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("decode OAST response: %w", err)
	}
	if payload.ProbeToken != token {
		return nil, fmt.Errorf("OAST response token mismatch")
	}
	return payload.Events, nil
}

func isLoopbackHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
