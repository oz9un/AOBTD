package target

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestCanonicalWebAlias(t *testing.T) {
	tests := []struct {
		left, right string
		want        bool
	}{
		{"audemarspiguet.com", "www.audemarspiguet.com", true},
		{"www.example.co.uk", "example.co.uk", true},
		{"www.example.com", "www.example.com", true},
		{"example.com", "dynamicmedia.example.com", false},
		{"app.example.com", "www.app.example.com", false},
		{"example.com", "example.net", false},
	}
	for _, tt := range tests {
		if got := CanonicalWebAlias(tt.left, tt.right); got != tt.want {
			t.Errorf("CanonicalWebAlias(%q, %q) = %v, want %v", tt.left, tt.right, got, tt.want)
		}
	}
}

func TestRegistrableDomain(t *testing.T) {
	for raw, want := range map[string]string{
		"https://www.example.com/path": "example.com",
		"https://api.example.co.uk":    "example.co.uk",
	} {
		got, err := RegistrableDomain(raw)
		if err != nil {
			t.Fatalf("RegistrableDomain(%q): %v", raw, err)
		}
		if got != want {
			t.Errorf("RegistrableDomain(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestResolveCanonicalAllowsApexToWWW(t *testing.T) {
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "example.com" {
			return &http.Response{
				StatusCode: http.StatusMovedPermanently,
				Header:     http.Header{"Location": []string{"https://www.example.com/home"}},
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    req,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("ok")),
			Request:    req,
		}, nil
	})

	got, err := resolveCanonicalWithClient(context.Background(), "http://example.com", &http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://www.example.com/home" {
		t.Fatalf("resolved target = %q", got)
	}
}

func TestResolveCanonicalRecoversAuthLoginFromLogoutDeadEnd(t *testing.T) {
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "", "/":
			return &http.Response{
				StatusCode: http.StatusFound,
				Header:     http.Header{"Location": []string{"https://partner.example.test/auth/logout?redirect=%2F"}},
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    req,
			}, nil
		case "/auth/logout":
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("logout")),
				Request:    req,
			}, nil
		case "/auth/login":
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("login")),
				Request:    req,
			}, nil
		default:
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("missing")),
				Request:    req,
			}, nil
		}
	})

	got, err := resolveCanonicalWithClient(context.Background(), "https://partner.example.test", &http.Client{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://partner.example.test/auth/login" {
		t.Fatalf("resolved target = %q", got)
	}
}

func TestResolveCanonicalRejectsSiblingSubdomain(t *testing.T) {
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": []string{"https://dynamicmedia.example.com/asset"}},
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}, nil
	})

	_, err := resolveCanonicalWithClient(context.Background(), "https://example.com", &http.Client{Transport: transport})
	if err == nil || !strings.Contains(err.Error(), "apex/www boundary") {
		t.Fatalf("error = %v, want apex/www boundary denial", err)
	}
}
