package store

import (
	"path/filepath"
	"testing"

	"github.com/ozzyw/aobtd/pkg/types"
)

func TestBestCredentialHeadersReusesSameOriginBearer(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "auth-context.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://app.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.InsertTraffic(scanID, &types.TrafficEntry{
		Request: types.CapturedRequest{
			Method: "GET",
			URL:    "https://app.example.test/api/orders",
			Host:   "app.example.test",
			Path:   "/api/orders",
			Headers: map[string]string{
				"Authorization": "Bearer observed-token",
				"Accept":        "application/json",
			},
		},
		Response: types.CapturedResponse{
			StatusCode:  200,
			ContentType: "application/json",
			Body:        []byte(`[]`),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	headers, source, err := db.BestCredentialHeaders(scanID, "https://app.example.test/api/users")
	if err != nil {
		t.Fatal(err)
	}
	if headers["Authorization"] != "Bearer observed-token" {
		t.Fatalf("Authorization = %q, want observed bearer (headers=%v)", headers["Authorization"], headers)
	}
	if source != "https://app.example.test/api/orders" {
		t.Fatalf("source = %q", source)
	}
}

func TestBestCredentialHeadersPrefersExplicitCredentialContext(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "auth-context.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://app.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.InsertTraffic(scanID, &types.TrafficEntry{
		Request: types.CapturedRequest{
			Method:  "GET",
			URL:     "https://app.example.test/api/orders",
			Host:    "app.example.test",
			Path:    "/api/orders",
			Headers: map[string]string{"Authorization": "Bearer observed-token"},
		},
		Response: types.CapturedResponse{StatusCode: 200, ContentType: "application/json", Body: []byte(`[]`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.RecordCredentialHeaders(scanID, "https://app.example.test/", map[string]string{
		"Authorization": "Bearer api-login-token",
	}, "api_login:https://app.example.test/login"); err != nil {
		t.Fatal(err)
	}

	headers, source, err := db.BestCredentialHeaders(scanID, "https://app.example.test/api/users")
	if err != nil {
		t.Fatal(err)
	}
	if headers["Authorization"] != "Bearer api-login-token" {
		t.Fatalf("Authorization = %q, want explicit API-login bearer (headers=%v)", headers["Authorization"], headers)
	}
	if source != "api_login:https://app.example.test/login" {
		t.Fatalf("source = %q", source)
	}
}

func TestBestCredentialHeadersDoesNotCrossOrigin(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "auth-context.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://app.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.InsertTraffic(scanID, &types.TrafficEntry{
		Request: types.CapturedRequest{
			Method:  "GET",
			URL:     "https://app.example.test/api/orders",
			Host:    "app.example.test",
			Path:    "/api/orders",
			Headers: map[string]string{"Authorization": "Bearer observed-token"},
		},
		Response: types.CapturedResponse{StatusCode: 200, ContentType: "application/json", Body: []byte(`[]`)},
	})
	if err != nil {
		t.Fatal(err)
	}

	headers, source, err := db.BestCredentialHeaders(scanID, "https://evil.example.test/api/users")
	if err != nil {
		t.Fatal(err)
	}
	if len(headers) != 0 || source != "" {
		t.Fatalf("cross-origin headers = %v source=%q, want none", headers, source)
	}
}

func TestCredentialHeadersKeepsAuthLikelyCookie(t *testing.T) {
	got := CredentialHeaders(map[string]string{
		"Cookie": "theme=dark; connect.sid=s%3Aabc",
	})
	if got["Cookie"] == "" {
		t.Fatalf("auth-like cookie was not retained: %v", got)
	}
	if noisy := CredentialHeaders(map[string]string{
		"Cookie": "utm=1; locale=en-US",
	}); len(noisy) != 0 {
		t.Fatalf("analytics-style cookie should be ignored: %v", noisy)
	}
}
