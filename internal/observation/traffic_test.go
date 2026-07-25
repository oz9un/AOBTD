package observation

import (
	"testing"
	"time"

	"github.com/ozzyw/aobtd/pkg/types"
)

func TestNormalizeFillsCanonicalObservationFields(t *testing.T) {
	entry := &types.TrafficEntry{
		Request: types.CapturedRequest{
			Method: " get ",
			URL:    "https://api.example.test/orders/42?expand=items",
		},
		Response: types.CapturedResponse{
			Headers: map[string]string{"content-type": "application/json; charset=utf-8"},
			Body:    []byte(`{"id":42}`),
		},
	}

	before := time.Now().UTC()
	if err := Normalize(entry); err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if entry.Request.Method != "GET" {
		t.Errorf("method = %q, want GET", entry.Request.Method)
	}
	if entry.Request.Host != "api.example.test" {
		t.Errorf("host = %q, want api.example.test", entry.Request.Host)
	}
	if entry.Request.Path != "/orders/42" {
		t.Errorf("path = %q, want /orders/42", entry.Request.Path)
	}
	if entry.Request.Query != "expand=items" {
		t.Errorf("query = %q, want expand=items", entry.Request.Query)
	}
	if entry.Response.ContentType != "application/json; charset=utf-8" {
		t.Errorf("content type = %q", entry.Response.ContentType)
	}
	if entry.Response.Size != int64(len(entry.Response.Body)) {
		t.Errorf("response size = %d, want %d", entry.Response.Size, len(entry.Response.Body))
	}
	if entry.EndpointHash == "" {
		t.Error("endpoint hash is blank")
	}
	if entry.Timestamp.Before(before) || entry.Request.Timestamp != entry.Timestamp {
		t.Errorf("timestamps were not canonicalized: entry=%v request=%v", entry.Timestamp, entry.Request.Timestamp)
	}
	if entry.Request.Headers == nil || entry.Response.Headers == nil {
		t.Error("header maps must be non-nil")
	}
}

func TestEndpointHashNormalizesIDsAndQueryValues(t *testing.T) {
	first := EndpointHash("GET", "https://example.test/orders/41?view=compact&expand=items")
	second := EndpointHash("get", "https://example.test/orders/99?expand=other&view=full")
	if first != second {
		t.Fatalf("equivalent endpoint hashes differ: %q != %q", first, second)
	}

	differentShape := EndpointHash("GET", "https://example.test/orders/99?view=full")
	if first == differentShape {
		t.Fatal("different query parameter shapes produced the same hash")
	}
}

func TestEndpointHashPreservesReadableLongSegments(t *testing.T) {
	applicationConfig := EndpointHash("GET", "https://example.test/rest/admin/application-configuration")
	privacyConfig := EndpointHash("GET", "https://example.test/rest/admin/privacy-policy-configuration")
	if applicationConfig == privacyConfig {
		t.Fatal("distinct readable route names collapsed to one endpoint hash")
	}

	firstToken := EndpointHash("GET", "https://example.test/session/dGhpcy1pc19hX2xvbmdfdG9rZW4")
	secondToken := EndpointHash("GET", "https://example.test/session/01J2Z7W3K9M8N6P4Q5R7S8T9UV")
	if firstToken != secondToken {
		t.Fatal("opaque values in the same path position did not normalize together")
	}
}

func TestIsOpaquePathSegment(t *testing.T) {
	tests := []struct {
		segment string
		want    bool
	}{
		{segment: "application-configuration", want: false},
		{segment: "discovery-storefrontmarketing-marketinggw-service", want: false},
		{segment: "customeraccountpreferences", want: false},
		{segment: "dGhpcy1pc19hX2xvbmdfdG9rZW4", want: true},
		{segment: "01J2Z7W3K9M8N6P4Q5R7S8T9UV", want: true},
		{segment: "6f5902ac237024bdd0c176cb93063dc4", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.segment, func(t *testing.T) {
			if got := IsOpaquePathSegment(tt.segment); got != tt.want {
				t.Fatalf("IsOpaquePathSegment(%q) = %v, want %v", tt.segment, got, tt.want)
			}
		})
	}
}

func TestIsInvalidPathIdentifier(t *testing.T) {
	tests := []struct {
		segment string
		want    bool
	}{
		{segment: "NaN", want: true},
		{segment: "undefined", want: true},
		{segment: "null", want: true},
		{segment: "%5Bobject%20Object%5D", want: true},
		{segment: "7", want: false},
		{segment: "application-configuration", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.segment, func(t *testing.T) {
			if got := IsInvalidPathIdentifier(tt.segment); got != tt.want {
				t.Fatalf("IsInvalidPathIdentifier(%q) = %v, want %v", tt.segment, got, tt.want)
			}
		})
	}
}

func TestEndpointHashSeparatesOrigins(t *testing.T) {
	app := EndpointHash("GET", "https://app.example.test/orders/41?expand=items")
	api := EndpointHash("GET", "https://api.example.test/orders/41?expand=items")
	if app == api {
		t.Fatal("same path on different origins produced the same endpoint hash")
	}

	httpsDefault := EndpointHash("get", "HTTPS://EXAMPLE.TEST/orders/99?expand=other")
	httpsExplicit := EndpointHash("GET", "https://example.test:443/orders/41?expand=items")
	if httpsDefault != httpsExplicit {
		t.Fatalf("equivalent default-port origins differ: %q != %q", httpsDefault, httpsExplicit)
	}

	nonDefault := EndpointHash("GET", "https://example.test:8443/orders/41?expand=items")
	if httpsDefault == nonDefault {
		t.Fatal("non-default port was not included in endpoint identity")
	}

	plainHTTP := EndpointHash("GET", "http://example.test/orders/41?expand=items")
	if httpsDefault == plainHTTP {
		t.Fatal("HTTP and HTTPS origins produced the same endpoint hash")
	}
}

func TestEndpointHashSeparatesInvalidPlaceholderFromRealIDs(t *testing.T) {
	invalid := EndpointHash("GET", "https://example.test/rest/basket/NaN")
	real := EndpointHash("GET", "https://example.test/rest/basket/7")
	if invalid == real {
		t.Fatal("invalid client-side sentinel collapsed into real resource-id endpoint")
	}
	alsoInvalid := EndpointHash("GET", "https://example.test/rest/basket/undefined")
	if invalid != alsoInvalid {
		t.Fatal("invalid sentinel identifiers should deduplicate together")
	}
}


func TestCanonicalOrigin(t *testing.T) {
	tests := map[string]string{
		"https://EXAMPLE.test/path":        "https://example.test:443",
		"https://example.test:443/path":    "https://example.test:443",
		"http://example.test/path":         "http://example.test:80",
		"http://example.test:8080/path":    "http://example.test:8080",
		"https://[2001:db8::1]/path":       "https://[2001:db8::1]:443",
		"wss://socket.example.test/events": "wss://socket.example.test:443",
	}
	for rawURL, want := range tests {
		if got := CanonicalOrigin(rawURL); got != want {
			t.Errorf("CanonicalOrigin(%q) = %q, want %q", rawURL, got, want)
		}
	}
}

func TestNormalizeRejectsIncompleteIdentity(t *testing.T) {
	tests := []struct {
		name  string
		entry *types.TrafficEntry
	}{
		{name: "nil", entry: nil},
		{name: "method", entry: &types.TrafficEntry{Request: types.CapturedRequest{URL: "https://example.test/"}}},
		{name: "url", entry: &types.TrafficEntry{Request: types.CapturedRequest{Method: "GET"}}},
		{name: "host", entry: &types.TrafficEntry{Request: types.CapturedRequest{Method: "GET", URL: "https:///missing-host"}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Normalize(tt.entry); err == nil {
				t.Fatal("Normalize() error = nil, want error")
			}
		})
	}
}

func TestNormalizeRepairsInconsistentProducerIdentity(t *testing.T) {
	entry := &types.TrafficEntry{
		Request: types.CapturedRequest{
			Method: "get",
			URL:    "https://api.example.test/orders/42?expand=owner",
			Host:   "attacker.invalid",
			Path:   "/wrong",
			Query:  "wrong=true",
		},
		EndpointHash: "producer-controlled-hash",
	}

	if err := Normalize(entry); err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if entry.Request.Host != "api.example.test" || entry.Request.Path != "/orders/42" || entry.Request.Query != "expand=owner" {
		t.Fatalf("identity was not repaired: host=%q path=%q query=%q", entry.Request.Host, entry.Request.Path, entry.Request.Query)
	}
	wantHash := EndpointHash("GET", entry.Request.URL)
	if entry.EndpointHash != wantHash {
		t.Fatalf("endpoint hash = %q, want canonical %q", entry.EndpointHash, wantHash)
	}
}
