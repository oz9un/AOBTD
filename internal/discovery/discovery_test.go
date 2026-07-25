package discovery

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/ozzyw/aobtd/internal/store"
)

// TestIsSensitivePath covers the shape-based path classifier. Must NOT
// false-positive on ordinary SPA routes; must catch industry-standard
// sensitive paths.
func TestIsSensitivePath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		// Sensitive — backup extensions
		{"/foo/bar.bak", true},
		{"/config.yml.old", true},
		{"/data.sql.orig", true},
		{"/secret~", true},
		// Sensitive — VCS / credential directories
		{"/.git/config", true},
		{"/.svn/entries", true},
		{"/.env", true},
		{"/.env.production", true},
		{"/.aws/credentials", true},
		{"/.ssh/id_rsa", true},
		{"/actuator/env", true},
		// Sensitive — framework-level config filenames
		{"/path/to/package.json", true},
		{"/web.config", true},
		{"/path/appsettings.json", true},
		{"/id_rsa", true},
		// Not sensitive — ordinary SPA routes
		{"/", false},
		{"/index.html", false},
		{"/about", false},
		{"/login", false},
		{"/api/users", false},
		{"/assets/main.js", false},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			if got := IsSensitivePath(tc.path); got != tc.want {
				t.Errorf("IsSensitivePath(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// TestLooksLikeLoginPath covers the path-shape heuristic used by
// DiscoverLoginEndpoints when the crawler didn't capture a real login
// POST (common on SPAs). Must be permissive enough for real conventions
// but not false-positive on unrelated routes.
func TestLooksLikeLoginPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		// Canonical
		{"/login", true},
		{"/signin", true},
		{"/sign-in", true},
		{"/signup", false}, // signup, not signin
		{"/log-in", true},
		{"/logon", true},
		{"/authenticate", true},
		{"/authentication", true},
		// API / REST conventions
		{"/api/login", true},
		{"/api/auth", true},
		{"/api/signin", true},
		{"/rest/user/login", true},
		{"/user/login", true},
		{"/users/login", true},
		{"/account/login", true},
		// OAuth / token
		{"/oauth/token", true},
		{"/oauth2/token", true},
		{"/auth/token", true},
		{"/auth/session", true},
		// Trailing slash variants
		{"/api/login/", true},
		{"/rest/user/login/", true},
		// Non-matches
		{"/", false},
		{"/index.html", false},
		{"/about", false},
		{"/api/users", false},
		{"/api/products", false},
		{"/dashboard", false},
		{"/logout", false}, // logout, not login
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			if got := LooksLikeLoginPath(tc.path); got != tc.want {
				t.Errorf("LooksLikeLoginPath(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestExtractRequestFieldNamesJSONAndForm(t *testing.T) {
	jsonFields := extractRequestFieldNames([]byte(`{"title":"x","owner_id":2}`), "application/json")
	if !containsString(jsonFields, "title") || !containsString(jsonFields, "owner_id") {
		t.Fatalf("json fields = %v, want title and owner_id", jsonFields)
	}
	formFields := extractRequestFieldNames([]byte(`note=aobtd&displayName=Bob`), "application/x-www-form-urlencoded")
	if !containsString(formFields, "note") || !containsString(formFields, "displayName") {
		t.Fatalf("form fields = %v, want note and displayName", formFields)
	}
}

func TestDiscoverAuthenticatedAPIEndpointsKeepsRequestBodyFields(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "discovery.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}

	_, err = db.Conn().Exec(`
		INSERT INTO traffic (
			scan_id, method, url, host, path, query,
			request_headers, request_body,
			status_code, response_headers, response_body,
			content_type, response_size, endpoint_hash,
			has_auth, is_api, is_filtered
		) VALUES (?, 'PATCH', 'https://example.test/api/orders/2', 'example.test', '/api/orders/2', '',
			'{"Content-Type":"application/json","Authorization":"Bearer t"}', '{"note":"hello","owner_id":2}',
			200, '{}', '{"ok":true}', 'application/json', 11, 'PATCH:/api/orders/{id}',
			TRUE, TRUE, FALSE)`, scanID)
	if err != nil {
		t.Fatalf("insert traffic: %v", err)
	}

	eps, err := DiscoverAuthenticatedAPIEndpoints(db, scanID)
	if err != nil {
		t.Fatalf("DiscoverAuthenticatedAPIEndpoints: %v", err)
	}
	if len(eps) != 1 {
		t.Fatalf("endpoints = %+v, want one", eps)
	}
	if eps[0].RequestContentType != "application/json" {
		t.Fatalf("request content-type = %q", eps[0].RequestContentType)
	}
	if !containsString(eps[0].BodyFields, "note") || !containsString(eps[0].BodyFields, "owner_id") {
		t.Fatalf("body fields = %v, want note and owner_id", eps[0].BodyFields)
	}
}

func TestDiscoverRecoveredObjectIDEndpointsFromJWTBid(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "discovery-recovered.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://shop.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}

	token := testJWT(map[string]any{
		"data": map[string]any{"id": 1, "email": "admin@example.test"},
		"bid":  1,
	})
	headers := `{"Authorization":"Bearer ` + token + `","Accept":"application/json"}`
	_, err = db.Conn().Exec(`
		INSERT INTO traffic (
			scan_id, method, url, host, path, query,
			request_headers, request_body,
			status_code, response_headers, response_body,
			content_type, response_size, endpoint_hash,
			has_auth, is_api, is_filtered
		) VALUES (?, 'GET', 'https://shop.example.test/rest/basket/NaN', 'shop.example.test', '/rest/basket/NaN', '',
			?, '',
			200, '{}', '{"status":"success","data":null}',
			'application/json', 32, 'GET:/rest/basket/{id}',
			TRUE, TRUE, FALSE)`, scanID, headers)
	if err != nil {
		t.Fatalf("insert traffic: %v", err)
	}

	eps, err := DiscoverRecoveredObjectIDEndpoints(db, scanID, 10)
	if err != nil {
		t.Fatalf("DiscoverRecoveredObjectIDEndpoints: %v", err)
	}
	if len(eps) != 1 {
		t.Fatalf("endpoints = %+v, want one recovered endpoint", eps)
	}
	if eps[0].URL != "https://shop.example.test/rest/basket/1" || eps[0].Path != "/rest/basket/1" {
		t.Fatalf("recovered endpoint = %+v, want /rest/basket/1", eps[0])
	}
	if got := eps[0].AuthHeaders["Authorization"]; got != "Bearer "+token {
		t.Fatalf("recovered auth header = %q, want bearer token", got)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func testJWT(payload map[string]any) string {
	headerBytes, _ := json.Marshal(map[string]any{"typ": "JWT", "alg": "none"})
	payloadBytes, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(headerBytes) + "." +
		base64.RawURLEncoding.EncodeToString(payloadBytes) + ".sig"
}
