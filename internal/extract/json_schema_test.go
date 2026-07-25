package extract

import (
	"strings"
	"testing"
)

// TestExtractJSONSchema_FlatObject — basic type inference on primitive values.
func TestExtractJSONSchema_FlatObject(t *testing.T) {
	body := `{
  "id": 42,
  "email": "alice@example.com",
  "name": "Alice",
  "active": true,
  "balance": 19.95,
  "avatar": null
}`

	schema := ExtractJSONSchema([]byte(body))
	if schema == nil {
		t.Fatal("got nil schema")
	}

	shape, ok := schema.Shape.(map[string]any)
	if !ok {
		t.Fatalf("Shape: got %T, want map[string]any", schema.Shape)
	}

	if shape["id"] != "int" {
		t.Errorf("id: got %v, want int", shape["id"])
	}
	if shape["email"] != "email" {
		t.Errorf("email: got %v, want email", shape["email"])
	}
	if shape["name"] != "string" {
		t.Errorf("name: got %v, want string", shape["name"])
	}
	if shape["active"] != "bool" {
		t.Errorf("active: got %v, want bool", shape["active"])
	}
	if shape["balance"] != "float" {
		t.Errorf("balance: got %v, want float", shape["balance"])
	}
	if shape["avatar"] != "null" {
		t.Errorf("avatar: got %v, want null", shape["avatar"])
	}

	if schema.TotalFields != 6 {
		t.Errorf("TotalFields: got %d, want 6", schema.TotalFields)
	}

	// email field name is sensitive
	foundEmail := false
	for _, f := range schema.SensitiveFields {
		if f == "email" {
			foundEmail = true
		}
	}
	if !foundEmail {
		t.Errorf("SensitiveFields should contain 'email', got %v", schema.SensitiveFields)
	}
}

// TestExtractJSONSchema_NestedObject — nested structure with dot-path
// sensitive field reporting.
func TestExtractJSONSchema_NestedObject(t *testing.T) {
	body := `{
  "user": {
    "id": 1,
    "credentials": {
      "password": "hunter2",
      "api_key": "sk-xxx"
    }
  }
}`

	schema := ExtractJSONSchema([]byte(body))
	if schema == nil {
		t.Fatal("got nil schema")
	}

	// Both password and api_key should be reported with full paths
	wantPaths := []string{
		"user.credentials.password",
		"user.credentials.api_key",
		"user.credentials", // matches "key" substring? No — let's check
	}
	// credentials does not contain any sensitive pattern directly, so we
	// only expect password and api_key. But "key" is a sensitive pattern
	// so "api_key" matches twice effectively (it contains "key" and is "api_key").
	// Just assert the two obvious ones are present.
	_ = wantPaths

	hasPath := func(p string) bool {
		for _, f := range schema.SensitiveFields {
			if f == p {
				return true
			}
		}
		return false
	}

	if !hasPath("user.credentials.password") {
		t.Errorf("missing password path, got %v", schema.SensitiveFields)
	}
	if !hasPath("user.credentials.api_key") {
		t.Errorf("missing api_key path, got %v", schema.SensitiveFields)
	}
}

// TestExtractJSONSchema_Arrays — arrays extract shape from first element;
// ArrayCounts records the observed length.
func TestExtractJSONSchema_Arrays(t *testing.T) {
	body := `{
  "users": [
    {"id": 1, "email": "a@b.com"},
    {"id": 2, "email": "c@d.com"},
    {"id": 3, "email": "e@f.com"}
  ],
  "tags": ["admin", "user", "guest"]
}`

	schema := ExtractJSONSchema([]byte(body))
	if schema == nil {
		t.Fatal("got nil schema")
	}

	if schema.ArrayCounts["users"] != 3 {
		t.Errorf("users array count: got %d, want 3", schema.ArrayCounts["users"])
	}
	if schema.ArrayCounts["tags"] != 3 {
		t.Errorf("tags array count: got %d, want 3", schema.ArrayCounts["tags"])
	}

	// sensitive field inside array element should report with [] path
	foundEmail := false
	for _, f := range schema.SensitiveFields {
		if strings.Contains(f, "users[].email") {
			foundEmail = true
		}
	}
	if !foundEmail {
		t.Errorf("email inside users[] not flagged: %v", schema.SensitiveFields)
	}
}

// TestExtractJSONSchema_EmptyArray — empty arrays shouldn't crash; shape
// becomes ["empty_array"] sentinel.
func TestExtractJSONSchema_EmptyArray(t *testing.T) {
	body := `{"items": []}`
	schema := ExtractJSONSchema([]byte(body))
	if schema == nil {
		t.Fatal("got nil schema")
	}
	if schema.ArrayCounts["items"] != 0 {
		t.Errorf("items count: got %d, want 0", schema.ArrayCounts["items"])
	}
}

// TestExtractJSONSchema_TypeInference — uuid, url, jwt, datetime.
func TestExtractJSONSchema_TypeInference(t *testing.T) {
	body := `{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "avatar": "https://cdn.example.com/a.png",
  "session": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123",
  "created_at": "2024-01-15T10:30:00Z"
}`

	schema := ExtractJSONSchema([]byte(body))
	if schema == nil {
		t.Fatal("got nil schema")
	}
	shape := schema.Shape.(map[string]any)

	if shape["id"] != "uuid" {
		t.Errorf("id: got %v, want uuid", shape["id"])
	}
	if shape["avatar"] != "url" {
		t.Errorf("avatar: got %v, want url", shape["avatar"])
	}
	if shape["session"] != "jwt" {
		t.Errorf("session: got %v, want jwt", shape["session"])
	}
	if shape["created_at"] != "datetime" {
		t.Errorf("created_at: got %v, want datetime", shape["created_at"])
	}
}

// TestExtractJSONSchema_MalformedJSON — returns nil, doesn't panic.
func TestExtractJSONSchema_MalformedJSON(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"empty", ""},
		{"not-json", "hello world"},
		{"broken", `{"a": 1,}`}, // trailing comma
		{"unclosed", `{"a": 1`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic: %v", r)
				}
			}()
			schema := ExtractJSONSchema([]byte(c.body))
			if schema != nil {
				t.Errorf("expected nil for malformed %q, got %+v", c.name, schema)
			}
		})
	}
}

// TestExtractJSONSchema_SensitivePatterns — ensures all listed patterns
// actually flag their fields.
func TestExtractJSONSchema_SensitivePatterns(t *testing.T) {
	// One field per sensitive pattern
	body := `{
  "email": "x",
  "phone": "x",
  "password": "x",
  "ssn": "x",
  "token": "x",
  "secret": "x",
  "api_key": "x",
  "credit_card": "x",
  "session_id": "x",
  "dob": "x",
  "home_address": "x",
  "iban": "x"
}`
	schema := ExtractJSONSchema([]byte(body))
	if schema == nil {
		t.Fatal("got nil")
	}
	// Each of those field names matches at least one sensitive pattern.
	// We expect all 12 paths in SensitiveFields.
	if len(schema.SensitiveFields) != 12 {
		t.Errorf("SensitiveFields count: got %d, want 12\n  got: %v",
			len(schema.SensitiveFields), schema.SensitiveFields)
	}
}

// TestRenderSchema — output is non-empty and includes sensitive fields line.
func TestRenderSchema(t *testing.T) {
	body := `{"email": "a@b.com", "id": 1}`
	schema := ExtractJSONSchema([]byte(body))

	out := RenderSchema(schema)
	if out == "" {
		t.Fatal("empty render")
	}
	if !strings.Contains(out, "Sensitive fields") {
		t.Errorf("render missing sensitive fields line: %s", out)
	}
	if !strings.Contains(out, "email") {
		t.Errorf("render missing 'email': %s", out)
	}
}

// TestRenderSchema_Nil — nil schema should not crash.
func TestRenderSchema_Nil(t *testing.T) {
	if s := RenderSchema(nil); s != "" {
		t.Errorf("expected empty string, got %q", s)
	}
}
