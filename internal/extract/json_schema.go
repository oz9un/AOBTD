package extract

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// JSONSchema represents the extracted shape of a JSON response.
type JSONSchema struct {
	Shape           any            `json:"shape"`
	ArrayCounts     map[string]int `json:"array_counts,omitempty"`
	SensitiveFields []string       `json:"sensitive_fields,omitempty"`
	TotalFields     int            `json:"total_fields"`
}

var (
	emailRe    = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	uuidRe     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	datetimeRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2})?`)
	urlRe      = regexp.MustCompile(`^https?://`)
	jwtRe      = regexp.MustCompile(`^eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$`)

	sensitivePatterns = []string{
		"email", "mail", "phone", "mobile", "tel",
		"password", "passwd", "pass", "pwd",
		"ssn", "social_security",
		"token", "secret", "key", "api_key", "apikey",
		"card", "credit", "cvv", "cvc", "expir",
		"session", "auth", "bearer",
		"private", "salary", "income",
		"dob", "birth", "age",
		"address", "street", "zip", "postal",
		"account", "routing", "iban", "swift",
	}
)

// ExtractJSONSchema parses a JSON response body and extracts its type schema.
func ExtractJSONSchema(rawJSON []byte) *JSONSchema {
	var parsed any
	if err := json.Unmarshal(rawJSON, &parsed); err != nil {
		return nil
	}

	schema := &JSONSchema{
		ArrayCounts: make(map[string]int),
	}

	schema.Shape = extractShape(parsed, "", schema)

	// Deduplicate sensitive fields
	schema.SensitiveFields = deduplicateStrings(schema.SensitiveFields)

	return schema
}

func extractShape(v any, path string, schema *JSONSchema) any {
	switch val := v.(type) {
	case map[string]any:
		result := make(map[string]any, len(val))
		for k, v := range val {
			fieldPath := k
			if path != "" {
				fieldPath = path + "." + k
			}

			// Check if field name looks sensitive
			if isSensitiveField(k) {
				schema.SensitiveFields = append(schema.SensitiveFields, fieldPath)
			}

			schema.TotalFields++
			result[k] = extractShape(v, fieldPath, schema)
		}
		return result

	case []any:
		arrayPath := path
		if arrayPath == "" {
			arrayPath = "$root"
		}
		schema.ArrayCounts[arrayPath] = len(val)

		if len(val) == 0 {
			return []any{"empty_array"}
		}
		// Extract schema from first element only
		return []any{extractShape(val[0], path+"[]", schema)}

	case string:
		return inferStringType(val)

	case float64:
		if val == float64(int64(val)) {
			return "int"
		}
		return "float"

	case bool:
		return "bool"

	case nil:
		return "null"

	default:
		return "unknown"
	}
}

func inferStringType(s string) string {
	if s == "" {
		return "string"
	}
	if emailRe.MatchString(s) {
		return "email"
	}
	if uuidRe.MatchString(s) {
		return "uuid"
	}
	if jwtRe.MatchString(s) {
		return "jwt"
	}
	if urlRe.MatchString(s) {
		return "url"
	}
	if datetimeRe.MatchString(s) {
		return "datetime"
	}
	return "string"
}

func isSensitiveField(name string) bool {
	lower := strings.ToLower(name)
	for _, pattern := range sensitivePatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// RenderSchema produces a compact string representation of a JSON schema for LLM consumption.
func RenderSchema(schema *JSONSchema) string {
	if schema == nil {
		return ""
	}

	rendered, err := json.Marshal(schema.Shape)
	if err != nil {
		return ""
	}

	var sb strings.Builder
	sb.WriteString(string(rendered))

	// Add array size annotations
	if len(schema.ArrayCounts) > 0 {
		sb.WriteString("\n")
		for path, count := range schema.ArrayCounts {
			fmt.Fprintf(&sb, "  %s: array of %d items\n", path, count)
		}
	}

	// Add sensitive field warnings
	if len(schema.SensitiveFields) > 0 {
		fmt.Fprintf(&sb, "Sensitive fields: %s\n", strings.Join(schema.SensitiveFields, ", "))
	}

	return sb.String()
}

func deduplicateStrings(ss []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
