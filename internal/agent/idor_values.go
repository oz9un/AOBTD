package agent

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/ozzyw/aobtd/internal/observation"
)

func cleanIDORProbeValues(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if !isUsableResourceIdentifier(value) {
			continue
		}
		key := strings.ToLower(value)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, value)
	}
	return out
}

func cleanIDORProbeValuesAny(values []any) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		switch v := value.(type) {
		case string:
			out = append(out, v)
		case float64:
			out = append(out, fmt.Sprintf("%.0f", v))
		case int:
			out = append(out, fmt.Sprintf("%d", v))
		case int64:
			out = append(out, fmt.Sprintf("%d", v))
		case jsonNumberStringer:
			out = append(out, v.String())
		default:
			// Deliberately ignore arrays/objects/bools: those are not scalar
			// resource identifiers and often stringify into "[object Object]".
		}
	}
	return cleanIDORProbeValues(out)
}

type jsonNumberStringer interface {
	String() string
}

func isUsableResourceIdentifier(value string) bool {
	if value == "" || strings.ContainsAny(value, "{}") {
		return false
	}
	if observation.IsInvalidPathIdentifier(value) {
		return false
	}
	return true
}

func containsInvalidPathIdentifier(raw string) bool {
	if raw == "" {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	path := parsed.Path
	if path == "" {
		path = raw
	}
	for _, segment := range strings.Split(path, "/") {
		if observation.IsInvalidPathIdentifier(segment) {
			return true
		}
	}
	return false
}
