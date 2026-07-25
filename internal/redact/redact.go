package redact

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

var processKey = newProcessKey()

var (
	headerLineRe = regexp.MustCompile(`(?im)\b(authorization|proxy-authorization|cookie|set-cookie|x-csrf-token|x-xsrf-token|csrf-token|xsrf-token|x-api-key|api-key|x-auth-token)\s*:\s*([^\r\n]+)`)
	jsonFieldRe  = regexp.MustCompile(`(?i)("?(?:password|passwd|pwd|secret|token|access_token|refresh_token|id_token|api[_-]?key|session|sessionid|session_id|sid|csrf|xsrf|auth|authorization|cookie)"?\s*:\s*)"([^"\\]*(?:\\.[^"\\]*)*)"`)
	pairRe       = regexp.MustCompile(`(?i)(^|[?&;\s])((?:password|passwd|pwd|secret|token|access_token|refresh_token|id_token|api[_-]?key|session|sessionid|session_id|sid|csrf|xsrf|auth|authorization|cookie)=)([^&;\s"'<>]+)`)
	bearerRe     = regexp.MustCompile(`(?i)\b(Bearer\s+)([A-Za-z0-9._~+/=-]{8,})`)
	basicRe      = regexp.MustCompile(`(?i)\b(Basic\s+)([A-Za-z0-9+/=]{8,})`)
	jwtRe        = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)
)

// Text removes credential-like values from text while preserving a stable,
// non-reversible fingerprint so repeated secrets can still be correlated.
func Text(s string) string {
	if s == "" {
		return ""
	}
	out := headerLineRe.ReplaceAllStringFunc(s, func(m string) string {
		parts := headerLineRe.FindStringSubmatch(m)
		if len(parts) != 3 || isPlaceholder(parts[2]) {
			return m
		}
		return parts[1] + ": " + Placeholder(parts[1], parts[2])
	})
	out = jsonFieldRe.ReplaceAllStringFunc(out, func(m string) string {
		parts := jsonFieldRe.FindStringSubmatch(m)
		if len(parts) != 3 || isPlaceholder(parts[2]) {
			return m
		}
		return parts[1] + `"` + Placeholder(keyKind(parts[1]), unescapeJSONish(parts[2])) + `"`
	})
	out = pairRe.ReplaceAllStringFunc(out, func(m string) string {
		parts := pairRe.FindStringSubmatch(m)
		if len(parts) != 4 || isPlaceholder(parts[3]) {
			return m
		}
		kind := strings.TrimSuffix(parts[2], "=")
		return parts[1] + parts[2] + Placeholder(kind, parts[3])
	})
	out = bearerRe.ReplaceAllStringFunc(out, func(m string) string {
		parts := bearerRe.FindStringSubmatch(m)
		if len(parts) != 3 || isPlaceholder(parts[2]) {
			return m
		}
		return parts[1] + Placeholder("bearer", parts[2])
	})
	out = basicRe.ReplaceAllStringFunc(out, func(m string) string {
		parts := basicRe.FindStringSubmatch(m)
		if len(parts) != 3 || isPlaceholder(parts[2]) {
			return m
		}
		return parts[1] + Placeholder("basic", parts[2])
	})
	out = jwtRe.ReplaceAllStringFunc(out, func(m string) string {
		if isPlaceholder(m) {
			return m
		}
		return Placeholder("jwt", m)
	})
	return out
}

// Placeholder returns the stable redaction marker for a single secret value.
func Placeholder(kind, value string) string {
	kind = normalizeKind(kind)
	value = strings.TrimSpace(value)
	if value == "" {
		return "[REDACTED:" + kind + ":empty]"
	}
	mac := hmac.New(sha256.New, processKey)
	_, _ = mac.Write([]byte(kind))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(value))
	sum := mac.Sum(nil)
	return "[REDACTED:" + kind + ":" + hex.EncodeToString(sum[:])[:12] + "]"
}

func newProcessKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err == nil {
		return key
	}
	return []byte("aobtd-redaction-fallback-key")
}

func normalizeKind(kind string) string {
	kind = strings.ToLower(strings.TrimSpace(kind))
	kind = strings.Trim(kind, `"'`)
	kind = strings.ReplaceAll(kind, "_", "-")
	kind = strings.ReplaceAll(kind, " ", "-")
	if kind == "" {
		return "secret"
	}
	if strings.Contains(kind, "authorization") {
		return "authorization"
	}
	if strings.Contains(kind, "cookie") {
		return "cookie"
	}
	if strings.Contains(kind, "password") || kind == "passwd" || kind == "pwd" {
		return "password"
	}
	if strings.Contains(kind, "csrf") || strings.Contains(kind, "xsrf") {
		return "csrf"
	}
	if strings.Contains(kind, "api-key") {
		return "api-key"
	}
	if strings.Contains(kind, "token") {
		return "token"
	}
	if strings.Contains(kind, "session") || kind == "sid" {
		return "session"
	}
	return kind
}

func keyKind(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	prefix = strings.TrimSuffix(prefix, ":")
	prefix = strings.TrimSpace(prefix)
	return strings.Trim(prefix, `"`)
}

func isPlaceholder(value string) bool {
	return strings.HasPrefix(strings.TrimSpace(value), "[REDACTED:")
}

func unescapeJSONish(value string) string {
	return strings.ReplaceAll(value, `\"`, `"`)
}
