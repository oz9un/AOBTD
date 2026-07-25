package agent

import (
	"net/url"
	"strings"
)

var agentOwnedResourceSegments = map[string]bool{
	"user": true, "users": true, "account": true, "accounts": true,
	"customer": true, "customers": true, "profile": true, "profiles": true,
	"tenant": true, "tenants": true, "team": true, "teams": true,
	"organization": true, "organizations": true, "org": true, "orgs": true,
	"member": true, "members": true,
	"order": true, "orders": true, "booking": true, "bookings": true,
	"basket": true, "baskets": true, "cart": true, "carts": true,
	"address": true, "addresses": true, "payment": true, "payments": true,
	"wallet": true, "wallets": true, "invoice": true, "invoices": true,
	"message": true, "messages": true, "memory": true, "memories": true,
	"review": true, "reviews": true, "feedback": true, "feedbacks": true,
	"file": true, "files": true, "document": true, "documents": true,
}

var agentPublicOrMetaResourceSegments = map[string]bool{
	"challenge": true, "challenges": true, "score": true, "scores": true,
	"status": true, "health": true, "metrics": true, "version": true,
	"config": true, "configuration": true, "settings": true,
	"captcha": true, "language": true, "languages": true, "i18n": true,
	"product": true, "products": true, "catalog": true, "search": true,
	"quantity": true, "quantitys": true, "inventory": true,
	"swagger": true, "docs": true, "api-docs": true, "openapi": true,
	"unknown": true, "unknownpath": true, "notfound": true, "not-found": true,
	"asset": true, "assets": true, "static": true, "public": true,
	"image": true, "images": true, "media": true, "upload": true, "uploads": true,
}

// idorTargetLooksOwnedObject is a lightweight authorization-target guard for
// the agent layer. It does not try to prove an IDOR; it only answers whether a
// probe target looks like a single owned object rather than public catalogue,
// status, docs, or challenge metadata.
func idorTargetLooksOwnedObject(raw string, fields ...string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	path := raw
	var query url.Values
	if err == nil {
		path = u.Path
		query = u.Query()
	}
	if agentLooksLikePublicStaticAsset(path) {
		return false
	}
	segments := agentPathSegments(path)
	score := 0
	if agentHasAnySegment(segments, agentOwnedResourceSegments) {
		score += 3
	}
	if agentHasAnySegment(segments, agentPublicOrMetaResourceSegments) {
		score -= 4
	}
	if agentHasIDShapedSegment(segments) && !agentHasAnySegment(segments, agentPublicOrMetaResourceSegments) {
		score += 2
	}
	for _, field := range fields {
		if agentAccessFieldLooksOwnershipRelevant(field) {
			score += 2
			break
		}
	}
	for key := range query {
		if agentAccessFieldLooksOwnershipRelevant(key) {
			score += 2
			break
		}
	}
	return score >= 2
}

func agentPathSegments(path string) []string {
	parts := strings.Split(strings.ToLower(path), "/")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, "{}")
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func agentHasAnySegment(segments []string, dict map[string]bool) bool {
	for _, segment := range segments {
		if dict[segment] {
			return true
		}
		for _, token := range strings.FieldsFunc(segment, func(r rune) bool { return r == '-' || r == '_' || r == '.' }) {
			if dict[token] {
				return true
			}
		}
	}
	return false
}

func agentHasIDShapedSegment(segments []string) bool {
	for _, segment := range segments {
		if segment == "id" || strings.HasSuffix(segment, "_id") || strings.HasSuffix(segment, "-id") || isAllDigits(segment) || looksUUIDLikeSegment(segment) {
			return true
		}
	}
	return false
}

func agentAccessFieldLooksOwnershipRelevant(field string) bool {
	normalized := strings.ToLower(strings.TrimSpace(field))
	normalized = strings.ReplaceAll(normalized, "-", "_")
	compact := strings.ReplaceAll(normalized, "_", "")
	for _, marker := range []string{"user", "owner", "account", "customer", "tenant", "team", "org", "organization", "member"} {
		if normalized == marker || normalized == marker+"_id" || strings.HasPrefix(normalized, marker+"_") || strings.HasSuffix(normalized, "_"+marker) ||
			compact == marker+"id" || strings.HasPrefix(compact, marker) || strings.HasSuffix(compact, marker) {
			return true
		}
	}
	return normalized == "id" || strings.HasSuffix(normalized, "_id")
}

func looksUUIDLikeSegment(s string) bool {
	return len(s) == 36 && s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-'
}

// followUpTargetLooksGrounded filters LLM follow-ups that look like placeholder
// examples or invented API names rather than URLs discovered from target
// behavior. It is deliberately generic: reject synthetic naming patterns, not
// target-specific paths.
func followUpTargetLooksGrounded(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	parsed, err := url.Parse(raw)
	path := raw
	if err == nil && parsed.Path != "" {
		path = parsed.Path
	}
	for _, segment := range strings.Split(path, "/") {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		lower := strings.ToLower(strings.Trim(segment, "{}"))
		if lower == ".." || strings.Contains(lower, "%2f") || strings.Contains(lower, "\\") {
			return false
		}
		if lower == "someformsubmitendpoint" || strings.HasSuffix(lower, "submitendpoint") || strings.HasSuffix(lower, "endpoint") {
			return false
		}
		if genericExampleFileName(lower) {
			return false
		}
		if strings.Contains(lower, "_") {
			parts := strings.Split(lower, "_")
			if len(parts) > 1 && genericHTTPishToken(parts[0]) {
				return false
			}
		}
	}
	return true
}

func followUpTargetsPublicStaticAsset(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	parsed, err := url.Parse(raw)
	path := raw
	if err == nil && parsed.Path != "" {
		path = parsed.Path
	}
	return agentLooksLikePublicStaticAsset(path)
}

func agentLooksLikePublicStaticAsset(path string) bool {
	segments := agentPathSegments(path)
	if len(segments) == 0 {
		return false
	}
	hasStaticRoot := false
	for _, segment := range segments {
		for _, token := range strings.FieldsFunc(segment, func(r rune) bool { return r == '-' || r == '_' || r == '.' }) {
			switch token {
			case "asset", "assets", "static", "public", "image", "images", "media", "upload", "uploads":
				hasStaticRoot = true
			}
		}
	}
	if !hasStaticRoot {
		return false
	}
	last := segments[len(segments)-1]
	if strings.Contains(last, ".") || strings.Contains(path, "{") || strings.HasSuffix(path, "/") {
		return true
	}
	return false
}

func genericExampleFileName(segment string) bool {
	segment = strings.ToLower(strings.Trim(segment, "{}"))
	for _, marker := range []string{
		"test.", "shell.", "upload.", "malicious.", "validimage.", "sensitive_image.",
		"secret.", "passwd", "shadow", "auth.log", "config.yaml", "config.yml",
	} {
		if strings.Contains(segment, marker) {
			return true
		}
	}
	return false
}

func reasonMentionsAccessControl(reason string) bool {
	reason = strings.ToLower(reason)
	for _, marker := range []string{
		"idor", "bola", "broken object", "ownership", "owner", "unauthorized",
		"authorisation", "authorization", "access control", "privilege",
	} {
		if strings.Contains(reason, marker) {
			return true
		}
	}
	return false
}

func genericHTTPishToken(s string) bool {
	switch s {
	case "api", "rest", "graphql", "http", "https", "ajax", "xhr":
		return true
	}
	return false
}
