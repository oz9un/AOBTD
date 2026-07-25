package reasoner

import (
	"net/url"
	"strings"
)

func accessCandidateEvidence(ev Evidence) Evidence {
	ev.APIEndpoints = filterAccessCandidateEndpoints(ev.APIEndpoints)
	ev.QueryEndpoints = filterAccessCandidateEndpoints(ev.QueryEndpoints)
	return ev
}

func filterAccessCandidateEndpoints(eps []DiscoveredEndpoint) []DiscoveredEndpoint {
	out := make([]DiscoveredEndpoint, 0, len(eps))
	for _, ep := range eps {
		if accessEndpointLooksOwnedObject(ep) {
			out = append(out, ep)
		}
	}
	return out
}

func accessEndpointLooksOwnedObject(ep DiscoveredEndpoint) bool {
	path := endpointCandidatePath(ep)
	if path == "" {
		return false
	}
	segments := pathSegments(path)
	score := 0
	if hasAnySegment(segments, ownedResourceSegments) {
		score += 3
	}
	if hasAnySegment(segments, publicOrMetaResourceSegments) {
		score -= 4
	}
	if hasIDShapedSegment(segments) && !hasAnySegment(segments, publicOrMetaResourceSegments) {
		score += 2
	}
	for _, field := range append(append([]string{}, ep.Params...), ep.BodyFields...) {
		if accessFieldLooksOwnershipRelevant(field) {
			score += 2
			break
		}
	}
	return score >= 2
}

var ownedResourceSegments = map[string]bool{
	"user": true, "users": true, "account": true, "accounts": true,
	"customer": true, "customers": true, "profile": true, "profiles": true,
	"tenant": true, "tenants": true, "team": true, "teams": true,
	"organization": true, "organizations": true, "org": true, "orgs": true,
	"order": true, "orders": true, "booking": true, "bookings": true,
	"basket": true, "baskets": true, "cart": true, "carts": true,
	"address": true, "addresses": true, "payment": true, "payments": true,
	"wallet": true, "wallets": true, "invoice": true, "invoices": true,
	"message": true, "messages": true, "memory": true, "memories": true,
	"review": true, "reviews": true, "feedback": true, "feedbacks": true,
	"file": true, "files": true, "document": true, "documents": true,
}

var publicOrMetaResourceSegments = map[string]bool{
	"challenge": true, "challenges": true, "score": true, "scores": true,
	"status": true, "health": true, "metrics": true, "version": true,
	"config": true, "configuration": true, "settings": true,
	"captcha": true, "language": true, "languages": true, "i18n": true,
	"product": true, "products": true, "catalog": true, "search": true,
	"quantity": true, "quantitys": true, "inventory": true,
	"swagger": true, "docs": true, "api-docs": true, "openapi": true,
	"unknown": true, "unknownpath": true,
}

func endpointCandidatePath(ep DiscoveredEndpoint) string {
	if strings.TrimSpace(ep.Path) != "" {
		return ep.Path
	}
	parsed, err := url.Parse(ep.URL)
	if err != nil {
		return ep.URL
	}
	return parsed.Path
}

func pathSegments(path string) []string {
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

func hasAnySegment(segments []string, dict map[string]bool) bool {
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

func hasIDShapedSegment(segments []string) bool {
	for _, segment := range segments {
		if segment == "id" || strings.HasSuffix(segment, "_id") || strings.HasSuffix(segment, "-id") || isSmallInteger(segment) || looksUUIDLike(segment) {
			return true
		}
	}
	return false
}

func accessFieldLooksOwnershipRelevant(field string) bool {
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

func isSmallInteger(s string) bool {
	if s == "" || len(s) > 10 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func looksUUIDLike(s string) bool {
	return len(s) == 36 && s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-'
}
