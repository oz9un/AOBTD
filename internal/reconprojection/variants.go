package reconprojection

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/ozzyw/aobtd/internal/observation"
	"github.com/ozzyw/aobtd/pkg/types"
)

// VariantStateCount is a value-redacted summary of exact query specimens.
type VariantStateCount struct {
	State string `json:"state"`
	Count int    `json:"count"`
}

// QueryVariantEvidence preserves one logical route in the UI while keeping
// content, redirect, auth-shell, error, and empty evidence specimen-exact.
type QueryVariantEvidence struct {
	Variants           int
	ContentVariants    int
	UnverifiedVariants int
	State              string
	Note               string
	ObservedStatuses   []int
	RedirectLocations  []string
	States             []VariantStateCount
}

// EntriesForExactSpecimen returns only the method + canonical URL specimen
// represented by a profile or action. Query values are intentionally retained.
func EntriesForExactSpecimen(entries []types.TrafficEntry, method, rawURL string) []types.TrafficEntry {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = http.MethodGet
	}
	want := observation.CanonicalEvidenceURL(rawURL)
	if want == "" {
		return nil
	}
	result := make([]types.TrafficEntry, 0)
	for _, entry := range entries {
		entryMethod := strings.ToUpper(strings.TrimSpace(entry.Request.Method))
		if entryMethod == "" {
			entryMethod = http.MethodGet
		}
		if entryMethod == method && observation.CanonicalEvidenceURL(entry.Request.URL) == want {
			result = append(result, entry)
		}
	}
	return result
}

// SummarizeQueryVariantEvidence classifies each exact query specimen before
// aggregating a logical route. A content response on one specimen can never
// promote a redirect/auth/error/empty sibling.
func SummarizeQueryVariantEvidence(method, rawRouteURL string, entries []types.TrafficEntry, catchAll *CatchAllIndex) QueryVariantEvidence {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = http.MethodGet
	}
	routeOrigin, routePath, routeOK := queryVariantRouteIdentity(rawRouteURL)
	groups := make(map[string][]types.TrafficEntry)
	for _, entry := range entries {
		entryMethod := strings.ToUpper(strings.TrimSpace(entry.Request.Method))
		if entryMethod == "" {
			entryMethod = http.MethodGet
		}
		if entryMethod != method {
			continue
		}
		origin, path, ok := queryVariantRouteIdentity(entry.Request.URL)
		if !ok || (routeOK && (origin != routeOrigin || path != routePath)) {
			continue
		}
		specimen := observation.CanonicalEvidenceURL(entry.Request.URL)
		if specimen == "" {
			continue
		}
		groups[specimen] = append(groups[specimen], entry)
	}
	if len(groups) == 0 {
		return QueryVariantEvidence{}
	}

	specimens := make([]string, 0, len(groups))
	for specimen := range groups {
		specimens = append(specimens, specimen)
	}
	sort.Strings(specimens)
	stateCounts := make(map[string]int)
	statuses := make(map[int]bool)
	locations := make(map[string]bool)
	result := QueryVariantEvidence{Variants: len(specimens)}
	for _, specimen := range specimens {
		projection := types.PageProfile{Method: method, URL: specimen}
		AnnotateProfile(&projection, groups[specimen])
		ApplyCatchAllCeiling(&projection, catchAll)
		state := strings.ToLower(strings.TrimSpace(projection.EvidenceState))
		if state == "" {
			state = "response_unverified"
		}
		stateCounts[state]++
		if state == "content_observed" {
			result.ContentVariants++
		} else {
			result.UnverifiedVariants++
		}
		for _, status := range projection.ObservedStatuses {
			statuses[status] = true
		}
		for _, location := range projection.RedirectLocations {
			locations[location] = true
		}
	}
	for state, count := range stateCounts {
		result.States = append(result.States, VariantStateCount{State: state, Count: count})
	}
	sort.Slice(result.States, func(i, j int) bool { return result.States[i].State < result.States[j].State })
	for status := range statuses {
		result.ObservedStatuses = append(result.ObservedStatuses, status)
	}
	for location := range locations {
		result.RedirectLocations = append(result.RedirectLocations, location)
	}
	sort.Ints(result.ObservedStatuses)
	sort.Strings(result.RedirectLocations)

	switch {
	case result.UnverifiedVariants == 0:
		result.State = "content_observed"
	case result.ContentVariants > 0:
		result.State = "query_mixed_unverified"
		result.Note = fmt.Sprintf(
			"Exact query specimens disagree: %d returned substantive content and %d remained redirect/auth/error/empty or otherwise unverified. Content from one query value does not verify its siblings.",
			result.ContentVariants, result.UnverifiedVariants,
		)
	case len(result.States) == 1:
		result.State = result.States[0].State
		if first := groups[specimens[0]]; len(first) > 0 {
			projection := types.PageProfile{Method: method, URL: specimens[0]}
			AnnotateProfile(&projection, first)
			ApplyCatchAllCeiling(&projection, catchAll)
			result.Note = projection.EvidenceNote
		}
	default:
		result.State = "query_mixed_unverified"
		result.Note = "Exact query specimens produced different non-content verdicts. Every variant remains unverified, and no variant lends semantics to another."
	}
	return result
}

// ApplyQueryVariantCeiling strips logical-route semantics when any exact query
// sibling remains unverified. Exact actions may still classify their selected
// specimen independently.
func ApplyQueryVariantCeiling(profile *types.PageProfile, entries []types.TrafficEntry, catchAll *CatchAllIndex) bool {
	if profile == nil {
		return false
	}
	summary := SummarizeQueryVariantEvidence(profile.Method, profile.URL, entries, catchAll)
	if summary.Variants < 2 || summary.UnverifiedVariants == 0 {
		return false
	}
	if summary.Note == "" {
		summary.Note = "One or more exact query specimens remain unverified. Query values are facets of one logical route, but their response evidence is not interchangeable."
	}
	applyUnverifiedProfileCeiling(profile, summary.State, summary.Note, summary.ObservedStatuses, summary.RedirectLocations)
	return true
}

func queryVariantRouteIdentity(rawURL string) (origin, path string, ok bool) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Hostname() == "" {
		return "", "", false
	}
	origin = observation.CanonicalOrigin(rawURL)
	path = parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	return origin, path, origin != ""
}
