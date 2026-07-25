package reconprojection

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ozzyw/aobtd/pkg/types"
)

func TestCatchAllIndexPreservesMethodOriginAndCanonicalLogin(t *testing.T) {
	body := []byte(`<html><body><form><input type="password"></form></body></html>`)
	digest := BodySHA256(body)
	index := NewCatchAllIndex([]CatchAllObservation{
		{Method: http.MethodGet, URL: "https://app.test/admin", BodySHA256: digest},
		{Method: http.MethodGet, URL: "https://app.test/adminasdasd", BodySHA256: digest},
		{Method: http.MethodGet, URL: "https://app.test/auth/login", BodySHA256: digest},
		{Method: http.MethodPost, URL: "https://app.test/admin", BodySHA256: digest},
		{Method: http.MethodGet, URL: "https://api.app.test/admin", BodySHA256: digest},
	})

	profile := &types.PageProfile{
		Method: http.MethodGet, URL: "https://APP.test:443/admin",
		EvidenceState: "content_observed", Purpose: "Administrative dashboard", Confidence: .95,
	}
	if !ApplyCatchAllCeiling(profile, index) || profile.EvidenceState != "response_unverified" ||
		!strings.Contains(profile.EvidenceNote, "/adminasdasd") || strings.Contains(profile.Purpose, "dashboard") {
		t.Fatalf("GET same-origin catch-all ceiling = %+v", profile)
	}
	for _, candidate := range []types.PageProfile{
		// Query values are exact action specimens. An unobserved sibling does
		// not inherit the indexed /admin response; MatchResponse can still
		// reject it if its newly captured full body equals the shell.
		{Method: http.MethodGet, URL: "https://app.test/admin?redirect=%2Forders", EvidenceState: "content_observed"},
		{Method: http.MethodPost, URL: "https://app.test/admin", EvidenceState: "content_observed"},
		{Method: http.MethodGet, URL: "https://api.app.test/admin", EvidenceState: "content_observed"},
		{Method: http.MethodGet, URL: "https://app.test/auth/login", EvidenceState: "content_observed"},
	} {
		candidate := candidate
		if ApplyCatchAllCeiling(&candidate, index) || candidate.EvidenceState != "content_observed" {
			t.Fatalf("unrelated method/origin or canonical login was downgraded: %+v", candidate)
		}
	}
}

func TestCatchAllResponseCeilingMatchesNewExactBody(t *testing.T) {
	body := []byte("shared complete response body")
	index := NewCatchAllIndex([]CatchAllObservation{
		{Method: http.MethodGet, URL: "https://app.test/known", BodySHA256: BodySHA256(body)},
		{Method: http.MethodGet, URL: "https://app.test/missingroute-qwerty", BodySHA256: BodySHA256(body)},
	})
	profile := &types.PageProfile{Method: http.MethodGet, URL: "https://app.test/new", EvidenceState: "content_observed"}
	entries := []types.TrafficEntry{{
		Request:  types.CapturedRequest{Method: http.MethodGet, URL: profile.URL},
		Response: types.CapturedResponse{StatusCode: http.StatusOK, Body: body},
	}}
	if !ApplyCatchAllResponseCeiling(profile, entries, index) || profile.EvidenceState != "response_unverified" {
		t.Fatalf("new response was not matched to invalid shell: %+v", profile)
	}
	entries[0].Response.Body = []byte("different complete response body")
	profile.EvidenceState = "content_observed"
	if ApplyCatchAllResponseCeiling(profile, entries, index) {
		t.Fatalf("different response body was downgraded: %+v", profile)
	}
}
