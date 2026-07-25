package agent

import (
	"testing"

	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/pkg/types"
)

func TestSanitizeProfileAuthRequirementRejectsAmbientSessionCookie(t *testing.T) {
	profile := &types.PageProfile{AuthRequired: "session_cookie"}
	bundle := &extract.EndpointBundle{
		URLPattern:      "/catalog",
		SampleURL:       "https://shop.test/catalog",
		StatusCodes:     []int{200},
		RequestHeaders:  map[string]string{"cookie": "session=anonymous"},
		ResponseHeaders: map[string]string{"set-cookie": "session=anonymous"},
	}

	sanitizeProfileAuthRequirement(profile, bundle)
	if profile.AuthRequired != "unknown" {
		t.Fatalf("ambient cookie produced auth_required=%q, want unknown", profile.AuthRequired)
	}
}

func TestSanitizeProfileAuthRequirementRecognizesLoginRedirect(t *testing.T) {
	profile := &types.PageProfile{AuthRequired: "unknown"}
	bundle := &extract.EndpointBundle{
		URLPattern:      "/my-account",
		SampleURL:       "https://shop.test/my-account",
		StatusCodes:     []int{302},
		ResponseHeaders: map[string]string{"location": "/login"},
	}

	sanitizeProfileAuthRequirement(profile, bundle)
	if profile.AuthRequired != "session_cookie" {
		t.Fatalf("login redirect produced auth_required=%q, want session_cookie", profile.AuthRequired)
	}
}

func TestSanitizeProfileAuthRequirementLeavesLoginPagePublic(t *testing.T) {
	profile := &types.PageProfile{AuthRequired: "session_cookie"}
	bundle := &extract.EndpointBundle{
		URLPattern:  "/login",
		SampleURL:   "https://shop.test/login",
		StatusCodes: []int{200},
	}

	sanitizeProfileAuthRequirement(profile, bundle)
	if profile.AuthRequired != "none" {
		t.Fatalf("public login form produced auth_required=%q, want none", profile.AuthRequired)
	}
}
