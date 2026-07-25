package reconprojection

import (
	"strings"
	"testing"

	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/pkg/types"
)

func TestAnnotateProfilesMarksOrphanRouteUnverifiedButPreservesSyntheticSummaries(t *testing.T) {
	profiles := []types.PageProfile{
		{
			ID: "GET /admin", Method: "GET", URL: "https://app.test/admin",
			Purpose: "Administrative console", AuthRequired: "required", Confidence: .94,
			Inputs: []types.Input{{Name: "record_id"}}, DataExposed: []string{"partner records"},
			APIsCalled: []string{"/api/admin"}, Behaviors: []string{"updates records"},
			Relationships: []string{"administrator owns records"}, Issues: []string{"possible IDOR"},
			TechNotes: "privileged React page", TemplateID: "admin-template", HasInput: true,
			HasAuth: true, IsAPI: true,
		},
		{
			ID: "js_discovered_routes", URL: "JavaScript source analysis",
			Purpose: "Discovered 2 routes from JavaScript", Confidence: .8,
			TechNotes: `[{"method":"GET","path":"/catalog"}]`,
		},
		{
			ID: "attack_surface", URL: "Attack surface analysis",
			Purpose: "Aggregate input and endpoint summary", Confidence: .9,
			TechNotes: `{"total_inputs":3}`,
		},
	}

	AnnotateProfiles(profiles, nil)
	orphan := profiles[0]
	if orphan.EvidenceState != "response_unverified" || orphan.AuthRequired != "unknown" || orphan.Confidence != .35 {
		t.Fatalf("orphan verdict = %+v", orphan)
	}
	if !strings.Contains(orphan.EvidenceNote, "No matching direct HTTP response") ||
		!strings.Contains(orphan.EvidenceNote, "analysis inventory only") {
		t.Fatalf("orphan note = %q", orphan.EvidenceNote)
	}
	if len(orphan.Inputs) != 0 || len(orphan.DataExposed) != 0 || len(orphan.APIsCalled) != 0 ||
		len(orphan.Behaviors) != 0 || len(orphan.Relationships) != 0 || len(orphan.Issues) != 0 ||
		orphan.TechNotes != "" || orphan.TemplateID != "" || orphan.HasInput || orphan.HasAuth || orphan.IsAPI {
		t.Fatalf("orphan retained unsupported semantics: %+v", orphan)
	}
	if profiles[1].EvidenceState != "" || profiles[1].Purpose != "Discovered 2 routes from JavaScript" || profiles[1].TechNotes == "" {
		t.Fatalf("JavaScript summary was reclassified: %+v", profiles[1])
	}
	if profiles[2].EvidenceState != "" || profiles[2].Purpose != "Aggregate input and endpoint summary" || profiles[2].TechNotes == "" {
		t.Fatalf("attack-surface summary was reclassified: %+v", profiles[2])
	}
}

func TestApplyRedirectEvidenceRemovesSemanticsBackedOnlyByOrphanProfile(t *testing.T) {
	u := extract.NewAppUnderstanding()
	u.Summary = "An administrative console lets operators approve partner records."
	u.Recon = extract.ReconModel{
		Identity: extract.ReconIdentity{AppType: "portal", Summary: u.Summary},
		Pages: []extract.PagePurposeCard{{
			ID: "GET /admin", Method: "GET", URL: "https://app.test/admin",
			Purpose: "Administrative console", Area: "admin", AuthRequired: "required",
			ObjectIDs: []string{"record"}, SecurityInterest: []string{"privileged"}, Confidence: .9,
			Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: "GET /admin"}},
		}},
		Roles: []extract.ReconRole{{
			ID: "admin", Name: "Administrator", Confidence: .9,
			Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: "GET /admin"}},
		}},
		Objects: []extract.BusinessObject{{
			ID: "record", Name: "Partner record", Confidence: .9,
			Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: "GET /admin"}},
		}},
	}
	profiles := []types.PageProfile{{
		ID: "GET /admin", URL: "https://app.test/admin", Method: "GET",
		Purpose: "Administrative console", Confidence: .9,
	}}
	AnnotateProfiles(profiles, nil)
	ApplyRedirectEvidence(u, profiles)

	if len(u.Recon.Roles) != 0 || len(u.Recon.Objects) != 0 {
		t.Fatalf("orphan-backed semantics survived: roles=%+v objects=%+v", u.Recon.Roles, u.Recon.Objects)
	}
	page := u.Recon.Pages[0]
	if page.Area != "unverified" || page.AuthRequired != "unknown" || page.Confidence != .35 || len(page.ObjectIDs) != 0 {
		t.Fatalf("orphan-backed page = %+v", page)
	}
	if !strings.Contains(strings.ToLower(u.Recon.Identity.Summary), "not backed by a verifiable direct page response") {
		t.Fatalf("orphan-backed summary = %q", u.Recon.Identity.Summary)
	}
}

func TestAnnotateProfileClearsArbitrarySemanticsForEveryNonSubstantiveVerdict(t *testing.T) {
	tests := []struct {
		name      string
		response  types.CapturedResponse
		wantState string
	}{
		{
			name: "redirect gate",
			response: types.CapturedResponse{StatusCode: 302, Headers: map[string]string{
				"Location": "/login?redirect=%2Fadmin",
			}},
			wantState: "auth_gate_unverified",
		},
		{
			name: "negative response",
			response: types.CapturedResponse{
				StatusCode: 404, ContentType: "text/html", Body: []byte("<h1>Page not found</h1>"),
			},
			wantState: "response_unverified",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := types.PageProfile{
				ID: "GET /admin", Method: "GET", URL: "https://app.test/admin",
				Purpose: "Administrative console", AuthRequired: "required", Confidence: .9,
				Inputs: []types.Input{{Name: "tenant_id"}}, DataExposed: []string{"tenant"},
				APIsCalled: []string{"/api/admin"}, Behaviors: []string{"approves records"},
				Relationships: []string{"admin owns tenant"}, Issues: []string{"possible IDOR"},
				TechNotes: "React admin", TemplateID: "admin", HasInput: true, HasAuth: true, IsAPI: true,
			}
			AnnotateProfile(&profile, []types.TrafficEntry{{
				Request:  types.CapturedRequest{Method: "GET", URL: profile.URL, Path: "/admin"},
				Response: tt.response,
			}})
			if profile.EvidenceState != tt.wantState || profile.AuthRequired != "unknown" || profile.Confidence != .35 {
				t.Fatalf("verdict = %+v", profile)
			}
			if len(profile.Inputs) != 0 || len(profile.DataExposed) != 0 || len(profile.APIsCalled) != 0 ||
				len(profile.Behaviors) != 0 || len(profile.Relationships) != 0 || len(profile.Issues) != 0 ||
				profile.TechNotes != "" || profile.TemplateID != "" || profile.HasInput || profile.HasAuth || profile.IsAPI {
				t.Fatalf("non-substantive verdict retained arbitrary semantics: %+v", profile)
			}
		})
	}
}

func TestApplyRedirectEvidenceCeilsDependenciesEvenWhenPageCardIsMissing(t *testing.T) {
	u := extract.NewAppUnderstanding()
	u.Summary = "Administrators approve tenant records."
	u.Recon.Identity.Summary = u.Summary
	u.Recon.Roles = []extract.ReconRole{{
		ID: "administrator", Name: "Administrator",
		Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: "GET /admin"}},
	}}
	u.Recon.Objects = []extract.BusinessObject{{
		ID: "tenant", Name: "Tenant record",
		Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: "GET /admin"}},
	}}
	profiles := []types.PageProfile{{
		ID: "GET /admin", Method: "GET", URL: "https://app.test/admin",
		EvidenceState: "response_unverified", EvidenceNote: "No matching direct HTTP response was captured.",
	}}

	ApplyRedirectEvidence(u, profiles)
	if len(u.Recon.Roles) != 0 || len(u.Recon.Objects) != 0 {
		t.Fatalf("orphan-backed dependencies without a page card survived: roles=%+v objects=%+v", u.Recon.Roles, u.Recon.Objects)
	}
	if !strings.Contains(strings.ToLower(u.Recon.Identity.Summary), "not backed by a verifiable direct page response") {
		t.Fatalf("summary without page card = %q", u.Recon.Identity.Summary)
	}
}

func TestApplyRedirectEvidenceIgnoresBlankAndUnknownSupportRefs(t *testing.T) {
	u := extract.NewAppUnderstanding()
	u.Summary = "Administrators approve records from the admin console."
	u.Recon.Identity.Summary = u.Summary
	u.Recon.Roles = []extract.ReconRole{{
		ID: "admin", Name: "Administrator",
		Evidence: []extract.ReconEvidence{
			{Kind: "endpoint", Ref: "GET /admin"},
			{Kind: "endpoint", Ref: ""},
			{Kind: "endpoint", Ref: "GET /hallucinated"},
		},
	}}
	profiles := []types.PageProfile{
		{ID: "GET /admin", URL: "https://app.test/admin", EvidenceState: "auth_gate_unverified"},
		// A different verified route containing the same word must not globally
		// verify the exact /admin claim.
		{ID: "GET /admin/help", URL: "https://app.test/admin/help", EvidenceState: "content_observed"},
	}
	ApplyRedirectEvidence(u, profiles)
	if len(u.Recon.Roles) != 0 {
		t.Fatalf("blank/hallucinated support preserved an unverified role: %+v", u.Recon.Roles)
	}
	if strings.Contains(strings.ToLower(u.Recon.Identity.Summary), "approve records") {
		t.Fatalf("unrelated verified route exempted stale summary: %q", u.Recon.Identity.Summary)
	}
}

func TestApplyRedirectEvidenceSanitizesNonAdminRouteSemantics(t *testing.T) {
	u := extract.NewAppUnderstanding()
	u.Summary = "The billing workspace exposes invoices and payment reports."
	u.Recon.Identity.Summary = u.Summary
	profiles := []types.PageProfile{{
		ID: "GET /billing", URL: "https://app.test/billing",
		EvidenceState: "response_unverified", EvidenceNote: "Generic login shell only.",
	}}
	ApplyRedirectEvidence(u, profiles)
	if strings.Contains(strings.ToLower(u.Recon.Identity.Summary), "billing workspace") {
		t.Fatalf("non-admin unverified semantics survived: %q", u.Recon.Identity.Summary)
	}
	if !strings.Contains(strings.ToLower(u.Recon.Identity.Summary), "remain unverified") {
		t.Fatalf("sanitized summary omitted calibrated note: %q", u.Recon.Identity.Summary)
	}
}

func TestApplyRedirectEvidenceTreatsAnyUnverifiedVerdictAsSemanticCeiling(t *testing.T) {
	u := extract.NewAppUnderstanding()
	u.Summary = "An administrative console controls partner records."
	u.Recon = extract.ReconModel{
		Identity: extract.ReconIdentity{AppType: "portal", Summary: u.Summary},
		Pages: []extract.PagePurposeCard{{
			ID: "GET /admin", Method: "GET", URL: "https://app.test/admin",
			Purpose: "Administrative console", Area: "admin", AuthRequired: "required",
			ObjectIDs: []string{"record"}, SecurityInterest: []string{"privileged"}, Confidence: .9,
			Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: "GET /admin"}},
		}},
		Roles: []extract.ReconRole{{
			ID: "admin", Name: "Administrator", Confidence: .9,
			Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: "GET /admin"}},
		}},
		Objects: []extract.BusinessObject{{
			ID: "record", Name: "Partner record", Confidence: .9,
			Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: "GET /admin"}},
		}},
	}
	profiles := []types.PageProfile{{
		ID: "GET /admin", URL: "https://app.test/admin",
		EvidenceState: "response_unverified",
		EvidenceNote:  "The response could not be verified as target page content.",
	}}

	ApplyRedirectEvidence(u, profiles)
	if len(u.Recon.Roles) != 0 || len(u.Recon.Objects) != 0 {
		t.Fatalf("response-unverified dependencies survived: roles=%+v objects=%+v", u.Recon.Roles, u.Recon.Objects)
	}
	page := u.Recon.Pages[0]
	if page.AuthRequired != "unknown" || page.Area != "unverified" || page.Confidence != .35 {
		t.Fatalf("response-unverified page = %+v", page)
	}
	if strings.Contains(strings.Join(page.Actions, " "), "redirect") {
		t.Fatalf("generic unverifiable response was mislabeled a redirect: %+v", page.Actions)
	}
	if !strings.Contains(u.Recon.Identity.Summary, "not backed by a verifiable direct page response") {
		t.Fatalf("generic unverified summary = %q", u.Recon.Identity.Summary)
	}
}

func TestSanitizeHistoricalAnswerPreservesCalibratedRedirectEvidence(t *testing.T) {
	profiles := []types.PageProfile{{
		ID: "GET /admin", URL: "https://app.test/admin", EvidenceState: "auth_gate_unverified",
	}}
	answer := "The /admin page is auth-required and proves an administrator role.\nThe /admin request is unverified; only redirect behavior was observed.\nPublic login was observed."
	got, changed := SanitizeHistoricalAnswer(answer, profiles)
	if !changed || strings.Contains(got, "proves an administrator role") {
		t.Fatalf("stale historical claim survived: %q", got)
	}
	for _, want := range []string{"Historical claim removed", "only redirect behavior", "Public login was observed"} {
		if !strings.Contains(got, want) {
			t.Fatalf("sanitized history omitted %q: %q", want, got)
		}
	}
}
