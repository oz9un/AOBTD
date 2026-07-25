package ui

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

func TestUnderstandingTopLevelIdentityMatchesNormalizedReconIdentity(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://meta.example/", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	summary := "Meta is a community forum for software users and developers with public discussions."
	if err := db.UpsertAppUnderstanding(scanID, "other", `[]`, `[]`, `{}`, summary); err != nil {
		t.Fatal(err)
	}
	reconJSON := `{"identity":{"app_type":"other","summary":"` + summary + `"},"pages":[{"id":"GET /","method":"GET","url":"https://meta.example/","purpose":"Community forum homepage","confidence":0.9}]}`
	if err := db.UpsertReconModel(scanID, reconJSON); err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	s.handleUnderstanding(w, httptest.NewRequest(http.MethodGet,
		"/api/understanding?scan_id="+strconv.FormatInt(scanID, 10), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var response struct {
		AppType string `json:"app_type"`
		Recon   struct {
			Identity struct {
				AppType string `json:"app_type"`
			} `json:"identity"`
		} `json:"recon"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.AppType != "developer_community" || response.Recon.Identity.AppType != response.AppType {
		t.Fatalf("top=%q recon=%q body=%s", response.AppType, response.Recon.Identity.AppType, w.Body.String())
	}
}

func TestUnderstandingProjectionCeilsOrphanProfileDependencyWithoutPageCard(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "orphan-without-page.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://app.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertProfile(scanID, &types.PageProfile{
		ID: "GET /admin", Method: http.MethodGet, URL: "https://app.example.test/admin",
		Purpose: "Administrative console", AuthRequired: "required", Confidence: .9,
	}); err != nil {
		t.Fatal(err)
	}
	u := extract.NewAppUnderstanding()
	u.Summary = "Administrators approve tenant records."
	u.Recon.Identity.Summary = u.Summary
	u.Recon.Roles = []extract.ReconRole{{
		ID: "administrator", Name: "Administrator",
		Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: "GET /admin"}},
	}}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.projectUnderstandingRedirectEvidence(scanID, u)
	if len(u.Recon.Roles) != 0 {
		t.Fatalf("orphan-backed role escaped because page card was absent: %+v", u.Recon.Roles)
	}
	if !strings.Contains(strings.ToLower(u.Recon.Identity.Summary), "not backed by a verifiable direct page response") {
		t.Fatalf("summary = %q", u.Recon.Identity.Summary)
	}
}

func TestUnderstandingProjectsRedirectOnlyAdminClaimsAsUnverified(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://partner.example.test/auth/login", `{}`)
	if err != nil {
		t.Fatal(err)
	}

	summary := "Partner food-delivery portal. Partners authenticate to access the admin dashboard."
	if err := db.UpsertAppUnderstanding(scanID, "api_service", `[]`, `[]`, `{}`, summary); err != nil {
		t.Fatal(err)
	}
	u := extract.NewAppUnderstanding()
	u.AppType = "api_service"
	u.Summary = summary
	u.Recon.Pages = []extract.PagePurposeCard{
		{
			ID: "GET /admin", Method: "GET", URL: "https://partner.example.test/admin",
			Purpose: "Administrative dashboard for partners", Area: "admin", AuthRequired: "session_cookie",
			Actions: []string{"View partner records"}, ObjectIDs: []string{"partner"},
			SecurityInterest: []string{"Privileged admin surface"}, Confidence: .85,
			Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: "GET /admin"}},
		},
		{
			ID: "GET /auth/login", Method: "GET", URL: "https://partner.example.test/auth/login",
			Purpose: "Sign-in form", Area: "authentication", Confidence: .9,
		},
	}
	u.Recon.Roles = []extract.ReconRole{{
		ID: "authenticated_partner", Name: "Authenticated partner",
		Description: "Can access the protected admin dashboard", Confidence: .8,
		Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: "GET /admin"}},
	}}
	u.Recon.Unknowns = []extract.ReconUnknown{{
		ID: "admin_role_enforcement", Question: "Does /admin enforce role beyond authentication?",
		WhyItMatters: "Privilege escalation if any authenticated role is accepted.", Priority: 9,
		// Historical models sometimes used the generic gap sentinel even while
		// naming a concrete route. The read-time projection must still apply the
		// route's direct redirect evidence ceiling.
		Evidence: []extract.ReconEvidence{{Kind: "inference", Ref: "gap"}},
	}}
	if err := db.UpsertReconModel(scanID, u.ReconJSON()); err != nil {
		t.Fatal(err)
	}
	for _, profile := range []types.PageProfile{
		{ID: "GET /admin", Method: "GET", URL: "https://partner.example.test/admin", Purpose: "Administrative dashboard for partners", AuthRequired: "session_cookie", Confidence: .85},
		{ID: "GET /auth/login", Method: "GET", URL: "https://partner.example.test/auth/login", Purpose: "Sign-in form", Confidence: .9},
	} {
		profile := profile
		if err := db.UpsertProfile(scanID, &profile); err != nil {
			t.Fatal(err)
		}
	}
	for _, entry := range []*types.TrafficEntry{
		{
			Request: types.CapturedRequest{Method: "GET", URL: "https://partner.example.test/admin", Headers: map[string]string{}},
			Response: types.CapturedResponse{StatusCode: http.StatusFound, Headers: map[string]string{
				"Location": "/account/logout?redirect=%2Fadmin",
			}},
			Timestamp: time.Now(),
		},
		{
			Request:   types.CapturedRequest{Method: "GET", URL: "https://partner.example.test/auth/login", Headers: map[string]string{}},
			Response:  types.CapturedResponse{StatusCode: http.StatusOK, Headers: map[string]string{}, ContentType: "text/html", Body: []byte("<form>Sign in</form>")},
			Timestamp: time.Now(),
		},
	} {
		if _, err := db.InsertTraffic(scanID, entry); err != nil {
			t.Fatal(err)
		}
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	s.handleUnderstanding(w, httptest.NewRequest(http.MethodGet,
		"/api/understanding?scan_id="+strconv.FormatInt(scanID, 10), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var response struct {
		Summary string             `json:"summary"`
		Recon   extract.ReconModel `json:"recon"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	for _, renderedSummary := range []string{response.Summary, response.Recon.Identity.Summary} {
		lower := strings.ToLower(renderedSummary)
		if strings.Contains(lower, "access the admin dashboard") {
			t.Fatalf("stale semantic claim survived: %q", renderedSummary)
		}
		if !strings.Contains(lower, "backing route existence and business purpose remain unverified") || !strings.Contains(renderedSummary, "/admin") {
			t.Fatalf("summary lacks redirect evidence ceiling: %q", renderedSummary)
		}
	}
	var admin *extract.PagePurposeCard
	for i := range response.Recon.Pages {
		if response.Recon.Pages[i].ID == "GET /admin" {
			admin = &response.Recon.Pages[i]
			break
		}
	}
	if admin == nil {
		t.Fatalf("admin card missing: %s", w.Body.String())
	}
	if lower := strings.ToLower(admin.Purpose); !strings.Contains(lower, "only a redirect") || !strings.Contains(lower, "unverified") || strings.Contains(lower, "administrative dashboard") {
		t.Fatalf("admin purpose = %q", admin.Purpose)
	}
	if admin.Area != "authentication" || admin.AuthRequired != "unknown" || admin.Confidence != .35 || len(admin.ObjectIDs) != 0 || len(admin.SecurityInterest) != 0 {
		t.Fatalf("admin card was not evidence-capped: %+v", *admin)
	}
	for _, role := range response.Recon.Roles {
		if role.ID == "authenticated_partner" {
			t.Fatalf("redirect-only role survived: %+v", role)
		}
	}
	foundUnknown := false
	for _, unknown := range response.Recon.Unknowns {
		if unknown.ID != "admin_role_enforcement" {
			continue
		}
		foundUnknown = true
		if !strings.Contains(unknown.Question, "unverified direct-response evidence for GET /admin") || strings.Contains(strings.ToLower(unknown.Question), "which partner role") {
			t.Fatalf("redirect-only unknown was not reframed: %+v", unknown)
		}
	}
	if !foundUnknown {
		t.Fatalf("evidence gap should remain as a reframed unknown: %s", w.Body.String())
	}
}

func TestRedirectProjectionPrunesExclusiveDependenciesAndKeepsDirectlyObservedOnes(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://partner.example.test/", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range []types.PageProfile{
		{ID: "GET /admin", Method: "GET", URL: "https://partner.example.test/admin", Purpose: "Administrative dashboard", Confidence: .9},
		{ID: "POST /logout", Method: "POST", URL: "https://partner.example.test/logout", Purpose: "End the current session", Confidence: .9},
	} {
		profile := profile
		if err := db.UpsertProfile(scanID, &profile); err != nil {
			t.Fatal(err)
		}
	}
	for _, entry := range []*types.TrafficEntry{
		{
			Request:   types.CapturedRequest{Method: "GET", URL: "https://partner.example.test/admin", Headers: map[string]string{}},
			Response:  types.CapturedResponse{StatusCode: http.StatusFound, Headers: map[string]string{"Location": "/login?redirect=%2Fadmin"}},
			Timestamp: time.Now(),
		},
		{
			Request:   types.CapturedRequest{Method: "POST", URL: "https://partner.example.test/logout", Headers: map[string]string{}},
			Response:  types.CapturedResponse{StatusCode: http.StatusOK, Headers: map[string]string{}, ContentType: "application/json", Body: []byte(`{"logged_out":true}`)},
			Timestamp: time.Now(),
		},
	} {
		if _, err := db.InsertTraffic(scanID, entry); err != nil {
			t.Fatal(err)
		}
	}

	u := extract.NewAppUnderstanding()
	u.Summary = "Partner portal with an admin dashboard and logout flow."
	u.Recon.Identity.Summary = u.Summary
	u.Recon.Pages = []extract.PagePurposeCard{
		{ID: "GET /admin", Method: "GET", URL: "https://partner.example.test/admin", Purpose: "Administrative dashboard", ObjectIDs: []string{"partner_records"}, Confidence: .9},
		{ID: "POST /logout", Method: "POST", URL: "https://partner.example.test/logout", Purpose: "End the current session", ObjectIDs: []string{"logout_receipt"}, Confidence: .9},
	}
	u.Recon.Roles = []extract.ReconRole{
		{ID: "admin", Name: "Administrator", Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: "GET /admin"}}},
		{ID: "signed_in_user", Name: "Signed-in user", Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: "POST /logout"}}},
	}
	u.Recon.Objects = []extract.BusinessObject{
		{ID: "partner_records", Name: "Partner records", OwnerRoleIDs: []string{"admin"}, Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: "GET /admin"}}},
		{ID: "logout_receipt", Name: "Logout receipt", OwnerRoleIDs: []string{"signed_in_user"}, Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: "POST /logout"}}},
	}
	u.Recon.Workflows = []extract.BusinessWorkflow{
		{ID: "admin_review", Name: "Review partner records", Steps: []extract.WorkflowStep{{ID: "open_admin", PageIDs: []string{"GET /admin"}, RoleIDs: []string{"admin"}, ObjectIDs: []string{"partner_records"}}}, Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: "GET /admin"}}},
		{ID: "logout", Name: "Log out", Steps: []extract.WorkflowStep{{ID: "logout", PageIDs: []string{"POST /logout"}, RoleIDs: []string{"signed_in_user"}, ObjectIDs: []string{"logout_receipt"}, StateChange: true}}, Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: "POST /logout"}}},
	}
	u.Recon.OwnershipBoundaries = []extract.OwnershipBoundary{{
		ID: "admin_ownership", ObjectID: "partner_records", OwnerRoleID: "admin", Rule: "Admins own partner records", EnforcedAt: []string{"GET /admin"},
		Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: "GET /admin"}},
	}}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.projectUnderstandingRedirectEvidence(scanID, u)
	if len(u.Recon.Roles) != 1 || u.Recon.Roles[0].ID != "signed_in_user" {
		t.Fatalf("roles = %+v", u.Recon.Roles)
	}
	if len(u.Recon.Objects) != 1 || u.Recon.Objects[0].ID != "logout_receipt" {
		t.Fatalf("objects = %+v", u.Recon.Objects)
	}
	if len(u.Recon.Workflows) != 1 || u.Recon.Workflows[0].ID != "logout" {
		t.Fatalf("workflows = %+v", u.Recon.Workflows)
	}
	if len(u.Recon.OwnershipBoundaries) != 0 {
		t.Fatalf("boundaries = %+v", u.Recon.OwnershipBoundaries)
	}
	if len(u.Recon.Pages[0].ObjectIDs) != 0 || len(u.Recon.Pages[1].ObjectIDs) != 1 || u.Recon.Pages[1].ObjectIDs[0] != "logout_receipt" {
		t.Fatalf("page object links = %+v", u.Recon.Pages)
	}
}

func TestRedirectProjectionRouteMentionIsExactAndPreservesMechanicsQuestions(t *testing.T) {
	if !textMentionsRoutePath("Does /admin enforce a partner role?", "/admin") {
		t.Fatal("exact route token was not recognized")
	}
	if textMentionsRoutePath("What is served by /api/v1?", "/api") {
		t.Fatal("route prefix was mistaken for the exact redirect-only path")
	}
	if !redirectMechanicsQuestion("Can the /admin redirect parameter become an open redirect?") {
		t.Fatal("redirect-mechanics question was not preserved")
	}
	model := extract.ReconModel{
		Pages: []extract.PagePurposeCard{{ID: "GET /admin", URL: "https://partner.example.test/admin"}},
		Unknowns: []extract.ReconUnknown{{
			ID: "admin-role", Question: "Does /admin enforce role beyond authentication?",
			Evidence: []extract.ReconEvidence{{Kind: "inference", Ref: "gap"}},
		}},
	}
	projectRedirectOnlyReconDependencies(&model, map[string]bool{"GET /admin": true}, map[string]string{"GET /admin": "/admin"})
	if !strings.Contains(model.Unknowns[0].Question, "unverified direct-response evidence for GET /admin") {
		t.Fatalf("gap-backed route question was not reframed: %+v", model.Unknowns[0])
	}
}

func TestUnderstandingKeepsAdminSemanticsWhenDirectContentWasObserved(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://partner.example.test/admin", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	summary := "Authenticated admin dashboard for partner operations."
	if err := db.UpsertAppUnderstanding(scanID, "internal_tool", `[]`, `[]`, `{}`, summary); err != nil {
		t.Fatal(err)
	}
	u := extract.NewAppUnderstanding()
	u.AppType = "internal_tool"
	u.Summary = summary
	u.Recon.Pages = []extract.PagePurposeCard{{
		ID: "GET /admin", Method: "GET", URL: "https://partner.example.test/admin",
		Purpose: "Administrative dashboard", Area: "admin", Confidence: .9,
	}}
	if err := db.UpsertReconModel(scanID, u.ReconJSON()); err != nil {
		t.Fatal(err)
	}
	profile := types.PageProfile{ID: "GET /admin", Method: "GET", URL: "https://partner.example.test/admin", Purpose: "Administrative dashboard", Confidence: .9}
	if err := db.UpsertProfile(scanID, &profile); err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertTraffic(scanID, &types.TrafficEntry{
		Request:   types.CapturedRequest{Method: "GET", URL: profile.URL, Headers: map[string]string{}},
		Response:  types.CapturedResponse{StatusCode: http.StatusOK, Headers: map[string]string{}, ContentType: "text/html", Body: []byte("<main>Partner operations</main>")},
		Timestamp: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	s.handleUnderstanding(w, httptest.NewRequest(http.MethodGet,
		"/api/understanding?scan_id="+strconv.FormatInt(scanID, 10), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var response struct {
		Summary string             `json:"summary"`
		Recon   extract.ReconModel `json:"recon"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Summary != summary || len(response.Recon.Pages) != 1 || response.Recon.Pages[0].Purpose != "Administrative dashboard" {
		t.Fatalf("direct content was incorrectly downgraded: %s", w.Body.String())
	}
}

func TestUnderstandingReportsObservedDiscoveryDiversity(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://letterboxd.test/", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	profiles := []types.PageProfile{
		{ID: "GET /films", URL: "https://letterboxd.test/films/", Method: "GET", Purpose: "Film catalog", TemplateID: "catalog-list", Confidence: .9},
		{ID: "GET /reviews", URL: "https://letterboxd.test/reviews/", Method: "GET", Purpose: "Popular member reviews", TemplateID: "review-list", Confidence: .9},
		{ID: "GET /reviews/{token}", URL: "https://letterboxd.test:443/reviews/", Method: "GET", Purpose: "", Confidence: .1},
		{ID: "GET /settings", URL: "https://letterboxd.test/settings/", Method: "GET", Purpose: "Account settings", TemplateID: "account-form", Confidence: .8},
		{ID: "GET /profile", URL: "https://letterboxd.test/account/profile/", Method: "GET", Purpose: "Account profile", TemplateID: "account-form", Confidence: .8},
	}
	for i := range profiles {
		if err := db.UpsertProfile(scanID, &profiles[i]); err != nil {
			t.Fatal(err)
		}
	}
	for _, observedURL := range []string{
		"https://letterboxd.test/films/",
		"https://letterboxd.test/reviews/",
		"https://letterboxd.test/settings/",
		"https://letterboxd.test/account/profile/",
	} {
		if _, err := db.InsertTraffic(scanID, &types.TrafficEntry{
			Request: types.CapturedRequest{Method: http.MethodGet, URL: observedURL},
			Response: types.CapturedResponse{
				StatusCode: http.StatusOK, Headers: map[string]string{}, ContentType: "text/html",
				Body: []byte("<main>Representative application page</main>"),
			},
		}); err != nil {
			t.Fatal(err)
		}
	}

	quality := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil))).reconDiscoveryQuality(scanID)
	if quality.Profiles != 4 || quality.ResponseTemplates != 3 || quality.Spread != "developing" {
		t.Fatalf("discovery quality = %+v", quality)
	}
	if quality.DominantSurface != "account" || quality.SurfaceCounts["account"] != 2 {
		t.Fatalf("dominant surface = %+v", quality)
	}
	want := []string{"account", "catalog", "review"}
	if len(quality.SemanticSurfaces) != len(want) {
		t.Fatalf("semantic surfaces = %#v", quality.SemanticSurfaces)
	}
	for i := range want {
		if quality.SemanticSurfaces[i] != want[i] {
			t.Fatalf("semantic surfaces = %#v, want %#v", quality.SemanticSurfaces, want)
		}
	}
}

func TestDiscoveryQualityDoesNotPromoteUnverifiedRouteName(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "quality-unverified.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://app.example.test/", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	admin := types.PageProfile{
		ID: "GET /admin", URL: "https://app.example.test/admin", Method: http.MethodGet,
		Purpose: "Administrative dashboard", TemplateID: "login-shell", Confidence: .95,
	}
	if err := db.UpsertProfile(scanID, &admin); err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertTraffic(scanID, &types.TrafficEntry{
		Request: types.CapturedRequest{Method: http.MethodGet, URL: admin.URL},
		Response: types.CapturedResponse{StatusCode: http.StatusFound, Headers: map[string]string{
			"Location": "/auth/login?redirect=%2Fadmin",
		}},
	}); err != nil {
		t.Fatal(err)
	}

	quality := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil))).reconDiscoveryQuality(scanID)
	if quality.Profiles != 1 {
		t.Fatalf("route observation disappeared instead of remaining unverified: %+v", quality)
	}
	if quality.ResponseTemplates != 0 || len(quality.SemanticSurfaces) != 0 || quality.DominantSurface != "" {
		t.Fatalf("unverified /admin inflated semantic discovery quality: %+v", quality)
	}
}
