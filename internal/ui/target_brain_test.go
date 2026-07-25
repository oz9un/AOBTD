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

	scanagent "github.com/ozzyw/aobtd/internal/agent"
	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

func TestTargetBrainAPIUsesExactCapturedQueueAndNormalizedGaps(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "brain.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://app.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	entry := &types.TrafficEntry{
		Request: types.CapturedRequest{Method: "GET", URL: "https://app.test/login", Headers: map[string]string{}},
		Response: types.CapturedResponse{
			StatusCode: 200, Headers: map[string]string{}, ContentType: "text/html",
			Body: []byte(`<form><input name="email"><input name="password"></form>`),
		},
		Timestamp: time.Now(),
	}
	if _, err := db.InsertTraffic(scanID, entry); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Conn().Exec(`UPDATE traffic SET relevance_score=.9, relevance_scored=TRUE WHERE scan_id=?`, scanID); err != nil {
		t.Fatal(err)
	}
	u := extract.NewAppUnderstanding()
	u.AppType = "saas"
	u.Summary = "Observed application login surface."
	u.Recon.Pages = []extract.PagePurposeCard{{
		ID: "GET /login", Method: "GET", URL: "https://app.test/login", Purpose: "Sign in", Area: "authentication", Confidence: .9,
		Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: "GET /login"}},
	}}
	u.Recon.Unknowns = []extract.ReconUnknown{{
		ID: "login-actor-gap", Question: "Which login boundary distinguishes anonymous and authenticated actors?",
		SuggestedAction: "Analyze the observed login response.", Priority: 10,
		Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: "GET /login"}},
	}}
	if err := db.UpsertAppUnderstanding(scanID, u.AppType, "[]", "[]", "{}", u.Summary); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertReconModel(scanID, u.ReconJSON()); err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	s.handleTargetBrain(w, httptest.NewRequest(http.MethodGet,
		"/api/target-brain?scan_id="+strconv.FormatInt(scanID, 10), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var brain scanagent.TargetBrainSnapshot
	if err := json.Unmarshal(w.Body.Bytes(), &brain); err != nil {
		t.Fatal(err)
	}
	if brain.ScanID != scanID || brain.Focus == nil || brain.Focus.ID == "" || !brain.Focus.EvidenceReady {
		t.Fatalf("focus = %+v body=%s", brain.Focus, w.Body.String())
	}
	if len(brain.Moves) == 0 || brain.Moves[0].Mode != "analyze" || brain.Moves[0].EvidenceID == 0 || brain.Moves[0].URL != "https://app.test/login" {
		t.Fatalf("captured move = %+v body=%s", brain.Moves, w.Body.String())
	}
	foundFocusImpact := false
	for _, impact := range brain.Moves[0].Expected {
		foundFocusImpact = foundFocusImpact || impact.ID == brain.Focus.ID
	}
	if len(brain.Moves[0].Expected) == 0 || !foundFocusImpact {
		t.Fatalf("move lost exact gap impact: %+v", brain.Moves[0])
	}
	if len(brain.Dimensions) != 7 || brain.Fingerprint == "" || brain.Saturation.ExactMoves == 0 {
		t.Fatalf("briefing contract incomplete: %+v", brain)
	}
}

func TestTargetBrainUsesRedirectEvidenceProjectionBeforePlanning(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "brain.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://partner.example.test/admin", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	profile := types.PageProfile{
		ID: "GET /admin", Method: "GET", URL: "https://partner.example.test/admin",
		Purpose: "Administrative dashboard", AuthRequired: "session_cookie", Confidence: .9,
	}
	if err := db.UpsertProfile(scanID, &profile); err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertTraffic(scanID, &types.TrafficEntry{
		Request: types.CapturedRequest{Method: "GET", URL: profile.URL, Headers: map[string]string{}},
		Response: types.CapturedResponse{StatusCode: http.StatusFound, Headers: map[string]string{
			"Location": "/auth/login?redirect=%2Fadmin",
		}},
		Timestamp: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	u := extract.NewAppUnderstanding()
	u.AppType = "internal_tool"
	u.Summary = "Partners authenticate to access the admin dashboard."
	u.Recon.Pages = []extract.PagePurposeCard{{
		ID: "GET /admin", Method: "GET", URL: profile.URL, Purpose: "Administrative dashboard", Area: "admin", Confidence: .9,
		Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: "GET /admin"}},
	}}
	u.Recon.Roles = []extract.ReconRole{{
		ID: "partner_admin", Name: "Authenticated partner administrator", Confidence: .8,
		Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: "GET /admin"}},
	}}
	u.Recon.Unknowns = []extract.ReconUnknown{{
		ID: "admin_role_enforcement", Question: "Which role can access the admin dashboard?", Priority: 10,
		Evidence: []extract.ReconEvidence{{Kind: "endpoint", Ref: "GET /admin"}},
	}}
	if err := db.UpsertAppUnderstanding(scanID, u.AppType, "[]", "[]", "{}", u.Summary); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertReconModel(scanID, u.ReconJSON()); err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	s.handleTargetBrain(w, httptest.NewRequest(http.MethodGet,
		"/api/target-brain?scan_id="+strconv.FormatInt(scanID, 10), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var brain scanagent.TargetBrainSnapshot
	if err := json.Unmarshal(w.Body.Bytes(), &brain); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(brain.Thesis.Summary), "access the admin dashboard") || !strings.Contains(strings.ToLower(brain.Thesis.Summary), "remain unverified") {
		t.Fatalf("thesis = %+v", brain.Thesis)
	}
	foundRedirectGap := false
	for _, dimension := range brain.Dimensions {
		for _, claim := range dimension.Claims {
			if strings.Contains(claim.Label, "Authenticated partner administrator") {
				t.Fatalf("redirect-only actor reached Target Brain: %+v", claim)
			}
			if dimension.ID == "unknowns" && strings.Contains(claim.Label, "unverified direct-response evidence for GET /admin") {
				foundRedirectGap = true
			}
		}
	}
	if !foundRedirectGap {
		t.Fatalf("Target Brain did not receive the reframed evidence gap: %+v", brain.Dimensions)
	}
}

func TestTargetBrainUIContractNamesHonestAdaptiveStates(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`api('/api/target-brain')`,
		`function rcRenderTargetBrain`,
		`Target Brain`,
		`Observed, inferred, unknown`,
		`Exact captured response`,
		`not proof that one route caused`,
		`needs_capture`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("Target Brain UI contract missing %q", want)
		}
	}
}
