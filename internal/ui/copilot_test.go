package ui

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

func TestTargetCopilotDrawerAndContextContractsAreEmbedded(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, contract := range []string{
		"TARGET COPILOT",
		"id=\"copilotDrawer\"",
		"id=\"copilotContext\"",
		"function toggleCopilot",
		"function collectCopilotContext",
		"function selectedCopilotNode",
		"function refreshAskSurfaces",
		"context: workspace",
		"id=\"copilotModelLabel\"",
		"question: q, history: askTurns",
		"resume_state: act.resume_state, approved",
		"Grounded in this scan's evidence + Knowledge",
		"async function loadCopilotThread",
		"historical:Boolean(turn.answer)",
		"historicalCorrected:Boolean(turn.historical_corrected)",
		"Saved answer · not reused as current evidence · re-check before acting",
		"Saved answer · stale route claims removed using current direct evidence",
		"copilot-history-note",
		"only answers produced in this page session enter askTurns",
		"/api/copilot/thread?scan_id=",
		"function askEvidenceHTML",
		"async function openCopilotEvidence",
		"function copilotActionHistoryFromSteps",
		"function copilotDirectiveRefreshNeeded",
		"copilotOpen && !askBusy && copilotDirectiveRefreshNeeded()",
		"approval_decision",
		"Brief me: what is observed, inferred, and still unknown",
		"function askReconObjective",
		"Plan with Copilot",
		"function askInlineMd",
		"copilot-answer-heading",
		"copilot-answer-divider",
		"function rcAuthorityAwareNext",
		"authorization bypass",
		"open redirect",
		"submitting",
		"bucket directly",
		"Hypothesis, not a verified exploit",
		"SEPARATE ACTIVE RUN REQUIRED",
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("embedded Target Copilot missing %q", contract)
		}
	}
	if strings.Contains(html, "question: q, model: 'qwen2.5:32b'") ||
		strings.Contains(html, "approved, model: 'qwen2.5:32b'") {
		t.Fatal("Target Copilot must inherit the scan model instead of sending a hardcoded browser model")
	}
}

func TestHandleCopilotThreadRestoresAndClearsPersistedTurns(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, _ := db.CreateScan("https://app.example.test", `{}`)
	turnID, err := db.CreateCopilotTurn(scanID, "What is proven?")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateCopilotTurn(turnID, store.CopilotTurnUpdate{
		Status:       "completed",
		Answer:       "One finding is proven.",
		EvidenceJSON: `[{"kind":"finding","id":"7","label":"Proof"}]`,
	}); err != nil {
		t.Fatal(err)
	}
	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/copilot/thread?scan_id="+stringID(scanID), nil)
	s.handleCopilotThread(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "What is proven?") ||
		!strings.Contains(w.Body.String(), `"evidence_refs"`) {
		t.Fatalf("thread response status=%d body=%s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodDelete, "/api/copilot/thread?scan_id="+stringID(scanID), nil)
	s.handleCopilotThread(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", w.Code, w.Body.String())
	}
	turns, err := db.CopilotThread(scanID, 20)
	if err != nil || len(turns) != 0 {
		t.Fatalf("cleared turns = (%+v, %v)", turns, err)
	}
}

func TestHandleCopilotThreadSanitizesStaleRouteClaimsBeforeDisplay(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, _ := db.CreateScan("https://partner.example.test/auth/login", `{}`)
	adminURL := "https://partner.example.test/admin"
	if err := db.UpsertProfile(scanID, &types.PageProfile{
		ID: "GET /admin", Method: http.MethodGet, URL: adminURL,
		Purpose: "Administrative dashboard for partners", Confidence: .9,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertTraffic(scanID, &types.TrafficEntry{
		Request: types.CapturedRequest{Method: http.MethodGet, URL: adminURL},
		Response: types.CapturedResponse{StatusCode: http.StatusFound, Headers: map[string]string{
			"Location": "/auth/login?redirect=%2Fadmin",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	turnID, err := db.CreateCopilotTurn(scanID, "What does /admin do?")
	if err != nil {
		t.Fatal(err)
	}
	answer := "- /admin is an authenticated dashboard for partner admins.\n- /admin remains unverified because only redirect evidence was observed.\n- The login form is observed."
	if err := db.UpdateCopilotTurn(turnID, store.CopilotTurnUpdate{Status: "completed", Answer: answer}); err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/copilot/thread?scan_id="+stringID(scanID), nil)
	s.handleCopilotThread(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if strings.Contains(body, "authenticated dashboard") {
		t.Fatalf("stale semantic claim survived history projection: %s", body)
	}
	for _, want := range []string{"Historical claim removed", "remains unverified", `"historical_corrected":true`} {
		if !strings.Contains(body, want) {
			t.Fatalf("projected history missing %q: %s", want, body)
		}
	}
}

func TestHandleCopilotThreadRefreshesDirectiveStatus(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, _ := db.CreateScan("https://app.example.test", `{}`)
	directiveID, err := db.InsertFollowUp(scanID, store.FollowUp{
		SourceAgent: "copilot", Action: "visit", URL: "https://app.example.test/docs", Priority: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := db.ClaimFollowUps(scanID, 1, 0)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim directive = (%+v, %v)", claimed, err)
	}
	if err := db.CompleteFollowUp(scanID, directiveID, claimed[0].LeaseToken, store.FollowUpDone, "visited"); err != nil {
		t.Fatal(err)
	}
	turnID, err := db.CreateCopilotTurn(scanID, "Visit the docs route")
	if err != nil {
		t.Fatal(err)
	}
	steps := fmt.Sprintf(`[{"directive_id":%d,"directive_action":"visit","directive_status":"pending","approval_decision":"approved","proposal":{"kind":"directive"}}]`, directiveID)
	if err := db.UpdateCopilotTurn(turnID, store.CopilotTurnUpdate{Status: "completed", Answer: "Queued the visit.", StepsJSON: steps}); err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/copilot/thread?scan_id="+stringID(scanID), nil)
	s.handleCopilotThread(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"directive_status":"done"`) {
		t.Fatalf("thread did not expose terminal directive status: status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestCopilotModelFromConfigInheritsScanProvider(t *testing.T) {
	tests := []struct {
		name       string
		configJSON string
		want       copilotModelConfig
	}{
		{
			name:       "GLM scan derives z.ai endpoint for legacy config",
			configJSON: `{"LLM":{"Provider":"openai-compatible","Model":"glm-5.2"}}`,
			want: copilotModelConfig{
				Provider: "openai-compatible",
				Model:    "glm-5.2",
				BaseURL:  "https://api.z.ai/api/coding/paas/v4",
				Source:   "scan",
			},
		},
		{
			name:       "custom compatible endpoint is preserved",
			configJSON: `{"LLM":{"Provider":"openai-compatible","Model":"deepseek-chat","BaseURL":"https://models.example.test/v1"}}`,
			want: copilotModelConfig{
				Provider: "openai-compatible",
				Model:    "deepseek-chat",
				BaseURL:  "https://models.example.test/v1",
				Source:   "scan",
			},
		},
		{
			name:       "crawl-only legacy scan keeps local fallback",
			configJSON: `{}`,
			want: copilotModelConfig{
				Provider: "ollama",
				Model:    "qwen2.5:32b",
				Source:   "fallback",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := copilotModelFromConfig(tt.configJSON); got != tt.want {
				t.Fatalf("copilotModelFromConfig() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestResolveCopilotModelUsesInMemoryScanCredential(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://app.example.test", `{"LLM":{"Provider":"openai-compatible","Model":"glm-5.2","BaseURL":"https://api.z.ai/api/coding/paas/v4","APIKey":"must-not-be-read"}}`)
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.rememberCopilotCredential("openai-compatible", "https://api.z.ai/api/coding/paas/v4", "typed-in-ui")

	got, key, err := s.resolveCopilotModel(scanID, "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Provider != "openai-compatible" || got.Model != "glm-5.2" {
		t.Fatalf("resolved model = %#v", got)
	}
	if key != "typed-in-ui" {
		t.Fatalf("credential = %q, want in-memory credential", key)
	}
}

func TestHandleScanExposesCopilotModelWithoutCredential(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://app.example.test", `{"LLM":{"Provider":"openai-compatible","Model":"glm-5.2","BaseURL":"https://api.z.ai/api/coding/paas/v4","APIKey":"server-secret"}}`)
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(db, t.TempDir(), "127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/scan?scan_id="+stringID(scanID), nil)
	s.handleScan(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["copilot_provider"] != "openai-compatible" || got["copilot_model"] != "glm-5.2" || got["copilot_model_source"] != "scan" {
		t.Fatalf("scan model metadata = %#v", got)
	}
	if strings.Contains(w.Body.String(), "server-secret") || strings.Contains(w.Body.String(), "api.z.ai") {
		t.Fatalf("browser-facing scan response leaked a credential or endpoint: %s", w.Body.String())
	}
}

func stringID(id int64) string {
	return fmt.Sprintf("%d", id)
}

func TestTargetCopilotSeparatesNavigationAndApprovedEffects(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, contract := range []string{
		"async function applyCopilotUIActions",
		"switch_view",
		"set_graph_mode",
		"focus_graph",
		"set_graph_filter",
		"focus_recon",
		"data-recon-id",
		"Recon focus ·",
		"Redirect active scan?",
		"Approve & queue",
		"Approve & send",
		"s.request || s.directive_action || s.directive_status",
		"Requests and scan steering always require approval",
		"decision: 'pending'",
		"rec.decision = 'failed'",
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("Target Copilot action boundary missing %q", contract)
		}
	}
}

func TestTargetCopilotIsDockedAndResponsive(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, contract := range []string{
		"--copilot-w: 390px",
		"body.copilot-open .copilot-drawer",
		"@media (max-width: 1440px)",
		"position: fixed; z-index: 180",
		"body.copilot-open .atlas-zoom",
		"body.copilot-open .atlas-minimap",
		"body.home-mode .copilot-drawer",
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("responsive Target Copilot missing %q", contract)
		}
	}
}
