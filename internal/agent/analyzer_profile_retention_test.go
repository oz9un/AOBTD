package agent

import (
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

func TestSalvagePageProfileFromProviderTruncatedJSON(t *testing.T) {
	body := `{
  "id":"GET /account/login/",
  "url":"https://example.test/account/login/",
  "method":"GET",
  "purpose":"Account sign-in boundary observed in the captured response.",
  "inputs":[{"name":"next","type":"string","location":"query","required":false}],
  "auth_required":"public login entry",
  "data_exposed":["login form"],
  "issues":[],
  "relationships":["redirects to account home", "unfinished`
	got := salvagePageProfileFromPartial(body)
	if got == nil {
		t.Fatal("expected complete leading fields to be salvaged")
	}
	if got.ID != "GET /account/login/" || got.URL != "https://example.test/account/login/" || got.Purpose == "" {
		t.Fatalf("wrong recovered identity: %+v", got)
	}
	if got.Confidence != 0.35 {
		t.Fatalf("salvaged profile must stay explicitly low confidence, got %.2f", got.Confidence)
	}
	if len(got.Inputs) != 1 || len(got.DataExposed) != 1 {
		t.Fatalf("complete arrays were not recovered: inputs=%+v data=%+v", got.Inputs, got.DataExposed)
	}
	if len(got.Relationships) != 0 {
		t.Fatalf("unfinished array must not be guessed: %+v", got.Relationships)
	}
}

func TestSalvagePageProfileRequiresCompleteGroundedIdentity(t *testing.T) {
	body := `{"id":"GET /login","url":"https://example.test/login","purpose":"unfinished`
	if got := salvagePageProfileFromPartial(body); got != nil {
		t.Fatalf("incomplete purpose was promoted: %+v", got)
	}
}

func TestParseProfileRepairsMiniMaxJSONStringRepeatExpression(t *testing.T) {
	analyzer := &AnalyzerAgent{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	body := `{
  "id":"POST /api/Complaints/",
  "url":"http://juice-shop.test:3000/api/Complaints/",
  "method":"POST",
  "purpose":"Submit a customer complaint.",
  "confidence":0.82,
  "follow_ups":[{
    "action":"probe_logic",
    "url":"http://juice-shop.test:3000/api/Complaints/",
    "field":"message",
    "test_values":["A".repeat(10000),""],
    "reason":"Check bounded length validation."
  }]
}`
	got := analyzer.parseProfile(body)
	if got == nil {
		t.Fatal("MiniMax profile with a JavaScript-style repeat expression was not repaired")
	}
	if got.ID != "POST /api/Complaints/" || got.Confidence != 0.82 {
		t.Fatalf("complete profile was degraded instead of repaired: %+v", got)
	}
	var repaired map[string]any
	if err := json.Unmarshal([]byte(repairModelJSONExpressions(body)), &repaired); err != nil {
		t.Fatalf("repaired response is not valid JSON: %v", err)
	}
	if !strings.Contains(repairModelJSONExpressions(body), `"A (repeat 10000 times)"`) {
		t.Fatalf("unsafe repeat expression was not converted to a bounded descriptive literal")
	}
}

func TestParseProfileRepairsMiniMaxDroppedIDPrefix(t *testing.T) {
	analyzer := &AnalyzerAgent{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	body := `": "GET /index.php",
  "url": "http://127.0.0.1:4280/index.php",
  "method": "GET",
  "purpose": "DVWA landing page listing vulnerability modules.",
  "confidence": 0.82,
  "inputs": [],
  "issues": []
}`
	got := analyzer.parseProfile(body)
	if got == nil {
		t.Fatal("MiniMax profile with dropped id prefix was not repaired")
	}
	if got.ID != "GET /index.php" || got.URL != "http://127.0.0.1:4280/index.php" || got.Confidence != 0.82 {
		t.Fatalf("wrong repaired profile: %+v", got)
	}
}

func TestRepairDroppedProfileIDPrefixRequiresProfileShape(t *testing.T) {
	body := `": "GET /index.php", "url": "http://127.0.0.1:4280/index.php"}`
	if got := repairDroppedProfileIDPrefix(body); got != body {
		t.Fatalf("fragment without profile shape was repaired: %q", got)
	}
}

func TestStoreExtractedInputsDoesNotClobberAnalyzedProfile(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "profiles.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}

	const profileID = "GET /secure/account"
	if err := db.UpsertProfile(scanID, &types.PageProfile{
		ID: profileID, URL: "https://example.test/secure/account", Method: "GET",
		Purpose: "SAML account gateway", AuthRequired: "session", Confidence: .9,
		Inputs:  []types.Input{{Name: "SAMLRequest", Type: "hidden", Location: "body"}},
		Issues:  []string{"Cross-domain session boundary requires review"},
		HasAuth: true,
	}); err != nil {
		t.Fatal(err)
	}

	analyzer := &AnalyzerAgent{
		db: db, scanID: scanID,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	bundle := &extract.EndpointBundle{
		Method: "GET", URLPattern: "/secure/account", SampleURL: "https://example.test/secure/account",
		HasInput: true, HasErrors: true,
		QueryParams: []extract.ParamVariant{{Name: "RelayState", Type: "string", Location: "query"}},
	}
	analyzer.storeExtractedInputs(bundle, []types.TrafficEntry{{
		Request: types.CapturedRequest{Method: "GET", URL: bundle.SampleURL, Path: bundle.URLPattern},
		Response: types.CapturedResponse{StatusCode: 200, ContentType: "text/html", Body: []byte(
			`<html><body><h1>Account overview</h1><p>Current organization settings</p></body></html>`)},
	}})

	got, err := db.GetProfile(scanID, profileID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Purpose != "SAML account gateway" || got.AuthRequired != "session" || got.Confidence != .9 {
		t.Fatalf("semantic profile was clobbered: %+v", got)
	}
	if len(got.Inputs) != 1 || len(got.Issues) != 1 {
		t.Fatalf("LLM evidence was clobbered: inputs=%+v issues=%+v", got.Inputs, got.Issues)
	}
	if len(got.ExtractedInputs) != 1 || got.ExtractedInputs[0].Name != "RelayState" {
		t.Fatalf("new extracted input was not merged: %+v", got.ExtractedInputs)
	}
	if !got.HasAuth || !got.HasInput || !got.HasErrors {
		t.Fatalf("observed flags were not unioned: %+v", got)
	}
}

func TestStoreExtractedInputsAppliesEvidenceCeilingBeforePreLLMUpsert(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "non-content-profile.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}

	const profileID = "GET /admin"
	if err := db.UpsertProfile(scanID, &types.PageProfile{
		ID: profileID, URL: "https://example.test/admin", Method: "GET",
		Purpose: "Administrative control panel", AuthRequired: "session", Confidence: .9,
		Inputs:          []types.Input{{Name: "tenant_id", Location: "query"}},
		ExtractedInputs: []types.Input{{Name: "legacy", Location: "query"}},
		DataExposed:     []string{"tenant records"}, APIsCalled: []string{"/api/admin"},
		Behaviors: []string{"deletes users"}, Relationships: []string{"admin owns tenant"},
		Issues: []string{"Hypothesis — authorization bypass"}, TechNotes: "privileged route",
		TemplateID: "admin", HasInput: true, HasFileUpload: true, HasAuth: true, HasErrors: true, IsAPI: true,
	}); err != nil {
		t.Fatal(err)
	}

	analyzer := &AnalyzerAgent{
		db: db, scanID: scanID,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	bundle := &extract.EndpointBundle{
		Method: "GET", URLPattern: "/admin", SampleURL: "https://example.test/admin",
	}
	analyzer.storeExtractedInputs(bundle, []types.TrafficEntry{{
		Request: types.CapturedRequest{Method: "GET", URL: bundle.SampleURL, Path: bundle.URLPattern},
		Response: types.CapturedResponse{StatusCode: 302, Headers: map[string]string{
			"Location": "/auth/login?redirect=%2Fadmin",
		}},
	}})

	got, err := db.GetProfile(scanID, profileID)
	if err != nil {
		t.Fatal(err)
	}
	if got.AuthRequired != "unknown" || got.Confidence != .35 {
		t.Fatalf("pre-LLM evidence verdict was not persisted: %+v", got)
	}
	if len(got.Inputs) != 0 || len(got.ExtractedInputs) != 0 || len(got.DataExposed) != 0 ||
		len(got.APIsCalled) != 0 || len(got.Behaviors) != 0 || len(got.Relationships) != 0 ||
		len(got.Issues) != 0 || got.TechNotes != "" || got.TemplateID != "" || got.HasInput ||
		got.HasFileUpload || got.HasAuth || got.HasErrors || got.IsAPI {
		t.Fatalf("pre-LLM non-content claims survived persistence: %+v", got)
	}
}
