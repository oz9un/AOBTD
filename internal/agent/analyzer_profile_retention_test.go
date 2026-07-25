package agent

import (
	"io"
	"log/slog"
	"path/filepath"
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
