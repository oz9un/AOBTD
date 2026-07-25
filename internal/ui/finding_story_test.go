package ui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

const bolaStoryEvidence = `Two-persona BOLA confirmation
- Login A (alice@example.test): HTTP 200, token captured.
- Login B (bob@example.test): HTTP 200, token captured.
- Positive control B→B: GET http://127.0.0.1:3000/rest/basket/8 returned HTTP 200 with owner proof "25".
- Positive control A→A: GET http://127.0.0.1:3000/rest/basket/7 returned HTTP 200 with owner proof "24".
- Anonymous control → B: GET http://127.0.0.1:3000/rest/basket/8 returned HTTP 401; owner proof visible=false ("").
- Attack A→B: GET http://127.0.0.1:3000/rest/basket/8 returned HTTP 200 and still proved B ownership via "25".
Reasoner: AccessReasoner
Rationale: operator provided two personas with owned object URLs; run positive controls, anonymous boundary control, then cross-owner readback`

func TestFindingStoryForBOLAProofTrail(t *testing.T) {
	story := findingStoryFor("bola", bolaStoryEvidence, "")
	if story == nil {
		t.Fatal("expected BOLA finding story")
	}
	if story.Kind != "ownership_proof" {
		t.Fatalf("story kind = %q, want ownership_proof", story.Kind)
	}
	if len(story.Steps) != 4 {
		t.Fatalf("story steps = %d, want 4: %+v", len(story.Steps), story.Steps)
	}
	if story.Steps[0].Label != "B can read B-owned object" || story.Steps[0].Tone != "control" {
		t.Fatalf("first step = %+v", story.Steps[0])
	}
	attack := story.Steps[3]
	if attack.Label != "A reads B-owned object" || attack.Tone != "attack" {
		t.Fatalf("attack step = %+v", attack)
	}
	if !strings.Contains(attack.Text, `owner proof`) && !strings.Contains(attack.Text, `proved B ownership`) {
		t.Fatalf("attack text does not preserve ownership proof: %q", attack.Text)
	}
	if !strings.Contains(story.Rationale, "cross-owner readback") {
		t.Fatalf("rationale = %q", story.Rationale)
	}
}

func TestHandleFindingsIncludesBOLAStory(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	scanID, err := db.CreateScan("http://127.0.0.1:3000", "{}")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertFinding(scanID, types.Finding{
		Title:       "BOLA confirmed: persona A can read persona B's object at http://127.0.0.1:3000/rest/basket/8 [via AccessReasoner]",
		Description: "Two-persona ownership proof succeeded.",
		Severity:    types.SeverityHigh,
		Confidence:  types.ConfidenceConfirmed,
		EndpointID:  "GET http://127.0.0.1:3000/rest/basket/8",
		VulnType:    "bola",
		Evidence:    bolaStoryEvidence,
	}); err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", nil)
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/findings?scan_id=%d", scanID), nil)
	w := httptest.NewRecorder()
	s.handleFindings(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var findings []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &findings); err != nil {
		t.Fatalf("decode response: %v\n%s", err, w.Body.String())
	}
	if len(findings) != 1 {
		t.Fatalf("findings len = %d, want 1", len(findings))
	}
	story, ok := findings[0]["finding_story"].(map[string]any)
	if !ok {
		t.Fatalf("finding_story missing or wrong type: %#v", findings[0]["finding_story"])
	}
	if story["kind"] != "ownership_proof" {
		t.Fatalf("story kind = %#v", story["kind"])
	}
	steps, ok := story["steps"].([]any)
	if !ok || len(steps) != 4 {
		t.Fatalf("story steps = %#v", story["steps"])
	}
}

func TestHandleFindingsAddsTargetContextForRetest(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	scanID, err := db.CreateScan("https://www.example.com/", "{}")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertFinding(scanID, types.Finding{
		Title:            "SQL injection login bypass on /login",
		Description:      "confirmed",
		Severity:         types.SeverityCritical,
		Confidence:       types.ConfidenceConfirmed,
		EndpointID:       "POST /login",
		VulnType:         "sqli",
		ParamName:        "email",
		Payload:          "tester@example.test' --",
		PocRequest:       "POST /login HTTP/1.1\nHost: <target>\nContent-Type: application/json\n\n{}",
		StepsToReproduce: "1. Send the request.",
	}); err != nil {
		t.Fatal(err)
	}

	s := NewServer(db, t.TempDir(), "127.0.0.1:0", nil)
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/findings?scan_id=%d", scanID), nil)
	w := httptest.NewRecorder()
	s.handleFindings(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}

	var findings []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &findings); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings len = %d, want 1", len(findings))
	}
	ctx, ok := findings[0]["target_context"].(map[string]any)
	if !ok {
		t.Fatalf("target_context missing: %#v", findings[0])
	}
	if ctx["scan_target"] != "https://www.example.com/" ||
		ctx["host"] != "www.example.com" ||
		ctx["method"] != "POST" ||
		ctx["endpoint_url"] != "https://www.example.com/login" {
		t.Fatalf("target_context = %#v", ctx)
	}
	if got := findings[0]["poc_request_resolved"]; !strings.Contains(fmt.Sprint(got), "Host: www.example.com") {
		t.Fatalf("resolved PoC request = %#v", got)
	}
}
