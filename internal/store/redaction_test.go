package store

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestLogAIFullRedactsStoredSecrets(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "redaction.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	scanID, err := db.CreateScan("http://127.0.0.1:3000", `{}`)
	if err != nil {
		t.Fatal(err)
	}

	if err := db.LogAIFull(scanID, "tester", "decide",
		"Authorization: Bearer detail-secret",
		"http://127.0.0.1:3000/api?token=url-secret", "",
		`{"password":"result-secret"}`,
		1, 1, 1, 0, "model",
		"Cookie: sid=prompt-secret",
		"Set-Cookie: session=response-secret; Path=/",
	); err != nil {
		t.Fatal(err)
	}

	entries, err := db.GetAILog(scanID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	prompt, response, err := db.GetAILogFull(entries[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	combined := entries[0].Detail + "\n" + entries[0].FromURL + "\n" + entries[0].Result + "\n" + prompt + "\n" + response
	for _, secret := range []string{"detail-secret", "url-secret", "result-secret", "prompt-secret", "response-secret"} {
		if strings.Contains(combined, secret) {
			t.Fatalf("stored AI log still contains %q:\n%s", secret, combined)
		}
	}
	for _, marker := range []string{"[REDACTED:authorization:", "[REDACTED:token:", "[REDACTED:password:", "[REDACTED:cookie:"} {
		if !strings.Contains(combined, marker) {
			t.Fatalf("stored AI log missing marker %q:\n%s", marker, combined)
		}
	}
}

func TestInsertStrategistCycleRedactsRawOutput(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "strategist-redaction.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	scanID, err := db.CreateScan("http://127.0.0.1:3000", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.InsertStrategistCycle(StrategistCycle{
		ScanID:           scanID,
		TriggerReason:    "test",
		ModelID:          "model",
		RawOutput:        "Authorization: Bearer strategist-secret-token",
		ExecutiveSummary: `{"access_token":"strategist-summary-secret"}`,
		Error:            "Cookie: sid=strategist-error-secret",
	}); err != nil {
		t.Fatal(err)
	}
	cycles, err := db.ListStrategistCycles(scanID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(cycles) != 1 {
		t.Fatalf("cycles = %d, want 1", len(cycles))
	}
	combined := cycles[0].RawOutput + "\n" + cycles[0].ExecutiveSummary + "\n" + cycles[0].Error
	for _, secret := range []string{"strategist-secret-token", "strategist-summary-secret", "strategist-error-secret"} {
		if strings.Contains(combined, secret) {
			t.Fatalf("stored strategist cycle still contains %q:\n%s", secret, combined)
		}
	}
}
