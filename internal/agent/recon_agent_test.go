package agent

import (
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

func TestReconSecurityHeadersArePostureObservations(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "recon.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	headers, _ := json.Marshal(map[string]string{
		"Content-Security-Policy":   "default-src 'self'; frame-ancestors 'none'",
		"Strict-Transport-Security": "max-age=31536000",
		"X-Content-Type-Options":    "nosniff",
	})
	_, err = db.Conn().Exec(`
		INSERT INTO traffic (scan_id, method, url, host, path, response_headers, content_type, status_code, is_filtered)
		VALUES (?, 'GET', 'https://example.test/', 'example.test', '/', ?, 'text/html', 200, FALSE)`, scanID, string(headers))
	if err != nil {
		t.Fatal(err)
	}
	agent := NewReconAgent(db, nil, NewSharedState("https://example.test"), scanID,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	_, findings := agent.analyzeTraffic()
	for _, finding := range findings {
		if finding.Title == "Missing security header: x-xss-protection" ||
			finding.Title == "Security posture observation: missing x-xss-protection" {
			t.Fatalf("obsolete X-XSS-Protection emitted as a finding: %+v", finding)
		}
		if finding.Title == "Security posture observation: missing x-frame-options" {
			t.Fatalf("X-Frame-Options flagged despite CSP frame-ancestors: %+v", finding)
		}
		if finding.Confidence == types.ConfidenceConfirmed || finding.Severity != types.SeverityInfo {
			t.Fatalf("header absence overstated as vulnerability: %+v", finding)
		}
	}
}
