package agent

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

func TestReplayAnalysisCompactionPreservesProtectionExceptions(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "protection-replay.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://app.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	challengeBody := `<title>Just a moment...</title><script src="/cdn-cgi/challenge-platform/x"></script><p>Enable JavaScript and cookies to continue</p>`
	insert := func(path string, status int, body string) {
		t.Helper()
		if _, err := db.InsertTraffic(scanID, &types.TrafficEntry{
			Request: types.CapturedRequest{Method: "GET", URL: "https://app.test" + path, Headers: map[string]string{}},
			Response: types.CapturedResponse{
				StatusCode: status, ContentType: "text/html",
				Headers: map[string]string{"Server": "cloudflare", "CF-Ray": "volatile"}, Body: []byte(body),
			},
			Timestamp: time.Now(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	insert("/blocked-a", 403, challengeBody)
	insert("/blocked-b", 403, challengeBody)
	insert("/recovered", 403, challengeBody)
	insert("/recovered", 200, `<title>Application</title><main>Representative content</main>`)
	insert("/upstream-failure", 503, challengeBody)

	report, err := ReplayAnalysisCompaction(db, scanID)
	if err != nil {
		t.Fatal(err)
	}
	if report.ProtectionFamilies != 4 || report.ProtectionShapes != 2 || report.ProtectionSpecimens != 2 || report.ProtectionDuplicates != 1 {
		t.Fatalf("protection replay compaction = %+v", report)
	}
	if report.RecoveredApplications != 1 || report.ProtectionServerErrors != 1 {
		t.Fatalf("protection replay exceptions = %+v", report)
	}
	if report.PassiveClosed != 2 || report.SemanticCandidates != 2 {
		t.Fatalf("protection replay semantic split = %+v", report)
	}
}
