package ui

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/pkg/types"
)

func TestReconEvidenceCeilingRequiresObservedAuthAndMutation(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://app.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{db: db}

	if got := s.reconEvidenceCeiling(scanID); got["authenticated_request_observed"] || got["state_changing_request_observed"] {
		t.Fatalf("empty ceiling = %v", got)
	}
	if _, err := db.Conn().Exec(`INSERT INTO traffic(scan_id,method,url,host,path,status_code,has_auth) VALUES (?,'GET','https://app.example.test/me','app.example.test','/me',200,1)`, scanID); err != nil {
		t.Fatal(err)
	}
	if got := s.reconEvidenceCeiling(scanID); got["authenticated_request_observed"] {
		t.Fatalf("ambient auth marker lifted ceiling: %v", got)
	}
	if _, err := db.InsertNarration(scanID, "auth", "success", "Session established.", "https://app.example.test/login", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Conn().Exec(`INSERT INTO traffic(scan_id,method,url,host,path,status_code) VALUES (?,'POST','https://app.example.test/update','app.example.test','/update',200)`, scanID); err != nil {
		t.Fatal(err)
	}
	got := s.reconEvidenceCeiling(scanID)
	if !got["authenticated_request_observed"] || !got["state_changing_request_observed"] {
		t.Fatalf("grounded ceiling = %v", got)
	}
}

func TestReconAccessStateDistinguishesRenderedShellFromMappedTarget(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://app.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{db: db}
	if got := s.reconAccessState(scanID, 0); got["state"] != "unavailable" {
		t.Fatalf("empty access state = %v", got)
	}
	if _, err := db.Conn().Exec(`INSERT INTO traffic(scan_id,method,url,host,path,status_code,content_type) VALUES (?,'GET','https://app.example.test/','app.example.test','/',200,'text/html')`, scanID); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertDiscovery(scanID, store.Discovery{TargetURL: "https://app.example.test/", Kind: store.DiscoverySeed}); err != nil {
		t.Fatal(err)
	}
	if got := s.reconAccessState(scanID, 1); got["state"] != "limited" || got["detail"] == "" {
		t.Fatalf("rendered-shell access state = %v", got)
	}
	if _, err := db.Conn().Exec(`INSERT INTO traffic(scan_id,method,url,host,path,status_code,content_type) VALUES (?,'GET','https://app.example.test/docs','app.example.test','/docs',200,'text/html')`, scanID); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertDiscovery(scanID, store.Discovery{TargetURL: "https://app.example.test/docs", Kind: store.DiscoveryHTMLLink}); err != nil {
		t.Fatal(err)
	}
	if got := s.reconAccessState(scanID, 2); got["state"] != "available" {
		t.Fatalf("mapped-target access state = %v", got)
	}
}

func TestReconAccessStateDoesNotTreatProtectionPageAsApplication(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "protected.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://protected.example.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	insert := func(status int, body string) {
		t.Helper()
		if _, err := db.InsertTraffic(scanID, &types.TrafficEntry{
			Request: types.CapturedRequest{Method: "GET", URL: "https://protected.example.test/", Headers: map[string]string{}},
			Response: types.CapturedResponse{
				StatusCode: status, ContentType: "text/html",
				Headers: map[string]string{"Server": "cloudflare"}, Body: []byte(body),
			},
			Timestamp: time.Now(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	s := &Server{db: db}
	insert(403, `<title>Just a moment...</title><p>Performing security verification</p>`)
	if got := s.reconAccessState(scanID, 1); got["state"] != "protected" || got["detail"] == "" {
		t.Fatalf("protection-only access state = %v", got)
	}
	insert(200, `<title>Application</title><main>Representative target content</main>`)
	if got := s.reconAccessState(scanID, 2); got["state"] != "available" {
		t.Fatalf("recovered application access state = %v", got)
	}
}
