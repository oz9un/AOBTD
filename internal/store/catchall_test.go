package store

import (
	"bytes"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/ozzyw/aobtd/internal/reconprojection"
	"github.com/ozzyw/aobtd/pkg/types"
)

func TestGetCatchAllIndexUsesCompleteInlineAndBlobDigests(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "catchall.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, _ := db.CreateScan("https://app.test/", `{}`)

	insertPair := func(prefix string, body []byte) {
		t.Helper()
		for _, path := range []string{"/" + prefix, "/" + prefix + "-asdasd"} {
			entry := &types.TrafficEntry{
				Request: types.CapturedRequest{Method: http.MethodGet, URL: "https://app.test" + path},
				Response: types.CapturedResponse{
					StatusCode: http.StatusOK, ContentType: "text/html", Body: append([]byte(nil), body...),
				},
			}
			if _, err := db.InsertTraffic(scanID, entry); err != nil {
				t.Fatal(err)
			}
		}
	}
	insertPair("small", []byte("<html>small exact shell</html>"))
	insertPair("large", bytes.Repeat([]byte("<main>large exact shell</main>"), 900))

	index, err := db.GetCatchAllIndex(scanID)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/small", "/large"} {
		profile := &types.PageProfile{Method: http.MethodGet, URL: "https://app.test" + path, EvidenceState: "content_observed"}
		if !reconprojection.ApplyCatchAllCeiling(profile, index) {
			t.Fatalf("complete-body catch-all not indexed for %s: %+v", path, profile)
		}
	}
}
