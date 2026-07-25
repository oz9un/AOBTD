package store

import (
	"path/filepath"
	"testing"
)

func TestGetVisitedClientRoutesExcludesLinkedAndPlainAnchors(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "discoveries.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://spa.example.test/", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, discovery := range []Discovery{
		{TargetURL: "https://spa.example.test/#/login", Kind: DiscoveryHTMLLink},
		{TargetURL: "https://spa.example.test/#/login", SourceURL: "https://spa.example.test/", Kind: DiscoveryNavigator},
		{TargetURL: "https://spa.example.test/#section", SourceURL: "https://spa.example.test/", Kind: DiscoveryNavigator},
		{TargetURL: "https://spa.example.test/#/score-board", SourceURL: "js_discovered_routes", Kind: DiscoveryNavigator},
	} {
		if err := db.InsertDiscovery(scanID, discovery); err != nil {
			t.Fatal(err)
		}
	}
	got, err := db.GetVisitedClientRoutes(scanID, 80)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].TargetURL != "https://spa.example.test/#/login" || got[1].TargetURL != "https://spa.example.test/#/score-board" {
		t.Fatalf("visited client routes = %+v", got)
	}
}
