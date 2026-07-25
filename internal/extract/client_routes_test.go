package extract

import (
	"strings"
	"testing"

	"github.com/ozzyw/aobtd/pkg/types"
)

func TestDiscoverVisitedClientRoutesKeepsOnlySafeDirectRouteIdentity(t *testing.T) {
	got := DiscoverVisitedClientRoutes([]ClientRouteEvidence{
		{ID: 1, URL: "https://spa.example.test/#/login"},
		{ID: 2, URL: "https://spa.example.test/#/login?next=%2Fadmin"},
		{ID: 3, URL: "https://spa.example.test/#/score-board"},
		{ID: 4, URL: "https://spa.example.test/#/product/123"},
		{ID: 5, URL: "https://spa.example.test/#section"},
		{ID: 6, URL: "https://spa.example.test/#/reset/user@example.test"},
	}, 16)
	if len(got) != 3 {
		t.Fatalf("client routes = %+v, want login, score board, and product detail", got)
	}
	if got[0].Label != "login" || got[0].Observations != 2 || got[0].URL != "https://spa.example.test/#/login" {
		t.Fatalf("login route = %+v", got[0])
	}
	if got[1].Label != "score board" || got[2].Label != "product detail" {
		t.Fatalf("route labels = %+v", got)
	}
	for _, view := range got {
		if len(view.DiscoveryIDs) == 0 {
			t.Fatalf("route lacks direct discovery evidence: %+v", view)
		}
	}
}

func TestVisitedClientRoutesBecomePersistentSemanticPages(t *testing.T) {
	u := NewAppUnderstanding()
	u.RefreshPagePurposeCards([]types.PageProfile{{
		ID: "GET /", Method: "GET", URL: "https://spa.example.test/", Purpose: "SPA shell", Confidence: .7,
	}})
	u.RefreshClientRoutedPagePurposeCards([]ClientRoutedView{
		{Label: "login", URL: "https://spa.example.test/#/login", Route: "/login", DiscoveryIDs: []int64{31}},
		{Label: "score board", URL: "https://spa.example.test/#/score-board", Route: "/score-board", DiscoveryIDs: []int64{32}},
	})
	if len(u.Recon.Pages) != 3 {
		t.Fatalf("semantic SPA pages = %+v", u.Recon.Pages)
	}
	var login PagePurposeCard
	for _, page := range u.Recon.Pages {
		if strings.Contains(page.ID, "#/login") {
			login = page
		}
	}
	if login.ID == "" || login.Purpose != "Login client-side page observed in the browser" || login.Area != "authentication" || login.Evidence[0].Ref != "discovery:31" {
		t.Fatalf("login client page = %+v", login)
	}
	u.RefreshPagePurposeCards([]types.PageProfile{{
		ID: "GET /", Method: "GET", URL: "https://spa.example.test/", Purpose: "SPA shell", Confidence: .7,
	}})
	if len(u.Recon.Pages) != 3 {
		t.Fatalf("profile refresh discarded SPA pages: %+v", u.Recon.Pages)
	}
}
