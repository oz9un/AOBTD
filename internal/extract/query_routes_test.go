package extract

import (
	"strings"
	"testing"

	"github.com/ozzyw/aobtd/pkg/types"
)

func TestDiscoverQueryRoutedViewsSplitsResponsesAndCollapsesAliases(t *testing.T) {
	jobs := []byte(`<html><head><title>Careers</title></head><body><main><h1>Open roles</h1><table><tr><td>Engineer</td></tr></table></main></body></html>`)
	privacy := []byte(`<html><head><title>Privacy</title></head><body><main><h1>Privacy notice</h1><article>How customer information is handled and protected.</article></main></body></html>`)
	entries := []types.TrafficEntry{
		queryRouteEntry(11, "content=inside_jobs.htm", jobs),
		queryRouteEntry(12, "content=inside_jobs.htm", jobs),
		queryRouteEntry(13, "content=careers.htm", jobs), // different label, equivalent response
		queryRouteEntry(14, "content=privacy.htm", privacy),
		queryRouteEntry(15, "content=user%40example.test", privacy), // rejected as user data
	}

	got := DiscoverQueryRoutedViews(entries, 12)
	if len(got) != 2 {
		t.Fatalf("views = %+v, want two materially distinct responses", got)
	}
	if got[0].Label != "jobs" || got[0].ResponseKind != "table view" || got[0].Observations != 3 || got[0].Aliases != 1 {
		t.Fatalf("jobs view = %+v", got[0])
	}
	if got[1].Label != "privacy" || got[1].ResponseKind != "article view" || got[1].Observations != 1 {
		t.Fatalf("privacy view = %+v", got[1])
	}
	for _, view := range got {
		if view.URL != "https://demo.example.test/index.jsp" {
			t.Fatalf("raw query leaked into URL: %+v", view)
		}
		if view.ShapeID == "" || len(view.TrafficIDs) == 0 {
			t.Fatalf("view lacks response evidence: %+v", view)
		}
	}
}

func TestDiscoverQueryRoutedViewsRequiresDistinctResponseEvidence(t *testing.T) {
	body := []byte(`<html><head><title>Same page</title></head><body><main><h1>Same page</h1><p>Same response content for both aliases.</p></main></body></html>`)
	got := DiscoverQueryRoutedViews([]types.TrafficEntry{
		queryRouteEntry(1, "page=first.htm", body),
		queryRouteEntry(2, "page=second.htm", body),
	}, 12)
	if len(got) != 0 {
		t.Fatalf("aliases were presented as page types: %+v", got)
	}
}

func TestQueryRoutedViewsBecomeStableSemanticPageCards(t *testing.T) {
	u := NewAppUnderstanding()
	u.RefreshPagePurposeCards([]types.PageProfile{{
		ID: "GET /index.jsp", Method: "GET", URL: "https://demo.example.test/index.jsp",
		Purpose: "Generic application shell", Confidence: .7,
	}})
	u.RefreshQueryRoutedPagePurposeCards([]QueryRoutedView{
		{Path: "/index.jsp", Parameter: "content", Label: "jobs", URL: "https://demo.example.test/index.jsp", Status: 200, ResponseKind: "table view", ShapeID: "abc123", TrafficIDs: []int64{11}},
		{Path: "/index.jsp", Parameter: "content", Label: "privacy", URL: "https://demo.example.test/index.jsp", Status: 200, ResponseKind: "article view", ShapeID: "def456", TrafficIDs: []int64{14}},
	})
	if len(u.Recon.Pages) != 3 {
		t.Fatalf("semantic pages = %+v, want shell plus two routed page types", u.Recon.Pages)
	}
	var jobs PagePurposeCard
	for _, page := range u.Recon.Pages {
		if strings.Contains(page.ID, "content:jobs") {
			jobs = page
		}
	}
	if jobs.ID == "" || jobs.Purpose != "Jobs page selected by the content query router" || len(jobs.Evidence) != 1 || jobs.Evidence[0].Ref != "traffic:11" {
		t.Fatalf("jobs card = %+v", jobs)
	}

	// Periodic profile refreshes must not collapse the response-backed cards.
	u.RefreshPagePurposeCards([]types.PageProfile{{
		ID: "GET /index.jsp", Method: "GET", URL: "https://demo.example.test/index.jsp",
		Purpose: "Generic application shell", Confidence: .7,
	}})
	if len(u.Recon.Pages) != 3 {
		t.Fatalf("profile refresh discarded query-routed cards: %+v", u.Recon.Pages)
	}
}

func queryRouteEntry(id int64, query string, body []byte) types.TrafficEntry {
	return types.TrafficEntry{
		ID: id,
		Request: types.CapturedRequest{
			Method: "GET", URL: "https://demo.example.test/index.jsp?" + query,
			Host: "demo.example.test", Path: "/index.jsp", Query: query,
		},
		Response: types.CapturedResponse{StatusCode: 200, ContentType: "text/html; charset=utf-8", Body: body},
	}
}
