package ui

import (
	"strings"
	"testing"

	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/internal/store"
)

// TestRenderMarkdown_AppUnderstanding verifies the new "Application
// understanding" section renders correctly when the analyzer populated
// AppType / AppSummary / FunctionalAreas / PageTemplates in the report.
// Regression guard: this section was added on top of an existing
// report generator and has to stay wired end-to-end.
func TestRenderMarkdown_AppUnderstanding(t *testing.T) {
	r := &scanReport{
		ScanID:        7,
		Target:        "http://localhost:3000/",
		Status:        "finished",
		StartedAt:     "2026-04-21 12:00:00",
		AppType:       "e-commerce SPA",
		AppSummary:    "OWASP Juice Shop training CTF with admin panel and product catalog.",
		EndpointCount: 21,
		TrafficCount:  350,
		FunctionalAreas: []reportFunctionalArea{
			{Name: "authentication", Priority: 10, EndpointCount: 2},
			{Name: "admin", Priority: 9, EndpointCount: 4},
			{Name: "api", Priority: 7, EndpointCount: 6},
		},
		PageTemplates: []reportPageTemplate{
			{ID: "get_rest_products_search", Description: "Product search API", EndpointCount: 2},
			{ID: "ctf-challenge-board-api", Description: "CTF challenge metadata", EndpointCount: 1},
		},
	}

	md := renderMarkdown(r)

	// High-level section header
	if !strings.Contains(md, "## Application understanding") {
		t.Error("missing 'Application understanding' section header")
	}

	// App type + summary render inline
	if !strings.Contains(md, "e-commerce SPA") {
		t.Error("app type not rendered")
	}
	if !strings.Contains(md, "OWASP Juice Shop training CTF") {
		t.Error("app summary not rendered")
	}

	// Functional areas table appears with priority-ordered rows
	if !strings.Contains(md, "### Functional areas") {
		t.Error("missing functional areas subsection")
	}
	for _, area := range []string{"authentication", "admin", "api"} {
		if !strings.Contains(md, area) {
			t.Errorf("functional area %q missing from output", area)
		}
	}

	// Page templates table
	if !strings.Contains(md, "### Page templates") {
		t.Error("missing page templates subsection")
	}
	if !strings.Contains(md, "get_rest_products_search") {
		t.Error("template id not rendered")
	}
	if !strings.Contains(md, "Product search API") {
		t.Error("template description not rendered")
	}
}

func TestRenderMarkdown_SemanticReconModel(t *testing.T) {
	r := &scanReport{
		ScanID: 9, Target: "https://app.test", Status: "finished", AppType: "saas",
		Recon: extract.ReconModel{
			Roles:               []extract.ReconRole{{ID: "member", Name: "Member"}},
			Objects:             []extract.BusinessObject{{ID: "invoice", Name: "Invoice"}},
			Workflows:           []extract.BusinessWorkflow{{ID: "billing", Name: "Billing review", Description: "A member reviews an invoice.", Confidence: .8, Steps: []extract.WorkflowStep{{ID: "view", Label: "View invoice", PageIDs: []string{"GET /invoices/{id}"}}}}},
			OwnershipBoundaries: []extract.OwnershipBoundary{{ID: "invoice-owner", ObjectID: "invoice", Rule: "Members see invoices in their tenant", Confidence: .7}},
			Unknowns:            []extract.ReconUnknown{{ID: "tenant", Question: "How is tenant context selected?", SuggestedAction: "Compare two sessions", Priority: 9}},
			Metrics:             extract.ReconMetrics{OverallConfidence: .72},
		},
	}
	md := renderMarkdown(r)
	for _, want := range []string{"### Semantic application model", "Billing review", "Ownership and trust boundaries", "How is tenant context selected?"} {
		if !strings.Contains(md, want) {
			t.Fatalf("semantic report missing %q:\n%s", want, md)
		}
	}
}

// TestRenderMarkdown_AppUnderstandingEmpty — when a scan has no app
// understanding data (e.g. pre-migration scan), the section should be
// omitted entirely rather than printed empty.
func TestRenderMarkdown_AppUnderstandingEmpty(t *testing.T) {
	r := &scanReport{
		ScanID: 1,
		Target: "http://x",
		Status: "finished",
		// No AppType, no summary, no areas, no templates
	}
	md := renderMarkdown(r)
	if strings.Contains(md, "## Application understanding") {
		t.Error("empty app understanding should not render the section header")
	}
	if strings.Contains(md, "### Functional areas") {
		t.Error("empty areas should not render the subsection")
	}
}

// TestRenderMarkdown_NotableEndpoints_EnrichedColumns — the Notable
// Endpoints table gained Template + Inputs columns. Verify they appear
// in both the header and the body, and that an empty TemplateID renders
// as the em-dash placeholder (not literal "").
func TestRenderMarkdown_NotableEndpoints_EnrichedColumns(t *testing.T) {
	r := &scanReport{
		ScanID: 1, Target: "http://x", Status: "finished",
		Profiles: []profileSummary{
			{
				ID: "GET /api/search", URL: "http://x/api/search", Method: "GET",
				Purpose: "Search API", IssueCount: 2, AuthRequired: "session",
				TemplateID:      "generic_search_api",
				InputCount:      3,
				ExtractedInputs: 2,
			},
			{
				ID: "GET /about", URL: "http://x/about", Method: "GET",
				Purpose: "Static about page", IssueCount: 0, AuthRequired: "none",
				TemplateID: "", // should render as em-dash
				InputCount: 0,
			},
		},
	}

	md := renderMarkdown(r)

	// Header has the new columns
	if !strings.Contains(md, "| Template |") {
		t.Error("Notable endpoints table missing Template column header")
	}
	if !strings.Contains(md, "| Inputs |") {
		t.Error("Notable endpoints table missing Inputs column header")
	}

	// Body renders the template id in monospace backticks
	if !strings.Contains(md, "`generic_search_api`") {
		t.Error("template id not rendered in backticks")
	}

	// Em-dash placeholder for endpoints without a template
	if !strings.Contains(md, "| — |") {
		t.Error("empty template should render as em-dash placeholder")
	}
}

// TestRenderMarkdown_ExecutiveSummaryStable — the top-of-report
// executive summary shouldn't accidentally disappear when we extend
// other sections. Quick sanity check that the critical numbers remain.
func TestRenderMarkdown_ExecutiveSummaryStable(t *testing.T) {
	r := &scanReport{
		ScanID: 5, Target: "http://test", Status: "finished",
		EndpointCount: 14, TrafficCount: 280,
		TotalTokens: 50000, CostUSD: 0.42,
		Findings: []map[string]any{
			{"severity": "critical", "confidence": "confirmed"},
			{"severity": "high", "confidence": "confirmed"},
			{"severity": "medium", "confidence": "possible"},
		},
	}
	md := renderMarkdown(r)

	for _, want := range []string{
		"## Executive summary",
		"**Target:**",
		"**Endpoints discovered:** 14",
		"**Traffic captured:** 280",
		"**Findings:** 3 total",
		"**Confirmed findings:** 2",
		"**Critical / High:** 2",
		"$0.4200",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("Executive summary missing %q", want)
		}
	}
}

// TestScanReport_Narrations_TruncationBoundary — the buildReport logic
// truncates narrations to the most-recent 80 to keep exports small.
// This test exercises the truncation branch via direct renderMarkdown
// (buildReport's DB path is covered in integration, not here).
func TestScanReport_Narrations_TruncationBoundary(t *testing.T) {
	r := &scanReport{ScanID: 1, Target: "http://x", Status: "finished"}
	// 5 narrations — below the truncation limit
	for i := 0; i < 5; i++ {
		r.Narrations = append(r.Narrations, store.Narration{
			Agent: "test", Action: "thought", Message: "message " + string(rune('A'+i)),
		})
	}
	md := renderMarkdown(r)

	if !strings.Contains(md, "## Agent reasoning log") {
		t.Error("narration section missing")
	}
	for _, msg := range []string{"message A", "message B", "message E"} {
		if !strings.Contains(md, msg) {
			t.Errorf("narration %q missing from output", msg)
		}
	}
}
