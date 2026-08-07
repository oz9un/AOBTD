package ui

import (
	"strings"
	"testing"
)

func embeddedUIForDemoContract(t *testing.T) string {
	t.Helper()
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestLiveBrowserUsesOriginAwareRedactedLabels(t *testing.T) {
	html := embeddedUIForDemoContract(t)
	for _, contract := range []string{
		"function browserRedactedQuery",
		"function browserRedactedHash",
		"function browserDisplayURL",
		"function browserSafeNarrationText",
		"return parsed.host + path + browserRedactedQuery(parsed.search) + browserRedactedHash(parsed.hash)",
		"browserDisplayURL(frameURL)",
		"browserDisplayURL(interaction.url)",
		"browserSafeNarrationText(n.message, 800)",
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("Live browser origin/redaction contract missing %q", contract)
		}
	}
	if strings.Contains(html, "shortURL(frameURL)") {
		t.Fatal("browser frame chrome still hides the origin behind a path-only label")
	}

	start := strings.Index(html, "function browserDisplayURL")
	if start < 0 {
		t.Fatal("could not find browser display URL helper")
	}
	end := strings.Index(html[start:], "function browserSafeNarrationText")
	if end <= 0 {
		t.Fatal("could not isolate browser display URL helper")
	}
	helper := html[start : start+end]
	if strings.Contains(helper, "parsed.search +") || strings.Contains(helper, "+ parsed.search") {
		t.Fatal("browser display URL concatenates raw query values")
	}
}

func TestReconReconcilesContradictoryAPIServiceBadge(t *testing.T) {
	html := embeddedUIForDemoContract(t)
	for _, contract := range []string{
		"function rcReconciledAppType",
		"normalized !== 'api service'",
		"summaryDescribesUI && observedUIPage ? 'web application' : normalized",
		"const displayedAppType = rcReconciledAppType(appType, recon, rawIdentitySummary)",
		"displayedAppType ? `<span class=\"rc-app-type\">",
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("Recon app-type reconciliation contract missing %q", contract)
		}
	}
	if strings.Contains(html, "<span class=\"rc-app-type\">${esc(String(appType)") {
		t.Fatal("Recon still renders the raw model app type without evidence reconciliation")
	}
}

func TestDemoLayoutsAccountForFixedSidebarAtProjectorWidth(t *testing.T) {
	html := embeddedUIForDemoContract(t)
	if strings.Count(html, "@media (max-width: 1250px)") < 3 {
		t.Fatal("Recon and Live do not switch layouts before the fixed sidebar makes their content narrow")
	}
	for _, contract := range []string{
		".rc-grid { grid-template-columns: 1fr; }",
		".rc-brain-grid { grid-template-columns: 1fr; }",
		".rc-lens { grid-template-columns: repeat(4,minmax(72px,1fr)); }",
		".rc-surface-brief { grid-template-columns: 1fr; }",
		".live-grid { height: auto; min-height: 0; grid-template-columns: 1fr;",
		".live-thoughts-pane { grid-column: 1; grid-row: 2; }",
		".live-discoveries-pane { grid-column: 1; grid-row: 3; }",
		".browser-frame:not(.focus-mode) .browser-screen-index { display: none; }",
		".browser-frame:not(.focus-mode) .browser-screen-live { width: 5px; gap: 0; font-size: 0; }",
		"#exportWrap, #refreshBtn { display: none !important; }",
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("fixed-sidebar responsive contract missing %q", contract)
		}
	}
	if strings.Contains(html, "@media (max-width: 980px) {\n  .rc-grid") {
		t.Fatal("Recon still waits for a phone-width viewport before collapsing its desktop columns")
	}
	if strings.Contains(html, "@media (max-width: 900px) {\n  .live-grid") {
		t.Fatal("Live still waits for a phone-width viewport before stacking support panes")
	}
}
