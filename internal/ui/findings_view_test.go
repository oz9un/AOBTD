package ui

import (
	"strings"
	"testing"
)

func TestFindingsWalkthroughUsesDedicatedLauncherStyling(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, contract := range []string{
		`.walkthrough-launcher`,
		`.walkthrough-launch-btn`,
		`class="walkthrough-launch-btn"`,
		`Walk through the evidence`,
		`Use the arrow keys to move between findings.`,
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("Findings walkthrough launcher missing %q", contract)
		}
	}

	start := strings.Index(html, "function renderFindings(el)")
	if start < 0 {
		t.Fatal("could not find Findings renderer")
	}
	end := strings.Index(html[start:], "// ─── TRAFFIC ───")
	if end < 0 {
		t.Fatal("could not isolate Findings renderer")
	}
	renderer := html[start : start+end]
	if strings.Contains(renderer, `class="refresh-btn"`) {
		t.Fatal("Findings walkthrough still relies on the topbar-scoped refresh button style")
	}
}

func TestFindingsSurfacesReconCandidatesWithoutCountingThemAsFindings(t *testing.T) {
	raw, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, contract := range []string{
		`surface: '/api/surface'`,
		`findings: ['scan','stats','endpoints','findings','surface']`,
		`function rcSurfaceLeadRows(surface)`,
		`function rcLeadConfirmedFinding(lead, findings=cache.findings||[])`,
		`function rcUnverifiedSurfaceLeadRows(surface)`,
		`function renderFindingsTestingLeads(surface)`,
		`function openSurfaceTestingLead(button)`,
		`Unverified testing leads`,
		`Recon candidates are passive classifications, not findings or queued jobs.`,
		`confirmed matches leave this list`,
		`the Findings counts above stay unchanged`,
		`html += renderFindingsTestingLeads(surface)`,
	} {
		if !strings.Contains(html, contract) {
			t.Fatalf("Recon-to-Findings handoff missing %q", contract)
		}
	}
}
