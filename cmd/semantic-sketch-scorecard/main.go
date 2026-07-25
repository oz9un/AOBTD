// Command semantic-sketch-scorecard replays deterministic response sketches
// against a saved scan and reports wrong-family template verifications that
// the current selector can avoid without changing captured evidence.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/internal/target"
)

type routeCard struct {
	Method             string
	Path               string
	Sketch             string
	SketchFacet        string
	Confidence         int
	Legacy             string
	LegacyFamily       string
	LegacyFacet        string
	Current            string
	CurrentFamily      string
	CurrentFacet       string
	AvoidedWrong       bool
	ExpectedTemplate   string
	TemplateRegression bool
}

func main() {
	dbPath := flag.String("db", "./aobtd-output/scan.db", "path to scan.db")
	scanID := flag.Int64("scan", 59, "saved scan ID")
	flag.Parse()

	db, err := store.Open(*dbPath)
	if err != nil {
		fatalf("open scan database: %v", err)
	}
	defer db.Close()

	appType, templatesJSON, areasJSON, hashesJSON, summary, err := db.GetAppUnderstanding(*scanID)
	if err != nil {
		fatalf("load app understanding: %v", err)
	}
	understanding := extract.LoadAppUnderstanding(appType, templatesJSON, areasJSON, hashesJSON, summary)

	rows, err := db.Conn().Query(`
		SELECT DISTINCT endpoint_hash
		FROM traffic
		WHERE scan_id = ? AND endpoint_hash != ''
		  AND is_filtered = FALSE AND is_duplicate = FALSE
		  AND status_code >= 200 AND status_code < 300
		  AND LOWER(content_type) LIKE 'text/html%'
		ORDER BY endpoint_hash`, *scanID)
	if err != nil {
		fatalf("list captured HTML families: %v", err)
	}
	hashes := []string{}
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			rows.Close()
			fatalf("scan endpoint hash: %v", err)
		}
		hashes = append(hashes, hash)
	}
	if err := rows.Close(); err != nil {
		fatalf("close endpoint rows: %v", err)
	}

	cards := make([]routeCard, 0, len(hashes))
	classified := 0
	wrongLegacy := 0
	avoided := 0
	exactComparable := 0
	exactPreserved := 0
	exactRegressions := 0
	for _, hash := range hashes {
		entries, err := db.GetTrafficByEndpointHash(*scanID, hash)
		if err != nil || len(entries) == 0 {
			continue
		}
		bundle := extract.BuildEndpointBundle(entries, 20)
		if bundle == nil || bundle.HTMLExtraction == nil {
			continue
		}
		sketch := bundle.SemanticSketch()
		if sketch.Family != "" {
			classified++
		}
		legacy, legacyOK := legacyTemplateCandidate(understanding.PageTemplates, bundle)
		currentID, currentOK := understanding.MatchTemplate(bundle)
		current := findTemplate(understanding.PageTemplates, currentID)
		legacyFamily, legacyFacet := "", ""
		if legacyOK {
			legacyFamily = templateFamily(legacy)
			legacyFacet = templateFacet(legacy, legacyFamily)
		}
		currentFamily, currentFacet := "", ""
		if currentOK {
			currentFamily = templateFamily(current)
			currentFacet = templateFacet(current, currentFamily)
		}
		expectedTemplate := exactSavedTemplate(understanding.PageTemplates, bundle)
		// A learned template for this exact route is not a wasted cross-route
		// verification even when its historical model label disagrees with the
		// deterministic sketch. Only score reuse of another route as avoidable.
		wrong := sketch.Family != "" && legacyFamily != "" && sketch.Family != legacyFamily && legacy.ID != expectedTemplate.ID
		currentUsesSketchFamily := currentOK && currentFamily == sketch.Family &&
			(currentFacet == "" || sketch.Facet == "" || currentFacet == sketch.Facet)
		prevents := wrong && (!currentOK || current.ID == expectedTemplate.ID || currentUsesSketchFamily)
		templateRegression := expectedTemplate.ID != "" && (!currentOK || current.ID != expectedTemplate.ID)
		if expectedTemplate.ID != "" {
			exactComparable++
			if templateRegression {
				exactRegressions++
			} else {
				exactPreserved++
			}
		}
		if wrong {
			wrongLegacy++
		}
		if prevents {
			avoided++
		}
		cards = append(cards, routeCard{
			Method: bundle.Method, Path: bundle.URLPattern, Sketch: sketch.Family, SketchFacet: sketch.Facet,
			Confidence: sketch.Confidence, Legacy: legacy.ID, LegacyFamily: legacyFamily,
			LegacyFacet: legacyFacet, Current: current.ID, CurrentFamily: currentFamily, CurrentFacet: currentFacet, AvoidedWrong: prevents,
			ExpectedTemplate: expectedTemplate.ID, TemplateRegression: templateRegression,
		})
	}
	sort.Slice(cards, func(i, j int) bool { return cards[i].Path < cards[j].Path })

	fmt.Printf("# Semantic sketch scorecard — scan %d\n\n", *scanID)
	fmt.Printf("- Captured HTML endpoint families: **%d**\n", len(cards))
	fmt.Printf("- Deterministically classified: **%d/%d**\n", classified, len(cards))
	fmt.Printf("- Legacy cross-route wrong-family candidates: **%d**\n", wrongLegacy)
	fmt.Printf("- Wrong-family verification calls avoided: **%d/%d**\n\n", avoided, wrongLegacy)
	fmt.Printf("- Exact saved-template regressions: **%d/%d** · preserved: **%d**\n\n", exactRegressions, exactComparable, exactPreserved)
	fmt.Println("| Route | Sketch | Exact saved template | Legacy candidate | Current candidate | Result |")
	fmt.Println("|---|---|---|---|---|---|")
	for _, card := range cards {
		result := "unchanged"
		if card.AvoidedWrong {
			result = "wrong-family call avoided"
		}
		if card.TemplateRegression {
			result = "TEMPLATE REGRESSION"
		}
		fmt.Printf("| %s %s | %s | %s | %s | %s | %s |\n",
			card.Method, markdown(card.Path), familyCell(card.Sketch, card.SketchFacet, card.Confidence),
			markdown(firstNonEmpty(card.ExpectedTemplate, "none")), templateCell(card.Legacy, card.LegacyFamily, card.LegacyFacet),
			templateCell(card.Current, card.CurrentFamily, card.CurrentFacet), result)
	}
}

func exactSavedTemplate(templates []extract.PageTemplate, bundle *extract.EndpointBundle) extract.PageTemplate {
	for _, candidate := range templates {
		if !strings.EqualFold(strings.TrimSpace(candidate.Method), strings.TrimSpace(bundle.Method)) {
			continue
		}
		if strings.TrimSpace(candidate.URLPattern) != strings.TrimSpace(bundle.URLPattern) {
			continue
		}
		if candidate.InputSignature != bundle.InputSignature() {
			continue
		}
		return candidate
	}
	return extract.PageTemplate{}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func legacyTemplateCandidate(templates []extract.PageTemplate, bundle *extract.EndpointBundle) (extract.PageTemplate, bool) {
	sig := bundle.InputSignature()
	if sig == "" {
		return extract.PageTemplate{}, false
	}
	for _, candidate := range templates {
		if candidate.InputSignature != sig {
			continue
		}
		if candidate.Method != "" && bundle.Method != "" && !strings.EqualFold(candidate.Method, bundle.Method) {
			continue
		}
		bundleFamily := target.SurfaceFamily(bundle.URLPattern, "")
		candidateFamily := templateFamily(candidate)
		if bundleFamily != "" && candidateFamily != "" && bundleFamily != candidateFamily {
			continue
		}
		return candidate, true
	}
	return extract.PageTemplate{}, false
}

func findTemplate(templates []extract.PageTemplate, id string) extract.PageTemplate {
	for _, candidate := range templates {
		if candidate.ID == id {
			return candidate
		}
	}
	return extract.PageTemplate{}
}

func templateFamily(template extract.PageTemplate) string {
	if strings.TrimSpace(template.SemanticFamily) != "" {
		return strings.TrimSpace(template.SemanticFamily)
	}
	rawURL := template.URLPattern
	if rawURL == "" && len(template.ExampleURLs) > 0 {
		rawURL = template.ExampleURLs[0]
	}
	return target.SurfaceFamily(rawURL, template.Description)
}

func templateFacet(template extract.PageTemplate, family string) string {
	if strings.TrimSpace(template.SemanticFacet) != "" {
		return strings.TrimSpace(template.SemanticFacet)
	}
	if family != "support" {
		return ""
	}
	text := " " + strings.Join(strings.Fields(strings.NewReplacer(
		"/", " ", "-", " ", "_", " ", ".", " ", ":", " ",
	).Replace(strings.ToLower(template.URLPattern+" "+template.Description))), " ") + " "
	if strings.Contains(text, " faq ") || strings.Contains(text, " frequently asked questions ") {
		return "faq"
	}
	if strings.Contains(text, " professional support ") || strings.Contains(text, " pro support ") || strings.Contains(text, " technical support ") || strings.Contains(text, " support services ") {
		return "service"
	}
	return ""
}

func familyCell(family, facet string, confidence int) string {
	if family == "" {
		return "unknown"
	}
	if facet != "" {
		family += ":" + facet
	}
	return fmt.Sprintf("%s (%d%%)", markdown(family), confidence)
}

func templateCell(id, family, facet string) string {
	if id == "" {
		return "none"
	}
	if family == "" {
		return markdown(id) + " (unknown)"
	}
	if facet != "" {
		family += ":" + facet
	}
	return markdown(id) + " (" + markdown(family) + ")"
}

func markdown(value string) string {
	return strings.ReplaceAll(strings.TrimSpace(value), "|", "\\|")
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
