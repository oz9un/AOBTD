package extract

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/ozzyw/aobtd/internal/target"
	"github.com/ozzyw/aobtd/internal/workflow"
)

// AppUnderstanding is the evolving model of what the application is and does.
// It accumulates as the LLM analyzes more endpoints.
type AppUnderstanding struct {
	AppType         string            `json:"app_type"`
	PageTemplates   []PageTemplate    `json:"page_templates"`
	FunctionalAreas []FunctionalArea  `json:"functional_areas"`
	AnalyzedHashes  map[string]string `json:"analyzed_hashes"` // endpoint_hash -> template_id or "unique"
	Summary         string            `json:"summary"`
	Recon           ReconModel        `json:"recon"`
}

// PageTemplate represents a recognized page pattern (e.g., "product detail", "user profile").
type PageTemplate struct {
	ID                 string   `json:"id"`
	Description        string   `json:"description"`
	ExampleURLs        []string `json:"example_urls"`
	Method             string   `json:"method,omitempty"`
	URLPattern         string   `json:"url_pattern,omitempty"`
	InputSignature     string   `json:"input_signature"` // from EndpointBundle.InputSignature()
	ResponseShape      string   `json:"response_shape,omitempty"`
	SemanticFamily     string   `json:"semantic_family,omitempty"`
	SemanticFacet      string   `json:"semantic_facet,omitempty"`
	SemanticConfidence int      `json:"semantic_confidence,omitempty"`
	EndpointCount      int      `json:"endpoint_count"`
}

// FunctionalArea groups related endpoints by business function.
type FunctionalArea struct {
	Name      string   `json:"name"`      // "authentication", "checkout", "admin", "catalog"
	Endpoints []string `json:"endpoints"` // list of endpoint_hashes
	Status    string   `json:"status"`    // "fully_analyzed", "partially_analyzed", "not_started"
	Priority  int      `json:"priority"`  // higher = more security-relevant
}

// NewAppUnderstanding creates an empty understanding.
func NewAppUnderstanding() *AppUnderstanding {
	return &AppUnderstanding{
		AnalyzedHashes: make(map[string]string),
	}
}

// LoadAppUnderstanding deserializes from DB-stored JSON fields.
func LoadAppUnderstanding(appType, templatesJSON, areasJSON, analyzedHashesJSON, summary string) *AppUnderstanding {
	u := &AppUnderstanding{
		AppType:        appType,
		Summary:        summary,
		AnalyzedHashes: make(map[string]string),
	}
	json.Unmarshal([]byte(templatesJSON), &u.PageTemplates)
	json.Unmarshal([]byte(areasJSON), &u.FunctionalAreas)
	json.Unmarshal([]byte(analyzedHashesJSON), &u.AnalyzedHashes)
	return u
}

// Serialize returns the JSON strings for DB storage.
func (u *AppUnderstanding) Serialize() (templatesJSON, areasJSON, analyzedHashesJSON string) {
	t, _ := json.Marshal(u.PageTemplates)
	a, _ := json.Marshal(u.FunctionalAreas)
	h, _ := json.Marshal(u.AnalyzedHashes)
	return string(t), string(a), string(h)
}

// MatchTemplate checks if a bundle's input signature matches a known template.
// Returns the template ID and true if matched, or empty string and false.
func (u *AppUnderstanding) MatchTemplate(bundle *EndpointBundle) (string, bool) {
	if bundle == nil {
		return "", false
	}
	sig := bundle.InputSignature()
	shape := bundle.ResponseShapeSignature()
	bundleSketch := bundle.SemanticSketch()
	if sig == "" && shape == "" {
		return "", false
	}

	// An exact learned route is stronger evidence than a newly inferred
	// semantic label. Match it first so model-written historical labels cannot
	// veto the route they were learned from. The caller still verifies the
	// template against the response; this only chooses the safest candidate.
	for _, tmpl := range u.PageTemplates {
		inputMatch := sig != "" && tmpl.InputSignature == sig
		shapeMatch := shape != "" && tmpl.ResponseShape != "" && tmpl.ResponseShape == shape
		if (inputMatch || shapeMatch) && templateMethodCompatible(tmpl, bundle) && templateExactRouteCompatible(tmpl, bundle) {
			return tmpl.ID, true
		}
	}

	for _, tmpl := range u.PageTemplates {
		inputMatch := sig != "" && tmpl.InputSignature == sig
		shapeMatch := shape != "" && tmpl.ResponseShape != "" && tmpl.ResponseShape == shape
		shapeCandidate := shapeMatch && responseShapeTemplateCompatible(tmpl, bundle)
		if (inputMatch || shapeCandidate) && templateMethodCompatible(tmpl, bundle) && templateURLFamilyCompatible(tmpl, bundle) && semanticTemplateFamilyCompatible(tmpl, bundle, bundleSketch) {
			return tmpl.ID, true
		}
	}
	return "", false
}

func templateExactRouteCompatible(tmpl PageTemplate, bundle *EndpointBundle) bool {
	if bundle == nil {
		return false
	}
	templateRoute := strings.TrimSpace(tmpl.URLPattern)
	bundleRoute := strings.TrimSpace(bundle.URLPattern)
	return templateRoute != "" && bundleRoute != "" && templateRoute == bundleRoute
}

// Matching search/header inputs are common across otherwise unrelated HTML
// pages. If both captured routes have a concrete semantic family and those
// families disagree, a template verification call cannot compact the page
// safely; go directly to full analysis. Unknown families remain eligible so
// this optimization never turns absence of a label into a semantic claim.
func semanticTemplateFamilyCompatible(tmpl PageTemplate, bundle *EndpointBundle, sketch ResponseSemanticSketch) bool {
	if bundle == nil {
		return true
	}
	description := strings.ToLower(strings.TrimSpace(tmpl.ID + " " + tmpl.Description))
	for _, marker := range []string{"site shell", "shared shell", "page shell", "shared layout", "base layout", "site template"} {
		if strings.Contains(description, marker) {
			return true
		}
	}
	templateFamily := templateSemanticFamily(tmpl)
	templateFacet := templateSemanticFacet(tmpl, templateFamily)
	bundleFamily := sketch.Family
	bundleFacet := sketch.Facet
	if bundleFamily == "" {
		bundleURL := firstNonEmptyString(bundle.URLPattern, bundle.SampleURL)
		bundleFamily = target.SurfaceFamily(bundleURL, "")
	}
	if templateFamily != "" && bundleFamily != "" && templateFamily != bundleFamily {
		return false
	}
	return templateFacet == "" || bundleFacet == "" || templateFacet == bundleFacet
}

func templateSemanticFacet(tmpl PageTemplate, family string) string {
	if strings.TrimSpace(tmpl.SemanticFacet) != "" {
		return strings.TrimSpace(tmpl.SemanticFacet)
	}
	templateURL := firstNonEmptyString(tmpl.URLPattern, firstTemplateExampleURL(tmpl))
	return semanticSketchFacet(templateURL+" "+tmpl.Description, family)
}

func templateSemanticFamily(tmpl PageTemplate) string {
	if strings.TrimSpace(tmpl.SemanticFamily) != "" {
		return strings.TrimSpace(tmpl.SemanticFamily)
	}
	templateURL := firstNonEmptyString(tmpl.URLPattern, firstTemplateExampleURL(tmpl))
	return target.SurfaceFamily(templateURL, tmpl.Description)
}

// A shared header/nav/footer makes many unrelated HTML pages look identical
// to the coarse response-shape fingerprint. Only spend a verification call
// across different routes when the stored template explicitly represents a
// reusable shell/layout. Route-specific templates remain reusable for the
// same normalized URL family (for example /products/{id}).
func responseShapeTemplateCompatible(tmpl PageTemplate, bundle *EndpointBundle) bool {
	description := strings.ToLower(strings.TrimSpace(tmpl.ID + " " + tmpl.Description))
	for _, marker := range []string{"site shell", "shared shell", "page shell", "shared layout", "base layout", "site template"} {
		if strings.Contains(description, marker) {
			return true
		}
	}
	templatePath := firstNonEmptyString(tmpl.URLPattern, firstTemplateExampleURL(tmpl))
	bundlePath := firstNonEmptyString(bundle.URLPattern, bundle.SampleURL)
	templateFamily, _ := canonicalTemplateFamilyPath(templatePath)
	bundleFamily, _ := canonicalTemplateFamilyPath(bundlePath)
	return templateFamily != "" && templateFamily == bundleFamily
}

func templateMethodCompatible(tmpl PageTemplate, bundle *EndpointBundle) bool {
	if strings.TrimSpace(tmpl.Method) == "" || bundle == nil || strings.TrimSpace(bundle.Method) == "" {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(tmpl.Method), strings.TrimSpace(bundle.Method))
}

func templateURLFamilyCompatible(tmpl PageTemplate, bundle *EndpointBundle) bool {
	if bundle == nil {
		return true
	}
	templatePath := firstNonEmptyString(tmpl.URLPattern, firstTemplateExampleURL(tmpl))
	bundlePath := firstNonEmptyString(bundle.URLPattern, bundle.SampleURL)
	if templatePath == "" || bundlePath == "" {
		return true
	}
	templateFamily, templateLesson := canonicalTemplateFamilyPath(templatePath)
	bundleFamily, bundleLesson := canonicalTemplateFamilyPath(bundlePath)
	if !templateLesson || !bundleLesson {
		return true
	}
	return templateFamily == bundleFamily
}

func firstTemplateExampleURL(tmpl PageTemplate) string {
	for _, example := range tmpl.ExampleURLs {
		if strings.TrimSpace(example) != "" {
			return example
		}
	}
	return ""
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func canonicalTemplateFamilyPath(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	path := raw
	if parsed, err := url.Parse(raw); err == nil && parsed.Path != "" {
		path = parsed.Path
	} else if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	if path == "" {
		return "/", false
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	segments := strings.Split(path, "/")
	hasLessonLevel := false
	for i, segment := range segments {
		if segment == "" {
			continue
		}
		if decoded, err := url.PathUnescape(segment); err == nil {
			segment = decoded
		}
		lower := strings.ToLower(strings.TrimSpace(segment))
		switch {
		case isLessonLevelSegment(lower):
			segments[i] = "{level}"
			hasLessonLevel = true
		case strings.HasPrefix(lower, "{") && strings.HasSuffix(lower, "}"):
			segments[i] = lower
		case isNumericID(lower) || uuidRe.MatchString(lower):
			segments[i] = "{id}"
		default:
			segments[i] = lower
		}
	}
	return strings.Join(segments, "/"), hasLessonLevel
}

func isLessonLevelSegment(segment string) bool {
	for _, prefix := range []string{"level_", "level-", "level"} {
		if strings.HasPrefix(segment, prefix) && allDigits(segment[len(prefix):]) {
			return true
		}
	}
	return false
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// RegisterTemplate adds a new page template from an analyzed bundle.
func (u *AppUnderstanding) RegisterTemplate(id, description string, bundle *EndpointBundle) {
	sketch := bundle.SemanticSketch()
	tmpl := PageTemplate{
		ID:                 id,
		Description:        description,
		InputSignature:     bundle.InputSignature(),
		ResponseShape:      bundle.ResponseShapeSignature(),
		SemanticFamily:     sketch.Family,
		SemanticFacet:      sketch.Facet,
		SemanticConfidence: sketch.Confidence,
		ExampleURLs:        []string{bundle.SampleURL},
		Method:             bundle.Method,
		URLPattern:         bundle.URLPattern,
		EndpointCount:      1,
	}
	u.PageTemplates = append(u.PageTemplates, tmpl)
}

// IncrementTemplate bumps the count for a matched template and adds a new example URL.
func (u *AppUnderstanding) IncrementTemplate(templateID string, sampleURL string) {
	for i := range u.PageTemplates {
		if u.PageTemplates[i].ID == templateID {
			u.PageTemplates[i].EndpointCount++
			if len(u.PageTemplates[i].ExampleURLs) < 3 {
				u.PageTemplates[i].ExampleURLs = append(u.PageTemplates[i].ExampleURLs, sampleURL)
			}
			return
		}
	}
}

// MarkAnalyzed records that an endpoint hash has been analyzed.
func (u *AppUnderstanding) MarkAnalyzed(endpointHash, templateID string) {
	if templateID == "" {
		templateID = "unique"
	}
	u.AnalyzedHashes[endpointHash] = templateID
}

// IsAnalyzed checks if an endpoint hash was already analyzed.
func (u *AppUnderstanding) IsAnalyzed(endpointHash string) bool {
	_, ok := u.AnalyzedHashes[endpointHash]
	return ok
}

// ClassifyFunctionalArea returns the likely functional area for an endpoint based on its URL.
func ClassifyFunctionalArea(urlPattern string) (name string, priority int) {
	area, priority := workflow.ClassifyArea(urlPattern)
	return string(area), priority
}

// AddToFunctionalArea adds an endpoint to the appropriate functional area.
func (u *AppUnderstanding) AddToFunctionalArea(endpointHash, urlPattern string) {
	areaName, priority := ClassifyFunctionalArea(urlPattern)

	for i := range u.FunctionalAreas {
		if u.FunctionalAreas[i].Name == areaName {
			// Check if already in this area
			for _, ep := range u.FunctionalAreas[i].Endpoints {
				if ep == endpointHash {
					return
				}
			}
			u.FunctionalAreas[i].Endpoints = append(u.FunctionalAreas[i].Endpoints, endpointHash)
			return
		}
	}

	// New area
	u.FunctionalAreas = append(u.FunctionalAreas, FunctionalArea{
		Name:      areaName,
		Endpoints: []string{endpointHash},
		Status:    "partially_analyzed",
		Priority:  priority,
	})
}

// RenderForLLM produces a compact text representation for injection into LLM context.
func (u *AppUnderstanding) RenderForLLM() string {
	if u == nil || (u.AppType == "" && u.Summary == "" && len(u.PageTemplates) == 0 && len(u.FunctionalAreas) == 0 && len(u.AnalyzedHashes) == 0) {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("## Application Understanding\n")

	if u.AppType != "" {
		fmt.Fprintf(&sb, "App type: %s\n", u.AppType)
	}
	if u.Summary != "" {
		fmt.Fprintf(&sb, "Summary: %s\n", u.Summary)
	}

	if len(u.PageTemplates) > 0 {
		sb.WriteString("\nKnown page templates:\n")
		for _, t := range u.PageTemplates {
			fmt.Fprintf(&sb, "  - %s: %s (%d instances)\n", t.ID, t.Description, t.EndpointCount)
		}
	}

	if len(u.FunctionalAreas) > 0 {
		sb.WriteString("\nFunctional areas:\n")
		for _, a := range u.FunctionalAreas {
			fmt.Fprintf(&sb, "  - %s: %d endpoints [%s]\n", a.Name, len(a.Endpoints), a.Status)
		}
	}

	fmt.Fprintf(&sb, "\nEndpoints analyzed so far: %d\n", len(u.AnalyzedHashes))
	if recon := u.RenderReconForLLM(); recon != "" {
		sb.WriteString("\n")
		sb.WriteString(recon)
	}

	return sb.String()
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
