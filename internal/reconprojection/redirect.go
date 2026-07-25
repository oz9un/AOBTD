// Package reconprojection applies deterministic response evidence ceilings to
// the semantic target model. It is shared by every read surface that explains
// the application so Knowledge, Recon, Target Brain, and Target Copilot cannot
// disagree about what a redirect-only route proves.
package reconprojection

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/internal/observation"
	"github.com/ozzyw/aobtd/pkg/types"
)

// AnnotateProfiles projects the direct response verdict onto a copy of the
// stored page profiles. The underlying model prose remains immutable; a later
// direct content response can lift a route out of redirect-only state.
func AnnotateProfiles(profiles []types.PageProfile, entries []types.TrafficEntry) {
	if len(profiles) == 0 {
		return
	}
	byHash := make(map[string][]types.TrafficEntry)
	for _, entry := range entries {
		hash := strings.TrimSpace(entry.EndpointHash)
		if hash == "" {
			hash = observation.EndpointHash(entry.Request.Method, entry.Request.URL)
		}
		byHash[hash] = append(byHash[hash], entry)
	}
	for i := range profiles {
		profile := &profiles[i]
		method := strings.ToUpper(strings.TrimSpace(profile.Method))
		if method == "" {
			method = http.MethodGet
		}
		hash := observation.EndpointHash(method, profile.URL)
		familyEntries := byHash[hash]
		AnnotateProfile(profile, EntriesForExactSpecimen(familyEntries, method, profile.URL))
		ApplyQueryVariantCeiling(profile, familyEntries, nil)
	}
}

// IsSyntheticSummaryProfile reports the two page_profiles rows that are
// structured scan summaries rather than claims about an HTTP route. Their
// value comes from captured JavaScript or aggregate surface analysis, so the
// absence of a same-ID direct response must not erase or mislabel them as a
// failed page observation.
func IsSyntheticSummaryProfile(profile types.PageProfile) bool {
	switch strings.TrimSpace(profile.ID) {
	case "attack_surface", "js_discovered_routes":
		return true
	default:
		return false
	}
}

// AnnotateProfile applies direct response evidence to one page profile.
func AnnotateProfile(profile *types.PageProfile, entries []types.TrafficEntry) {
	if profile == nil || IsSyntheticSummaryProfile(*profile) {
		return
	}
	if len(entries) == 0 {
		note := fmt.Sprintf(
			"No matching direct HTTP response was captured for %s. The stored profile is analysis inventory only; route existence, access, purpose, and business semantics are unverified.",
			profileRequestLabel(*profile),
		)
		applyUnverifiedProfileCeiling(profile, "response_unverified", note, nil, nil)
		return
	}
	evidence := observation.SummarizeRedirectEvidence(entries)
	profile.ObservedStatuses = append([]int(nil), evidence.StatusCodes...)
	if evidence.ContentObserved {
		profile.EvidenceState = "content_observed"
		profile.EvidenceNote = ""
		profile.RedirectLocations = nil
		return
	}
	if !evidence.RedirectOnly {
		requested := profile.URL
		if strings.TrimSpace(entries[0].Request.Path) != "" {
			requested = entries[0].Request.Path
		}
		reasons := make([]string, 0, 4)
		if len(evidence.NonContentStatusCodes) > 0 {
			reasons = append(reasons, "non-content HTTP statuses "+formatStatuses(evidence.NonContentStatusCodes))
		}
		if evidence.EmptySuccessObserved {
			reasons = append(reasons, "an empty success response")
		}
		if evidence.AuthShellObserved {
			reasons = append(reasons, "a generic authentication shell")
		}
		if evidence.ErrorShellObserved {
			reasons = append(reasons, "a generic error shell")
		}
		if len(reasons) == 0 {
			reasons = append(reasons, "no substantive direct page response")
		}
		note := fmt.Sprintf(
			"Requested %s; observed %s, but no substantive backing page content. Route purpose and business semantics are unverified.",
			requested, joinNatural(reasons),
		)
		applyUnverifiedProfileCeiling(profile, "response_unverified", note, evidence.StatusCodes, nil)
		return
	}
	state := "redirect_only_unverified"
	if evidence.PathPreservingAuthGate {
		state = "auth_gate_unverified"
	}
	requested := profile.URL
	if strings.TrimSpace(entries[0].Request.Path) != "" {
		requested = entries[0].Request.Path
	}
	destination := "a redirect destination"
	if len(evidence.Locations) == 1 {
		destination = evidence.Locations[0]
	} else if len(evidence.Locations) > 1 {
		destination = fmt.Sprintf("%d redirect destinations", len(evidence.Locations))
	}
	observed := "only a redirect to " + destination + " was observed"
	if !evidence.PureRedirect {
		observed = "redirect behavior to " + destination + " plus non-content responses was observed"
	}
	note := fmt.Sprintf(
		"Requested %s; %s. Backing route existence and purpose are unverified.",
		requested, observed,
	)
	applyUnverifiedProfileCeiling(profile, state, note, evidence.StatusCodes, evidence.Locations)
}

func applyUnverifiedProfileCeiling(profile *types.PageProfile, state, note string, statuses []int, locations []string) {
	profile.EvidenceState = state
	profile.EvidenceNote = note
	profile.Purpose = note
	profile.AuthRequired = "unknown"
	profile.DataExposed = nil
	profile.APIsCalled = nil
	profile.Behaviors = nil
	profile.Relationships = nil
	profile.Issues = nil
	profile.TechNotes = ""
	profile.Inputs = nil
	profile.ExtractedInputs = nil
	profile.HasInput = false
	profile.HasFileUpload = false
	profile.HasAuth = false
	profile.HasErrors = false
	profile.IsAPI = false
	profile.TemplateID = ""
	profile.ObservedStatuses = append([]int(nil), statuses...)
	profile.RedirectLocations = append([]string(nil), locations...)
	if profile.Confidence > 0.35 {
		profile.Confidence = 0.35
	}
}

// MarkResponseUnverified applies the same semantic ceiling used by direct
// response classification when an independent deterministic verifier finds
// that a stored profile cannot be safely attributed to one concrete route.
// Callers must supply a grounded reason; this function deliberately exposes
// no way to promote evidence.
func MarkResponseUnverified(profile *types.PageProfile, note string) {
	if profile == nil {
		return
	}
	if strings.TrimSpace(note) == "" {
		note = "The stored profile cannot be attributed to one substantive direct response."
	}
	applyUnverifiedProfileCeiling(profile, "response_unverified", note, nil, nil)
}

func profileRequestLabel(profile types.PageProfile) string {
	method := strings.ToUpper(strings.TrimSpace(profile.Method))
	if method == "" {
		method = http.MethodGet
	}
	rawURL := strings.TrimSpace(profile.URL)
	if rawURL == "" {
		rawURL = strings.TrimSpace(profile.ID)
	}
	if rawURL == "" {
		return method + " route"
	}
	return method + " " + rawURL
}

func formatStatuses(statuses []int) string {
	values := make([]string, 0, len(statuses))
	for _, status := range statuses {
		values = append(values, fmt.Sprint(status))
	}
	return strings.Join(values, ", ")
}

func joinNatural(values []string) string {
	switch len(values) {
	case 0:
		return "no substantive direct page response"
	case 1:
		return values[0]
	case 2:
		return values[0] + " and " + values[1]
	default:
		return strings.Join(values[:len(values)-1], ", ") + ", and " + values[len(values)-1]
	}
}

// ApplyRedirectEvidence projects annotated unverified-response profiles onto
// an application understanding. A path-preserving authentication redirect,
// negative/shell response, or inventory-only profile proves neither the
// backing page nor its role, object, workflow, access policy, or purpose.
func ApplyRedirectEvidence(u *extract.AppUnderstanding, profiles []types.PageProfile) {
	if u == nil || len(profiles) == 0 {
		return
	}

	profilesByID := make(map[string]types.PageProfile, len(profiles))
	verifiedPageIDs := make(map[string]bool)
	for _, profile := range profiles {
		profilesByID[profile.ID] = profile
		if profile.EvidenceState == "content_observed" {
			verifiedPageIDs[profile.ID] = true
		}
	}

	unverifiedPaths := make(map[string]bool)
	unverifiedTerms := make(map[string]bool)
	unverifiedPageIDs := make(map[string]bool)
	unverifiedPagePaths := make(map[string]string)
	hasNonRedirectUnverified := false
	// Build the dependency ceiling from profiles themselves, not only from
	// page cards. Historical/partial semantic models can contain a role,
	// workflow, or object whose evidence references a stored profile even when
	// the corresponding page card is absent. Omitting that profile ID here
	// would let the dependent claim escape every read surface.
	for _, profile := range profiles {
		state := strings.ToLower(strings.TrimSpace(profile.EvidenceState))
		if !strings.HasSuffix(state, "_unverified") {
			continue
		}
		unverifiedPageIDs[profile.ID] = true
		if state != "auth_gate_unverified" && state != "redirect_only_unverified" {
			hasNonRedirectUnverified = true
		}
		path := EvidencePath(profile.URL)
		if path != "" {
			unverifiedPagePaths[profile.ID] = path
			unverifiedPaths[path] = true
		}
		for _, term := range SemanticTerms(profile.URL) {
			unverifiedTerms[term] = true
		}
	}
	for i := range u.Recon.Pages {
		page := &u.Recon.Pages[i]
		profile, ok := profilesByID[page.ID]
		state := strings.ToLower(strings.TrimSpace(profile.EvidenceState))
		if !ok || !strings.HasSuffix(state, "_unverified") {
			continue
		}

		note := strings.TrimSpace(profile.EvidenceNote)
		if note == "" {
			note = "No verifiable direct page response was observed. Backing route existence and purpose are unverified."
		}
		page.Purpose = note
		page.AuthRequired = "unknown"
		page.ObjectIDs = nil
		page.SecurityInterest = nil
		evidenceKind := "verification"
		if state == "auth_gate_unverified" {
			page.Actions = []string{"Returned an HTTP redirect; no backing page content was observed"}
			page.Area = "authentication"
			evidenceKind = "redirect"
		} else if state == "redirect_only_unverified" {
			page.Actions = []string{"Returned an HTTP redirect; no backing page content was observed"}
			page.Area = "redirect"
			evidenceKind = "redirect"
		} else {
			page.Actions = []string{"No directly verifiable backing page response was observed"}
			page.Area = "unverified"
			hasNonRedirectUnverified = true
		}
		if page.Confidence > 0.35 {
			page.Confidence = 0.35
		}
		page.Evidence = appendEvidenceOnce(page.Evidence, evidenceKind, profile.ID, note)
	}
	ProjectRedirectOnlyDependencies(&u.Recon, unverifiedPageIDs, verifiedPageIDs, unverifiedPagePaths)

	if sanitized, changed := sanitizeSemanticSummary(u.Recon.Identity.Summary, unverifiedTerms, unverifiedPaths, hasNonRedirectUnverified); changed {
		u.Summary = sanitized
		u.Recon.Identity.Summary = sanitized
	}
	u.RecalculateReconMetrics()
}

// ProjectRedirectOnlyDependencies removes semantic claims whose complete
// support set is redirect-only page references. Mixed claims retain their
// independently supported branch.
func ProjectRedirectOnlyDependencies(model *extract.ReconModel, unverifiedPageIDs, verifiedPageIDs map[string]bool, unverifiedPagePaths map[string]string) {
	if model == nil || len(unverifiedPageIDs) == 0 {
		return
	}

	removedRoles := make(map[string]bool)
	roles := make([]extract.ReconRole, 0, len(model.Roles))
	for _, role := range model.Roles {
		if supportExclusivelyUnverified(role.Evidence, nil, unverifiedPageIDs, verifiedPageIDs) {
			removedRoles[role.ID] = true
			continue
		}
		role.Evidence = withoutUnverifiedEvidence(role.Evidence, unverifiedPageIDs)
		roles = append(roles, role)
	}
	model.Roles = roles

	removedObjects := make(map[string]bool)
	objects := make([]extract.BusinessObject, 0, len(model.Objects))
	for _, object := range model.Objects {
		if supportExclusivelyUnverified(object.Evidence, nil, unverifiedPageIDs, verifiedPageIDs) {
			removedObjects[object.ID] = true
			continue
		}
		object.Evidence = withoutUnverifiedEvidence(object.Evidence, unverifiedPageIDs)
		object.OwnerRoleIDs = withoutRemovedIDs(object.OwnerRoleIDs, removedRoles)
		objects = append(objects, object)
	}
	model.Objects = objects

	workflows := make([]extract.BusinessWorkflow, 0, len(model.Workflows))
	for _, workflow := range model.Workflows {
		pageRefs := make([]string, 0)
		for _, step := range workflow.Steps {
			pageRefs = append(pageRefs, step.PageIDs...)
		}
		if supportExclusivelyUnverified(workflow.Evidence, pageRefs, unverifiedPageIDs, verifiedPageIDs) {
			continue
		}
		workflow.Evidence = withoutUnverifiedEvidence(workflow.Evidence, unverifiedPageIDs)
		steps := make([]extract.WorkflowStep, 0, len(workflow.Steps))
		for _, step := range workflow.Steps {
			hadPageRefs := len(step.PageIDs) > 0
			step.PageIDs = withoutRemovedIDs(step.PageIDs, unverifiedPageIDs)
			if hadPageRefs && len(step.PageIDs) == 0 {
				continue
			}
			step.RoleIDs = withoutRemovedIDs(step.RoleIDs, removedRoles)
			step.ObjectIDs = withoutRemovedIDs(step.ObjectIDs, removedObjects)
			steps = append(steps, step)
		}
		workflow.Steps = steps
		if len(workflow.Steps) == 0 {
			continue
		}
		workflows = append(workflows, workflow)
	}
	model.Workflows = workflows

	boundaries := make([]extract.OwnershipBoundary, 0, len(model.OwnershipBoundaries))
	for _, boundary := range model.OwnershipBoundaries {
		if supportExclusivelyUnverified(boundary.Evidence, boundary.EnforcedAt, unverifiedPageIDs, verifiedPageIDs) {
			continue
		}
		if removedObjects[boundary.ObjectID] || removedRoles[boundary.OwnerRoleID] {
			continue
		}
		hadEnforcementRefs := len(boundary.EnforcedAt) > 0
		boundary.EnforcedAt = withoutRemovedIDs(boundary.EnforcedAt, unverifiedPageIDs)
		if hadEnforcementRefs && len(boundary.EnforcedAt) == 0 {
			continue
		}
		boundary.Evidence = withoutUnverifiedEvidence(boundary.Evidence, unverifiedPageIDs)
		boundaries = append(boundaries, boundary)
	}
	model.OwnershipBoundaries = boundaries

	type unverifiedRouteRef struct {
		pageID string
		path   string
	}
	unverifiedRoutes := make([]unverifiedRouteRef, 0, len(unverifiedPageIDs))
	for pageID, path := range unverifiedPagePaths {
		if unverifiedPageIDs[pageID] && path != "" && path != "/" {
			unverifiedRoutes = append(unverifiedRoutes, unverifiedRouteRef{pageID: pageID, path: path})
		}
	}
	sort.Slice(unverifiedRoutes, func(i, j int) bool {
		if len(unverifiedRoutes[i].path) == len(unverifiedRoutes[j].path) {
			return unverifiedRoutes[i].pageID < unverifiedRoutes[j].pageID
		}
		return len(unverifiedRoutes[i].path) > len(unverifiedRoutes[j].path)
	})

	for i := range model.Unknowns {
		unknown := &model.Unknowns[i]
		var refs []string
		if supportExclusivelyUnverified(unknown.Evidence, nil, unverifiedPageIDs, verifiedPageIDs) {
			refs = unverifiedEvidenceRefs(unknown.Evidence, unverifiedPageIDs)
		}
		if len(refs) == 0 {
			text := strings.Join([]string{unknown.Question, unknown.WhyItMatters, unknown.SuggestedAction}, " ")
			if RedirectMechanicsQuestion(text) {
				continue
			}
			for _, route := range unverifiedRoutes {
				if TextMentionsRoutePath(text, route.path) {
					refs = append(refs, route.pageID)
				}
			}
		}
		if len(refs) == 0 {
			continue
		}
		sort.Strings(refs)
		refs = compactSortedStrings(refs)
		refLabel := strings.Join(refs, " and ")
		unknown.Question = "What, if anything, is verified by the unverified direct-response evidence for " + refLabel + "?"
		unknown.WhyItMatters = "A redirect, negative response, empty body, or generic shell does not verify a backing page, role boundary, or business behavior."
		unknown.SuggestedAction = "Capture a substantive direct response for " + refLabel + " before assigning route semantics."
	}

	for i := range model.Pages {
		model.Pages[i].ObjectIDs = withoutRemovedIDs(model.Pages[i].ObjectIDs, removedObjects)
	}
}

// RedirectMechanicsQuestion distinguishes questions about redirect behavior
// itself from semantic claims about a route hidden behind the redirect.
func RedirectMechanicsQuestion(text string) bool {
	lower := strings.ToLower(text)
	for _, marker := range []string{
		"open redirect", "redirect parameter", "redirect target", "redirect chain",
		"redirect behavior", "redirect-only route", "location header",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// TextMentionsRoutePath matches a complete route token so /api is not treated
// as evidence for a claim about /api/v1.
func TextMentionsRoutePath(text, path string) bool {
	text = strings.ToLower(text)
	path = strings.ToLower(strings.TrimSpace(path))
	if path == "" || path == "/" {
		return false
	}
	for offset := 0; offset < len(text); {
		index := strings.Index(text[offset:], path)
		if index < 0 {
			return false
		}
		index += offset
		end := index + len(path)
		beforeOK := index == 0 || !routePathTokenByte(text[index-1])
		afterOK := end == len(text) || !routePathTokenByte(text[end])
		if beforeOK && afterOK {
			return true
		}
		offset = index + 1
	}
	return false
}

// SanitizeHistoricalAnswer removes stale semantic claims from prior Copilot
// answers before they are returned to the model as follow-up context. History
// is useful conversational state, but it is not evidence and must not override
// a newer deterministic response verdict.
func SanitizeHistoricalAnswer(answer string, profiles []types.PageProfile) (string, bool) {
	type routeVerdict struct {
		path  string
		terms []string
	}
	verdicts := make([]routeVerdict, 0)
	seenPaths := make(map[string]bool)
	for _, profile := range profiles {
		state := strings.ToLower(strings.TrimSpace(profile.EvidenceState))
		if !strings.HasSuffix(state, "_unverified") {
			continue
		}
		path := EvidencePath(profile.URL)
		if path == "" || path == "/" || seenPaths[path] {
			continue
		}
		seenPaths[path] = true
		verdicts = append(verdicts, routeVerdict{path: path, terms: SemanticTerms(profile.URL)})
	}
	if strings.TrimSpace(answer) == "" || len(verdicts) == 0 {
		return answer, false
	}
	sort.Slice(verdicts, func(i, j int) bool { return verdicts[i].path < verdicts[j].path })

	isCalibrated := func(line string) bool {
		lower := strings.ToLower(line)
		for _, marker := range []string{
			"unverified", "not verified", "redirect-only", "redirect only", "only redirect",
			"backing route", "does not prove", "doesn't prove", "not prove", "no page content",
			"no directly observed", "do not assume", "unknown whether", "existence is unknown",
		} {
			if strings.Contains(lower, marker) {
				return true
			}
		}
		return false
	}
	claimsUnverifiedRoute := func(line string) bool {
		lower := strings.ToLower(line)
		for _, verdict := range verdicts {
			if TextMentionsRoutePath(line, verdict.path) {
				return true
			}
			for _, term := range verdict.terms {
				if term == "admin" && (strings.Contains(lower, "admin") || strings.Contains(lower, "administrative")) {
					return true
				}
				if term == "dashboard" && strings.Contains(lower, "dashboard") {
					return true
				}
			}
		}
		return false
	}

	lines := strings.Split(answer, "\n")
	kept := make([]string, 0, len(lines)+1)
	changed := false
	for _, line := range lines {
		if claimsUnverifiedRoute(line) && !isCalibrated(line) {
			changed = true
			continue
		}
		kept = append(kept, line)
	}
	if !changed {
		return answer, false
	}
	paths := make([]string, 0, len(verdicts))
	for _, verdict := range verdicts {
		paths = append(paths, verdict.path)
	}
	note := "[Historical claim removed: current direct evidence leaves " + strings.Join(paths, ", ") + " unverified.]"
	kept = append([]string{note}, kept...)
	return strings.TrimSpace(strings.Join(kept, "\n")), true
}

// SemanticTerms extracts meaningful route words that a model might promote
// into business semantics without direct evidence. Authentication plumbing
// and generic web prefixes are excluded; everything else is kept so the same
// ceiling protects /billing, /orders, /reports, and future app-specific names
// rather than only the historically obvious /admin example.
func SemanticTerms(rawURL string) []string {
	path := strings.ToLower(EvidencePath(rawURL))
	if decoded, err := url.PathUnescape(path); err == nil {
		path = decoded
	}
	stop := map[string]bool{
		"api": true, "v1": true, "v2": true, "v3": true, "www": true,
		"auth": true, "oauth": true, "login": true, "logout": true,
		"signin": true, "signout": true, "callback": true, "redirect": true,
		"index": true, "home": true, "page": true, "html": true, "htm": true,
	}
	seen := make(map[string]bool)
	terms := make([]string, 0, 4)
	for _, segment := range strings.FieldsFunc(path, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
	}) {
		if len(segment) < 3 || stop[segment] || seen[segment] {
			continue
		}
		seen[segment] = true
		terms = append(terms, segment)
	}
	sort.Strings(terms)
	return terms
}

// EvidencePath returns the exact request path represented by a profile URL.
func EvidencePath(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err == nil && parsed.Path != "" {
		return parsed.Path
	}
	if strings.HasPrefix(strings.TrimSpace(rawURL), "/") {
		return strings.TrimSpace(rawURL)
	}
	return ""
}

func routePathTokenByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9' ||
		value == '/' || value == '_' || value == '-' || value == '.' || value == '%'
}

func compactSortedStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

func supportExclusivelyUnverified(evidence []extract.ReconEvidence, pageRefs []string, unverifiedPageIDs, verifiedPageIDs map[string]bool) bool {
	hasUnverifiedSupport := false
	hasVerifiedSupport := false
	for _, item := range evidence {
		ref := strings.TrimSpace(item.Ref)
		if ref == "" {
			continue
		}
		if unverifiedPageIDs[ref] {
			hasUnverifiedSupport = true
			continue
		}
		if verifiedPageIDs[ref] {
			hasVerifiedSupport = true
		}
	}
	for _, ref := range pageRefs {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			continue
		}
		if unverifiedPageIDs[ref] {
			hasUnverifiedSupport = true
			continue
		}
		if verifiedPageIDs[ref] {
			hasVerifiedSupport = true
		}
	}
	// Blank, hallucinated, and unresolved refs are not independent evidence.
	// A semantic claim survives an unverified route only when another exact
	// profile with substantive direct content positively supports it.
	return hasUnverifiedSupport && !hasVerifiedSupport
}

func withoutUnverifiedEvidence(evidence []extract.ReconEvidence, unverifiedPageIDs map[string]bool) []extract.ReconEvidence {
	kept := make([]extract.ReconEvidence, 0, len(evidence))
	for _, item := range evidence {
		if !unverifiedPageIDs[strings.TrimSpace(item.Ref)] {
			kept = append(kept, item)
		}
	}
	return kept
}

func unverifiedEvidenceRefs(evidence []extract.ReconEvidence, unverifiedPageIDs map[string]bool) []string {
	seen := make(map[string]bool)
	refs := make([]string, 0, len(evidence))
	for _, item := range evidence {
		ref := strings.TrimSpace(item.Ref)
		if ref == "" || !unverifiedPageIDs[ref] || seen[ref] {
			continue
		}
		seen[ref] = true
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	return refs
}

func withoutRemovedIDs(ids []string, removed map[string]bool) []string {
	kept := make([]string, 0, len(ids))
	for _, id := range ids {
		if !removed[id] {
			kept = append(kept, id)
		}
	}
	return kept
}

func appendEvidenceOnce(evidence []extract.ReconEvidence, kind, ref, detail string) []extract.ReconEvidence {
	for _, item := range evidence {
		if item.Kind == kind && item.Ref == ref && item.Detail == detail {
			return evidence
		}
	}
	return append(evidence, extract.ReconEvidence{Kind: kind, Ref: ref, Detail: detail})
}

func sanitizeSemanticSummary(summary string, terms, paths map[string]bool, hasNonRedirectUnverified bool) (string, bool) {
	if strings.TrimSpace(summary) == "" || len(terms) == 0 && len(paths) == 0 {
		return summary, false
	}
	claimsTerm := func(sentence string) bool {
		lower := strings.ToLower(sentence)
		for path := range paths {
			if path = strings.ToLower(strings.TrimSpace(path)); path != "" && path != "/" && strings.Contains(lower, path) {
				return true
			}
		}
		words := make(map[string]bool)
		for _, word := range strings.FieldsFunc(lower, func(r rune) bool {
			return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
		}) {
			words[word] = true
		}
		for term := range terms {
			if words[term] || term == "admin" &&
				(words["administrator"] || words["administrators"] || words["administrative"] || words["administration"]) {
				return true
			}
		}
		return false
	}

	parts := strings.FieldsFunc(summary, func(r rune) bool {
		return r == '.' || r == '!' || r == '?'
	})
	kept := make([]string, 0, len(parts))
	changed := false
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if claimsTerm(part) {
			changed = true
			continue
		}
		kept = append(kept, part)
	}
	if !changed {
		return summary, false
	}

	orderedPaths := make([]string, 0, len(paths))
	for path := range paths {
		orderedPaths = append(orderedPaths, path)
	}
	sort.Strings(orderedPaths)
	subject := "The suggestive route"
	verb := "was"
	if len(orderedPaths) == 1 {
		subject = "The request for " + orderedPaths[0]
	} else if len(orderedPaths) > 1 {
		subject = "Requests for " + strings.Join(orderedPaths[:len(orderedPaths)-1], ", ") + " and " + orderedPaths[len(orderedPaths)-1]
		verb = "were"
	}
	verdict := "observed only as path-preserving authentication redirects"
	if hasNonRedirectUnverified {
		verdict = "not backed by a verifiable direct page response"
	}
	note := fmt.Sprintf("%s %s %s; backing route existence and business purpose remain unverified.", subject, verb, verdict)
	if len(kept) == 0 {
		return note, true
	}
	return strings.Join(kept, ". ") + ". " + note, true
}
