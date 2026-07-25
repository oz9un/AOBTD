package ask

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/ozzyw/aobtd/internal/observation"
	"github.com/ozzyw/aobtd/internal/reconprojection"
	"github.com/ozzyw/aobtd/pkg/types"
)

const maxRouteEvidenceRows = 256

var (
	explicitRoutePathRE         = regexp.MustCompile(`(?:^|[^A-Za-z0-9_%./-])(/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+)`)
	routeEvidenceIntentRE       = regexp.MustCompile(`(?i)\b(?:what|which)\b.{0,48}\b(?:know|known|observed|proven|verified|evidence)\b`)
	routeExistenceEvidenceRE    = regexp.MustCompile(`(?i)\b(?:does|do|is|are)\b.{0,80}\b(?:exist|real|known|proven|verified|unverified)\b`)
	routeBucketEvidenceIntentRE = regexp.MustCompile(`(?i)\b(?:observed|inferred|unknown|proven|verified|unverified)\b.{0,32}\b(?:about|for)\b`)
)

// deterministicRouteEvidenceAnswer handles the deliberately narrow class of
// Copilot questions that ask what the current scan knows or proves about one
// or more explicit paths. Those questions should never depend on a model
// successfully finishing the JSON tool loop: exact direct-response evidence
// already has a deterministic interpretation shared with Recon and Knowledge.
//
// It intentionally does not match imperative questions such as "test /admin"
// or broad application questions that merely happen to mention a URL. Those
// continue through the normal Copilot loop and its approval controls.
func (e *Engine) deterministicRouteEvidenceAnswer(scanID int64, question string) (*Result, bool) {
	if e == nil || e.db == nil || !routeEvidenceQuestion(question) {
		return nil, false
	}
	paths := explicitRoutePaths(question)
	if len(paths) == 0 {
		return nil, false
	}

	profiles, err := e.db.GetAllProfiles(scanID)
	if err != nil {
		return nil, false
	}
	catchAllIndex, err := e.db.GetCatchAllIndex(scanID)
	if err != nil {
		return nil, false
	}

	var observed strings.Builder
	var unknown strings.Builder
	refs := make([]EvidenceRef, 0, 8)
	seenRefs := make(map[string]bool)
	for _, requestedPath := range paths {
		entries, total, err := e.exactRouteEvidenceTraffic(scanID, requestedPath)
		if err != nil {
			return nil, false
		}
		matchingProfiles := exactPathProfiles(profiles, requestedPath)
		methodOrigins := routeEvidenceMethodOrigins(entries, matchingProfiles)

		fmt.Fprintf(&observed, "- `%s`\n", requestedPath)
		if len(entries) == 0 {
			if len(matchingProfiles) == 0 {
				observed.WriteString("  - No direct traffic or profile record exactly matches this path in the selected scan. This is absence of evidence, not proof that the route is absent.\n")
			} else {
				fmt.Fprintf(&observed, "  - %d stored profile record(s) exactly match, but no direct response was captured for this path. A profile label is model interpretation, not proof of route behavior.\n", len(matchingProfiles))
			}
			fmt.Fprintf(&unknown, "- `%s`: whether the target serves this exact path, and any purpose, access policy, roles, data, or workflow behind it, remain unknown.\n", requestedPath)
			appendSanitizedProfileRefs(&refs, seenRefs, matchingProfiles)
			continue
		}

		methodStates := make(map[string]string, len(methodOrigins))
		originSet := make(map[string]bool)
		for _, item := range methodOrigins {
			originSet[item.Origin] = true
		}
		showOrigin := len(originSet) > 1
		for _, item := range methodOrigins {
			method, origin := item.Method, item.Origin
			methodEntries := trafficForMethodOrigin(entries, method, origin)
			methodKey := method + " " + origin
			originLabel := origin
			if originLabel == "" {
				originLabel = "unknown origin"
			} else {
				originLabel = displayRouteEvidenceOrigin(originLabel)
			}
			if len(methodEntries) == 0 {
				// A profile-only method is useful inventory context but cannot
				// inherit response proof from a different method.
				if showOrigin {
					fmt.Fprintf(&observed, "  - `%s` at `%s`: profile inventory only; no exact direct response for this method and origin.\n", method, originLabel)
				} else {
					fmt.Fprintf(&observed, "  - `%s`: profile inventory only; no exact direct response for this method.\n", method)
				}
				methodStates[methodKey] = "profile_only"
				continue
			}

			verdictURL := requestedPath
			if origin != "" {
				verdictURL = origin + requestedPath
			}
			verdict := types.PageProfile{ID: method + " " + verdictURL, Method: method, URL: verdictURL}
			variant := reconprojection.SummarizeQueryVariantEvidence(method, verdictURL, methodEntries, catchAllIndex)
			verdict.EvidenceState, verdict.EvidenceNote = variant.State, variant.Note
			verdict.ObservedStatuses = append([]int(nil), variant.ObservedStatuses...)
			verdict.RedirectLocations = append([]string(nil), variant.RedirectLocations...)
			if total > len(entries) && verdict.EvidenceState == "content_observed" {
				reconprojection.MarkResponseUnverified(&verdict,
					"The exact-path evidence set exceeded the bounded Copilot sample. Omitted query specimens were not allowed to inherit a sampled content verdict.")
			}
			methodStates[methodKey] = verdict.EvidenceState

			statuses := variant.ObservedStatuses
			locations := variant.RedirectLocations
			trafficIDs := routeEvidenceTrafficIDs(methodEntries, 3)
			if showOrigin {
				fmt.Fprintf(&observed, "  - `%s` at `%s`: status%s %s", method, originLabel, pluralSuffix(len(statuses)), inlineCodeInts(statuses))
			} else {
				fmt.Fprintf(&observed, "  - `%s`: status%s %s", method, pluralSuffix(len(statuses)), inlineCodeInts(statuses))
			}
			if len(locations) > 0 {
				fmt.Fprintf(&observed, "; `Location` %s", inlineCodeStrings(locations))
			}
			fmt.Fprintf(&observed, "; %s", routeEvidenceVerdict(verdict))
			if variant.Variants > 1 {
				fmt.Fprintf(&observed, "; %d exact query variants (%d content, %d unverified)",
					variant.Variants, variant.ContentVariants, variant.UnverifiedVariants)
			}
			if len(trafficIDs) > 0 {
				fmt.Fprintf(&observed, " (%s)", formatTrafficCitations(trafficIDs))
			}
			observed.WriteString(".\n")

			addedForMethod := 0
			for _, entry := range methodEntries {
				if len(refs) >= 8 {
					break
				}
				key := fmt.Sprintf("traffic\x00%d", entry.ID)
				if seenRefs[key] {
					continue
				}
				if ref, ok := e.resolveEvidenceRef(scanID, "traffic", fmt.Sprint(entry.ID)); ok {
					refs = append(refs, ref)
					seenRefs[key] = true
					addedForMethod++
					if addedForMethod == 2 {
						break
					}
				}
			}
		}
		if total > len(entries) {
			fmt.Fprintf(&observed, "  - Classification used a bounded %d of %d exact-path response rows; no omitted row is promoted into a semantic claim.\n", len(entries), total)
		}
		if routeMethodsDisagree(methodStates) {
			if showOrigin {
				observed.WriteString("  - Origin/method evidence differs. A substantive response on one origin or method does not verify a redirect, shell, error, or empty response on another.\n")
			} else {
				observed.WriteString("  - Method evidence differs. A substantive response to one method does not verify a redirect, shell, error, or empty response observed for another method.\n")
			}
		}

		if hasUnverifiedRouteMethod(methodStates) {
			fmt.Fprintf(&unknown, "- `%s`: the backing route's existence and business purpose behind the redirect, negative response, empty response, or generic shell remain unverified. The path and redirect target do not prove an access requirement, privileged function, role, object, or workflow.\n", requestedPath)
		} else {
			fmt.Fprintf(&unknown, "- `%s`: the captured substantive response proves only that the listed method/path returned content at that time. Its business purpose, access-control behavior, roles, data sensitivity, and workflows remain unknown without separate evidence.\n", requestedPath)
		}
		appendSanitizedProfileRefs(&refs, seenRefs, matchingProfiles)
	}

	answer := "## Observed\n\n" + strings.TrimSpace(observed.String()) +
		"\n\n## Inferred\n\n- None promoted from route names or persisted profile prose. Suggestive names are hypotheses, not proof of purpose, authorization, roles, data, or workflows.\n\n" +
		"## Unknown\n\n" + strings.TrimSpace(unknown.String())
	return &Result{
		Answer:    answer,
		Evidence:  refs,
		UIActions: []UIAction{{Type: "switch_view", View: "traffic"}},
	}, true
}

func routeEvidenceQuestion(question string) bool {
	lower := strings.ToLower(strings.TrimSpace(question))
	if lower == "" {
		return false
	}
	return containsAny(lower,
		"what do we know", "what do you know", "what is known", "what's known", "what was known",
		"what did recon find", "what did the scan find", "what has recon found", "what have we observed",
		"what was observed", "what is observed", "what is proven", "what's proven", "what does the evidence prove",
		"what can the evidence prove", "what evidence do we have", "what evidence exists", "evidence for",
		"observed, inferred", "observed versus inferred", "observed vs inferred", "observed/inferred",
		"proven versus unknown", "proven vs unknown", "actually know", "currently know", "is verified",
		"are verified", "is unverified", "are unverified", "does it exist", "do they exist", "is it real") ||
		routeEvidenceIntentRE.MatchString(question) || routeExistenceEvidenceRE.MatchString(question) ||
		routeBucketEvidenceIntentRE.MatchString(question)
}

func explicitRoutePaths(question string) []string {
	matches := explicitRoutePathRE.FindAllStringSubmatch(question, -1)
	paths := make([]string, 0, len(matches))
	seen := make(map[string]bool)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		candidate := match[1]
		if before, _, found := strings.Cut(candidate, "?"); found {
			candidate = before
		}
		candidate = strings.TrimRight(candidate, ".,;:!)]}>\"'`")
		if candidate == "" || candidate == "/" || strings.HasPrefix(candidate, "//") || seen[candidate] {
			continue
		}
		seen[candidate] = true
		paths = append(paths, candidate)
		if len(paths) == 8 {
			break
		}
	}
	return paths
}

func (e *Engine) exactRouteEvidenceTraffic(scanID int64, requestedPath string) ([]types.TrafficEntry, int, error) {
	var total int
	if err := e.db.Conn().QueryRow(`
		SELECT COUNT(*) FROM traffic
		 WHERE scan_id = ? AND is_filtered = FALSE AND is_duplicate = FALSE AND path = ?`, scanID, requestedPath).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := e.db.Conn().Query(`
		SELECT id, UPPER(method), url, path, status_code,
		       COALESCE(response_headers, '{}'), endpoint_hash,
		       CASE
		         WHEN LENGTH(COALESCE(response_body, X'')) <= 4096
		           THEN COALESCE(response_body, X'')
		         ELSE SUBSTR(COALESCE(response_body, X''), 1, 1024)
		              || SUBSTR(COALESCE(response_body, X''), -3072)
		       END,
		       COALESCE(content_type, ''), COALESCE(response_size, 0)
		  FROM traffic_resolved
		 WHERE scan_id = ? AND is_filtered = FALSE AND is_duplicate = FALSE AND path = ?
		 ORDER BY captured_at ASC, id ASC
		 LIMIT ?`, scanID, requestedPath, maxRouteEvidenceRows)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	entries := make([]types.TrafficEntry, 0)
	for rows.Next() {
		var entry types.TrafficEntry
		var responseHeaders string
		if err := rows.Scan(
			&entry.ID, &entry.Request.Method, &entry.Request.URL, &entry.Request.Path,
			&entry.Response.StatusCode, &responseHeaders, &entry.EndpointHash,
			&entry.Response.Body, &entry.Response.ContentType, &entry.Response.Size,
		); err != nil {
			return nil, 0, err
		}
		entry.Response.Headers = make(map[string]string)
		_ = json.Unmarshal([]byte(responseHeaders), &entry.Response.Headers)
		entries = append(entries, entry)
	}
	return entries, total, rows.Err()
}

func exactPathProfiles(profiles []types.PageProfile, requestedPath string) []types.PageProfile {
	matching := make([]types.PageProfile, 0)
	for _, profile := range profiles {
		parsed, err := url.Parse(strings.TrimSpace(profile.URL))
		if err != nil || parsed.EscapedPath() != requestedPath {
			continue
		}
		profile.Method = strings.ToUpper(strings.TrimSpace(profile.Method))
		if profile.Method == "" {
			profile.Method = http.MethodGet
		}
		matching = append(matching, profile)
	}
	sort.SliceStable(matching, func(i, j int) bool {
		if matching[i].Method != matching[j].Method {
			return matching[i].Method < matching[j].Method
		}
		return matching[i].ID < matching[j].ID
	})
	return matching
}

type routeEvidenceMethodOrigin struct {
	Method string
	Origin string
}

func displayRouteEvidenceOrigin(origin string) string {
	if strings.HasPrefix(origin, "https://") {
		return strings.TrimSuffix(origin, ":443")
	}
	if strings.HasPrefix(origin, "http://") {
		return strings.TrimSuffix(origin, ":80")
	}
	return origin
}

func routeEvidenceMethodOrigins(entries []types.TrafficEntry, profiles []types.PageProfile) []routeEvidenceMethodOrigin {
	seen := make(map[routeEvidenceMethodOrigin]bool)
	for _, entry := range entries {
		method := strings.ToUpper(strings.TrimSpace(entry.Request.Method))
		if method == "" {
			method = http.MethodGet
		}
		seen[routeEvidenceMethodOrigin{Method: method, Origin: observation.CanonicalOrigin(entry.Request.URL)}] = true
	}
	for _, profile := range profiles {
		seen[routeEvidenceMethodOrigin{Method: profile.Method, Origin: observation.CanonicalOrigin(profile.URL)}] = true
	}
	items := make([]routeEvidenceMethodOrigin, 0, len(seen))
	for item := range seen {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Origin != items[j].Origin {
			return items[i].Origin < items[j].Origin
		}
		return items[i].Method < items[j].Method
	})
	return items
}

func trafficForMethodOrigin(entries []types.TrafficEntry, method, origin string) []types.TrafficEntry {
	matching := make([]types.TrafficEntry, 0)
	for _, entry := range entries {
		if strings.EqualFold(strings.TrimSpace(entry.Request.Method), method) &&
			observation.CanonicalOrigin(entry.Request.URL) == origin {
			matching = append(matching, entry)
		}
	}
	return matching
}

func routeEvidenceStatuses(entries []types.TrafficEntry) []int {
	seen := make(map[int]bool)
	for _, entry := range entries {
		seen[entry.Response.StatusCode] = true
	}
	values := make([]int, 0, len(seen))
	for value := range seen {
		values = append(values, value)
	}
	sort.Ints(values)
	return values
}

func routeEvidenceLocations(entries []types.TrafficEntry) []string {
	seen := make(map[string]bool)
	for _, entry := range entries {
		for name, value := range entry.Response.Headers {
			if strings.EqualFold(strings.TrimSpace(name), "Location") && strings.TrimSpace(value) != "" {
				seen[strings.TrimSpace(value)] = true
			}
		}
	}
	values := make([]string, 0, len(seen))
	for value := range seen {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func routeEvidenceTrafficIDs(entries []types.TrafficEntry, limit int) []int64 {
	ids := make([]int64, 0, limit)
	seen := make(map[int64]bool)
	for _, entry := range entries {
		if entry.ID <= 0 || seen[entry.ID] {
			continue
		}
		seen[entry.ID] = true
		ids = append(ids, entry.ID)
		if len(ids) == limit {
			break
		}
	}
	return ids
}

func routeEvidenceVerdict(profile types.PageProfile) string {
	switch strings.ToLower(strings.TrimSpace(profile.EvidenceState)) {
	case "content_observed":
		return "a substantive direct response was observed. This verifies only the exact method/path response, not its business semantics"
	case "auth_gate_unverified", "redirect_only_unverified":
		return "UNVERIFIED redirect evidence. It proves the redirect and `Location`, not a backing page, its purpose, or an access requirement"
	case "response_unverified":
		note := strings.TrimSpace(profile.EvidenceNote)
		if note != "" {
			return "UNVERIFIED negative/shell response: " + note
		}
		return "UNVERIFIED response; no substantive backing content was observed"
	case "query_mixed_unverified":
		note := strings.TrimSpace(profile.EvidenceNote)
		if note != "" {
			return "UNVERIFIED mixed query-variant evidence: " + note
		}
		return "UNVERIFIED mixed query-variant evidence; one query specimen cannot verify its siblings"
	default:
		return "UNVERIFIED response evidence"
	}
}

func routeMethodsDisagree(states map[string]string) bool {
	hasContent := false
	hasOther := false
	for _, state := range states {
		if state == "content_observed" {
			hasContent = true
		} else {
			hasOther = true
		}
	}
	return hasContent && hasOther
}

func hasUnverifiedRouteMethod(states map[string]string) bool {
	if len(states) == 0 {
		return true
	}
	for _, state := range states {
		if state != "content_observed" {
			return true
		}
	}
	return false
}

func inlineCodeInts(values []int) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, fmt.Sprintf("`%d`", value))
	}
	if len(parts) == 0 {
		return "`unknown`"
	}
	return strings.Join(parts, ", ")
}

func inlineCodeStrings(values []string) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, "`"+strings.ReplaceAll(value, "`", "")+"`")
	}
	return strings.Join(parts, ", ")
}

func formatTrafficCitations(ids []int64) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, fmt.Sprintf("traffic #%d", id))
	}
	return strings.Join(parts, ", ")
}

func pluralSuffix(count int) string {
	if count == 1 {
		return ""
	}
	return "es"
}

func appendSanitizedProfileRefs(refs *[]EvidenceRef, seen map[string]bool, profiles []types.PageProfile) {
	for _, profile := range profiles {
		if len(*refs) >= 8 {
			return
		}
		key := "profile\x00" + profile.ID
		if seen[key] {
			continue
		}
		*refs = append(*refs, EvidenceRef{
			Kind:  "profile",
			ID:    profile.ID,
			Label: profile.ID + " · semantic labels not treated as direct proof",
			URL:   profile.URL,
		})
		seen[key] = true
	}
}
