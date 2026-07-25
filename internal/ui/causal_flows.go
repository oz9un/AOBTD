package ui

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	causalFlowSchemaVersion = 2
	causalFlowDefaultEvents = 600
	causalFlowMaxEvents     = 5000
	causalFlowDefaultFlows  = 40
	causalFlowMaxFlows      = 200
)

type causalFlowEvent struct {
	ID             int64             `json:"id"`
	Method         string            `json:"method"`
	URL            string            `json:"url"`
	Host           string            `json:"host"`
	Path           string            `json:"path"`
	StatusCode     int               `json:"status_code"`
	EndpointHash   string            `json:"endpoint_hash,omitempty"`
	HasAuth        bool              `json:"has_auth"`
	IsAPI          bool              `json:"is_api"`
	CapturedAt     string            `json:"captured_at"`
	SourceAgent    string            `json:"source_agent,omitempty"`
	SourceActionID int64             `json:"source_action_id,omitempty"`
	HypothesisID   string            `json:"hypothesis_id,omitempty"`
	Action         *causalFlowAction `json:"action,omitempty"`
	InScope        bool              `json:"in_scope"`

	capturedTime   time.Time
	requestHeaders string
	responseHeader string
}

type causalFlowAction struct {
	ID           int64  `json:"id"`
	Namespace    string `json:"namespace"`
	SourceAgent  string `json:"source_agent"`
	Action       string `json:"action"`
	Reason       string `json:"reason,omitempty"`
	FromURL      string `json:"from_url,omitempty"`
	ToURL        string `json:"to_url,omitempty"`
	HypothesisID string `json:"hypothesis_id,omitempty"`
	Status       string `json:"status"`
	Result       string `json:"result,omitempty"`
	StartedAt    string `json:"started_at"`
	CompletedAt  string `json:"completed_at,omitempty"`
}

type causalFlowLink struct {
	SourceID   int64   `json:"source_id"`
	TargetID   int64   `json:"target_id"`
	Type       string  `json:"type"`
	Evidence   string  `json:"evidence"`
	Grade      string  `json:"grade"`
	Confidence float64 `json:"confidence"`
	DeltaMS    int64   `json:"delta_ms"`
}

type causalFlowFinding struct {
	ID           int64   `json:"id"`
	Title        string  `json:"title"`
	Severity     string  `json:"severity"`
	EndpointID   string  `json:"endpoint_id"`
	Method       string  `json:"method,omitempty"`
	Path         string  `json:"path,omitempty"`
	HypothesisID string  `json:"hypothesis_id,omitempty"`
	MatchBasis   string  `json:"match_basis"`
	EventIDs     []int64 `json:"event_ids"`
}

type causalFlow struct {
	ID                string              `json:"id"`
	Label             string              `json:"label"`
	StartedAt         string              `json:"started_at"`
	EndedAt           string              `json:"ended_at"`
	DurationMS        int64               `json:"duration_ms"`
	Confidence        float64             `json:"confidence"`
	StrongestEvidence string              `json:"strongest_evidence"`
	WorstSeverity     string              `json:"worst_severity,omitempty"`
	LinkCounts        map[string]int      `json:"link_counts"`
	Events            []causalFlowEvent   `json:"events"`
	Links             []causalFlowLink    `json:"links"`
	Findings          []causalFlowFinding `json:"findings"`
}

type causalFlowLegendEntry struct {
	Grade   string `json:"grade"`
	Meaning string `json:"meaning"`
}

type causalFlowResponse struct {
	SchemaVersion    int                     `json:"schema_version"`
	Scope            string                  `json:"scope"`
	Flows            []causalFlow            `json:"flows"`
	UnlinkedFindings []causalFlowFinding     `json:"unlinked_findings"`
	Stats            map[string]int          `json:"stats"`
	Legend           []causalFlowLegendEntry `json:"legend"`
}

func (s *Server) handleCausalFlows(w http.ResponseWriter, r *http.Request) {
	scanID := s.scanIDFromRequest(r)
	eventLimit := boundedCausalParam(r, "limit", causalFlowDefaultEvents, causalFlowMaxEvents)
	flowLimit := boundedCausalParam(r, "flow_limit", causalFlowDefaultFlows, causalFlowMaxFlows)
	includeAllScope := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("scope")), "all")

	var scanTarget, configJSON string
	if err := s.db.Conn().QueryRow(`SELECT target, config_json FROM scans WHERE id = ?`, scanID).
		Scan(&scanTarget, &configJSON); err != nil {
		jsonError(w, "no scans found", http.StatusNotFound)
		return
	}
	scope := graphProjectionScopeFromConfig(scanTarget, configJSON)

	columns, err := causalTrafficColumns(s.db.Conn())
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	optional := func(name, fallback string) string {
		if columns[name] {
			return "COALESCE(" + name + ", " + fallback + ")"
		}
		return fallback
	}
	query := fmt.Sprintf(`
		SELECT id, UPPER(method), url, status_code, endpoint_hash,
		       has_auth, is_api, captured_at, request_headers, response_headers,
		       %s, %s, %s
		  FROM traffic
		 WHERE scan_id = ? AND is_filtered = FALSE AND is_duplicate = FALSE
		 ORDER BY captured_at DESC, id DESC
		 LIMIT ?`, optional("source_agent", "''"), optional("source_action_id", "0"), optional("hypothesis_id", "''"))
	rows, err := s.db.Conn().Query(query, scanID, eventLimit+1)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	events := make([]causalFlowEvent, 0, eventLimit)
	truncated := false
	for rows.Next() {
		var event causalFlowEvent
		var rawURL string
		if err := rows.Scan(&event.ID, &event.Method, &rawURL, &event.StatusCode, &event.EndpointHash,
			&event.HasAuth, &event.IsAPI, &event.capturedTime, &event.requestHeaders, &event.responseHeader,
			&event.SourceAgent, &event.SourceActionID, &event.HypothesisID); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if len(events) >= eventLimit {
			truncated = true
			continue
		}
		canonical, ok := canonicalGraphURL(rawURL)
		if !ok {
			continue
		}
		_, inScope, _ := scope.MatchURL(canonical)
		if !includeAllScope && !inScope {
			continue
		}
		parsed, _ := url.Parse(canonical)
		event.URL = canonical
		event.Host = parsed.Host
		event.Path = parsed.RequestURI()
		if event.Path == "" {
			event.Path = "/"
		}
		event.CapturedAt = event.capturedTime.UTC().Format(time.RFC3339Nano)
		event.InScope = inScope
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for left, right := 0, len(events)-1; left < right; left, right = left+1, right-1 {
		events[left], events[right] = events[right], events[left]
	}
	if err := attachCausalFlowActions(s.db.Conn(), scanID, events); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	links := buildCausalFlowLinks(events)
	flows, orphanEvents := assembleCausalFlows(events, links)
	unlinkedFindings, confirmedFindings, linkedFindings, err := attachCausalFlowFindings(
		s.db.Conn(), scanID, scanTarget, events, flows,
	)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sortCausalFlows(flows)
	if len(flows) > flowLimit {
		flows = flows[:flowLimit]
		truncated = true
	}
	stats := map[string]int{
		"events_considered":            len(events),
		"links":                        len(links),
		"flows":                        len(flows),
		"orphan_events":                orphanEvents,
		"confirmed_findings":           confirmedFindings,
		"linked_findings":              linkedFindings,
		"unlinked_findings":            len(unlinkedFindings),
		"observed_links":               0,
		"attributed_links":             0,
		"correlated_links":             0,
		"inferred_links":               0,
		"agent_attributed_events":      0,
		"action_attributed_events":     0,
		"hypothesis_attributed_events": 0,
		"unattributed_events":          0,
		"unresolved_action_refs":       0,
		"attribution_coverage_pct":     0,
		"action_coverage_pct":          0,
		"truncated":                    0,
	}
	for _, link := range links {
		stats[link.Grade+"_links"]++
	}
	for _, event := range events {
		if causalAttributedAgent(event.SourceAgent) {
			stats["agent_attributed_events"]++
		} else {
			stats["unattributed_events"]++
		}
		if event.Action != nil {
			stats["action_attributed_events"]++
		} else if event.SourceActionID > 0 {
			stats["unresolved_action_refs"]++
		}
		if event.HypothesisID != "" {
			stats["hypothesis_attributed_events"]++
		}
	}
	if len(events) > 0 {
		stats["attribution_coverage_pct"] = causalPercent(stats["agent_attributed_events"], len(events))
	}
	if stats["agent_attributed_events"] > 0 {
		stats["action_coverage_pct"] = causalPercent(stats["action_attributed_events"], stats["agent_attributed_events"])
	}
	if truncated {
		stats["truncated"] = 1
	}
	jsonResponse(w, causalFlowResponse{
		SchemaVersion:    causalFlowSchemaVersion,
		Scope:            map[bool]string{true: "all", false: "in"}[includeAllScope],
		Flows:            flows,
		UnlinkedFindings: unlinkedFindings,
		Stats:            stats,
		Legend: []causalFlowLegendEntry{
			{Grade: "observed", Meaning: "A protocol artifact directly links the requests (Referer or redirect Location)."},
			{Grade: "attributed", Meaning: "Scanner provenance explicitly assigns both requests to one action or hypothesis."},
			{Grade: "correlated", Meaning: "Related evidence supports a transition, but does not prove the initiating cause."},
			{Grade: "inferred", Meaning: "Timing and request shape suggest sequence only; causation is not claimed."},
		},
	})
}

func attachCausalFlowActions(db *sql.DB, scanID int64, events []causalFlowEvent) error {
	actions := make(map[string]causalFlowAction)
	rows, err := db.Query(`
		SELECT id, source_agent, action, reason, from_url, to_url,
		       hypothesis_id, status, result, CAST(started_at AS TEXT),
		       COALESCE(CAST(completed_at AS TEXT), '')
		  FROM traffic_actions
		 WHERE scan_id = ?
		 ORDER BY id`, scanID)
	if err != nil {
		return fmt.Errorf("query browser traffic actions: %w", err)
	}
	for rows.Next() {
		var action causalFlowAction
		action.Namespace = "browser"
		if err := rows.Scan(
			&action.ID, &action.SourceAgent, &action.Action, &action.Reason,
			&action.FromURL, &action.ToURL, &action.HypothesisID, &action.Status,
			&action.Result, &action.StartedAt, &action.CompletedAt,
		); err != nil {
			rows.Close()
			return fmt.Errorf("scan browser traffic action: %w", err)
		}
		actions[causalActionKey(action.SourceAgent, action.ID)] = action
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate browser traffic actions: %w", err)
	}
	rows.Close()

	rows, err = db.Query(`
		SELECT id, action, COALESCE(reason, ''), COALESCE(url, ''),
		       COALESCE(hypothesis_id, ''), status, COALESCE(result, ''),
		       CAST(created_at AS TEXT), COALESCE(CAST(completed_at AS TEXT), '')
		  FROM follow_ups
		 WHERE scan_id = ?
		 ORDER BY id`, scanID)
	if err != nil {
		return fmt.Errorf("query explorer traffic actions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		action := causalFlowAction{Namespace: "follow_up", SourceAgent: "explorer"}
		if err := rows.Scan(
			&action.ID, &action.Action, &action.Reason, &action.ToURL,
			&action.HypothesisID, &action.Status, &action.Result,
			&action.StartedAt, &action.CompletedAt,
		); err != nil {
			return fmt.Errorf("scan explorer traffic action: %w", err)
		}
		actions[causalActionKey(action.SourceAgent, action.ID)] = action
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate explorer traffic actions: %w", err)
	}

	for index := range events {
		if events[index].SourceActionID <= 0 {
			continue
		}
		action, ok := actions[causalActionKey(events[index].SourceAgent, events[index].SourceActionID)]
		if !ok {
			continue
		}
		events[index].Action = &action
		if events[index].HypothesisID == "" {
			events[index].HypothesisID = action.HypothesisID
		}
	}
	return nil
}

func causalActionKey(sourceAgent string, actionID int64) string {
	return strings.ToLower(strings.TrimSpace(sourceAgent)) + ":" + strconv.FormatInt(actionID, 10)
}

func causalAttributedAgent(sourceAgent string) bool {
	sourceAgent = strings.TrimSpace(sourceAgent)
	return sourceAgent != "" && !strings.EqualFold(sourceAgent, "capture")
}

func causalPercent(numerator, denominator int) int {
	if numerator <= 0 || denominator <= 0 {
		return 0
	}
	return (numerator*100 + denominator/2) / denominator
}

func boundedCausalParam(r *http.Request, name string, fallback, maximum int) int {
	value, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get(name)))
	if err != nil || value <= 0 {
		return fallback
	}
	if value > maximum {
		return maximum
	}
	return value
}

func causalTrafficColumns(db *sql.DB) (map[string]bool, error) {
	rows, err := db.Query(`PRAGMA table_info('traffic')`)
	if err != nil {
		return nil, fmt.Errorf("inspect traffic schema: %w", err)
	}
	defer rows.Close()
	columns := make(map[string]bool)
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return nil, err
		}
		columns[strings.ToLower(name)] = true
	}
	return columns, rows.Err()
}

func buildCausalFlowLinks(events []causalFlowEvent) []causalFlowLink {
	links := make([]causalFlowLink, 0, len(events))
	seen := make(map[string]struct{})
	add := func(source, target int, kind, evidence, grade string, confidence float64) {
		if source < 0 || target < 0 || source >= target || target >= len(events) {
			return
		}
		key := fmt.Sprintf("%d:%d:%s", events[source].ID, events[target].ID, kind)
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		links = append(links, causalFlowLink{
			SourceID: events[source].ID, TargetID: events[target].ID,
			Type: kind, Evidence: evidence, Grade: grade, Confidence: confidence,
			DeltaMS: causalDeltaMS(events[source], events[target]),
		})
	}

	lastURL := make(map[string]int)
	lastAction := make(map[string]int)
	lastHypothesis := make(map[string]int)
	pendingRedirect := make(map[string]int)
	for index := range events {
		event := events[index]
		incomingEvidence := false
		if source, ok := pendingRedirect[event.URL]; ok {
			add(source, index, "redirect", "3xx response Location matched the next captured URL", "observed", 1)
			incomingEvidence = true
			delete(pendingRedirect, event.URL)
		}
		if referer := causalHeader(event.requestHeaders, "referer"); referer != "" {
			if canonical, ok := canonicalGraphURL(referer); ok {
				if source, exists := lastURL[canonical]; exists {
					kind := "referer-navigation"
					if causalStateChanging(event.Method) {
						kind = "referer-submission"
					}
					add(source, index, kind, "request Referer matched an earlier captured URL", "observed", .95)
					incomingEvidence = true
				}
			}
		}
		if event.SourceActionID > 0 {
			actionKey := causalActionKey(event.SourceAgent, event.SourceActionID)
			if source, exists := lastAction[actionKey]; exists {
				add(source, index, "agent-action", "shared source_action_id", "attributed", .9)
				incomingEvidence = true
			}
			lastAction[actionKey] = index
		}
		if event.HypothesisID != "" {
			if source, exists := lastHypothesis[event.HypothesisID]; exists {
				add(source, index, "hypothesis-sequence", "shared hypothesis_id", "attributed", .75)
				incomingEvidence = true
			}
			lastHypothesis[event.HypothesisID] = index
		}
		if index > 0 {
			previous := events[index-1]
			delta := causalDeltaMS(previous, event)
			eventCarriesSession := event.HasAuth || causalHeader(event.requestHeaders, "cookie") != ""
			previousCarriesSession := previous.HasAuth || causalHeader(previous.requestHeaders, "cookie") != ""
			if delta >= 0 && delta <= int64((30*time.Second)/time.Millisecond) &&
				causalHeader(previous.responseHeader, "set-cookie") != "" && eventCarriesSession &&
				(!previousCarriesSession || discoveryGraphAuthPath(previous.Path)) {
				add(index-1, index, "auth-transition", "Set-Cookie response followed by a cookie or credential-bearing request", "correlated", .8)
				incomingEvidence = true
			}
			if !incomingEvidence && delta >= 0 && delta <= int64((2*time.Second)/time.Millisecond) &&
				previous.Host == event.Host && causalTemporalCandidate(previous, event) {
				add(index-1, index, "temporal-sequence", fmt.Sprintf("adjacent captures within %d ms", delta), "inferred", .35)
			}
		}
		if event.StatusCode >= 300 && event.StatusCode < 400 {
			if location := causalHeader(event.responseHeader, "location"); location != "" {
				if resolved, ok := causalResolveURL(event.URL, location); ok {
					pendingRedirect[resolved] = index
				}
			}
		}
		lastURL[event.URL] = index
	}
	return links
}

func causalHeader(raw, wanted string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	var headers map[string]any
	if json.Unmarshal([]byte(raw), &headers) != nil {
		return ""
	}
	for key, value := range headers {
		if !strings.EqualFold(key, wanted) && !(wanted == "referer" && strings.EqualFold(key, "referrer")) {
			continue
		}
		switch typed := value.(type) {
		case string:
			return strings.TrimSpace(typed)
		case []any:
			if len(typed) > 0 {
				return strings.TrimSpace(fmt.Sprint(typed[0]))
			}
		default:
			return strings.TrimSpace(fmt.Sprint(typed))
		}
	}
	return ""
}

func causalResolveURL(baseURL, location string) (string, bool) {
	base, baseErr := url.Parse(baseURL)
	reference, refErr := url.Parse(strings.TrimSpace(location))
	if baseErr != nil || refErr != nil {
		return "", false
	}
	return canonicalGraphURL(base.ResolveReference(reference).String())
}

func causalStateChanging(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func causalTemporalCandidate(source, target causalFlowEvent) bool {
	return causalStateChanging(source.Method) || causalStateChanging(target.Method) ||
		discoveryGraphAuthPath(source.Path) || discoveryGraphAuthPath(target.Path) ||
		source.HasAuth != target.HasAuth
}

func causalDeltaMS(source, target causalFlowEvent) int64 {
	if source.capturedTime.IsZero() || target.capturedTime.IsZero() {
		return 0
	}
	return target.capturedTime.Sub(source.capturedTime).Milliseconds()
}

func attachCausalFlowFindings(db *sql.DB, scanID int64, scanTarget string, events []causalFlowEvent, flows []causalFlow) ([]causalFlowFinding, int, int, error) {
	eventByID := make(map[int64]causalFlowEvent, len(events))
	eventFlow := make(map[int64]int, len(events))
	for _, event := range events {
		eventByID[event.ID] = event
	}
	for flowIndex := range flows {
		flows[flowIndex].Findings = []causalFlowFinding{}
		for _, event := range flows[flowIndex].Events {
			eventFlow[event.ID] = flowIndex
		}
	}

	rows, err := db.Query(`
		SELECT id, title, severity, COALESCE(endpoint_id, ''),
		       COALESCE(traffic_ids, '[]'), COALESCE(poc_request, ''),
		       COALESCE(hypothesis_id, '')
		  FROM findings
		 WHERE scan_id = ? AND confidence = 'confirmed'
		 ORDER BY id`, scanID)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("query causal-flow findings: %w", err)
	}
	defer rows.Close()

	unlinked := make([]causalFlowFinding, 0)
	confirmedCount := 0
	linkedCount := 0
	for rows.Next() {
		confirmedCount++
		var finding causalFlowFinding
		var trafficJSON, pocRequest string
		if err := rows.Scan(&finding.ID, &finding.Title, &finding.Severity, &finding.EndpointID,
			&trafficJSON, &pocRequest, &finding.HypothesisID); err != nil {
			return nil, 0, 0, err
		}
		ctx := graphFindingTargetContext(scanTarget, finding.EndpointID, pocRequest)
		finding.Method = strings.ToUpper(strings.TrimSpace(ctx.Method))
		finding.Path = ctx.Path

		matched := make([]int64, 0)
		for _, trafficID := range causalFindingTrafficIDs(trafficJSON) {
			if _, ok := eventByID[trafficID]; ok {
				matched = appendUniqueInt64(matched, trafficID)
			}
		}
		if len(matched) > 0 {
			finding.MatchBasis = "explicit-traffic"
		} else if finding.HypothesisID != "" {
			for _, event := range events {
				if event.HypothesisID == finding.HypothesisID {
					matched = appendUniqueInt64(matched, event.ID)
				}
			}
			if len(matched) > 0 {
				finding.MatchBasis = "hypothesis"
			}
		}
		if len(matched) == 0 && finding.Path != "" {
			for _, event := range events {
				if event.Path == finding.Path && (finding.Method == "" || event.Method == finding.Method) {
					matched = appendUniqueInt64(matched, event.ID)
				}
			}
			if len(matched) > 0 {
				finding.MatchBasis = "endpoint"
			}
		}
		if finding.MatchBasis == "" {
			finding.MatchBasis = "unmatched"
		}

		byFlow := make(map[int][]int64)
		for _, eventID := range matched {
			if flowIndex, ok := eventFlow[eventID]; ok {
				byFlow[flowIndex] = appendUniqueInt64(byFlow[flowIndex], eventID)
			}
		}
		if len(byFlow) == 0 {
			finding.EventIDs = nonNilInt64s(matched)
			unlinked = append(unlinked, finding)
			continue
		}
		linkedCount++
		for flowIndex, eventIDs := range byFlow {
			flowFinding := finding
			flowFinding.EventIDs = nonNilInt64s(eventIDs)
			flows[flowIndex].Findings = append(flows[flowIndex].Findings, flowFinding)
			if causalSeverityRank(finding.Severity) > causalSeverityRank(flows[flowIndex].WorstSeverity) {
				flows[flowIndex].WorstSeverity = strings.ToLower(finding.Severity)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, 0, 0, err
	}
	for index := range flows {
		sort.Slice(flows[index].Findings, func(i, j int) bool {
			left, right := flows[index].Findings[i], flows[index].Findings[j]
			if causalSeverityRank(left.Severity) == causalSeverityRank(right.Severity) {
				return left.ID < right.ID
			}
			return causalSeverityRank(left.Severity) > causalSeverityRank(right.Severity)
		})
	}
	sort.Slice(unlinked, func(i, j int) bool {
		if causalSeverityRank(unlinked[i].Severity) == causalSeverityRank(unlinked[j].Severity) {
			return unlinked[i].ID < unlinked[j].ID
		}
		return causalSeverityRank(unlinked[i].Severity) > causalSeverityRank(unlinked[j].Severity)
	})
	return unlinked, confirmedCount, linkedCount, nil
}

func causalFindingTrafficIDs(raw string) []int64 {
	var ids []int64
	if json.Unmarshal([]byte(strings.TrimSpace(raw)), &ids) != nil {
		return []int64{}
	}
	return nonNilInt64s(ids)
}

func appendUniqueInt64(values []int64, value int64) []int64 {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func nonNilInt64s(values []int64) []int64 {
	if values == nil {
		return []int64{}
	}
	return values
}

func causalSeverityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

func sortCausalFlows(flows []causalFlow) {
	sort.SliceStable(flows, func(i, j int) bool {
		leftRisk := causalSeverityRank(flows[i].WorstSeverity)
		rightRisk := causalSeverityRank(flows[j].WorstSeverity)
		if leftRisk != rightRisk {
			return leftRisk > rightRisk
		}
		if len(flows[i].Findings) != len(flows[j].Findings) {
			return len(flows[i].Findings) > len(flows[j].Findings)
		}
		return flows[i].EndedAt > flows[j].EndedAt
	})
}

func assembleCausalFlows(events []causalFlowEvent, links []causalFlowLink) ([]causalFlow, int) {
	if len(events) == 0 {
		return []causalFlow{}, 0
	}
	parents := make([]int, len(events))
	byID := make(map[int64]int, len(events))
	for index := range events {
		parents[index] = index
		byID[events[index].ID] = index
	}
	var find func(int) int
	find = func(index int) int {
		if parents[index] != index {
			parents[index] = find(parents[index])
		}
		return parents[index]
	}
	union := func(left, right int) {
		leftRoot, rightRoot := find(left), find(right)
		if leftRoot != rightRoot {
			parents[rightRoot] = leftRoot
		}
	}
	for _, link := range links {
		left, leftOK := byID[link.SourceID]
		right, rightOK := byID[link.TargetID]
		if leftOK && rightOK {
			union(left, right)
		}
	}
	components := make(map[int][]int)
	for index := range events {
		components[find(index)] = append(components[find(index)], index)
	}
	linksByRoot := make(map[int][]causalFlowLink)
	for _, link := range links {
		if index, ok := byID[link.SourceID]; ok {
			root := find(index)
			linksByRoot[root] = append(linksByRoot[root], link)
		}
	}
	flows := make([]causalFlow, 0, len(components))
	orphans := 0
	gradeRank := map[string]int{"observed": 4, "attributed": 3, "correlated": 2, "inferred": 1}
	for root, indexes := range components {
		componentLinks := linksByRoot[root]
		if len(componentLinks) == 0 {
			orphans += len(indexes)
			continue
		}
		flowEvents := make([]causalFlowEvent, 0, len(indexes))
		for _, index := range indexes {
			flowEvents = append(flowEvents, events[index])
		}
		sort.Slice(flowEvents, func(i, j int) bool {
			if flowEvents[i].capturedTime.Equal(flowEvents[j].capturedTime) {
				return flowEvents[i].ID < flowEvents[j].ID
			}
			return flowEvents[i].capturedTime.Before(flowEvents[j].capturedTime)
		})
		sort.Slice(componentLinks, func(i, j int) bool {
			if componentLinks[i].TargetID == componentLinks[j].TargetID {
				return componentLinks[i].SourceID < componentLinks[j].SourceID
			}
			return componentLinks[i].TargetID < componentLinks[j].TargetID
		})
		linkCounts := make(map[string]int)
		strongest := "inferred"
		confidenceTotal := 0.0
		for _, link := range componentLinks {
			linkCounts[link.Grade]++
			confidenceTotal += link.Confidence
			if gradeRank[link.Grade] > gradeRank[strongest] {
				strongest = link.Grade
			}
		}
		first, last := flowEvents[0], flowEvents[len(flowEvents)-1]
		flows = append(flows, causalFlow{
			ID:                fmt.Sprintf("flow-%d-%d", first.ID, last.ID),
			Label:             causalFlowLabel(first, last),
			StartedAt:         first.CapturedAt,
			EndedAt:           last.CapturedAt,
			DurationMS:        causalDeltaMS(first, last),
			Confidence:        confidenceTotal / float64(len(componentLinks)),
			StrongestEvidence: strongest,
			LinkCounts:        linkCounts,
			Events:            flowEvents,
			Links:             componentLinks,
			Findings:          []causalFlowFinding{},
		})
	}
	sort.Slice(flows, func(i, j int) bool {
		return flows[i].EndedAt > flows[j].EndedAt
	})
	return flows, orphans
}

func causalFlowLabel(first, last causalFlowEvent) string {
	left := strings.TrimSpace(first.Method + " " + first.Path)
	right := strings.TrimSpace(last.Method + " " + last.Path)
	if first.Host != last.Host {
		left = first.Host + " · " + left
		right = last.Host + " · " + right
	}
	if first.ID == last.ID {
		return left
	}
	return left + " → " + right
}
