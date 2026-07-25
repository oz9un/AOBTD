package agent

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"unicode"

	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/internal/store"
	targetmodel "github.com/ozzyw/aobtd/internal/target"
)

const maxAnalysisEvidenceGain = 64

// RankAnalysisQueue applies the application's current semantic gaps to the
// capture-based queue. It performs no network activity and invents no routes;
// it only changes which already-captured endpoint family the AI reads next.
func RankAnalysisQueue(items []store.AnalysisQueueItem, recon extract.ReconModel) []store.AnalysisQueueItem {
	return RankAnalysisQueueWithAges(items, recon, nil)
}

// RankAnalysisQueueWithAges adds a bounded fairness boost derived from durable
// checkpoint history. Semantic evidence remains the primary ordering signal;
// age only ensures an eligible lower-base family cannot remain invisible over
// repeated learning checkpoints.
func RankAnalysisQueueWithAges(items []store.AnalysisQueueItem, recon extract.ReconModel, ages map[string]int) []store.AnalysisQueueItem {
	return RankAnalysisQueueWithFeedback(items, recon, ages, nil)
}

// RankAnalysisQueueWithFeedback applies small scan-local adjustments learned
// only after at least two prior batch outcomes for the same explicit gap.
func RankAnalysisQueueWithFeedback(items []store.AnalysisQueueItem, recon extract.ReconModel, ages map[string]int, calibration map[string]int) []store.AnalysisQueueItem {
	ranked := append([]store.AnalysisQueueItem(nil), items...)
	knownFamilies := make(map[string]bool)
	for _, page := range recon.Pages {
		if family := targetmodel.SurfaceFamily(page.URL, page.Purpose+" "+page.Area); family != "" {
			knownFamilies[family] = true
		}
	}
	objectTerms := reconObjectTerms(recon.Objects)
	successfulRouteShapes := make(map[string]string)
	for _, item := range ranked {
		if item.StatusCode >= 200 && item.StatusCode < 300 {
			if key := analysisQueueRouteShape(item); key != "" {
				successfulRouteShapes[key] = strings.TrimSpace(item.Path)
			}
		}
	}

	for index := range ranked {
		item := &ranked[index]
		item.Reasons = append([]string(nil), item.Reasons...)
		item.LearnedBoost = 0
		item.EvidenceGain = 0
		item.AgingBoost = 0
		item.QueueAge = ages[item.EndpointHash]
		item.FairnessLane = false
		item.PriorityScore = item.BaseScore
		item.LearnedReasons = nil
		item.Impact = nil
		if item.CanonicalRedirect && !item.HasHypothesis {
			item.Disposition = "skip"
			item.LearnedBoost = -80
			item.QueueAge = 0
			item.LearnedReasons = appendQueueReason(item.LearnedReasons, "canonical trailing-slash redirect with captured successful landing page")
			item.Reasons = appendQueueReason(item.Reasons, "canonical trailing-slash redirect with captured successful landing page")
			item.PriorityScore = item.BaseScore + item.LearnedBoost
			continue
		}
		// Gap attribution is deliberately path-local. Hostnames often contain
		// product/account words that describe deployment topology, not the
		// response's business evidence, and would create misleading impacts.
		text := strings.ToLower(strings.Join([]string{item.Method, item.Path}, " "))
		family := targetmodel.SurfaceFamily(item.URL, item.Path)
		addLearned := func(points int, reason string) {
			if points <= 0 || reason == "" {
				return
			}
			item.LearnedBoost += points
			item.Reasons = appendQueueReason(item.Reasons, reason)
			item.LearnedReasons = appendQueueReason(item.LearnedReasons, reason)
		}
		addImpact := func(kind, id, label string, priority, points int, reason string) {
			if id == "" || points <= 0 || reason == "" {
				return
			}
			adjustment := calibration[analysisImpactCalibrationKey(kind, id)]
			adjustedPoints := points + adjustment
			if adjustedPoints < 1 {
				adjustedPoints = 1
			}
			item.Impact = append(item.Impact, store.AnalysisGapImpact{
				Kind: kind, ID: id, Label: analysisGapLabel(label, id), Priority: priority,
				Score: adjustedPoints, Calibration: adjustment,
			})
			item.Reasons = appendQueueReason(item.Reasons, reason)
			item.LearnedReasons = appendQueueReason(item.LearnedReasons, reason)
		}
		if queueIsCapturedRedirectAlias(item, successfulRouteShapes) {
			item.Disposition = "skip"
			item.LearnedBoost = -80
			item.QueueAge = 0
			item.LearnedReasons = appendQueueReason(item.LearnedReasons, "redirect alias of a captured successful landing page")
			item.Reasons = appendQueueReason(item.Reasons, "redirect alias of a captured successful landing page")
			item.PriorityScore = item.BaseScore + item.LearnedBoost
			continue
		}
		if queueLooksLikeBrowserArtifact(item) {
			item.Disposition = "skip"
			item.LearnedBoost = -80
			item.QueueAge = 0
			item.LearnedReasons = appendQueueReason(item.LearnedReasons, "low-value browser or transport artifact")
			item.Reasons = appendQueueReason(item.Reasons, "low-value browser or transport artifact")
			item.PriorityScore = item.BaseScore + item.LearnedBoost
			continue
		}

		for _, target := range recon.Targets {
			if target.Met || strings.TrimSpace(target.ID) == "" {
				continue
			}
			matched, points, reason := analysisTargetImpact(target.ID, item, family, text, objectTerms)
			if matched {
				addImpact("target", target.ID, target.Label, target.Priority, points, reason)
			}
		}
		if family != "" && !knownFamilies[family] && targetmodel.SurfaceValue(family) >= 11 {
			addLearned(14, "new semantic surface family: "+family)
		}
		for _, unknown := range recon.Unknowns {
			if unknown.Priority < 6 || strings.TrimSpace(unknown.ID) == "" {
				continue
			}
			if hits := queueTermHits(text, reconUnknownGapTerms(unknown)); hits > 0 {
				addImpact("unknown", unknown.ID, unknown.Question, unknown.Priority,
					minQueueInt(18, 6*hits), "matches open Recon question: "+analysisGapLabel(unknown.Question, unknown.ID))
			}
		}
		sort.SliceStable(item.Impact, func(i, j int) bool {
			if item.Impact[i].Score != item.Impact[j].Score {
				return item.Impact[i].Score > item.Impact[j].Score
			}
			if item.Impact[i].Priority != item.Impact[j].Priority {
				return item.Impact[i].Priority > item.Impact[j].Priority
			}
			return item.Impact[i].ID < item.Impact[j].ID
		})
		for _, impact := range item.Impact {
			item.EvidenceGain += impact.Score
		}
		item.EvidenceGain = minQueueInt(maxAnalysisEvidenceGain, item.EvidenceGain)
		item.LearnedBoost += item.EvidenceGain
		if item.EvidenceGain > 0 {
			item.Reasons = appendQueueReason(item.Reasons, fmt.Sprintf("bounded evidence gain +%d", item.EvidenceGain))
			item.LearnedReasons = appendQueueReason(item.LearnedReasons, fmt.Sprintf("bounded evidence gain +%d", item.EvidenceGain))
		}
		if item.QueueAge > 0 {
			item.AgingBoost = minQueueInt(20, item.QueueAge*4)
			ageReason := fmt.Sprintf("deferred for %d learning checkpoint", item.QueueAge)
			if item.QueueAge != 1 {
				ageReason += "s"
			}
			item.Reasons = appendQueueReason(item.Reasons, ageReason)
		}
		item.PriorityScore = item.BaseScore + item.LearnedBoost + item.AgingBoost
	}

	sort.SliceStable(ranked, func(i, j int) bool {
		if ranked[i].PriorityScore != ranked[j].PriorityScore {
			return ranked[i].PriorityScore > ranked[j].PriorityScore
		}
		if ranked[i].LearnedBoost != ranked[j].LearnedBoost {
			return ranked[i].LearnedBoost > ranked[j].LearnedBoost
		}
		return ranked[i].EndpointHash < ranked[j].EndpointHash
	})
	return ranked
}

func AnalysisImpactCalibrationMap(values []store.AnalysisImpactCalibration) map[string]int {
	out := make(map[string]int, len(values))
	for _, value := range values {
		if value.Adjustment != 0 {
			out[analysisImpactCalibrationKey(value.Kind, value.ID)] = value.Adjustment
		}
	}
	return out
}

func analysisImpactCalibrationKey(kind, id string) string {
	return strings.ToLower(strings.TrimSpace(kind)) + ":" + strings.TrimSpace(id)
}

func analysisQueueRouteShape(item store.AnalysisQueueItem) string {
	method := strings.ToUpper(strings.TrimSpace(item.Method))
	host := strings.ToLower(strings.TrimSpace(item.Host))
	path := strings.TrimSpace(item.Path)
	if parsed, err := url.Parse(strings.TrimSpace(item.URL)); err == nil {
		if host == "" {
			host = strings.ToLower(parsed.Host)
		}
		if path == "" {
			path = parsed.EscapedPath()
		}
	}
	path = strings.TrimSuffix(path, "/")
	if path == "" {
		path = "/"
	}
	if method == "" || host == "" {
		return ""
	}
	return method + " " + host + " " + path
}

func queueIsCapturedRedirectAlias(item *store.AnalysisQueueItem, successfulRouteShapes map[string]string) bool {
	if item == nil || item.HasHypothesis || item.StatusCode < 300 || item.StatusCode >= 400 {
		return false
	}
	key := analysisQueueRouteShape(*item)
	landingPath, ok := successfulRouteShapes[key]
	if !ok {
		return false
	}
	return strings.TrimSpace(item.Path) != strings.TrimSpace(landingPath)
}

// SelectAnalysisLearningBatch reserves at most one of the eight checkpoint
// slots for the oldest eligible family outside the normal top batch. Static or
// protection noise never enters the lane, and explicit hypotheses already in
// the top batch are never displaced.
func SelectAnalysisLearningBatch(ranked []store.AnalysisQueueItem, batchSize int) []store.AnalysisQueueItem {
	if batchSize <= 0 || len(ranked) == 0 {
		return nil
	}
	if batchSize > len(ranked) {
		batchSize = len(ranked)
	}
	batch := append([]store.AnalysisQueueItem(nil), ranked[:batchSize]...)
	if batchSize < 2 || len(ranked) <= batchSize {
		return batch
	}

	fairIndex := -1
	for index := batchSize; index < len(ranked); index++ {
		candidate := ranked[index]
		if candidate.Disposition == "skip" || candidate.QueueAge < 1 {
			continue
		}
		if fairIndex < 0 || analysisFairnessCandidateBefore(candidate, ranked[fairIndex]) {
			fairIndex = index
		}
	}
	if fairIndex < 0 {
		return batch
	}

	replaceIndex := -1
	for index := len(batch) - 1; index >= 0; index-- {
		if batch[index].HasHypothesis || batch[index].QueueAge >= ranked[fairIndex].QueueAge {
			continue
		}
		replaceIndex = index
		break
	}
	if replaceIndex < 0 {
		return batch
	}
	fair := ranked[fairIndex]
	fair.FairnessLane = true
	fair.Reasons = appendQueueReason(fair.Reasons, "reserved fairness lane for deferred application evidence")
	batch[replaceIndex] = fair
	return batch
}

func analysisFairnessCandidateBefore(left, right store.AnalysisQueueItem) bool {
	if left.QueueAge != right.QueueAge {
		return left.QueueAge > right.QueueAge
	}
	if left.EvidenceID != right.EvidenceID {
		if left.EvidenceID == 0 {
			return false
		}
		if right.EvidenceID == 0 {
			return true
		}
		return left.EvidenceID < right.EvidenceID
	}
	if left.PriorityScore != right.PriorityScore {
		return left.PriorityScore > right.PriorityScore
	}
	return left.EndpointHash < right.EndpointHash
}

func AnalysisQueueFocusIDs(recon extract.ReconModel) []string {
	focus := make([]string, 0, len(recon.Targets))
	for _, target := range recon.Targets {
		if !target.Met && strings.TrimSpace(target.ID) != "" {
			focus = append(focus, strings.TrimSpace(target.ID))
		}
	}
	sort.Strings(focus)
	return focus
}

func AnalysisGapStateSnapshot(recon extract.ReconModel) []store.AnalysisGapState {
	states := make([]store.AnalysisGapState, 0, len(recon.Targets)+len(recon.Unknowns))
	for _, target := range recon.Targets {
		if strings.TrimSpace(target.ID) == "" {
			continue
		}
		states = append(states, store.AnalysisGapState{
			Kind: "target", ID: target.ID, Label: analysisGapLabel(target.Label, target.ID),
			Value: target.Actual, Met: target.Met, Present: true,
		})
	}
	for _, unknown := range recon.Unknowns {
		if strings.TrimSpace(unknown.ID) == "" {
			continue
		}
		states = append(states, store.AnalysisGapState{
			Kind: "unknown", ID: unknown.ID, Label: analysisGapLabel(unknown.Question, unknown.ID), Present: true,
		})
	}
	sort.Slice(states, func(i, j int) bool {
		if states[i].Kind != states[j].Kind {
			return states[i].Kind < states[j].Kind
		}
		return states[i].ID < states[j].ID
	})
	return states
}

func AnalysisReconFingerprint(recon extract.ReconModel) string {
	raw, err := json.Marshal(recon)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return fmt.Sprintf("%x", sum[:6])
}

func analysisTargetImpact(targetID string, item *store.AnalysisQueueItem, family, text string, objectTerms []string) (bool, int, string) {
	if item == nil {
		return false, 0, ""
	}
	switch targetID {
	case "application_identity", "app_identity":
		matched := strings.HasPrefix(strings.ToLower(item.ContentType), "text/html") && strings.EqualFold(item.Method, "GET")
		return matched, 18, "open application-identity gap"
	case "critical_purpose_coverage":
		matched := targetmodel.SurfaceValue(family) >= 11 || item.HasInput || item.IsAPI
		return matched, 12, "under-modeled critical purpose"
	case "actor_model":
		matched := family == "authentication" || family == "account" || family == "administration" ||
			((item.StatusCode == 401 || item.StatusCode == 403) && item.HasAuth)
		return matched, 30, "open actor/auth model"
	case "workflow_grounding":
		matched := family == "transaction" || family == "review" || family == "collection" ||
			family == "search" || isQueueMutation(item.Method) ||
			(item.HasInput && family != "authentication" && family != "account" && family != "administration")
		return matched, 28, "open workflow grounding"
	case "ownership_boundaries":
		matched := queueLooksExplicitOwnershipBearing(text, item) ||
			((family == "community" || family == "transaction") && (item.HasParams || item.IsAPI) && !queueLooksAuthLifecycle(text))
		return matched, 26, "open ownership boundary"
	case "business_object_coverage":
		matched := (queueContainsTerm(text, objectTerms) && !queueLooksAuthLifecycle(text)) ||
			queueLooksBusinessObjectBearing(text) || queueLooksExplicitOwnershipBearing(text, item)
		return matched, 18, "candidate can ground a business object"
	case "claim_confidence":
		matched := item.HasInput || item.HasErrors || item.HasAuth || item.IsAPI
		return matched, 10, "direct evidence can replace inference"
	default:
		return false, 0, ""
	}
}

func analysisGapLabel(label, id string) string {
	if label = strings.TrimSpace(label); label != "" {
		return label
	}
	return strings.ReplaceAll(strings.TrimSpace(id), "_", " ")
}

func reconObjectTerms(objects []extract.BusinessObject) []string {
	terms := make([]string, 0, len(objects)*2)
	for _, object := range objects {
		terms = append(terms, queueTokens(object.ID+" "+object.Name)...)
		for _, identifier := range object.Identifiers {
			terms = append(terms, queueTokens(identifier)...)
		}
	}
	return uniqueQueueTerms(terms)
}

func reconUnknownGapTerms(unknown extract.ReconUnknown) []string {
	return uniqueQueueTerms(queueTokens(unknown.Question + " " + unknown.SuggestedAction))
}

func queueTokens(text string) []string {
	return strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

func uniqueQueueTerms(terms []string) []string {
	ignored := map[string]bool{
		"this": true, "that": true, "with": true, "from": true, "page": true, "pages": true,
		"route": true, "routes": true, "observed": true, "evidence": true, "application": true,
		"target": true, "user": true, "users": true, "which": true, "what": true, "where": true,
		"when": true, "does": true, "whether": true, "current": true, "exact": true, "inspect": true,
		"capture": true, "captured": true, "request": true, "requests": true, "response": true,
		"responses": true, "endpoint": true, "endpoints": true, "server": true, "client": true,
		"behavior": true, "properly": true, "direct": true, "ground": true, "model": true,
		"safe": true, "action": true, "unknown": true, "form": true, "forms": true,
	}
	seen := make(map[string]bool)
	out := make([]string, 0, len(terms))
	for _, term := range terms {
		if len(term) < 4 || ignored[term] || seen[term] {
			continue
		}
		seen[term] = true
		out = append(out, term)
	}
	return out
}

func queueTermHits(text string, terms []string) int {
	hits := 0
	for _, term := range terms {
		if strings.Contains(text, term) {
			hits++
		}
	}
	return hits
}

func queueContainsTerm(text string, terms []string) bool { return queueTermHits(text, terms) > 0 }

func queueLooksExplicitOwnershipBearing(text string, item *store.AnalysisQueueItem) bool {
	if queueLooksAuthLifecycle(text) {
		return false
	}
	if containsAnyRecon(text, "/id/", "_id", "uuid", "tenant", "customer", "owner", "order") {
		return true
	}
	return containsAnyRecon(text, "account", "profile", "member") &&
		((item != nil && (item.HasParams || item.IsAPI)) || queueHasIdentifierToken(text))
}

func queueHasIdentifierToken(text string) bool {
	for _, token := range queueTokens(text) {
		if len(token) < 2 {
			continue
		}
		digits := true
		for _, r := range token {
			if r < '0' || r > '9' {
				digits = false
				break
			}
		}
		if digits {
			return true
		}
	}
	return false
}

func queueLooksAuthLifecycle(text string) bool {
	return containsAnyRecon(text, "login", "logout", "signin", "signout", "register", "signup", "oauth", "sso", "giris", "kaydol")
}

func queueLooksBusinessObjectBearing(text string) bool {
	if queueLooksAuthLifecycle(text) {
		return false
	}
	for _, token := range queueTokens(text) {
		switch token {
		case "account", "accounts", "profile", "profiles", "order", "orders", "product", "products",
			"item", "items", "cart", "carts", "store", "stores", "review", "reviews", "list", "lists",
			"invoice", "invoices", "subscription", "subscriptions", "ticket", "tickets":
			return true
		}
	}
	return false
}

func queueLooksLikeBrowserArtifact(item *store.AnalysisQueueItem) bool {
	if item == nil {
		return false
	}
	if item.HasHypothesis {
		return false
	}
	path := strings.ToLower(strings.TrimSpace(item.Path))
	if path == "" {
		path = strings.ToLower(strings.TrimSpace(item.URL))
	}
	if item.StatusCode < 500 && (item.IsInterstitial || containsAnyRecon(path,
		"/cdn-cgi/challenge-platform/", "/.well-known/captcha/", "/static/", "/_static/", "/assets/", "/fonts/",
		"/__manifest", "/__pb/", "opensearch.xml", "favicon.ico", "browserconfig.xml")) {
		return true
	}
	contentType := strings.ToLower(strings.TrimSpace(item.ContentType))
	if item.StatusCode < 500 && containsAnyRecon(contentType,
		"text/css", "javascript", "image/", "font/", "audio/", "video/") {
		return true
	}
	trimmed := strings.TrimSuffix(path, "/")
	if item.StatusCode >= 300 && item.StatusCode < 400 && strings.HasSuffix(trimmed, "/avatar") {
		return true
	}
	if strings.HasSuffix(trimmed, "/fp") && queueUUIDSegmentCount(trimmed) >= 2 {
		return true
	}
	for _, suffix := range []string{".css", ".js", ".mjs", ".map", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".woff", ".woff2", ".ttf", ".eot"} {
		if item.StatusCode < 500 && strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}

func queueUUIDSegmentCount(path string) int {
	count := 0
	for _, segment := range strings.Split(strings.Trim(path, "/"), "/") {
		if len(segment) != 36 || strings.Count(segment, "-") != 4 {
			continue
		}
		hexish := true
		for _, r := range strings.ReplaceAll(strings.ToLower(segment), "-", "") {
			if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
				hexish = false
				break
			}
		}
		if hexish {
			count++
		}
	}
	return count
}

func isQueueMutation(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

func appendQueueReason(reasons []string, reason string) []string {
	for _, existing := range reasons {
		if existing == reason {
			return reasons
		}
	}
	return append(reasons, reason)
}

func minQueueInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}
