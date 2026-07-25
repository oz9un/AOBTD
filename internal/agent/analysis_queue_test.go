package agent

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/internal/store"
)

func TestRankAnalysisQueueLearnsFromActorGap(t *testing.T) {
	items := []store.AnalysisQueueItem{
		{EndpointHash: "reviews", Method: "GET", URL: "https://app.test/reviews", Path: "/reviews", BaseScore: 70, PriorityScore: 70, Reasons: []string{"capture relevance"}},
		{EndpointHash: "login", Method: "GET", URL: "https://app.test/login", Path: "/login", BaseScore: 55, PriorityScore: 55, Reasons: []string{"input-bearing page"}},
	}
	recon := extract.ReconModel{Targets: []extract.ReconTarget{{ID: "actor_model", Met: false}}}
	ranked := RankAnalysisQueue(items, recon)
	if ranked[0].EndpointHash != "login" {
		t.Fatalf("ranked queue = %+v, want auth surface first", ranked)
	}
	if ranked[0].LearnedBoost < 30 || !analysisQueueContains(ranked[0].LearnedReasons, "open actor/auth model") {
		t.Fatalf("login learning signal = %+v", ranked[0])
	}
	if len(items[1].LearnedReasons) != 0 || len(items[1].Reasons) != 1 {
		t.Fatalf("ranking mutated caller-owned queue: %+v", items[1])
	}
}

func TestRankAnalysisQueueReshapesForWorkflowAndOwnership(t *testing.T) {
	items := []store.AnalysisQueueItem{
		{EndpointHash: "news", Method: "GET", URL: "https://app.test/news", Path: "/news", BaseScore: 80, PriorityScore: 80},
		{EndpointHash: "order", Method: "POST", URL: "https://app.test/orders/123", Path: "/orders/123", BaseScore: 45, PriorityScore: 45, HasInput: true},
	}
	recon := extract.ReconModel{Targets: []extract.ReconTarget{
		{ID: "workflow_grounding", Met: false},
		{ID: "ownership_boundaries", Met: false},
	}}
	ranked := RankAnalysisQueue(items, recon)
	if ranked[0].EndpointHash != "order" {
		t.Fatalf("ranked queue = %+v, want identifier-bearing mutation first", ranked)
	}
	for _, reason := range []string{"open workflow grounding", "open ownership boundary"} {
		if !analysisQueueContains(ranked[0].LearnedReasons, reason) {
			t.Fatalf("order item missing %q: %+v", reason, ranked[0])
		}
	}
}

func TestRankAnalysisQueueMapsBoundedEvidenceImpactToExactOpenGaps(t *testing.T) {
	items := []store.AnalysisQueueItem{
		{EndpointHash: "news", Method: "GET", URL: "https://app.test/news", Path: "/news", BaseScore: 100, PriorityScore: 100},
		{
			EndpointHash: "order", Method: "POST", URL: "https://app.test/accounts/42/orders/99", Path: "/accounts/42/orders/99",
			BaseScore: 40, PriorityScore: 40, HasInput: true, HasParams: true, IsAPI: true,
		},
	}
	recon := extract.ReconModel{
		Targets: []extract.ReconTarget{
			{ID: "workflow_grounding", Label: "Grounded workflow coverage", Priority: 9, Met: false},
			{ID: "ownership_boundaries", Label: "Ownership boundary coverage", Priority: 8, Met: false},
			{ID: "business_object_coverage", Label: "Business object coverage", Priority: 8, Met: false},
			{ID: "claim_confidence", Label: "Evidence confidence", Priority: 7, Met: false},
			{ID: "actor_model", Label: "Actor model", Priority: 10, Met: true},
		},
		Unknowns: []extract.ReconUnknown{{
			ID: "order-owner", Priority: 9,
			Question: "Which account owns each order?", SuggestedAction: "Inspect the exact order route.",
		}},
		Objects: []extract.BusinessObject{{ID: "order", Name: "Order", Identifiers: []string{"order_id"}}},
	}
	ranked := RankAnalysisQueue(items, recon)
	if ranked[0].EndpointHash != "order" {
		t.Fatalf("evidence-impact ranking = %+v, want order first", ranked)
	}
	order := ranked[0]
	if order.EvidenceGain != maxAnalysisEvidenceGain {
		t.Fatalf("bounded evidence gain=%d, want %d: %+v", order.EvidenceGain, maxAnalysisEvidenceGain, order)
	}
	for _, id := range []string{"workflow_grounding", "ownership_boundaries", "business_object_coverage", "claim_confidence", "order-owner"} {
		if !analysisImpactContains(order.Impact, id) {
			t.Fatalf("impact map missing %q: %+v", id, order.Impact)
		}
	}
	if analysisImpactContains(order.Impact, "actor_model") {
		t.Fatalf("satisfied target entered predicted evidence impact: %+v", order.Impact)
	}
	if len(ranked[1].Impact) != 0 || ranked[1].EvidenceGain != 0 {
		t.Fatalf("unrelated news route received gap impact: %+v", ranked[1])
	}
}

func TestEvidenceImpactDoesNotConfusePrivacyAPIsOrAuthLifecycleWithOwnership(t *testing.T) {
	recon := extract.ReconModel{
		Targets: []extract.ReconTarget{
			{ID: "ownership_boundaries", Label: "Ownership", Priority: 9, Met: false},
			{ID: "business_object_coverage", Label: "Objects", Priority: 8, Met: false},
		},
		Objects: []extract.BusinessObject{{ID: "account", Name: "Account"}},
	}
	ranked := RankAnalysisQueue([]store.AnalysisQueueItem{
		{EndpointHash: "privacy", Method: "GET", URL: "https://accounts.test/privacy_compliance/context", Path: "/privacy_compliance/context", IsAPI: true, HasParams: true, BaseScore: 80},
		{EndpointHash: "logout", Method: "GET", URL: "https://app.test/account/logout", Path: "/account/logout", IsAPI: true, HasParams: true, BaseScore: 80},
		{EndpointHash: "account", Method: "GET", URL: "https://app.test/accounts/42", Path: "/accounts/42", BaseScore: 40},
	}, recon)
	byHash := make(map[string]store.AnalysisQueueItem, len(ranked))
	for _, item := range ranked {
		byHash[item.EndpointHash] = item
	}
	for _, endpointHash := range []string{"privacy", "logout"} {
		if analysisImpactContains(byHash[endpointHash].Impact, "ownership_boundaries") || analysisImpactContains(byHash[endpointHash].Impact, "business_object_coverage") {
			t.Fatalf("%s received unsupported ownership/object impact: %+v", endpointHash, byHash[endpointHash])
		}
	}
	for _, id := range []string{"ownership_boundaries", "business_object_coverage"} {
		if !analysisImpactContains(byHash["account"].Impact, id) {
			t.Fatalf("identifier-bearing account route missing %s: %+v", id, byHash["account"])
		}
	}
}

func TestRepeatedBatchOutcomesConservativelyCalibrateImpactScore(t *testing.T) {
	recon := extract.ReconModel{Targets: []extract.ReconTarget{{
		ID: "ownership_boundaries", Label: "Ownership", Priority: 9, Met: false,
	}}}
	item := store.AnalysisQueueItem{
		EndpointHash: "order", Method: "GET", URL: "https://app.test/orders/42", Path: "/orders/42", BaseScore: 30,
	}
	down := RankAnalysisQueueWithFeedback([]store.AnalysisQueueItem{item}, recon, nil, map[string]int{"target:ownership_boundaries": -12})[0]
	if down.EvidenceGain != 14 || len(down.Impact) != 1 || down.Impact[0].Calibration != -12 || down.Impact[0].Score != 14 {
		t.Fatalf("negative scan-local calibration = %+v", down)
	}
	up := RankAnalysisQueueWithFeedback([]store.AnalysisQueueItem{item}, recon, nil, map[string]int{"target:ownership_boundaries": 6})[0]
	if up.EvidenceGain != 32 || up.Impact[0].Calibration != 6 || up.Impact[0].Score != 32 {
		t.Fatalf("positive scan-local calibration = %+v", up)
	}
	if len(item.Impact) != 0 || item.EvidenceGain != 0 {
		t.Fatalf("feedback ranking mutated caller-owned candidate: %+v", item)
	}
}

func TestRankAnalysisQueuePenalizesBrowserMechanics(t *testing.T) {
	items := []store.AnalysisQueueItem{
		{EndpointHash: "challenge", Method: "GET", URL: "https://app.test/cdn-cgi/challenge-platform/help", Path: "/cdn-cgi/challenge-platform/help", BaseScore: 90, PriorityScore: 90, HasAuth: true},
		{EndpointHash: "catalog", Method: "GET", URL: "https://app.test/products", Path: "/products", BaseScore: 45, PriorityScore: 45},
	}
	recon := extract.ReconModel{Targets: []extract.ReconTarget{{ID: "actor_model", Met: false}, {ID: "critical_purpose_coverage", Met: false}}}
	ranked := RankAnalysisQueue(items, recon)
	if ranked[0].EndpointHash != "catalog" {
		t.Fatalf("ranked queue = %+v, want target application surface before browser mechanics", ranked)
	}
	var challenge store.AnalysisQueueItem
	for _, item := range ranked {
		if item.EndpointHash == "challenge" {
			challenge = item
		}
	}
	if challenge.LearnedBoost != -80 || !analysisQueueContains(challenge.LearnedReasons, "low-value browser or transport artifact") {
		t.Fatalf("challenge penalty = %+v", challenge)
	}
}

func TestRankAnalysisQueuePenalizesInterstitialOnApplicationRoute(t *testing.T) {
	items := []store.AnalysisQueueItem{{
		EndpointHash: "reviews", Method: "GET", URL: "https://app.test/reviews", Path: "/reviews",
		BaseScore: 90, PriorityScore: 90, HasAuth: true, HasErrors: true, IsInterstitial: true,
	}}
	ranked := RankAnalysisQueue(items, extract.ReconModel{Targets: []extract.ReconTarget{{ID: "claim_confidence", Met: false}}})
	if ranked[0].Disposition != "skip" || ranked[0].LearnedBoost != -80 {
		t.Fatalf("interstitial queue item = %+v", ranked[0])
	}
}

func TestRankAnalysisQueuePreservesProtectionServerFailure(t *testing.T) {
	items := []store.AnalysisQueueItem{{
		EndpointHash: "failure", Method: "GET", URL: "https://app.test/cdn-cgi/challenge-platform/x",
		Path: "/cdn-cgi/challenge-platform/x", StatusCode: 503, ContentType: "text/html",
		BaseScore: 90, PriorityScore: 90, HasErrors: true, IsInterstitial: true,
	}}
	ranked := RankAnalysisQueue(items, extract.ReconModel{})
	if ranked[0].Disposition == "skip" {
		t.Fatalf("protection server failure was suppressed in queue: %+v", ranked[0])
	}
}

func TestRankAnalysisQueueSuppressesExtensionlessAssetsAndMediaRedirects(t *testing.T) {
	items := []store.AnalysisQueueItem{
		{EndpointHash: "static", Method: "GET", Path: "/_static/", ContentType: "application/javascript", StatusCode: 200, BaseScore: 70},
		{EndpointHash: "avatar", Method: "GET", Path: "/api/organizations/acme/avatar", ContentType: "text/plain", StatusCode: 302, BaseScore: 70},
		{EndpointHash: "fingerprint", Method: "GET", Path: "/149e9513-01fa-4fb0-aad4-566afd725d1b/2d206a39-8ed7-437e-a3be-862e0f06eea3/fp", ContentType: "text/html", StatusCode: 429, BaseScore: 70},
		{EndpointHash: "hypothesis", Method: "GET", Path: "/_static/", ContentType: "application/javascript", StatusCode: 200, BaseScore: 70, HasHypothesis: true},
	}
	ranked := RankAnalysisQueue(items, extract.ReconModel{})
	disposition := make(map[string]string, len(ranked))
	for _, item := range ranked {
		disposition[item.EndpointHash] = item.Disposition
	}
	for _, id := range []string{"static", "avatar", "fingerprint"} {
		if disposition[id] != "skip" {
			t.Fatalf("%s disposition = %q, want skip", id, disposition[id])
		}
	}
	if disposition["hypothesis"] == "skip" {
		t.Fatal("explicit hypothesis was suppressed as passive browser noise")
	}
}

func TestAnalysisLearningBatchReservesOneFairnessLane(t *testing.T) {
	items := make([]store.AnalysisQueueItem, 0, 10)
	for index := 0; index < 10; index++ {
		items = append(items, store.AnalysisQueueItem{
			EndpointHash: string(rune('a' + index)), EvidenceID: int64(index + 10),
			Method: "GET", Path: "/surface", BaseScore: 200 - index*10,
			PriorityScore: 200 - index*10, Disposition: "analyze",
		})
	}
	items[0].HasHypothesis = true
	ages := map[string]int{items[9].EndpointHash: 2}
	ranked := RankAnalysisQueueWithAges(items, extract.ReconModel{}, ages)
	if ranked[9].AgingBoost != 8 || ranked[9].QueueAge != 2 {
		t.Fatalf("aging signal = %+v", ranked[9])
	}
	batch := SelectAnalysisLearningBatch(ranked, 8)
	if len(batch) != 8 {
		t.Fatalf("batch size = %d", len(batch))
	}
	var fairness *store.AnalysisQueueItem
	for index := range batch {
		if batch[index].FairnessLane {
			fairness = &batch[index]
		}
	}
	if fairness == nil || fairness.EndpointHash != items[9].EndpointHash {
		t.Fatalf("fairness batch = %+v, want oldest deferred endpoint", batch)
	}
	if batch[0].EndpointHash != items[0].EndpointHash {
		t.Fatal("fairness lane displaced the top explicit hypothesis")
	}
}

func TestAnalysisQueueArtifactNeverAgesIntoFairnessLane(t *testing.T) {
	items := []store.AnalysisQueueItem{
		{EndpointHash: "app", EvidenceID: 1, Method: "GET", Path: "/products", BaseScore: 70, Disposition: "analyze"},
		{EndpointHash: "static", EvidenceID: 2, Method: "GET", Path: "/static/app.js", ContentType: "application/javascript", BaseScore: 200, Disposition: "analyze"},
	}
	ranked := RankAnalysisQueueWithAges(items, extract.ReconModel{}, map[string]int{"static": 50})
	for _, item := range ranked {
		if item.EndpointHash == "static" && (item.Disposition != "skip" || item.QueueAge != 0 || item.AgingBoost != 0) {
			t.Fatalf("static artifact accumulated fairness = %+v", item)
		}
	}
}

func TestAnalysisLearningQueuePreventsStarvationUnderContinuousHighPriorityArrival(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "fairness.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scanID, err := db.CreateScan("https://app.test", `{}`)
	if err != nil {
		t.Fatal(err)
	}

	novel := store.AnalysisQueueItem{
		EndpointHash: "novel", EvidenceID: 1, Method: "GET", URL: "https://app.test/novel",
		Path: "/novel", BaseScore: 1, Disposition: "analyze",
	}
	queue := []store.AnalysisQueueItem{novel}
	for index := 0; index < 500; index++ {
		queue = append(queue, store.AnalysisQueueItem{
			EndpointHash: fmt.Sprintf("high-%03d", index), EvidenceID: int64(1000 + index),
			Method: "GET", URL: fmt.Sprintf("https://app.test/feed/%d", index),
			Path: fmt.Sprintf("/feed/%d", index), BaseScore: 200, Disposition: "analyze",
		})
	}

	firstRanked := RankAnalysisQueue(queue, extract.ReconModel{})
	firstBatch := SelectAnalysisLearningBatch(firstRanked, 8)
	if analysisQueueBatchContains(firstBatch, novel.EndpointHash) {
		t.Fatal("low-base route unexpectedly entered the first semantic batch")
	}
	if _, err := db.RecordAnalysisLearningCheckpoint(scanID, "model-1", nil, nil, firstRanked, firstBatch); err != nil {
		t.Fatal(err)
	}
	selected := make(map[string]bool, len(firstBatch))
	for _, item := range firstBatch {
		selected[item.EndpointHash] = true
	}
	remaining := make([]store.AnalysisQueueItem, 0, len(queue))
	for _, item := range queue {
		if !selected[item.EndpointHash] {
			remaining = append(remaining, item)
		}
	}
	for index := 0; index < 8; index++ {
		remaining = append(remaining, store.AnalysisQueueItem{
			EndpointHash: fmt.Sprintf("arrival-%d", index), EvidenceID: int64(2000 + index),
			Method: "GET", URL: fmt.Sprintf("https://app.test/hot/%d", index),
			Path: fmt.Sprintf("/hot/%d", index), BaseScore: 300, Disposition: "analyze",
		})
	}
	ages, err := db.GetAnalysisQueueAges(scanID)
	if err != nil {
		t.Fatal(err)
	}
	secondRanked := RankAnalysisQueueWithAges(remaining, extract.ReconModel{}, ages)
	secondBatch := SelectAnalysisLearningBatch(secondRanked, 8)
	var selectedNovel *store.AnalysisQueueItem
	for index := range secondBatch {
		if secondBatch[index].EndpointHash == novel.EndpointHash {
			selectedNovel = &secondBatch[index]
			break
		}
	}
	if selectedNovel == nil || !selectedNovel.FairnessLane || selectedNovel.QueueAge != 1 {
		t.Fatalf("novel route starved after a durable deferral: %+v", secondBatch)
	}
	if _, err := db.RecordAnalysisLearningCheckpoint(scanID, "model-2", nil, nil, secondRanked, secondBatch); err != nil {
		t.Fatal(err)
	}
	ages, err = db.GetAnalysisQueueAges(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if ages[novel.EndpointHash] != 0 {
		t.Fatalf("selected fairness route retained stale age: %#v", ages)
	}
}

func TestRankAnalysisQueueCollapsesOnlyCapturedTrailingSlashRedirectAlias(t *testing.T) {
	items := []store.AnalysisQueueItem{
		{EndpointHash: "redirect", Method: "GET", Host: "app.test", URL: "https://app.test/author/alice", Path: "/author/alice", StatusCode: 308, BaseScore: 80},
		{EndpointHash: "landing", Method: "GET", Host: "app.test", URL: "https://app.test/author/alice/", Path: "/author/alice/", StatusCode: 200, BaseScore: 70},
		{EndpointHash: "unmatched", Method: "GET", Host: "app.test", URL: "https://app.test/legacy", Path: "/legacy", StatusCode: 301, BaseScore: 60},
		{EndpointHash: "hypothesis", Method: "GET", Host: "app.test", URL: "https://app.test/member/bob", Path: "/member/bob", StatusCode: 308, BaseScore: 90, HasHypothesis: true},
		{EndpointHash: "hypothesis-landing", Method: "GET", Host: "app.test", URL: "https://app.test/member/bob/", Path: "/member/bob/", StatusCode: 200, BaseScore: 50},
	}
	ranked := RankAnalysisQueue(items, extract.ReconModel{})
	dispositions := make(map[string]string, len(ranked))
	for _, item := range ranked {
		dispositions[item.EndpointHash] = item.Disposition
	}
	if dispositions["redirect"] != "skip" {
		t.Fatalf("captured redirect alias remained analyzable: %+v", ranked)
	}
	if dispositions["landing"] == "skip" || dispositions["unmatched"] == "skip" || dispositions["hypothesis"] == "skip" {
		t.Fatalf("redirect collapse exceeded evidence boundary: %+v", ranked)
	}
}

func TestRankAnalysisQueueUsesDurableCanonicalRedirectEvidence(t *testing.T) {
	ranked := RankAnalysisQueue([]store.AnalysisQueueItem{{
		EndpointHash: "redirect-only-backlog", Method: "GET", Host: "app.test",
		URL: "https://app.test/download/catalog", Path: "/download/catalog",
		StatusCode: 301, BaseScore: 80, CanonicalRedirect: true,
	}}, extract.ReconModel{})
	if len(ranked) != 1 || ranked[0].Disposition != "skip" {
		t.Fatalf("durably observed canonical redirect remained a semantic move: %+v", ranked)
	}
}

func TestAnalysisReconFingerprintAndFocusAreDeterministic(t *testing.T) {
	recon := extract.ReconModel{Targets: []extract.ReconTarget{
		{ID: "workflow_grounding", Met: false},
		{ID: "application_identity", Met: false},
		{ID: "actor_model", Met: true},
	}}
	left := AnalysisReconFingerprint(recon)
	right := AnalysisReconFingerprint(recon)
	if left == "" || left != right {
		t.Fatalf("fingerprints = %q, %q", left, right)
	}
	focus := AnalysisQueueFocusIDs(recon)
	if len(focus) != 2 || focus[0] != "application_identity" || focus[1] != "workflow_grounding" {
		t.Fatalf("focus = %#v", focus)
	}
}

func analysisQueueContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func analysisQueueBatchContains(items []store.AnalysisQueueItem, endpointHash string) bool {
	for _, item := range items {
		if item.EndpointHash == endpointHash {
			return true
		}
	}
	return false
}

func analysisImpactContains(items []store.AnalysisGapImpact, id string) bool {
	for _, item := range items {
		if item.ID == id {
			return true
		}
	}
	return false
}
