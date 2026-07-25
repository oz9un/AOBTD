package agent

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ozzyw/aobtd/internal/store"
)

func TestStrategistPlanOnlyConfiguration(t *testing.T) {
	agent := NewStrategistAgent(nil, 1, &routingTestProvider{model: "planner"}, nil,
		StrategistConfig{Period: time.Minute, PlanOnly: true},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !agent.planOnly {
		t.Fatal("plan-only strategist configuration was not retained")
	}
}

func TestStrategistWorldRevisionIgnoresSelfChangingCycleFields(t *testing.T) {
	base := &strategistWorldModel{
		Duration:            "1m",
		NarrationCount:      10,
		PreviousSummary:     "first plan",
		EndpointCount:       12,
		ProfileCount:        3,
		DirectivesCompleted: 1,
		Hosts:               []wmHost{{Host: "target.test", Endpoints: 12}},
		RecentThoughts:      []wmNarrationCard{{Agent: "explorer", Action: "result", Message: "no IDOR"}},
	}
	changedOnlyByStrategist := *base
	changedOnlyByStrategist.Duration = "4m"
	changedOnlyByStrategist.NarrationCount = 18
	changedOnlyByStrategist.PreviousSummary = "second plan"
	changedOnlyByStrategist.ActiveHypotheses = []wmHypothesisCard{{}}

	if got, want := strategistWorldRevision(&changedOnlyByStrategist), strategistWorldRevision(base); got != want {
		t.Fatalf("revision changed for Strategist-only fields: got %s want %s", got, want)
	}
}

func TestStrategistWorldRevisionChangesWithExternalEvidence(t *testing.T) {
	base := &strategistWorldModel{EndpointCount: 12, ProfileCount: 3, DirectivesCompleted: 1}
	changed := *base
	changed.DirectivesCompleted++

	if got, want := strategistWorldRevision(&changed), strategistWorldRevision(base); got == want {
		t.Fatalf("revision did not change when completed evidence changed: %s", got)
	}
}

func TestStrategistWorldRevisionChangesWithRejectedPlannerAttempt(t *testing.T) {
	base := &strategistWorldModel{EndpointCount: 12, ProfileCount: 3}
	changed := *base
	changed.RejectedDirectives = []wmRejectedDirectiveCard{{
		Message: `Skipped probe_logic on /rest/web3/submitKey for field "key": body/form mutation is incompatible with observed GET request shape.`,
		URL:     "https://example.test/rest/web3/submitKey",
	}}

	if got, want := strategistWorldRevision(&changed), strategistWorldRevision(base); got == want {
		t.Fatalf("revision did not change when planner guardrail changed: %s", got)
	}
}

func TestBuildStrategistPromptIncludesRejectedPlannerAttempts(t *testing.T) {
	prompt := buildStrategistPrompt(&strategistWorldModel{
		ScanID:        1,
		Target:        "https://example.test",
		Status:        "running",
		EndpointCount: 12,
		RejectedDirectives: []wmRejectedDirectiveCard{{
			Message: `Skipped probe_logic on /rest/web3/submitKey for field "key": body/form mutation is incompatible with observed GET request shape.`,
			URL:     "https://example.test/rest/web3/submitKey",
		}},
	})

	for _, want := range []string{
		"Recently rejected planner attempts",
		"Skipped probe_logic on /rest/web3/submitKey",
		"do not send another equivalent body/form mutation",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("prompt missing %q:\n%s", want, prompt)
		}
	}
}

func TestNormalizeStrategistDirectiveUsesCompatiblePrimitive(t *testing.T) {
	queryLogic := strategistDirective{
		Action:       "probe_logic",
		URL:          "https://example.test/whoami?fields=id,email",
		Field:        "fields",
		Values:       []string{"id", "password"},
		GroundedIn:   []string{"endpoint:GET /whoami"},
		HypothesisID: "h1",
	}
	normalized, ok := normalizeStrategistDirective(queryLogic)
	if !ok || normalized.Action != "probe_param" {
		t.Fatalf("query directive = (%+v, %v), want probe_param", normalized, ok)
	}

	readOnlyFieldProbe := strategistDirective{
		Action:     "probe_logic",
		URL:        "https://example.test/feedback",
		Field:      "UserId",
		Values:     []string{"1", "2"},
		GroundedIn: []string{"endpoint:GET /feedback"},
	}
	normalized, ok = normalizeStrategistDirective(readOnlyFieldProbe)
	if !ok || normalized.Action != "probe_param" {
		t.Fatalf("GET field directive = (%+v, %v), want probe_param", normalized, ok)
	}

	readOnlyMissingField := strategistDirective{
		Action:     "probe_logic",
		URL:        "https://example.test/feedback",
		GroundedIn: []string{"endpoint:GET /feedback"},
	}
	if _, ok := normalizeStrategistDirective(readOnlyMissingField); ok {
		t.Fatal("GET body mutation without a field was accepted")
	}

	postMutation := strategistDirective{
		Action:     "probe_logic",
		URL:        "https://example.test/orders",
		Field:      "price",
		GroundedIn: []string{"endpoint:POST /orders"},
	}
	normalized, ok = normalizeStrategistDirective(postMutation)
	if !ok || normalized.Action != "probe_logic" {
		t.Fatalf("POST body directive = (%+v, %v), want probe_logic", normalized, ok)
	}
}

func TestNormalizeStrategistDirectiveRejectsPluralIDFilterAsIDOR(t *testing.T) {
	directive := strategistDirective{
		Action:      "probe_idor",
		URLTemplate: "https://example.test/catalog?ids={id}&lang=en",
		Values:      []string{"1", "2"},
		GroundedIn:  []string{"endpoint:GET /catalog"},
	}
	if _, ok := normalizeStrategistDirective(directive); ok {
		t.Fatal("plural ids filter was accepted as an owned-resource IDOR probe")
	}
	message := rejectedStrategistDirectiveMessage(directive)
	if !strings.Contains(message, "plural/list filter") {
		t.Fatalf("rejection message = %q", message)
	}

	directive.URLTemplate = "https://example.test/accounts/{id}"
	if _, ok := normalizeStrategistDirective(directive); !ok {
		t.Fatal("scalar resource path was rejected")
	}
}

func TestNormalizeStrategistDirectiveRejectsPublicMetaIDORTarget(t *testing.T) {
	directive := strategistDirective{
		Action:      "probe_idor",
		URLTemplate: "https://example.test/rest/admin/application-configuration/{id}",
		Values:      []string{"1", "2"},
		GroundedIn:  []string{"endpoint:GET /rest/admin/application-configuration"},
	}
	if _, ok := normalizeStrategistDirective(directive); ok {
		t.Fatal("application configuration endpoint was accepted as an owned-object IDOR target")
	}
	message := rejectedStrategistDirectiveMessage(directive)
	if !strings.Contains(message, "public metadata/configuration") {
		t.Fatalf("rejection message = %q", message)
	}
}

func TestNormalizeStrategistDirectiveRejectsStaticAssetMutation(t *testing.T) {
	directive := strategistDirective{
		Action:     "probe_param",
		URL:        "https://example.test/assets/public/images/uploads/test.php",
		Field:      "id",
		Values:     []string{"../../etc/passwd", "shell.php"},
		GroundedIn: []string{"endpoint:GET /assets/public/images/uploads/cat.png"},
	}
	if _, ok := normalizeStrategistDirective(directive); ok {
		t.Fatal("public/static asset mutation directive was accepted")
	}
	message := rejectedStrategistDirectiveMessage(directive)
	if !strings.Contains(message, "public/static asset") {
		t.Fatalf("rejection message = %q", message)
	}
}

func TestNormalizeStrategistDirectiveRejectsTokenBusinessLogicMutation(t *testing.T) {
	directive := strategistDirective{
		Action:     "probe_logic",
		URL:        "https://example.test/login.php",
		Field:      "user_token",
		Values:     []string{"abc", "def"},
		GroundedIn: []string{"endpoint:POST /login.php"},
	}
	if _, ok := normalizeStrategistDirective(directive); ok {
		t.Fatal("token/anti-forgery field was accepted as a business-logic mutation")
	}
	message := rejectedStrategistDirectiveMessage(directive)
	if !strings.Contains(message, "token/anti-forgery") {
		t.Fatalf("rejection message = %q", message)
	}
}

func TestNormalizeStrategistDirectiveRejectsSentinelIDORValues(t *testing.T) {
	directive := strategistDirective{
		Action:      "probe_idor",
		URLTemplate: "https://example.test/baskets/{id}",
		Values:      []string{"NaN", "undefined", "[object Object]"},
		GroundedIn:  []string{"endpoint:GET /baskets/{id}"},
	}
	if _, ok := normalizeStrategistDirective(directive); ok {
		t.Fatal("sentinel-only IDOR values were accepted")
	}

	directive.Values = []string{"NaN", "7", "8", "7"}
	normalized, ok := normalizeStrategistDirective(directive)
	if !ok {
		t.Fatal("valid scalar values were rejected")
	}
	if got, want := strings.Join(normalized.Values, ","), "7,8"; got != want {
		t.Fatalf("normalized values = %q, want %q", got, want)
	}
}

func TestGroundedHypothesisConfidenceRequiresConfirmedFinding(t *testing.T) {
	if got := groundedHypothesisConfidence(0.97, false); got != 0.85 {
		t.Fatalf("unsupported confidence = %.2f", got)
	}
	if got := groundedHypothesisConfidence(0.97, true); got != 0.97 {
		t.Fatalf("confirmed confidence = %.2f", got)
	}
}

func TestValidateStrategistGroundingRejectsInventedReferences(t *testing.T) {
	wm := &strategistWorldModel{
		Hosts: []wmHost{{Host: "app.example.test", Endpoints: 2}},
		InterestingEndpoints: []wmEndpointCard{{
			ID: "ep-orders", Method: "GET", Path: "/api/orders/{id}",
		}},
		Findings:       []wmFindingCard{{ID: 42}},
		RecentThoughts: []wmNarrationCard{{Agent: "analyzer", Action: "thought"}},
	}
	out := &strategistOutput{
		Hypotheses: []strategistHypothesis{
			{ID: "grounded", Statement: "Order ownership may be weak", Confidence: .7, SupportingEvidence: []string{"endpoint:GET /api/orders/{id}", "endpoint:invented"}},
			{ID: "invented", Statement: "An admin panel exists", Confidence: .8, SupportingEvidence: []string{"endpoint:GET /admin"}},
		},
		Directives: []strategistDirective{
			{Action: "fetch", URL: "https://app.example.test/api/orders/1", HypothesisID: "grounded", GroundedIn: []string{"host:app.example.test", "host:evil.test"}},
			{Action: "fetch", URL: "https://app.example.test/admin", HypothesisID: "invented", GroundedIn: []string{"endpoint:GET /admin"}},
			{Action: "fetch", URL: "https://app.example.test/other", HypothesisID: "missing", GroundedIn: []string{"host:app.example.test"}},
		},
	}

	rejections := validateStrategistGrounding(out, wm)
	if len(rejections) != 3 {
		t.Fatalf("rejections = %v, want 3", rejections)
	}
	if len(out.Hypotheses) != 1 || out.Hypotheses[0].ID != "grounded" {
		t.Fatalf("hypotheses after grounding = %+v", out.Hypotheses)
	}
	if got := out.Hypotheses[0].SupportingEvidence; len(got) != 1 || got[0] != "endpoint:GET /api/orders/{id}" {
		t.Fatalf("validated hypothesis evidence = %v", got)
	}
	if len(out.Directives) != 1 || out.Directives[0].HypothesisID != "grounded" {
		t.Fatalf("directives after grounding = %+v", out.Directives)
	}
	if got := out.Directives[0].GroundedIn; len(got) != 1 || got[0] != "host:app.example.test" {
		t.Fatalf("validated directive evidence = %v", got)
	}
}

func TestValidateStrategistGroundingKeepsExistingHypothesisEvidence(t *testing.T) {
	wm := &strategistWorldModel{ActiveHypotheses: []wmHypothesisCard{{Hypothesis: store.Hypothesis{
		ID: "h-existing", SupportingEvidence: []string{"endpoint:historical-profile"},
	}}}}
	out := &strategistOutput{
		Hypotheses: []strategistHypothesis{{
			ID: "h-existing", Statement: "Existing belief revised", Confidence: .5,
			SupportingEvidence: []string{"endpoint:historical-profile"},
		}},
		Directives: []strategistDirective{{
			Action: "reanalyze", EndpointID: "historical-profile", HypothesisID: "h-existing",
			GroundedIn: []string{"endpoint:historical-profile"},
		}},
	}
	if rejected := validateStrategistGrounding(out, wm); len(rejected) != 0 {
		t.Fatalf("existing grounded belief rejected: %v", rejected)
	}
}
