package agent

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/pkg/types"
)

func TestAnalysisLearningBatchSizeHonorsRemainingEndpointLimit(t *testing.T) {
	tests := []struct {
		queue, processed, limit, want int
	}{
		{queue: 15, processed: 0, limit: 12, want: 8},
		{queue: 7, processed: 8, limit: 12, want: 4},
		{queue: 7, processed: 12, limit: 12, want: 0},
		{queue: 3, processed: 8, limit: 0, want: 3},
	}
	for _, tt := range tests {
		if got := analysisLearningBatchSize(tt.queue, tt.processed, tt.limit); got != tt.want {
			t.Fatalf("analysisLearningBatchSize(%d,%d,%d)=%d, want %d", tt.queue, tt.processed, tt.limit, got, tt.want)
		}
	}
}

func TestFrameworkSerializationNoiseIsNotPromotedToAnIssue(t *testing.T) {
	profile := &types.PageProfile{Issues: []string{
		"Debug state exposed in HTML comments: nested indices, array structure metadata, variable references, and a Stripe reference.",
		"HTML comment contains an actual API key secret value: sk-example-redacted.",
	}}
	sanitizeFrameworkSerializationIssues(profile)
	if len(profile.Issues) != 1 || profile.Issues[0] != "HTML comment contains an actual API key secret value: sk-example-redacted." {
		t.Fatalf("framework serialization calibration = %v", profile.Issues)
	}
	if !frameworkSerializationNoise("Internal state in HTML comments contains array indices and a Stripe reference") {
		t.Fatal("framework-only narration was not suppressed")
	}
}

func TestDeepAnalysisSkipReason(t *testing.T) {
	tests := []struct {
		name     string
		entry    types.TrafficEntry
		bundle   extract.EndpointBundle
		wantSkip bool
	}{
		{
			name:     "all not modified",
			entry:    types.TrafficEntry{Request: types.CapturedRequest{Path: "/api/data"}, Response: types.CapturedResponse{StatusCode: 304}},
			bundle:   extract.EndpointBundle{Method: "GET", IsAPI: true},
			wantSkip: true,
		},
		{
			name:     "ambient inputs on navigation 404 do not create an endpoint",
			entry:    types.TrafficEntry{Request: types.CapturedRequest{Path: "/account"}, Response: types.CapturedResponse{StatusCode: 404, ContentType: "text/html"}, SourceAgent: "navigator", SourceActionID: 7},
			bundle:   extract.EndpointBundle{Method: "GET", HasInput: true, HasAuth: true, HasErrors: true},
			wantSkip: true,
		},
		{
			name:     "hypothesis-driven 404 remains evidence",
			entry:    types.TrafficEntry{Request: types.CapturedRequest{Path: "/api/orders/999"}, Response: types.CapturedResponse{StatusCode: 404}, SourceAgent: "explorer", SourceActionID: 4, HypothesisID: "h-order"},
			bundle:   extract.EndpointBundle{Method: "GET", IsAPI: true, HasErrors: true},
			wantSkip: false,
		},
		{
			name:     "socket transport",
			entry:    types.TrafficEntry{Request: types.CapturedRequest{Path: "/socket.io/"}, Response: types.CapturedResponse{StatusCode: 200}},
			bundle:   extract.EndpointBundle{Method: "GET"},
			wantSkip: true,
		},
		{
			name:     "nested socket transport under spa route",
			entry:    types.TrafficEntry{Request: types.CapturedRequest{Path: "/admin/socket.io/"}, Response: types.CapturedResponse{StatusCode: 200}},
			bundle:   extract.EndpointBundle{Method: "GET", HasInput: true},
			wantSkip: true,
		},
		{
			name:     "invalid client side path identifier",
			entry:    types.TrafficEntry{Request: types.CapturedRequest{Path: "/rest/basket/NaN"}, Response: types.CapturedResponse{StatusCode: 200}},
			bundle:   extract.EndpointBundle{Method: "GET", IsAPI: true, HasAuth: true, URLPattern: "/rest/basket/NaN"},
			wantSkip: true,
		},
		{
			name:     "synthetic invalid api route",
			entry:    types.TrafficEntry{Request: types.CapturedRequest{Path: "/api/unknownpath"}, Response: types.CapturedResponse{StatusCode: 500}},
			bundle:   extract.EndpointBundle{Method: "GET", HasInput: true, HasErrors: true, URLPattern: "/api/unknownpath"},
			wantSkip: true,
		},
		{
			name:     "synthetic invalid api route with explicit hypothesis retained",
			entry:    types.TrafficEntry{Request: types.CapturedRequest{Path: "/api/unknownpath"}, Response: types.CapturedResponse{StatusCode: 500}, HypothesisID: "hyp-invalid-route"},
			bundle:   extract.EndpointBundle{Method: "GET", HasInput: true, HasErrors: true, URLPattern: "/api/unknownpath"},
			wantSkip: false,
		},
		{
			name:     "localization",
			entry:    types.TrafficEntry{Request: types.CapturedRequest{Path: "/assets/i18n/en.json"}, Response: types.CapturedResponse{StatusCode: 200}},
			bundle:   extract.EndpointBundle{Method: "GET", IsAPI: true},
			wantSkip: true,
		},
		{
			name:     "ambient auth on browser challenge mechanic",
			entry:    types.TrafficEntry{Request: types.CapturedRequest{Path: "/cdn-cgi/challenge-platform/help"}, Response: types.CapturedResponse{StatusCode: 200}},
			bundle:   extract.EndpointBundle{Method: "GET", HasAuth: true, HasInput: true},
			wantSkip: true,
		},
		{
			name:     "protection helper server failure remains evidence",
			entry:    types.TrafficEntry{Request: types.CapturedRequest{Path: "/cdn-cgi/challenge-platform/help"}, Response: types.CapturedResponse{StatusCode: 503, ContentType: "text/html"}},
			bundle:   extract.EndpointBundle{Method: "GET", HasErrors: true},
			wantSkip: false,
		},
		{
			name:     "application route returning cloudflare interstitial",
			entry:    types.TrafficEntry{Request: types.CapturedRequest{Path: "/reviews/popular"}, Response: types.CapturedResponse{StatusCode: 403, ContentType: "text/html", Body: []byte(`<title>Just a moment...</title><p>Enable JavaScript and cookies to continue</p>`)}},
			bundle:   extract.EndpointBundle{Method: "GET", HasAuth: true, HasErrors: true},
			wantSkip: true,
		},
		{
			name: "canonical slash redirect",
			entry: types.TrafficEntry{
				Request:  types.CapturedRequest{URL: "https://example.test/vulnerabilities/sqli", Path: "/vulnerabilities/sqli"},
				Response: types.CapturedResponse{StatusCode: 301, Headers: map[string]string{"Location": "https://example.test/vulnerabilities/sqli/"}},
			},
			bundle:   extract.EndpointBundle{Method: "GET"},
			wantSkip: true,
		},
		{
			name: "navigator canonical slash redirect remains transport only",
			entry: types.TrafficEntry{
				Request:        types.CapturedRequest{URL: "https://example.test/events", Path: "/events"},
				Response:       types.CapturedResponse{StatusCode: 301, Headers: map[string]string{"Location": "https://example.test/events/"}},
				SourceAgent:    "navigator",
				SourceActionID: 9,
			},
			bundle:   extract.EndpointBundle{Method: "GET"},
			wantSkip: true,
		},
		{
			name: "explicit default port canonical redirect remains transport only",
			entry: types.TrafficEntry{
				Request:  types.CapturedRequest{URL: "https://example.test:443/events", Path: "/events"},
				Response: types.CapturedResponse{StatusCode: 301, Headers: map[string]string{"Location": "https://example.test/events/"}},
			},
			bundle:   extract.EndpointBundle{Method: "GET"},
			wantSkip: true,
		},
		{
			name: "cross-origin redirect retained",
			entry: types.TrafficEntry{
				Request:  types.CapturedRequest{URL: "https://example.test/redirect", Path: "/redirect"},
				Response: types.CapturedResponse{StatusCode: 302, Headers: map[string]string{"Location": "https://evil.test/"}},
			},
			bundle:   extract.EndpointBundle{Method: "GET"},
			wantSkip: false,
		},
		{
			name: "admin-shaped route behind path-preserving auth gate remains unverified",
			entry: types.TrafficEntry{
				Request: types.CapturedRequest{URL: "https://partner.example.test/admin", Path: "/admin"},
				Response: types.CapturedResponse{StatusCode: 302, Headers: map[string]string{
					"Location": "/account/logout?redirect=%2Fadmin",
				}},
				SourceAgent: "navigator", SourceActionID: 19,
			},
			bundle:   extract.EndpointBundle{Method: "GET", URLPattern: "/admin", HasAuth: true},
			wantSkip: true,
		},
		{
			name: "explicit redirect hypothesis can inspect authentication gate mechanics",
			entry: types.TrafficEntry{
				Request: types.CapturedRequest{URL: "https://partner.example.test/admin", Path: "/admin"},
				Response: types.CapturedResponse{StatusCode: 302, Headers: map[string]string{
					"Location": "/account/logout?redirect=%2Fadmin",
				}},
				SourceAgent: "verifier", SourceActionID: 20, HypothesisID: "hyp-open-redirect",
			},
			bundle:   extract.EndpointBundle{Method: "GET", URLPattern: "/admin", HasAuth: true},
			wantSkip: false,
		},
		{
			name:     "static with security error retained",
			entry:    types.TrafficEntry{Request: types.CapturedRequest{Path: "/assets/app.js"}, Response: types.CapturedResponse{StatusCode: 500}},
			bundle:   extract.EndpointBundle{Method: "GET", HasErrors: true},
			wantSkip: false,
		},
		{
			name:     "missing static asset with misleading xml response skipped",
			entry:    types.TrafficEntry{Request: types.CapturedRequest{Path: "/static/token/theme.css"}, Response: types.CapturedResponse{StatusCode: 404, ContentType: "application/xml"}},
			bundle:   extract.EndpointBundle{Method: "GET", HasErrors: true},
			wantSkip: true,
		},
		{
			name:     "authenticated js asset still skipped",
			entry:    types.TrafficEntry{Request: types.CapturedRequest{Path: "/chunk-ABCD1234.js"}, Response: types.CapturedResponse{StatusCode: 200}},
			bundle:   extract.EndpointBundle{Method: "GET", HasAuth: true},
			wantSkip: true,
		},
		{
			name: "navigator wordpress plugin asset still skipped",
			entry: types.TrafficEntry{
				Request:     types.CapturedRequest{Path: "/wp-content/plugins/accessibility-checker-pro/build/frontendFixes.bundle.js"},
				Response:    types.CapturedResponse{StatusCode: 200, ContentType: "application/javascript"},
				SourceAgent: "navigator", SourceActionID: 400421,
			},
			bundle:   extract.EndpointBundle{Method: "GET"},
			wantSkip: true,
		},
		{
			name: "extensionless CMS asset combiner skipped by response type",
			entry: types.TrafficEntry{
				Request:     types.CapturedRequest{Path: "/_static/", Query: "??/wp-includes/js/jquery.js?m=1784313004j"},
				Response:    types.CapturedResponse{StatusCode: 200, ContentType: "application/javascript"},
				SourceAgent: "navigator", SourceActionID: 400422,
			},
			bundle:   extract.EndpointBundle{Method: "GET", HasInput: true},
			wantSkip: true,
		},
		{
			name:     "root readme docs still skipped",
			entry:    types.TrafficEntry{Request: types.CapturedRequest{Path: "/README.fr.md"}, Response: types.CapturedResponse{StatusCode: 200, ContentType: "text/markdown"}},
			bundle:   extract.EndpointBundle{Method: "GET"},
			wantSkip: true,
		},
		{
			name:     "authenticated uploaded image still skipped",
			entry:    types.TrafficEntry{Request: types.CapturedRequest{Path: "/assets/public/images/uploads/cat.webp"}, Response: types.CapturedResponse{StatusCode: 200}},
			bundle:   extract.EndpointBundle{Method: "GET", HasAuth: true},
			wantSkip: true,
		},
		{
			name:     "public artifact bypass variant from verifier still skipped",
			entry:    types.TrafficEntry{Request: types.CapturedRequest{Path: "/ftp/package.json.bak%2500.md"}, Response: types.CapturedResponse{StatusCode: 200, ContentType: "application/octet-stream"}, SourceAgent: "verifier"},
			bundle:   extract.EndpointBundle{Method: "GET"},
			wantSkip: true,
		},
		{
			name:     "api json endpoint is not treated as a passive artifact",
			entry:    types.TrafficEntry{Request: types.CapturedRequest{Path: "/api/reports/export.json"}, Response: types.CapturedResponse{StatusCode: 200, ContentType: "application/json"}},
			bundle:   extract.EndpointBundle{Method: "GET", IsAPI: true},
			wantSkip: false,
		},
		{
			name:     "scanner benchmark metadata skipped",
			entry:    types.TrafficEntry{Request: types.CapturedRequest{Path: "/VulnerableApp/scanner/benchmark"}, Response: types.CapturedResponse{StatusCode: 200, ContentType: "application/json"}, SourceAgent: "explorer", SourceActionID: 2},
			bundle:   extract.EndpointBundle{Method: "GET", IsAPI: true, URLPattern: "/VulnerableApp/scanner/benchmark"},
			wantSkip: true,
		},
		{
			name:     "endpoint index metadata skipped",
			entry:    types.TrafficEntry{Request: types.CapturedRequest{Path: "/VulnerableApp/allEndPointJson"}, Response: types.CapturedResponse{StatusCode: 200, ContentType: "application/json"}},
			bundle:   extract.EndpointBundle{Method: "GET", IsAPI: true, URLPattern: "/VulnerableApp/allEndPointJson"},
			wantSkip: true,
		},
		{
			name:     "metadata explicit hypothesis retained",
			entry:    types.TrafficEntry{Request: types.CapturedRequest{Path: "/VulnerableApp/scanner"}, Response: types.CapturedResponse{StatusCode: 200, ContentType: "application/json"}, HypothesisID: "hyp-index-leak"},
			bundle:   extract.EndpointBundle{Method: "GET", IsAPI: true, URLPattern: "/VulnerableApp/scanner"},
			wantSkip: false,
		},
		{
			name:     "static explicit hypothesis retained",
			entry:    types.TrafficEntry{Request: types.CapturedRequest{Path: "/assets/app.js"}, Response: types.CapturedResponse{StatusCode: 200}, HypothesisID: "hyp-js-secret"},
			bundle:   extract.EndpointBundle{Method: "GET", HasAuth: true},
			wantSkip: false,
		},
		{
			name:     "active evidence retained",
			entry:    types.TrafficEntry{Request: types.CapturedRequest{Path: "/api/account/1"}, Response: types.CapturedResponse{StatusCode: 200}, SourceAgent: "explorer", SourceActionID: 1},
			bundle:   extract.EndpointBundle{Method: "GET"},
			wantSkip: false,
		},
		{
			name:     "socket protocol inputs still skipped",
			entry:    types.TrafficEntry{Request: types.CapturedRequest{Path: "/socket.io/"}, Response: types.CapturedResponse{StatusCode: 200}, SourceAgent: "explorer", SourceActionID: 1},
			bundle:   extract.EndpointBundle{Method: "GET", HasInput: true},
			wantSkip: true,
		},
		{
			name:     "socket explicit hypothesis retained",
			entry:    types.TrafficEntry{Request: types.CapturedRequest{Path: "/socket.io/"}, Response: types.CapturedResponse{StatusCode: 200}, SourceAgent: "verifier", HypothesisID: "hyp-ws-auth"},
			bundle:   extract.EndpointBundle{Method: "GET", HasInput: true},
			wantSkip: false,
		},
		{
			name:     "ordinary api retained",
			entry:    types.TrafficEntry{Request: types.CapturedRequest{Path: "/api/BasketItems"}, Response: types.CapturedResponse{StatusCode: 200}},
			bundle:   extract.EndpointBundle{Method: "GET", IsAPI: true},
			wantSkip: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason := deepAnalysisSkipReason([]types.TrafficEntry{tt.entry}, &tt.bundle)
			if (reason != "") != tt.wantSkip {
				t.Fatalf("reason=%q, wantSkip=%v", reason, tt.wantSkip)
			}
		})
	}
}

func TestAnalyzerProfileEvidenceCeilingClearsEveryNonContentClaim(t *testing.T) {
	tests := []struct {
		name      string
		entries   []types.TrafficEntry
		wantState string
	}{
		{
			name: "redirect auth gate",
			entries: []types.TrafficEntry{{
				Request: types.CapturedRequest{Method: "GET", URL: "https://partner.example.test/admin", Path: "/admin"},
				Response: types.CapturedResponse{StatusCode: 302, Headers: map[string]string{
					"Location": "/account/logout?redirect=%2Fadmin",
				}},
			}},
			wantState: "auth_gate_unverified",
		},
		{
			name: "negative response",
			entries: []types.TrafficEntry{{
				Request:  types.CapturedRequest{Method: "GET", URL: "https://partner.example.test/admin", Path: "/admin"},
				Response: types.CapturedResponse{StatusCode: 404, ContentType: "text/html", Body: []byte(`<h1>Page not found</h1>`)},
			}},
			wantState: "response_unverified",
		},
		{
			name: "empty success",
			entries: []types.TrafficEntry{{
				Request:  types.CapturedRequest{Method: "GET", URL: "https://partner.example.test/admin", Path: "/admin"},
				Response: types.CapturedResponse{StatusCode: 200, ContentType: "text/html", Body: []byte("  \n")},
			}},
			wantState: "response_unverified",
		},
		{
			name: "authentication shell",
			entries: []types.TrafficEntry{{
				Request: types.CapturedRequest{Method: "GET", URL: "https://partner.example.test/admin", Path: "/admin"},
				Response: types.CapturedResponse{StatusCode: 200, ContentType: "text/html", Body: []byte(
					`<html><head><title>Login</title></head><body><h1>Sign in</h1><form><input type="password"></form></body></html>`),
				}}},
			wantState: "response_unverified",
		},
		{
			name: "error shell",
			entries: []types.TrafficEntry{{
				Request: types.CapturedRequest{Method: "GET", URL: "https://partner.example.test/admin", Path: "/admin"},
				Response: types.CapturedResponse{StatusCode: 200, ContentType: "text/html", Body: []byte(
					`<html><head><title>404 - Page not found</title></head><body><h1>Page not found</h1></body></html>`),
				}}},
			wantState: "response_unverified",
		},
		{
			name:      "no matching response",
			wantState: "response_unverified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := &types.PageProfile{
				ID: "GET /admin", Method: "GET", URL: "https://partner.example.test/admin",
				Purpose: "Administrative dashboard for partners", AuthRequired: "session_cookie", Confidence: 0.8,
				Inputs: []types.Input{{Name: "tenant_id"}}, ExtractedInputs: []types.Input{{Name: "upload"}},
				DataExposed: []string{"partner records"}, APIsCalled: []string{"/api/admin"},
				Relationships: []string{"partner owns records"}, Behaviors: []string{"approves partners"},
				Issues: []string{"Hypothesis — authorization bypass"}, TechNotes: "privileged React route",
				TemplateID: "admin-template", HasInput: true, HasFileUpload: true, HasAuth: true,
				HasErrors: true, IsAPI: true,
			}

			// analyzeEndpoint invokes this boundary immediately before UpsertProfile
			// and before iterating Issues to publish finding events.
			applyAnalyzerProfileEvidenceCeiling(profile, tt.entries)

			if profile.EvidenceState != tt.wantState || profile.AuthRequired != "unknown" || profile.Confidence != 0.35 {
				t.Fatalf("evidence verdict = %+v", profile)
			}
			if !strings.Contains(strings.ToLower(profile.Purpose), "unverified") {
				t.Fatalf("purpose escaped evidence ceiling: %q", profile.Purpose)
			}
			if len(profile.Inputs) != 0 || len(profile.ExtractedInputs) != 0 || len(profile.DataExposed) != 0 ||
				len(profile.APIsCalled) != 0 || len(profile.Relationships) != 0 || len(profile.Behaviors) != 0 ||
				len(profile.Issues) != 0 || profile.TechNotes != "" || profile.TemplateID != "" ||
				profile.HasInput || profile.HasFileUpload || profile.HasAuth || profile.HasErrors || profile.IsAPI {
				t.Fatalf("non-content claims could persist or emit: %+v", profile)
			}
		})
	}
}

func TestAnalyzerProfileEvidenceCeilingPreservesSubstantiveContent(t *testing.T) {
	profile := &types.PageProfile{
		ID: "GET /orders", Method: "GET", URL: "https://partner.example.test/orders",
		Purpose: "Partner order list", AuthRequired: "session_cookie", Confidence: 0.8,
		Inputs: []types.Input{{Name: "page"}}, Issues: []string{"Observed cache inconsistency"},
		TechNotes: "React order route", HasInput: true,
	}
	entries := []types.TrafficEntry{{
		Request: types.CapturedRequest{Method: "GET", URL: profile.URL, Path: "/orders"},
		Response: types.CapturedResponse{StatusCode: 200, ContentType: "text/html", Body: []byte(
			`<html><body><h1>Partner orders</h1><table><tr><td>Order 8172</td></tr></table></body></html>`)},
	}}

	applyAnalyzerProfileEvidenceCeiling(profile, entries)
	if profile.EvidenceState != "content_observed" || profile.Purpose != "Partner order list" ||
		len(profile.Inputs) != 1 || len(profile.Issues) != 1 || profile.TechNotes == "" || !profile.HasInput {
		t.Fatalf("substantive content was over-sanitized: %+v", profile)
	}
}

func TestProtectionAnalysisDispositionPreservesChangedAndRecoveredEvidence(t *testing.T) {
	challengeEntry := func(url string, status int, body string) types.TrafficEntry {
		return types.TrafficEntry{
			Request: types.CapturedRequest{Method: "GET", URL: url, Path: "/protected"},
			Response: types.CapturedResponse{
				StatusCode: status, ContentType: "text/html",
				Headers: map[string]string{"Server": "cloudflare", "CF-Ray": "volatile"},
				Body:    []byte(body),
			},
		}
	}
	cloudflare := challengeEntry("https://app.test/protected", 403,
		`<title>Just a moment...</title><script src="/cdn-cgi/challenge-platform/x"></script><p>Enable JavaScript and cookies to continue</p>`)
	analyzer := &AnalyzerAgent{}

	disposition, reason, handled := analyzer.protectionAnalysisDisposition([]types.TrafficEntry{cloudflare}, "first")
	if !handled || disposition != "closed" || !strings.Contains(reason, "protection specimen retained") {
		t.Fatalf("first protection shape = disposition %q reason %q handled=%v", disposition, reason, handled)
	}
	disposition, reason, handled = analyzer.protectionAnalysisDisposition([]types.TrafficEntry{cloudflare}, "duplicate")
	if !handled || disposition != "compacted" || !strings.Contains(reason, "already retained") {
		t.Fatalf("duplicate protection shape = disposition %q reason %q handled=%v", disposition, reason, handled)
	}

	changed := challengeEntry("https://app.test/verify", 403,
		`<title>Verify you are human</title><div class="cf-turnstile">Verify that you are human</div>`)
	disposition, _, handled = analyzer.protectionAnalysisDisposition([]types.TrafficEntry{changed}, "changed")
	if !handled || disposition != "closed" {
		t.Fatalf("changed protection shape was hidden: disposition=%q handled=%v", disposition, handled)
	}

	application := types.TrafficEntry{
		Request:  types.CapturedRequest{Method: "GET", URL: "https://app.test/protected", Path: "/protected"},
		Response: types.CapturedResponse{StatusCode: 200, ContentType: "text/html", Body: []byte(`<title>Member reviews</title><main>Application content</main>`)},
	}
	if disposition, reason, handled := analyzer.protectionAnalysisDisposition([]types.TrafficEntry{cloudflare, application}, "recovered"); handled {
		t.Fatalf("recovered application was compacted: disposition=%q reason=%q", disposition, reason)
	}
	serverFailure := cloudflare
	serverFailure.Response.StatusCode = 503
	if disposition, reason, handled := analyzer.protectionAnalysisDisposition([]types.TrafficEntry{serverFailure}, "failure"); handled {
		t.Fatalf("server failure was compacted: disposition=%q reason=%q", disposition, reason)
	}
	hypothesis := cloudflare
	hypothesis.HypothesisID = "h-protection-differential"
	if disposition, reason, handled := analyzer.protectionAnalysisDisposition([]types.TrafficEntry{hypothesis}, "hypothesis"); handled {
		t.Fatalf("explicit hypothesis was compacted: disposition=%q reason=%q", disposition, reason)
	}
	if trafficLooksLikeProtectionInterstitial([]types.TrafficEntry{cloudflare, application}) {
		t.Fatal("any-response interstitial logic still hides a recovered application")
	}
}

func TestSanitizePublicReferenceIssues(t *testing.T) {
	profile := &types.PageProfile{
		Purpose: "Provides geolocation and currency information for the current request",
		Issues: []string{
			"Hypothesis — sensitive geolocation data lacks ownership validation",
			"Observed malformed cache header",
		},
	}
	bundle := &extract.EndpointBundle{URLPattern: "/home.ipstack.json", SampleURL: "https://example.test/home.ipstack.json"}
	sanitizePublicReferenceIssues(profile, bundle)
	if len(profile.Issues) != 1 || profile.Issues[0] != "Observed malformed cache header" {
		t.Fatalf("issues = %#v", profile.Issues)
	}

	privateProfile := &types.PageProfile{Purpose: "Account location settings", Issues: []string{"Hypothesis — missing authorization"}}
	privateBundle := &extract.EndpointBundle{URLPattern: "/secure/account/location"}
	sanitizePublicReferenceIssues(privateProfile, privateBundle)
	if len(privateProfile.Issues) != 1 {
		t.Fatalf("private account issue was removed: %#v", privateProfile.Issues)
	}
}

func TestShouldSummarizeAppUsesMeaningfulDelta(t *testing.T) {
	analyzer := &AnalyzerAgent{understanding: extract.NewAppUnderstanding()}
	if !analyzer.shouldSummarizeApp(0) {
		t.Fatal("empty app understanding should be summarized")
	}

	analyzer.understanding.AppType = "api_service"
	analyzer.understanding.Summary = "GraphQL API"
	analyzer.understanding.Recon.Metrics.SynthesizedPageCount = 10
	if analyzer.shouldSummarizeApp(12) {
		t.Fatal("two new profiles should not trigger another app summary")
	}
	if !analyzer.shouldSummarizeApp(16) {
		t.Fatal("six new profiles should trigger a refreshed app summary")
	}

	analyzer.understanding.Recon.Metrics.SynthesizedPageCount = 35
	if analyzer.shouldSummarizeApp(42) {
		t.Fatal("large scans should require a larger summary delta")
	}
	if !analyzer.shouldSummarizeApp(45) {
		t.Fatal("large scans should refresh after ten new profiles")
	}
}

func TestShouldSummarizeAppRefreshesImmediatelyForCriticalUnderstandingTarget(t *testing.T) {
	analyzer := &AnalyzerAgent{understanding: extract.NewAppUnderstanding()}
	analyzer.understanding.AppType = "saas"
	analyzer.understanding.Summary = "A team workspace with account and project administration workflows."
	analyzer.understanding.Recon.Metrics.SynthesizedPageCount = 10
	analyzer.understanding.Recon.Targets = []extract.ReconTarget{{
		ID: "actor_model", Priority: 9, Met: false,
	}}

	if !analyzer.shouldSummarizeApp(11) {
		t.Fatal("one new profile should refresh a model with an unmet critical target")
	}
}

func TestMergeProfileGroundsModelIdentityToObservedBundle(t *testing.T) {
	analyzer := &AnalyzerAgent{}
	llmProfile := &types.PageProfile{
		ID:      "GET /openapi.",
		URL:     "http://127.0.0.1:5002/openapi.",
		Method:  "GET",
		Purpose: "OpenAPI spec",
	}
	bundle := &extract.EndpointBundle{
		Method:        "GET",
		URLPattern:    "/openapi.json",
		SampleURL:     "http://127.0.0.1:5002/openapi.json",
		HasInput:      true,
		HasFileUpload: true,
		HasAuth:       true,
		HasErrors:     true,
		IsAPI:         true,
	}

	got := analyzer.mergeProfile(llmProfile, bundle)
	if got.ID != "GET /openapi.json" {
		t.Fatalf("ID = %q, want observed bundle identity", got.ID)
	}
	if got.URL != "http://127.0.0.1:5002/openapi.json" {
		t.Fatalf("URL = %q, want observed sample URL", got.URL)
	}
	if got.Method != "GET" {
		t.Fatalf("Method = %q, want GET", got.Method)
	}
	if got.Purpose != "OpenAPI spec" {
		t.Fatalf("Purpose should still come from model, got %q", got.Purpose)
	}
	if !got.HasInput || !got.HasFileUpload || !got.HasAuth || !got.HasErrors || !got.IsAPI {
		t.Fatalf("observed flags were not carried from bundle: %+v", got)
	}
}

func TestAnalysisFingerprintCanonicalizesRepeatedIDProbes(t *testing.T) {
	firstEntries := []types.TrafficEntry{
		analysisFingerprintEntry(1, "http://127.0.0.1:3000/rest/memories/1", "/rest/memories/1", "", 500, "text/html", "h1", "explorer"),
	}
	firstBundle := extract.BuildEndpointBundle(firstEntries, 20)
	first := analysisFingerprint(firstEntries, firstBundle)
	if first == "" {
		t.Fatal("empty first fingerprint")
	}

	repeatedEntries := []types.TrafficEntry{
		analysisFingerprintEntry(2, "http://127.0.0.1:3000/rest/memories/-1", "/rest/memories/-1", "", 500, "text/html", "h2", "explorer"),
	}
	repeatedBundle := extract.BuildEndpointBundle(repeatedEntries, 20)
	repeated := analysisFingerprint(repeatedEntries, repeatedBundle)
	if repeated != first {
		t.Fatalf("repeated ID probe fingerprint changed\nfirst:    %s\nrepeated: %s", first, repeated)
	}

	analyzer := &AnalyzerAgent{analysisFingerprints: map[string]string{first: "h1"}}
	if reason := analyzer.repeatedAnalysisSkipReason(repeatedEntries, repeatedBundle, "h2"); reason == "" {
		t.Fatal("expected repeated analysis skip reason")
	}
}

func TestAnalysisFingerprintCanonicalizesLessonLevelSiblings(t *testing.T) {
	firstEntries := []types.TrafficEntry{
		analysisFingerprintEntry(1,
			"http://127.0.0.1:9091/VulnerableApp/PathTraversal/LEVEL_1",
			"/VulnerableApp/PathTraversal/LEVEL_1", "", 200, "application/json", "h1", "capture"),
	}
	firstBundle := extract.BuildEndpointBundle(firstEntries, 20)
	first := analysisFingerprint(firstEntries, firstBundle)

	repeatedEntries := []types.TrafficEntry{
		analysisFingerprintEntry(2,
			"http://127.0.0.1:9091/VulnerableApp/PathTraversal/LEVEL_7",
			"/VulnerableApp/PathTraversal/LEVEL_7", "", 200, "application/json", "h2", "capture"),
	}
	repeatedBundle := extract.BuildEndpointBundle(repeatedEntries, 20)
	repeated := analysisFingerprint(repeatedEntries, repeatedBundle)
	if repeated != first {
		t.Fatalf("lesson sibling fingerprint changed\nfirst:    %s\nrepeated: %s", first, repeated)
	}

	otherModuleEntries := []types.TrafficEntry{
		analysisFingerprintEntry(3,
			"http://127.0.0.1:9091/VulnerableApp/IDORVulnerability/LEVEL_7",
			"/VulnerableApp/IDORVulnerability/LEVEL_7", "", 200, "application/json", "h3", "capture"),
	}
	otherModuleBundle := extract.BuildEndpointBundle(otherModuleEntries, 20)
	otherModule := analysisFingerprint(otherModuleEntries, otherModuleBundle)
	if otherModule == first {
		t.Fatal("different lesson modules must retain distinct analysis fingerprints")
	}
}

func TestCanonicalAnalysisPathCollapsesAttackPayloadSegments(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "encoded traversal",
			raw:  "/assets/public/images/uploads/..%2f..%2f..%2f..%2fetc%2fshadow",
			want: "/assets/public/images/uploads/{path_traversal}",
		},
		{
			name: "alternate traversal target same family",
			raw:  "/assets/public/images/uploads/../../../../home/node/.ssh/id_rsa",
			want: "/assets/public/images/uploads/{path_traversal}",
		},
		{
			name: "xss payload path segment",
			raw:  `/rest/track-order/%3Ciframe%20src%3D%22javascript%3Aalert(1)%22%3E`,
			want: "/rest/track-order/{payload}",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := canonicalAnalysisPath(tt.raw); got != tt.want {
				t.Fatalf("canonicalAnalysisPath(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestAnalysisFingerprintKeepsMeaningfulDeltas(t *testing.T) {
	baseEntries := []types.TrafficEntry{
		analysisFingerprintEntry(1, "http://127.0.0.1:3000/rest/memories/1", "/rest/memories/1", "", 500, "text/html", "h1", "explorer"),
	}
	baseBundle := extract.BuildEndpointBundle(baseEntries, 20)
	base := analysisFingerprint(baseEntries, baseBundle)

	tests := []struct {
		name  string
		entry types.TrafficEntry
	}{
		{
			name:  "status changed",
			entry: analysisFingerprintEntry(2, "http://127.0.0.1:3000/rest/memories/2", "/rest/memories/2", "", 200, "application/json", "h2", "explorer"),
		},
		{
			name:  "new query input",
			entry: analysisFingerprintEntry(3, "http://127.0.0.1:3000/rest/memories/2?fields=email", "/rest/memories/2", "fields=email", 500, "text/html", "h3", "explorer"),
		},
		{
			name:  "active source after passive crawl",
			entry: analysisFingerprintEntry(4, "http://127.0.0.1:3000/rest/memories/2", "/rest/memories/2", "", 500, "text/html", "h4", "capture"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries := []types.TrafficEntry{tt.entry}
			bundle := extract.BuildEndpointBundle(entries, 20)
			got := analysisFingerprint(entries, bundle)
			if got == base {
				t.Fatalf("fingerprint did not change for %s: %s", tt.name, got)
			}
		})
	}
}

func TestTemplateAnalysisFingerprintIgnoresSourceOnlyDelta(t *testing.T) {
	passiveEntries := []types.TrafficEntry{
		analysisFingerprintEntry(1, "http://127.0.0.1:3000/api/Feedbacks/?id=1", "/api/Feedbacks/", "id=1", 200, "application/json", "h1", "capture"),
	}
	passiveBundle := extract.BuildEndpointBundle(passiveEntries, 20)
	activeEntries := []types.TrafficEntry{
		analysisFingerprintEntry(2, "http://127.0.0.1:3000/api/Feedbacks/?id=9999", "/api/Feedbacks/", "id=9999", 200, "application/json", "h2", "explorer"),
	}
	activeBundle := extract.BuildEndpointBundle(activeEntries, 20)

	strictPassive := analysisFingerprint(passiveEntries, passiveBundle)
	strictActive := analysisFingerprint(activeEntries, activeBundle)
	if strictPassive == strictActive {
		t.Fatal("strict analysis fingerprint should retain source-intent delta")
	}

	templatePassive := templateAnalysisFingerprint(passiveEntries, passiveBundle, "get_api_Feedbacks_")
	templateActive := templateAnalysisFingerprint(activeEntries, activeBundle, "get_api_Feedbacks_")
	if templatePassive == "" || templatePassive != templateActive {
		t.Fatalf("template fingerprint should ignore source-only delta\npassive: %s\nactive:  %s", templatePassive, templateActive)
	}

	analyzer := &AnalyzerAgent{templateFingerprints: map[string]string{templatePassive: "h1"}}
	if reason := analyzer.repeatedTemplateAnalysisSkipReason(activeEntries, activeBundle, "get_api_Feedbacks_", "h2"); reason == "" {
		t.Fatal("expected repeated template analysis skip reason")
	}
}

func TestAnalysisFingerprintTreatsCrawlerAndNavigatorAsSamePassiveIntent(t *testing.T) {
	crawled := analysisFingerprintEntry(1, "https://shop.test/account", "/account", "", 200, "text/html", "h1", "crawler")
	crawled.SourceActionID = 101
	navigated := analysisFingerprintEntry(2, "https://shop.test/account", "/account", "", 200, "text/html", "h1", "navigator")
	navigated.SourceActionID = 202
	crawlBundle := extract.BuildEndpointBundle([]types.TrafficEntry{crawled}, 20)
	navBundle := extract.BuildEndpointBundle([]types.TrafficEntry{navigated}, 20)
	want := analysisFingerprint([]types.TrafficEntry{crawled}, crawlBundle)
	if got := analysisFingerprint([]types.TrafficEntry{navigated}, navBundle); got != want {
		t.Fatalf("passive browser provenance caused repeat analysis\ncrawler: %s\nnavigator: %s", want, got)
	}

	copilot := navigated
	copilot.SourceAgent = "copilot"
	if analysisFingerprint([]types.TrafficEntry{copilot}, extract.BuildEndpointBundle([]types.TrafficEntry{copilot}, 20)) == want {
		t.Fatal("operator-approved Copilot evidence lost its active intent delta")
	}
}

func TestAnalysisFingerprintCompactsEquivalentTaxonomyAndEntityFamilies(t *testing.T) {
	tests := []struct {
		name, firstPath, secondPath string
	}{
		{"tag pages", "/tag/humor/page/1/", "/tag/books/page/2/"},
		{"nested categories", "/catalogue/category/books/history/index.html", "/catalogue/category/fiction/classics/index.html"},
		{"author pages", "/author/Albert-Einstein/", "/author/J-K-Rowling/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			first := analysisFingerprintEntry(1, "https://content.test"+tt.firstPath, tt.firstPath, "", 200, "text/html", "first", "crawler")
			second := analysisFingerprintEntry(2, "https://content.test"+tt.secondPath, tt.secondPath, "", 200, "text/html", "second", "crawler")
			first.Response.Body = []byte(`<html><body><main><article>representative content</article></main></body></html>`)
			second.Response.Body = append([]byte(nil), first.Response.Body...)
			firstBundle := extract.BuildEndpointBundle([]types.TrafficEntry{first}, 20)
			secondBundle := extract.BuildEndpointBundle([]types.TrafficEntry{second}, 20)
			firstFP := analysisFingerprint([]types.TrafficEntry{first}, firstBundle)
			secondFP := analysisFingerprint([]types.TrafficEntry{second}, secondBundle)
			if firstFP == "" || firstFP != secondFP {
				t.Fatalf("equivalent family did not compact\nfirst:  %s\nsecond: %s", firstFP, secondFP)
			}

			second.Response.StatusCode = 503
			secondBundle = extract.BuildEndpointBundle([]types.TrafficEntry{second}, 20)
			if analysisFingerprint([]types.TrafficEntry{second}, secondBundle) == firstFP {
				t.Fatal("novel error behavior was hidden by route-family compaction")
			}
		})
	}
}

func TestLiveAnalysisRemembersPreRefinementFingerprint(t *testing.T) {
	first := analysisFingerprintEntry(1, "https://content.test/tag/change/page/1/", "/tag/change/page/1/", "", 200, "text/html", "first", "crawler")
	second := analysisFingerprintEntry(2, "https://content.test/tag/books/page/1/", "/tag/books/page/1/", "", 200, "text/html", "second", "navigator")
	body := []byte(`<html><body><a href="/login">Login</a><a href="/tag/example/page/1/">Tag</a><a href="/author/example/">Author</a></body></html>`)
	first.Response.Body = append([]byte(nil), body...)
	second.Response.Body = append([]byte(nil), body...)
	firstBundle := extract.BuildEndpointBundle([]types.TrafficEntry{first}, 20)
	secondBundle := extract.BuildEndpointBundle([]types.TrafficEntry{second}, 20)
	rawFingerprint := analysisFingerprint([]types.TrafficEntry{first}, firstBundle)

	// This is the mutation performed by refineBundleURLPattern during the
	// live model call. It must not change which raw evidence fingerprint is
	// remembered for the representative.
	firstBundle.URLPattern = "/tag/{tag}/page/{page}"
	analyzer := &AnalyzerAgent{}
	analyzer.rememberAnalysisFingerprintValue(rawFingerprint, "first")
	if reason := analyzer.repeatedAnalysisSkipReason([]types.TrafficEntry{second}, secondBundle, "second"); reason == "" {
		t.Fatal("live pre-refinement representative did not compact the next equivalent raw route")
	}
}

func TestAnalysisCompactionBenchmarkDenseTaxonomyPreservesNovelEvidence(t *testing.T) {
	fingerprints := make(map[string]struct{})
	add := func(entry types.TrafficEntry) {
		bundle := extract.BuildEndpointBundle([]types.TrafficEntry{entry}, 20)
		fingerprints[analysisFingerprint([]types.TrafficEntry{entry}, bundle)] = struct{}{}
	}
	standardBody := []byte(`<html><head><meta name="viewport"></head><body><main><a href="/author/example/">author</a></main></body></html>`)
	for index := 0; index < 100; index++ {
		path := fmt.Sprintf("/tag/topic-%03d/page/1/", index)
		entry := analysisFingerprintEntry(int64(index+1), "https://content.test"+path, path, "", 200, "text/html", fmt.Sprintf("tag-%03d", index), "crawler")
		entry.Response.Body = append([]byte(nil), standardBody...)
		add(entry)
	}

	errorEntry := analysisFingerprintEntry(201, "https://content.test/tag/error/page/1/", "/tag/error/page/1/", "", 503, "text/html", "error", "crawler")
	errorEntry.Response.Body = []byte(`<html><body><main><h1>temporarily unavailable</h1></main></body></html>`)
	add(errorEntry)
	inputEntry := analysisFingerprintEntry(202, "https://content.test/tag/search/page/1/?q=robot", "/tag/search/page/1/", "q=robot", 200, "text/html", "input", "crawler")
	inputEntry.Response.Body = []byte(`<html><body><form><input name="q"></form></body></html>`)
	add(inputEntry)
	shapeEntry := analysisFingerprintEntry(203, "https://content.test/tag/directory/page/1/", "/tag/directory/page/1/", "", 200, "text/html", "shape", "crawler")
	shapeEntry.Response.Body = []byte(`<html><body><main><a href="/author/example/">author</a><a href="/api/v1/export">export API</a></main></body></html>`)
	add(shapeEntry)

	if got := len(fingerprints); got != 4 {
		t.Fatalf("103-route family produced %d semantic representatives, want 4 (base + novel status/input/shape)", got)
	}
}

func TestLessonValidationSchemaReuseSkipReason(t *testing.T) {
	templateEntries := []types.TrafficEntry{
		lessonJSONEntry(1,
			"http://127.0.0.1:9091/VulnerableApp/IDORVulnerability/LEVEL_5",
			"/VulnerableApp/IDORVulnerability/LEVEL_5", "", "h1"),
	}
	templateBundle := extract.BuildEndpointBundle(templateEntries, 20)
	understanding := extract.NewAppUnderstanding()
	understanding.RegisterTemplate("get_VulnerableApp_IDORVulnerability_LEVEL_5", "IDOR lesson", templateBundle)

	reusedEntries := []types.TrafficEntry{
		lessonJSONEntry(2,
			"http://127.0.0.1:9091/VulnerableApp/AuthenticationVulnerability/LEVEL_3",
			"/VulnerableApp/AuthenticationVulnerability/LEVEL_3", "", "h2"),
	}
	reusedBundle := extract.BuildEndpointBundle(reusedEntries, 20)
	analyzer := &AnalyzerAgent{understanding: understanding}
	if reason := analyzer.lessonValidationSchemaReuseSkipReason(reusedBundle); reason == "" {
		t.Fatal("expected no-input lesson schema reuse to skip deep analysis")
	}

	withInputEntries := []types.TrafficEntry{
		lessonJSONEntry(3,
			"http://127.0.0.1:9091/VulnerableApp/AuthenticationVulnerability/LEVEL_4?username=aobtd",
			"/VulnerableApp/AuthenticationVulnerability/LEVEL_4", "username=aobtd", "h3"),
	}
	withInputBundle := extract.BuildEndpointBundle(withInputEntries, 20)
	if reason := analyzer.lessonValidationSchemaReuseSkipReason(withInputBundle); reason != "" {
		t.Fatalf("lesson endpoint with observed input should not skip deep analysis: %s", reason)
	}
}

func lessonJSONEntry(id int64, rawURL, path, query, hash string) types.TrafficEntry {
	entry := analysisFingerprintEntry(id, rawURL, path, query, 200, "application/json", hash, "capture")
	entry.Response.Body = []byte(`{"content":"same shape","isValid":true}`)
	entry.Response.Size = int64(len(entry.Response.Body))
	return entry
}

func analysisFingerprintEntry(id int64, rawURL, path, query string, status int, contentType, hash, source string) types.TrafficEntry {
	return types.TrafficEntry{
		ID: id,
		Request: types.CapturedRequest{
			Method: "GET",
			URL:    rawURL,
			Host:   "127.0.0.1:3000",
			Path:   path,
			Query:  query,
		},
		Response: types.CapturedResponse{
			StatusCode:  status,
			ContentType: contentType,
		},
		EndpointHash: hash,
		SourceAgent:  source,
	}
}
