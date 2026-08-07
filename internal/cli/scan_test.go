package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ozzyw/aobtd/internal/config"
	"github.com/ozzyw/aobtd/internal/policy"
	"github.com/ozzyw/aobtd/internal/store"
)

func TestRunScanFinalizesInvalidProviderStartup(t *testing.T) {
	output := t.TempDir()
	err := runScan(scanOpts{
		target:      "https://example.test",
		output:      output,
		llmProvider: "not-a-provider",
	})
	if err == nil || !strings.Contains(err.Error(), "create LLM provider") {
		t.Fatalf("runScan() error = %v, want provider initialization error", err)
	}

	db, openErr := store.Open(filepath.Join(output, "scan.db"))
	if openErr != nil {
		t.Fatalf("store.Open() error = %v", openErr)
	}
	defer db.Close()

	var status, finishedAt string
	if queryErr := db.Conn().QueryRow(`
		SELECT status, COALESCE(finished_at, '')
		FROM scans ORDER BY id DESC LIMIT 1`).Scan(&status, &finishedAt); queryErr != nil {
		t.Fatalf("load failed scan: %v", queryErr)
	}
	if status != "failed" || finishedAt == "" {
		t.Fatalf("failed startup persisted status=%q finished_at=%q; want failed with timestamp",
			status, finishedAt)
	}
}

func TestResolveTestingAuthority(t *testing.T) {
	tests := []struct {
		raw     string
		want    policy.TestingAuthority
		wantErr bool
	}{
		{raw: "", want: policy.AuthorityActive},
		{raw: "recon", want: policy.AuthorityRecon},
		{raw: "active", want: policy.AuthorityActive},
		{raw: "full_control", want: policy.AuthorityFullControl},
		{raw: "full", wantErr: true},
		{raw: "FULL_CONTROL", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got, err := resolveTestingAuthority(tt.raw)
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Fatalf("resolveTestingAuthority(%q) = (%q, %v), want (%q, err=%v)",
					tt.raw, got, err, tt.want, tt.wantErr)
			}
		})
	}
}

func TestResolveScanScope(t *testing.T) {
	policyScope, crawlScope, err := resolveScanScope(
		"https://www.example.co.uk/app",
		true,
		[]string{"https://admin.example.net", "*.staging.example.co.uk"},
	)
	if err != nil {
		t.Fatal(err)
	}
	wantPolicy := []string{
		"https://www.example.co.uk/app",
		"https://example.co.uk",
		"https://*.example.co.uk",
		"https://admin.example.net",
		"https://*.staging.example.co.uk",
	}
	if !reflect.DeepEqual(policyScope, wantPolicy) {
		t.Fatalf("policy scope = %#v, want %#v", policyScope, wantPolicy)
	}
	wantCrawl := []string{"www.example.co.uk", "example.co.uk", "admin.example.net", "staging.example.co.uk"}
	if !reflect.DeepEqual(crawlScope, wantCrawl) {
		t.Fatalf("crawl scope = %#v, want %#v", crawlScope, wantCrawl)
	}
}

func TestResolveScanScopeSmartDiscoveryUsesRegistrableDomain(t *testing.T) {
	policyScope, crawlScope, err := resolveScanScope("https://partner.example.com/auth/login", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	wantPolicy := []string{
		"https://partner.example.com/auth/login",
		"https://example.com",
		"https://*.example.com",
	}
	if !reflect.DeepEqual(policyScope, wantPolicy) {
		t.Fatalf("policy scope = %#v, want %#v", policyScope, wantPolicy)
	}
	if !reflect.DeepEqual(crawlScope, []string{"partner.example.com", "example.com"}) {
		t.Fatalf("crawl scope = %#v", crawlScope)
	}

	scope, err := policy.NewScope(policyScope)
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		url  string
		want bool
	}{
		{"https://partner.example.com/account", true},
		{"https://api-service.example.com/api", true},
		{"https://deep.api.example.com/v1", true},
		{"https://example.com/", true},
		{"https://mail.google.com/", false},
		{"https://gmail.com/", false},
		{"https://example.com.evil.test/", false},
	}
	for _, check := range checks {
		_, got, matchErr := scope.MatchURL(check.url)
		if matchErr != nil || got != check.want {
			t.Errorf("MatchURL(%q) = (%v, %v), want %v", check.url, got, matchErr, check.want)
		}
	}
}

func TestResolveScanScopeKeepsDefaultExact(t *testing.T) {
	policyScope, crawlScope, err := resolveScanScope("https://www.example.com", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(policyScope, []string{"https://www.example.com"}) {
		t.Fatalf("policy scope = %#v", policyScope)
	}
	if !reflect.DeepEqual(crawlScope, []string{"www.example.com"}) {
		t.Fatalf("crawl scope = %#v", crawlScope)
	}
}

func TestResolveScanScopeKeepsIPLiteralExact(t *testing.T) {
	policyScope, crawlScope, err := resolveScanScope("http://127.0.0.1:4280/app", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(policyScope, []string{"http://127.0.0.1:4280/app"}) {
		t.Fatalf("policy scope = %#v", policyScope)
	}
	if !reflect.DeepEqual(crawlScope, []string{"127.0.0.1"}) {
		t.Fatalf("crawl scope = %#v", crawlScope)
	}
}

func TestResolveScanScopeRejectsWildcardTarget(t *testing.T) {
	_, _, err := resolveScanScope("https://*.example.com", true, nil)
	if err == nil || !strings.Contains(err.Error(), "not a wildcard") {
		t.Fatalf("error = %v, want wildcard target rejection", err)
	}
}

func TestNormalizeSeedURLsResolvesRelativeAndDedupes(t *testing.T) {
	got := normalizeSeedURLs("https://app.example.test/base/", []string{
		"/openapi.json",
		"https://app.example.test/openapi.json",
		"docs/swagger.json",
		"",
	})
	want := []string{
		"https://app.example.test/openapi.json",
		"https://app.example.test/base/docs/swagger.json",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeSeedURLs() = %#v, want %#v", got, want)
	}
}

func TestScanHasPreconfiguredAuth(t *testing.T) {
	t.Setenv("AOBTD_SESSION_COOKIE", "")
	t.Setenv("AOBTD_LOGIN_URL", "")
	t.Setenv("AOBTD_LOGIN_USER", "")
	t.Setenv("AOBTD_LOGIN_PASS", "")
	t.Setenv("AOBTD_LOGIN_API_URL", "")

	if !scanHasPreconfiguredAuth(scanOpts{sessionCookie: "sid=abc"}) {
		t.Fatal("session cookie should count as preconfigured auth")
	}
	if !scanHasPreconfiguredAuth(scanOpts{
		loginURL:  "https://app.example.test/login",
		loginUser: "alice",
		loginPass: "secret",
	}) {
		t.Fatal("form login credentials should count as preconfigured auth")
	}
	if scanHasPreconfiguredAuth(scanOpts{loginURL: "https://app.example.test/login", loginUser: "alice"}) {
		t.Fatal("incomplete login credentials should not count as preconfigured auth")
	}
}

func TestExternalReconTargetEligibleSkipsLocalAndReservedTargets(t *testing.T) {
	tests := []struct {
		target string
		want   bool
	}{
		{target: "http://127.0.0.1:4280/index.php", want: false},
		{target: "http://[::1]:8080/", want: false},
		{target: "http://10.0.0.5/", want: false},
		{target: "https://app.internal.test/", want: false},
		{target: "https://demo.localhost/", want: false},
		{target: "https://app.example.com/", want: true},
		{target: "https://8.8.8.8/", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			if got := externalReconTargetEligible(tt.target); got != tt.want {
				t.Fatalf("externalReconTargetEligible(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}

func TestPolicyAuditLimiterCollapsesRepeatedDecisions(t *testing.T) {
	limiter := &policyAuditLimiter{}
	decision := policy.Decision{
		Code:            policy.CodeOutOfScope,
		CanonicalOrigin: "https://cdn.example.net:443",
		Reason:          "outside scope",
	}
	for i := 1; i <= 50; i++ {
		count, emit := limiter.observe(decision)
		wantEmit := i == 1 || i == 10 || i == 50
		if count != i || emit != wantEmit {
			t.Fatalf("observation %d = (count=%d emit=%v), want emit=%v", i, count, emit, wantEmit)
		}
	}
}

func TestScanCommandTestingAuthorityFlagDefaultsActive(t *testing.T) {
	flag := NewScanCmd().Flags().Lookup("testing-authority")
	if flag == nil {
		t.Fatal("--testing-authority flag is missing")
	}
	if flag.DefValue != string(policy.AuthorityActive) {
		t.Fatalf("--testing-authority default = %q, want %q", flag.DefValue, policy.AuthorityActive)
	}
}

func TestScanCommandModelFlagDefaultsRecommendedLocal(t *testing.T) {
	flag := NewScanCmd().Flags().Lookup("model")
	if flag == nil {
		t.Fatal("--model flag is missing")
	}
	if flag.DefValue != "qwen2.5:14b" {
		t.Fatalf("--model default = %q, want qwen2.5:14b", flag.DefValue)
	}
}

func TestScanCommandReasoningModelIsOptional(t *testing.T) {
	flag := NewScanCmd().Flags().Lookup("reasoning-model")
	if flag == nil {
		t.Fatal("--reasoning-model flag is missing")
	}
	if flag.DefValue != "" {
		t.Fatalf("--reasoning-model default = %q, want empty", flag.DefValue)
	}
}

func TestScanCommandLLMTokenBudgetFlagsDefaultToProductionCaps(t *testing.T) {
	flags := NewScanCmd().Flags()
	inputFlag := flags.Lookup("llm-input-budget")
	if inputFlag == nil {
		t.Fatal("--llm-input-budget flag is missing")
	}
	if inputFlag.DefValue != "2000000" {
		t.Fatalf("--llm-input-budget default = %q, want 2000000", inputFlag.DefValue)
	}
	outputFlag := flags.Lookup("llm-output-budget")
	if outputFlag == nil {
		t.Fatal("--llm-output-budget flag is missing")
	}
	if outputFlag.DefValue != "500000" {
		t.Fatalf("--llm-output-budget default = %q, want 500000", outputFlag.DefValue)
	}
}

func TestScanCommandAnalysisEndpointLimitDefaultsUnlimited(t *testing.T) {
	flag := NewScanCmd().Flags().Lookup("analysis-endpoint-limit")
	if flag == nil {
		t.Fatal("--analysis-endpoint-limit flag is missing")
	}
	if flag.DefValue != "0" {
		t.Fatalf("--analysis-endpoint-limit default = %q, want 0", flag.DefValue)
	}
}

func TestScanCommandLoginAPIURLFlagExists(t *testing.T) {
	flag := NewScanCmd().Flags().Lookup("login-api-url")
	if flag == nil {
		t.Fatal("--login-api-url flag is missing")
	}
	if flag.DefValue != "" {
		t.Fatalf("--login-api-url default = %q, want empty", flag.DefValue)
	}
}

func TestScanCommandBOLAFlagsExist(t *testing.T) {
	flags := NewScanCmd().Flags()
	for _, name := range []string{
		"bola-primary-owner",
		"bola-primary-login-url",
		"bola-primary-object-url",
		"bola-secondary-login-url",
		"bola-secondary-user",
		"bola-secondary-pass",
		"bola-secondary-owner",
		"bola-secondary-object-url",
	} {
		if flags.Lookup(name) == nil {
			t.Fatalf("--%s flag is missing", name)
		}
	}
}

func TestDefaultOpenAIModelIsMeasuredScout(t *testing.T) {
	if got := defaultModelFor("openai", ""); got != "gpt-4.1-mini" {
		t.Fatalf("defaultModelFor(openai)=%q, want gpt-4.1-mini", got)
	}
}

func TestResolveLLMAPIKeyUsesOpenAIEnvFallback(t *testing.T) {
	t.Setenv("AOBTD_LLM_KEY", "")
	t.Setenv("OPENAI_API_KEY", "openai-env-key")
	if got := resolveLLMAPIKey("openai", "", "", ""); got != "openai-env-key" {
		t.Fatalf("resolveLLMAPIKey(openai)=%q, want OPENAI_API_KEY fallback", got)
	}
}

func TestResolveLLMAPIKeyPrefersExplicitAndAOBTDKey(t *testing.T) {
	t.Setenv("AOBTD_LLM_KEY", "aobtd-env-key")
	t.Setenv("OPENAI_API_KEY", "openai-env-key")
	if got := resolveLLMAPIKey("openai", "explicit-key", "", ""); got != "explicit-key" {
		t.Fatalf("explicit key not preferred: got %q", got)
	}
	if got := resolveLLMAPIKey("openai", "", "", ""); got != "aobtd-env-key" {
		t.Fatalf("AOBTD_LLM_KEY not preferred over OPENAI_API_KEY: got %q", got)
	}
}

func TestResolveLLMAPIKeyUsesCompatibleProviderSpecificFallbacks(t *testing.T) {
	t.Setenv("AOBTD_LLM_KEY", "")
	t.Setenv("ZAI_API_KEY", "zai-key")
	if got := resolveLLMAPIKey("openai-compatible", "", "", ""); got != "zai-key" {
		t.Fatalf("openai-compatible key fallback = %q, want ZAI_API_KEY", got)
	}

	t.Setenv("AOBTD_LLM_KEY", "generic-key")
	if got := resolveLLMAPIKey("openai-compatible", "", "", ""); got != "generic-key" {
		t.Fatalf("AOBTD_LLM_KEY should win over provider-specific fallback, got %q", got)
	}
}

func TestResolveLLMAPIKeyPrefersMiniMaxForMiniMaxCompatibleConfig(t *testing.T) {
	t.Setenv("AOBTD_LLM_KEY", "")
	t.Setenv("ZAI_API_KEY", "zai-key")
	t.Setenv("Z_AI_API_KEY", "")
	t.Setenv("GLM_API_KEY", "")
	t.Setenv("MINIMAX_API_KEY", "minimax-key")

	if got := resolveLLMAPIKey("openai-compatible", "", "https://api.minimax.io/v1", "MiniMax-M2.7-highspeed"); got != "minimax-key" {
		t.Fatalf("MiniMax compatible key fallback = %q, want MINIMAX_API_KEY", got)
	}
	if got := resolveLLMAPIKey("openai-compatible", "", "https://api.z.ai/api/coding/paas/v4", "glm-4.6"); got != "zai-key" {
		t.Fatalf("GLM/ZAI compatible key fallback = %q, want ZAI_API_KEY", got)
	}
}

func TestLoadDotEnvLocalSetsMissingValuesOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env.local")
	if err := os.WriteFile(path, []byte(`
# comment
OPENAI_API_KEY=from-file
export AOBTD_LLM_KEY="from-aobtd"
EXISTING_VALUE=from-file
SINGLE_QUOTED='single quoted'
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("AOBTD_LLM_KEY", "")
	t.Setenv("EXISTING_VALUE", "already-set")
	t.Setenv("SINGLE_QUOTED", "")

	loadDotEnvLocal(path)

	if got := os.Getenv("OPENAI_API_KEY"); got != "from-file" {
		t.Fatalf("OPENAI_API_KEY=%q", got)
	}
	if got := os.Getenv("AOBTD_LLM_KEY"); got != "from-aobtd" {
		t.Fatalf("AOBTD_LLM_KEY=%q", got)
	}
	if got := os.Getenv("EXISTING_VALUE"); got != "already-set" {
		t.Fatalf("EXISTING_VALUE was overwritten: %q", got)
	}
	if got := os.Getenv("SINGLE_QUOTED"); got != "single quoted" {
		t.Fatalf("SINGLE_QUOTED=%q", got)
	}
}

func TestRunScanPersistsTestingAuthorityAndAuditNarration(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want policy.TestingAuthority
	}{
		{name: "omitted defaults active", want: policy.AuthorityActive},
		{name: "recon", raw: "recon", want: policy.AuthorityRecon},
		{name: "active explicit", raw: "active", want: policy.AuthorityActive},
		{name: "full control", raw: "full_control", want: policy.AuthorityFullControl},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := t.TempDir()
			err := runScan(scanOpts{
				target:           "https://example.test",
				output:           output,
				llmProvider:      "not-a-provider",
				testingAuthority: tt.raw,
			})
			if err == nil || !strings.Contains(err.Error(), "create LLM provider") {
				t.Fatalf("runScan() error = %v, want provider initialization error", err)
			}

			db, err := store.Open(filepath.Join(output, "scan.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()

			var rawConfig string
			if err := db.Conn().QueryRow(`SELECT config_json FROM scans ORDER BY id DESC LIMIT 1`).Scan(&rawConfig); err != nil {
				t.Fatal(err)
			}
			var persisted config.Config
			if err := json.Unmarshal([]byte(rawConfig), &persisted); err != nil {
				t.Fatalf("decode config: %v", err)
			}
			if persisted.Scan.TestingAuthority != tt.want {
				t.Fatalf("persisted authority = %q, want %q; config=%s",
					persisted.Scan.TestingAuthority, tt.want, rawConfig)
			}

			var message, metadataJSON string
			if err := db.Conn().QueryRow(`
				SELECT message, metadata_json FROM narrations
				WHERE action = 'authority' ORDER BY id DESC LIMIT 1`).Scan(&message, &metadataJSON); err != nil {
				t.Fatalf("load authority narration: %v", err)
			}
			if !strings.Contains(message, string(tt.want)) || !strings.Contains(metadataJSON, `"testing_authority":"`+string(tt.want)+`"`) {
				t.Fatalf("authority audit mismatch: message=%q metadata=%s", message, metadataJSON)
			}
		})
	}
}

func TestRunScanPersistsResolvedCLIConfig(t *testing.T) {
	output := t.TempDir()
	err := runScan(scanOpts{
		target:               "https://example.test",
		port:                 17777,
		headless:             true,
		output:               output,
		maxDepth:             3,
		maxPages:             7,
		llmProvider:          "not-a-provider",
		llmModel:             "demo-model",
		reasoningModel:       "deep-demo-model",
		llmInputTokenBudget:  12345,
		llmOutputTokenBudget: 6789,
		budgetCents:          42,
		testingAuthority:     "full_control",
	})
	if err == nil || !strings.Contains(err.Error(), "create LLM provider") {
		t.Fatalf("runScan() error = %v, want provider initialization error", err)
	}

	db, err := store.Open(filepath.Join(output, "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var rawConfig string
	if err := db.Conn().QueryRow(`SELECT config_json FROM scans ORDER BY id DESC LIMIT 1`).Scan(&rawConfig); err != nil {
		t.Fatal(err)
	}
	var persisted config.Config
	if err := json.Unmarshal([]byte(rawConfig), &persisted); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	if persisted.Target != "https://example.test" ||
		persisted.Proxy.Port != 17777 ||
		!persisted.Browser.Headless ||
		persisted.LLM.Provider != "not-a-provider" ||
		persisted.LLM.Model != "demo-model" ||
		persisted.LLM.ReasoningModel != "deep-demo-model" ||
		persisted.LLM.Budget.MaxInputTokens != 12345 ||
		persisted.LLM.Budget.MaxOutputTokens != 6789 ||
		persisted.LLM.Budget.MaxCostCents != 42 ||
		persisted.Scan.MaxDepth != 3 ||
		persisted.Scan.MaxPages != 7 ||
		persisted.Scan.TestingAuthority != policy.AuthorityFullControl ||
		persisted.Output.Dir != output {
		t.Fatalf("persisted config does not match CLI opts:\n%s", rawConfig)
	}
}

func TestRunScanPersistsBOLAPersonaContextWithoutPasswords(t *testing.T) {
	output := t.TempDir()
	err := runScan(scanOpts{
		target:                 "https://example.test",
		output:                 output,
		llmProvider:            "not-a-provider",
		loginURL:               "https://example.test/login",
		loginUser:              "alice@example.test",
		loginPass:              "alice-secret",
		bolaPrimaryLoginURL:    "https://example.test/rest/user/login",
		bolaPrimaryOwner:       "1",
		bolaPrimaryObjectURL:   "/api/orders/1",
		bolaSecondaryUser:      "bob@example.test",
		bolaSecondaryPass:      "bob-secret",
		bolaSecondaryOwner:     "2",
		bolaSecondaryObjectURL: "/api/orders/2",
	})
	if err == nil || !strings.Contains(err.Error(), "create LLM provider") {
		t.Fatalf("runScan() error = %v, want provider initialization error", err)
	}

	db, err := store.Open(filepath.Join(output, "scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var rawConfig string
	if err := db.Conn().QueryRow(`SELECT config_json FROM scans ORDER BY id DESC LIMIT 1`).Scan(&rawConfig); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rawConfig, "alice-secret") || strings.Contains(rawConfig, "bob-secret") {
		t.Fatalf("persisted config leaked BOLA password: %s", rawConfig)
	}
	var persisted config.Config
	if err := json.Unmarshal([]byte(rawConfig), &persisted); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	if persisted.Scan.PrimaryPersona.Username != "alice@example.test" ||
		persisted.Scan.PrimaryPersona.LoginURL != "https://example.test/rest/user/login" ||
		persisted.Scan.PrimaryPersona.OwnerMarker != "1" ||
		persisted.Scan.PrimaryPersona.ObjectURL != "https://example.test/api/orders/1" ||
		persisted.Scan.SecondaryPersona.Username != "bob@example.test" ||
		persisted.Scan.SecondaryPersona.OwnerMarker != "2" ||
		persisted.Scan.SecondaryPersona.ObjectURL != "https://example.test/api/orders/2" {
		t.Fatalf("persisted BOLA persona context mismatch:\n%s", rawConfig)
	}

	var narration string
	if err := db.Conn().QueryRow(`
		SELECT message FROM narrations WHERE action = 'authz_context' ORDER BY id DESC LIMIT 1`).Scan(&narration); err != nil {
		t.Fatalf("load BOLA narration: %v", err)
	}
	if !strings.Contains(narration, "Two-persona BOLA context configured") {
		t.Fatalf("unexpected BOLA narration: %q", narration)
	}
}

func TestRunScanRejectsInvalidTestingAuthorityBeforeCreatingScan(t *testing.T) {
	err := runScan(scanOpts{
		target:           "https://example.test",
		output:           filepath.Join(t.TempDir(), "must-not-be-created"),
		testingAuthority: "model_says_full",
	})
	if err == nil || !strings.Contains(err.Error(), "invalid --testing-authority") {
		t.Fatalf("runScan() error = %v, want invalid authority", err)
	}
}

func TestCanonicalPreflightMessageExplainsExpiredTLSWithoutRawError(t *testing.T) {
	message := canonicalPreflightMessage(fmt.Errorf("Get target: tls: failed to verify certificate: x509: certificate has expired or is not yet valid"))
	if !strings.Contains(message, "expired or not yet valid") || !strings.Contains(message, "transport trust marked as degraded") {
		t.Fatalf("expired certificate message = %q", message)
	}
	if strings.Contains(message, "Get target") || strings.Contains(message, "x509") {
		t.Fatalf("preflight message leaked raw transport error: %q", message)
	}
}
