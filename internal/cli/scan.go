package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ozzyw/aobtd/internal/agent"
	"github.com/ozzyw/aobtd/internal/browser"
	"github.com/ozzyw/aobtd/internal/config"
	"github.com/ozzyw/aobtd/internal/llm"
	"github.com/ozzyw/aobtd/internal/policy"
	"github.com/ozzyw/aobtd/internal/proxy"
	"github.com/ozzyw/aobtd/internal/store"
	targetresolver "github.com/ozzyw/aobtd/internal/target"
	"github.com/spf13/cobra"
)

const (
	defaultLLMInputTokenBudget  = 2_000_000
	defaultLLMOutputTokenBudget = 500_000
)

// NewScanCmd creates the `aobtd scan` command.
func NewScanCmd() *cobra.Command {
	var (
		target                 string
		port                   int
		headless               bool
		outputDir              string
		crawl                  bool
		maxDepth               int
		maxPages               int
		includeSubdomains      bool
		scopeEntries           []string
		seedURLs               []string
		llmProvider            string
		llmModel               string
		llmURL                 string
		llmKey                 string
		reasoningModel         string
		llmInputTokenBudget    int
		llmOutputTokenBudget   int
		budgetCents            int
		analysisEndpointLimit  int
		sessionCookie          string
		loginAPIURL            string
		loginURL               string
		loginUser              string
		loginPass              string
		bolaPrimaryLoginURL    string
		bolaPrimaryOwner       string
		bolaPrimaryObjectURL   string
		bolaSecondaryLoginURL  string
		bolaSecondaryUser      string
		bolaSecondaryPass      string
		bolaSecondaryOwner     string
		bolaSecondaryObjectURL string
		testingAuthority       string
		// Sovereign Strategist — optional, runs alongside phase pipeline
		strategistModel   string
		strategistPeriodS int
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Start a scan against a target URL",
		Long:  "Launch a browser through a MITM proxy, crawl the target, and analyze captured traffic.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if target == "" {
				return fmt.Errorf("--target is required")
			}
			return runScan(scanOpts{
				target:                 target,
				port:                   port,
				headless:               headless,
				output:                 outputDir,
				crawl:                  crawl,
				maxDepth:               maxDepth,
				maxPages:               maxPages,
				includeSubdomains:      includeSubdomains,
				scopeEntries:           scopeEntries,
				seedURLs:               seedURLs,
				llmProvider:            llmProvider,
				llmModel:               llmModel,
				llmURL:                 llmURL,
				llmKey:                 llmKey,
				reasoningModel:         reasoningModel,
				llmInputTokenBudget:    llmInputTokenBudget,
				llmOutputTokenBudget:   llmOutputTokenBudget,
				budgetCents:            budgetCents,
				analysisEndpointLimit:  analysisEndpointLimit,
				sessionCookie:          sessionCookie,
				loginAPIURL:            loginAPIURL,
				loginURL:               loginURL,
				loginUser:              loginUser,
				loginPass:              loginPass,
				bolaPrimaryLoginURL:    bolaPrimaryLoginURL,
				bolaPrimaryOwner:       bolaPrimaryOwner,
				bolaPrimaryObjectURL:   bolaPrimaryObjectURL,
				bolaSecondaryLoginURL:  bolaSecondaryLoginURL,
				bolaSecondaryUser:      bolaSecondaryUser,
				bolaSecondaryPass:      bolaSecondaryPass,
				bolaSecondaryOwner:     bolaSecondaryOwner,
				bolaSecondaryObjectURL: bolaSecondaryObjectURL,
				testingAuthority:       testingAuthority,
				strategistModel:        strategistModel,
				strategistPeriod:       time.Duration(strategistPeriodS) * time.Second,
			})
		},
	}

	cmd.Flags().StringVarP(&target, "target", "t", "", "Target URL, domain, or wildcard scope to scan (required)")
	cmd.Flags().IntVarP(&port, "port", "p", 8089, "Proxy listen port")
	cmd.Flags().BoolVar(&headless, "headless", true, "Run browser in headless mode (use --headless=false to show Chrome)")
	cmd.Flags().StringVarP(&outputDir, "output", "o", "./aobtd-output", "Output directory for scan data")
	cmd.Flags().BoolVar(&crawl, "crawl", true, "Enable automated crawling")
	cmd.Flags().IntVar(&maxDepth, "max-depth", 10, "Maximum crawl depth")
	cmd.Flags().IntVar(&maxPages, "max-pages", 100, "Maximum pages to crawl")
	cmd.Flags().BoolVar(&includeSubdomains, "include-subdomains", false, "Smart-discover observed services across the target's registrable domain; external domains stay out of scope")
	cmd.Flags().StringSliceVar(&scopeEntries, "scope", nil, "Additional exact or wildcard origins (repeatable or comma-separated, e.g. https://api.example.com,https://*.example.com)")
	cmd.Flags().StringSliceVar(&seedURLs, "seed-url", nil, "Additional in-scope URL to visit and capture before crawling (repeatable or comma-separated; useful for OpenAPI/Swagger/Postman specs)")

	// LLM flags
	cmd.Flags().StringVar(&llmProvider, "llm", "", "LLM provider: ollama, openai, anthropic (empty = no LLM analysis)")
	cmd.Flags().StringVar(&llmModel, "model", "qwen2.5:14b", "LLM model name")
	cmd.Flags().StringVar(&llmURL, "llm-url", "", "LLM API base URL (empty = provider default)")
	cmd.Flags().StringVar(&llmKey, "llm-key", "", "LLM API key (not needed for Ollama)")
	cmd.Flags().StringVar(&reasoningModel, "reasoning-model", "", "Optional stronger model for attack planning and domain reasoners (falls back to --model on errors)")
	cmd.Flags().IntVar(&llmInputTokenBudget, "llm-input-budget", defaultLLMInputTokenBudget, "Max LLM input tokens per scan (0 = no token cap)")
	cmd.Flags().IntVar(&llmOutputTokenBudget, "llm-output-budget", defaultLLMOutputTokenBudget, "Max LLM output tokens per scan (0 = no token cap)")
	cmd.Flags().IntVar(&budgetCents, "budget", 500, "Max LLM cost in cents (0 = no cap; useful for token-subscription providers like MiniMax). Default $5.00")
	cmd.Flags().IntVar(&analysisEndpointLimit, "analysis-endpoint-limit", 0, "Max endpoint families the Analyzer may process per pass (0 = unlimited)")
	cmd.Flags().StringVar(&sessionCookie, "session-cookie", "", "Session cookie to inject into the browser before crawling (e.g. 'sid=abc123; user=42'). Falls back to AOBTD_SESSION_COOKIE env var.")
	cmd.Flags().StringVar(&loginAPIURL, "login-api-url", "", "Optional JSON API login URL. When set with login credentials, AOBTD captures a token and seeds browser storage before crawling. Falls back to AOBTD_LOGIN_API_URL.")
	cmd.Flags().StringVar(&loginURL, "login-url", "", "URL of a login form. When --login-user and --login-pass are also set, AOBTD logs in before crawling. Falls back to AOBTD_LOGIN_URL env var.")
	cmd.Flags().StringVar(&loginUser, "login-user", "", "Username for form login. Falls back to AOBTD_LOGIN_USER env var.")
	cmd.Flags().StringVar(&loginPass, "login-pass", "", "Password for form login. Falls back to AOBTD_LOGIN_PASS env var.")
	cmd.Flags().StringVar(&bolaPrimaryLoginURL, "bola-primary-login-url", "", "Optional API login URL for the primary BOLA persona; defaults to --login-url. Falls back to AOBTD_BOLA_PRIMARY_LOGIN_URL.")
	cmd.Flags().StringVar(&bolaPrimaryOwner, "bola-primary-owner", "", "Owner marker expected in the primary user's own object (e.g. user id/email). Falls back to AOBTD_BOLA_PRIMARY_OWNER.")
	cmd.Flags().StringVar(&bolaPrimaryObjectURL, "bola-primary-object-url", "", "URL for an object owned by the primary login user. Falls back to AOBTD_BOLA_PRIMARY_OBJECT_URL.")
	cmd.Flags().StringVar(&bolaSecondaryLoginURL, "bola-secondary-login-url", "", "Optional login URL for the secondary BOLA persona; defaults to primary login URL. Falls back to AOBTD_BOLA_SECONDARY_LOGIN_URL.")
	cmd.Flags().StringVar(&bolaSecondaryUser, "bola-secondary-user", "", "Username/email for secondary BOLA persona. Falls back to AOBTD_BOLA_SECONDARY_USER.")
	cmd.Flags().StringVar(&bolaSecondaryPass, "bola-secondary-pass", "", "Password for secondary BOLA persona. Falls back to AOBTD_BOLA_SECONDARY_PASS.")
	cmd.Flags().StringVar(&bolaSecondaryOwner, "bola-secondary-owner", "", "Owner marker expected in the secondary user's object. Falls back to AOBTD_BOLA_SECONDARY_OWNER.")
	cmd.Flags().StringVar(&bolaSecondaryObjectURL, "bola-secondary-object-url", "", "URL for an object owned by the secondary persona. Falls back to AOBTD_BOLA_SECONDARY_OBJECT_URL.")
	cmd.Flags().StringVar(&testingAuthority, "testing-authority", string(policy.AuthorityActive), "Testing authority: recon, active, or full_control")
	cmd.Flags().StringVar(&strategistModel, "strategist-model", "", "Model for the Sovereign Strategist (defaults to analyzer model). Recommended: qwen2.5:14b locally, or claude-sonnet for API.")
	cmd.Flags().IntVar(&strategistPeriodS, "strategist-period", 180, "How often the Strategist wakes up in seconds. 0 disables it.")

	cmd.MarkFlagRequired("target")

	return cmd
}

// defaultModelFor picks a reasonable model id when the user didn't specify.
// The scan flag --model defaults to the recommended local Ollama model, so we
// only override that local default when the user picked a hosted provider.
func defaultModelFor(provider, current string) string {
	switch provider {
	case "anthropic":
		return "claude-sonnet-4-6-20250514"
	case "openai":
		return "gpt-4.1-mini"
	case "ollama":
		return "qwen2.5:14b"
	}
	return current
}

func resolvedModelFor(provider, requested string) string {
	if provider == "" {
		return ""
	}
	if requested == "" || (provider != "ollama" && (requested == "qwen2.5:14b" || requested == "qwen3:8b")) {
		return defaultModelFor(provider, requested)
	}
	return requested
}

func resolveTestingAuthority(raw string) (policy.TestingAuthority, error) {
	if strings.TrimSpace(raw) == "" {
		return policy.AuthorityActive, nil
	}
	return policy.ParseTestingAuthority(raw)
}

func resolveScanScope(target string, includeSubdomains bool, extra []string) ([]string, []string, error) {
	parsedTarget, err := url.Parse(target)
	if err != nil || parsedTarget.Scheme == "" || parsedTarget.Host == "" {
		return nil, nil, fmt.Errorf("invalid target URL %q", target)
	}
	if strings.Contains(parsedTarget.Hostname(), "*") {
		return nil, nil, fmt.Errorf("target must be a reachable host, not a wildcard; put %q in --scope instead", parsedTarget.Hostname())
	}

	policyScope := []string{target}
	crawlScope := []string{strings.ToLower(parsedTarget.Hostname())}
	appendUnique := func(values []string, value string) []string {
		for _, existing := range values {
			if strings.EqualFold(existing, value) {
				return values
			}
		}
		return append(values, value)
	}

	if includeSubdomains {
		root, rootErr := targetresolver.RegistrableDomain(target)
		if rootErr != nil {
			return nil, nil, rootErr
		}
		rootHost := root
		if parsedTarget.Port() != "" {
			rootHost += ":" + parsedTarget.Port()
		}
		// Starting from a subdomain establishes the whole registrable site as
		// the operator-approved smart-discovery boundary. Add both the apex
		// origin and its wildcard: https://partner.example.com therefore covers
		// https://example.com plus every observed https://*.example.com service.
		// The wildcard alone deliberately does not match the apex.
		if !strings.EqualFold(parsedTarget.Hostname(), root) {
			policyScope = appendUnique(policyScope, parsedTarget.Scheme+"://"+rootHost)
		}
		policyScope = appendUnique(policyScope, parsedTarget.Scheme+"://*."+rootHost)
		crawlScope = appendUnique(crawlScope, root)
	}

	for _, raw := range extra {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "://") {
			entry = parsedTarget.Scheme + "://" + entry
		}
		policyScope = appendUnique(policyScope, entry)

		parseable := strings.Replace(entry, "://*.", "://", 1)
		parsed, parseErr := url.Parse(parseable)
		if parseErr != nil || parsed.Hostname() == "" {
			return nil, nil, fmt.Errorf("invalid scope entry %q", raw)
		}
		crawlScope = appendUnique(crawlScope, strings.ToLower(parsed.Hostname()))
	}
	return policyScope, crawlScope, nil
}

func testingAuthorityLabel(authority policy.TestingAuthority) string {
	switch authority {
	case policy.AuthorityRecon:
		return "Recon Only"
	case policy.AuthorityFullControl:
		return "Full Control / Owned Target"
	default:
		return "Active Pentest"
	}
}

type scanOpts struct {
	target                string
	port                  int
	headless              bool
	output                string
	crawl                 bool
	maxDepth              int
	maxPages              int
	includeSubdomains     bool
	scopeEntries          []string
	seedURLs              []string
	llmProvider           string
	llmModel              string
	llmURL                string
	llmKey                string
	reasoningModel        string
	llmInputTokenBudget   int
	llmOutputTokenBudget  int
	budgetCents           int
	analysisEndpointLimit int
	sessionCookie         string // raw "Cookie:" header value; empty = unauthenticated scan
	// API/form login: when credentials are set, AOBTD tries API token seeding
	// first if loginAPIURL is present, then falls back to form login.
	loginAPIURL string
	loginURL    string
	loginUser   string
	loginPass   string
	// Optional two-persona BOLA context. Primary credentials come from the
	// form-login fields above; these fields add owner/object mappings plus the
	// secondary persona.
	bolaPrimaryLoginURL    string
	bolaPrimaryOwner       string
	bolaPrimaryObjectURL   string
	bolaSecondaryLoginURL  string
	bolaSecondaryUser      string
	bolaSecondaryPass      string
	bolaSecondaryOwner     string
	bolaSecondaryObjectURL string
	// Operator-selected testing authority. Empty uses the recommended active
	// default for programmatic callers that predate this field.
	testingAuthority string
	// Sovereign Strategist
	strategistModel  string
	strategistPeriod time.Duration
}

type policyAuditLimiter struct {
	mu     sync.Mutex
	counts map[string]int
}

func (l *policyAuditLimiter) observe(decision policy.Decision) (int, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.counts == nil {
		l.counts = make(map[string]int)
	}
	key := string(decision.Code) + "|" + decision.CanonicalOrigin + "|" + decision.Reason
	l.counts[key]++
	count := l.counts[key]
	return count, count == 1 || count == 10 || count == 50
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func firstNonEmptySecret(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func configuredBOLAPersonas(opts scanOpts, primaryLoginURL, primaryUser, primaryPass string) []agent.BOLAPersonaConfig {
	primaryBOLALoginURL := firstNonEmpty(opts.bolaPrimaryLoginURL, os.Getenv("AOBTD_BOLA_PRIMARY_LOGIN_URL"), primaryLoginURL)
	primaryOwner := firstNonEmpty(opts.bolaPrimaryOwner, os.Getenv("AOBTD_BOLA_PRIMARY_OWNER"))
	primaryObjectURL := resolveTargetRelativeURL(opts.target,
		firstNonEmpty(opts.bolaPrimaryObjectURL, os.Getenv("AOBTD_BOLA_PRIMARY_OBJECT_URL")))
	secondaryLoginURL := firstNonEmpty(opts.bolaSecondaryLoginURL, os.Getenv("AOBTD_BOLA_SECONDARY_LOGIN_URL"), primaryBOLALoginURL)
	secondaryUser := firstNonEmpty(opts.bolaSecondaryUser, os.Getenv("AOBTD_BOLA_SECONDARY_USER"))
	secondaryPass := firstNonEmptySecret(opts.bolaSecondaryPass, os.Getenv("AOBTD_BOLA_SECONDARY_PASS"))
	secondaryOwner := firstNonEmpty(opts.bolaSecondaryOwner, os.Getenv("AOBTD_BOLA_SECONDARY_OWNER"))
	secondaryObjectURL := resolveTargetRelativeURL(opts.target,
		firstNonEmpty(opts.bolaSecondaryObjectURL, os.Getenv("AOBTD_BOLA_SECONDARY_OBJECT_URL")))

	if primaryBOLALoginURL == "" || primaryUser == "" || primaryPass == "" ||
		primaryOwner == "" || primaryObjectURL == "" ||
		secondaryLoginURL == "" || secondaryUser == "" || secondaryPass == "" ||
		secondaryOwner == "" || secondaryObjectURL == "" {
		return nil
	}

	return []agent.BOLAPersonaConfig{
		{
			Label:       "primary",
			LoginURL:    primaryBOLALoginURL,
			Username:    primaryUser,
			Password:    primaryPass,
			OwnerMarker: primaryOwner,
			ObjectURL:   primaryObjectURL,
		},
		{
			Label:       "secondary",
			LoginURL:    secondaryLoginURL,
			Username:    secondaryUser,
			Password:    secondaryPass,
			OwnerMarker: secondaryOwner,
			ObjectURL:   secondaryObjectURL,
		},
	}
}

func resolveTargetRelativeURL(target, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return raw
	}
	base, err := url.Parse(target)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return raw
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return base.ResolveReference(ref).String()
}

func scanHasPreconfiguredAuth(opts scanOpts) bool {
	if firstNonEmptySecret(opts.sessionCookie, os.Getenv("AOBTD_SESSION_COOKIE")) != "" {
		return true
	}
	user := firstNonEmpty(opts.loginUser, os.Getenv("AOBTD_LOGIN_USER"))
	pass := firstNonEmptySecret(opts.loginPass, os.Getenv("AOBTD_LOGIN_PASS"))
	formLogin := firstNonEmpty(opts.loginURL, os.Getenv("AOBTD_LOGIN_URL"))
	apiLogin := firstNonEmpty(opts.loginAPIURL, os.Getenv("AOBTD_LOGIN_API_URL"))
	return user != "" && pass != "" && (formLogin != "" || apiLogin != "")
}

func normalizeSeedURLs(target string, rawSeeds []string) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, raw := range rawSeeds {
		seed := resolveTargetRelativeURL(target, raw)
		seed = strings.TrimSpace(seed)
		if seed == "" {
			continue
		}
		if _, err := url.Parse(seed); err != nil {
			continue
		}
		if _, ok := seen[seed]; ok {
			continue
		}
		seen[seed] = struct{}{}
		out = append(out, seed)
	}
	return out
}

func canonicalPreflightMessage(err error) string {
	if err == nil {
		return ""
	}
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "certificate has expired") || strings.Contains(lower, "expired or is not yet valid") {
		return "TLS preflight could not verify the target certificate because it is expired or not yet valid. Browser evidence collection continued with transport trust marked as degraded."
	}
	if strings.Contains(lower, "certificate") || strings.Contains(lower, "x509") {
		return "TLS preflight could not verify the target certificate. Browser evidence collection continued with transport trust marked as degraded."
	}
	return "Target preflight could not confirm canonical reachability. Browser evidence collection continued on the operator-declared URL."
}

func runScan(opts scanOpts) (retErr error) {
	loadDotEnvLocal(".env.local")

	testingAuthority, err := resolveTestingAuthority(opts.testingAuthority)
	if err != nil {
		return fmt.Errorf("invalid --testing-authority: %w", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// A wildcard target is an authorization declaration, not a DNS name. Turn
	// it into a concrete seed and carry the wildcard into explicit scope before
	// doing any reachability work.
	declaredTarget := opts.target
	declaration, err := targetresolver.NormalizeStartDeclaration(opts.target)
	if err != nil {
		return fmt.Errorf("invalid --target: %w", err)
	}
	opts.target = declaration.Target
	if declaration.WasWildcard {
		seen := false
		for _, existing := range opts.scopeEntries {
			if strings.EqualFold(strings.TrimSpace(existing), declaration.ScopeRule) {
				seen = true
				break
			}
		}
		if !seen {
			opts.scopeEntries = append(opts.scopeEntries, declaration.ScopeRule)
		}
	}

	// Establish the real browser origin before constructing the exact-origin
	// policy. A very common deployment redirects example.com to
	// www.example.com (often while upgrading HTTP to HTTPS). That conventional
	// canonical alias is safe to adopt; arbitrary sibling/cross-site redirects
	// remain outside scope and will still be blocked by the proxy.
	requestedTarget := declaredTarget
	var canonicalResolveErr error
	if scanHasPreconfiguredAuth(opts) {
		logger.Info("canonical target resolution skipped because auth is preconfigured; preserving explicit start URL",
			"target", opts.target)
	} else if resolved, resolveErr := targetresolver.ResolveCanonical(context.Background(), opts.target); resolveErr != nil {
		canonicalResolveErr = resolveErr
		logger.Info("canonical target resolution unavailable; keeping declared target",
			"target", opts.target, "error", resolveErr)
	} else if resolved != opts.target {
		logger.Info("canonical target resolved", "requested", opts.target, "resolved", resolved)
		opts.target = resolved
	}

	policyScope, crawlScope, err := resolveScanScope(opts.target, opts.includeSubdomains, opts.scopeEntries)
	if err != nil {
		return fmt.Errorf("resolve scan scope: %w", err)
	}
	executionPolicy, err := policy.New(testingAuthority, policyScope)
	if err != nil {
		return fmt.Errorf("create execution policy: %w", err)
	}

	if err := os.MkdirAll(opts.output, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	// Open database
	dbPath := filepath.Join(opts.output, "scan.db")
	db, err := store.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	// Resolve secret-bearing auth inputs once, before persisting the scan config.
	// Passwords stay out of cfgJSON; non-secret owner/object mappings are
	// persisted so reports and later views know why BOLA tests were attempted.
	loginURLFinal := firstNonEmpty(opts.loginURL, os.Getenv("AOBTD_LOGIN_URL"))
	loginUserFinal := firstNonEmpty(opts.loginUser, os.Getenv("AOBTD_LOGIN_USER"))
	loginPassFinal := firstNonEmptySecret(opts.loginPass, os.Getenv("AOBTD_LOGIN_PASS"))
	loginAPIURLFinal := firstNonEmpty(opts.loginAPIURL, os.Getenv("AOBTD_LOGIN_API_URL"))
	bolaPersonas := configuredBOLAPersonas(opts, loginURLFinal, loginUserFinal, loginPassFinal)
	if loginAPIURLFinal == "" && len(bolaPersonas) > 0 {
		loginAPIURLFinal = bolaPersonas[0].LoginURL
	}

	// Create scan record
	cfg := config.DefaultConfig()
	resolvedModel := resolvedModelFor(opts.llmProvider, opts.llmModel)
	cfg.Target = opts.target
	cfg.Proxy.Port = opts.port
	cfg.Browser.Headless = opts.headless
	cfg.LLM.Provider = opts.llmProvider
	cfg.LLM.Model = resolvedModel
	cfg.LLM.ReasoningModel = opts.reasoningModel
	cfg.LLM.BaseURL = opts.llmURL
	cfg.LLM.APIKey = ""
	cfg.LLM.Budget.MaxInputTokens = opts.llmInputTokenBudget
	cfg.LLM.Budget.MaxOutputTokens = opts.llmOutputTokenBudget
	cfg.LLM.Budget.MaxCostCents = opts.budgetCents
	cfg.Scan.MaxDepth = opts.maxDepth
	cfg.Scan.MaxPages = opts.maxPages
	cfg.Scan.Scope = policyScope
	cfg.Scan.SeedURLs = normalizeSeedURLs(opts.target, opts.seedURLs)
	cfg.Scan.TestingAuthority = testingAuthority
	if len(bolaPersonas) >= 2 {
		cfg.Scan.PrimaryPersona = config.PersonaConfig{
			LoginURL:    bolaPersonas[0].LoginURL,
			Username:    bolaPersonas[0].Username,
			OwnerMarker: bolaPersonas[0].OwnerMarker,
			ObjectURL:   bolaPersonas[0].ObjectURL,
		}
		cfg.Scan.SecondaryPersona = config.PersonaConfig{
			LoginURL:    bolaPersonas[1].LoginURL,
			Username:    bolaPersonas[1].Username,
			OwnerMarker: bolaPersonas[1].OwnerMarker,
			ObjectURL:   bolaPersonas[1].ObjectURL,
		}
	}
	cfg.Output.Dir = opts.output

	cfgJSON, _ := json.Marshal(cfg)
	scanID, err := db.CreateScan(opts.target, string(cfgJSON))
	if err != nil {
		return fmt.Errorf("create scan: %w", err)
	}
	db.InsertNarration(scanID, "orchestrator", "authority",
		fmt.Sprintf("Testing authority selected: %s (%s).", testingAuthorityLabel(testingAuthority), testingAuthority),
		opts.target, map[string]any{"testing_authority": testingAuthority})
	db.InsertNarration(scanID, "orchestrator", "scope",
		fmt.Sprintf("Operator scope established with %d origin rule(s).", len(policyScope)),
		opts.target, map[string]any{
			"policy_scope":       policyScope,
			"include_subdomains": opts.includeSubdomains,
		})
	if requestedTarget != opts.target {
		db.InsertNarration(scanID, "orchestrator", "canonical_target",
			fmt.Sprintf("Canonical target selected: %s redirected to %s before scope enforcement.", requestedTarget, opts.target),
			opts.target, map[string]any{"requested_target": requestedTarget, "resolved_target": opts.target})
	}
	if canonicalResolveErr != nil {
		db.InsertNarration(scanID, "orchestrator", "reachability_warning",
			canonicalPreflightMessage(canonicalResolveErr), opts.target,
			map[string]any{"stage": "canonical_target_preflight"})
	}
	if len(bolaPersonas) >= 2 {
		db.InsertNarration(scanID, "orchestrator", "authz_context",
			"Two-persona BOLA context configured: reasoners can test whether the primary persona can read the secondary persona's object.",
			opts.target, map[string]any{
				"primary_user":         bolaPersonas[0].Username,
				"primary_owner":        bolaPersonas[0].OwnerMarker,
				"primary_object_url":   bolaPersonas[0].ObjectURL,
				"secondary_user":       bolaPersonas[1].Username,
				"secondary_owner":      bolaPersonas[1].OwnerMarker,
				"secondary_object_url": bolaPersonas[1].ObjectURL,
			})
	}
	// Every created scan owns a terminal transition. Any startup/runtime
	// return below (invalid provider, proxy/browser launch, orchestration
	// failure) is finalized instead of leaving a ghost "running" row.
	scanStatus := "failed"
	scanFinalized := false
	defer func() {
		if scanFinalized {
			return
		}
		if retErr != nil {
			db.InsertNarration(scanID, "orchestrator", "failed", retErr.Error(), opts.target, nil)
		}
		if err := db.FinishScan(scanID, scanStatus); err != nil && retErr == nil {
			retErr = fmt.Errorf("finish scan as %s: %w", scanStatus, err)
		}
	}()

	logger.Info("scan started", "id", scanID, "target", opts.target)
	logger.Info("testing authority selected", "testing_authority", testingAuthority)

	// Set up LLM provider (optional)
	var provider llm.Provider
	var budget *llm.Budget
	var reasoningProvider llm.Provider
	// Resolved outside the provider-init block so the Strategist block later
	// can reuse the same key to spin up its own provider if a different
	// model was requested.
	apiKey := resolveLLMAPIKey(opts.llmProvider, opts.llmKey, opts.llmURL, resolvedModel)

	if opts.llmProvider != "" {
		// Sensible default model per provider if the user didn't override.
		model := resolvedModel
		provider, err = llm.NewProvider(opts.llmProvider, opts.llmURL, apiKey, model)
		if err != nil {
			return fmt.Errorf("create LLM provider: %w", err)
		}
		budget = llm.NewBudget(opts.llmInputTokenBudget, opts.llmOutputTokenBudget, opts.budgetCents, logger)
		budget.SetModel(model)
		logger.Info("LLM configured",
			"provider", opts.llmProvider,
			"model", model,
			"input_token_budget", opts.llmInputTokenBudget,
			"output_token_budget", opts.llmOutputTokenBudget,
			"budget_cents", opts.budgetCents,
		)
		reasoningProvider = provider
		if opts.reasoningModel != "" && opts.reasoningModel != model {
			deep, deepErr := llm.NewProvider(opts.llmProvider, opts.llmURL, apiKey, opts.reasoningModel)
			if deepErr != nil {
				logger.Warn("reasoning model init failed; using scout model", "error", deepErr, "model", opts.reasoningModel)
			} else {
				reasoningProvider = llm.NewFallbackProvider(deep, provider, logger)
				logger.Info("task model routing enabled",
					"scout_model", model,
					"reasoning_model", opts.reasoningModel,
					"fallback_model", model)
			}
		}
	}

	// Keep SQLite commits off the proxy response path. The writer applies
	// bounded backpressure only if capture outpaces a 1024-entry queue and
	// flushes all accepted evidence before the database closes.
	trafficWriter := newTrafficCaptureWriter(db, scanID, logger)
	defer trafficWriter.Close()
	trafficCallback := trafficWriter.Enqueue

	// Start proxy
	certDir := filepath.Join(opts.output, "certs")
	policyAudit := &policyAuditLimiter{}
	p, err := proxy.New("127.0.0.1", opts.port, certDir, trafficCallback,
		executionPolicy, opts.target, func(decision policy.Decision) {
			if decision.Allowed {
				return
			}
			count, emit := policyAudit.observe(decision)
			if !emit {
				return
			}
			message := decision.Reason
			if count > 1 {
				message = fmt.Sprintf("%s — repeated %d times; duplicate policy events suppressed", decision.Reason, count)
			}
			_, _ = db.InsertNarration(scanID, "policy", "denied", message,
				decision.TargetURL, map[string]any{
					"code":              decision.Code,
					"testing_authority": decision.Authority,
					"canonical_origin":  decision.CanonicalOrigin,
					"classes":           decision.Classes,
					"occurrence_count":  count,
				})
		}, logger)
	if err != nil {
		return fmt.Errorf("create proxy: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", opts.port))
	if err != nil {
		cancel()
		return fmt.Errorf("reserve proxy listener: %w", err)
	}
	proxyDone := make(chan error, 1)
	go func() {
		proxyDone <- p.Serve(ctx, listener)
	}()
	defer func() {
		cancel()
		select {
		case proxyErr := <-proxyDone:
			if proxyErr != nil {
				logger.Warn("proxy stopped with error", "error", proxyErr)
			}
		case <-time.After(2 * time.Second):
			logger.Warn("proxy did not stop within shutdown grace period")
		}
	}()

	// Launch browser
	bc := browser.NewController(listener.Addr().String(), opts.headless, logger)
	p.SetTrafficProvenanceResolver(bc.TrafficProvenanceForRequest)
	bc.SetTrafficActionRecorder(func(sourceAgent, action, reason, fromURL, toURL, hypothesisID string) (int64, browser.TrafficActionCompletion, error) {
		actionID, err := db.BeginTrafficAction(scanID, sourceAgent, action, reason, fromURL, toURL, hypothesisID)
		if err != nil {
			return 0, nil, err
		}
		return actionID, func(status, result, finalURL string) error {
			return db.CompleteTrafficAction(scanID, actionID, status, result, finalURL)
		}, nil
	})

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down... (Ctrl+C again to force quit)")
		cancel()
		// Kill browser immediately on first Ctrl+C — don't wait for crawler
		go bc.Close()

		// Second Ctrl+C = instant exit, let OS clean up
		<-sigCh
		fmt.Println("\nForce quit!")
		os.Exit(1)
	}()
	if err := bc.Launch(ctx); err != nil {
		cancel()
		return fmt.Errorf("launch browser: %w", err)
	}
	defer bc.Close()

	// Inject session cookies before any navigation so the very first page load
	// already carries auth. Accepts either the raw `Cookie:` header form
	// ("name=value; name2=value2") OR a header-prefixed form. If the flag
	// wasn't set, fall back to the env var (used by the UI subprocess path
	// to avoid cookies showing up in `ps`/`tasklist`).
	cookie := opts.sessionCookie
	if cookie == "" {
		cookie = os.Getenv("AOBTD_SESSION_COOKIE")
	}
	if cookie != "" {
		n, err := bc.SetSessionCookies(ctx, opts.target, cookie)
		if err != nil {
			logger.Warn("failed to inject session cookies", "error", err)
		} else {
			logger.Info("session cookies injected", "count", n, "target", opts.target)
			db.InsertNarration(scanID, "orchestrator", "auth",
				fmt.Sprintf("Authenticated session: injected %d cookie(s) for %s. Crawling as a logged-in user.",
					n, opts.target),
				opts.target, map[string]any{"cookie_count": n})
		}
	}

	// API/form login (if credentials were provided). Env-var fallback was
	// resolved before cfgJSON was persisted so secrets never land in scan.db.
	preAuthSucceeded := false
	if loginAPIURLFinal != "" && loginUserFinal != "" && loginPassFinal != "" {
		sharedState := agent.NewSharedState(opts.target)
		bus := agent.NewBus(logger)
		auth := agent.NewAuthAgent(db, bc, provider, bus, sharedState, scanID, nil, logger)
		auth.SetBudget(budget)
		auth.SetCredentials(loginUserFinal, loginPassFinal, nil)
		ok, err := auth.AttemptAPILoginAndSeedBrowser(ctx, opts.target, loginAPIURLFinal)
		if err != nil {
			logger.Warn("pre-crawl API login error", "error", err)
		} else {
			preAuthSucceeded = ok
			logger.Info("pre-crawl API login result", "success", ok)
		}
	}
	if !preAuthSucceeded && loginURLFinal != "" && loginUserFinal != "" && loginPassFinal != "" {
		sharedState := agent.NewSharedState(opts.target)
		bus := agent.NewBus(logger)
		auth := agent.NewAuthAgent(db, bc, provider, bus, sharedState, scanID, nil, logger)
		auth.SetBudget(budget)
		auth.SetCredentials(loginUserFinal, loginPassFinal, nil)
		ok, err := auth.AttemptDirectLogin(ctx, loginURLFinal)
		if err != nil {
			logger.Warn("pre-crawl login error", "error", err)
		} else {
			preAuthSucceeded = ok
			logger.Info("pre-crawl login result", "success", ok)
		}
	}

	fmt.Println()
	fmt.Println("=== AOBTD Scan ===")
	fmt.Printf("Target:    %s\n", opts.target)
	fmt.Printf("Proxy:     %s\n", p.Addr())
	fmt.Printf("Output:    %s\n", opts.output)
	fmt.Printf("Crawl:     %v (depth=%d, max=%d pages)\n", opts.crawl, opts.maxDepth, opts.maxPages)
	fmt.Printf("Authority: %s (%s)\n", testingAuthorityLabel(testingAuthority), testingAuthority)
	if provider != nil {
		fmt.Printf("LLM scout: %s (%s)\n", opts.llmProvider, resolvedModel)
		if reasoningProvider != nil && opts.reasoningModel != "" && opts.reasoningModel != resolvedModel {
			fmt.Printf("LLM deep:  %s (%s, fallback %s)\n", opts.llmProvider, opts.reasoningModel, resolvedModel)
		}
	} else {
		fmt.Println("LLM:       disabled (use --llm=ollama to enable)")
	}
	if preAuthSucceeded {
		fmt.Printf("Auth:      form login as %s (OK)\n", loginUserFinal)
	} else if loginURLFinal != "" {
		fmt.Printf("Auth:      form login attempted — see narrations\n")
	}
	fmt.Println()

	var scanRunErr error
	var returnErr error
	if opts.crawl {
		// Optional separate Strategist provider. If the user picked a model
		// different from the main analyzer's, we instantiate it here with
		// the same provider kind (e.g. ollama or openai-compatible). If not
		// set, the orchestrator falls back to the main provider.
		var stratProv llm.Provider
		if provider != nil && opts.strategistModel != "" {
			if sp, err := llm.NewProvider(opts.llmProvider, opts.llmURL, apiKey, opts.strategistModel); err == nil {
				stratProv = llm.NewFallbackProvider(sp, provider, logger)
				logger.Info("Sovereign Strategist using separate model", "model", opts.strategistModel)
			} else {
				logger.Warn("strategist provider init failed; falling back to analyzer model", "error", err)
			}
		}

		// auth-configured flag drives the interactive login-found
		// notification. If the user already passed credentials (CLI flags,
		// env vars, session cookie), we suppress the prompt path.
		authConfigured := (cookie != "") ||
			(loginURLFinal != "" && loginUserFinal != "" && loginPassFinal != "")
		authPhaseLoginURL := loginURLFinal
		if preAuthSucceeded {
			// The browser context already carries the logged-in session. Avoid
			// spending scan time submitting the same form again in Phase 4.
			authPhaseLoginURL = ""
		}

		orch := agent.NewOrchestrator(db, bc, agent.OrchestratorConfig{
			Target:                opts.target,
			ScanID:                scanID,
			MaxDepth:              opts.maxDepth,
			MaxPages:              opts.maxPages,
			Scope:                 crawlScope,
			PolicyScope:           policyScope,
			SeedURLs:              cfg.Scan.SeedURLs,
			Provider:              provider,
			ReasoningProvider:     reasoningProvider,
			Budget:                budget,
			Interactor:            NewTerminalInteractor(),
			StrategistProvider:    stratProv,
			StrategistPeriod:      opts.strategistPeriod,
			AnalysisEndpointLimit: opts.analysisEndpointLimit,
			AuthAlreadyConfigured: authConfigured,
			AuthLoginURL:          authPhaseLoginURL,
			AuthLoginUser:         loginUserFinal,
			AuthLoginPass:         loginPassFinal,
			BOLAPersonas:          bolaPersonas,
			TestingAuthority:      testingAuthority,
		}, logger)

		// Start the interactive-prompt poll loop in the background. It
		// watches the `prompts` table for operator answers (delivered via
		// the UI's notification bell) and runs the login inline when one
		// arrives. The scanner never blocks on this — the scan proceeds
		// unauthenticated until/unless the operator chooses to log in.
		if !authConfigured {
			go runPromptPollLoop(ctx, db, bc, provider, budget, scanID, opts.target, logger)
		}

		if err := orch.Run(ctx); err != nil {
			scanRunErr = err
			var convergenceErr *agent.ConvergenceError
			var noSurfaceErr *agent.NoSurfaceError
			switch {
			case ctx.Err() != nil:
				scanStatus = "interrupted"
				returnErr = err
			case errors.As(err, &convergenceErr), errors.As(err, &noSurfaceErr):
				scanStatus = "incomplete"
				if errors.As(err, &noSurfaceErr) {
					returnErr = err
				}
			default:
				scanStatus = "failed"
				returnErr = err
			}
			if errors.As(err, &convergenceErr) {
				logger.Warn("orchestrator stopped before fixed point", "status", scanStatus, "error", err)
			} else {
				logger.Error("orchestrator stopped", "status", scanStatus, "error", err)
			}
		}
	} else {
		fmt.Println("Manual mode: browse the target in the launched browser.")
		fmt.Println("Press Ctrl+C to stop.")
		fmt.Println()

		if _, err := bc.Navigate(ctx, opts.target); err != nil {
			logger.Warn("initial navigation failed", "error", err)
		}

		<-ctx.Done()
		scanStatus = "interrupted"
	}

	// Final stats
	stats, err := db.GetTrafficStats(scanID)
	if err == nil {
		fmt.Println()
		fmt.Println("=== Traffic Summary ===")
		fmt.Printf("Total captured:    %d\n", stats.Total)
		fmt.Printf("Filtered out:      %d\n", stats.Filtered)
		fmt.Printf("Duplicates:        %d\n", stats.Duplicated)
		fmt.Printf("With inputs:       %d\n", stats.WithInput)
		fmt.Printf("With auth:         %d\n", stats.WithAuth)
		fmt.Printf("With errors:       %d\n", stats.WithErrors)
		fmt.Printf("API endpoints:     %d\n", stats.APIEndpoints)
		fmt.Printf("AI analyzed:       %d\n", stats.Analyzed)
	}

	// Knowledge base summary
	if provider != nil {
		if pStats, err := db.GetProfileStats(scanID); err == nil && pStats.Total > 0 {
			fmt.Println()
			fmt.Println("=== Knowledge Base ===")
			fmt.Printf("Page profiles:     %d\n", pStats.Total)
			fmt.Printf("With issues:       %d\n", pStats.WithIssues)
			fmt.Printf("With inputs:       %d\n", pStats.WithInput)
			fmt.Printf("Needs re-analysis: %d\n", pStats.LowConf)
		}
		if budget != nil {
			fmt.Printf("\n%s\n", budget.Summary())
		}
	}

	fmt.Printf("\nData: %s\n", dbPath)
	if scanRunErr == nil && opts.crawl {
		scanStatus = "completed"
	}
	if scanRunErr != nil {
		db.InsertNarration(scanID, "orchestrator", scanStatus,
			scanRunErr.Error(), opts.target, map[string]any{"terminal_status": scanStatus})
	}
	if err := db.FinishScan(scanID, scanStatus); err != nil {
		return fmt.Errorf("finish scan as %s: %w", scanStatus, err)
	}
	scanFinalized = true
	return returnErr
}

func resolveLLMAPIKey(providerName, explicit, baseURL, model string) string {
	if explicit != "" {
		return explicit
	}
	if v := os.Getenv("AOBTD_LLM_KEY"); v != "" {
		return v
	}
	if providerName == "openai" {
		return os.Getenv("OPENAI_API_KEY")
	}
	if providerName == "openai-compatible" {
		for _, name := range openAICompatibleKeyNames(baseURL, model) {
			if v := os.Getenv(name); v != "" {
				return v
			}
		}
	}
	return ""
}

func openAICompatibleKeyNames(baseURL, model string) []string {
	lowerURL := strings.ToLower(strings.TrimSpace(baseURL))
	lowerModel := strings.ToLower(strings.TrimSpace(model))
	if strings.Contains(lowerURL, "minimax") || strings.HasPrefix(lowerModel, "minimax") {
		return []string{"MINIMAX_API_KEY", "ZAI_API_KEY", "Z_AI_API_KEY", "GLM_API_KEY"}
	}
	if strings.Contains(lowerURL, "z.ai") || strings.Contains(lowerURL, "bigmodel") || strings.HasPrefix(lowerModel, "glm-") {
		return []string{"ZAI_API_KEY", "Z_AI_API_KEY", "GLM_API_KEY", "MINIMAX_API_KEY"}
	}
	return []string{"ZAI_API_KEY", "Z_AI_API_KEY", "GLM_API_KEY", "MINIMAX_API_KEY"}
}

func loadDotEnvLocal(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" || os.Getenv(key) != "" {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') ||
				(value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}
		_ = os.Setenv(key, value)
	}
}
