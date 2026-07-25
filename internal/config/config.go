package config

import (
	"time"

	"github.com/ozzyw/aobtd/internal/policy"
)

// Config holds all configuration for an AOBTD scan.
type Config struct {
	Target  string        `mapstructure:"target"`
	Proxy   ProxyConfig   `mapstructure:"proxy"`
	Browser BrowserConfig `mapstructure:"browser"`
	LLM     LLMConfig     `mapstructure:"llm"`
	Scan    ScanConfig    `mapstructure:"scan"`
	Output  OutputConfig  `mapstructure:"output"`
}

type ProxyConfig struct {
	ListenAddr string `mapstructure:"listen_addr"`
	Port       int    `mapstructure:"port"`
}

type BrowserConfig struct {
	Headless bool          `mapstructure:"headless"`
	Timeout  time.Duration `mapstructure:"timeout"`
}

type LLMConfig struct {
	Provider       string `mapstructure:"provider"`
	Model          string `mapstructure:"model"`
	ReasoningModel string `mapstructure:"reasoning_model"`
	// BaseURL is safe to persist and lets scan-scoped tools reuse the exact
	// OpenAI-compatible endpoint. APIKey remains deliberately blank in the
	// persisted scan config.
	BaseURL string       `mapstructure:"base_url"`
	APIKey  string       `mapstructure:"api_key"`
	Budget  BudgetConfig `mapstructure:"budget"`
}

type BudgetConfig struct {
	MaxInputTokens  int `mapstructure:"max_input_tokens"`
	MaxOutputTokens int `mapstructure:"max_output_tokens"`
	MaxCostCents    int `mapstructure:"max_cost_cents"`
}

type ScanConfig struct {
	MaxDepth         int                     `mapstructure:"max_depth"`
	MaxPages         int                     `mapstructure:"max_pages"`
	CrawlTimeout     time.Duration           `mapstructure:"crawl_timeout"`
	Scope            []string                `mapstructure:"scope"` // allowed domains
	SeedURLs         []string                `mapstructure:"seed_urls" json:"seed_urls,omitempty"`
	TestingAuthority policy.TestingAuthority `mapstructure:"testing_authority" json:"testing_authority"`
	PrimaryPersona   PersonaConfig           `mapstructure:"primary_persona" json:"primary_persona,omitempty"`
	SecondaryPersona PersonaConfig           `mapstructure:"secondary_persona" json:"secondary_persona,omitempty"`
}

// PersonaConfig stores non-secret BOLA context in the persisted scan config.
// Passwords are deliberately excluded from this struct; UI-launched scans pass
// them via environment variables and the reasoner hydrates executable plans
// in-process without sending secrets to an LLM or writing them to scan.db.
type PersonaConfig struct {
	LoginURL    string `mapstructure:"login_url" json:"login_url,omitempty"`
	Username    string `mapstructure:"username" json:"username,omitempty"`
	OwnerMarker string `mapstructure:"owner_marker" json:"owner_marker,omitempty"`
	ObjectURL   string `mapstructure:"object_url" json:"object_url,omitempty"`
}

type OutputConfig struct {
	Dir    string `mapstructure:"dir"`
	Format string `mapstructure:"format"` // json, markdown, html
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Proxy: ProxyConfig{
			ListenAddr: "127.0.0.1",
			Port:       8089,
		},
		Browser: BrowserConfig{
			Headless: true,
			Timeout:  30 * time.Second,
		},
		LLM: LLMConfig{
			Provider: "anthropic",
			Model:    "claude-sonnet-4-20250514",
			Budget: BudgetConfig{
				MaxInputTokens:  2000000,
				MaxOutputTokens: 500000,
				MaxCostCents:    500,
			},
		},
		Scan: ScanConfig{
			MaxDepth:         10,
			MaxPages:         500,
			CrawlTimeout:     30 * time.Minute,
			TestingAuthority: policy.AuthorityActive,
		},
		Output: OutputConfig{
			Dir:    "./aobtd-output",
			Format: "json",
		},
	}
}
