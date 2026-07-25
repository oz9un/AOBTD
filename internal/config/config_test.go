package config

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ozzyw/aobtd/internal/policy"
)

func TestDefaultConfigUsesRecommendedTestingAuthority(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Scan.TestingAuthority != policy.AuthorityActive {
		t.Fatalf("default testing authority = %q, want %q",
			cfg.Scan.TestingAuthority, policy.AuthorityActive)
	}
	if !cfg.Browser.Headless {
		t.Fatal("default browser mode should be headless; use explicit --headless=false for visible demo runs")
	}

	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"testing_authority":"active"`) {
		t.Fatalf("persisted config lacks snake-case testing_authority: %s", raw)
	}
}
