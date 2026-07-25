package reasoner

import (
	"strings"
	"testing"

	"github.com/ozzyw/aobtd/pkg/types"
)

// TestValidateChainPlans locks in the chain-specific validation:
//   - technique MUST be "chain_attack_narrative"
//   - payloads MUST have ≥ 2 steps
//   - rationale MUST be non-empty
//   - Target.URL MUST be on-target (not arbitrary external)
func TestValidateChainPlans(t *testing.T) {
	ev := Evidence{
		Target: "http://target.test",
		LoginEndpoints: []DiscoveredEndpoint{
			{URL: "http://target.test/api/login", Method: "POST"},
		},
		APIEndpoints: []DiscoveredEndpoint{
			{URL: "http://target.test/api/Users", Method: "GET"},
		},
		Findings: []types.Finding{
			{EndpointID: "POST /api/login", Confidence: types.ConfidenceConfirmed},
		},
	}

	tests := []struct {
		name  string
		plan  ProbePlan
		valid bool
	}{
		{
			name: "valid chain with 3 steps",
			plan: ProbePlan{
				Technique: "chain_attack_narrative",
				Target:    ProbeTarget{URL: "http://target.test/api/Users", Method: "GET"},
				Payloads: []string{
					"step 1: login with admin:admin123",
					"step 2: use token on /api/Users",
					"step 3: exfiltrate all user emails",
				},
				Confirmation: ConfirmationRule{BodyContains: []string{"(narrative)"}},
				Rationale:    "weak creds + auth-gated endpoint → account takeover",
				Confidence:   0.8,
			},
			valid: true,
		},
		{
			name: "wrong technique rejected",
			plan: ProbePlan{
				Technique:    "sqli_generic",
				Target:       ProbeTarget{URL: "http://target.test/api/Users"},
				Payloads:     []string{"a", "b"},
				Confirmation: ConfirmationRule{BodyContains: []string{"x"}},
				Rationale:    "x",
			},
			valid: false,
		},
		{
			name: "single-step chain rejected",
			plan: ProbePlan{
				Technique:    "chain_attack_narrative",
				Target:       ProbeTarget{URL: "http://target.test/api/Users"},
				Payloads:     []string{"only one step"},
				Confirmation: ConfirmationRule{BodyContains: []string{"x"}},
				Rationale:    "x",
			},
			valid: false,
		},
		{
			name: "empty rationale rejected",
			plan: ProbePlan{
				Technique:    "chain_attack_narrative",
				Target:       ProbeTarget{URL: "http://target.test/api/Users"},
				Payloads:     []string{"a", "b"},
				Confirmation: ConfirmationRule{BodyContains: []string{"x"}},
				Rationale:    "",
			},
			valid: false,
		},
		{
			name: "off-target URL rejected",
			plan: ProbePlan{
				Technique:    "chain_attack_narrative",
				Target:       ProbeTarget{URL: "http://evil.external/exploit"},
				Payloads:     []string{"a", "b"},
				Confirmation: ConfirmationRule{BodyContains: []string{"x"}},
				Rationale:    "off-target chain",
			},
			valid: false,
		},
		{
			name: "on-target URL from evidence accepted",
			plan: ProbePlan{
				Technique:    "chain_attack_narrative",
				Target:       ProbeTarget{URL: "http://target.test/api/login", Method: "POST"},
				Payloads:     []string{"a", "b"},
				Confirmation: ConfirmationRule{BodyContains: []string{"x"}},
				Rationale:    "login in a chain",
			},
			valid: true,
		},
		{
			name: "on-target URL not in strict evidence but matching target prefix accepted",
			plan: ProbePlan{
				Technique:    "chain_attack_narrative",
				Target:       ProbeTarget{URL: "http://target.test/api/something/new"},
				Payloads:     []string{"a", "b"},
				Confirmation: ConfirmationRule{BodyContains: []string{"x"}},
				Rationale:    "multi-endpoint chain",
			},
			valid: true,
		},
		{
			name: "executable chain missing headers rejected",
			plan: ProbePlan{
				Technique:    "chain_auth_then_access",
				Target:       ProbeTarget{URL: "http://target.test/api/login", Method: "POST", BodyType: "json"},
				Payloads:     []string{"step 1", "step 2"},
				Confirmation: ConfirmationRule{BodyContains: []string{"x"}},
				Rationale:    "weak creds plus IDOR",
			},
			valid: false,
		},
		{
			name: "executable chain with auth headers accepted",
			plan: ProbePlan{
				Technique: "chain_auth_then_access",
				Target: ProbeTarget{
					URL:      "http://target.test/api/login",
					Method:   "POST",
					BodyType: "json",
					Headers: map[string]string{
						"chain_auth_user":   "demo",
						"chain_auth_pass":   "demo",
						"chain_access_urls": "http://target.test/api/Users/2",
					},
				},
				Payloads:     []string{"1", "2"},
				Confirmation: ConfirmationRule{BodyContains: []string{"email"}},
				Rationale:    "weak creds plus IDOR",
			},
			valid: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := validateChainPlans([]ProbePlan{tc.plan}, ev)
			if tc.valid && len(got) != 1 {
				t.Fatalf("expected plan to pass, got %d", len(got))
			}
			if !tc.valid && len(got) != 0 {
				t.Fatalf("expected plan to be rejected, got %d", len(got))
			}
		})
	}
}

// TestURLOnTarget covers the on-target-origin check used to gate
// chain plan URLs.
func TestURLOnTarget(t *testing.T) {
	tests := []struct {
		u, target string
		want      bool
	}{
		{"http://target.test/x", "http://target.test", true},
		{"http://target.test/x", "http://target.test/", true},
		{"http://target.test/a/b/c", "http://target.test", true},
		{"http://evil.external/x", "http://target.test", false},
		{"", "http://target.test", false},
		{"http://target.test/x", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.u+"|"+tc.target, func(t *testing.T) {
			got := urlOnTarget(tc.u, tc.target)
			if got != tc.want {
				t.Errorf("urlOnTarget(%q,%q) = %v, want %v", tc.u, tc.target, got, tc.want)
			}
		})
	}
}

func TestChainReasonerBuildUserMessagePrioritizesBOLA(t *testing.T) {
	r := NewChainReasoner(nil, nil)
	msg := r.buildUserMessage(Evidence{
		Target: "http://target.test",
		Findings: []types.Finding{
			{
				Title:      "BOLA: user A can read user B basket",
				Confidence: types.ConfidenceConfirmed,
				Severity:   types.SeverityHigh,
				VulnType:   "bola_two_persona_ownership",
				EndpointID: "GET /rest/basket/8",
				Evidence:   "A→B readback returned owner marker for user B",
				Impact:     "Cross-user basket disclosure with positive controls",
			},
			{
				Title:      "Weak credentials accepted",
				Confidence: types.ConfidenceConfirmed,
				Severity:   types.SeverityHigh,
				VulnType:   "weak_credentials",
				EndpointID: "POST /rest/user/login",
			},
		},
	})

	for _, want := range []string{
		"chain_priorities",
		"priority_access_control_business_logic",
		"auth_capability",
		"Cross-user basket disclosure",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("buildUserMessage() missing %q in:\n%s", want, msg)
		}
	}
}
