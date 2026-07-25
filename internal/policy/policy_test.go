package policy

import (
	"strings"
	"testing"
)

func mustEngine(t *testing.T, authority TestingAuthority, origins ...string) *Engine {
	t.Helper()
	engine, err := New(authority, origins)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func TestAuthorizeAuthorityMatrix(t *testing.T) {
	const target = "https://app.example.test/resource"
	actions := []struct {
		name   string
		action Action
		class  ActionClass
	}{
		{"passive", Action{TargetURL: target, Class: ActionPassive}, ActionPassive},
		{"read only", Action{TargetURL: target, Method: "GET"}, ActionReadOnlyActive},
		{"state changing", Action{TargetURL: target, Method: "POST"}, ActionStateChanging},
		{"destructive", Action{TargetURL: target, Method: "DELETE"}, ActionDestructive},
		{"credential bearing", Action{
			TargetURL: target,
			Method:    "GET",
			Credentials: &CredentialContext{
				Origin: "https://app.example.test",
			},
		}, ActionCredentialBearing},
	}
	expected := map[TestingAuthority]map[string]bool{
		AuthorityRecon: {
			"passive": true, "read only": true, "credential bearing": true,
		},
		AuthorityActive: {
			"passive": true, "read only": true, "state changing": true, "credential bearing": true,
		},
		AuthorityFullControl: {
			"passive": true, "read only": true, "state changing": true,
			"destructive": true, "credential bearing": true,
		},
	}

	for authority, byAction := range expected {
		engine := mustEngine(t, authority, "https://app.example.test")
		for _, tt := range actions {
			t.Run(string(authority)+"/"+tt.name, func(t *testing.T) {
				decision := engine.Authorize(tt.action)
				if decision.Allowed != byAction[tt.name] {
					t.Fatalf("Allowed = %v, want %v; decision=%+v", decision.Allowed, byAction[tt.name], decision)
				}
				if decision.Reason == "" || decision.Code == "" {
					t.Fatalf("decision lacks auditable reason/code: %+v", decision)
				}
				if decision.Allowed && decision.Code != CodeAllowed {
					t.Fatalf("allowed decision code = %q", decision.Code)
				}
				if !decision.Allowed && decision.Code != CodeAuthorityDenied {
					t.Fatalf("denied decision code = %q, want %q", decision.Code, CodeAuthorityDenied)
				}
				if tt.class == ActionCredentialBearing {
					if len(decision.Classes) != 2 || decision.Classes[1] != ActionCredentialBearing {
						t.Fatalf("credential classes = %v", decision.Classes)
					}
				} else if len(decision.Classes) != 1 || decision.Classes[0] != tt.class {
					t.Fatalf("classes = %v, want [%s]", decision.Classes, tt.class)
				}
			})
		}
	}
}

func TestMethodClassCannotBeDowngraded(t *testing.T) {
	tests := []struct {
		name      string
		authority TestingAuthority
		action    Action
		wantClass ActionClass
		allowed   bool
	}{
		{
			name: "POST cannot claim passive under recon", authority: AuthorityRecon,
			action:    Action{TargetURL: "https://app.test/x", Method: "POST", Class: ActionPassive},
			wantClass: ActionStateChanging, allowed: false,
		},
		{
			name: "DELETE cannot claim read-only under active", authority: AuthorityActive,
			action:    Action{TargetURL: "https://app.test/x", Method: "DELETE", Class: ActionReadOnlyActive},
			wantClass: ActionDestructive, allowed: false,
		},
		{
			name: "known destructive GET can raise classification", authority: AuthorityActive,
			action:    Action{TargetURL: "https://app.test/reset", Method: "GET", Class: ActionDestructive},
			wantClass: ActionDestructive, allowed: false,
		},
		{
			name: "full control accepts raised classification", authority: AuthorityFullControl,
			action:    Action{TargetURL: "https://app.test/reset", Method: "GET", Class: ActionDestructive},
			wantClass: ActionDestructive, allowed: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := mustEngine(t, tt.authority, "https://app.test").Authorize(tt.action)
			if decision.Allowed != tt.allowed || len(decision.Classes) != 1 || decision.Classes[0] != tt.wantClass {
				t.Fatalf("decision = %+v, want allowed=%v class=%s", decision, tt.allowed, tt.wantClass)
			}
		})
	}
}

func TestAuthorizeRejectsUnclassifiedAndInventedActions(t *testing.T) {
	engine := mustEngine(t, AuthorityFullControl, "https://app.test")
	tests := []struct {
		name   string
		action Action
		code   DecisionCode
	}{
		{"missing method and class", Action{TargetURL: "https://app.test/x"}, CodeActionClassRequired},
		{"unknown HTTP method", Action{TargetURL: "https://app.test/x", Method: "MODEL-SAFE"}, CodeUnsupportedMethod},
		{"credential modifier cannot be impact", Action{TargetURL: "https://app.test/x", Class: ActionCredentialBearing}, CodeInvalidActionClass},
		{"model invented class", Action{TargetURL: "https://app.test/x", Class: "totally_safe"}, CodeInvalidActionClass},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := engine.Authorize(tt.action)
			if decision.Allowed || decision.Code != tt.code || decision.Reason == "" {
				t.Fatalf("decision = %+v, want denial %s", decision, tt.code)
			}
		})
	}
}

func TestCredentialOriginInvariantAcrossAuthorityModes(t *testing.T) {
	for _, authority := range []TestingAuthority{AuthorityActive, AuthorityFullControl} {
		engine := mustEngine(t, authority,
			"https://app.example.test", "https://api.example.test",
			"https://app.example.test:444", "http://app.example.test")

		same := engine.Authorize(Action{
			TargetURL: "https://app.example.test/account",
			Method:    "GET",
			Credentials: &CredentialContext{
				Origin: "https://APP.example.test:443/login",
			},
		})
		if !same.Allowed {
			t.Fatalf("%s same-origin credentials denied: %+v", authority, same)
		}

		cross := engine.Authorize(Action{
			TargetURL: "https://api.example.test/account",
			Method:    "GET",
			Credentials: &CredentialContext{
				Origin: "https://app.example.test",
			},
		})
		if cross.Allowed || cross.Code != CodeCredentialOriginMismatch {
			t.Fatalf("%s cross-origin credentials decision = %+v", authority, cross)
		}

		for name, target := range map[string]string{
			"different port":   "https://app.example.test:444/account",
			"different scheme": "http://app.example.test/account",
		} {
			t.Run(string(authority)+"/"+name, func(t *testing.T) {
				decision := engine.Authorize(Action{
					TargetURL: target,
					Method:    "GET",
					Credentials: &CredentialContext{
						Origin: "https://app.example.test",
					},
				})
				if decision.Allowed || decision.Code != CodeCredentialOriginMismatch {
					t.Fatalf("credential origin boundary decision = %+v", decision)
				}
			})
		}
	}

	full := mustEngine(t, AuthorityFullControl, "https://app.example.test")
	tests := []struct {
		name   string
		action Action
		code   DecisionCode
	}{
		{
			"missing bound origin",
			Action{TargetURL: "https://app.example.test/x", Method: "GET", Credentials: &CredentialContext{}},
			CodeCredentialOriginRequired,
		},
		{
			"invalid bound origin",
			Action{TargetURL: "https://app.example.test/x", Method: "GET", Credentials: &CredentialContext{Origin: "app.example.test"}},
			CodeInvalidCredentialOrigin,
		},
		{
			"off-scope wins before credentials",
			Action{TargetURL: "https://app.example.test.evil/x", Method: "GET", Credentials: &CredentialContext{Origin: "https://app.example.test"}},
			CodeOutOfScope,
		},
		{
			"userinfo target is invalid",
			Action{TargetURL: "https://attacker@app.example.test/x", Method: "GET", Credentials: &CredentialContext{Origin: "https://app.example.test"}},
			CodeInvalidTarget,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := full.Authorize(tt.action)
			if decision.Allowed || decision.Code != tt.code {
				t.Fatalf("decision = %+v, want denial %s", decision, tt.code)
			}
		})
	}

	recon := mustEngine(t, AuthorityRecon, "https://app.example.test")
	decision := recon.Authorize(Action{
		TargetURL: "https://app.example.test/x", Method: "GET",
		Credentials: &CredentialContext{Origin: "https://app.example.test"},
	})
	if !decision.Allowed || decision.Code != CodeAllowed {
		t.Fatalf("recon same-origin read-only credential decision = %+v", decision)
	}
	login := recon.Authorize(Action{
		TargetURL: "https://app.example.test/login", Method: "POST",
		Credentials: &CredentialContext{Origin: "https://app.example.test"},
	})
	if login.Allowed || login.Code != CodeAuthorityDenied || !strings.Contains(login.Reason, string(ActionStateChanging)) {
		t.Fatalf("recon credential-bearing login decision = %+v", login)
	}
}

func TestAuthorizeRedirectHopRevalidatesEveryDestination(t *testing.T) {
	engine := mustEngine(t, AuthorityFullControl,
		"https://app.example.test", "https://api.example.test")
	tests := []struct {
		name string
		hop  RedirectHop
		code DecisionCode
		ok   bool
	}{
		{
			name: "relative same-origin",
			hop:  RedirectHop{FromURL: "https://app.example.test/start", Location: "/next", Method: "GET"},
			code: CodeAllowed, ok: true,
		},
		{
			name: "second explicitly scoped origin without credentials",
			hop:  RedirectHop{FromURL: "https://app.example.test/start", Location: "https://api.example.test/next", Method: "GET"},
			code: CodeAllowed, ok: true,
		},
		{
			name: "lookalike domain",
			hop:  RedirectHop{FromURL: "https://app.example.test/start", Location: "https://app.example.test.evil/next", Method: "GET"},
			code: CodeOutOfScope,
		},
		{
			name: "protocol-relative off scope",
			hop:  RedirectHop{FromURL: "https://app.example.test/start", Location: "//evil.test/next", Method: "GET"},
			code: CodeOutOfScope,
		},
		{
			name: "different port",
			hop:  RedirectHop{FromURL: "https://app.example.test/start", Location: "https://app.example.test:444/next", Method: "GET"},
			code: CodeOutOfScope,
		},
		{
			name: "credentials cannot cross between scoped origins",
			hop: RedirectHop{
				FromURL: "https://app.example.test/start", Location: "https://api.example.test/next", Method: "GET",
				Credentials: &CredentialContext{Origin: "https://app.example.test"},
			},
			code: CodeCredentialOriginMismatch,
		},
		{
			name: "userinfo location rejected",
			hop:  RedirectHop{FromURL: "https://app.example.test/start", Location: "https://user@app.example.test/next", Method: "GET"},
			code: CodeInvalidTarget,
		},
		{
			name: "off-scope source rejected",
			hop:  RedirectHop{FromURL: "https://evil.test/start", Location: "https://app.example.test/next", Method: "GET"},
			code: CodeRedirectSourceOutOfScope,
		},
		{
			name: "encoded invalid location",
			hop:  RedirectHop{FromURL: "https://app.example.test/start", Location: "https://example.test/%zz", Method: "GET"},
			code: CodeInvalidRedirectLocation,
		},
		{
			name: "browser-style backslash authority trick",
			hop:  RedirectHop{FromURL: "https://app.example.test/start", Location: `\\evil.test/next`, Method: "GET"},
			code: CodeInvalidRedirectLocation,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := engine.AuthorizeRedirectHop(tt.hop)
			if decision.Allowed != tt.ok || decision.Code != tt.code || decision.Reason == "" {
				t.Fatalf("decision = %+v, want allowed=%v code=%s", decision, tt.ok, tt.code)
			}
		})
	}

	first := engine.AuthorizeRedirectHop(RedirectHop{
		FromURL: "https://app.example.test/start", Location: "https://api.example.test/intermediate", Method: "GET",
	})
	if !first.Allowed {
		t.Fatalf("first hop denied: %+v", first)
	}
	second := engine.AuthorizeRedirectHop(RedirectHop{
		FromURL: first.TargetURL, Location: "https://evil.test/final", Method: "GET",
	})
	if second.Allowed || second.Code != CodeOutOfScope {
		t.Fatalf("later off-scope hop escaped revalidation: %+v", second)
	}
}

func TestRedirectStillObservesAuthority(t *testing.T) {
	active := mustEngine(t, AuthorityActive, "https://app.test")
	decision := active.AuthorizeRedirectHop(RedirectHop{
		FromURL: "https://app.test/start", Location: "/delete-account", Method: "DELETE",
	})
	if decision.Allowed || decision.Code != CodeAuthorityDenied || len(decision.Classes) != 1 || decision.Classes[0] != ActionDestructive {
		t.Fatalf("active destructive redirect decision = %+v", decision)
	}
}
