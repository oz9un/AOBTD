package policy

import "testing"

func TestParseTestingAuthority(t *testing.T) {
	for _, want := range []TestingAuthority{AuthorityRecon, AuthorityActive, AuthorityFullControl} {
		got, err := ParseTestingAuthority("  " + string(want) + "  ")
		if err != nil {
			t.Fatalf("ParseTestingAuthority(%q): %v", want, err)
		}
		if got != want {
			t.Fatalf("ParseTestingAuthority(%q) = %q", want, got)
		}
	}
	for _, invalid := range []string{"", "full", "FULL_CONTROL", "admin", "active_pentest"} {
		if _, err := ParseTestingAuthority(invalid); err == nil {
			t.Errorf("ParseTestingAuthority(%q) unexpectedly succeeded", invalid)
		}
	}
}

func TestTestingAuthorityMatrix(t *testing.T) {
	classes := []ActionClass{
		ActionPassive,
		ActionReadOnlyActive,
		ActionStateChanging,
		ActionDestructive,
		ActionCredentialBearing,
	}
	tests := []struct {
		authority TestingAuthority
		allowed   map[ActionClass]bool
	}{
		{AuthorityRecon, map[ActionClass]bool{
			ActionPassive: true, ActionReadOnlyActive: true, ActionCredentialBearing: true,
		}},
		{AuthorityActive, map[ActionClass]bool{
			ActionPassive: true, ActionReadOnlyActive: true,
			ActionStateChanging: true, ActionCredentialBearing: true,
		}},
		{AuthorityFullControl, map[ActionClass]bool{
			ActionPassive: true, ActionReadOnlyActive: true,
			ActionStateChanging: true, ActionDestructive: true,
			ActionCredentialBearing: true,
		}},
	}
	for _, tt := range tests {
		for _, class := range classes {
			t.Run(string(tt.authority)+"/"+string(class), func(t *testing.T) {
				if got := tt.authority.Allows(class); got != tt.allowed[class] {
					t.Fatalf("Allows(%s, %s) = %v, want %v", tt.authority, class, got, tt.allowed[class])
				}
			})
		}
	}
	if TestingAuthority("future_mode").Allows(ActionPassive) {
		t.Fatal("unknown authority must fail closed")
	}
	if AuthorityFullControl.Allows(ActionClass("model_invented")) {
		t.Fatal("unknown action class must fail closed even in full control")
	}
}

func TestClassifyMethod(t *testing.T) {
	tests := []struct {
		method string
		class  ActionClass
		ok     bool
	}{
		{"GET", ActionReadOnlyActive, true},
		{" head ", ActionReadOnlyActive, true},
		{"options", ActionReadOnlyActive, true},
		{"POST", ActionStateChanging, true},
		{"put", ActionStateChanging, true},
		{"PATCH", ActionStateChanging, true},
		{"DELETE", ActionDestructive, true},
		{"", "", false},
		{"TRACE", "", false},
		{"CONNECT", "", false},
		{"MODEL-SAYS-SAFE", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			class, ok := ClassifyMethod(tt.method)
			if class != tt.class || ok != tt.ok {
				t.Fatalf("ClassifyMethod(%q) = (%q, %v), want (%q, %v)",
					tt.method, class, ok, tt.class, tt.ok)
			}
		})
	}
}
