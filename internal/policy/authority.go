// Package policy is the single authorization boundary for target-directed
// actions. It deliberately contains no agent or UI dependencies.
package policy

import (
	"fmt"
	"strings"
)

// TestingAuthority is the operator-selected ceiling for a scan. It never
// changes as a result of target content or model output.
type TestingAuthority string

const (
	AuthorityRecon       TestingAuthority = "recon"
	AuthorityActive      TestingAuthority = "active"
	AuthorityFullControl TestingAuthority = "full_control"
)

// ParseTestingAuthority parses the persisted/UI value. Unknown and empty
// values fail closed; callers must choose an explicit default themselves.
func ParseTestingAuthority(raw string) (TestingAuthority, error) {
	authority := TestingAuthority(strings.TrimSpace(raw))
	if !authority.Valid() {
		return "", fmt.Errorf("unknown testing authority %q", raw)
	}
	return authority, nil
}

// Valid reports whether the authority is one of the operator-facing modes.
func (a TestingAuthority) Valid() bool {
	switch a {
	case AuthorityRecon, AuthorityActive, AuthorityFullControl:
		return true
	default:
		return false
	}
}

// ActionClass describes the security effect of an action. The first four
// values are mutually-exclusive impact classes. Credential-bearing is an
// additional modifier and may accompany any impact class.
type ActionClass string

const (
	ActionPassive           ActionClass = "passive"
	ActionReadOnlyActive    ActionClass = "read_only_active"
	ActionStateChanging     ActionClass = "state_changing"
	ActionDestructive       ActionClass = "destructive"
	ActionCredentialBearing ActionClass = "credential_bearing"
)

// Allows reports whether this authority permits a class in principle. Scope
// and credential-origin invariants are enforced separately and can never be
// bypassed by a true result here.
func (a TestingAuthority) Allows(class ActionClass) bool {
	if !a.Valid() {
		return false
	}
	switch class {
	case ActionPassive, ActionReadOnlyActive, ActionCredentialBearing:
		// Credential-bearing is an orthogonal transport modifier, not a
		// mutation by itself. Recon may use an operator-provided session for
		// read-only discovery; the underlying impact class still gates the
		// action, and Engine enforces exact credential-origin binding.
		return true
	case ActionStateChanging:
		return a == AuthorityActive || a == AuthorityFullControl
	case ActionDestructive:
		return a == AuthorityFullControl
	default:
		return false
	}
}

// ClassifyMethod returns the minimum impact class implied by a standard HTTP
// method. Unknown methods return ok=false so a forgotten or model-invented
// method cannot silently inherit a permissive class.
func ClassifyMethod(method string) (class ActionClass, ok bool) {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "GET", "HEAD", "OPTIONS":
		return ActionReadOnlyActive, true
	case "POST", "PUT", "PATCH":
		return ActionStateChanging, true
	case "DELETE":
		return ActionDestructive, true
	default:
		return "", false
	}
}

func isImpactClass(class ActionClass) bool {
	switch class {
	case ActionPassive, ActionReadOnlyActive, ActionStateChanging, ActionDestructive:
		return true
	default:
		return false
	}
}

func impactRank(class ActionClass) int {
	switch class {
	case ActionPassive:
		return 0
	case ActionReadOnlyActive:
		return 1
	case ActionStateChanging:
		return 2
	case ActionDestructive:
		return 3
	default:
		return -1
	}
}
