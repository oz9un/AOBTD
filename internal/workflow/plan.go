package workflow

import (
	"fmt"
	"net/url"
	"strings"
)

// ActorRole describes how a test actor participates in a workflow. The names
// are intentionally generic: the same model covers shoppers, bank users,
// tenants, patients, support agents, and administrators.
type ActorRole string

const (
	ActorAnonymous ActorRole = "anonymous"
	ActorPrimary   ActorRole = "primary"
	ActorSecondary ActorRole = "secondary"
	ActorAdmin     ActorRole = "admin"
	ActorSystem    ActorRole = "system"
)

// Actor is an identity available to a workflow test.
type Actor struct {
	Label       string
	Role        ActorRole
	LoginURL    string
	Username    string
	Secret      string
	OwnerMarker string
}

// ResourceRef names an object or collection whose server-side ownership or
// state should be protected.
type ResourceRef struct {
	Type        string
	URL         string
	Method      string
	OwnerMarker string
}

// InvariantType is the security/business rule a workflow is trying to prove.
type InvariantType string

const (
	InvariantOwnership       InvariantType = "ownership"
	InvariantRoleBoundary    InvariantType = "role_boundary"
	InvariantServerDerived   InvariantType = "server_derived_value"
	InvariantStateTransition InvariantType = "state_transition"
	InvariantAntiAutomation  InvariantType = "anti_automation"
	InvariantInputValidation InvariantType = "input_validation"
	InvariantSensitiveRead   InvariantType = "sensitive_read"
)

// Invariant is the human-readable claim a workflow must preserve.
type Invariant struct {
	Type        InvariantType
	Subject     ResourceRef
	AllowedFor  []string
	DeniedFor   []string
	Description string
}

// StepAction names the primitive an executor can perform.
type StepAction string

const (
	StepLogin           StepAction = "login"
	StepFetch           StepAction = "fetch"
	StepMutateParam     StepAction = "mutate_param"
	StepMutateBody      StepAction = "mutate_body"
	StepSubmitForm      StepAction = "submit_form"
	StepObserve         StepAction = "observe"
	StepAssertInvariant StepAction = "assert_invariant"
)

// Step is one action in a stateful workflow plan.
type Step struct {
	Actor       string
	Action      StepAction
	Method      string
	URL         string
	Field       string
	Value       string
	Expectation string
}

// Plan is a general workflow test recipe. It is deliberately not tied to
// Juice Shop challenge keys or any vertical-specific vocabulary.
type Plan struct {
	ID         string
	Title      string
	Area       Area
	Actors     []Actor
	Resources  []ResourceRef
	Invariants []Invariant
	Steps      []Step
}

// Validate catches plans that are impossible or too vague for an executor to
// run safely. It does not enforce target policy; origin and authority checks
// stay in the policy layer.
func (p Plan) Validate() error {
	if strings.TrimSpace(p.ID) == "" {
		return fmt.Errorf("workflow plan missing id")
	}
	if len(p.Steps) == 0 {
		return fmt.Errorf("workflow plan %q has no steps", p.ID)
	}
	actors := make(map[string]struct{}, len(p.Actors))
	for _, a := range p.Actors {
		if a.Label == "" {
			return fmt.Errorf("workflow plan %q has actor without label", p.ID)
		}
		actors[a.Label] = struct{}{}
	}
	for _, r := range p.Resources {
		if r.URL == "" {
			return fmt.Errorf("workflow plan %q has resource without url", p.ID)
		}
		if _, err := url.Parse(r.URL); err != nil {
			return fmt.Errorf("workflow plan %q has invalid resource url %q: %w", p.ID, r.URL, err)
		}
	}
	for i, step := range p.Steps {
		if step.Action == "" {
			return fmt.Errorf("workflow plan %q step %d missing action", p.ID, i+1)
		}
		if step.Actor != "" {
			if _, ok := actors[step.Actor]; !ok {
				return fmt.Errorf("workflow plan %q step %d references unknown actor %q", p.ID, i+1, step.Actor)
			}
		}
		if needsURL(step.Action) && strings.TrimSpace(step.URL) == "" {
			return fmt.Errorf("workflow plan %q step %d missing url", p.ID, i+1)
		}
		if needsField(step.Action) && strings.TrimSpace(step.Field) == "" {
			return fmt.Errorf("workflow plan %q step %d missing field", p.ID, i+1)
		}
	}
	return nil
}

func needsURL(action StepAction) bool {
	switch action {
	case StepLogin, StepFetch, StepMutateParam, StepMutateBody, StepSubmitForm:
		return true
	default:
		return false
	}
}

func needsField(action StepAction) bool {
	switch action {
	case StepMutateParam, StepMutateBody:
		return true
	default:
		return false
	}
}

// OwnershipReadPlan creates the common two-actor access-control workflow:
// actor A proves they can read their own object, then tries actor B's object,
// and the invariant asserts that B's object must not be readable by A.
func OwnershipReadPlan(id string, primary, secondary Actor, primaryObject, secondaryObject ResourceRef) Plan {
	resourceType := firstNonEmpty(primaryObject.Type, secondaryObject.Type, "resource")
	area, _ := ClassifyArea(primaryObject.URL + " " + secondaryObject.URL + " " + resourceType)
	return Plan{
		ID:    id,
		Title: "Cross-actor ownership read check for " + resourceType,
		Area:  area,
		Actors: []Actor{
			primary,
			secondary,
		},
		Resources: []ResourceRef{primaryObject, secondaryObject},
		Invariants: []Invariant{{
			Type:        InvariantOwnership,
			Subject:     secondaryObject,
			AllowedFor:  []string{secondary.Label},
			DeniedFor:   []string{primary.Label},
			Description: fmt.Sprintf("%s must not read %s owned by %s", primary.Label, resourceType, secondary.Label),
		}},
		Steps: []Step{
			{Actor: primary.Label, Action: StepLogin, Method: "POST", URL: primary.LoginURL, Expectation: "primary actor obtains a session"},
			{Actor: primary.Label, Action: StepFetch, Method: firstNonEmpty(primaryObject.Method, "GET"), URL: primaryObject.URL, Expectation: "positive control: primary can read own object"},
			{Actor: secondary.Label, Action: StepLogin, Method: "POST", URL: secondary.LoginURL, Expectation: "secondary actor obtains a session"},
			{Actor: secondary.Label, Action: StepFetch, Method: firstNonEmpty(secondaryObject.Method, "GET"), URL: secondaryObject.URL, Expectation: "positive control: secondary can read own object"},
			{Actor: primary.Label, Action: StepFetch, Method: firstNonEmpty(secondaryObject.Method, "GET"), URL: secondaryObject.URL, Expectation: "negative control: primary must be denied or receive no secondary-owned data"},
			{Action: StepAssertInvariant, Expectation: "ownership invariant holds for the negative control"},
		},
	}
}

// OwnershipMutationPlan creates the common two-actor access-control workflow:
// actor B proves they can read their own object, then actor A attempts to
// mutate one field on B's object. The invariant asserts that A must not be
// able to change B-owned state. The caller decides whether this state-changing
// plan is allowed for the current target via the policy layer.
func OwnershipMutationPlan(id string, primary, secondary Actor, primaryObject, secondaryObject ResourceRef, mutation Step) Plan {
	resourceType := firstNonEmpty(secondaryObject.Type, primaryObject.Type, "resource")
	if mutation.Action == "" {
		mutation.Action = StepMutateBody
	}
	if mutation.Actor == "" {
		mutation.Actor = primary.Label
	}
	if mutation.Method == "" {
		mutation.Method = "PATCH"
	}
	area, _ := ClassifyArea(primaryObject.URL + " " + secondaryObject.URL + " " + mutation.URL + " " + resourceType)
	return Plan{
		ID:    id,
		Title: "Cross-actor ownership mutation check for " + resourceType,
		Area:  area,
		Actors: []Actor{
			primary,
			secondary,
		},
		Resources: []ResourceRef{primaryObject, secondaryObject},
		Invariants: []Invariant{{
			Type:        InvariantOwnership,
			Subject:     secondaryObject,
			AllowedFor:  []string{secondary.Label},
			DeniedFor:   []string{primary.Label},
			Description: fmt.Sprintf("%s must not mutate %s owned by %s", primary.Label, resourceType, secondary.Label),
		}},
		Steps: []Step{
			{Actor: primary.Label, Action: StepLogin, Method: "POST", URL: primary.LoginURL, Expectation: "primary actor obtains a session"},
			{Actor: secondary.Label, Action: StepLogin, Method: "POST", URL: secondary.LoginURL, Expectation: "secondary actor obtains a session"},
			{Actor: secondary.Label, Action: StepFetch, Method: firstNonEmpty(secondaryObject.Method, "GET"), URL: secondaryObject.URL, Expectation: "positive control: secondary can read own object before mutation"},
			{Actor: primary.Label, Action: mutation.Action, Method: mutation.Method, URL: mutation.URL, Field: mutation.Field, Value: mutation.Value, Expectation: "negative control: primary must not change secondary-owned state"},
			{Actor: secondary.Label, Action: StepFetch, Method: firstNonEmpty(secondaryObject.Method, "GET"), URL: secondaryObject.URL, Expectation: "verification: secondary-owned object state should not be changed by primary"},
			{Action: StepAssertInvariant, Expectation: "ownership invariant holds for the mutation attempt"},
		},
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
