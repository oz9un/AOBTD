package workflow

import (
	"strings"
	"testing"
)

func TestOwnershipReadPlanIsDomainAgnosticAndValid(t *testing.T) {
	primary := Actor{
		Label:       "alice",
		Role:        ActorPrimary,
		LoginURL:    "https://app.example.test/login",
		Username:    "alice@example.test",
		OwnerMarker: "user-1",
	}
	secondary := Actor{
		Label:       "bob",
		Role:        ActorSecondary,
		LoginURL:    "https://app.example.test/login",
		Username:    "bob@example.test",
		OwnerMarker: "user-2",
	}

	plan := OwnershipReadPlan("wf-owned-object-read", primary, secondary,
		ResourceRef{Type: "booking", URL: "https://app.example.test/api/bookings/100", Method: "GET", OwnerMarker: "user-1"},
		ResourceRef{Type: "booking", URL: "https://app.example.test/api/bookings/200", Method: "GET", OwnerMarker: "user-2"},
	)

	if err := plan.Validate(); err != nil {
		t.Fatalf("OwnershipReadPlan did not validate: %v", err)
	}
	if plan.Area != AreaTransaction {
		t.Fatalf("area=%q, want %q", plan.Area, AreaTransaction)
	}
	if len(plan.Invariants) != 1 || plan.Invariants[0].Type != InvariantOwnership {
		t.Fatalf("invariants = %+v, want one ownership invariant", plan.Invariants)
	}
	if got := plan.Steps[len(plan.Steps)-2]; got.Actor != "alice" || got.URL != "https://app.example.test/api/bookings/200" {
		t.Fatalf("negative control step = %+v, want alice fetching bob's object", got)
	}
	for _, forbidden := range []string{"juice", "basket", "shop"} {
		if strings.Contains(strings.ToLower(plan.Title), forbidden) {
			t.Fatalf("plan title %q is target-specific", plan.Title)
		}
	}
}

func TestOwnershipMutationPlanIsDomainAgnosticAndValid(t *testing.T) {
	primary := Actor{
		Label:       "alice",
		Role:        ActorPrimary,
		LoginURL:    "https://app.example.test/login",
		Username:    "alice@example.test",
		OwnerMarker: "user-1",
	}
	secondary := Actor{
		Label:       "bob",
		Role:        ActorSecondary,
		LoginURL:    "https://app.example.test/login",
		Username:    "bob@example.test",
		OwnerMarker: "user-2",
	}

	plan := OwnershipMutationPlan("wf-owned-object-mutation", primary, secondary,
		ResourceRef{Type: "document", URL: "https://app.example.test/api/documents/100", Method: "GET", OwnerMarker: "user-1"},
		ResourceRef{Type: "document", URL: "https://app.example.test/api/documents/200", Method: "GET", OwnerMarker: "user-2"},
		Step{Action: StepMutateBody, Method: "PATCH", URL: "https://app.example.test/api/documents/200", Field: "title", Value: "aobtd-proof"},
	)

	if err := plan.Validate(); err != nil {
		t.Fatalf("OwnershipMutationPlan did not validate: %v", err)
	}
	if plan.Invariants[0].Type != InvariantOwnership {
		t.Fatalf("invariant = %+v, want ownership", plan.Invariants[0])
	}
	var foundMutation bool
	for _, step := range plan.Steps {
		if step.Action == StepMutateBody && step.Actor == "alice" && step.Field == "title" && step.Value == "aobtd-proof" {
			foundMutation = true
		}
	}
	if !foundMutation {
		t.Fatalf("mutation step not found in %+v", plan.Steps)
	}
	for _, forbidden := range []string{"juice", "basket", "shop"} {
		if strings.Contains(strings.ToLower(plan.Title), forbidden) {
			t.Fatalf("plan title %q is target-specific", plan.Title)
		}
	}
}

func TestWorkflowPlanValidateRejectsVagueUnsafePlans(t *testing.T) {
	plan := Plan{
		ID:     "wf-bad",
		Actors: []Actor{{Label: "alice", Role: ActorPrimary}},
		Steps: []Step{{
			Actor:  "mallory",
			Action: StepMutateBody,
			URL:    "https://app.example.test/api/profile",
		}},
	}

	err := plan.Validate()
	if err == nil {
		t.Fatal("Validate() accepted a step with unknown actor and missing field")
	}
	if !strings.Contains(err.Error(), "unknown actor") {
		t.Fatalf("Validate() error = %q, want unknown actor", err)
	}
}
