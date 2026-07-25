package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRunnerConfirmsCrossActorOwnershipRead(t *testing.T) {
	srv := ownershipRunnerServer(t, false)
	defer srv.Close()

	plan := runnerOwnershipPlan(srv.URL)
	result, err := NewRunner(srv.Client()).RunOwnershipRead(context.Background(), plan, AuthConfig{
		UserAgent: "AOBTD/workflow-test",
	})
	if err != nil {
		t.Fatalf("RunOwnershipRead: %v", err)
	}
	if !result.Confirmed {
		t.Fatalf("workflow did not confirm vulnerable ownership read: %+v", result)
	}
	if result.Attack.Status != http.StatusOK || !strings.Contains(result.Attack.OwnerProofEvidence, "user-2") {
		t.Fatalf("attack result = %+v, want B owner proof", result.Attack)
	}
}

func TestRunnerDoesNotConfirmWhenOwnershipIsEnforced(t *testing.T) {
	srv := ownershipRunnerServer(t, true)
	defer srv.Close()

	plan := runnerOwnershipPlan(srv.URL)
	result, err := NewRunner(srv.Client()).RunOwnershipRead(context.Background(), plan, AuthConfig{})
	if err != nil {
		t.Fatalf("RunOwnershipRead: %v", err)
	}
	if result.Confirmed {
		t.Fatalf("workflow confirmed despite enforced ownership: %+v", result)
	}
	if result.Attack.Status != http.StatusForbidden {
		t.Fatalf("attack status=%d, want 403", result.Attack.Status)
	}
}

func TestRunnerConfirmsCrossActorOwnershipMutation(t *testing.T) {
	srv := ownershipMutationRunnerServer(t, false)
	defer srv.Close()

	plan := runnerOwnershipMutationPlan(srv.URL)
	result, err := NewRunner(srv.Client()).RunOwnershipMutation(context.Background(), plan, AuthConfig{
		UserAgent: "AOBTD/workflow-test",
	})
	if err != nil {
		t.Fatalf("RunOwnershipMutation: %v", err)
	}
	if !result.Confirmed {
		t.Fatalf("workflow did not confirm vulnerable ownership mutation: %+v", result)
	}
	if result.Attack.Status != http.StatusOK {
		t.Fatalf("attack status=%d, want 200", result.Attack.Status)
	}
	if !BodyContainsMutationValue(result.AfterSecondary.Body, "title", "aobtd-proof") {
		t.Fatalf("after body = %s, want changed title", result.AfterSecondary.Body)
	}
}

func TestRunnerDoesNotConfirmWhenOwnershipMutationIsEnforced(t *testing.T) {
	srv := ownershipMutationRunnerServer(t, true)
	defer srv.Close()

	plan := runnerOwnershipMutationPlan(srv.URL)
	result, err := NewRunner(srv.Client()).RunOwnershipMutation(context.Background(), plan, AuthConfig{})
	if err != nil {
		t.Fatalf("RunOwnershipMutation: %v", err)
	}
	if result.Confirmed {
		t.Fatalf("workflow confirmed despite enforced ownership mutation: %+v", result)
	}
	if result.Attack.Status != http.StatusForbidden {
		t.Fatalf("attack status=%d, want 403", result.Attack.Status)
	}
}

func TestExtractBearerTokenNestedJSON(t *testing.T) {
	body := `{"authentication":{"token":"nested-token"},"user":{"id":1}}`
	if got := ExtractBearerToken(body); got != "nested-token" {
		t.Fatalf("ExtractBearerToken()=%q, want nested-token", got)
	}
}

func TestBodyContainsMutationValueNestedJSON(t *testing.T) {
	body := []byte(`{"document":{"owner_id":"user-2","title":"aobtd-proof"}}`)
	if !BodyContainsMutationValue(body, "title", "aobtd-proof") {
		t.Fatal("BodyContainsMutationValue did not match nested field/value")
	}
	if BodyContainsMutationValue(body, "status", "aobtd-proof") {
		t.Fatal("BodyContainsMutationValue matched wrong field")
	}
}

func runnerOwnershipPlan(base string) Plan {
	primary := Actor{
		Label:       "primary",
		Role:        ActorPrimary,
		LoginURL:    base + "/login",
		Username:    "alice@example.test",
		Secret:      "alicepass",
		OwnerMarker: "user-1",
	}
	secondary := Actor{
		Label:       "secondary",
		Role:        ActorSecondary,
		LoginURL:    base + "/login",
		Username:    "bob@example.test",
		Secret:      "bobpass",
		OwnerMarker: "user-2",
	}
	return OwnershipReadPlan("wf-test-ownership", primary, secondary,
		ResourceRef{Type: "document", Method: "GET", URL: base + "/api/documents/1", OwnerMarker: "user-1"},
		ResourceRef{Type: "document", Method: "GET", URL: base + "/api/documents/2", OwnerMarker: "user-2"},
	)
}

func runnerOwnershipMutationPlan(base string) Plan {
	primary := Actor{
		Label:       "primary",
		Role:        ActorPrimary,
		LoginURL:    base + "/login",
		Username:    "alice@example.test",
		Secret:      "alicepass",
		OwnerMarker: "user-1",
	}
	secondary := Actor{
		Label:       "secondary",
		Role:        ActorSecondary,
		LoginURL:    base + "/login",
		Username:    "bob@example.test",
		Secret:      "bobpass",
		OwnerMarker: "user-2",
	}
	return OwnershipMutationPlan("wf-test-ownership-mutation", primary, secondary,
		ResourceRef{Type: "document", Method: "GET", URL: base + "/api/documents/1", OwnerMarker: "user-1"},
		ResourceRef{Type: "document", Method: "GET", URL: base + "/api/documents/2", OwnerMarker: "user-2"},
		Step{Action: StepMutateBody, Method: "PATCH", URL: base + "/api/documents/2", Field: "title", Value: "aobtd-proof"},
	)
}

func ownershipRunnerServer(t *testing.T, enforceOwnerCheck bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	type loginBody struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	accounts := map[string]struct {
		pass  string
		token string
		owner string
	}{
		"alice@example.test": {pass: "alicepass", token: "alice-token", owner: "user-1"},
		"bob@example.test":   {pass: "bobpass", token: "bob-token", owner: "user-2"},
	}
	tokens := map[string]string{
		"alice-token": "user-1",
		"bob-token":   "user-2",
	}
	documents := map[string]struct {
		owner string
		title string
	}{
		"1": {owner: "user-1", title: "Alice plan"},
		"2": {owner: "user-2", title: "Bob plan"},
	}

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var body loginBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		account, ok := accounts[body.Email]
		if !ok || account.pass != body.Password {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"authentication":{"token":%q},"user":{"id":%q}}`, account.token, account.owner)
	})
	mux.HandleFunc("/api/documents/", func(w http.ResponseWriter, r *http.Request) {
		authz := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		caller := tokens[authz]
		if caller == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"auth required"}`))
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/documents/")
		doc, ok := documents[id]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if enforceOwnerCheck && caller != doc.owner {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"forbidden"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"document":{"id":%q,"owner_id":%q,"title":%q}}`, id, doc.owner, doc.title)
	})
	return httptest.NewServer(mux)
}

func ownershipMutationRunnerServer(t *testing.T, enforceOwnerCheck bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	type loginBody struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	accounts := map[string]struct {
		pass  string
		token string
		owner string
	}{
		"alice@example.test": {pass: "alicepass", token: "alice-token", owner: "user-1"},
		"bob@example.test":   {pass: "bobpass", token: "bob-token", owner: "user-2"},
	}
	tokens := map[string]string{
		"alice-token": "user-1",
		"bob-token":   "user-2",
	}
	documents := map[string]struct {
		owner string
		title string
	}{
		"1": {owner: "user-1", title: "Alice plan"},
		"2": {owner: "user-2", title: "Bob plan"},
	}

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var body loginBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		account, ok := accounts[body.Email]
		if !ok || account.pass != body.Password {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"authentication":{"token":%q},"user":{"id":%q}}`, account.token, account.owner)
	})
	mux.HandleFunc("/api/documents/", func(w http.ResponseWriter, r *http.Request) {
		authz := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		caller := tokens[authz]
		if caller == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"auth required"}`))
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/documents/")
		doc, ok := documents[id]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if enforceOwnerCheck && caller != doc.owner {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"forbidden"}`))
			return
		}
		if r.Method == http.MethodPatch {
			var patch struct {
				Title string `json:"title"`
			}
			if err := json.NewDecoder(r.Body).Decode(&patch); err != nil || patch.Title == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			doc.title = patch.Title
			documents[id] = doc
		} else if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"document":{"id":%q,"owner_id":%q,"title":%q}}`, id, doc.owner, doc.title)
	})
	return httptest.NewServer(mux)
}
