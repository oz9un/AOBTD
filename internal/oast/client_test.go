package oast

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewProbeProducesSignedCallbackURL(t *testing.T) {
	client, err := New("https://oast.example.test", "api", "signing", nil)
	if err != nil {
		t.Fatal(err)
	}
	token, callbackURL, err := client.NewProbe()
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "v1" || len(parts[1]) != 32 || len(parts[2]) != 32 {
		t.Fatalf("unexpected token shape %q", token)
	}
	if callbackURL != "https://oast.example.test/c/"+token {
		t.Fatalf("callback URL = %q", callbackURL)
	}
}

func TestNewRejectsIncompleteOrInsecureRemoteConfiguration(t *testing.T) {
	if _, err := New("https://oast.example.test", "", "signing", nil); err == nil {
		t.Fatal("missing API token accepted")
	}
	if _, err := New("http://oast.example.test", "api", "signing", nil); err == nil {
		t.Fatal("insecure remote URL accepted")
	}
	if _, err := New("http://127.0.0.1:8787", "api", "signing", nil); err != nil {
		t.Fatalf("loopback development URL rejected: %v", err)
	}
}

func TestWaitForEventPollsUntilCallbackArrives(t *testing.T) {
	var mu sync.Mutex
	polls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer api-secret" {
			t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
		}
		mu.Lock()
		polls++
		current := polls
		mu.Unlock()
		payload := pollResponse{ProbeToken: "v1.token.signature"}
		if current >= 2 {
			payload.Events = []Event{{ID: 1, Method: "GET", Path: "/c/v1.token.signature"}}
		}
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer server.Close()

	client, err := New(server.URL, "api-secret", "signing", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	client.pollEvery = 5 * time.Millisecond
	event, err := client.WaitForEvent(context.Background(), "v1.token.signature", time.Now().Add(-time.Second), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if event == nil || event.Method != "GET" {
		t.Fatalf("event = %#v", event)
	}
}
