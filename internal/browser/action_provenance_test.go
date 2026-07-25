package browser

import (
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
)

func TestControllerRecordsActionAndScopesProvenance(t *testing.T) {
	controller := NewController("127.0.0.1:8080", true,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	endAgent := controller.BeginTrafficProvenance("navigator", 0, "h-account")
	defer endAgent()

	var completedStatus, completedResult, completedURL string
	controller.SetTrafficActionRecorder(func(agent, action, reason, fromURL, toURL, hypothesisID string) (int64, TrafficActionCompletion, error) {
		if agent != "navigator" || action != "click" || reason != "open account" || hypothesisID != "h-account" {
			t.Fatalf("recorded action = %q/%q/%q hypothesis=%q", agent, action, reason, hypothesisID)
		}
		return 77, func(status, result, finalURL string) error {
			completedStatus, completedResult, completedURL = status, result, finalURL
			return nil
		}, nil
	})

	finish := controller.beginTrafficAction("click", "open account", "https://example.test/", "")
	if got := controller.TrafficProvenance(); got.SourceActionID != 77 || got.HypothesisID != "h-account" {
		t.Fatalf("active provenance = %+v", got)
	}
	finish(errors.New("element detached"), "https://example.test/")
	finish(nil, "ignored")
	if completedStatus != "failed" || completedResult != "element detached" || completedURL != "https://example.test/" {
		t.Fatalf("completion = %q/%q/%q", completedStatus, completedResult, completedURL)
	}
	if got := controller.TrafficProvenance(); got.SourceActionID != 0 || got.SourceAgent != "navigator" {
		t.Fatalf("restored provenance = %+v", got)
	}
}

func TestControllerRecordsConcurrentTargetedActions(t *testing.T) {
	controller := NewController("127.0.0.1:8080", true,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	endAgent := controller.BeginTrafficProvenance("crawler", 0, "")
	defer endAgent()

	var nextID atomic.Int64
	controller.SetTrafficActionRecorder(func(agent, action, reason, fromURL, toURL, hypothesisID string) (int64, TrafficActionCompletion, error) {
		return nextID.Add(1), func(status, result, finalURL string) error { return nil }, nil
	})
	finishA := controller.beginTrafficAction("navigate", "crawl page", "", "https://example.test/a")
	finishB := controller.beginTrafficAction("navigate", "crawl page", "", "https://example.test/b")
	defer finishA(nil, "https://example.test/a")
	defer finishB(nil, "https://example.test/b")

	if nextID.Load() != 2 {
		t.Fatalf("recorded actions = %d, want 2", nextID.Load())
	}
	if got := controller.TrafficProvenanceForRequest("https://example.test/a", ""); got.SourceActionID != 1 {
		t.Fatalf("target A provenance = %+v", got)
	}
	if got := controller.TrafficProvenanceForRequest("https://example.test/b", ""); got.SourceActionID != 2 {
		t.Fatalf("target B provenance = %+v", got)
	}
}
