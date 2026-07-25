package proxy

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/ozzyw/aobtd/internal/observation"
	"github.com/ozzyw/aobtd/pkg/types"
)

func TestInterceptorSnapshotsProvenanceWhenRequestStarts(t *testing.T) {
	tracker := observation.NewProvenanceTracker()
	var got *types.TrafficEntry
	interceptor := NewInterceptor(func(entry *types.TrafficEntry) { got = entry },
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	interceptor.SetTrafficProvenanceResolver(tracker.SnapshotForRequest)

	end := tracker.Begin(observation.Provenance{
		SourceAgent:    "explorer",
		SourceActionID: 17,
		HypothesisID:   "h-orders",
	})
	req, err := http.NewRequest(http.MethodGet, "https://example.test/api/orders/7", nil)
	if err != nil {
		t.Fatal(err)
	}
	captured := interceptor.CaptureRequest(req)
	end()

	interceptor.CaptureResponse(captured, &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewBufferString(`{"id":7}`)),
	})
	if got == nil {
		t.Fatal("traffic callback was not invoked")
	}
	if got.SourceAgent != "explorer" || got.SourceActionID != 17 || got.HypothesisID != "h-orders" {
		t.Fatalf("captured provenance = agent=%q action=%d hypothesis=%q",
			got.SourceAgent, got.SourceActionID, got.HypothesisID)
	}
}

func TestInterceptorDefaultsToPassiveCaptureProvenance(t *testing.T) {
	var got *types.TrafficEntry
	interceptor := NewInterceptor(func(entry *types.TrafficEntry) { got = entry },
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	req, _ := http.NewRequest(http.MethodGet, "https://example.test/", nil)
	captured := interceptor.CaptureRequest(req)
	interceptor.CaptureResponse(captured, &http.Response{
		StatusCode: http.StatusNoContent,
		Header:     make(http.Header),
		Body:       http.NoBody,
	})
	if got == nil || got.SourceAgent != "capture" {
		t.Fatalf("default provenance = %#v", got)
	}
}
