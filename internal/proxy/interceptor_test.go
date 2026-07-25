package proxy

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/ozzyw/aobtd/pkg/types"
)

type trackedReadCloser struct {
	*bytes.Reader
	closed bool
}

func (r *trackedReadCloser) Close() error {
	r.closed = true
	return nil
}

func TestCaptureBodyPrefixPreservesFullStream(t *testing.T) {
	payload := bytes.Repeat([]byte("abcdef"), int(maxCapturedBodyBytes/6)+20)
	original := &trackedReadCloser{Reader: bytes.NewReader(payload)}

	captured, replayed, truncated, observed, err := captureBodyPrefix(original, maxCapturedBodyBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated || len(captured) != int(maxCapturedBodyBytes) {
		t.Fatalf("capture = %d bytes truncated=%v", len(captured), truncated)
	}
	if observed != maxCapturedBodyBytes+1 {
		t.Fatalf("observed = %d, want %d", observed, maxCapturedBodyBytes+1)
	}
	got, err := io.ReadAll(replayed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("replayed body differs: got=%d want=%d", len(got), len(payload))
	}
	if err := replayed.Close(); err != nil {
		t.Fatal(err)
	}
	if !original.closed {
		t.Fatal("closing replayed body did not close original body")
	}
}

func TestCaptureResponseCapsStoredBodyButPreservesClientBody(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), int(maxCapturedBodyBytes)+128)
	var captured *types.TrafficEntry
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	interceptor := NewInterceptor(func(entry *types.TrafficEntry) { captured = entry }, logger)
	request := &types.CapturedRequest{
		Method: "GET", URL: "https://example.test/large", Host: "example.test",
		Path: "/large", Timestamp: time.Now(),
	}
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": []string{"text/html"}},
		Body:          io.NopCloser(bytes.NewReader(payload)),
		ContentLength: int64(len(payload)),
	}

	interceptor.CaptureResponse(request, resp)
	if captured == nil {
		t.Fatal("callback was not invoked")
	}
	if len(captured.Response.Body) != int(maxCapturedBodyBytes) {
		t.Fatalf("stored body = %d bytes", len(captured.Response.Body))
	}
	if captured.Response.Size != int64(len(payload)) || !captured.Filtered {
		t.Fatalf("size=%d filtered=%v", captured.Response.Size, captured.Filtered)
	}
	replayed, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(replayed, payload) {
		t.Fatalf("client body differs: got=%d want=%d", len(replayed), len(payload))
	}
}

func TestCaptureResponseHonorsForcedFilterBeforeCallback(t *testing.T) {
	payload := []byte("window.appReady = true")
	var captured *types.TrafficEntry
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	interceptor := NewInterceptor(func(entry *types.TrafficEntry) {
		if !entry.Filtered {
			t.Fatal("callback observed passive dependency before it was filtered")
		}
		captured = entry
	}, logger)
	req, err := http.NewRequest(http.MethodGet, "https://cdn.example.test/runtime.js", nil)
	if err != nil {
		t.Fatal(err)
	}
	request := interceptor.captureRequest(req, true)
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": []string{"application/javascript"}},
		Body:          io.NopCloser(bytes.NewReader(payload)),
		ContentLength: int64(len(payload)),
	}
	originalBody := resp.Body

	interceptor.CaptureResponse(request, resp)
	if captured == nil {
		t.Fatal("callback was not invoked")
	}
	if !captured.Filtered {
		t.Fatal("forced passive dependency was not filtered")
	}
	if len(captured.Response.Body) != 0 || captured.Response.Size != int64(len(payload)) {
		t.Fatalf("captured passive body/size = %d/%d, want 0/%d", len(captured.Response.Body), captured.Response.Size, len(payload))
	}
	if resp.Body != originalBody {
		t.Fatal("forced passive response body reader was replaced")
	}
	replayed, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(replayed, payload) {
		t.Fatalf("browser body changed: got %q want %q", replayed, payload)
	}
	if ShouldFilter(request.URL, resp.Header.Get("Content-Type"), captured.Response.Size) {
		t.Fatal("test fixture was already covered by the coarse filter")
	}
}
