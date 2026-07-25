package proxy

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ozzyw/aobtd/internal/observation"
	"github.com/ozzyw/aobtd/pkg/types"
)

// TrafficCallback is called for each captured request/response pair.
type TrafficCallback func(entry *types.TrafficEntry)

const maxCapturedBodyBytes int64 = 1 << 20

type replayReadCloser struct {
	io.Reader
	closer io.Closer
}

func (r *replayReadCloser) Close() error {
	return r.closer.Close()
}

// Interceptor captures HTTP traffic passing through the proxy.
type Interceptor struct {
	callback TrafficCallback
	logger   *slog.Logger

	provenanceMu       sync.RWMutex
	provenanceResolver observation.ProvenanceResolver
	pendingProvenance  sync.Map // map[*types.CapturedRequest]observation.Provenance
	forcedFiltered     sync.Map // map[*types.CapturedRequest]struct{}
}

// NewInterceptor creates an interceptor that calls cb for each captured pair.
func NewInterceptor(cb TrafficCallback, logger *slog.Logger) *Interceptor {
	return &Interceptor{
		callback: cb,
		logger:   logger,
	}
}

// SetTrafficProvenanceResolver configures request-time attribution. Provenance
// is snapshotted in CaptureRequest so a delayed response cannot be mislabeled
// after the active browser agent changes.
func (i *Interceptor) SetTrafficProvenanceResolver(resolver observation.ProvenanceResolver) {
	i.provenanceMu.Lock()
	i.provenanceResolver = resolver
	i.provenanceMu.Unlock()
}

func (i *Interceptor) currentTrafficProvenance(req *http.Request) observation.Provenance {
	i.provenanceMu.RLock()
	resolver := i.provenanceResolver
	i.provenanceMu.RUnlock()
	if resolver == nil {
		return observation.Provenance{}.Normalize()
	}
	requestURL, referer := "", ""
	if req != nil {
		if req.URL != nil {
			requestURL = req.URL.String()
		}
		referer = req.Header.Get("Referer")
	}
	return resolver(requestURL, referer).Normalize()
}

// CaptureRequest extracts request data. Called in the proxy request handler.
func (i *Interceptor) CaptureRequest(req *http.Request) *types.CapturedRequest {
	return i.captureRequest(req, false)
}

// captureRequest optionally marks a request as permanently filtered. The bit
// is consumed in CaptureResponse before the callback, so no downstream queue
// can mistake a permitted off-scope paint dependency for target evidence.
func (i *Interceptor) captureRequest(req *http.Request, forceFiltered bool) *types.CapturedRequest {
	headers := make(map[string]string)
	for k, v := range req.Header {
		headers[k] = strings.Join(v, "; ")
	}

	var body []byte
	if req.Body != nil {
		var truncated bool
		var err error
		body, req.Body, truncated, _, err = captureBodyPrefix(req.Body, maxCapturedBodyBytes)
		if err != nil {
			i.logger.Warn("request body capture failed", "url", req.URL.String(), "error", err)
		} else if truncated {
			i.logger.Debug("request body capture truncated", "url", req.URL.String(), "limit", maxCapturedBodyBytes)
		}
	}

	parsed := req.URL
	if parsed.Host == "" {
		parsed.Host = req.Host
	}

	captured := &types.CapturedRequest{
		Method:    req.Method,
		URL:       parsed.String(),
		Host:      req.Host,
		Path:      parsed.Path,
		Query:     parsed.RawQuery,
		Headers:   headers,
		Body:      body,
		Timestamp: time.Now(),
	}
	i.pendingProvenance.Store(captured, i.currentTrafficProvenance(req))
	if forceFiltered {
		i.forcedFiltered.Store(captured, struct{}{})
	}
	return captured
}

// CaptureResponse extracts response data and emits the full traffic entry.
func (i *Interceptor) CaptureResponse(captured *types.CapturedRequest, resp *http.Response) *types.TrafficEntry {
	if captured == nil {
		return nil
	}
	provenance := observation.Provenance{}.Normalize()
	if value, ok := i.pendingProvenance.LoadAndDelete(captured); ok {
		if resolved, typeOK := value.(observation.Provenance); typeOK {
			provenance = resolved
		}
	}
	_, forceFiltered := i.forcedFiltered.LoadAndDelete(captured)
	if resp == nil {
		return nil
	}

	headers := make(map[string]string)
	for k, v := range resp.Header {
		headers[k] = strings.Join(v, "; ")
	}

	var body []byte
	var observedSize int64
	if forceFiltered {
		// Passive off-scope assets exist only to paint the browser. Do not read,
		// replace, or persist any of their body bytes; Content-Length is enough
		// metadata for the already-filtered traffic row.
		if resp.ContentLength > 0 {
			observedSize = resp.ContentLength
		}
	} else if resp.Body != nil {
		var truncated bool
		var err error
		body, resp.Body, truncated, observedSize, err = captureBodyPrefix(resp.Body, maxCapturedBodyBytes)
		if err != nil {
			i.logger.Warn("response body capture failed", "url", captured.URL, "error", err)
		} else if truncated {
			i.logger.Debug("response body capture truncated", "url", captured.URL, "limit", maxCapturedBodyBytes)
		}
	}
	if !forceFiltered && resp.ContentLength > observedSize {
		observedSize = resp.ContentLength
	}

	contentType := resp.Header.Get("Content-Type")

	// Apply coarse filter
	filtered := forceFiltered || ShouldFilter(captured.URL, contentType, observedSize)

	entry := &types.TrafficEntry{
		Request: *captured,
		Response: types.CapturedResponse{
			StatusCode:  resp.StatusCode,
			Headers:     headers,
			Body:        body,
			ContentType: contentType,
			Size:        observedSize,
		},
		EndpointHash: ComputeEndpointHash(captured.Method, captured.URL),
		Filtered:     filtered,
		Timestamp:    time.Now(),
	}
	provenance.Apply(entry)

	if filtered {
		i.logger.Debug("filtered traffic", "url", captured.URL, "content_type", contentType)
	} else {
		i.logger.Info("captured traffic",
			"method", captured.Method,
			"url", captured.URL,
			"status", resp.StatusCode,
			"size", len(body),
		)
	}

	i.callback(entry)
	return entry
}

// captureBodyPrefix stores at most limit bytes while rebuilding a reader that
// yields every byte consumed during capture followed by the untouched remainder.
// The upstream server or browser therefore sees the original body unchanged.
func captureBodyPrefix(body io.ReadCloser, limit int64) ([]byte, io.ReadCloser, bool, int64, error) {
	if body == nil {
		return nil, nil, false, 0, nil
	}
	if limit <= 0 {
		return nil, body, false, 0, nil
	}

	consumed, err := io.ReadAll(io.LimitReader(body, limit+1))
	observed := int64(len(consumed))
	truncated := observed > limit
	captured := consumed
	if truncated {
		captured = consumed[:limit]
	}
	replayed := &replayReadCloser{
		Reader: io.MultiReader(bytes.NewReader(consumed), body),
		closer: body,
	}
	return captured, replayed, truncated, observed, err
}

// ComputeEndpointHash creates a normalized hash for deduplication.
// Method + normalized path (IDs replaced) + sorted param keys.
func ComputeEndpointHash(method, rawURL string) string {
	return observation.EndpointHash(method, rawURL)
}
