package types

import "time"

// CapturedRequest represents an intercepted HTTP request.
type CapturedRequest struct {
	ID        int64             `json:"id"`
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Host      string            `json:"host"`
	Path      string            `json:"path"`
	Query     string            `json:"query,omitempty"`
	Headers   map[string]string `json:"headers"`
	Body      []byte            `json:"body,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
}

// CapturedResponse represents an intercepted HTTP response.
type CapturedResponse struct {
	StatusCode  int               `json:"status_code"`
	Headers     map[string]string `json:"headers"`
	Body        []byte            `json:"body,omitempty"`
	ContentType string            `json:"content_type"`
	Size        int64             `json:"size"`
}

// TrafficEntry pairs a request with its response.
type TrafficEntry struct {
	ID             int64            `json:"id"`
	Request        CapturedRequest  `json:"request"`
	Response       CapturedResponse `json:"response"`
	EndpointHash   string           `json:"endpoint_hash"`
	SourceAgent    string           `json:"source_agent,omitempty"`
	SourceActionID int64            `json:"source_action_id,omitempty"`
	HypothesisID   string           `json:"hypothesis_id,omitempty"`
	Filtered       bool             `json:"filtered"`
	Timestamp      time.Time        `json:"timestamp"`
}
