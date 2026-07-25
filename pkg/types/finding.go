package types

import "time"

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type Confidence string

const (
	ConfidenceConfirmed Confidence = "confirmed"
	ConfidenceLikely    Confidence = "likely"
	ConfidencePossible  Confidence = "possible"
)

// Finding represents a potential security issue discovered during analysis.
type Finding struct {
	ID          int64      `json:"id"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Severity    Severity   `json:"severity"`
	Confidence  Confidence `json:"confidence"`
	EndpointID  string     `json:"endpoint_id"`
	TrafficIDs  []int64    `json:"traffic_ids"`
	Evidence    string     `json:"evidence"`
	Remediation string     `json:"remediation,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`

	// Bug-bounty-report-style structured fields. Populated by the verifier
	// when it confirms an issue so the UI can render a proper report.
	VulnType         string `json:"vuln_type,omitempty"`          // "xss", "csrf", "sqli", "open_redirect"
	ParamName        string `json:"param_name,omitempty"`         // parameter that carries the vuln
	Payload          string `json:"payload,omitempty"`            // payload that confirmed it
	PocRequest       string `json:"poc_request,omitempty"`        // raw HTTP request that triggered
	PocResponse      string `json:"poc_response,omitempty"`       // raw response showing exploitation
	StepsToReproduce string `json:"steps_to_reproduce,omitempty"` // numbered steps
	Impact           string `json:"impact,omitempty"`             // what an attacker can do

	// HypothesisID traces this finding back to the Strategist hypothesis
	// that motivated the test chain (via the directive → probe → finding
	// path). When set AND Confidence=="confirmed", the store layer will
	// auto-transition the hypothesis to "confirmed" status. Empty for
	// findings that didn't originate from a Strategist hypothesis.
	HypothesisID string `json:"hypothesis_id,omitempty"`
}
