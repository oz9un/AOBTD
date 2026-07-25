package types

import "time"

// Input represents a form field, query param, or JSON body field.
type Input struct {
	Name         string `json:"name"`
	Type         string `json:"type"`     // text, email, password, number, file, hidden, etc.
	Location     string `json:"location"` // form, query, body, path
	Required     bool   `json:"required"`
	DefaultValue string `json:"default_value,omitempty"`
	// Label is the human-readable label associated with the input when we
	// have one (HTML <label>, placeholder, or name-derived). Shown to the
	// user so the UI can explain "what is this field?" without an LLM call.
	Label string `json:"label,omitempty"`
	// Explanation is a short, heuristic description of what the input is
	// for ("user's email — credential field", "search query — user-supplied
	// string, likely reflected"). Produced by extract.ExplainInput at zero
	// cost; the LLM can supplement but isn't required. This powers the UI's
	// "what does this input do" hover / inline annotation.
	Explanation string `json:"explanation,omitempty"`
}

// PageProfile is the LLM-generated documentation for a page or endpoint.
type PageProfile struct {
	ID            string    `json:"id"`
	URL           string    `json:"url"`
	Method        string    `json:"method,omitempty"`
	Purpose       string    `json:"purpose"`
	Inputs        []Input   `json:"inputs,omitempty"`
	AuthRequired  string    `json:"auth_required"`
	DataExposed   []string  `json:"data_exposed,omitempty"`
	APIsCalled    []string  `json:"apis_called,omitempty"`
	Behaviors     []string  `json:"behaviors,omitempty"`
	Relationships []string  `json:"relationships,omitempty"`
	Issues        []string  `json:"issues,omitempty"`
	TechNotes     string    `json:"tech_notes,omitempty"`
	LastUpdated   time.Time `json:"last_updated"`
	Confidence    float64   `json:"confidence"`
	TemplateID    string    `json:"template_id,omitempty"`
	// Observed classification flags. These come from concrete traffic
	// extraction rather than model prose, and are persisted so UI summaries and
	// benchmark scorecards can distinguish JSON/API endpoints from plain pages.
	HasInput      bool `json:"has_input,omitempty"`
	HasFileUpload bool `json:"has_file_upload,omitempty"`
	HasAuth       bool `json:"has_auth,omitempty"`
	HasErrors     bool `json:"has_errors,omitempty"`
	IsAPI         bool `json:"is_api,omitempty"`
	// EvidenceState is a response-backed UI verdict populated at read time.
	// It is intentionally not persisted in page_profiles: the underlying
	// traffic remains authoritative and a later direct 2xx can lift a route
	// out of redirect-only state without rewriting model prose.
	EvidenceState     string   `json:"evidence_state,omitempty"`
	EvidenceNote      string   `json:"evidence_note,omitempty"`
	ObservedStatuses  []int    `json:"observed_statuses,omitempty"`
	RedirectLocations []string `json:"redirect_locations,omitempty"`
	// ExtractedInputs are inputs found by the HTML/param extractor (zero LLM cost).
	// These are always complete — the LLM supplements but doesn't replace them.
	ExtractedInputs []Input `json:"extracted_inputs,omitempty"`
}
