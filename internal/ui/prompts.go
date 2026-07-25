package ui

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// handlePromptsList returns interactive prompts for a scan. Powers the
// UI's notification bell — the bell shows a count based on the length
// of this list.
//
// Query params:
//   scan_id — required (default: latest scan)
//   status  — "open" (unanswered, default) | "answered" | "all"
func (s *Server) handlePromptsList(w http.ResponseWriter, r *http.Request) {
	scanID := s.scanIDFromRequest(r)
	status := strings.ToLower(r.URL.Query().Get("status"))
	if status == "" {
		status = "open"
	}

	var prompts any
	var err error
	switch status {
	case "open":
		prompts, err = s.db.ListOpenPrompts(scanID)
	case "all":
		// Quick path: pull open + pending-answers back separately.
		open, e1 := s.db.ListOpenPrompts(scanID)
		if e1 != nil {
			jsonError(w, e1.Error(), 500)
			return
		}
		pending, e2 := s.db.ListPendingAnswers(scanID)
		if e2 != nil {
			jsonError(w, e2.Error(), 500)
			return
		}
		merged := append([]any{}, toAny(open)...)
		merged = append(merged, toAny(pending)...)
		prompts = merged
	default:
		prompts, err = s.db.ListOpenPrompts(scanID)
	}
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	jsonResponse(w, prompts)
}

// handlePromptAnswer delivers the operator's answer for a prompt. The
// scanner's background poller (cli/prompt_poll.go) picks it up within
// a few seconds and acts — e.g. runs login if the prompt kind is
// login_found.
//
// URL: /api/prompts/:id/answer  (POST, JSON body is the answer payload)
func (s *Server) handlePromptAnswer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "POST required", 405)
		return
	}

	// Parse prompt id from path tail: /api/prompts/{id}/answer
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 {
		jsonError(w, "path should be /api/prompts/{id}/answer", 400)
		return
	}
	promptID, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || promptID <= 0 {
		jsonError(w, "invalid prompt id", 400)
		return
	}

	// Validate the prompt exists and is still open.
	p, err := s.db.GetPrompt(promptID)
	if err != nil {
		jsonError(w, "prompt not found: "+err.Error(), 404)
		return
	}
	if p.AnsweredAt != nil {
		jsonError(w, "prompt already answered", 409)
		return
	}

	// Body is whatever the prompt kind expects. For login_found it's
	// {username, password, skip}. Store as-is; the scanner interprets.
	var answer map[string]any
	if err := json.NewDecoder(r.Body).Decode(&answer); err != nil {
		jsonError(w, "invalid JSON body: "+err.Error(), 400)
		return
	}
	if err := s.db.AnswerPrompt(promptID, answer); err != nil {
		jsonError(w, "store answer: "+err.Error(), 500)
		return
	}
	jsonResponse(w, map[string]any{"ok": true, "prompt_id": promptID})
}

// toAny is a cheap reflection-free conversion used above to merge two
// typed slices into a single []any for JSON output.
func toAny[T any](in []T) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}
