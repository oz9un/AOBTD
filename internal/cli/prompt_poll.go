package cli

import (
	"context"
	"log/slog"
	"time"

	"github.com/ozzyw/aobtd/internal/agent"
	"github.com/ozzyw/aobtd/internal/browser"
	"github.com/ozzyw/aobtd/internal/llm"
	"github.com/ozzyw/aobtd/internal/store"
)

// runPromptPollLoop is the scanner-side counterpart to the UI's
// notification bell. Every few seconds it asks the DB "any prompts the
// operator has answered but I haven't acted on yet?" and, for each,
// dispatches the appropriate handler.
//
// The scanner NEVER blocks on this — the scan itself proceeds
// unauthenticated. If the operator clicks the notification bell mid-
// scan and enters credentials, this loop picks them up and runs the
// login against the still-alive browser so future crawler requests
// carry the cookies.
//
// Currently handles one prompt kind: "login_found" → run
// AuthAgent.AttemptDirectLogin with the supplied username/password.
// More kinds (register_found, sso_detected, mfa_prompt) can be added
// by extending the switch below.
func runPromptPollLoop(
	ctx context.Context,
	db *store.DB,
	bc *browser.Controller,
	provider llm.Provider,
	budget *llm.Budget,
	scanID int64,
	target string,
	logger *slog.Logger,
) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pending, err := db.ListPendingAnswers(scanID)
			if err != nil {
				logger.Debug("prompt poll query failed", "error", err)
				continue
			}
			for _, p := range pending {
				handlePromptAnswer(ctx, db, bc, provider, budget, p, scanID, target, logger)
			}
		}
	}
}

// handlePromptAnswer dispatches one answered prompt to its handler.
// After the handler runs, mark the prompt handled so we don't act
// on it twice on the next tick.
func handlePromptAnswer(
	ctx context.Context,
	db *store.DB,
	bc *browser.Controller,
	provider llm.Provider,
	budget *llm.Budget,
	p store.Prompt,
	scanID int64,
	target string,
	logger *slog.Logger,
) {
	defer func() {
		if err := db.MarkPromptHandled(p.ID); err != nil {
			logger.Warn("failed to mark prompt handled", "prompt_id", p.ID, "error", err)
		}
	}()

	switch p.Kind {
	case "login_found":
		handleLoginAnswer(ctx, db, bc, provider, budget, p, scanID, target, logger)
	default:
		logger.Warn("unknown prompt kind received — ignoring",
			"prompt_id", p.ID, "kind", p.Kind)
	}
}

// handleLoginAnswer runs AuthAgent.AttemptDirectLogin with the user-
// supplied credentials from a login_found prompt answer. The login
// page URL and the submit URL both live in the prompt's payload;
// AuthAgent handles the rest (form fill + submit + success detection
// + session-cookie hardening).
func handleLoginAnswer(
	ctx context.Context,
	db *store.DB,
	bc *browser.Controller,
	provider llm.Provider,
	budget *llm.Budget,
	p store.Prompt,
	scanID int64,
	target string,
	logger *slog.Logger,
) {
	type loginPayload struct {
		PageURL   string `json:"page_url"`
		SubmitURL string `json:"submit_url"`
	}
	type loginAnswer struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Skip     bool   `json:"skip"` // user explicitly opted out — no login attempt
	}

	payload, err := store.PayloadAs[loginPayload](p)
	if err != nil {
		logger.Warn("login prompt payload malformed", "error", err)
		return
	}
	answer, err := store.AnswerAs[loginAnswer](p)
	if err != nil {
		logger.Warn("login prompt answer malformed", "error", err)
		return
	}
	if answer.Skip {
		db.InsertNarration(scanID, "auth", "skipped",
			"Operator declined to log in — scan continues unauthenticated.",
			payload.PageURL, nil)
		return
	}
	if answer.Username == "" || answer.Password == "" {
		db.InsertNarration(scanID, "auth", "failed",
			"Login answer arrived without credentials — scan continues unauthenticated.",
			payload.PageURL, nil)
		return
	}

	// Give AuthAgent a minimal shared-state + bus. We're outside the
	// orchestrator's run loop, so we build throwaway instances; nothing
	// downstream consumes their events here.
	sharedState := agent.NewSharedState(target)
	bus := agent.NewBus(logger)
	auth := agent.NewAuthAgent(db, bc, provider, bus, sharedState, scanID, nil, logger)
	auth.SetBudget(budget)
	auth.SetCredentials(answer.Username, answer.Password, nil)

	loginURL := payload.PageURL
	if loginURL == "" {
		loginURL = payload.SubmitURL
	}

	logger.Info("operator provided credentials — attempting login",
		"prompt_id", p.ID, "login_url", loginURL, "user", answer.Username)
	db.InsertNarration(scanID, "auth", "operator_login",
		"Operator provided credentials via the notification bell — running login now.",
		loginURL, map[string]any{"prompt_id": p.ID, "user": answer.Username})

	ok, err := auth.AttemptDirectLogin(ctx, loginURL)
	if err != nil {
		logger.Warn("operator-triggered login errored", "error", err)
		return
	}
	logger.Info("operator-triggered login result", "success", ok)
}
