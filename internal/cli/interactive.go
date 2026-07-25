package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// TerminalInteractor implements agent.Interactor using stdin/stdout.
type TerminalInteractor struct {
	reader *bufio.Reader
}

// NewTerminalInteractor creates an interactor that prompts in the terminal.
func NewTerminalInteractor() *TerminalInteractor {
	return &TerminalInteractor{
		reader: bufio.NewReader(os.Stdin),
	}
}

// Ask prompts the user with a question and returns their text input.
func (t *TerminalInteractor) Ask(question string) (string, error) {
	fmt.Printf("  %s ", question)
	answer, err := t.reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(answer), nil
}

// Confirm prompts the user with a yes/no question.
func (t *TerminalInteractor) Confirm(question string) (bool, error) {
	fmt.Printf("  %s [y/N] ", question)
	answer, err := t.reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	answer = strings.TrimSpace(strings.ToLower(answer))
	return answer == "y" || answer == "yes", nil
}
