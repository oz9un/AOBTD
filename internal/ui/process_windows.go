//go:build windows

package ui

import (
	"errors"
	"os"
	"os/exec"
)

func configureScanProcess(cmd *exec.Cmd) {}

func interruptScanProcess(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return errors.New("scan process is not running")
	}
	return cmd.Process.Signal(os.Interrupt)
}

func killScanProcess(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return errors.New("scan process is not running")
	}
	return cmd.Process.Kill()
}
