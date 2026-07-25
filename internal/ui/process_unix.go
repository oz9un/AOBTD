//go:build !windows

package ui

import (
	"errors"
	"os/exec"
	"syscall"
)

func configureScanProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func interruptScanProcess(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return errors.New("scan process is not running")
	}
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
}

func killScanProcess(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return errors.New("scan process is not running")
	}
	err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}
