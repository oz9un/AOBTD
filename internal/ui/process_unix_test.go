//go:build !windows

package ui

import (
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestConfigureScanProcessCreatesKillableProcessGroup(t *testing.T) {
	cmd := exec.Command("sh", "-c", "sleep 30")
	configureScanProcess(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	pgid, err := syscall.Getpgid(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if pgid != cmd.Process.Pid {
		t.Fatalf("process group = %d, want %d", pgid, cmd.Process.Pid)
	}
	if err := killScanProcess(cmd); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("process group did not terminate")
	}
}
