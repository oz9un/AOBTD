// Package externalrecon adapts Enumeraite's stable JSON envelope to AOBTD.
package externalrecon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type Config struct {
	Binary            string
	Sources           []string
	IncludeSubdomains bool
	Limit             int
	DNSEnumeration    bool
	ValidateHTTP      bool
	VHostEnumeration  bool
	Timeout           time.Duration
}

type SourceError struct {
	Source  string `json:"source"`
	Message string `json:"message"`
}

type Observation struct {
	SchemaVersion string         `json:"schema_version"`
	Target        string         `json:"target"`
	AssetType     string         `json:"asset_type"`
	Value         string         `json:"value"`
	Source        string         `json:"source"`
	State         string         `json:"state"`
	Confidence    float64        `json:"confidence"`
	ObservedAt    string         `json:"observed_at"`
	InScope       bool           `json:"in_scope"`
	Evidence      map[string]any `json:"evidence"`
}

type Result struct {
	SchemaVersion string        `json:"schema_version"`
	Target        string        `json:"target"`
	Sources       []string      `json:"sources"`
	Observations  []Observation `json:"observations"`
	Errors        []SourceError `json:"errors"`
}

func Run(ctx context.Context, target string, cfg Config) (Result, string, error) {
	var result Result
	bin, err := resolveBinary(cfg.Binary)
	if err != nil {
		return result, "", err
	}
	if cfg.Limit <= 0 {
		cfg.Limit = 500
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 90 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	args := []string{"recon", target, "--format", "json", "--limit", fmt.Sprint(cfg.Limit)}
	for _, source := range cfg.Sources {
		if source = strings.TrimSpace(source); source != "" {
			args = append(args, "--source", source)
		}
	}
	if cfg.IncludeSubdomains {
		args = append(args, "--include-subdomains")
	}
	if cfg.DNSEnumeration {
		args = append(args, "--dns-enumeration")
	}
	if cfg.ValidateHTTP {
		args = append(args, "--validate-http")
	}
	if cfg.VHostEnumeration {
		args = append(args, "--vhost-enumeration")
	}

	cmd := exec.CommandContext(ctx, bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	if ctx.Err() != nil {
		return result, stderr.String(), fmt.Errorf("enumeraite recon timed out after %s", cfg.Timeout)
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		if runErr != nil {
			return result, stderr.String(), fmt.Errorf("enumeraite recon failed: %w: %s", runErr, strings.TrimSpace(stderr.String()))
		}
		return result, stderr.String(), fmt.Errorf("decode enumeraite JSON: %w", err)
	}
	if majorVersion(result.SchemaVersion) != "1" {
		return result, stderr.String(), fmt.Errorf("unsupported enumeraite schema version %q", result.SchemaVersion)
	}
	// A partial-source failure intentionally returns useful observations.
	if runErr != nil && len(result.Observations) == 0 {
		return result, stderr.String(), fmt.Errorf("enumeraite recon failed: %w", runErr)
	}
	return result, stderr.String(), nil
}

func resolveBinary(configured string) (string, error) {
	candidates := []string{strings.TrimSpace(configured), strings.TrimSpace(os.Getenv("AOBTD_ENUMERAITE_BIN"))}
	if found, err := exec.LookPath("enumeraite"); err == nil {
		candidates = append(candidates, found)
	}
	for _, relative := range []string{"../enumeraite/.venv/bin/enumeraite", "./enumeraite/.venv/bin/enumeraite"} {
		if absolute, err := filepath.Abs(relative); err == nil {
			candidates = append(candidates, absolute)
		}
	}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", errors.New("enumeraite executable not found; set --enumeraite-bin or AOBTD_ENUMERAITE_BIN")
}

func majorVersion(version string) string {
	version = strings.TrimSpace(version)
	if before, _, ok := strings.Cut(version, "."); ok {
		return before
	}
	return version
}
