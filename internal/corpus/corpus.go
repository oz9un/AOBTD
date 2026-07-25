// Package corpus loads industry-standard wordlists used by proactive probes.
// Files are embedded at build time via `go:embed` so the binary stays
// self-contained.
//
// Everything here deliberately avoids application-specific knowledge — the
// wordlists are general-purpose (SecLists / Nuclei / Dirb class). Target-
// specific intelligence belongs in probe-discovery helpers (extracted from
// captured traffic) or in the Strategist's LLM reasoning, not here.
package corpus

import (
	"bufio"
	_ "embed"
	"strings"
)

//go:embed common_exposure_paths.txt
var commonExposurePathsRaw string

//go:embed default_credentials.txt
var defaultCredentialsRaw string

//go:embed version_disclosure_paths.txt
var versionDisclosurePathsRaw string

// parseList strips blank lines and comments from a wordlist file.
func parseList(raw string) []string {
	var out []string
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// CommonExposurePaths returns the curated list of high-value paths that
// commonly leak unauthenticated — VCS, config, debug, metrics, docs.
// NOT application-specific; every entry applies to broad classes of
// web applications.
func CommonExposurePaths() []string {
	return parseList(commonExposurePathsRaw)
}

// DefaultCredentialPair is a (username, password) tuple from the wordlist.
type DefaultCredentialPair struct {
	Username string
	Password string
}

// DefaultCredentials returns the curated default-credentials wordlist.
// Each entry is formatted `user:pass`; lines with multiple colons are
// preserved intact in the Password field (supporting passwords that
// contain colons).
func DefaultCredentials() []DefaultCredentialPair {
	var out []DefaultCredentialPair
	for _, line := range parseList(defaultCredentialsRaw) {
		i := strings.Index(line, ":")
		if i < 1 || i == len(line)-1 {
			continue
		}
		out = append(out, DefaultCredentialPair{
			Username: line[:i],
			Password: line[i+1:],
		})
	}
	return out
}

// VersionDisclosurePaths returns the curated list of version-disclosure
// endpoints. Used by probeOutdatedVersion to discover the target's
// advertised version independent of application-specific knowledge.
func VersionDisclosurePaths() []string {
	return parseList(versionDisclosurePathsRaw)
}
