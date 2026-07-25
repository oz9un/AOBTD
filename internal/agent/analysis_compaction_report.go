package agent

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/internal/protection"
	"github.com/ozzyw/aobtd/internal/store"
)

type AnalysisCompactionReport struct {
	ScanID                  int64                     `json:"scan_id"`
	CapturedFamilies        int                       `json:"captured_families"`
	PassiveClosed           int                       `json:"passive_closed"`
	SemanticCandidates      int                       `json:"semantic_candidates"`
	SemanticRepresentatives int                       `json:"semantic_representatives"`
	EquivalentCallsSaved    int                       `json:"equivalent_calls_saved"`
	CallReductionPercent    float64                   `json:"call_reduction_percent"`
	ProtectionFamilies      int                       `json:"protection_families"`
	ProtectionShapes        int                       `json:"protection_shapes"`
	ProtectionSpecimens     int                       `json:"protection_specimens"`
	ProtectionDuplicates    int                       `json:"protection_duplicates_compacted"`
	RecoveredApplications   int                       `json:"recovered_application_families"`
	ProtectionServerErrors  int                       `json:"protection_server_error_families_preserved"`
	Groups                  []AnalysisCompactionGroup `json:"groups"`
}

type AnalysisCompactionGroup struct {
	Representative string   `json:"representative"`
	Equivalent     []string `json:"equivalent"`
}

// ReplayAnalysisCompaction replays the deterministic pre-model guards against
// saved traffic. It performs no network activity and writes nothing; the
// result answers how many endpoint-family model calls the current build would
// need from the evidence already captured by an older scan.
func ReplayAnalysisCompaction(db *store.DB, scanID int64) (AnalysisCompactionReport, error) {
	report := AnalysisCompactionReport{ScanID: scanID, Groups: []AnalysisCompactionGroup{}}
	if db == nil || scanID == 0 {
		return report, nil
	}
	rows, err := db.Conn().Query(`
		SELECT endpoint_hash
		FROM traffic
		WHERE scan_id = ? AND is_filtered = FALSE AND is_duplicate = FALSE
		  AND endpoint_hash != ''
		GROUP BY endpoint_hash ORDER BY MIN(id)`, scanID)
	if err != nil {
		return report, fmt.Errorf("list compaction endpoint families: %w", err)
	}
	hashes := make([]string, 0)
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			rows.Close()
			return report, err
		}
		hashes = append(hashes, hash)
	}
	if err := rows.Close(); err != nil {
		return report, err
	}
	report.CapturedFamilies = len(hashes)

	representativeByFingerprint := make(map[string]string)
	groupByRepresentative := make(map[string][]string)
	protectionShapes := make(map[string]bool)
	for _, hash := range hashes {
		entries, err := db.GetTrafficByEndpointHash(scanID, hash)
		if err != nil {
			return report, err
		}
		bundle := extract.BuildEndpointBundle(entries, 20)
		if bundle == nil {
			continue
		}
		protectionSummary := protection.SummarizeTraffic(entries)
		if protectionSummary.InterstitialResponses > 0 {
			report.ProtectionFamilies++
			newShape := false
			for _, fingerprint := range protectionSummary.Fingerprints {
				if !protectionShapes[fingerprint] {
					newShape = true
					protectionShapes[fingerprint] = true
				}
			}
			if protectionSummary.RecoveredApplication {
				report.RecoveredApplications++
			}
			if protectionSummary.ServerErrors > 0 {
				report.ProtectionServerErrors++
			}
			if protectionSummary.ChallengeOnly {
				if !newShape {
					report.ProtectionDuplicates++
				}
			}
		}
		if deepAnalysisSkipReason(entries, bundle) != "" {
			report.PassiveClosed++
			continue
		}
		report.SemanticCandidates++
		fingerprint := analysisFingerprint(entries, bundle)
		label := strings.TrimSpace(bundle.Method + " " + firstNonEmpty(bundle.URLPattern, bundle.SampleURL))
		if fingerprint == "" {
			fingerprint = "endpoint:" + hash
		}
		if representative := representativeByFingerprint[fingerprint]; representative != "" {
			report.EquivalentCallsSaved++
			groupByRepresentative[representative] = append(groupByRepresentative[representative], label)
			continue
		}
		representativeByFingerprint[fingerprint] = label
		report.SemanticRepresentatives++
	}
	report.ProtectionShapes = len(protectionShapes)
	report.ProtectionSpecimens = report.ProtectionShapes
	if report.SemanticCandidates > 0 {
		report.CallReductionPercent = float64(report.EquivalentCallsSaved) * 100 / float64(report.SemanticCandidates)
	}
	for representative, equivalents := range groupByRepresentative {
		sort.Strings(equivalents)
		report.Groups = append(report.Groups, AnalysisCompactionGroup{Representative: representative, Equivalent: equivalents})
	}
	sort.Slice(report.Groups, func(i, j int) bool {
		if len(report.Groups[i].Equivalent) != len(report.Groups[j].Equivalent) {
			return len(report.Groups[i].Equivalent) > len(report.Groups[j].Equivalent)
		}
		return report.Groups[i].Representative < report.Groups[j].Representative
	})
	return report, nil
}
