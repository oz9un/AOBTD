package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ozzyw/aobtd/internal/store"
	"github.com/spf13/cobra"
)

// NewReportCmd creates the `aobtd report` command.
func NewReportCmd() *cobra.Command {
	var (
		inputDir string
		format   string
	)

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate a report from scan data",
		Long:  "Read captured traffic from a scan database and output a structured report.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReport(inputDir, format)
		},
	}

	cmd.Flags().StringVarP(&inputDir, "input", "i", "./aobtd-output", "Directory containing scan.db")
	cmd.Flags().StringVarP(&format, "format", "f", "json", "Output format: json, summary")

	return cmd
}

func runReport(inputDir, format string) error {
	dbPath := filepath.Join(inputDir, "scan.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return fmt.Errorf("no scan database found at %s", dbPath)
	}

	db, err := store.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	// Get the latest scan
	var scanID int64
	var target, status string
	err = db.Conn().QueryRow(
		`SELECT id, target, status FROM scans ORDER BY id DESC LIMIT 1`,
	).Scan(&scanID, &target, &status)
	if err != nil {
		return fmt.Errorf("no scans found: %w", err)
	}

	switch format {
	case "json":
		return reportJSON(db, scanID, target)
	case "summary":
		return reportSummary(db, scanID, target)
	default:
		return fmt.Errorf("unknown format: %s (use json or summary)", format)
	}
}

func reportJSON(db *store.DB, scanID int64, target string) error {
	entries, err := db.GetTrafficByScan(scanID)
	if err != nil {
		return err
	}

	stats, err := db.GetTrafficStats(scanID)
	if err != nil {
		return err
	}

	report := map[string]any{
		"target":  target,
		"scan_id": scanID,
		"stats":   stats,
		"traffic": entries,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func reportSummary(db *store.DB, scanID int64, target string) error {
	stats, err := db.GetTrafficStats(scanID)
	if err != nil {
		return err
	}

	fmt.Printf("=== AOBTD Scan Report ===\n")
	fmt.Printf("Target: %s\n", target)
	fmt.Printf("Scan ID: %d\n\n", scanID)
	fmt.Printf("Traffic Summary:\n")
	fmt.Printf("  Total captured:  %d\n", stats.Total)
	fmt.Printf("  Filtered out:    %d\n", stats.Filtered)
	fmt.Printf("  Deduplicated:    %d\n", stats.Duplicated)
	fmt.Printf("  AI analyzed:     %d\n", stats.Analyzed)
	fmt.Printf("\nClassification:\n")
	fmt.Printf("  With inputs:     %d\n", stats.WithInput)
	fmt.Printf("  With auth:       %d\n", stats.WithAuth)
	fmt.Printf("  With errors:     %d\n", stats.WithErrors)
	fmt.Printf("  API endpoints:   %d\n", stats.APIEndpoints)

	// Show unique endpoints
	rows, err := db.Conn().Query(`
		SELECT DISTINCT endpoint_hash, method, path,
		       has_input, has_auth, is_api
		FROM traffic
		WHERE scan_id = ? AND is_filtered = FALSE
		GROUP BY endpoint_hash
		ORDER BY path`,
		scanID,
	)
	if err != nil {
		return err
	}
	defer rows.Close()

	fmt.Printf("\nDiscovered Endpoints:\n")
	count := 0
	for rows.Next() {
		var hash, method, path string
		var hasInput, hasAuth, isAPI bool
		rows.Scan(&hash, &method, &path, &hasInput, &hasAuth, &isAPI)

		flags := ""
		if hasInput {
			flags += " [INPUT]"
		}
		if hasAuth {
			flags += " [AUTH]"
		}
		if isAPI {
			flags += " [API]"
		}
		fmt.Printf("  %-7s %s%s\n", method, path, flags)
		count++
	}
	fmt.Printf("\nTotal unique endpoints: %d\n", count)

	return nil
}
