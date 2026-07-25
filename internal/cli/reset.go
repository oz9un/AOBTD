package cli

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ozzyw/aobtd/internal/store"
	"github.com/spf13/cobra"
)

// knownArtifacts is the closed set of names `aobtd scan` writes inside an
// output directory. The reset command refuses to touch a directory that
// contains anything outside this set, so a stray `aobtd reset -i ~/Documents`
// can't quietly nuke unrelated files.
var knownArtifacts = map[string]bool{
	"scan.db":     true,
	"scan.db-shm": true,
	"scan.db-wal": true,
	"certs":       true,
	"frames":      true,
	"screenshots": true,
}

// NewResetCmd creates the `aobtd reset` command — wipes scan artifacts from
// an output directory so the UI boots into the first-run welcome flow again.
func NewResetCmd() *cobra.Command {
	var (
		inputDir string
		yes      bool
	)

	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Delete all scans and artifacts from an output directory",
		Long: `Wipe scan.db plus the certs/, frames/, and screenshots/ subdirectories
from an output directory. Useful for testing the first-run UX or starting
fresh on a target.

The directory itself is preserved. Aborts if the directory contains
anything that doesn't look like an AOBTD artifact, so you can't
accidentally point it at the wrong path.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReset(inputDir, yes)
		},
		SilenceUsage: true,
	}

	cmd.Flags().StringVarP(&inputDir, "input", "i", "./aobtd-output", "Output directory to wipe")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip confirmation prompt")

	return cmd
}

func runReset(inputDir string, yes bool) error {
	abs, err := filepath.Abs(inputDir)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}

	info, err := os.Stat(abs)
	if os.IsNotExist(err) {
		fmt.Printf("Nothing to do — %s does not exist.\n", abs)
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat %s: %w", abs, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", abs)
	}

	entries, err := os.ReadDir(abs)
	if err != nil {
		return fmt.Errorf("read %s: %w", abs, err)
	}

	if len(entries) == 0 {
		fmt.Printf("Nothing to do — %s is already empty.\n", abs)
		return nil
	}

	// Refuse if anything in the dir isn't an AOBTD-known artifact. This is
	// the guardrail against pointing reset at, say, your home directory.
	var unexpected []string
	for _, e := range entries {
		if !knownArtifacts[e.Name()] {
			unexpected = append(unexpected, e.Name())
		}
	}
	if len(unexpected) > 0 {
		return fmt.Errorf("refusing to reset %s: it contains non-AOBTD entries (%s).\nIf this really is an AOBTD output dir, remove those entries manually first",
			abs, strings.Join(unexpected, ", "))
	}

	// Best-effort scan count + size. We open the DB for a single COUNT;
	// if it fails (corrupt, locked by a running scanner, …) we fall back
	// to "?" rather than aborting — the user can still wipe.
	scanCount := "?"
	dbPath := filepath.Join(abs, "scan.db")
	if _, err := os.Stat(dbPath); err == nil {
		if db, err := store.Open(dbPath); err == nil {
			var n int
			if err := db.Conn().QueryRow(`SELECT COUNT(*) FROM scans`).Scan(&n); err == nil {
				scanCount = fmt.Sprintf("%d", n)
			}
			db.Close()
		}
	}

	totalBytes, err := dirSizeBytes(abs)
	if err != nil {
		return fmt.Errorf("size %s: %w", abs, err)
	}

	if !yes {
		fmt.Printf("Wipe %s across %s scan(s) from %s? [y/N] ", humanBytes(totalBytes), scanCount, abs)
		reader := bufio.NewReader(os.Stdin)
		line, _ := reader.ReadString('\n')
		ans := strings.TrimSpace(strings.ToLower(line))
		if ans != "y" && ans != "yes" {
			fmt.Println("Aborted.")
			return nil
		}
	}

	for _, e := range entries {
		path := filepath.Join(abs, e.Name())
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("remove %s: %w", path, err)
		}
	}

	fmt.Printf("Reset %s — removed %s.\n", abs, humanBytes(totalBytes))
	return nil
}

func dirSizeBytes(root string) (int64, error) {
	var total int64
	err := filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total, err
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
