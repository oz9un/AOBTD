package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"

	"github.com/ozzyw/aobtd/internal/agent"
	"github.com/ozzyw/aobtd/internal/store"
)

func main() {
	dbPath := flag.String("db", "aobtd-output/scan.db", "path to the AOBTD scan database")
	scanID := flag.Int64("scan-id", 0, "saved scan ID to replay")
	jsonOutput := flag.Bool("json", false, "emit JSON")
	flag.Parse()
	if *scanID <= 0 {
		log.Fatal("-scan-id is required")
	}
	db, err := store.Open(*dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	report, err := agent.ReplayAnalysisCompaction(db, *scanID)
	if err != nil {
		log.Fatal(err)
	}
	if *jsonOutput {
		raw, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(raw))
		return
	}
	fmt.Printf("Scan %d adaptive compaction replay\n", report.ScanID)
	fmt.Printf("Captured endpoint families: %d\n", report.CapturedFamilies)
	fmt.Printf("Passive mechanics closed: %d\n", report.PassiveClosed)
	fmt.Printf("Semantic candidates: %d\n", report.SemanticCandidates)
	fmt.Printf("Representative model calls: %d\n", report.SemanticRepresentatives)
	fmt.Printf("Equivalent calls saved: %d (%.1f%%)\n", report.EquivalentCallsSaved, report.CallReductionPercent)
	fmt.Printf("Protection evidence: %d families, %d shapes, %d retained specimen(s), %d duplicate mechanic(s) compacted\n",
		report.ProtectionFamilies, report.ProtectionShapes, report.ProtectionSpecimens, report.ProtectionDuplicates)
	fmt.Printf("Protection exceptions preserved: %d recovered application family/families, %d server-error family/families\n",
		report.RecoveredApplications, report.ProtectionServerErrors)
	for _, group := range report.Groups {
		fmt.Printf("  %s reused for %d equivalent route(s)\n", group.Representative, len(group.Equivalent))
	}
}
