// Command target-brain-scorecard replays the deterministic Target Brain over
// saved scans and verifies the product's most important honesty invariants.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	scanagent "github.com/ozzyw/aobtd/internal/agent"
	"github.com/ozzyw/aobtd/internal/extract"
	"github.com/ozzyw/aobtd/internal/store"
)

type brainCard struct {
	ScanID          int64  `json:"scan_id"`
	Target          string `json:"target"`
	ApplicationType string `json:"application_type"`
	State           string `json:"state"`
	Score           int    `json:"understanding"`
	Dimensions      int    `json:"dimensions"`
	FocusID         string `json:"focus_id,omitempty"`
	ExactMoves      int    `json:"exact_moves"`
	WaitingMoves    int    `json:"waiting_moves"`
	BriefingReady   bool   `json:"briefing_ready"`
	TruthfulPlan    bool   `json:"truthful_plan"`
	Verdict         string `json:"verdict"`
}

type scorecardReport struct {
	Scans            int            `json:"scans"`
	BriefingReady    int            `json:"briefing_ready"`
	TruthfulPlans    int            `json:"truthful_plans"`
	FocusedOpenModel int            `json:"focused_open_models"`
	OpenModels       int            `json:"open_models"`
	ExactMoves       int            `json:"exact_moves"`
	WaitingMoves     int            `json:"waiting_moves"`
	States           map[string]int `json:"states"`
	Cards            []brainCard    `json:"cards"`
}

func main() {
	dbPath := flag.String("db", "./aobtd-output/scan.db", "path to scan.db")
	format := flag.String("format", "markdown", "markdown or json")
	flag.Parse()

	db, err := store.Open(*dbPath)
	if err != nil {
		fatalf("open scan database: %v", err)
	}
	defer db.Close()

	report, err := buildReport(db)
	if err != nil {
		fatalf("build Target Brain scorecard: %v", err)
	}
	if strings.EqualFold(*format, "json") {
		raw, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(raw))
		return
	}
	printMarkdown(report)
}

func buildReport(db *store.DB) (scorecardReport, error) {
	report := scorecardReport{States: map[string]int{}}
	rows, err := db.Conn().Query(`SELECT id, target FROM scans ORDER BY id`)
	if err != nil {
		return report, err
	}
	defer rows.Close()
	type scanRef struct {
		id     int64
		target string
	}
	refs := []scanRef{}
	for rows.Next() {
		var ref scanRef
		if err := rows.Scan(&ref.id, &ref.target); err != nil {
			return report, err
		}
		refs = append(refs, ref)
	}
	if err := rows.Err(); err != nil {
		return report, err
	}

	for _, ref := range refs {
		u := extract.NewAppUnderstanding()
		if appType, templates, areas, analyzed, summary, loadErr := db.GetAppUnderstanding(ref.id); loadErr == nil {
			u = extract.LoadAppUnderstanding(appType, templates, areas, analyzed, summary)
		}
		if raw, loadErr := db.GetReconModel(ref.id); loadErr == nil {
			u.LoadReconJSON(raw)
		}
		u.NormalizeReconModel()
		queue, _ := db.GetUnanalyzedEndpointQueue(ref.id, .3, scanagent.AnalysisCandidateWindowSize)
		ages, _ := db.GetAnalysisQueueAges(ref.id)
		calibration, _ := db.ListAnalysisImpactCalibration(ref.id)
		queue = scanagent.RankAnalysisQueueWithFeedback(queue, u.Recon, ages, scanagent.AnalysisImpactCalibrationMap(calibration))
		history, _ := db.ListAnalysisLearningCheckpoints(ref.id, 6, 12)
		objectives := scanagent.BuildReconObjectives(u.Recon, 6)
		brain := scanagent.BuildTargetBrain(u.Recon, objectives, queue, history)

		card := brainCard{
			ScanID: ref.id, Target: ref.target, ApplicationType: brain.Thesis.ApplicationType,
			State: brain.State, Score: brain.Saturation.UnderstandingScore,
			Dimensions: len(brain.Dimensions), Verdict: brain.Saturation.Verdict,
			BriefingReady: len(brain.Dimensions) == 7 && brain.Fingerprint != "" && strings.TrimSpace(brain.Thesis.Summary) != "",
			TruthfulPlan:  true,
		}
		if brain.Focus != nil {
			card.FocusID = brain.Focus.ID
		}
		for _, move := range brain.Moves {
			if move.Mode == "analyze" {
				card.ExactMoves++
				if move.EvidenceID <= 0 || strings.TrimSpace(move.URL) == "" || len(move.Expected) == 0 {
					card.TruthfulPlan = false
				}
			} else {
				card.WaitingMoves++
				if move.EvidenceID != 0 || strings.TrimSpace(move.URL) != "" {
					card.TruthfulPlan = false
				}
			}
		}
		if brain.Saturation.OpenTargets > 0 {
			report.OpenModels++
			if brain.Focus != nil && strings.TrimSpace(brain.Focus.ID) != "" {
				report.FocusedOpenModel++
			}
		}
		report.Scans++
		report.States[brain.State]++
		report.ExactMoves += card.ExactMoves
		report.WaitingMoves += card.WaitingMoves
		if card.BriefingReady {
			report.BriefingReady++
		}
		if card.TruthfulPlan {
			report.TruthfulPlans++
		}
		report.Cards = append(report.Cards, card)
	}
	return report, nil
}

func printMarkdown(report scorecardReport) {
	fmt.Printf("# Target Brain scorecard\n\n")
	fmt.Printf("- Saved scans: **%d**\n", report.Scans)
	fmt.Printf("- Complete one-minute briefing contract: **%d/%d**\n", report.BriefingReady, report.Scans)
	fmt.Printf("- Truthful plans (exact captured analysis or explicit wait): **%d/%d**\n", report.TruthfulPlans, report.Scans)
	fmt.Printf("- Open models with an explicit focus: **%d/%d**\n", report.FocusedOpenModel, report.OpenModels)
	fmt.Printf("- Exact captured moves: **%d** · explicit waiting/prerequisite moves: **%d**\n\n", report.ExactMoves, report.WaitingMoves)

	states := make([]string, 0, len(report.States))
	for state := range report.States {
		states = append(states, state)
	}
	sort.Strings(states)
	fmt.Println("## State distribution")
	fmt.Println()
	for _, state := range states {
		fmt.Printf("- %s: %d\n", state, report.States[state])
	}
	fmt.Println()
	fmt.Println("## Per-scan replay")
	fmt.Println()
	fmt.Println("| Scan | Target | App | Brain | Score | Focus | Exact | Wait | Contract |")
	fmt.Println("|---:|---|---|---|---:|---|---:|---:|---|")
	for _, card := range report.Cards {
		contract := "pass"
		if !card.BriefingReady || !card.TruthfulPlan {
			contract = "fail"
		}
		fmt.Printf("| %d | %s | %s | %s | %d | %s | %d | %d | %s |\n",
			card.ScanID, markdownCell(card.Target), markdownCell(card.ApplicationType), card.State,
			card.Score, markdownCell(card.FocusID), card.ExactMoves, card.WaitingMoves, contract)
	}
}

func markdownCell(value string) string {
	return strings.ReplaceAll(strings.TrimSpace(value), "|", "\\|")
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
