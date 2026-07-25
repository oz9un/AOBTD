package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/ozzyw/aobtd/internal/store"
	"github.com/ozzyw/aobtd/internal/ui"
	"github.com/spf13/cobra"
)

// NewUICmd creates the `aobtd ui` command.
func NewUICmd() *cobra.Command {
	var (
		inputDir  string
		port      int
		noBrowser bool
		dev       bool
		staticDir string
	)

	cmd := &cobra.Command{
		Use:   "ui",
		Short: "Launch the web UI to explore scan results",
		Long:  "Start a local web server to visualize scan data: endpoints, traffic, findings, screenshots, and the knowledge base.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUI(inputDir, port, noBrowser, dev, staticDir)
		},
	}

	cmd.Flags().StringVarP(&inputDir, "input", "i", "./aobtd-output", "Directory containing scan.db")
	cmd.Flags().IntVarP(&port, "port", "p", 8090, "UI server port")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "Don't open browser automatically")
	cmd.Flags().BoolVar(&dev, "dev", false, "Dev mode: serve frontend from disk (live reload), bypassing the embedded files")
	cmd.Flags().StringVar(&staticDir, "static-dir", "", "Override the on-disk static dir for --dev (default: internal/ui/static relative to CWD)")

	return cmd
}

func runUI(inputDir string, port int, noBrowser bool, dev bool, staticDir string) error {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// First-run friendly: create the output dir if missing and let
	// store.Open create+migrate a fresh scan.db. The UI is the entry
	// point now — users start their first scan from the Home view.
	if err := os.MkdirAll(inputDir, 0o755); err != nil {
		return fmt.Errorf("create input dir: %w", err)
	}
	dbPath := filepath.Join(inputDir, "scan.db")
	freshDB := false
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		freshDB = true
	}

	db, err := store.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	server := ui.NewServer(db, inputDir, addr, logger)

	if freshDB {
		fmt.Printf("\n  No prior scans in %s — start your first one from the Home view.\n", inputDir)
	}

	if dev {
		resolvedDir := staticDir
		if resolvedDir == "" {
			resolvedDir = filepath.Join("internal", "ui", "static")
		}
		abs, err := filepath.Abs(resolvedDir)
		if err != nil {
			return fmt.Errorf("resolve static dir: %w", err)
		}
		if _, err := os.Stat(filepath.Join(abs, "index.html")); err != nil {
			return fmt.Errorf("dev mode: %s/index.html not found — pass --static-dir or run from the project root", abs)
		}
		server.SetDevStaticDir(abs)
		fmt.Printf("\n  [dev] serving frontend from: %s (live reload)\n", abs)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down UI server...")
		cancel()
	}()

	// Open browser
	if !noBrowser {
		go func() {
			url := fmt.Sprintf("http://%s", addr)
			openBrowser(url)
		}()
	}

	return server.Start(ctx)
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	cmd.Start()
}
