package main

import (
	"fmt"
	"os"

	"github.com/ozzyw/aobtd/internal/cli"
	"github.com/spf13/cobra"
)

var version = "0.1.0-dev"

func main() {
	root := &cobra.Command{
		Use:   "aobtd",
		Short: "AI One Bites The DAST — LLM-powered dynamic application security testing",
		Long: `AOBTD is an AI-powered DAST tool that crawls web applications,
captures traffic through a MITM proxy, and uses LLMs to understand
the application's attack surface, business logic, and potential vulnerabilities.`,
		Version: version,
	}

	root.AddCommand(cli.NewScanCmd())
	root.AddCommand(cli.NewReportCmd())
	root.AddCommand(cli.NewUICmd())
	root.AddCommand(cli.NewResetCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
