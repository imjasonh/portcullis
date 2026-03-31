package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/imjasonh/portcullis/internal/gate"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "portcullis",
	Short: "Inspect and gate piped shell scripts before execution",
	Long:  "Portcullis interposes in shell script execution pipelines to verify trust before allowing execution.",
	// When invoked with no subcommand, run in pipe mode.
	RunE: runPipeMode,
}

func init() {
	rootCmd.AddCommand(trustCmd)
	rootCmd.AddCommand(attestCmd)
	rootCmd.AddCommand(queryCmd)
	rootCmd.AddCommand(authCmd)
}

// Execute runs the root command.
func Execute() error {
	// If invoked as "pc", run pipe mode directly.
	base := filepath.Base(os.Args[0])
	if base == "pc" {
		return runPipeMode(rootCmd, nil)
	}
	return rootCmd.Execute()
}

func runPipeMode(cmd *cobra.Command, args []string) error {
	// Read all of stdin.
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "portcullis: failed to read stdin: %v\n", err)
		return err
	}

	if len(input) == 0 {
		fmt.Fprintln(os.Stderr, "portcullis: empty input")
		return fmt.Errorf("empty input")
	}

	g := gate.New()
	return g.Run(input, os.Stdout, os.Stderr)
}
