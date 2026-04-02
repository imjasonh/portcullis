package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/imjasonh/portcullis/internal/gate"
	"github.com/imjasonh/portcullis/internal/rekor"
	"github.com/imjasonh/portcullis/internal/review"
	"github.com/imjasonh/portcullis/internal/sigstore"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "portcullis",
	Short: "Inspect and gate piped shell scripts before execution",
	Long:  "Portcullis interposes in shell script execution pipelines to verify trust before allowing execution.",
	RunE:  runPipeMode,
}

func init() {
	rootCmd.AddCommand(trustCmd)
	rootCmd.AddCommand(attestCmd)
	rootCmd.AddCommand(queryCmd)
	rootCmd.AddCommand(authCmd)
	rootCmd.AddCommand(cleanCmd)
}

// Execute runs the root command.
func Execute() error {
	base := filepath.Base(os.Args[0])
	if base == "pc" {
		return runPipeMode(rootCmd, nil)
	}
	return rootCmd.Execute()
}

func runPipeMode(cmd *cobra.Command, args []string) error {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "portcullis: failed to read stdin: %v\n", err)
		return err
	}

	if len(input) == 0 {
		fmt.Fprintln(os.Stderr, "portcullis: empty input")
		return fmt.Errorf("empty input")
	}

	g, err := gate.NewWithConfig("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "portcullis: using basic mode: %v\n", err)
		g = gate.New()
	}

	g.ReviewFunc = review.InteractiveReview
	g.AttestFunc = attestAndPublish

	return g.Run(input, os.Stdout, os.Stderr)
}

// attestAndPublish signs an attestation and publishes it to Rekor via sigstore-go.
func attestAndPublish(hash, verdict, reason string, stderr io.Writer) error {
	token, err := sigstore.Authenticate(stderr)
	if err != nil {
		return err
	}

	payload := sigstore.AttestationPayload{
		Type:       rekor.AttestationType,
		ScriptHash: hash,
		Verdict:    verdict,
		Reason:     reason,
		Timestamp:  time.Now().UTC(),
	}

	return sigstore.SignAndPublish(context.Background(), payload, token.RawString, stderr)
}
