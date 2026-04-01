package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/imjasonh/portcullis/internal/rekor"
	"github.com/imjasonh/portcullis/internal/sigstore"
	"github.com/spf13/cobra"
)

var (
	attestApprove bool
	attestDeny    bool
	attestReason  string
)

var attestCmd = &cobra.Command{
	Use:   "attest <sha256:hash>",
	Short: "Manually attest to approve or deny a script hash",
	Long:  "Sign a positive or negative attestation for a script hash and publish it to the Rekor transparency log via Sigstore.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if attestApprove == attestDeny {
			return fmt.Errorf("specify exactly one of --approve or --deny")
		}

		hash := strings.TrimPrefix(args[0], "sha256:")
		verdict := "approve"
		if attestDeny {
			verdict = "deny"
		}

		// Authenticate with Sigstore.
		token, err := sigstore.Authenticate(os.Stderr)
		if err != nil {
			return fmt.Errorf("authentication required for attestation: %w", err)
		}

		// Create and sign the attestation via sigstore-go.
		payload := sigstore.AttestationPayload{
			Type:       rekor.AttestationType,
			ScriptHash: hash,
			Verdict:    verdict,
			Reason:     attestReason,
			Timestamp:  time.Now().UTC(),
		}

		if err := sigstore.SignAndPublish(context.Background(), payload, token.RawString, os.Stderr); err != nil {
			return fmt.Errorf("signing attestation: %w", err)
		}

		fmt.Fprintf(os.Stderr, "Attestation published: %s sha256:%s by %s\n", verdict, hash, token.Subject)
		if attestReason != "" {
			fmt.Fprintf(os.Stderr, "Reason: %s\n", attestReason)
		}
		return nil
	},
}

func init() {
	attestCmd.Flags().BoolVar(&attestApprove, "approve", false, "Approve the script hash")
	attestCmd.Flags().BoolVar(&attestDeny, "deny", false, "Deny the script hash")
	attestCmd.Flags().StringVar(&attestReason, "reason", "", "Reason for the attestation")
}
