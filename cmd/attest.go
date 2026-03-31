package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
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
	Long:  "Sign a positive or negative attestation for a script hash and publish it to the Rekor transparency log.",
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

		// Create and sign the attestation.
		payload := sigstore.AttestationPayload{
			Type:       rekor.AttestationType,
			ScriptHash: hash,
			Verdict:    verdict,
			Reason:     attestReason,
			Timestamp:  time.Now().UTC(),
		}

		result, err := sigstore.SignAttestation(context.Background(), payload, token.RawString, os.Stderr)
		if err != nil {
			return fmt.Errorf("signing attestation: %w", err)
		}

		// Submit to Rekor.
		contentHash := sha256.Sum256(result.Content)
		contentHashHex := fmt.Sprintf("%x", contentHash[:])
		signatureB64 := base64.StdEncoding.EncodeToString(result.Signature)

		fmt.Fprintln(os.Stderr, "Submitting to Rekor transparency log...")
		client := rekor.NewClient()
		uuid, err := client.Submit(contentHashHex, signatureB64, result.CertPEM)
		if err != nil {
			return fmt.Errorf("rekor submission: %w", err)
		}

		fmt.Fprintf(os.Stderr, "Attestation published: %s sha256:%s by %s\n", verdict, hash, token.Subject)
		fmt.Fprintf(os.Stderr, "Rekor entry: %s\n", uuid)
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
