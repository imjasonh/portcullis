package cmd

import (
	"fmt"
	"strings"

	"github.com/imjasonh/portcullis/internal/rekor"
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

		att := rekor.NewAttestation(hash, verdict, "", attestReason)
		client := rekor.NewClient()

		if err := client.Submit(att); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: %v\n", err)
			fmt.Fprintln(cmd.ErrOrStderr(), "Attestation created locally but not published to Rekor.")
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "Attestation published: %s sha256:%s\n", verdict, hash)
		}

		if attestReason != "" {
			fmt.Fprintf(cmd.ErrOrStderr(), "Reason: %s\n", attestReason)
		}
		return nil
	},
}

func init() {
	attestCmd.Flags().BoolVar(&attestApprove, "approve", false, "Approve the script hash")
	attestCmd.Flags().BoolVar(&attestDeny, "deny", false, "Deny the script hash")
	attestCmd.Flags().StringVar(&attestReason, "reason", "", "Reason for the attestation")
}
