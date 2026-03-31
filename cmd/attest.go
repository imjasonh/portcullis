package cmd

import (
	"fmt"

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

		hash := args[0]
		verdict := "approve"
		if attestDeny {
			verdict = "deny"
		}

		// TODO: Sigstore signing + Rekor submission (Phase 2)
		fmt.Fprintf(cmd.ErrOrStderr(), "Attestation recorded: %s %s\n", verdict, hash)
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
