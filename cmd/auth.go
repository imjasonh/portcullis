package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Authenticate with Sigstore via OIDC",
	RunE: func(cmd *cobra.Command, args []string) error {
		// TODO: Sigstore OIDC auth flow (Phase 2)
		fmt.Fprintln(cmd.ErrOrStderr(), "Sigstore authentication not yet implemented.")
		return nil
	},
}
