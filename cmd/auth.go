package cmd

import (
	"fmt"
	"os"

	"github.com/imjasonh/portcullis/internal/sigstore"
	"github.com/spf13/cobra"
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Authenticate with Sigstore via OIDC",
	Long:  "Opens a browser for Sigstore OIDC authentication. The identity token is used for keyless signing of attestations.",
	RunE: func(cmd *cobra.Command, args []string) error {
		token, err := sigstore.Authenticate(os.Stderr)
		if err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Successfully authenticated as: %s\n", token.Subject)
		return nil
	},
}
