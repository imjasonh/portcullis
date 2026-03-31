package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var queryCmd = &cobra.Command{
	Use:   "query <sha256:hash>",
	Short: "Query attestations for a script hash",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		hash := args[0]
		// TODO: Rekor query (Phase 2)
		fmt.Fprintf(cmd.ErrOrStderr(), "Querying attestations for %s...\n", hash)
		fmt.Fprintf(cmd.ErrOrStderr(), "No attestations found (Rekor integration pending).\n")
		return nil
	},
}
