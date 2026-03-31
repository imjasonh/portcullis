package cmd

import (
	"fmt"
	"strings"

	"github.com/imjasonh/portcullis/internal/rekor"
	"github.com/spf13/cobra"
)

var queryCmd = &cobra.Command{
	Use:   "query <sha256:hash>",
	Short: "Query attestations for a script hash",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		hash := args[0]
		hash = strings.TrimPrefix(hash, "sha256:")

		client := rekor.NewClient()
		fmt.Fprintf(cmd.ErrOrStderr(), "Querying attestations for sha256:%s...\n", hash)

		result := client.Query(hash)
		if result.Err != nil {
			return fmt.Errorf("query failed: %w", result.Err)
		}

		if len(result.Attestations) == 0 {
			fmt.Fprintln(cmd.ErrOrStderr(), "No attestations found.")
			return nil
		}

		for _, att := range result.Attestations {
			fmt.Fprintf(cmd.ErrOrStderr(), "  %s by %s (%s)",
				att.Verdict, att.Identity, att.Timestamp.Format("2006-01-02"))
			if att.Reason != "" {
				fmt.Fprintf(cmd.ErrOrStderr(), ": %s", att.Reason)
			}
			fmt.Fprintln(cmd.ErrOrStderr())
		}
		return nil
	},
}
