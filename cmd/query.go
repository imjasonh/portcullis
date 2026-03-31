package cmd

import (
	"fmt"
	"strings"

	"github.com/imjasonh/portcullis/internal/rekor"
	"github.com/spf13/cobra"
)

var queryCmd = &cobra.Command{
	Use:   "query <sha256:hash>",
	Short: "Query Rekor for attestations on a script hash",
	Long:  "Search the Rekor transparency log for all attestations matching the given script hash.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		hash := strings.TrimPrefix(args[0], "sha256:")

		client := rekor.NewClient()
		fmt.Fprintf(cmd.ErrOrStderr(), "Querying Rekor for sha256:%s...\n", hash)

		result := client.Query(hash)
		if result.Err != nil {
			return fmt.Errorf("query failed: %w", result.Err)
		}

		if len(result.Attestations) == 0 {
			fmt.Fprintln(cmd.ErrOrStderr(), "No attestations found.")
			return nil
		}

		fmt.Fprintf(cmd.ErrOrStderr(), "Found %d attestation(s):\n", len(result.Attestations))
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
