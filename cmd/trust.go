package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/imjasonh/portcullis/internal/trust"
	"github.com/spf13/cobra"
)

var trustCmd = &cobra.Command{
	Use:   "trust",
	Short: "Manage trusted identities",
}

var trustAddCmd = &cobra.Command{
	Use:   "add <identity>",
	Short: "Add a trusted identity (email or @domain)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := trust.NewStore("")
		if err != nil {
			return err
		}
		if err := store.Add(args[0]); err != nil {
			return err
		}
		if strings.HasPrefix(args[0], "@") {
			fmt.Fprintf(os.Stderr, "Added trusted domain: %s\n", args[0])
		} else {
			fmt.Fprintf(os.Stderr, "Added trusted identity: %s\n", args[0])
		}
		return nil
	},
}

var trustRemoveCmd = &cobra.Command{
	Use:   "remove <identity>",
	Short: "Remove a trusted identity",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := trust.NewStore("")
		if err != nil {
			return err
		}
		if err := store.Remove(args[0]); err != nil {
			return err
		}
		if strings.HasPrefix(args[0], "@") {
			fmt.Fprintf(os.Stderr, "Removed trusted domain: %s\n", args[0])
		} else {
			fmt.Fprintf(os.Stderr, "Removed trusted identity: %s\n", args[0])
		}
		return nil
	},
}

var trustListCmd = &cobra.Command{
	Use:   "list",
	Short: "List trusted identities",
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := trust.NewStore("")
		if err != nil {
			return err
		}
		identities, domains := store.List()
		if len(identities) == 0 && len(domains) == 0 {
			fmt.Fprintln(os.Stderr, "No trusted identities configured.")
			return nil
		}
		if len(identities) > 0 {
			fmt.Fprintln(os.Stderr, "Trusted identities:")
			for _, id := range identities {
				fmt.Fprintf(os.Stderr, "  %s\n", id)
			}
		}
		if len(domains) > 0 {
			fmt.Fprintln(os.Stderr, "Trusted domains:")
			for _, d := range domains {
				fmt.Fprintf(os.Stderr, "  %s\n", d)
			}
		}
		return nil
	},
}

func init() {
	trustCmd.AddCommand(trustAddCmd)
	trustCmd.AddCommand(trustRemoveCmd)
	trustCmd.AddCommand(trustListCmd)
}
