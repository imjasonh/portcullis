package cmd

import (
	"fmt"
	"os"

	"github.com/imjasonh/portcullis/internal/cache"
	"github.com/spf13/cobra"
)

var cleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Delete the local decision cache",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := cache.Open("", 0)
		if err != nil {
			return fmt.Errorf("opening cache: %w", err)
		}
		if err := c.Clean(); err != nil {
			return fmt.Errorf("cleaning cache: %w", err)
		}
		fmt.Fprintln(os.Stderr, "portcullis: cache cleared")
		return nil
	},
}
