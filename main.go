package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/imjasonh/portcullis/cmd"
)

func main() {
	// Handle SIGPIPE gracefully (e.g., when bash exits early in a pipe).
	signal.Ignore(syscall.SIGPIPE)

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
