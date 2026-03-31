package main

import (
	"os"

	"github.com/imjasonh/portcullis/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
