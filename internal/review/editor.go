package review

import (
	"fmt"
	"os"
	"os/exec"
)

// OpenInEditor writes the script to a temp file and opens it in $EDITOR.
// Uses /dev/tty for the editor's terminal I/O.
func OpenInEditor(script []byte) error {
	editorEnv := os.Getenv("EDITOR")
	if editorEnv == "" {
		return fmt.Errorf("no $EDITOR set")
	}

	f, err := os.CreateTemp("", "portcullis-review-*.sh")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpFile := f.Name()
	defer os.Remove(tmpFile)
	if _, err := f.Write(script); err != nil {
		f.Close()
		return fmt.Errorf("writing temp file: %w", err)
	}
	f.Close()

	// Use sh -c to handle complex $EDITOR values with quotes/arguments.
	cmd := exec.Command("sh", "-c", editorEnv+" \"$@\"", "--", tmpFile)

	// Connect to /dev/tty for interactive use.
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("opening /dev/tty: %w", err)
	}
	defer tty.Close()

	cmd.Stdin = tty
	cmd.Stdout = tty
	cmd.Stderr = tty

	return cmd.Run()
}
