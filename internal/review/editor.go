package review

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// OpenInEditor writes the script to a temp file and opens it in $EDITOR.
// Uses /dev/tty for the editor's terminal I/O.
func OpenInEditor(script []byte) error {
	editorEnv := os.Getenv("EDITOR")
	if editorEnv == "" {
		return fmt.Errorf("no $EDITOR set")
	}
	parts := strings.Fields(editorEnv)
	editor := parts[0]
	editorArgs := parts[1:]

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

	cmd := exec.Command(editor, append(editorArgs, tmpFile)...)

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
