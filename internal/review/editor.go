package review

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// OpenInEditor writes the script to a temp file and opens it in $EDITOR.
// Uses /dev/tty for the editor's terminal I/O.
func OpenInEditor(script []byte) error {
	editor := os.Getenv("EDITOR")
	if editor == "" {
		return fmt.Errorf("no $EDITOR set")
	}

	tmpDir := os.TempDir()
	tmpFile := filepath.Join(tmpDir, "portcullis-review.sh")
	if err := os.WriteFile(tmpFile, script, 0600); err != nil {
		return fmt.Errorf("writing temp file: %w", err)
	}
	defer os.Remove(tmpFile)

	cmd := exec.Command(editor, tmpFile)

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
