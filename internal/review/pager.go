package review

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// DisplayInPager shows the script content in a pager via /dev/tty.
// Falls back to printing directly if no pager is available.
func DisplayInPager(script []byte, tty *os.File) error {
	pager := os.Getenv("PAGER")
	if pager == "" {
		pager = "less"
	}

	// Check if pager is available.
	if _, err := exec.LookPath(pager); err != nil {
		return displayDirect(script, tty)
	}

	cmd := exec.Command(pager)
	cmd.Stdin = strings.NewReader(string(script))
	cmd.Stdout = tty
	cmd.Stderr = tty

	return cmd.Run()
}

// displayDirect prints the script with line numbers directly to the writer.
func displayDirect(script []byte, w io.Writer) error {
	lines := strings.Split(string(script), "\n")
	fmt.Fprintln(w, "--- script content ---")
	for i, line := range lines {
		fmt.Fprintf(w, "%4d | %s\n", i+1, line)
	}
	fmt.Fprintln(w, "--- end of script ---")
	return nil
}
