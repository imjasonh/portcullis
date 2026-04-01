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

	// Use sh -c to handle complex $PAGER values with quotes/arguments.
	cmd := exec.Command("sh", "-c", pager)
	cmd.Stdin = strings.NewReader(string(script))
	cmd.Stdout = tty
	cmd.Stderr = tty

	if err := cmd.Run(); err != nil {
		return displayDirect(script, tty)
	}
	return nil
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
