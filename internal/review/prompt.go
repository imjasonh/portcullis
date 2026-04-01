package review

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/imjasonh/portcullis/internal/rekor"
)

// ErrNoTTY is returned when /dev/tty is unavailable for interactive review.
var ErrNoTTY = errors.New("no interactive terminal available")

// Result holds the user's review decision.
type Result struct {
	Verdict string // "approve", "deny", "run", "block"
	Attest  bool   // whether to sign and publish attestation
	Reason  string // optional reason (for deny)
}

// InteractiveReview opens a review session via /dev/tty.
// Returns the verdict, whether to attest, and an optional reason.
func InteractiveReview(script []byte, untrusted []rekor.Attestation, stderr io.Writer) (string, bool, string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", false, "", ErrNoTTY
	}
	defer tty.Close()

	// Try to open in editor first, fall back to pager.
	if err := OpenInEditor(script); err != nil {
		DisplayInPager(script, tty)
	}

	// Show attestation context.
	if len(untrusted) > 0 {
		printAttestationContext(untrusted, tty)
	}

	// Prompt for decision.
	return promptDecision(tty)
}

func printAttestationContext(attestations []rekor.Attestation, w io.Writer) {
	fmt.Fprintln(w)
	rekor.FormatAttestationContext(attestations, w)
	fmt.Fprintln(w)
}

func promptDecision(tty *os.File) (string, bool, string, error) {
	reader := bufio.NewReader(tty)

	for {
		fmt.Fprintln(tty, "What would you like to do?")
		fmt.Fprintln(tty, "  [a] Approve + attest — sign attestation, publish to Rekor, pass to stdout")
		fmt.Fprintln(tty, "  [d] Deny + attest   — sign attestation, publish to Rekor, block")
		fmt.Fprintln(tty, "  [r] Run anyway       — pass to stdout, no attestation, cache locally")
		fmt.Fprintln(tty, "  [b] Block anyway     — block, no attestation, cache locally")
		fmt.Fprint(tty, "> ")

		input, err := reader.ReadString('\n')
		if err != nil {
			return "", false, "", fmt.Errorf("reading input: %w", err)
		}

		choice := strings.TrimSpace(strings.ToLower(input))
		switch choice {
		case "a":
			return "approve", true, "", nil
		case "d":
			fmt.Fprint(tty, "Reason (optional): ")
			reason, _ := reader.ReadString('\n')
			return "deny", true, strings.TrimSpace(reason), nil
		case "r":
			return "run", false, "", nil
		case "b":
			fmt.Fprint(tty, "Reason (optional): ")
			reason, _ := reader.ReadString('\n')
			return "block", false, strings.TrimSpace(reason), nil
		default:
			fmt.Fprintf(tty, "Invalid choice: %q. Please enter a, d, r, or b.\n\n", choice)
		}
	}
}

