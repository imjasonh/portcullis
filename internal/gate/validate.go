package gate

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// shellKeywords are common shell tokens used for heuristic detection.
var shellKeywords = []string{
	"#!/", "set -", "export ", "echo ", "if ", "then", "fi",
	"for ", "while ", "do ", "done", "case ", "esac",
	"function ", "exit ", "return ", "source ", "eval ",
	"cd ", "mkdir ", "rm ", "cp ", "mv ", "chmod ",
	"curl ", "wget ", "apt ", "yum ", "brew ", "pip ",
}

// Validate checks that the input looks like a valid shell script.
// Returns an error if the input should be blocked.
func Validate(input []byte, stderr io.Writer) error {
	// Check for null bytes (binary content).
	if bytes.ContainsRune(input, 0) {
		printPreview(input, stderr)
		fmt.Fprintln(stderr, "portcullis: blocked — input contains null bytes (binary, not a script)")
		return fmt.Errorf("binary input detected")
	}

	// Heuristic: check if it looks like shell.
	if !looksLikeShell(input) {
		printPreview(input, stderr)
		fmt.Fprintln(stderr, "portcullis: blocked — input does not appear to be a shell script")
		return fmt.Errorf("input does not look like a shell script")
	}

	// Syntax check with bash -n.
	if err := bashSyntaxCheck(input); err != nil {
		printPreview(input, stderr)
		fmt.Fprintf(stderr, "portcullis: blocked — bash syntax error: %v\n", err)
		return fmt.Errorf("bash syntax check failed")
	}

	return nil
}

// looksLikeShell checks whether the input has shell-like characteristics.
func looksLikeShell(input []byte) bool {
	text := string(input)

	// Check for shebang.
	if strings.HasPrefix(text, "#!") {
		first := strings.SplitN(text, "\n", 2)[0]
		if strings.Contains(first, "sh") || strings.Contains(first, "bash") || strings.Contains(first, "zsh") {
			return true
		}
	}

	// Check first 20 lines for shell keywords.
	lines := strings.SplitN(text, "\n", 21)
	if len(lines) > 20 {
		lines = lines[:20]
	}

	hits := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, kw := range shellKeywords {
			if strings.Contains(line, kw) {
				hits++
				break
			}
		}
	}

	// Require at least 1 shell keyword hit in the first 20 lines.
	return hits >= 1
}

// bashSyntaxCheck runs bash -n on the input to verify syntax.
func bashSyntaxCheck(input []byte) error {
	cmd := exec.Command("bash", "-n")
	cmd.Stdin = bytes.NewReader(input)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(stderr.String()))
	}
	return nil
}

// printPreview prints the first 10 lines of input to stderr for diagnostics.
func printPreview(input []byte, stderr io.Writer) {
	lines := strings.SplitN(string(input), "\n", 11)
	if len(lines) > 10 {
		lines = lines[:10]
	}
	fmt.Fprintln(stderr, "--- first lines of input ---")
	for _, line := range lines {
		fmt.Fprintln(stderr, line)
	}
	fmt.Fprintln(stderr, "---")
}
