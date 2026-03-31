package gate

import (
	"crypto/sha256"
	"fmt"
	"io"
)

// Gate orchestrates the full pipe flow: validate, hash, decide, output.
type Gate struct{}

// New creates a new Gate.
func New() *Gate {
	return &Gate{}
}

// Run processes a script through the gate pipeline.
// Output goes to stdout, diagnostics to stderr.
func (g *Gate) Run(input []byte, stdout io.Writer, stderr io.Writer) error {
	// Step 1: Shell validation
	if err := Validate(input, stderr); err != nil {
		return err
	}

	// Step 2: Compute SHA-256
	hash := ComputeHash(input)
	fmt.Fprintf(stderr, "portcullis: sha256:%s\n", hash)

	// Step 3: Check local cache (Phase 4)
	// Step 4: Query Rekor (Phase 2)
	// Step 5: Decision engine (Phase 3)

	// For now (Phase 1): pass through validated script
	_, err := stdout.Write(input)
	return err
}

// ComputeHash returns the hex-encoded SHA-256 hash of the input.
func ComputeHash(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:])
}
