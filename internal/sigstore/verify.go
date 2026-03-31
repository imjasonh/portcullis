package sigstore

import "fmt"

// Verify verifies the given signature against the data using Sigstore.
// TODO: Implement using sigstore-go SDK.
func Verify(data, signature []byte) (string, error) {
	return "", fmt.Errorf("sigstore verification not yet implemented")
}
