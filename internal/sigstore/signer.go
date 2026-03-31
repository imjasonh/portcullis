package sigstore

import "fmt"

// Sign signs the given data using Sigstore keyless signing.
// TODO: Implement using sigstore-go SDK.
func Sign(data []byte) ([]byte, error) {
	return nil, fmt.Errorf("sigstore signing not yet implemented")
}

// GetIdentity returns the current OIDC identity.
// TODO: Implement OIDC auth flow.
func GetIdentity() (string, error) {
	return "", fmt.Errorf("sigstore authentication not yet implemented")
}
