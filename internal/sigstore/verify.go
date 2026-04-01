package sigstore

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ExtractIdentityFromCert extracts the signer identity from a PEM-encoded certificate.
// Returns the email address (from SAN) or URI SAN for CI identities.
func ExtractIdentityFromCert(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("no PEM block found")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parsing certificate: %w", err)
	}

	if len(cert.EmailAddresses) > 0 {
		return cert.EmailAddresses[0], nil
	}

	if len(cert.URIs) > 0 {
		return cert.URIs[0].String(), nil
	}

	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName, nil
	}

	return "", fmt.Errorf("no identity found in certificate")
}

// VerifyCertificateIsLeaf performs basic validation that the certificate is a leaf
// (not a CA) certificate. Full chain verification against the Fulcio root is handled
// by sigstore-go's bundle verification and Rekor's inclusion proof — this function
// is only a sanity check for certificate parsing paths.
func VerifyCertificateIsLeaf(certPEM []byte) error {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("no PEM block found")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parsing certificate: %w", err)
	}

	if cert.IsCA {
		return fmt.Errorf("expected leaf certificate, got CA")
	}

	return nil
}
