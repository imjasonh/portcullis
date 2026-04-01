package sigstore

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
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

// VerifyCertificateChain verifies that a leaf certificate chains back to the
// Sigstore Fulcio root using the TUF-distributed trusted root.
func VerifyCertificateChain(certPEM []byte, observerTimestamp time.Time) error {
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

	trustedRoot, err := root.FetchTrustedRoot()
	if err != nil {
		return fmt.Errorf("fetching Sigstore trusted root: %w", err)
	}

	return verify.VerifyLeafCertificate(observerTimestamp, cert, trustedRoot)
}
