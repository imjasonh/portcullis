package sigstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func generateTestCert(t *testing.T, email string, isCA bool) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: email,
		},
		EmailAddresses:    []string{email},
		NotBefore:         time.Now(),
		NotAfter:          time.Now().Add(10 * time.Minute),
		IsCA:              isCA,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

func TestExtractIdentityFromCert(t *testing.T) {
	certPEM := generateTestCert(t, "alice@example.com", false)

	identity, err := ExtractIdentityFromCert(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if identity != "alice@example.com" {
		t.Errorf("expected alice@example.com, got %s", identity)
	}
}

func TestExtractIdentityFromCert_NoPEM(t *testing.T) {
	_, err := ExtractIdentityFromCert([]byte("not a certificate"))
	if err == nil {
		t.Error("expected error for non-PEM input")
	}
}

func TestVerifyCertificateIsLeaf_Leaf(t *testing.T) {
	certPEM := generateTestCert(t, "alice@example.com", false)
	if err := VerifyCertificateIsLeaf(certPEM); err != nil {
		t.Errorf("expected leaf cert to pass: %v", err)
	}
}

func TestVerifyCertificateIsLeaf_CA(t *testing.T) {
	certPEM := generateTestCert(t, "ca@example.com", true)
	if err := VerifyCertificateIsLeaf(certPEM); err == nil {
		t.Error("expected CA cert to fail verification")
	}
}
