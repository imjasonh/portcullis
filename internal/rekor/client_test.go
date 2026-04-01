package rekor

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/sigstore/rekor/pkg/generated/models"
)

// generateTestCert creates a self-signed test certificate with the given email.
func generateTestCert(t *testing.T, email string) []byte {
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
		EmailAddresses: []string{email},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().Add(10 * time.Minute),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

func TestExtractIdentityFromPEM(t *testing.T) {
	certPEM := generateTestCert(t, "alice@example.com")

	identity, err := extractIdentityFromPEM(string(certPEM))
	if err != nil {
		t.Fatal(err)
	}
	if identity != "alice@example.com" {
		t.Errorf("expected alice@example.com, got %s", identity)
	}
}

func TestExtractIdentityFromPEM_NoPEM(t *testing.T) {
	_, err := extractIdentityFromPEM("not a cert")
	if err == nil {
		t.Error("expected error for non-PEM input")
	}
}

func TestParseHashedRekordEntry(t *testing.T) {
	certPEM := generateTestCert(t, "bob@chainguard.dev")
	certB64 := base64.StdEncoding.EncodeToString(certPEM)

	spec := map[string]interface{}{
		"data": map[string]interface{}{
			"hash": map[string]interface{}{
				"algorithm": "sha256",
				"value":     "abc123def456",
			},
		},
		"signature": map[string]interface{}{
			"content": "c2lnbmF0dXJl", // base64("signature")
			"publicKey": map[string]interface{}{
				"content": certB64,
			},
		},
	}

	specJSON, _ := json.Marshal(spec)
	timestamp := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)

	att, err := parseHashedRekordEntry(specJSON, timestamp)
	if err != nil {
		t.Fatal(err)
	}

	if att.Identity != "bob@chainguard.dev" {
		t.Errorf("expected bob@chainguard.dev, got %s", att.Identity)
	}
	if att.Subject.SHA256 != "abc123def456" {
		t.Errorf("expected abc123def456, got %s", att.Subject.SHA256)
	}
	if att.Timestamp != timestamp {
		t.Errorf("expected timestamp %v, got %v", timestamp, att.Timestamp)
	}
}

func TestParseLogEntry_HashedRekord(t *testing.T) {
	certPEM := generateTestCert(t, "alice@example.com")
	certB64 := base64.StdEncoding.EncodeToString(certPEM)

	body := map[string]interface{}{
		"apiVersion": "0.0.1",
		"kind":       "hashedrekord",
		"spec": map[string]interface{}{
			"data": map[string]interface{}{
				"hash": map[string]interface{}{
					"algorithm": "sha256",
					"value":     "deadbeef",
				},
			},
			"signature": map[string]interface{}{
				"content": "c2ln",
				"publicKey": map[string]interface{}{
					"content": certB64,
				},
			},
		},
	}

	bodyJSON, _ := json.Marshal(body)
	bodyB64 := base64.StdEncoding.EncodeToString(bodyJSON)

	intTime := int64(1711900800) // 2024-03-31 12:00:00 UTC
	logID := "0000000000000000000000000000000000000000000000000000000000000000"
	logIndex := int64(0)
	entry := &models.LogEntryAnon{
		Body:           bodyB64,
		IntegratedTime: &intTime,
		LogID:          &logID,
		LogIndex:       &logIndex,
	}

	att, err := parseLogEntry(entry)
	if err != nil {
		t.Fatal(err)
	}

	if att.Identity != "alice@example.com" {
		t.Errorf("expected alice@example.com, got %s", att.Identity)
	}
	if att.Subject.SHA256 != "deadbeef" {
		t.Errorf("expected deadbeef, got %s", att.Subject.SHA256)
	}
}

func TestParseLogEntry_UnsupportedKind(t *testing.T) {
	body := map[string]interface{}{
		"apiVersion": "0.0.1",
		"kind":       "alpine",
		"spec":       map[string]interface{}{},
	}
	bodyJSON, _ := json.Marshal(body)
	bodyB64 := base64.StdEncoding.EncodeToString(bodyJSON)

	intTime := int64(1711900800)
	logID := "0000000000000000000000000000000000000000000000000000000000000000"
	logIndex := int64(0)
	entry := &models.LogEntryAnon{
		Body:           bodyB64,
		IntegratedTime: &intTime,
		LogID:          &logID,
		LogIndex:       &logIndex,
	}

	_, err := parseLogEntry(entry)
	if err == nil {
		t.Error("expected error for unsupported kind")
	}
}
