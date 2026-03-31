package review

import (
	"bytes"
	"testing"
	"time"

	"github.com/imjasonh/portcullis/internal/rekor"
)

func TestPrintAttestationContext(t *testing.T) {
	attestations := []rekor.Attestation{
		{Identity: "alice@example.com", Verdict: "approve", Timestamp: time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)},
		{Identity: "bob@example.com", Verdict: "approve", Timestamp: time.Date(2026, 3, 20, 0, 0, 0, 0, time.UTC)},
		{Identity: "mallory@evil.com", Verdict: "deny", Reason: "sends env to remote host", Timestamp: time.Date(2026, 3, 28, 0, 0, 0, 0, time.UTC)},
	}

	var buf bytes.Buffer
	printAttestationContext(attestations, &buf)

	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("2 unknown identities approved this")) {
		t.Errorf("expected approval count, got: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("1 unknown identity flagged this")) {
		t.Errorf("expected denial count, got: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("sends env to remote host")) {
		t.Errorf("expected reason in output, got: %s", output)
	}
}

func TestPluralize(t *testing.T) {
	if pluralize("identity", 1) != "identity" {
		t.Error("expected singular")
	}
	if pluralize("identity", 2) != "identities" {
		t.Error("expected plural")
	}
	if pluralize("identity", 0) != "identities" {
		t.Error("expected plural for zero")
	}
}
