package gate

import (
	"bytes"
	"testing"
	"time"

	"github.com/imjasonh/portcullis/internal/rekor"
	"github.com/imjasonh/portcullis/internal/trust"
)

func newTestStore(t *testing.T, identities ...string) *trust.Store {
	t.Helper()
	dir := t.TempDir()
	s, err := trust.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range identities {
		s.Add(id)
	}
	return s
}

func TestDecide_TrustedApproval(t *testing.T) {
	store := newTestStore(t, "alice@example.com")
	atts := []rekor.Attestation{
		{Identity: "alice@example.com", Verdict: "approve", Timestamp: time.Now()},
	}

	var stderr bytes.Buffer
	result := Decide(atts, store, &stderr)

	if result.Verdict != VerdictApprove {
		t.Errorf("expected approve, got %s", result.Verdict)
	}
}

func TestDecide_TrustedDenial(t *testing.T) {
	store := newTestStore(t, "alice@example.com")
	atts := []rekor.Attestation{
		{Identity: "alice@example.com", Verdict: "deny", Reason: "malicious", Timestamp: time.Now()},
	}

	var stderr bytes.Buffer
	result := Decide(atts, store, &stderr)

	if result.Verdict != VerdictDeny {
		t.Errorf("expected deny, got %s", result.Verdict)
	}
}

func TestDecide_DenyWinsOverApprove(t *testing.T) {
	store := newTestStore(t, "alice@example.com", "bob@example.com")
	atts := []rekor.Attestation{
		{Identity: "alice@example.com", Verdict: "approve", Timestamp: time.Now()},
		{Identity: "bob@example.com", Verdict: "deny", Reason: "bad script", Timestamp: time.Now()},
	}

	var stderr bytes.Buffer
	result := Decide(atts, store, &stderr)

	if result.Verdict != VerdictDeny {
		t.Errorf("expected deny to win over approve, got %s", result.Verdict)
	}
}

func TestDecide_NoTrustedSignals(t *testing.T) {
	store := newTestStore(t, "alice@example.com")
	atts := []rekor.Attestation{
		{Identity: "unknown@other.com", Verdict: "approve", Timestamp: time.Now()},
	}

	var stderr bytes.Buffer
	result := Decide(atts, store, &stderr)

	if result.Verdict != VerdictReview {
		t.Errorf("expected review, got %s", result.Verdict)
	}
	if len(result.Untrusted) != 1 {
		t.Errorf("expected 1 untrusted attestation, got %d", len(result.Untrusted))
	}
}

func TestDecide_EmptyAttestations(t *testing.T) {
	store := newTestStore(t, "alice@example.com")

	var stderr bytes.Buffer
	result := Decide(nil, store, &stderr)

	if result.Verdict != VerdictReview {
		t.Errorf("expected review for empty attestations, got %s", result.Verdict)
	}
}

func TestDecide_DomainMatch(t *testing.T) {
	store := newTestStore(t, "@chainguard.dev")
	atts := []rekor.Attestation{
		{Identity: "bob@chainguard.dev", Verdict: "approve", Timestamp: time.Now()},
	}

	var stderr bytes.Buffer
	result := Decide(atts, store, &stderr)

	if result.Verdict != VerdictApprove {
		t.Errorf("expected domain match to approve, got %s", result.Verdict)
	}
}
