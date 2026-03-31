package trust

import "testing"

func TestIsTrusted_ExactMatch(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(dir)
	s.Add("alice@example.com")

	if !s.IsTrusted("alice@example.com") {
		t.Error("expected alice@example.com to be trusted")
	}
	if s.IsTrusted("bob@example.com") {
		t.Error("expected bob@example.com to not be trusted")
	}
}

func TestIsTrusted_DomainMatch(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(dir)
	s.Add("@chainguard.dev")

	if !s.IsTrusted("alice@chainguard.dev") {
		t.Error("expected alice@chainguard.dev to match @chainguard.dev")
	}
	if !s.IsTrusted("bob@chainguard.dev") {
		t.Error("expected bob@chainguard.dev to match @chainguard.dev")
	}
	if s.IsTrusted("alice@example.com") {
		t.Error("expected alice@example.com to not match @chainguard.dev")
	}
}

func TestIsTrusted_BothMatchTypes(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(dir)
	s.Add("specific@example.com")
	s.Add("@google.com")

	if !s.IsTrusted("specific@example.com") {
		t.Error("expected exact match to work")
	}
	if !s.IsTrusted("anyone@google.com") {
		t.Error("expected domain match to work")
	}
	if s.IsTrusted("other@example.com") {
		t.Error("expected non-matching identity to be untrusted")
	}
}
