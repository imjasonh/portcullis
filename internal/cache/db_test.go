package cache

import (
	"testing"
	"time"
)

func TestCache_StoreAndLookup(t *testing.T) {
	dir := t.TempDir()
	c, err := Open(dir, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	d := Decision{
		ScriptHash: "abc123",
		Verdict:    "approve",
		Source:     "attested",
		Identity:   "alice@example.com",
	}
	if err := c.Store(d); err != nil {
		t.Fatal(err)
	}

	got, err := c.Lookup("abc123")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected cache hit, got nil")
	}
	if got.Verdict != "approve" {
		t.Errorf("expected approve, got %s", got.Verdict)
	}
	if got.Identity != "alice@example.com" {
		t.Errorf("expected alice@example.com, got %s", got.Identity)
	}
}

func TestCache_Miss(t *testing.T) {
	dir := t.TempDir()
	c, err := Open(dir, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	got, err := c.Lookup("nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Error("expected cache miss, got hit")
	}
}

func TestCache_Expiry(t *testing.T) {
	dir := t.TempDir()
	c, err := Open(dir, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Store with already-expired TTL.
	d := Decision{
		ScriptHash: "expired123",
		Verdict:    "approve",
		Source:     "local",
		CreatedAt:  time.Now().Add(-48 * time.Hour),
		ExpiresAt:  time.Now().Add(-24 * time.Hour),
	}
	if err := c.Store(d); err != nil {
		t.Fatal(err)
	}

	// Normal lookup should miss.
	got, err := c.Lookup("expired123")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Error("expected expired entry to be missed")
	}

	// Expired lookup should hit.
	got, err = c.LookupExpired("expired123")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Error("expected expired lookup to find entry")
	}
}

func TestCache_Upsert(t *testing.T) {
	dir := t.TempDir()
	c, err := Open(dir, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	c.Store(Decision{ScriptHash: "hash1", Verdict: "approve", Source: "local"})
	c.Store(Decision{ScriptHash: "hash1", Verdict: "deny", Source: "attested", Identity: "bob@example.com"})

	got, _ := c.Lookup("hash1")
	if got.Verdict != "deny" {
		t.Errorf("expected upsert to update verdict to deny, got %s", got.Verdict)
	}
}

func TestCache_DenyDecision(t *testing.T) {
	dir := t.TempDir()
	c, err := Open(dir, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	c.Store(Decision{
		ScriptHash: "bad123",
		Verdict:    "deny",
		Source:     "attested",
		Identity:   "alice@example.com",
		Reason:     "exfiltrates env vars",
	})

	got, _ := c.Lookup("bad123")
	if got == nil {
		t.Fatal("expected cache hit")
	}
	if got.Verdict != "deny" {
		t.Errorf("expected deny, got %s", got.Verdict)
	}
	if got.Reason != "exfiltrates env vars" {
		t.Errorf("expected reason, got %s", got.Reason)
	}
}
