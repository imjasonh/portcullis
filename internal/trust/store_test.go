package trust

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStore_AddAndList(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Add("alice@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.Add("@chainguard.dev"); err != nil {
		t.Fatal(err)
	}

	ids, domains := s.List()
	if len(ids) != 1 || ids[0] != "alice@example.com" {
		t.Errorf("expected [alice@example.com], got %v", ids)
	}
	if len(domains) != 1 || domains[0] != "@chainguard.dev" {
		t.Errorf("expected [@chainguard.dev], got %v", domains)
	}
}

func TestStore_Remove(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	s.Add("alice@example.com")
	s.Add("bob@example.com")
	s.Add("@google.com")

	if err := s.Remove("alice@example.com"); err != nil {
		t.Fatal(err)
	}
	ids, _ := s.List()
	if len(ids) != 1 || ids[0] != "bob@example.com" {
		t.Errorf("expected [bob@example.com], got %v", ids)
	}

	if err := s.Remove("@google.com"); err != nil {
		t.Fatal(err)
	}
	_, domains := s.List()
	if len(domains) != 0 {
		t.Errorf("expected empty domains, got %v", domains)
	}
}

func TestStore_DuplicateAdd(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	s.Add("alice@example.com")
	if err := s.Add("alice@example.com"); err == nil {
		t.Error("expected error for duplicate add")
	}
}

func TestStore_RemoveNotFound(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Remove("nobody@example.com"); err == nil {
		t.Error("expected error for removing non-existent identity")
	}
}

func TestStore_Persistence(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	s.Add("alice@example.com")
	s.Add("@chainguard.dev")

	// Reload from disk.
	s2, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ids, domains := s2.List()
	if len(ids) != 1 || ids[0] != "alice@example.com" {
		t.Errorf("persistence: expected [alice@example.com], got %v", ids)
	}
	if len(domains) != 1 || domains[0] != "@chainguard.dev" {
		t.Errorf("persistence: expected [@chainguard.dev], got %v", domains)
	}
}

func TestStore_ConfigFilePermissions(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	s.Add("alice@example.com")

	info, err := os.Stat(filepath.Join(dir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("expected 0600 permissions, got %o", perm)
	}
}
