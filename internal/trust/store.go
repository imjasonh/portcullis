package trust

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"
)

// Store manages trusted identities persisted in a config file.
type Store struct {
	path string
	// full is the parsed config file; [trust] and [policy] sections are preserved.
	// Note: any other custom sections in config.toml will not survive a round-trip.
	full   configFile
	mu     sync.Mutex
}

// configFile mirrors the TOML structure we persist.
type configFile struct {
	Trust   trustSection   `toml:"trust"`
	Policy  policySection  `toml:"policy,omitempty"`
}

type trustSection struct {
	Identities []string `toml:"identities"`
	Domains    []string `toml:"domains"`
}

// policySection is kept opaque so we round-trip it without loss.
type policySection struct {
	OnNegative string `toml:"on_negative,omitempty"`
	OnPositive string `toml:"on_positive,omitempty"`
	OnUnknown  string `toml:"on_unknown,omitempty"`
	CacheTTL   string `toml:"cache_ttl,omitempty"`
}

// NewStore creates a new trust store. If configDir is empty, uses default config path.
func NewStore(configDir string) (*Store, error) {
	if configDir == "" {
		configDir = DefaultConfigDir()
	}
	s := &Store{
		path: filepath.Join(configDir, "config.toml"),
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// DefaultConfigDir returns the default configuration directory.
func DefaultConfigDir() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "portcullis")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "portcullis")
}

// Add adds an identity or domain to the trust list.
func (s *Store) Add(identity string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if strings.HasPrefix(identity, "@") {
		for _, d := range s.full.Trust.Domains {
			if d == identity {
				return fmt.Errorf("domain %s already trusted", identity)
			}
		}
		s.full.Trust.Domains = append(s.full.Trust.Domains, identity)
	} else {
		for _, id := range s.full.Trust.Identities {
			if id == identity {
				return fmt.Errorf("identity %s already trusted", identity)
			}
		}
		s.full.Trust.Identities = append(s.full.Trust.Identities, identity)
	}
	return s.save()
}

// Remove removes an identity or domain from the trust list.
func (s *Store) Remove(identity string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if strings.HasPrefix(identity, "@") {
		found := false
		for i, d := range s.full.Trust.Domains {
			if d == identity {
				s.full.Trust.Domains = append(s.full.Trust.Domains[:i], s.full.Trust.Domains[i+1:]...)
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("domain %s not found", identity)
		}
	} else {
		found := false
		for i, id := range s.full.Trust.Identities {
			if id == identity {
				s.full.Trust.Identities = append(s.full.Trust.Identities[:i], s.full.Trust.Identities[i+1:]...)
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("identity %s not found", identity)
		}
	}
	return s.save()
}

// List returns all trusted identities and domains.
func (s *Store) List() (identities []string, domains []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.full.Trust.Identities...), append([]string{}, s.full.Trust.Domains...)
}

// load reads the config file and populates the store.
func (s *Store) load() error {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := toml.Decode(string(data), &s.full); err != nil {
		return fmt.Errorf("parsing config: %w", err)
	}
	return nil
}

// save writes the full config to disk, preserving all sections.
func (s *Store) save() error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	var buf bytes.Buffer
	enc := toml.NewEncoder(&buf)
	if err := enc.Encode(s.full); err != nil {
		return fmt.Errorf("encoding config: %w", err)
	}
	return os.WriteFile(s.path, buf.Bytes(), 0600)
}
