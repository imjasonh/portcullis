package trust

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Store manages trusted identities persisted in a config file.
type Store struct {
	path       string
	identities []string
	domains    []string
	mu         sync.Mutex
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
		for _, d := range s.domains {
			if d == identity {
				return fmt.Errorf("domain %s already trusted", identity)
			}
		}
		s.domains = append(s.domains, identity)
	} else {
		for _, id := range s.identities {
			if id == identity {
				return fmt.Errorf("identity %s already trusted", identity)
			}
		}
		s.identities = append(s.identities, identity)
	}
	return s.save()
}

// Remove removes an identity or domain from the trust list.
func (s *Store) Remove(identity string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if strings.HasPrefix(identity, "@") {
		found := false
		for i, d := range s.domains {
			if d == identity {
				s.domains = append(s.domains[:i], s.domains[i+1:]...)
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("domain %s not found", identity)
		}
	} else {
		found := false
		for i, id := range s.identities {
			if id == identity {
				s.identities = append(s.identities[:i], s.identities[i+1:]...)
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
	return append([]string{}, s.identities...), append([]string{}, s.domains...)
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
	// Simple TOML parser for our specific format.
	s.identities, s.domains = parseTrustConfig(string(data))
	return nil
}

// save writes the trust config to disk.
func (s *Store) save() error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	content := formatTrustConfig(s.identities, s.domains)
	return os.WriteFile(s.path, []byte(content), 0600)
}

// parseTrustConfig parses our TOML config format.
func parseTrustConfig(data string) (identities []string, domains []string) {
	lines := strings.Split(data, "\n")
	inIdentities := false
	inDomains := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "[trust]":
			continue
		case trimmed == "[policy]":
			inIdentities = false
			inDomains = false
		case strings.HasPrefix(trimmed, "identities"):
			inIdentities = true
			inDomains = false
		case strings.HasPrefix(trimmed, "domains"):
			inDomains = true
			inIdentities = false
		case strings.HasPrefix(trimmed, "]"):
			if inIdentities {
				inIdentities = false
			}
			if inDomains {
				inDomains = false
			}
		case strings.HasPrefix(trimmed, "\""):
			val := strings.Trim(trimmed, "\", ")
			if inIdentities {
				identities = append(identities, val)
			} else if inDomains {
				domains = append(domains, val)
			}
		}
	}
	return
}

// formatTrustConfig produces our TOML config.
func formatTrustConfig(identities []string, domains []string) string {
	var b strings.Builder
	b.WriteString("[trust]\n")
	b.WriteString("identities = [\n")
	for _, id := range identities {
		fmt.Fprintf(&b, "    %q,\n", id)
	}
	b.WriteString("]\n")
	b.WriteString("domains = [\n")
	for _, d := range domains {
		fmt.Fprintf(&b, "    %q,\n", d)
	}
	b.WriteString("]\n")
	return b.String()
}
