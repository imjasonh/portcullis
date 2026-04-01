package trust

import "strings"

// IsTrusted checks if the given identity is trusted by the store.
// Matches exact email addresses and @domain suffixes.
func (s *Store) IsTrusted(identity string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Exact email match.
	for _, id := range s.full.Trust.Identities {
		if id == identity {
			return true
		}
	}

	// Domain suffix match.
	for _, domain := range s.full.Trust.Domains {
		suffix := domain // e.g., "@chainguard.dev"
		if strings.HasSuffix(identity, suffix) {
			return true
		}
	}

	return false
}
