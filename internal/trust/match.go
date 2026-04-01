package trust

import "strings"

// IsTrusted checks if the given identity is trusted by the store.
// Matches exact email addresses and @domain suffixes (compared against
// the domain portion after the final '@' in the identity).
func (s *Store) IsTrusted(identity string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Exact email match.
	for _, id := range s.full.Trust.Identities {
		if id == identity {
			return true
		}
	}

	// Domain suffix match: compare against the part after the last '@'.
	if atIdx := strings.LastIndex(identity, "@"); atIdx >= 0 {
		identityDomain := identity[atIdx:] // e.g., "@chainguard.dev"
		for _, domain := range s.full.Trust.Domains {
			if domain == identityDomain {
				return true
			}
		}
	}

	return false
}
