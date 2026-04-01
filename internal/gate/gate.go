package gate

import (
	"crypto/sha256"
	"fmt"
	"io"
	"time"

	"github.com/imjasonh/portcullis/internal/cache"
	"github.com/imjasonh/portcullis/internal/config"
	"github.com/imjasonh/portcullis/internal/rekor"
	"github.com/imjasonh/portcullis/internal/trust"
)

// Gate orchestrates the full pipe flow: validate, hash, decide, output.
type Gate struct {
	TrustStore  *trust.Store
	Cache       *cache.Cache
	RekorClient *rekor.Client
	Policy      config.Policy
	ConfigDir   string
	// ReviewFunc is called when interactive review is needed.
	// Returns verdict ("approve", "deny", "run", "block") and whether to attest.
	ReviewFunc func(script []byte, untrusted []rekor.Attestation, stderr io.Writer) (string, bool, string, error)
	// AttestFunc is called to sign and publish an attestation to Rekor.
	// Parameters: script hash, verdict, reason, stderr writer.
	AttestFunc func(hash, verdict, reason string, stderr io.Writer) error
}

// New creates a new Gate with default configuration.
func New() *Gate {
	return &Gate{
		Policy: config.DefaultPolicy(),
	}
}

// NewWithConfig creates a Gate with full configuration.
func NewWithConfig(configDir string) (*Gate, error) {
	policy := config.LoadPolicy(configDir)

	trustStore, err := trust.NewStore(configDir)
	if err != nil {
		return nil, fmt.Errorf("loading trust store: %w", err)
	}

	c, err := cache.Open(configDir, policy.CacheTTL)
	if err != nil {
		return nil, fmt.Errorf("opening cache: %w", err)
	}

	return &Gate{
		TrustStore:  trustStore,
		Cache:       c,
		RekorClient: rekor.NewClient(),
		Policy:      policy,
		ConfigDir:   configDir,
	}, nil
}

// Run processes a script through the gate pipeline.
func (g *Gate) Run(input []byte, stdout io.Writer, stderr io.Writer) error {
	// Step 1: Shell validation.
	if err := Validate(input, stderr); err != nil {
		return err
	}

	// Step 2: Compute SHA-256.
	hash := ComputeHash(input)
	fmt.Fprintf(stderr, "portcullis: sha256:%s\n", hash)

	// Step 3: Check local cache.
	if g.Cache != nil {
		decision, err := g.Cache.Lookup(hash)
		if err != nil {
			fmt.Fprintf(stderr, "portcullis: cache error: %v\n", err)
		}
		if decision != nil {
			return g.applyCachedDecision(decision, input, stdout, stderr)
		}
	}

	// Step 4: Query Rekor for attestations.
	var attestations []rekor.Attestation
	rekorFailed := false
	if g.RekorClient != nil {
		result := g.RekorClient.Query(hash)
		if result.Err != nil {
			fmt.Fprintf(stderr, "portcullis: rekor query failed: %v\n", result.Err)
			rekorFailed = true

			// Fall back to expired cache.
			if g.Cache != nil {
				expired, _ := g.Cache.LookupExpired(hash)
				if expired != nil {
					fmt.Fprintln(stderr, "portcullis: using expired cache entry as fallback")
					return g.applyCachedDecision(expired, input, stdout, stderr)
				}
			}
		} else {
			attestations = result.Attestations
		}
	}

	// Step 5: Decision engine.
	if g.TrustStore != nil {
		result := Decide(attestations, g.TrustStore, stderr)

		switch result.Verdict {
		case VerdictApprove:
			// Apply on_positive policy: "review" forces interactive review even with trusted approval.
			if g.Policy.OnPositive == "review" {
				fmt.Fprintln(stderr, "portcullis: trusted approval found, but policy requires review")
				return g.handleReview(input, hash, result.Untrusted, rekorFailed, stdout, stderr)
			}
			if err := g.cacheDecision(hash, "approve", "attested", "", ""); err != nil {
				fmt.Fprintf(stderr, "portcullis: warning: failed to cache decision: %v\n", err)
			}
			_, err := stdout.Write(input)
			return err

		case VerdictDeny:
			// Apply on_negative policy: "warn" logs warning but passes through instead of blocking.
			if g.Policy.OnNegative == "warn" {
				fmt.Fprintf(stderr, "portcullis: WARNING — %s (passing through per policy)\n", result.Reason)
				if err := g.cacheDecision(hash, "deny", "attested", "", result.Reason); err != nil {
					fmt.Fprintf(stderr, "portcullis: warning: failed to cache decision: %v\n", err)
				}
				_, err := stdout.Write(input)
				return err
			}
			if err := g.cacheDecision(hash, "deny", "attested", "", result.Reason); err != nil {
				fmt.Fprintf(stderr, "portcullis: warning: failed to cache decision: %v\n", err)
			}
			return fmt.Errorf("blocked: %s", result.Reason)

		case VerdictReview:
			return g.handleReview(input, hash, result.Untrusted, rekorFailed, stdout, stderr)
		}
	}

	// No trust store configured — pass through (Phase 1 behavior).
	_, err := stdout.Write(input)
	return err
}

func (g *Gate) applyCachedDecision(d *cache.Decision, input []byte, stdout io.Writer, stderr io.Writer) error {
	switch d.Verdict {
	case "approve":
		fmt.Fprintf(stderr, "portcullis: cached approval")
		if d.Identity != "" {
			fmt.Fprintf(stderr, " (by %s)", d.Identity)
		}
		fmt.Fprintf(stderr, ", expires %s\n", d.ExpiresAt.Format(time.RFC3339))
		_, err := stdout.Write(input)
		return err
	case "deny":
		msg := "portcullis: cached denial"
		if d.Identity != "" {
			msg += fmt.Sprintf(" (by %s)", d.Identity)
		}
		if d.Reason != "" {
			msg += fmt.Sprintf(": %s", d.Reason)
		}
		fmt.Fprintln(stderr, msg)
		return fmt.Errorf("blocked by cached denial")
	default:
		return fmt.Errorf("unknown cached verdict: %s", d.Verdict)
	}
}

func (g *Gate) handleReview(input []byte, hash string, untrusted []rekor.Attestation, rekorFailed bool, stdout io.Writer, stderr io.Writer) error {
	// Check policy for unknown scripts.
	switch g.Policy.OnUnknown {
	case "block":
		fmt.Fprintln(stderr, "portcullis: policy blocks unknown scripts")
		return fmt.Errorf("blocked by policy (on_unknown = block)")
	case "warn":
		fmt.Fprintln(stderr, "portcullis: WARNING — no trusted attestations found, passing through per policy")
		_, err := stdout.Write(input)
		return err
	}

	if rekorFailed {
		fmt.Fprintln(stderr, "portcullis: note: Rekor was unreachable, attestation context may be incomplete")
	}

	// Interactive review.
	if g.ReviewFunc != nil {
		verdict, attest, reason, err := g.ReviewFunc(input, untrusted, stderr)
		if err != nil {
			return err
		}

		switch verdict {
		case "approve":
			source := "local"
			if attest && g.AttestFunc != nil {
				if err := g.AttestFunc(hash, "approve", "", stderr); err != nil {
					fmt.Fprintf(stderr, "portcullis: attestation failed: %v (caching locally)\n", err)
				} else {
					source = "attested"
				}
			}
			if err := g.cacheDecision(hash, "approve", source, "", ""); err != nil {
				fmt.Fprintf(stderr, "portcullis: warning: failed to cache decision: %v\n", err)
			}
			_, err := stdout.Write(input)
			return err
		case "deny":
			source := "local"
			if attest && g.AttestFunc != nil {
				if err := g.AttestFunc(hash, "deny", reason, stderr); err != nil {
					fmt.Fprintf(stderr, "portcullis: attestation failed: %v (caching locally)\n", err)
				} else {
					source = "attested"
				}
			}
			if err := g.cacheDecision(hash, "deny", source, "", reason); err != nil {
				fmt.Fprintf(stderr, "portcullis: warning: failed to cache decision: %v\n", err)
			}
			return fmt.Errorf("blocked by user")
		case "run":
			if err := g.cacheDecision(hash, "approve", "local", "", ""); err != nil {
				fmt.Fprintf(stderr, "portcullis: warning: failed to cache decision: %v\n", err)
			}
			_, err := stdout.Write(input)
			return err
		case "block":
			if err := g.cacheDecision(hash, "deny", "local", "", reason); err != nil {
				fmt.Fprintf(stderr, "portcullis: warning: failed to cache decision: %v\n", err)
			}
			return fmt.Errorf("blocked by user")
		}
	}

	// No review function and policy is "review" — block by default.
	fmt.Fprintln(stderr, "portcullis: no interactive terminal available, blocking by default")
	return fmt.Errorf("blocked: non-interactive context with no trusted attestations")
}

func (g *Gate) cacheDecision(hash, verdict, source, identity, reason string) error {
	if g.Cache == nil {
		return nil
	}
	return g.Cache.Store(cache.Decision{
		ScriptHash: hash,
		Verdict:    verdict,
		Source:     source,
		Identity:   identity,
		Reason:     reason,
	})
}

// ComputeHash returns the hex-encoded SHA-256 hash of the input.
func ComputeHash(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:])
}
