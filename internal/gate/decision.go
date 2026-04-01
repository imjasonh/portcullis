package gate

import (
	"fmt"
	"io"

	"github.com/imjasonh/portcullis/internal/rekor"
	"github.com/imjasonh/portcullis/internal/trust"
)

// Verdict represents a gate decision.
type Verdict string

const (
	VerdictApprove Verdict = "approve"
	VerdictDeny    Verdict = "deny"
	VerdictReview  Verdict = "review"
)

// DecisionResult holds the outcome of the decision engine.
type DecisionResult struct {
	Verdict       Verdict
	Reason        string
	Identity      string              // identity that drove the decision (for cache)
	TrustedBy     []rekor.Attestation // trusted attestations that informed the decision
	Untrusted     []rekor.Attestation // unknown attestations shown as context
}

// Decide evaluates attestations against the trust store and returns a verdict.
func Decide(attestations []rekor.Attestation, trustStore *trust.Store, stderr io.Writer) DecisionResult {
	var trusted, untrusted []rekor.Attestation

	for _, att := range attestations {
		if trustStore.IsTrusted(att.Identity) {
			trusted = append(trusted, att)
		} else {
			untrusted = append(untrusted, att)
		}
	}

	// Check for negative signals from trusted identities.
	for _, att := range trusted {
		if att.Verdict == "deny" {
			reason := fmt.Sprintf("blocked by trusted identity %s", att.Identity)
			if att.Reason != "" {
				reason += fmt.Sprintf(": %s", att.Reason)
			}
			fmt.Fprintf(stderr, "portcullis: %s (attested %s)\n", reason, att.Timestamp.Format("2006-01-02"))
			return DecisionResult{
				Verdict:   VerdictDeny,
				Reason:    reason,
				Identity:  att.Identity,
				TrustedBy: trusted,
				Untrusted: untrusted,
			}
		}
	}

	// Check for positive signals from trusted identities (with no negatives).
	for _, att := range trusted {
		if att.Verdict == "approve" {
			fmt.Fprintf(stderr, "portcullis: approved by trusted identity %s (attested %s)\n",
				att.Identity, att.Timestamp.Format("2006-01-02"))
			return DecisionResult{
				Verdict:   VerdictApprove,
				Reason:    fmt.Sprintf("approved by %s", att.Identity),
				Identity:  att.Identity,
				TrustedBy: trusted,
				Untrusted: untrusted,
			}
		}
	}

	// No trusted signals — needs review.
	if len(untrusted) > 0 {
		rekor.FormatAttestationContext(untrusted, stderr)
	}

	return DecisionResult{
		Verdict:   VerdictReview,
		Reason:    "no trusted attestations found",
		Untrusted: untrusted,
	}
}

