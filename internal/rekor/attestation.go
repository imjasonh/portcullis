package rekor

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// Attestation represents a portcullis attestation stored in Rekor.
type Attestation struct {
	Type      string    `json:"_type"`
	Subject   Subject   `json:"subject"`
	Verdict   string    `json:"verdict"`   // "approve" or "deny"
	Reason    string    `json:"reason"`    // optional
	Identity  string    `json:"identity"`  // signer email
	Timestamp time.Time `json:"timestamp"`
}

// Subject identifies the script being attested.
type Subject struct {
	SHA256 string `json:"sha256"`
}

const AttestationType = "https://portcullis.dev/attestation/v1"

// NewAttestation creates a new attestation.
func NewAttestation(hash, verdict, identity, reason string) Attestation {
	return Attestation{
		Type:      AttestationType,
		Subject:   Subject{SHA256: hash},
		Verdict:   verdict,
		Identity:  identity,
		Reason:    reason,
		Timestamp: time.Now(),
	}
}

// FormatAttestationContext writes a summary of untrusted attestations to w.
func FormatAttestationContext(attestations []Attestation, w io.Writer) {
	approvals := 0
	denials := 0
	for _, att := range attestations {
		switch att.Verdict {
		case "approve":
			approvals++
		case "deny":
			denials++
		}
	}

	if approvals > 0 {
		fmt.Fprintf(w, "%d unknown %s approved this:\n",
			approvals, Pluralize("identity", approvals))
		for _, att := range attestations {
			if att.Verdict == "approve" {
				fmt.Fprintf(w, "  - %s (%s)\n", att.Identity, att.Timestamp.Format("2006-01-02"))
			}
		}
	}

	if denials > 0 {
		fmt.Fprintf(w, "%d unknown %s flagged this:\n",
			denials, Pluralize("identity", denials))
		for _, att := range attestations {
			if att.Verdict == "deny" {
				msg := fmt.Sprintf("  - %s (%s)", att.Identity, att.Timestamp.Format("2006-01-02"))
				if att.Reason != "" {
					msg += fmt.Sprintf(": '%s'", att.Reason)
				}
				fmt.Fprintln(w, msg)
			}
		}
	}
}

// Pluralize returns the plural form of a word based on count.
func Pluralize(word string, count int) string {
	if count == 1 {
		return word
	}
	if strings.HasSuffix(word, "y") {
		return word[:len(word)-1] + "ies"
	}
	return word + "s"
}
