package rekor

import "time"

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
