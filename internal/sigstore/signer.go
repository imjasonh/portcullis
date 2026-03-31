package sigstore

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/oauthflow"
)

const (
	// SigstoreOIDCIssuer is the default Sigstore OIDC issuer.
	SigstoreOIDCIssuer = "https://oauth2.sigstore.dev/auth"
	// SigstoreOIDCClientID is the default client ID for Sigstore.
	SigstoreOIDCClientID = "sigstore"
	// FulcioURL is the public Fulcio instance.
	FulcioURL = "https://fulcio.sigstore.dev"
	// RekorURL is the public Rekor instance.
	RekorURL = "https://rekor.sigstore.dev"

	// AttestationPayloadType is the DSSE payload type for portcullis attestations.
	AttestationPayloadType = "application/vnd.portcullis.attestation.v1+json"
)

// AttestationPayload is the JSON payload for portcullis attestations.
type AttestationPayload struct {
	Type       string    `json:"_type"`
	ScriptHash string    `json:"script_hash"`
	Verdict    string    `json:"verdict"`
	Reason     string    `json:"reason,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

// Authenticate performs the Sigstore OIDC flow and returns an ID token.
func Authenticate(stderr io.Writer) (*oauthflow.OIDCIDToken, error) {
	fmt.Fprintln(stderr, "portcullis: opening browser for Sigstore authentication...")
	token, err := oauthflow.OIDConnect(
		SigstoreOIDCIssuer,
		SigstoreOIDCClientID,
		"",
		"",
		oauthflow.DefaultIDTokenGetter,
	)
	if err != nil {
		return nil, fmt.Errorf("OIDC authentication failed: %w", err)
	}
	fmt.Fprintf(stderr, "portcullis: authenticated as %s\n", token.Subject)
	return token, nil
}

// SignAndPublish signs an attestation payload using sigstore-go's Bundle flow:
// ephemeral keypair → Fulcio certificate → Rekor transparency log entry.
// The signed bundle is self-contained and publicly auditable.
func SignAndPublish(ctx context.Context, payload AttestationPayload, idToken string, stderr io.Writer) error {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling attestation: %w", err)
	}

	// Create ephemeral ECDSA P-256 keypair (used once, then discarded).
	keypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return fmt.Errorf("creating ephemeral keypair: %w", err)
	}

	// The attestation payload is the content to sign.
	// Using PlainData creates a hashedrekord entry in Rekor, indexed by the
	// SHA-256 of the payload (which contains the script hash).
	content := &sign.PlainData{Data: payloadBytes}

	// Fulcio: get a short-lived signing certificate bound to the OIDC identity.
	fulcio := sign.NewFulcio(&sign.FulcioOptions{
		BaseURL: FulcioURL,
	})

	// Rekor: log the signed entry to the transparency log.
	rekor := sign.NewRekor(&sign.RekorOptions{
		BaseURL: RekorURL,
	})

	fmt.Fprintln(stderr, "portcullis: signing attestation via Sigstore (Fulcio + Rekor)...")
	_, err = sign.Bundle(content, keypair, sign.BundleOptions{
		Context:             ctx,
		CertificateProvider: fulcio,
		CertificateProviderOptions: &sign.CertificateProviderOptions{
			IDToken: idToken,
		},
		TransparencyLogs: []sign.Transparency{rekor},
	})
	if err != nil {
		return fmt.Errorf("signing bundle: %w", err)
	}

	fmt.Fprintln(stderr, "portcullis: attestation signed and logged to Rekor")
	return nil
}
