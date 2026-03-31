package sigstore

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/oauthflow"
)

const (
	// SigstoreOIDCIssuer is the default Sigstore OIDC issuer.
	SigstoreOIDCIssuer = "https://oauth2.sigstore.dev/auth"
	// SigstoreOIDCClientID is the default client ID for Sigstore.
	SigstoreOIDCClientID = "sigstore"
	// FulcioURL is the public Fulcio instance.
	FulcioURL = "https://fulcio.sigstore.dev"

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

// SigningResult holds the output of a signing operation.
type SigningResult struct {
	Signature []byte // DER-encoded ECDSA signature
	CertPEM   []byte // PEM-encoded Fulcio signing certificate
	Content   []byte // The signed content (attestation JSON)
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

// SignAttestation signs an attestation payload with an ephemeral key and obtains
// a Fulcio certificate. Returns the signing result for Rekor submission.
func SignAttestation(ctx context.Context, payload AttestationPayload, idToken string, stderr io.Writer) (*SigningResult, error) {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling attestation: %w", err)
	}

	// Generate ephemeral ECDSA keypair.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating keypair: %w", err)
	}

	// Sign the attestation content.
	digest := sha256.Sum256(payloadBytes)
	signature, err := privateKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}

	// Get a Fulcio signing certificate.
	fmt.Fprintln(stderr, "portcullis: requesting signing certificate from Fulcio...")
	certPEM, err := getFulcioCert(ctx, privateKey, idToken)
	if err != nil {
		return nil, fmt.Errorf("fulcio certificate: %w", err)
	}

	fmt.Fprintln(stderr, "portcullis: attestation signed successfully")
	return &SigningResult{
		Signature: signature,
		CertPEM:   certPEM,
		Content:   payloadBytes,
	}, nil
}

// fulcioCertRequest is the request body for Fulcio's /api/v2/signingCert endpoint.
type fulcioCertRequest struct {
	PublicKeyRequest publicKeyRequest `json:"publicKeyRequest"`
}

type publicKeyRequest struct {
	PublicKey         publicKey `json:"publicKey"`
	ProofOfPossession string    `json:"proofOfPossession"`
}

type publicKey struct {
	Algorithm string `json:"algorithm"`
	Content   string `json:"content"`
}

type fulcioResponse struct {
	SctCertWithChain signedCertificateEmbeddedSct `json:"signedCertificateEmbeddedSct"`
}

type signedCertificateEmbeddedSct struct {
	Chain chain `json:"chain"`
}

type chain struct {
	Certificates []string `json:"certificates"`
}

// getFulcioCert requests a signing certificate from Fulcio using the ephemeral key and OIDC token.
func getFulcioCert(ctx context.Context, privateKey *ecdsa.PrivateKey, idToken string) ([]byte, error) {
	// Extract subject from token for proof of possession.
	tokenParts := strings.Split(idToken, ".")
	if len(tokenParts) < 2 {
		return nil, fmt.Errorf("invalid identity token format")
	}

	jwtPayload, err := base64.RawURLEncoding.DecodeString(tokenParts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding token payload: %w", err)
	}

	subject, err := oauthflow.SubjectFromUnverifiedToken(jwtPayload)
	if err != nil {
		return nil, fmt.Errorf("extracting subject: %w", err)
	}

	// Sign the subject as proof of possession.
	subjectDigest := sha256.Sum256([]byte(subject))
	proofSig, err := privateKey.Sign(rand.Reader, subjectDigest[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("signing proof of possession: %w", err)
	}

	// Marshal the public key.
	pubKeyPEM, err := cryptoutils.MarshalPublicKeyToPEM(privateKey.Public())
	if err != nil {
		return nil, fmt.Errorf("marshaling public key: %w", err)
	}

	// Build the Fulcio request.
	certReq := fulcioCertRequest{
		PublicKeyRequest: publicKeyRequest{
			PublicKey: publicKey{
				Algorithm: "ECDSA",
				Content:   string(pubKeyPEM),
			},
			ProofOfPossession: base64.StdEncoding.EncodeToString(proofSig),
		},
	}

	reqBody, err := json.Marshal(certReq)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	// Call Fulcio.
	req, err := http.NewRequestWithContext(ctx, "POST", FulcioURL+"/api/v2/signingCert", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+idToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fulcio request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading fulcio response: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("fulcio returned %d: %s", resp.StatusCode, string(body))
	}

	var fulcioResp fulcioResponse
	if err := json.Unmarshal(body, &fulcioResp); err != nil {
		return nil, fmt.Errorf("parsing fulcio response: %w", err)
	}

	certs := fulcioResp.SctCertWithChain.Chain.Certificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("fulcio returned no certificates")
	}

	// Verify the certificate contains our public key.
	block, _ := pem.Decode([]byte(certs[0]))
	if block == nil {
		return nil, fmt.Errorf("unable to parse Fulcio certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing Fulcio certificate: %w", err)
	}

	certPubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unexpected certificate public key type: %T", cert.PublicKey)
	}

	if !certPubKey.Equal(privateKey.Public()) {
		return nil, fmt.Errorf("fulcio certificate does not match our keypair")
	}

	return []byte(certs[0]), nil
}
