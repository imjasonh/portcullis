package rekor

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	rekorclient "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
)

const (
	DefaultRekorURL = "https://rekor.sigstore.dev"
)

// Client queries and submits attestations to Rekor.
type Client struct {
	baseURL string
}

// NewClient creates a new Rekor client with the default public instance.
func NewClient() *Client {
	return &Client{
		baseURL: DefaultRekorURL,
	}
}

// NewClientWithURL creates a client with a custom Rekor URL.
func NewClientWithURL(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
	}
}

// QueryResult holds the results of a Rekor query.
type QueryResult struct {
	Attestations []Attestation
	Err          error
}

// Query searches Rekor for entries matching the given SHA-256 hash.
func (c *Client) Query(hash string) QueryResult {
	rekorAPI, err := rekorclient.GetRekorClient(c.baseURL)
	if err != nil {
		return QueryResult{Err: fmt.Errorf("creating rekor client: %w", err)}
	}

	// Search the index by hash.
	searchParams := index.NewSearchIndexParams()
	searchParams.Query = &models.SearchIndex{
		Hash: fmt.Sprintf("sha256:%s", hash),
	}

	searchResp, err := rekorAPI.Index.SearchIndex(searchParams)
	if err != nil {
		return QueryResult{Err: fmt.Errorf("rekor index search: %w", err)}
	}

	if len(searchResp.Payload) == 0 {
		return QueryResult{}
	}

	// Fetch each entry and extract attestation data.
	var attestations []Attestation
	for _, uuid := range searchResp.Payload {
		att, err := fetchEntry(rekorAPI.Entries, uuid)
		if err != nil {
			continue // skip entries we can't parse
		}
		if att != nil {
			attestations = append(attestations, *att)
		}
	}

	return QueryResult{Attestations: attestations}
}

// Submit uploads a hashedrekord entry to Rekor.
// signatureB64 is the base64-encoded signature, certPEM is the signing certificate,
// and hash is the SHA-256 hex digest of the signed content.
func (c *Client) Submit(hash string, signatureB64 string, certPEM []byte) (string, error) {
	rekorAPI, err := rekorclient.GetRekorClient(c.baseURL)
	if err != nil {
		return "", fmt.Errorf("creating rekor client: %w", err)
	}

	// Build a hashedrekord entry.
	hashAlg := "sha256"
	re := &models.Hashedrekord{
		APIVersion: swag.String("0.0.1"),
		Spec: &models.HashedrekordV001Schema{
			Data: &models.HashedrekordV001SchemaData{
				Hash: &models.HashedrekordV001SchemaDataHash{
					Algorithm: &hashAlg,
					Value:     &hash,
				},
			},
			Signature: &models.HashedrekordV001SchemaSignature{
				Content: strfmt.Base64(mustDecodeB64(signatureB64)),
				PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
					Content: strfmt.Base64(certPEM),
				},
			},
		},
	}

	params := entries.NewCreateLogEntryParams()
	params.SetProposedEntry(re)

	resp, err := rekorAPI.Entries.CreateLogEntry(params)
	if err != nil {
		return "", fmt.Errorf("creating rekor entry: %w", err)
	}

	// Extract the entry UUID from the response.
	for uuid := range resp.Payload {
		return uuid, nil
	}

	return "", fmt.Errorf("empty rekor response")
}

func mustDecodeB64(s string) []byte {
	b, _ := base64.StdEncoding.DecodeString(s)
	return b
}

// entriesAPI is the interface for the Rekor entries client.
type entriesAPI interface {
	GetLogEntryByUUID(params *entries.GetLogEntryByUUIDParams, opts ...entries.ClientOption) (*entries.GetLogEntryByUUIDOK, error)
}

// fetchEntry retrieves and parses a single Rekor entry by UUID.
func fetchEntry(client entriesAPI, uuid string) (*Attestation, error) {
	params := entries.NewGetLogEntryByUUIDParams()
	params.EntryUUID = uuid

	resp, err := client.GetLogEntryByUUID(params)
	if err != nil {
		return nil, fmt.Errorf("fetching entry %s: %w", uuid, err)
	}

	for _, entry := range resp.Payload {
		return parseLogEntry(&entry)
	}

	return nil, fmt.Errorf("empty response for entry %s", uuid)
}

// parseLogEntry extracts attestation data from a Rekor log entry.
func parseLogEntry(entry *models.LogEntryAnon) (*Attestation, error) {
	if entry == nil || entry.Body == nil {
		return nil, fmt.Errorf("nil entry or body")
	}

	// The body is base64-encoded JSON.
	bodyStr, ok := entry.Body.(string)
	if !ok {
		return nil, fmt.Errorf("unexpected body type: %T", entry.Body)
	}

	bodyBytes, err := base64.StdEncoding.DecodeString(bodyStr)
	if err != nil {
		return nil, fmt.Errorf("decoding body: %w", err)
	}

	var entryBody struct {
		APIVersion string          `json:"apiVersion"`
		Kind       string          `json:"kind"`
		Spec       json.RawMessage `json:"spec"`
	}
	if err := json.Unmarshal(bodyBytes, &entryBody); err != nil {
		return nil, fmt.Errorf("parsing entry body: %w", err)
	}

	var timestamp time.Time
	if entry.IntegratedTime != nil {
		timestamp = time.Unix(*entry.IntegratedTime, 0)
	}

	switch entryBody.Kind {
	case "hashedrekord":
		return parseHashedRekordEntry(entryBody.Spec, timestamp)
	case "dsse":
		return parseDSSEEntry(entryBody.Spec, timestamp)
	default:
		return nil, fmt.Errorf("unsupported entry kind: %s", entryBody.Kind)
	}
}

// parseHashedRekordEntry extracts identity from a hashedrekord entry.
func parseHashedRekordEntry(spec json.RawMessage, timestamp time.Time) (*Attestation, error) {
	var hrekordSpec struct {
		Data struct {
			Hash struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"hash"`
		} `json:"data"`
		Signature struct {
			Content   string `json:"content"`
			PublicKey struct {
				Content string `json:"content"`
			} `json:"publicKey"`
		} `json:"signature"`
	}
	if err := json.Unmarshal(spec, &hrekordSpec); err != nil {
		return nil, fmt.Errorf("parsing hashedrekord spec: %w", err)
	}

	identity := extractIdentityFromB64PEM(hrekordSpec.Signature.PublicKey.Content)

	return &Attestation{
		Type:      AttestationType,
		Identity:  identity,
		Subject:   Subject{SHA256: hrekordSpec.Data.Hash.Value},
		Verdict:   "approve", // hashedrekord entries are implicit approvals
		Timestamp: timestamp,
	}, nil
}

// parseDSSEEntry extracts identity from a DSSE entry.
func parseDSSEEntry(spec json.RawMessage, timestamp time.Time) (*Attestation, error) {
	var dsseSpec struct {
		Signatures []struct {
			Verifier string `json:"verifier"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(spec, &dsseSpec); err != nil {
		return nil, fmt.Errorf("parsing dsse spec: %w", err)
	}

	identity := "unknown"
	if len(dsseSpec.Signatures) > 0 && dsseSpec.Signatures[0].Verifier != "" {
		if id, err := extractIdentityFromPEM(dsseSpec.Signatures[0].Verifier); err == nil {
			identity = id
		}
	}

	return &Attestation{
		Type:      AttestationType,
		Identity:  identity,
		Timestamp: timestamp,
		Verdict:   "approve",
	}, nil
}

// extractIdentityFromB64PEM decodes base64, then extracts identity from PEM cert.
func extractIdentityFromB64PEM(b64 string) string {
	pemData, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		// Try as raw PEM.
		if id, err := extractIdentityFromPEM(b64); err == nil {
			return id
		}
		return "unknown"
	}
	if id, err := extractIdentityFromPEM(string(pemData)); err == nil {
		return id
	}
	return "unknown"
}

// extractIdentityFromPEM extracts the email or URI SAN from a PEM-encoded certificate.
func extractIdentityFromPEM(pemStr string) (string, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return "", fmt.Errorf("no PEM block found")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parsing certificate: %w", err)
	}

	if len(cert.EmailAddresses) > 0 {
		return cert.EmailAddresses[0], nil
	}
	if len(cert.URIs) > 0 {
		return cert.URIs[0].String(), nil
	}
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName, nil
	}

	return "", fmt.Errorf("no identity found in certificate")
}

