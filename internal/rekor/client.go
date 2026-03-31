package rekor

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// Client queries and submits attestations to Rekor.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new Rekor client.
func NewClient() *Client {
	return &Client{
		baseURL:    "https://rekor.sigstore.dev",
		httpClient: http.DefaultClient,
	}
}

// NewClientWithBase creates a client with a custom base URL (for testing).
func NewClientWithBase(baseURL string, httpClient *http.Client) *Client {
	return &Client{
		baseURL:    baseURL,
		httpClient: httpClient,
	}
}

// QueryResult holds the results of a Rekor query.
type QueryResult struct {
	Attestations []Attestation
	Err          error
}

// Query searches Rekor for attestations matching the given SHA-256 hash.
func (c *Client) Query(hash string) QueryResult {
	searchURL := fmt.Sprintf("%s/api/v1/index/retrieve", c.baseURL)

	// Search by hash.
	resp, err := c.httpClient.PostForm(searchURL, url.Values{
		"hash": {fmt.Sprintf("sha256:%s", hash)},
	})
	if err != nil {
		return QueryResult{Err: fmt.Errorf("rekor query failed: %w", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return QueryResult{Err: fmt.Errorf("rekor returned status %d", resp.StatusCode)}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return QueryResult{Err: fmt.Errorf("reading rekor response: %w", err)}
	}

	// Parse UUIDs from index response.
	var uuids []string
	if err := json.Unmarshal(body, &uuids); err != nil {
		return QueryResult{Err: fmt.Errorf("parsing rekor index: %w", err)}
	}

	// Fetch each entry.
	var attestations []Attestation
	for _, uuid := range uuids {
		att, err := c.fetchEntry(uuid)
		if err != nil {
			continue // skip entries we can't parse
		}
		if att != nil {
			attestations = append(attestations, *att)
		}
	}

	return QueryResult{Attestations: attestations}
}

// Submit publishes a signed attestation to Rekor.
// TODO: implement actual Sigstore signing and Rekor submission.
func (c *Client) Submit(att Attestation) error {
	// Placeholder: in a full implementation, this would:
	// 1. Sign the attestation with Sigstore keyless signing
	// 2. Create a Rekor entry with the signed attestation
	// 3. Return the log entry UUID
	return fmt.Errorf("rekor submission not yet implemented — requires Sigstore signing")
}

func (c *Client) fetchEntry(uuid string) (*Attestation, error) {
	entryURL := fmt.Sprintf("%s/api/v1/log/entries/%s", c.baseURL, uuid)
	resp, err := c.httpClient.Get(entryURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("entry %s: status %d", uuid, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse the Rekor entry. The actual format is more complex;
	// this is a simplified parser for portcullis attestation types.
	var att Attestation
	if err := json.Unmarshal(body, &att); err != nil {
		return nil, err
	}

	if att.Type != AttestationType {
		return nil, nil // not a portcullis attestation
	}

	return &att, nil
}
