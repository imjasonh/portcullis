package cache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Decision represents a cached verdict for a script hash.
type Decision struct {
	ScriptHash string    `json:"script_hash"`
	Verdict    string    `json:"verdict"`
	Source     string    `json:"source"`
	Identity   string    `json:"identity,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// Cache provides local caching of script decisions backed by a JSON file.
type Cache struct {
	path    string
	ttl     time.Duration
	entries map[string]Decision
	mu      sync.Mutex
}

// Open opens or creates the cache file.
func Open(configDir string, ttl time.Duration) (*Cache, error) {
	if configDir == "" {
		configDir = defaultConfigDir()
	}
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return nil, err
	}

	c := &Cache{
		path:    filepath.Join(configDir, "cache.json"),
		ttl:     ttl,
		entries: make(map[string]Decision),
	}

	if err := c.load(); err != nil {
		return nil, err
	}

	return c, nil
}

// Lookup checks the cache for a valid (non-expired) decision.
func (c *Cache) Lookup(scriptHash string) (*Decision, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	d, ok := c.entries[scriptHash]
	if !ok {
		return nil, nil
	}

	if time.Now().After(d.ExpiresAt) {
		return nil, nil
	}

	return &d, nil
}

// LookupExpired returns a decision even if expired (for fallback when Rekor is unreachable).
func (c *Cache) LookupExpired(scriptHash string) (*Decision, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	d, ok := c.entries[scriptHash]
	if !ok {
		return nil, nil
	}

	return &d, nil
}

// Store saves a decision to the cache.
func (c *Cache) Store(d Decision) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	if d.CreatedAt.IsZero() {
		d.CreatedAt = now
	}
	if d.ExpiresAt.IsZero() {
		d.ExpiresAt = now.Add(c.ttl)
	}

	c.entries[d.ScriptHash] = d
	return c.save()
}

// Close is a no-op for the JSON cache (kept for interface compatibility).
func (c *Cache) Close() error {
	return nil
}

func (c *Cache) load() error {
	data, err := os.ReadFile(c.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}

	var entries map[string]Decision
	if err := json.Unmarshal(data, &entries); err != nil {
		// Corrupted cache — start fresh.
		c.entries = make(map[string]Decision)
		return nil
	}

	c.entries = entries
	return nil
}

func (c *Cache) save() error {
	data, err := json.Marshal(c.entries)
	if err != nil {
		return err
	}
	return os.WriteFile(c.path, data, 0600)
}

func defaultConfigDir() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "portcullis")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "portcullis")
}
