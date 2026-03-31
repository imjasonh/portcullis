package cache

import (
	"database/sql"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Decision represents a cached verdict for a script hash.
type Decision struct {
	ScriptHash string
	Verdict    string // "approve" or "deny"
	Source     string // "local" or "attested"
	Identity   string
	Reason     string
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// Cache provides local caching of script decisions in SQLite.
type Cache struct {
	db  *sql.DB
	ttl time.Duration
}

// Open opens or creates the cache database.
func Open(configDir string, ttl time.Duration) (*Cache, error) {
	if configDir == "" {
		configDir = defaultConfigDir()
	}
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return nil, err
	}

	dbPath := filepath.Join(configDir, "cache.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	// Create schema (this also creates the file).
	if _, err := db.Exec(createTableSQL); err != nil {
		db.Close()
		return nil, err
	}

	// Set file permissions after file is created.
	if err := os.Chmod(dbPath, 0600); err != nil {
		db.Close()
		return nil, err
	}

	return &Cache{db: db, ttl: ttl}, nil
}

// Lookup checks the cache for a valid (non-expired) decision.
func (c *Cache) Lookup(scriptHash string) (*Decision, error) {
	now := time.Now().Unix()
	row := c.db.QueryRow(
		`SELECT script_hash, verdict, source, identity, reason, created_at, expires_at
		 FROM decisions WHERE script_hash = ? AND expires_at > ?`,
		scriptHash, now,
	)

	var d Decision
	var createdAt, expiresAt int64
	var identity, reason sql.NullString
	err := row.Scan(&d.ScriptHash, &d.Verdict, &d.Source, &identity, &reason, &createdAt, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	d.Identity = identity.String
	d.Reason = reason.String
	d.CreatedAt = time.Unix(createdAt, 0)
	d.ExpiresAt = time.Unix(expiresAt, 0)
	return &d, nil
}

// LookupExpired returns a decision even if expired (for fallback when Rekor is unreachable).
func (c *Cache) LookupExpired(scriptHash string) (*Decision, error) {
	row := c.db.QueryRow(
		`SELECT script_hash, verdict, source, identity, reason, created_at, expires_at
		 FROM decisions WHERE script_hash = ?`,
		scriptHash,
	)

	var d Decision
	var createdAt, expiresAt int64
	var identity, reason sql.NullString
	err := row.Scan(&d.ScriptHash, &d.Verdict, &d.Source, &identity, &reason, &createdAt, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	d.Identity = identity.String
	d.Reason = reason.String
	d.CreatedAt = time.Unix(createdAt, 0)
	d.ExpiresAt = time.Unix(expiresAt, 0)
	return &d, nil
}

// Store saves a decision to the cache.
func (c *Cache) Store(d Decision) error {
	now := time.Now()
	if d.CreatedAt.IsZero() {
		d.CreatedAt = now
	}
	if d.ExpiresAt.IsZero() {
		d.ExpiresAt = now.Add(c.ttl)
	}

	_, err := c.db.Exec(
		`INSERT OR REPLACE INTO decisions (script_hash, verdict, source, identity, reason, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		d.ScriptHash, d.Verdict, d.Source,
		nullString(d.Identity), nullString(d.Reason),
		d.CreatedAt.Unix(), d.ExpiresAt.Unix(),
	)
	return err
}

// Close closes the database connection.
func (c *Cache) Close() error {
	return c.db.Close()
}

func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

func defaultConfigDir() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "portcullis")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "portcullis")
}
