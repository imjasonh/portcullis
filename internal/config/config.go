package config

import (
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
)

// Policy controls how portcullis responds to different attestation states.
type Policy struct {
	OnNegative string        // "block" (default) or "warn"
	OnPositive string        // "pass" (default) or "review"
	OnUnknown  string        // "review" (default), "warn", or "block"
	CacheTTL   time.Duration // default 24h
}

// DefaultPolicy returns the default policy configuration.
func DefaultPolicy() Policy {
	return Policy{
		OnNegative: "block",
		OnPositive: "pass",
		OnUnknown:  "review",
		CacheTTL:   24 * time.Hour,
	}
}

// ConfigDir returns the configuration directory.
func ConfigDir() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "portcullis")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "portcullis")
}

// configFile is the TOML structure for the config file.
type configFile struct {
	Policy policySection `toml:"policy"`
}

type policySection struct {
	OnNegative string `toml:"on_negative"`
	OnPositive string `toml:"on_positive"`
	OnUnknown  string `toml:"on_unknown"`
	CacheTTL   string `toml:"cache_ttl"`
}

// LoadPolicy loads policy from the config file, falling back to defaults.
func LoadPolicy(configDir string) Policy {
	p := DefaultPolicy()
	if configDir == "" {
		configDir = ConfigDir()
	}

	var cfg configFile
	if _, err := toml.DecodeFile(filepath.Join(configDir, "config.toml"), &cfg); err != nil {
		return p
	}

	if cfg.Policy.OnNegative != "" {
		p.OnNegative = cfg.Policy.OnNegative
	}
	if cfg.Policy.OnPositive != "" {
		p.OnPositive = cfg.Policy.OnPositive
	}
	if cfg.Policy.OnUnknown != "" {
		p.OnUnknown = cfg.Policy.OnUnknown
	}
	if cfg.Policy.CacheTTL != "" {
		if d, err := time.ParseDuration(cfg.Policy.CacheTTL); err == nil {
			p.CacheTTL = d
		}
	}

	return p
}
