package config

import (
	"os"
	"path/filepath"
	"strings"
	"time"
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

// LoadPolicy loads policy from the config file, falling back to defaults.
func LoadPolicy(configDir string) Policy {
	p := DefaultPolicy()
	if configDir == "" {
		configDir = ConfigDir()
	}
	data, err := os.ReadFile(filepath.Join(configDir, "config.toml"))
	if err != nil {
		return p
	}
	parsePolicy(string(data), &p)
	return p
}

func parsePolicy(data string, p *Policy) {
	inPolicy := false
	for _, line := range strings.Split(data, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "[policy]" {
			inPolicy = true
			continue
		}
		if strings.HasPrefix(trimmed, "[") {
			inPolicy = false
			continue
		}
		if !inPolicy {
			continue
		}
		parts := strings.SplitN(trimmed, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.Trim(strings.TrimSpace(parts[1]), "\"")
		switch key {
		case "on_negative":
			p.OnNegative = val
		case "on_positive":
			p.OnPositive = val
		case "on_unknown":
			p.OnUnknown = val
		case "cache_ttl":
			if d, err := time.ParseDuration(val); err == nil {
				p.CacheTTL = d
			}
		}
	}
}
