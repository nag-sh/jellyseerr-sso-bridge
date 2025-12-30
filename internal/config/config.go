package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds all configuration for the bridge
type Config struct {
	OIDC      OIDCConfig
	Jellyfin  JellyfinConfig
	Jellyseerr JellyseerrConfig
	Session   SessionConfig
	Bridge    BridgeConfig
}

// OIDCConfig holds OIDC provider configuration
type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

// JellyfinConfig holds Jellyfin API configuration
type JellyfinConfig struct {
	URL    string
	APIKey string
}

// JellyseerrConfig holds Jellyseerr API configuration
type JellyseerrConfig struct {
	URL    string
	APIKey string
}

// SessionConfig holds session management configuration
type SessionConfig struct {
	Secret string
	TTL    time.Duration
}

// BridgeConfig holds bridge-specific configuration
type BridgeConfig struct {
	Port         int
	ExternalURL  string
	CookieDomain string
}

// Load loads configuration from environment variables
func Load() (*Config, error) {
	cfg := &Config{}

	// OIDC Configuration
	cfg.OIDC.Issuer = getEnv("OIDC_ISSUER", "")
	cfg.OIDC.ClientID = getEnv("OIDC_CLIENT_ID", "")
	cfg.OIDC.ClientSecret = getEnv("OIDC_CLIENT_SECRET", "")
	cfg.OIDC.Scopes = []string{"openid", "email", "profile"}

	// Jellyfin Configuration
	cfg.Jellyfin.URL = getEnv("JELLYFIN_URL", "")
	cfg.Jellyfin.APIKey = getEnv("JELLYFIN_API_KEY", "")

	// Jellyseerr Configuration
	cfg.Jellyseerr.URL = getEnv("JELLYSEERR_URL", "")
	cfg.Jellyseerr.APIKey = getEnv("JELLYSEERR_API_KEY", "")

	// Session Configuration
	cfg.Session.Secret = getEnv("SESSION_SECRET", "")
	ttl, err := time.ParseDuration(getEnv("SESSION_TTL", "24h"))
	if err != nil {
		ttl = 24 * time.Hour
	}
	cfg.Session.TTL = ttl

	// Bridge Configuration
	port, err := strconv.Atoi(getEnv("BRIDGE_PORT", "8080"))
	if err != nil {
		port = 8080
	}
	cfg.Bridge.Port = port
	cfg.Bridge.ExternalURL = getEnv("BRIDGE_EXTERNAL_URL", "")
	cfg.Bridge.CookieDomain = getEnv("BRIDGE_COOKIE_DOMAIN", "")

	// Set redirect URL based on external URL
	cfg.OIDC.RedirectURL = cfg.Bridge.ExternalURL + "/callback"

	// Validate required fields
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) validate() error {
	if c.OIDC.Issuer == "" {
		return fmt.Errorf("OIDC_ISSUER is required")
	}
	if c.OIDC.ClientID == "" {
		return fmt.Errorf("OIDC_CLIENT_ID is required")
	}
	if c.OIDC.ClientSecret == "" {
		return fmt.Errorf("OIDC_CLIENT_SECRET is required")
	}
	if c.Jellyfin.URL == "" {
		return fmt.Errorf("JELLYFIN_URL is required")
	}
	if c.Jellyfin.APIKey == "" {
		return fmt.Errorf("JELLYFIN_API_KEY is required")
	}
	if c.Jellyseerr.URL == "" {
		return fmt.Errorf("JELLYSEERR_URL is required")
	}
	if c.Bridge.ExternalURL == "" {
		return fmt.Errorf("BRIDGE_EXTERNAL_URL is required")
	}
	if c.Session.Secret == "" {
		return fmt.Errorf("SESSION_SECRET is required")
	}
	return nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

