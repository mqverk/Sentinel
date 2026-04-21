package config

import (
	"errors"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server struct {
		HTTPAddress string `yaml:"http_address"`
		SSHAddress  string `yaml:"ssh_address"`
	} `yaml:"server"`

	Storage struct {
		Driver string `yaml:"driver"`
		DSN    string `yaml:"dsn"`
	} `yaml:"storage"`

	Security struct {
		AllowedCIDRs []string `yaml:"allowed_cidrs"`
		RateLimit    int      `yaml:"rate_limit"`
		RateWindow   string   `yaml:"rate_window"`
	} `yaml:"security"`

	Auth struct {
		JWTSecret         string `yaml:"jwt_secret"`
		TokenTTL          string `yaml:"token_ttl"`
		PasswordMinLength int    `yaml:"password_min_length"`
	} `yaml:"auth"`

	Bootstrap struct {
		AdminUsername    string `yaml:"admin_username"`
		AdminPassword    string `yaml:"admin_password"`
		AdminDisplayName string `yaml:"admin_display_name"`
	} `yaml:"bootstrap"`

	Plugins struct {
		WebhookAuditURL string `yaml:"webhook_audit_url"`
	} `yaml:"plugins"`

	Observability struct {
		LogLevel string `yaml:"log_level"`
	} `yaml:"observability"`

	API struct {
		CORSAllowedOrigins []string `yaml:"cors_allowed_origins"`
	} `yaml:"api"`
}

func Default() Config {
	var cfg Config
	cfg.Server.HTTPAddress = ":8080"
	cfg.Server.SSHAddress = ":2222"
	cfg.Storage.Driver = "sqlite"
	cfg.Storage.DSN = "sentinel.db"
	cfg.Security.AllowedCIDRs = []string{}
	cfg.Security.RateLimit = 120
	cfg.Security.RateWindow = "1m"
	cfg.Auth.TokenTTL = "12h"
	cfg.Auth.PasswordMinLength = 14
	cfg.Bootstrap.AdminUsername = "admin"
	cfg.Bootstrap.AdminDisplayName = "Sentinel Administrator"
	cfg.Observability.LogLevel = "info"
	cfg.API.CORSAllowedOrigins = []string{"http://localhost:5173"}
	return cfg
}

func Load(path string) (Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}

	cfg.applyDefaults()

	if cfg.Auth.JWTSecret == "" {
		return cfg, errors.New("auth.jwt_secret is required")
	}

	if cfg.Bootstrap.AdminPassword == "" {
		return cfg, errors.New("bootstrap.admin_password is required")
	}

	return cfg, nil
}

func (c *Config) applyDefaults() {
	defaults := Default()

	if c.Server.HTTPAddress == "" {
		c.Server.HTTPAddress = defaults.Server.HTTPAddress
	}

	if c.Server.SSHAddress == "" {
		c.Server.SSHAddress = defaults.Server.SSHAddress
	}

	if c.Storage.Driver == "" {
		c.Storage.Driver = defaults.Storage.Driver
	}

	if c.Storage.DSN == "" {
		c.Storage.DSN = defaults.Storage.DSN
	}

	if c.Security.RateLimit <= 0 {
		c.Security.RateLimit = defaults.Security.RateLimit
	}

	if c.Security.RateWindow == "" {
		c.Security.RateWindow = defaults.Security.RateWindow
	}

	if c.Auth.TokenTTL == "" {
		c.Auth.TokenTTL = defaults.Auth.TokenTTL
	}

	if c.Auth.PasswordMinLength <= 0 {
		c.Auth.PasswordMinLength = defaults.Auth.PasswordMinLength
	}

	if c.Bootstrap.AdminUsername == "" {
		c.Bootstrap.AdminUsername = defaults.Bootstrap.AdminUsername
	}

	if c.Bootstrap.AdminDisplayName == "" {
		c.Bootstrap.AdminDisplayName = defaults.Bootstrap.AdminDisplayName
	}

	if c.Observability.LogLevel == "" {
		c.Observability.LogLevel = defaults.Observability.LogLevel
	}

	if len(c.API.CORSAllowedOrigins) == 0 {
		c.API.CORSAllowedOrigins = defaults.API.CORSAllowedOrigins
	}
}

func (c Config) TokenTTLDuration() time.Duration {
	ttl, err := time.ParseDuration(c.Auth.TokenTTL)
	if err != nil {
		return 12 * time.Hour
	}

	return ttl
}

func (c Config) RateWindowDuration() time.Duration {
	window, err := time.ParseDuration(c.Security.RateWindow)
	if err != nil {
		return time.Minute
	}

	return window
}
