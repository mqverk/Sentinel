package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	API      APIConfig      `yaml:"api"`
	SSH      SSHConfig      `yaml:"ssh"`
	Database DatabaseConfig `yaml:"database"`
	Auth     AuthConfig     `yaml:"auth"`
	Security SecurityConfig `yaml:"security"`
	Session  SessionConfig  `yaml:"session"`
	Plugins  PluginsConfig  `yaml:"plugins"`
}

type APIConfig struct {
	ListenAddr   string        `yaml:"listenAddr"`
	ReadTimeout  time.Duration `yaml:"readTimeout"`
	WriteTimeout time.Duration `yaml:"writeTimeout"`
	IdleTimeout  time.Duration `yaml:"idleTimeout"`
	CORSOrigins  []string      `yaml:"corsOrigins"`
}

type SSHConfig struct {
	ListenAddr   string        `yaml:"listenAddr"`
	HostKeyPath  string        `yaml:"hostKeyPath"`
	Banner       string        `yaml:"banner"`
	MaxAuthTries int           `yaml:"maxAuthTries"`
	IdleTimeout  time.Duration `yaml:"idleTimeout"`
}

type DatabaseConfig struct {
	Driver          string        `yaml:"driver"`
	DSN             string        `yaml:"dsn"`
	MaxOpenConns    int           `yaml:"maxOpenConns"`
	MaxIdleConns    int           `yaml:"maxIdleConns"`
	ConnMaxLifetime time.Duration `yaml:"connMaxLifetime"`
}

type AuthConfig struct {
	JWTSecret         string        `yaml:"jwtSecret"`
	TokenTTL          time.Duration `yaml:"tokenTTL"`
	PasswordMinLength int           `yaml:"passwordMinLength"`
}

type SecurityConfig struct {
	RateLimit           RateLimitConfig `yaml:"rateLimit"`
	AllowedCIDRs        []string        `yaml:"allowedCIDRs"`
	MaxRequestBodyBytes int64           `yaml:"maxRequestBodyBytes"`
}

type RateLimitConfig struct {
	RequestsPerSecond float64 `yaml:"requestsPerSecond"`
	Burst             int     `yaml:"burst"`
}

type SessionConfig struct {
	RecordingDir        string `yaml:"recordingDir"`
	ReplayRetentionDays int    `yaml:"replayRetentionDays"`
}

type PluginsConfig struct {
	Enabled    []string `yaml:"enabled"`
	WebhookURL string   `yaml:"webhookURL"`
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	cfg := defaults()
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func defaults() Config {
	return Config{
		API: APIConfig{
			ListenAddr:   ":8080",
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 20 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
		SSH: SSHConfig{
			ListenAddr:   ":2222",
			HostKeyPath:  "./configs/host_key",
			Banner:       "Sentinel secure bastion",
			MaxAuthTries: 3,
			IdleTimeout:  30 * time.Minute,
		},
		Database: DatabaseConfig{
			Driver:          "sqlite",
			DSN:             "./sentinel.db",
			MaxOpenConns:    15,
			MaxIdleConns:    5,
			ConnMaxLifetime: 30 * time.Minute,
		},
		Auth: AuthConfig{
			JWTSecret:         "change-me-now",
			TokenTTL:          8 * time.Hour,
			PasswordMinLength: 12,
		},
		Security: SecurityConfig{
			RateLimit:           RateLimitConfig{RequestsPerSecond: 25, Burst: 50},
			MaxRequestBodyBytes: 1024 * 1024,
		},
		Session: SessionConfig{
			RecordingDir:        "./recordings",
			ReplayRetentionDays: 30,
		},
	}
}

func (c Config) validate() error {
	if c.API.ListenAddr == "" {
		return errors.New("api.listenAddr is required")
	}
	if c.SSH.ListenAddr == "" {
		return errors.New("ssh.listenAddr is required")
	}
	if c.SSH.HostKeyPath == "" {
		return errors.New("ssh.hostKeyPath is required")
	}
	if c.Database.Driver == "" {
		return errors.New("database.driver is required")
	}
	if c.Database.DSN == "" {
		return errors.New("database.dsn is required")
	}
	driver := strings.ToLower(c.Database.Driver)
	if driver != "sqlite" && driver != "postgres" {
		return errors.New("database.driver must be sqlite or postgres")
	}
	if len(c.Auth.JWTSecret) < 16 {
		return errors.New("auth.jwtSecret must be at least 16 characters")
	}
	if c.Auth.PasswordMinLength < 10 {
		return errors.New("auth.passwordMinLength must be >= 10")
	}
	if c.Security.RateLimit.RequestsPerSecond <= 0 {
		return errors.New("security.rateLimit.requestsPerSecond must be > 0")
	}
	if c.Security.RateLimit.Burst <= 0 {
		return errors.New("security.rateLimit.burst must be > 0")
	}
	if c.Security.MaxRequestBodyBytes <= 0 {
		return errors.New("security.maxRequestBodyBytes must be > 0")
	}
	if c.Session.RecordingDir == "" {
		return errors.New("session.recordingDir is required")
	}

	return nil
}
