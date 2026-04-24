package config

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Config holds all application configuration.
type Config struct {
	Port             int    `mapstructure:"PORT"`
	Env              string `mapstructure:"ENV"`
	DatabaseURL      string `mapstructure:"DATABASE_URL"`
	DBMaxConns       int32  `mapstructure:"DB_MAX_CONNS"`
	DBMinConns       int32  `mapstructure:"DB_MIN_CONNS"`
	MasterKeyB64     string `mapstructure:"MASTER_KEY"`
	MasterKey        []byte // Decoded from MasterKeyB64
	DefaultRateLimit int    `mapstructure:"DEFAULT_RATE_LIMIT"`
	LogLevel         string `mapstructure:"LOG_LEVEL"`

	// JWT
	JWTSecretB64 string `mapstructure:"JWT_SECRET"`
	JWTSecret    []byte // Decoded from JWTSecretB64

	// CORS
	CORSOrigins string `mapstructure:"CORS_ORIGINS"` // Comma-separated list of allowed origins

	// Trusted Proxies — comma-separated CIDRs (e.g. "127.0.0.1/32,10.0.0.0/8")
	// Only requests from these IPs will have X-Forwarded-For honoured.
	TrustedProxies string `mapstructure:"TRUSTED_PROXIES"`

	// SMTP (optional in development — verification codes logged to console)
	SMTPHost string `mapstructure:"SMTP_HOST"`
	SMTPPort int    `mapstructure:"SMTP_PORT"`
	SMTPUser string `mapstructure:"SMTP_USER"`
	SMTPPass string `mapstructure:"SMTP_PASS"`
	SMTPFrom string `mapstructure:"SMTP_FROM"`
}

// Load reads configuration from environment variables and .env file.
func Load() (*Config, error) {
	viper.SetConfigFile(".env")
	viper.SetConfigType("env")
	viper.AutomaticEnv()

	// Explicitly bind environment variables so they work with Unmarshal().
	// viper.AutomaticEnv() only works with viper.Get() — not Unmarshal().
	for _, key := range []string{
		"PORT", "ENV", "DATABASE_URL",
		"DB_USER", "DB_PASSWORD", "DB_NAME",
		"DB_MAX_CONNS", "DB_MIN_CONNS",
		"MASTER_KEY", "JWT_SECRET",
		"DEFAULT_RATE_LIMIT", "LOG_LEVEL",
		"CORS_ORIGINS", "TRUSTED_PROXIES",
		"SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS", "SMTP_FROM",
	} {
		_ = viper.BindEnv(key)
	}

	// Set defaults
	viper.SetDefault("PORT", 8080)
	viper.SetDefault("ENV", "development")
	viper.SetDefault("DB_MAX_CONNS", 25)
	viper.SetDefault("DB_MIN_CONNS", 5)
	viper.SetDefault("DEFAULT_RATE_LIMIT", 60)
	viper.SetDefault("LOG_LEVEL", "info")
	viper.SetDefault("CORS_ORIGINS", "http://localhost:3000")
	viper.SetDefault("SMTP_PORT", 587)
	viper.SetDefault("SMTP_FROM", "noreply@aegis.dev")

	// Read .env file (ignore error if not found — env vars are primary)
	_ = viper.ReadInConfig()

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (c *Config) validate() error {
	if c.DatabaseURL == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}

	if c.MasterKeyB64 == "" {
		return fmt.Errorf("MASTER_KEY is required")
	}

	decoded, err := base64.StdEncoding.DecodeString(c.MasterKeyB64)
	if err != nil {
		return fmt.Errorf("MASTER_KEY must be valid base64: %w", err)
	}

	if len(decoded) != 32 {
		return fmt.Errorf("MASTER_KEY must decode to exactly 32 bytes, got %d", len(decoded))
	}

	c.MasterKey = decoded
	c.MasterKeyB64 = "" // Clear from memory (security hardening)

	// JWT secret
	if c.JWTSecretB64 == "" {
		return fmt.Errorf("JWT_SECRET is required")
	}

	jwtDecoded, err := base64.StdEncoding.DecodeString(c.JWTSecretB64)
	if err != nil {
		return fmt.Errorf("JWT_SECRET must be valid base64: %w", err)
	}

	if len(jwtDecoded) < 32 {
		return fmt.Errorf("JWT_SECRET must decode to at least 32 bytes, got %d", len(jwtDecoded))
	}

	c.JWTSecret = jwtDecoded
	c.JWTSecretB64 = "" // Clear from memory

	// SMTP is optional in development
	if c.IsProduction() && c.SMTPHost == "" {
		return fmt.Errorf("SMTP_HOST is required in production")
	}

	validEnvs := map[string]bool{"development": true, "staging": true, "production": true}
	if !validEnvs[strings.ToLower(c.Env)] {
		return fmt.Errorf("ENV must be one of: development, staging, production")
	}

	return nil
}

// IsDevelopment returns true if running in development mode.
func (c *Config) IsDevelopment() bool {
	return strings.ToLower(c.Env) == "development"
}

// IsProduction returns true if running in production mode.
func (c *Config) IsProduction() bool {
	return strings.ToLower(c.Env) == "production"
}
