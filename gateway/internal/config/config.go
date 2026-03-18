// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Package config handles YAML configuration for the Phantex gateway.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level gateway configuration.
type Config struct {
	// gRPC server settings
	GRPC GRPCConfig `yaml:"grpc"`

	// Authentication
	Auth AuthConfig `yaml:"auth"`

	// Kafka publisher settings (Phase 1: unused, log publisher instead)
	Kafka KafkaConfig `yaml:"kafka"`

	// Vault (H2 — Secret Management)
	Vault VaultConfig `yaml:"vault"`

	// Backend API (for command relay, internal endpoints)
	Backend BackendConfig `yaml:"backend"`

	// Logging
	LogLevel  string `yaml:"log_level"`
	LogFormat string `yaml:"log_format"`
}

// GRPCConfig controls the gRPC server.
type GRPCConfig struct {
	// Listen address (e.g., ":50051")
	ListenAddr string `yaml:"listen_addr"`

	// TLS settings
	TLSEnabled  bool   `yaml:"tls_enabled"`
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`
	TLSCAFile   string `yaml:"tls_ca_file"` // for mTLS client cert validation

	// Rate limiting
	MaxEventsPerSec int64 `yaml:"max_events_per_sec"` // per sensor, 0 = unlimited

	// Keepalive
	KeepaliveInterval time.Duration `yaml:"keepalive_interval"`
	KeepaliveTimeout  time.Duration `yaml:"keepalive_timeout"`
}

// AuthConfig controls sensor authentication.
type AuthConfig struct {
	// Phase 1: static tokens mapped to tenant IDs.
	// Format: {"token_hex_string": "tenant-id", ...}
	Tokens map[string]string `yaml:"tokens"`
}

// KafkaConfig controls the Kafka producer.
type KafkaConfig struct {
	// Enable Kafka publishing (false = use log publisher for dev)
	Enabled bool `yaml:"enabled"`

	// Broker addresses
	Brokers []string `yaml:"brokers"`

	// Topic prefix (events go to {prefix}.{tenant_id})
	TopicPrefix string `yaml:"topic_prefix"`

	// Producer settings
	BatchSize    int           `yaml:"batch_size"`
	BatchTimeout time.Duration `yaml:"batch_timeout"`

	// TLS / SASL_SSL settings
	TLSEnabled  bool   `yaml:"tls_enabled"`
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`
	TLSCAFile   string `yaml:"tls_ca_file"`
}

// VaultConfig controls HashiCorp Vault integration.
type VaultConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Addr       string `yaml:"addr"`
	Token      string `yaml:"token"`        // Direct token (dev only)
	RoleID     string `yaml:"role_id"`      // AppRole auth
	SecretID   string `yaml:"secret_id"`    // AppRole auth
	JWTKeyName string `yaml:"jwt_key_name"` // Transit key for JWT verification
}

// BackendConfig controls connectivity to the Phantex backend API.
// Used for command relay (SOC response actions → sensor).
type BackendConfig struct {
	// Base URL of the backend API (e.g., "http://phantex-backend:8000")
	URL string `yaml:"url"`

	// Internal auth token for gateway-to-backend requests
	InternalToken string `yaml:"internal_token"`
}

// DefaultConfig returns a config with sensible defaults for development.
func DefaultConfig() *Config {
	return &Config{
		LogLevel:  "info",
		LogFormat: "json",
		GRPC: GRPCConfig{
			ListenAddr:        ":50051",
			TLSEnabled:        false,
			MaxEventsPerSec:   100000, // 100K events/sec per sensor
			KeepaliveInterval: 30 * time.Second,
			KeepaliveTimeout:  10 * time.Second,
		},
		Auth: AuthConfig{
			Tokens: map[string]string{
				// Default dev token — MUST be replaced in production
				"phantex-dev-token-do-not-use-in-production": "default-tenant",
			},
		},
		Kafka: KafkaConfig{
			Enabled:      false, // default: log publisher for dev
			Brokers:      []string{"localhost:9092"},
			TopicPrefix:  "phantex.events",
			BatchSize:    100,
			BatchTimeout: time.Second,
		},
		Vault: VaultConfig{
			Enabled:    false,
			Addr:       "http://127.0.0.1:8200",
			JWTKeyName: "jwt-signing",
		},
		Backend: BackendConfig{
			URL:           "http://phantex-backend:8000",
			InternalToken: "phantex-dev-internal-token",
		},
	}
}

// Load reads a YAML config file and merges it with defaults.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	if path == "" {
		for _, p := range []string{"/etc/phantex/gateway.yaml", "gateway.yaml"} {
			if _, err := os.Stat(p); err == nil {
				path = p
				break
			}
		}
	}

	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	// Clear default dev tokens so YAML tokens replace (not merge with) them.
	cfg.Auth.Tokens = nil

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	applyEnvOverrides(cfg)
	return cfg, nil
}

// applyEnvOverrides lets Docker/K8s env vars override YAML config.
// This is required because docker-compose sets PHANTEX_BACKEND_URL and
// PHANTEX_INTERNAL_TOKEN as container env vars.
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("PHANTEX_BACKEND_URL"); v != "" {
		cfg.Backend.URL = v
	}
	if v := os.Getenv("PHANTEX_INTERNAL_TOKEN"); v != "" {
		cfg.Backend.InternalToken = v
	}
	if v := os.Getenv("PHANTEX_LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
	if v := os.Getenv("PHANTEX_KAFKA_BOOTSTRAP"); v != "" {
		cfg.Kafka.Brokers = []string{v}
	}
	if v := os.Getenv("PHANTEX_LISTEN_ADDR"); v != "" {
		cfg.GRPC.ListenAddr = v
	}
}

// devToken is the baked-in default token — must never be used in production.
const devToken = "phantex-dev-token-do-not-use-in-production"

// Validate checks that required fields are set.
func (c *Config) Validate() error {
	if c.GRPC.ListenAddr == "" {
		return fmt.Errorf("grpc.listen_addr is required")
	}
	if len(c.Auth.Tokens) == 0 {
		return fmt.Errorf("auth.tokens must have at least one token")
	}
	for token, tenantID := range c.Auth.Tokens {
		if len(token) < 16 {
			return fmt.Errorf("auth token too short (min 16 chars, got %d)", len(token))
		}
		if tenantID == "" {
			return fmt.Errorf("auth token (len=%d) has empty tenant_id", len(token))
		}
		if token == devToken {
			return fmt.Errorf("auth.tokens still contains the default dev token — replace for production")
		}
	}
	if c.Kafka.Enabled {
		if len(c.Kafka.Brokers) == 0 {
			return fmt.Errorf("kafka.brokers required when kafka.enabled is true")
		}
		if c.Kafka.TopicPrefix == "" {
			return fmt.Errorf("kafka.topic_prefix required when kafka.enabled is true")
		}
	}
	// Production environment enforcement (set PHANTEX_ENVIRONMENT=production)
	if env := os.Getenv("PHANTEX_ENVIRONMENT"); env == "production" || env == "staging" {
		if !c.GRPC.TLSEnabled {
			return fmt.Errorf("grpc.tls_enabled must be true in production — provide TLS certificates")
		}
		if c.GRPC.TLSCertFile == "" || c.GRPC.TLSKeyFile == "" {
			return fmt.Errorf("grpc.tls_cert_file and grpc.tls_key_file are required when TLS is enabled")
		}
		if c.Backend.InternalToken == "phantex-dev-internal-token" {
			return fmt.Errorf("backend.internal_token still uses the dev default — set PHANTEX_INTERNAL_TOKEN")
		}
	}
	return nil
}
