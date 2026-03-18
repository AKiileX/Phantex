// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Package config handles YAML configuration for the Phantex sensor.
//
// Config file location (in order of precedence):
//  1. --config flag
//  2. /etc/phantex/sensor.yaml
//  3. ./sensor.yaml (development)
//
// Secrets (gRPC auth token) come from environment variables, not the config file.
package config

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level sensor configuration.
type Config struct {
	// Sensor identity
	SensorID string `yaml:"sensor_id"` // auto-generated if empty
	TenantID string `yaml:"tenant_id"` // required for multi-tenant

	// Config file integrity (populated by Load, not from YAML)
	ConfigHash string `yaml:"-"` // SHA-256 hex digest of the raw config file

	// Logging
	LogLevel  string `yaml:"log_level"`  // debug, info, warn, error
	LogFormat string `yaml:"log_format"` // json, console

	// eBPF settings
	EBPF EBPFConfig `yaml:"ebpf"`

	// Transport (gRPC to gateway)
	Transport TransportConfig `yaml:"transport"`

	// Health check
	Health HealthConfig `yaml:"health"`

	// Performance tuning
	Performance PerformanceConfig `yaml:"performance"`

	// Agent discovery
	Discovery DiscoveryConfig `yaml:"discovery"`

	// SDK socket (receives events from Python SDK)
	SDKSocket SDKSocketConfig `yaml:"sdk_socket"`
}

// EBPFConfig controls eBPF probe behavior.
type EBPFConfig struct {
	// PID filter mode: "all" (track everything) or "filtered" (only tracked PIDs)
	FilterMode string `yaml:"filter_mode"` // "all" or "filtered"

	// Ring buffer channel size (Go side)
	RingBufChanSize int `yaml:"ringbuf_chan_size"`
}

// TransportConfig controls how events are sent to the backend gateway.
type TransportConfig struct {
	// gRPC gateway endpoint
	GatewayAddr string `yaml:"gateway_addr"`

	// Authentication token (overridden by PHANTEX_AUTH_TOKEN env var)
	AuthToken string `yaml:"auth_token"`

	// TLS settings
	TLSEnabled  bool   `yaml:"tls_enabled"`
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`
	TLSCAFile   string `yaml:"tls_ca_file"`

	// Batching
	BatchSize    int           `yaml:"batch_size"`    // events per batch
	BatchTimeout time.Duration `yaml:"batch_timeout"` // max time before flushing
	BufferSize   int           `yaml:"buffer_size"`   // disconnect buffer capacity (default 10000)

	// Retry
	MaxRetries    int           `yaml:"max_retries"`
	RetryInterval time.Duration `yaml:"retry_interval"`
}

// HealthConfig controls the health check HTTP server.
type HealthConfig struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"` // e.g., ":9090"
}

// PerformanceConfig has tuning knobs.
type PerformanceConfig struct {
	// Max events per second (0 = unlimited)
	MaxEventsPerSec int `yaml:"max_events_per_sec"`

	// Enricher cache TTL
	EnricherCacheTTL time.Duration `yaml:"enricher_cache_ttl"`
}

// DiscoveryConfig controls AI agent discovery.
type DiscoveryConfig struct {
	// How often to scan /proc for new agent processes
	ScanInterval time.Duration `yaml:"scan_interval"`

	// Tenant slug for PAID generation (e.g., "acme")
	TenantSlug string `yaml:"tenant_slug"`

	// Environment tag for PAID generation (e.g., "prod", "staging", "dev")
	EnvTag string `yaml:"env_tag"`

	// Whether to read /proc/<pid>/environ (needs ptrace capability)
	CheckEnviron bool `yaml:"check_environ"`

	// WatchBinaries lists additional binary names or substrings to treat as
	// AI agent processes. Use this for Go/Rust/C++ agents that aren't launched
	// via an interpreter (e.g., ["my-go-agent", "custom-llm-proxy"]).
	// Matched against /proc/<pid>/comm and /proc/<pid>/cmdline.
	WatchBinaries []string `yaml:"watch_binaries"`

	// ExcludePatterns lists cmdline substrings that should never be treated as
	// AI agents. Use this to prevent PHANTEX's own services (uvicorn, celery,
	// storage-writer) from being registered as discovered agents.
	ExcludePatterns []string `yaml:"exclude_patterns"`

	// ExcludeSelf excludes the sensor's own process and PHANTEX infrastructure
	// processes from discovery. When true, the sensor will skip processes whose
	// cmdline matches known PHANTEX service patterns. Default: true.
	ExcludeSelf bool `yaml:"exclude_self"`

	// DeduplicateWorkers groups forked worker processes (e.g., gunicorn/uvicorn
	// workers) under a single agent entry using the parent PID. Default: true.
	DeduplicateWorkers bool `yaml:"deduplicate_workers"`
}

// SDKSocketConfig controls the Unix domain socket for Python SDK event ingestion.
type SDKSocketConfig struct {
	// Enabled controls whether the SDK socket listener starts.
	Enabled bool `yaml:"enabled"`

	// SocketPath is the Unix socket file path.
	SocketPath string `yaml:"socket_path"`

	// MaxConns is the maximum concurrent SDK connections.
	MaxConns int `yaml:"max_conns"`

	// MaxLineSize is the maximum size of a single NDJSON line in bytes.
	MaxLineSize int `yaml:"max_line_size"`

	// RateLimit is the maximum events per second per connection.
	RateLimit int `yaml:"rate_limit"`
}

// DefaultConfig returns a config with sensible defaults for development.
func DefaultConfig() *Config {
	return &Config{
		LogLevel:  "info",
		LogFormat: "json",
		EBPF: EBPFConfig{
			FilterMode:      "filtered",
			RingBufChanSize: 4096,
		},
		Transport: TransportConfig{
			GatewayAddr:   "localhost:50051",
			AuthToken:     "phantex-dev-token-do-not-use-in-production",
			TLSEnabled:    false,
			BatchSize:     100,
			BatchTimeout:  time.Second,
			BufferSize:    10000,
			MaxRetries:    5,
			RetryInterval: 2 * time.Second,
		},
		Health: HealthConfig{
			Enabled: true,
			Addr:    "127.0.0.1:9090",
		},
		Performance: PerformanceConfig{
			MaxEventsPerSec:  0,
			EnricherCacheTTL: 30 * time.Second,
		},
		Discovery: DiscoveryConfig{
			ScanInterval:       30 * time.Second,
			TenantSlug:         "default",
			EnvTag:             "dev",
			CheckEnviron:       false,
			ExcludeSelf:        true,
			DeduplicateWorkers: true,
		},
		SDKSocket: SDKSocketConfig{
			Enabled:     true,
			SocketPath:  "/var/run/phantex/sdk.sock",
			MaxConns:    50,
			MaxLineSize: 64 * 1024,
			RateLimit:   1000,
		},
	}
}

// Load reads a YAML config file and merges it with defaults.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	if path == "" {
		// Try default locations
		for _, p := range []string{"/etc/phantex/sensor.yaml", "sensor.yaml"} {
			if _, err := os.Stat(p); err == nil {
				path = p
				break
			}
		}
	}

	if path == "" {
		applyEnvOverrides(cfg)
		if cfg.SensorID == "" {
			cfg.SensorID = generateUUIDv4()
		}
		return cfg, nil // no config file — use defaults
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	// Verify config file integrity if a sidecar .sha256 file exists
	cfg.ConfigHash = computeSHA256(data)
	if intErr := verifyConfigIntegrity(path, data); intErr != nil {
		return nil, intErr
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	applyEnvOverrides(cfg)

	// Auto-generate sensor_id if still empty after config + env overrides.
	if cfg.SensorID == "" {
		cfg.SensorID = generateUUIDv4()
	}

	return cfg, nil
}

// generateUUIDv4 returns a random UUID v4 string without external dependencies.
func generateUUIDv4() string {
	var u [16]byte
	_, _ = rand.Read(u[:])
	u[6] = (u[6] & 0x0f) | 0x40 // version 4
	u[8] = (u[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// computeSHA256 returns the hex-encoded SHA-256 digest of data.
func computeSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// verifyConfigIntegrity checks the config file against a sidecar .sha256 file.
// If no sidecar exists, verification is skipped (not an error).
// If the sidecar exists but the hash doesn't match, returns an error.
func verifyConfigIntegrity(path string, data []byte) error {
	sidecar := path + ".sha256"
	expected, err := os.ReadFile(sidecar)
	if err != nil {
		// No sidecar file — integrity check is optional
		return nil
	}

	actualHash := computeSHA256(data)
	expectedHash := strings.TrimSpace(strings.SplitN(string(expected), " ", 2)[0])

	if !strings.EqualFold(actualHash, expectedHash) {
		return fmt.Errorf(
			"config integrity check FAILED for %s: expected sha256=%s, got sha256=%s — "+
				"config file may have been tampered with",
			path, expectedHash, actualHash,
		)
	}
	return nil
}

// applyEnvOverrides overrides config values with environment variables.
// The auth token should come from an env var in production, not the YAML file.
func applyEnvOverrides(cfg *Config) {
	if token := os.Getenv("PHANTEX_AUTH_TOKEN"); token != "" {
		cfg.Transport.AuthToken = token
	}
	if sid := os.Getenv("PHANTEX_SENSOR_ID"); sid != "" {
		cfg.SensorID = sid
	}
	if tid := os.Getenv("PHANTEX_TENANT_ID"); tid != "" {
		cfg.TenantID = tid
	}
}

// devToken is the baked-in default token — must never be used in production.
const devToken = "phantex-dev-token-do-not-use-in-production"

// Validate checks that required fields are set.
func (c *Config) Validate() error {
	if c.EBPF.FilterMode != "all" && c.EBPF.FilterMode != "filtered" {
		return fmt.Errorf("ebpf.filter_mode must be 'all' or 'filtered', got %q", c.EBPF.FilterMode)
	}
	if c.Transport.BatchSize <= 0 {
		return fmt.Errorf("transport.batch_size must be > 0")
	}
	if c.Health.Enabled && c.Health.Addr == "" {
		return fmt.Errorf("health.addr required when health.enabled is true")
	}

	// ── Transport guards ─────────────────────────────────────
	if c.Transport.GatewayAddr == "" {
		return fmt.Errorf("transport.gateway_addr is required")
	}

	// ── Auth / identity guards ───────────────────────────────
	if c.TenantID == "" {
		return fmt.Errorf("tenant_id is required (set via config or PHANTEX_TENANT_ID env var)")
	}
	if c.Transport.AuthToken == "" {
		return fmt.Errorf("transport.auth_token is required (set via PHANTEX_AUTH_TOKEN env var)")
	}
	if c.Transport.AuthToken == devToken {
		if c.Discovery.EnvTag != "dev" {
			return fmt.Errorf("transport.auth_token is still the default dev token — set a real token via PHANTEX_AUTH_TOKEN env var")
		}
	}

	return nil
}
