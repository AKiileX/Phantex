// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

//go:build windows

// Package config_win provides Windows-specific configuration extensions.
//
// On Windows the config file is searched in:
//  1. --config flag
//  2. %ProgramData%\Phantex\sensor.yaml
//  3. .\sensor.yaml (development)
//
// All secrets come from environment variables, not config files.
package config_win

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/AKiileX/Phantex/sensor/internal/config"
	"gopkg.in/yaml.v3"
)

// WindowsConfig extends the base config with Windows-specific settings.
type WindowsConfig struct {
	config.Config `yaml:",inline"`

	// ETW settings
	ETW ETWConfig `yaml:"etw"`

	// Network monitoring settings
	Network NetworkConfig `yaml:"network"`

	// SDK named pipe (replaces Unix socket)
	NamedPipe NamedPipeConfig `yaml:"named_pipe"`
}

// ETWConfig controls ETW provider behavior.
type ETWConfig struct {
	// Providers to enable (default: all)
	EnableProcess  bool `yaml:"enable_process"`
	EnableFile     bool `yaml:"enable_file"`
	EnableRegistry bool `yaml:"enable_registry"`

	// Channel buffer size
	EventChanSize int `yaml:"event_chan_size"`
}

// NetworkConfig controls TCP/DNS monitoring.
type NetworkConfig struct {
	// Poll interval for TCP connection table
	TCPPollInterval time.Duration `yaml:"tcp_poll_interval"`

	// Poll interval for DNS cache
	DNSPollInterval time.Duration `yaml:"dns_poll_interval"`

	// Max events per second from DNS polling
	DNSRateLimit int `yaml:"dns_rate_limit"`

	// Whether to extract TLS SNI from ClientHello
	ExtractSNI bool `yaml:"extract_sni"`
}

// NamedPipeConfig controls the Windows named pipe for SDK event ingestion.
type NamedPipeConfig struct {
	// Enabled controls whether the named pipe listener starts.
	Enabled bool `yaml:"enabled"`

	// PipeName is the Windows named pipe path (e.g., \\.\pipe\phantex-sdk)
	PipeName string `yaml:"pipe_name"`

	// MaxConns is the maximum concurrent SDK connections.
	MaxConns int `yaml:"max_conns"`

	// MaxLineSize is the maximum size of a single NDJSON line in bytes.
	MaxLineSize int `yaml:"max_line_size"`

	// RateLimit is the maximum events per second per connection.
	RateLimit int `yaml:"rate_limit"`
}

// DefaultWindowsConfig returns a config with Windows-specific defaults.
func DefaultWindowsConfig() *WindowsConfig {
	base := config.DefaultConfig()

	// Override Linux-specific defaults
	base.SDKSocket.Enabled = false // Use named pipe instead
	base.SDKSocket.SocketPath = "" // Not applicable on Windows
	base.EBPF.FilterMode = "all"   // ETW doesn't use this, but keep valid
	base.Health.Addr = "127.0.0.1:9090"

	return &WindowsConfig{
		Config: *base,
		ETW: ETWConfig{
			EnableProcess:  true,
			EnableFile:     true,
			EnableRegistry: true,
			EventChanSize:  8192,
		},
		Network: NetworkConfig{
			TCPPollInterval: 1 * time.Second,
			DNSPollInterval: 2 * time.Second,
			DNSRateLimit:    5000,
			ExtractSNI:      true,
		},
		NamedPipe: NamedPipeConfig{
			Enabled:     true,
			PipeName:    `\\.\pipe\phantex-sdk`,
			MaxConns:    50,
			MaxLineSize: 64 * 1024,
			RateLimit:   1000,
		},
	}
}

// LoadWindows reads the config file from Windows-specific locations.
func LoadWindows(path string) (*WindowsConfig, error) {
	cfg := DefaultWindowsConfig()

	if path == "" {
		// Try Windows-specific locations
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		candidates := []string{
			filepath.Join(programData, "Phantex", "sensor.yaml"),
			"sensor.yaml",
		}
		for _, p := range candidates {
			if _, err := os.Stat(p); err == nil {
				path = p
				break
			}
		}
	}

	if path == "" {
		applyEnvOverrides(&cfg.Config)
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	// Use yaml.v3 directly instead of going through base Load
	// to parse Windows-specific fields
	if err := parseYAML(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	applyEnvOverrides(&cfg.Config)
	return cfg, nil
}

// parseYAML unmarshals config YAML into the WindowsConfig struct.
func parseYAML(data []byte, cfg *WindowsConfig) error {
	return yaml.Unmarshal(data, cfg)
}

// applyEnvOverrides applies environment variable overrides.
func applyEnvOverrides(cfg *config.Config) {
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

// Validate checks Windows-specific configuration constraints.
func (c *WindowsConfig) Validate() error {
	// Run base validation
	if err := c.Config.Validate(); err != nil {
		return err
	}

	// Windows-specific checks
	if c.ETW.EventChanSize <= 0 {
		return fmt.Errorf("etw.event_chan_size must be > 0")
	}
	if !c.ETW.EnableProcess && !c.ETW.EnableFile && !c.ETW.EnableRegistry {
		return fmt.Errorf("at least one ETW provider must be enabled")
	}
	if c.Network.TCPPollInterval < 100*time.Millisecond {
		return fmt.Errorf("network.tcp_poll_interval must be >= 100ms")
	}
	if c.Network.DNSPollInterval < 500*time.Millisecond {
		return fmt.Errorf("network.dns_poll_interval must be >= 500ms")
	}
	if c.NamedPipe.Enabled && c.NamedPipe.PipeName == "" {
		return fmt.Errorf("named_pipe.pipe_name required when named_pipe.enabled is true")
	}

	return nil
}
