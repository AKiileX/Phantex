// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Package config manages CLI configuration stored at ~/.phantex/config.yaml.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config holds CLI configuration.
type Config struct {
	BaseURL      string `yaml:"base_url"`
	AccessToken  string `yaml:"access_token,omitempty"`
	RefreshToken string `yaml:"refresh_token,omitempty"`
	TenantID     string `yaml:"tenant_id,omitempty"`
	UserEmail    string `yaml:"user_email,omitempty"`
}

// Dir returns the config directory path (~/.phantex).
func Dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home dir: %w", err)
	}
	return filepath.Join(home, ".phantex"), nil
}

// Path returns the config file path.
func Path() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.yaml"), nil
}

// Load reads config from disk.
func Load() (*Config, error) {
	p, err := Path()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}

// Save writes config to disk with 0600 permissions.
func Save(cfg *Config) error {
	dir, err := Dir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	p := filepath.Join(dir, "config.yaml")
	return os.WriteFile(p, data, 0600)
}

// MustLoad loads config and ensures base_url and token are set, printing
// a helpful message if not.
func MustLoad() *Config {
	cfg, err := Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}
	if cfg.BaseURL == "" {
		fmt.Fprintln(os.Stderr, "Not configured. Run: phantex login --url <base-url>")
		os.Exit(1)
	}
	if cfg.AccessToken == "" {
		fmt.Fprintln(os.Stderr, "Not authenticated. Run: phantex login")
		os.Exit(1)
	}
	return cfg
}
