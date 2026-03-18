// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

package phantex

import (
	"os"
	"strconv"
	"strings"
)

// Config holds all SDK configuration. Built from environment variables.
type Config struct {
	// Auth token for the gateway.
	AuthToken string

	// Tenant UUID.
	TenantID string

	// Agent PAID (Phantex Agent ID).
	AgentID string

	// Transport mode: "auto", "grpc", "http", "buffer".
	Transport string

	// Gateway gRPC address (host:port).
	GatewayAddr string

	// HTTP gateway URL (fallback).
	HTTPEndpoint string

	// Max events per batch before flush.
	BatchSize int

	// Max seconds before flushing a partial batch.
	BatchTimeout float64

	// Max events to buffer when transport is unavailable.
	BufferSize int

	// Which hooks to enable: "auto", "openai,http", "none".
	Hooks string

	// Record prompt content (true = Level 2/3, false = hash only).
	RecordPrompts bool

	// Enable debug logging.
	Debug bool

	// SDK enabled/disabled kill switch.
	Enabled bool
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Transport:    "auto",
		GatewayAddr:  "localhost:50051",
		HTTPEndpoint: "https://localhost:8443/v1/events",
		BatchSize:    50,
		BatchTimeout: 1.0,
		BufferSize:   5000,
		Hooks:        "auto",
		Enabled:      true,
	}
}

// ConfigFromEnv builds a Config from PHANTEX_* environment variables.
func ConfigFromEnv() *Config {
	cfg := DefaultConfig()

	if v := os.Getenv("PHANTEX_TOKEN"); v != "" {
		cfg.AuthToken = sanitizeHeaderValue(v)
	}
	if v := os.Getenv("PHANTEX_TENANT_ID"); v != "" {
		cfg.TenantID = v
	}
	if v := os.Getenv("PHANTEX_AGENT_ID"); v != "" {
		cfg.AgentID = v
	}
	if v := os.Getenv("PHANTEX_TRANSPORT"); v != "" {
		cfg.Transport = v
	}
	if v := os.Getenv("PHANTEX_GATEWAY_ADDR"); v != "" {
		cfg.GatewayAddr = v
	}
	if v := os.Getenv("PHANTEX_HTTP_ENDPOINT"); v != "" {
		cfg.HTTPEndpoint = v
	}
	if v := os.Getenv("PHANTEX_BATCH_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.BatchSize = n
		}
	}
	if v := os.Getenv("PHANTEX_BATCH_TIMEOUT"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			cfg.BatchTimeout = f
		}
	}
	if v := os.Getenv("PHANTEX_BUFFER_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.BufferSize = n
		}
	}
	if v := os.Getenv("PHANTEX_HOOKS"); v != "" {
		cfg.Hooks = v
	}
	if os.Getenv("PHANTEX_RECORD_PROMPTS") == "1" {
		cfg.RecordPrompts = true
	}
	if os.Getenv("PHANTEX_DEBUG") == "1" {
		cfg.Debug = true
	}
	if os.Getenv("PHANTEX_ENABLED") == "0" {
		cfg.Enabled = false
	}

	return cfg
}

// sanitizeHeaderValue strips characters that could enable HTTP header injection.
func sanitizeHeaderValue(v string) string {
	r := strings.NewReplacer("\r", "", "\n", "")
	return strings.TrimSpace(r.Replace(v))
}
