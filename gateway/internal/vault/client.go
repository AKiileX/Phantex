// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Package vault provides a HashiCorp Vault client for the Phantex gateway.
//
// It handles AppRole authentication, KV v2 secret reads, and Transit
// engine operations (JWT verification via public key).
package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Client is a lightweight Vault client for the gateway.
type Client struct {
	log          *zap.Logger
	addr         string
	roleID       string
	secretID     string
	token        string
	tokenExpiry  time.Time
	mu           sync.Mutex
	httpClient   *http.Client
	mountPath    string
	transitMount string
}

// Config holds Vault client configuration.
type Config struct {
	Addr         string // e.g., "http://127.0.0.1:8200"
	RoleID       string // AppRole role_id
	SecretID     string // AppRole secret_id
	Token        string // Direct token (dev only)
	MountPath    string // KV mount path (default: "secret")
	TransitMount string // Transit mount path (default: "transit")
}

// NewClient creates a new Vault client.
func NewClient(log *zap.Logger, cfg Config) *Client {
	if cfg.MountPath == "" {
		cfg.MountPath = "secret"
	}
	if cfg.TransitMount == "" {
		cfg.TransitMount = "transit"
	}
	return &Client{
		log:          log.Named("vault"),
		addr:         strings.TrimRight(cfg.Addr, "/"),
		roleID:       cfg.RoleID,
		secretID:     cfg.SecretID,
		token:        cfg.Token,
		mountPath:    cfg.MountPath,
		transitMount: cfg.TransitMount,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// ensureToken authenticates via AppRole if the token is missing or expired.
func (c *Client) ensureToken(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token != "" && time.Now().Before(c.tokenExpiry.Add(-60*time.Second)) {
		return nil
	}

	if c.roleID == "" {
		// Using static token (dev mode)
		return nil
	}

	body := fmt.Sprintf(`{"role_id":%q,"secret_id":%q}`, c.roleID, c.secretID)
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost,
		c.addr+"/v1/auth/approle/login",
		strings.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("vault approle request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("vault approle login: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16)) // 64KB max for error
		return fmt.Errorf("vault approle login %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil { // 1MB max
		return fmt.Errorf("vault approle decode: %w", err)
	}

	c.token = result.Auth.ClientToken
	c.tokenExpiry = time.Now().Add(time.Duration(result.Auth.LeaseDuration) * time.Second)

	c.log.Info("vault approle login successful",
		zap.Int("lease_duration", result.Auth.LeaseDuration))

	return nil
}

// ReadSecret reads a KV v2 secret from Vault.
func (c *Client) ReadSecret(ctx context.Context, path string) (map[string]interface{}, error) {
	if err := validatePath(path); err != nil {
		return nil, err
	}
	if err := c.ensureToken(ctx); err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/v1/%s/data/%s", c.addr, c.mountPath, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("vault read request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault read: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16)) // 64KB max for error
		return nil, fmt.Errorf("vault read %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Data struct {
			Data map[string]interface{} `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil { // 1MB max
		return nil, fmt.Errorf("vault read decode: %w", err)
	}

	return result.Data.Data, nil
}

// GetTransitPublicKey retrieves the public key from a Transit key.
func (c *Client) GetTransitPublicKey(ctx context.Context, keyName string) (string, error) {
	if err := validatePath(keyName); err != nil {
		return "", err
	}
	if err := c.ensureToken(ctx); err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s/v1/%s/keys/%s", c.addr, c.transitMount, keyName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("vault transit key request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("vault transit key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16)) // 64KB max for error
		return "", fmt.Errorf("vault transit key %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Data struct {
			Keys map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil { // 1MB max
		return "", fmt.Errorf("vault transit key decode: %w", err)
	}

	// Find latest version
	var latestKey string
	var latestVer int
	for ver, key := range result.Data.Keys {
		v, err := strconv.Atoi(ver)
		if err != nil {
			continue
		}
		if v > latestVer {
			latestVer = v
			latestKey = key.PublicKey
		}
	}

	if latestKey == "" {
		return "", fmt.Errorf("no public key found for transit key %s", keyName)
	}

	return latestKey, nil
}

// validatePath rejects path traversal attempts and absolute paths.
func validatePath(path string) error {
	if strings.Contains(path, "..") || strings.HasPrefix(path, "/") {
		return fmt.Errorf("invalid vault path %q: must not contain '..' or start with '/'", path)
	}
	return nil
}
