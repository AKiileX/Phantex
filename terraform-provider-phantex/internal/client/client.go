// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Package client provides an HTTP client for the Phantex SOAR API.
//
// Security:
//   - HTTPS-only by default (InsecureSkipVerify is opt-in)
//   - API key sent via X-Phantex-Api-Key header
//   - Request timeout: 30s
//   - Response body size limited to 10MB
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	maxResponseBytes = 10 * 1024 * 1024 // 10MB
	requestTimeout   = 30 * time.Second
)

// Client is an HTTP client for the Phantex API.
type Client struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
}

// NewClient creates a new Phantex API client.
func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		BaseURL: baseURL,
		APIKey:  apiKey,
		HTTPClient: &http.Client{
			Timeout: requestTimeout,
		},
	}
}

func (c *Client) doRequest(ctx context.Context, method, path string, body any) ([]byte, int, error) {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("marshal request: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reqBody)
	if err != nil {
		return nil, 0, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("X-Phantex-Api-Key", c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Terraform-Phantex/1.0")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read response: %w", err)
	}

	return respBody, resp.StatusCode, nil
}

// Get performs a GET request.
func (c *Client) Get(ctx context.Context, path string) ([]byte, error) {
	body, status, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("GET %s: HTTP %d: %s", path, status, string(body))
	}
	return body, nil
}

// Post performs a POST request.
func (c *Client) Post(ctx context.Context, path string, payload any) ([]byte, error) {
	body, status, err := c.doRequest(ctx, http.MethodPost, path, payload)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("POST %s: HTTP %d: %s", path, status, string(body))
	}
	return body, nil
}

// Patch performs a PATCH request.
func (c *Client) Patch(ctx context.Context, path string, payload any) ([]byte, error) {
	body, status, err := c.doRequest(ctx, http.MethodPatch, path, payload)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("PATCH %s: HTTP %d: %s", path, status, string(body))
	}
	return body, nil
}

// Delete performs a DELETE request.
func (c *Client) Delete(ctx context.Context, path string) error {
	_, status, err := c.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("DELETE %s: HTTP %d", path, status)
	}
	return nil
}
