// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

package phantex

import (
	"log"
	"strings"
	"sync"
)

// Client is the main Phantex SDK entry point for Go applications.
type Client struct {
	mu        sync.Mutex
	config    *Config
	transport Transport
	hooks     []Hook
	started   bool
}

// NewClient creates a new Phantex client. Pass nil for default (env-based) config.
func NewClient(cfg *Config) *Client {
	if cfg == nil {
		cfg = ConfigFromEnv()
	}
	return &Client{
		config: cfg,
	}
}

// Config returns the client's configuration.
func (c *Client) Config() *Config {
	return c.config
}

// Transport returns the client's transport.
func (c *Client) Transport() Transport {
	return c.transport
}

// Started returns whether the client has been started.
func (c *Client) Started() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.started
}

// Start initialises the transport, installs hooks, and begins event collection.
func (c *Client) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.started {
		return nil
	}
	if !c.config.Enabled {
		if c.config.Debug {
			log.Println("phantex: SDK disabled (PHANTEX_ENABLED=0)")
		}
		return nil
	}

	// Create transport
	c.transport = CreateTransport(c.config)

	// Install hooks
	c.hooks = installHooks(c.transport, c.config)

	c.started = true

	if c.config.Debug {
		names := make([]string, len(c.hooks))
		for i, h := range c.hooks {
			names[i] = h.Name()
		}
		log.Printf("phantex: started — hooks: %s", strings.Join(names, ", "))
	}

	return nil
}

// Stop uninstalls hooks and shuts down the transport.
func (c *Client) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.started {
		return nil
	}

	// Uninstall hooks
	for _, h := range c.hooks {
		h.Uninstall()
	}
	c.hooks = nil

	// Flush and close transport
	if c.transport != nil {
		_ = c.transport.Flush()
		_ = c.transport.Close()
	}

	c.started = false
	if c.config.Debug {
		log.Println("phantex: stopped")
	}
	return nil
}

// Close is an alias for Stop (implements io.Closer).
func (c *Client) Close() error {
	return c.Stop()
}

// GetEvents returns buffered events (only works with BufferTransport).
func (c *Client) GetEvents() []interface{} {
	if bt, ok := c.transport.(*BufferTransport); ok {
		msgs := bt.Peek()
		out := make([]interface{}, len(msgs))
		for i, m := range msgs {
			out[i] = m
		}
		return out
	}
	return nil
}
