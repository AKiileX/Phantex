// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

//nolint:errcheck // test helper HTTP handlers — error returns don't matter
package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

// ── Helpers ─────────────────────────────────────────────────────────────────

// fakeVaultServer creates a test HTTP server that mimics Vault endpoints.
func fakeVaultServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(handler)
}

// ── NewClient ───────────────────────────────────────────────────────────────

func TestNewClient_Defaults(t *testing.T) {
	log := zaptest.NewLogger(t)
	c := NewClient(log, Config{
		Addr:   "http://fake:8200",
		RoleID: "role",
	})
	if c.mountPath != "secret" {
		t.Errorf("expected default mountPath 'secret', got %q", c.mountPath)
	}
	if c.transitMount != "transit" {
		t.Errorf("expected default transitMount 'transit', got %q", c.transitMount)
	}
	if c.httpClient.Timeout != 10*time.Second {
		t.Errorf("expected 10s timeout, got %v", c.httpClient.Timeout)
	}
}

func TestNewClient_CustomMounts(t *testing.T) {
	log := zaptest.NewLogger(t)
	c := NewClient(log, Config{
		Addr:         "http://fake:8200",
		MountPath:    "kv",
		TransitMount: "tx",
	})
	if c.mountPath != "kv" {
		t.Errorf("expected mountPath 'kv', got %q", c.mountPath)
	}
	if c.transitMount != "tx" {
		t.Errorf("expected transitMount 'tx', got %q", c.transitMount)
	}
}

// ── ensureToken ─────────────────────────────────────────────────────────────

func TestEnsureToken_StaticToken_SkipsLogin(t *testing.T) {
	log := zaptest.NewLogger(t)
	c := NewClient(log, Config{
		Addr:  "http://fake:8200",
		Token: "static-token",
		// No RoleID — should skip login
	})

	err := c.ensureToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.token != "static-token" {
		t.Errorf("expected static-token, got %q", c.token)
	}
}

func TestEnsureToken_CachedToken_SkipsLogin(t *testing.T) {
	var calls int32
	srv := fakeVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{
				"client_token":   "new-token",
				"lease_duration": 3600,
			},
		})
	})
	defer srv.Close()

	log := zaptest.NewLogger(t)
	c := NewClient(log, Config{
		Addr:     srv.URL,
		RoleID:   "role",
		SecretID: "secret",
	})

	// First call — should login
	if err := c.ensureToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Second call — should use cached token
	if err := c.ensureToken(context.Background()); err != nil {
		t.Fatal(err)
	}

	if atomic.LoadInt32(&calls) != 1 {
		t.Errorf("expected 1 login call, got %d", calls)
	}
}

func TestEnsureToken_AppRoleLogin(t *testing.T) {
	srv := fakeVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/approle/login" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "test-role") {
			t.Errorf("expected body to contain role_id")
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{
				"client_token":   "approle-token-123",
				"lease_duration": 7200,
			},
		})
	})
	defer srv.Close()

	log := zaptest.NewLogger(t)
	c := NewClient(log, Config{
		Addr:     srv.URL,
		RoleID:   "test-role",
		SecretID: "test-secret",
	})

	if err := c.ensureToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.token != "approle-token-123" {
		t.Errorf("expected approle-token-123, got %q", c.token)
	}
	if c.tokenExpiry.Before(time.Now().Add(7100 * time.Second)) {
		t.Error("tokenExpiry should be ~2h in the future")
	}
}

func TestEnsureToken_LoginFailure(t *testing.T) {
	srv := fakeVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"errors":["permission denied"]}`))
	})
	defer srv.Close()

	log := zaptest.NewLogger(t)
	c := NewClient(log, Config{
		Addr:     srv.URL,
		RoleID:   "bad-role",
		SecretID: "bad-secret",
	})

	err := c.ensureToken(context.Background())
	if err == nil {
		t.Fatal("expected error for 403 response")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("expected '403' in error, got: %v", err)
	}
}

// ── ReadSecret ──────────────────────────────────────────────────────────────

func TestReadSecret_Success(t *testing.T) {
	srv := fakeVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/approle/login" {
			json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]any{
					"client_token":   "tok",
					"lease_duration": 3600,
				},
			})
			return
		}
		if r.URL.Path != "/v1/secret/data/phantex/database" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("X-Vault-Token") == "" {
			t.Error("missing X-Vault-Token header")
		}

		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"data": map[string]any{
					"db_password": "prod-pass",
					"db_user":     "app",
				},
			},
		})
	})
	defer srv.Close()

	log := zaptest.NewLogger(t)
	c := NewClient(log, Config{
		Addr:     srv.URL,
		RoleID:   "role",
		SecretID: "secret",
	})

	data, err := c.ReadSecret(context.Background(), "phantex/database")
	if err != nil {
		t.Fatal(err)
	}
	if data["db_password"] != "prod-pass" {
		t.Errorf("expected 'prod-pass', got %v", data["db_password"])
	}
}

func TestReadSecret_NotFound(t *testing.T) {
	srv := fakeVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/approle/login" {
			json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]any{
					"client_token":   "tok",
					"lease_duration": 3600,
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"errors":[]}`))
	})
	defer srv.Close()

	log := zaptest.NewLogger(t)
	c := NewClient(log, Config{
		Addr:     srv.URL,
		RoleID:   "role",
		SecretID: "secret",
	})

	_, err := c.ReadSecret(context.Background(), "nonexistent/path")
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("expected '404' in error, got: %v", err)
	}
}

// ── GetTransitPublicKey ─────────────────────────────────────────────────────

func TestGetTransitPublicKey_LatestVersion(t *testing.T) {
	srv := fakeVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/approle/login" {
			json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]any{
					"client_token":   "tok",
					"lease_duration": 3600,
				},
			})
			return
		}

		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"keys": map[string]any{
					"1": map[string]any{"public_key": "-----OLD KEY-----"},
					"2": map[string]any{"public_key": "-----LATEST KEY-----"},
					"3": map[string]any{"public_key": "-----NEWEST KEY-----"},
				},
			},
		})
	})
	defer srv.Close()

	log := zaptest.NewLogger(t)
	c := NewClient(log, Config{
		Addr:     srv.URL,
		RoleID:   "role",
		SecretID: "secret",
	})

	key, err := c.GetTransitPublicKey(context.Background(), "jwt-signing")
	if err != nil {
		t.Fatal(err)
	}
	if key != "-----NEWEST KEY-----" {
		t.Errorf("expected newest key, got %q", key)
	}
}

func TestGetTransitPublicKey_NoKeys(t *testing.T) {
	srv := fakeVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/approle/login" {
			json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]any{
					"client_token":   "tok",
					"lease_duration": 3600,
				},
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"keys": map[string]any{}},
		})
	})
	defer srv.Close()

	log := zaptest.NewLogger(t)
	c := NewClient(log, Config{
		Addr:     srv.URL,
		RoleID:   "role",
		SecretID: "secret",
	})

	_, err := c.GetTransitPublicKey(context.Background(), "jwt-signing")
	if err == nil {
		t.Fatal("expected error for empty keys")
	}
	if !strings.Contains(err.Error(), "no public key found") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ── LimitReader Enforcement ─────────────────────────────────────────────────

func TestReadSecret_LargeResponseTruncated(t *testing.T) {
	// Verify that responses > 1MB are truncated by LimitReader (JSON decode fails)
	srv := fakeVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/approle/login" {
			json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]any{
					"client_token":   "tok",
					"lease_duration": 3600,
				},
			})
			return
		}
		// Send 2MB of valid-looking JSON
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"data":{"key":"`))
		w.Write(make([]byte, 2*1024*1024)) // 2MB of zeros
		w.Write([]byte(`"}}}`))
	})
	defer srv.Close()

	log := zaptest.NewLogger(t)
	c := NewClient(log, Config{
		Addr:     srv.URL,
		RoleID:   "role",
		SecretID: "secret",
	})

	_, err := c.ReadSecret(context.Background(), "big-secret")
	if err == nil {
		t.Fatal("expected error for oversized response")
	}
}

// ── ensureToken LimitReader ─────────────────────────────────────────────────

func TestEnsureToken_LargeResponseTruncated(t *testing.T) {
	srv := fakeVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"auth":{"client_token":"tok","lease_duration":3600,"`))
		// Pad to > 1MB
		w.Write([]byte(fmt.Sprintf(`"padding":"%s"}}`, strings.Repeat("x", 2*1024*1024))))
	})
	defer srv.Close()

	log := zaptest.NewLogger(t)
	c := NewClient(log, Config{
		Addr:     srv.URL,
		RoleID:   "role",
		SecretID: "secret",
	})

	err := c.ensureToken(context.Background())
	if err == nil {
		t.Fatal("expected error for oversized login response")
	}
}

// ── Error Response LimitReader (64KB) ───────────────────────────────────────

func TestReadSecret_ErrorResponseLimited(t *testing.T) {
	srv := fakeVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/approle/login" {
			json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]any{
					"client_token":   "tok",
					"lease_duration": 3600,
				},
			})
			return
		}
		// Return a massive error body
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(strings.Repeat("A", 200*1024))) // 200KB
	})
	defer srv.Close()

	log := zaptest.NewLogger(t)
	c := NewClient(log, Config{
		Addr:     srv.URL,
		RoleID:   "role",
		SecretID: "secret",
	})

	_, err := c.ReadSecret(context.Background(), "path")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	// The error message should be at most ~64KB (truncated by LimitReader)
	if len(err.Error()) > 100*1024 {
		t.Errorf("error message too large (%d bytes), LimitReader not working", len(err.Error()))
	}
}
