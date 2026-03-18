// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

//go:build windows

package enricher_win

import (
	"os"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestEnricherSelf(t *testing.T) {
	log, _ := zap.NewDevelopment()
	e := New(log, 30*time.Second)

	// Enrich our own process
	pid := uint32(getCurrentPID())
	info := e.Enrich(pid)
	if info == nil {
		t.Fatal("expected non-nil ProcessInfo for self")
	}

	if info.PID != pid {
		t.Errorf("PID mismatch: got %d, want %d", info.PID, pid)
	}
	if info.Exe == "" {
		t.Error("expected non-empty Exe path")
	}
	if info.Comm == "" {
		t.Error("expected non-empty Comm")
	}
	if info.UserSID == "" {
		t.Error("expected non-empty UserSID")
	}
	if info.UserName == "" {
		t.Error("expected non-empty UserName")
	}

	t.Logf("Self-enrichment: PID=%d Comm=%s Exe=%s SID=%s User=%s Elevated=%v Session=%d",
		info.PID, info.Comm, info.Exe, info.UserSID, info.UserName, info.Elevated, info.SessionID)
}

func TestEnricherCache(t *testing.T) {
	log, _ := zap.NewDevelopment()
	e := New(log, 30*time.Second)

	pid := uint32(getCurrentPID())

	// First call populates cache
	info1 := e.Enrich(pid)
	if info1 == nil {
		t.Fatal("first enrich returned nil")
	}

	// Second call should hit cache
	info2 := e.Enrich(pid)
	if info2 == nil {
		t.Fatal("second enrich returned nil")
	}

	if info1.CachedAt != info2.CachedAt {
		t.Error("expected cache hit (same CachedAt)")
	}

	if e.CacheSize() != 1 {
		t.Errorf("expected cache size 1, got %d", e.CacheSize())
	}
}

func TestEnricherEvict(t *testing.T) {
	log, _ := zap.NewDevelopment()
	e := New(log, 30*time.Second)

	pid := uint32(getCurrentPID())
	e.Enrich(pid)

	if e.CacheSize() != 1 {
		t.Fatalf("expected cache size 1, got %d", e.CacheSize())
	}

	e.Evict(pid)

	if e.CacheSize() != 0 {
		t.Errorf("expected cache size 0 after evict, got %d", e.CacheSize())
	}
}

func TestEnricherCacheTTL(t *testing.T) {
	log, _ := zap.NewDevelopment()
	e := New(log, 50*time.Millisecond) // Very short TTL

	pid := uint32(getCurrentPID())

	info1 := e.Enrich(pid)
	if info1 == nil {
		t.Fatal("first enrich returned nil")
	}

	time.Sleep(100 * time.Millisecond) // Wait for TTL to expire

	info2 := e.Enrich(pid)
	if info2 == nil {
		t.Fatal("second enrich returned nil")
	}

	if info1.CachedAt == info2.CachedAt {
		t.Error("expected cache refresh after TTL (different CachedAt)")
	}
}

func TestEnricherInvalidPID(t *testing.T) {
	log, _ := zap.NewDevelopment()
	e := New(log, 30*time.Second)

	// PID 99999999 should not exist
	info := e.Enrich(99999999)
	if info != nil {
		t.Error("expected nil for non-existent PID")
	}
}

func TestExtractFileName(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{`C:\Windows\System32\cmd.exe`, "cmd.exe"},
		{`C:\Program Files\Python312\python.exe`, "python.exe"},
		{"python.exe", "python.exe"},
		{"", ""},
		{`/usr/bin/python3`, "python3"}, // Unix path fallback
	}

	for _, tt := range tests {
		got := extractFileName(tt.path)
		if got != tt.want {
			t.Errorf("extractFileName(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func getCurrentPID() int {
	return os.Getpid()
}
