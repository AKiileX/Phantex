// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

//go:build windows

package discovery_win

import (
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/AKiileX/Phantex/sensor/internal/discovery"
)

func TestIsWindowsInterpreter(t *testing.T) {
	tests := []struct {
		comm string
		want bool
	}{
		{"python.exe", true},
		{"python3.exe", true},
		{"python312.exe", true}, // python3XX variant
		{"pythonw.exe", true},
		{"node.exe", true},
		{"deno.exe", true},
		{"bun.exe", true},
		{"java.exe", true},
		{"javaw.exe", true},
		{"cmd.exe", false},
		{"explorer.exe", false},
		{"svchost.exe", false},
		{"", false},
	}

	for _, tt := range tests {
		got := isWindowsInterpreter(strings.ToLower(tt.comm))
		if got != tt.want {
			t.Errorf("isWindowsInterpreter(%q) = %v, want %v", tt.comm, got, tt.want)
		}
	}
}

func TestBuiltinWindowsSignatures(t *testing.T) {
	sigs := BuiltinWindowsSignatures()

	if len(sigs) == 0 {
		t.Fatal("expected non-empty signatures")
	}

	// Should include base Linux signatures plus Windows-specific ones
	baseSigs := discovery.BuiltinSignatures()
	if len(sigs) <= len(baseSigs) {
		t.Errorf("expected Windows signatures (%d) > base signatures (%d)",
			len(sigs), len(baseSigs))
	}

	// Check for Windows-specific patterns
	has_sitepackages := false
	has_pyd := false
	for _, sig := range sigs {
		if strings.Contains(sig.Pattern, "site-packages\\") {
			has_sitepackages = true
		}
		if strings.HasSuffix(sig.Pattern, ".pyd") {
			has_pyd = true
		}
	}

	if !has_sitepackages {
		t.Error("expected Windows site-packages patterns")
	}
	if !has_pyd {
		t.Error("expected Windows .pyd patterns")
	}
}

func TestTruncateHelper(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"hello", 10, "hello"},
		{"hello world", 5, "hello"},
		{"", 5, ""},
	}

	for _, tt := range tests {
		got := truncate(tt.input, tt.maxLen)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
		}
	}
}

func TestScannerCreation(t *testing.T) {
	// Just verify scanner can be created without panicking
	log, _ := zap.NewDevelopment()
	cfg := DefaultScannerConfig()
	cfg.WatchBinaries = []string{"my-custom-agent"}

	scanner := NewScanner(log, cfg)
	if scanner == nil {
		t.Fatal("expected non-nil scanner")
	}

	// Event channel should be non-nil
	ch := scanner.Events()
	if ch == nil {
		t.Fatal("expected non-nil events channel")
	}

	// No agents tracked initially
	agents := scanner.Agents()
	if len(agents) != 0 {
		t.Errorf("expected 0 initial agents, got %d", len(agents))
	}
}
