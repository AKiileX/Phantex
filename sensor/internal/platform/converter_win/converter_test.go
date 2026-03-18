// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

//go:build windows

package converter_win

import (
	"strings"
	"testing"
	"time"

	"github.com/AKiileX/Phantex/sensor/internal/platform"
	enrichwin "github.com/AKiileX/Phantex/sensor/internal/platform/enricher_win"
)

func TestToProtoProcessExec(t *testing.T) {
	conv := New("sensor-test-001", "tenant-test")

	evt := platform.Event{
		Type:        platform.EventProcessExec,
		TimestampNs: uint64(time.Now().UnixNano()),
		PID:         1234,
		PPID:        1000,
		UID:         0,
		Comm:        "python.exe",
		Payload: &platform.ProcessExecPayload{
			Filename: `C:\Python312\python.exe`,
			Argv:     "-m langchain serve",
		},
	}

	info := &enrichwin.ProcessInfo{
		PID:  1234,
		Exe:  `C:\Python312\python.exe`,
		Comm: "python.exe",
	}

	pbEvt := conv.ToProto(evt, info, "ptx-test-dev-abc123")
	if pbEvt == nil {
		t.Fatal("expected non-nil PhantexEvent")
	}

	if pbEvt.TenantId != "tenant-test" {
		t.Errorf("TenantId = %q, want %q", pbEvt.TenantId, "tenant-test")
	}
	if pbEvt.SensorId != "sensor-test-001" {
		t.Errorf("SensorId = %q, want %q", pbEvt.SensorId, "sensor-test-001")
	}
	if pbEvt.AgentId != "ptx-test-dev-abc123" {
		t.Errorf("AgentId = %q, want %q", pbEvt.AgentId, "ptx-test-dev-abc123")
	}
	if pbEvt.EventId == "" {
		t.Error("expected non-empty EventId")
	}

	exec := pbEvt.GetProcessExec()
	if exec == nil {
		t.Fatal("expected ProcessExec payload")
	}
	if exec.Pid != 1234 {
		t.Errorf("PID = %d, want 1234", exec.Pid)
	}
	if exec.Filename != `C:\Python312\python.exe` {
		t.Errorf("Filename = %q", exec.Filename)
	}
}

func TestToProtoNetworkConnect(t *testing.T) {
	conv := New("sensor-test-001", "tenant-test")

	evt := platform.Event{
		Type:        platform.EventNetworkConnect,
		TimestampNs: uint64(time.Now().UnixNano()),
		PID:         5678,
		Comm:        "python.exe",
		Payload: &platform.NetworkPayload{
			SrcAddr:   "192.168.1.100",
			SrcPort:   49152,
			DstAddr:   "10.0.0.1",
			DstPort:   443,
			Protocol:  6,
			IPVersion: 4,
		},
	}

	pbEvt := conv.ToProto(evt, nil, "")
	if pbEvt == nil {
		t.Fatal("expected non-nil PhantexEvent")
	}

	net := pbEvt.GetNetwork()
	if net == nil {
		t.Fatal("expected Network payload")
	}
	if net.DstAddr != "10.0.0.1" {
		t.Errorf("DstAddr = %q, want %q", net.DstAddr, "10.0.0.1")
	}
	if net.DstPort != 443 {
		t.Errorf("DstPort = %d, want 443", net.DstPort)
	}
	if net.Protocol != 6 {
		t.Errorf("Protocol = %d, want 6", net.Protocol)
	}
}

func TestToProtoDNS(t *testing.T) {
	conv := New("sensor-test-001", "tenant-test")

	evt := platform.Event{
		Type:        platform.EventNetworkDNS,
		TimestampNs: uint64(time.Now().UnixNano()),
		PID:         5678,
		Comm:        "python.exe",
		Payload: &platform.DNSPayload{
			QueryName: "api.openai.com",
			QueryType: 1,
			DstAddr:   "8.8.8.8",
			DstPort:   53,
		},
	}

	pbEvt := conv.ToProto(evt, nil, "")
	if pbEvt == nil {
		t.Fatal("expected non-nil PhantexEvent")
	}

	dns := pbEvt.GetDns()
	if dns == nil {
		t.Fatal("expected DNS payload")
	}
	if dns.QueryName != "api.openai.com" {
		t.Errorf("QueryName = %q, want %q", dns.QueryName, "api.openai.com")
	}
}

func TestToProtoRegistry(t *testing.T) {
	conv := New("sensor-test-001", "tenant-test")

	evt := platform.Event{
		Type:        platform.EventRegistrySet,
		TimestampNs: uint64(time.Now().UnixNano()),
		PID:         9999,
		Comm:        "agent.exe",
		Payload: &platform.RegistryPayload{
			KeyPath:   `HKLM\Software\Phantex`,
			ValueName: "AuthToken",
			ValueData: "redacted",
		},
	}

	pbEvt := conv.ToProto(evt, nil, "")
	if pbEvt == nil {
		t.Fatal("expected non-nil PhantexEvent")
	}

	// Registry maps to FileEvent for now
	file := pbEvt.GetFile()
	if file == nil {
		t.Fatal("expected File payload for registry event")
	}
	if !strings.Contains(file.Filename, "HKLM") {
		t.Errorf("expected filename to contain registry key, got %q", file.Filename)
	}
}

func TestToProtoUnknownType(t *testing.T) {
	conv := New("sensor-test-001", "tenant-test")

	evt := platform.Event{
		Type:        platform.EventType(999),
		TimestampNs: uint64(time.Now().UnixNano()),
	}

	pbEvt := conv.ToProto(evt, nil, "")
	if pbEvt != nil {
		t.Error("expected nil for unknown event type")
	}
}

func TestUUIDv7Format(t *testing.T) {
	id := uuidV7()
	parts := strings.Split(id, "-")
	if len(parts) != 5 {
		t.Fatalf("expected 5 UUID parts, got %d: %q", len(parts), id)
	}
	if len(id) != 36 {
		t.Errorf("expected UUID length 36, got %d", len(id))
	}
	// Check version nibble
	if id[14] != '7' {
		t.Errorf("expected version '7' at position 14, got %c", id[14])
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"hello", 10, "hello"},
		{"hello world", 5, "hello"},
		{"", 5, ""},
		{"abc", 0, ""},
	}

	for _, tt := range tests {
		got := truncate(tt.input, tt.maxLen)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
		}
	}
}

func TestToAgentLifecycle(t *testing.T) {
	conv := New("sensor-test-001", "tenant-test")

	pbEvt := conv.ToAgentLifecycle(
		"AGENT_DISCOVERED",
		1234,
		"ptx-test-dev-abc123",
		"langchain",
		"high",
		`C:\Python312\python.exe`,
		"-m langchain serve",
	)

	if pbEvt == nil {
		t.Fatal("expected non-nil PhantexEvent")
	}
	if pbEvt.AgentId != "ptx-test-dev-abc123" {
		t.Errorf("AgentId = %q", pbEvt.AgentId)
	}

	lifecycle := pbEvt.GetLifecycle()
	if lifecycle == nil {
		t.Fatal("expected Lifecycle payload")
	}
	if lifecycle.Framework != "langchain" {
		t.Errorf("Framework = %q", lifecycle.Framework)
	}
}
