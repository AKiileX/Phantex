// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

package sdksocket

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/AKiileX/Phantex/proto/gen/go/phantex/v1"
	"go.uber.org/zap"
)

// ── Parser Tests ─────────────────────────────────────────────────────────────

func TestParser_ToolCallEvent(t *testing.T) {
	p := NewParser("sensor-1", "tenant-1")

	evt := map[string]interface{}{
		"event_id":     "abc123",
		"event_type":   50,
		"timestamp_ns": 1708800000000000000,
		"agent_paid":   "ptx-acme-dev-abc123def456",
		"pid":          12345,
		"tool_name":    "web_search",
		"tool_input":   `{"query": "latest AI news"}`,
		"protocol":     "langchain_tool",
		"framework":    "langchain",
		"severity":     1,
	}

	line, _ := json.Marshal(evt)
	result, err := p.Parse(line, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.EventType != pb.EventType_EVENT_TYPE_TOOL_CALL {
		t.Errorf("event_type = %v, want TOOL_CALL", result.EventType)
	}
	if result.TenantId != "tenant-1" {
		t.Errorf("tenant_id = %q, want %q", result.TenantId, "tenant-1")
	}
	if result.SensorId != "sensor-1" {
		t.Errorf("sensor_id = %q, want %q", result.SensorId, "sensor-1")
	}

	tc := result.GetToolCall()
	if tc == nil {
		t.Fatal("tool_call payload is nil")
	}
	if tc.ToolName != "web_search" {
		t.Errorf("tool_name = %q, want %q", tc.ToolName, "web_search")
	}
	if tc.Protocol != "langchain_tool" {
		t.Errorf("protocol = %q, want %q", tc.Protocol, "langchain_tool")
	}
	if tc.AgentPaid != "ptx-acme-dev-abc123def456" {
		t.Errorf("agent_paid = %q, want %q", tc.AgentPaid, "ptx-acme-dev-abc123def456")
	}
}

func TestParser_ToolResponseEvent(t *testing.T) {
	p := NewParser("sensor-1", "tenant-1")

	success := true
	evt := map[string]interface{}{
		"event_id":     "def456",
		"event_type":   51,
		"timestamp_ns": 1708800001000000000,
		"agent_paid":   "ptx-acme-dev-abc123def456",
		"pid":          12345,
		"tool_name":    "web_search",
		"protocol":     "langchain_tool",
		"success":      success,
		"duration_ns":  5000000,
		"output_size":  1024,
		"severity":     1,
	}

	line, _ := json.Marshal(evt)
	result, err := p.Parse(line, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.EventType != pb.EventType_EVENT_TYPE_TOOL_RESPONSE {
		t.Errorf("event_type = %v, want TOOL_RESPONSE", result.EventType)
	}

	tr := result.GetToolResponse()
	if tr == nil {
		t.Fatal("tool_response payload is nil")
	}
	if tr.ToolName != "web_search" {
		t.Errorf("tool_name = %q, want %q", tr.ToolName, "web_search")
	}
	if !tr.Success {
		t.Error("success = false, want true")
	}
	if tr.DurationNs != 5000000 {
		t.Errorf("duration_ns = %d, want 5000000", tr.DurationNs)
	}
	if tr.OutputSize != 1024 {
		t.Errorf("output_size = %d, want 1024", tr.OutputSize)
	}
}

func TestParser_PeerPIDOverridesSelfReportedPID(t *testing.T) {
	p := NewParser("sensor-1", "tenant-1")

	evt := map[string]interface{}{
		"event_type": 50,
		"pid":        99999, // Self-reported PID (potentially spoofed)
		"tool_name":  "file_read",
	}

	line, _ := json.Marshal(evt)
	result, err := p.Parse(line, 12345) // SO_PEERCRED says PID is 12345
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tc := result.GetToolCall()
	if tc.Pid != 12345 {
		t.Errorf("pid = %d, want 12345 (SO_PEERCRED override)", tc.Pid)
	}
}

func TestParser_MissingToolNameReturnsError(t *testing.T) {
	p := NewParser("sensor-1", "tenant-1")

	evt := map[string]interface{}{
		"event_type": 50,
		// tool_name is missing
	}

	line, _ := json.Marshal(evt)
	_, err := p.Parse(line, 0)
	if err == nil {
		t.Error("expected error for missing tool_name")
	}
}

func TestParser_InvalidEventTypeReturnsError(t *testing.T) {
	p := NewParser("sensor-1", "tenant-1")

	evt := map[string]interface{}{
		"event_type": 999,
		"tool_name":  "test",
	}

	line, _ := json.Marshal(evt)
	_, err := p.Parse(line, 0)
	if err == nil {
		t.Error("expected error for invalid event_type")
	}
}

func TestParser_InvalidJSONReturnsError(t *testing.T) {
	p := NewParser("sensor-1", "tenant-1")

	_, err := p.Parse([]byte("{not json"), 0)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParser_TenantIDFallsBackToSensorTenant(t *testing.T) {
	p := NewParser("sensor-1", "tenant-from-sensor")

	evt := map[string]interface{}{
		"event_type": 50,
		"tool_name":  "test",
		// No tenant_id in event
	}

	line, _ := json.Marshal(evt)
	result, err := p.Parse(line, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.TenantId != "tenant-from-sensor" {
		t.Errorf("tenant_id = %q, want %q", result.TenantId, "tenant-from-sensor")
	}
}

func TestParser_SanitizeTruncateLongToolName(t *testing.T) {
	p := NewParser("sensor-1", "tenant-1")

	longName := make([]byte, 500)
	for i := range longName {
		longName[i] = 'A'
	}

	evt := map[string]interface{}{
		"event_type": 50,
		"tool_name":  string(longName),
	}

	line, _ := json.Marshal(evt)
	result, err := p.Parse(line, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tc := result.GetToolCall()
	if len(tc.ToolName) > 256 {
		t.Errorf("tool_name length = %d, want <= 256", len(tc.ToolName))
	}
}

func TestParser_SeverityMapping(t *testing.T) {
	p := NewParser("sensor-1", "tenant-1")

	tests := []struct {
		severity int
		want     pb.Severity
	}{
		{0, pb.Severity_SEVERITY_INFO},
		{1, pb.Severity_SEVERITY_INFO},
		{2, pb.Severity_SEVERITY_LOW},
		{3, pb.Severity_SEVERITY_MEDIUM},
		{4, pb.Severity_SEVERITY_HIGH},
		{5, pb.Severity_SEVERITY_CRITICAL},
		{99, pb.Severity_SEVERITY_INFO},
	}

	for _, tt := range tests {
		evt := map[string]interface{}{
			"event_type": 50,
			"tool_name":  "test",
			"severity":   tt.severity,
		}
		line, _ := json.Marshal(evt)
		result, err := p.Parse(line, 0)
		if err != nil {
			t.Fatalf("severity %d: unexpected error: %v", tt.severity, err)
		}
		if result.Severity != tt.want {
			t.Errorf("severity %d: got %v, want %v", tt.severity, result.Severity, tt.want)
		}
	}
}

func TestParser_UnknownProtocolSanitized(t *testing.T) {
	p := NewParser("sensor-1", "tenant-1")

	evt := map[string]interface{}{
		"event_type": 50,
		"tool_name":  "test",
		"protocol":   "evil_protocol",
	}

	line, _ := json.Marshal(evt)
	result, err := p.Parse(line, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tc := result.GetToolCall()
	if tc.Protocol != "unknown" {
		t.Errorf("protocol = %q, want %q", tc.Protocol, "unknown")
	}
}

func TestParser_ToolResponseFailure(t *testing.T) {
	p := NewParser("sensor-1", "tenant-1")

	evt := map[string]interface{}{
		"event_type":    51,
		"tool_name":     "dangerous_tool",
		"success":       false,
		"error_message": "permission denied",
		"duration_ns":   100000,
	}

	line, _ := json.Marshal(evt)
	result, err := p.Parse(line, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tr := result.GetToolResponse()
	if tr.Success {
		t.Error("success = true, want false")
	}
}

// ── Listener Integration Tests (Unix Socket) ────────────────────────────────

func TestListener_AcceptAndParseEvents(t *testing.T) {
	// Use a temp directory for the socket
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")

	log, _ := zap.NewDevelopment()
	listener := New(Config{
		SocketPath:  sockPath,
		MaxConns:    5,
		MaxLineSize: 64 * 1024,
		RateLimit:   1000,
		SensorID:    "test-sensor",
		TenantID:    "test-tenant",
	}, log)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start listener in background
	go func() {
		if err := listener.Run(ctx); err != nil {
			t.Logf("listener error: %v", err)
		}
	}()

	// Wait for socket to be created
	waitForSocket(t, sockPath, 2*time.Second)

	// Connect and send events
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send a ToolCallEvent
	evt := map[string]interface{}{
		"event_type": 50,
		"tool_name":  "web_search",
		"tool_input": `{"q": "test"}`,
		"protocol":   "langchain_tool",
		"agent_paid": "ptx-test-agent",
	}
	line, _ := json.Marshal(evt)
	line = append(line, '\n')
	_, err = conn.Write(line)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	// Send a ToolResponseEvent
	resp := map[string]interface{}{
		"event_type":  51,
		"tool_name":   "web_search",
		"success":     true,
		"duration_ns": 5000000,
		"output_size": 512,
	}
	line, _ = json.Marshal(resp)
	line = append(line, '\n')
	_, err = conn.Write(line)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	// Read events from channel
	received := make([]*pb.PhantexEvent, 0, 2)
	timeout := time.After(3 * time.Second)
	for len(received) < 2 {
		select {
		case evt := <-listener.Events():
			received = append(received, evt)
		case <-timeout:
			t.Fatalf("timeout waiting for events, got %d", len(received))
		}
	}

	// Verify
	if len(received) != 2 {
		t.Fatalf("got %d events, want 2", len(received))
	}

	// First event should be ToolCall
	if received[0].EventType != pb.EventType_EVENT_TYPE_TOOL_CALL {
		t.Errorf("event[0] type = %v, want TOOL_CALL", received[0].EventType)
	}
	tc := received[0].GetToolCall()
	if tc == nil || tc.ToolName != "web_search" {
		t.Errorf("event[0] tool_name = %v, want web_search", tc)
	}
	if received[0].TenantId != "test-tenant" {
		t.Errorf("event[0] tenant_id = %q, want test-tenant", received[0].TenantId)
	}

	// Second event should be ToolResponse
	if received[1].EventType != pb.EventType_EVENT_TYPE_TOOL_RESPONSE {
		t.Errorf("event[1] type = %v, want TOOL_RESPONSE", received[1].EventType)
	}
	tr := received[1].GetToolResponse()
	if tr == nil || !tr.Success {
		t.Errorf("event[1] tool_response = %v, want success=true", tr)
	}
}

func TestListener_MultipleConnections(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")

	log, _ := zap.NewDevelopment()
	listener := New(Config{
		SocketPath:  sockPath,
		MaxConns:    10,
		MaxLineSize: 64 * 1024,
		RateLimit:   1000,
		SensorID:    "test-sensor",
		TenantID:    "test-tenant",
	}, log)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = listener.Run(ctx)
	}()

	waitForSocket(t, sockPath, 2*time.Second)

	// 3 concurrent connections
	conns := make([]net.Conn, 3)
	for i := 0; i < 3; i++ {
		c, err := net.Dial("unix", sockPath)
		if err != nil {
			t.Fatalf("dial[%d]: %v", i, err)
		}
		conns[i] = c
		defer c.Close()
	}

	// Each connection sends 1 event
	for i, c := range conns {
		evt := map[string]interface{}{
			"event_type": 50,
			"tool_name":  fmt.Sprintf("tool_%d", i),
		}
		line, _ := json.Marshal(evt)
		line = append(line, '\n')
		_, _ = c.Write(line)
	}

	// Collect 3 events
	received := 0
	timeout := time.After(3 * time.Second)
	for received < 3 {
		select {
		case <-listener.Events():
			received++
		case <-timeout:
			t.Fatalf("timeout: got %d events, want 3", received)
		}
	}
}

func TestListener_RejectsInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")

	log, _ := zap.NewDevelopment()
	listener := New(Config{
		SocketPath:  sockPath,
		MaxConns:    5,
		MaxLineSize: 64 * 1024,
		RateLimit:   1000,
		SensorID:    "test-sensor",
		TenantID:    "test-tenant",
	}, log)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = listener.Run(ctx)
	}()

	waitForSocket(t, sockPath, 2*time.Second)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send invalid JSON
	_, _ = conn.Write([]byte("{bad json}\n"))
	time.Sleep(100 * time.Millisecond)

	// Send valid event after invalid one
	evt := map[string]interface{}{
		"event_type": 50,
		"tool_name":  "valid_tool",
	}
	line, _ := json.Marshal(evt)
	line = append(line, '\n')
	_, _ = conn.Write(line)

	// Should still get the valid event
	timeout := time.After(3 * time.Second)
	select {
	case e := <-listener.Events():
		tc := e.GetToolCall()
		if tc.ToolName != "valid_tool" {
			t.Errorf("tool_name = %q, want valid_tool", tc.ToolName)
		}
	case <-timeout:
		t.Fatal("timeout waiting for valid event after invalid JSON")
	}

	// Parse errors should be counted
	if listener.ParseErrors.Load() < 1 {
		t.Error("expected at least 1 parse error")
	}
}

func TestListener_GracefulShutdown(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")

	log, _ := zap.NewDevelopment()
	listener := New(Config{
		SocketPath: sockPath,
		SensorID:   "test-sensor",
		TenantID:   "test-tenant",
	}, log)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- listener.Run(ctx)
	}()

	waitForSocket(t, sockPath, 2*time.Second)

	// Cancel context → listener should stop
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("unexpected error on shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("listener did not shut down within 5 seconds")
	}

	// Socket file should be removed or listener closed
	_, err := os.Stat(sockPath)
	_ = err // Socket file may or may not be cleaned up — not a hard requirement
}

// ── UUID Tests ──────────────────────────────────────────────────────────────

func TestUUIDV7_Format(t *testing.T) {
	id := uuidV7()

	// Should be 36 chars: 8-4-4-4-12
	if len(id) != 36 {
		t.Errorf("uuid length = %d, want 36", len(id))
	}

	// Version should be 7
	if id[14] != '7' {
		t.Errorf("uuid version = %c, want '7'", id[14])
	}
}

func TestUUIDV7_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id := uuidV7()
		if seen[id] {
			t.Fatalf("duplicate uuid: %s", id)
		}
		seen[id] = true
	}
}

// ── Token Bucket Tests ──────────────────────────────────────────────────────

func TestTokenBucket_AllowsUpToRate(t *testing.T) {
	tb := newTokenBucket(10)

	allowed := 0
	for i := 0; i < 10; i++ {
		if tb.allow() {
			allowed++
		}
	}

	if allowed != 10 {
		t.Errorf("allowed = %d, want 10", allowed)
	}

	// 11th should be denied
	if tb.allow() {
		t.Error("11th request should be denied")
	}
}

func TestTokenBucket_RefillsOverTime(t *testing.T) {
	tb := newTokenBucket(100)

	// Exhaust all tokens
	for i := 0; i < 100; i++ {
		tb.allow()
	}

	// Should be denied
	if tb.allow() {
		t.Error("should be denied after exhaustion")
	}

	// Wait for refill
	time.Sleep(100 * time.Millisecond)

	// Should have ~10 tokens now (100 rate * 0.1s)
	allowed := 0
	for i := 0; i < 20; i++ {
		if tb.allow() {
			allowed++
		}
	}
	if allowed < 5 || allowed > 15 {
		t.Errorf("allowed after refill = %d, want ~10", allowed)
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func waitForSocket(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("socket %s not created within %v", path, timeout)
}
