// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

package phantex

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

func TestConfigFromEnv(t *testing.T) {
	os.Setenv("PHANTEX_TOKEN", "test-token")
	os.Setenv("PHANTEX_TENANT_ID", "tenant-123")
	os.Setenv("PHANTEX_AGENT_ID", "agent-456")
	os.Setenv("PHANTEX_TRANSPORT", "buffer")
	os.Setenv("PHANTEX_BATCH_SIZE", "100")
	os.Setenv("PHANTEX_DEBUG", "1")
	defer func() {
		os.Unsetenv("PHANTEX_TOKEN")
		os.Unsetenv("PHANTEX_TENANT_ID")
		os.Unsetenv("PHANTEX_AGENT_ID")
		os.Unsetenv("PHANTEX_TRANSPORT")
		os.Unsetenv("PHANTEX_BATCH_SIZE")
		os.Unsetenv("PHANTEX_DEBUG")
	}()

	cfg := ConfigFromEnv()
	if cfg.AuthToken != "test-token" {
		t.Errorf("expected token 'test-token', got '%s'", cfg.AuthToken)
	}
	if cfg.TenantID != "tenant-123" {
		t.Errorf("expected tenant 'tenant-123', got '%s'", cfg.TenantID)
	}
	if cfg.AgentID != "agent-456" {
		t.Errorf("expected agent 'agent-456', got '%s'", cfg.AgentID)
	}
	if cfg.Transport != "buffer" {
		t.Errorf("expected transport 'buffer', got '%s'", cfg.Transport)
	}
	if cfg.BatchSize != 100 {
		t.Errorf("expected batch size 100, got %d", cfg.BatchSize)
	}
	if !cfg.Debug {
		t.Errorf("expected debug true")
	}
}

func TestBufferTransport(t *testing.T) {
	bt := NewBufferTransport(10)

	evt := NewToolCallEvent()
	evt.ToolName = "test-tool"
	evt.Framework = "test"

	if err := bt.Send(evt); err != nil {
		t.Fatalf("send failed: %v", err)
	}

	if bt.Len() != 1 {
		t.Fatalf("expected 1 event, got %d", bt.Len())
	}

	events := bt.Drain()
	if len(events) != 1 {
		t.Fatalf("expected 1 drained event, got %d", len(events))
	}

	if bt.Len() != 0 {
		t.Fatalf("expected 0 after drain, got %d", bt.Len())
	}

	// Verify event content
	var decoded ToolCallEvent
	if err := json.Unmarshal(events[0], &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if decoded.ToolName != "test-tool" {
		t.Errorf("expected tool 'test-tool', got '%s'", decoded.ToolName)
	}
}

func TestBufferTransportOverflow(t *testing.T) {
	bt := NewBufferTransport(3)

	for i := 0; i < 5; i++ {
		evt := NewToolCallEvent()
		evt.ToolName = "tool"
		_ = bt.Send(evt)
	}

	if bt.Len() != 3 {
		t.Fatalf("expected 3 (max size), got %d", bt.Len())
	}
}

func TestContext(t *testing.T) {
	ctx := context.Background()

	// Trace ID should be generated when absent
	tid := TraceID(ctx)
	if tid == "" {
		t.Error("expected non-empty trace ID")
	}

	// Setting values
	ctx = WithTraceID(ctx, "trace-abc")
	ctx = WithSpanID(ctx, "span-def")
	ctx = WithAgentPAID(ctx, "agent-ghi")
	ctx = WithFramework(ctx, "go-openai")

	if TraceID(ctx) != "trace-abc" {
		t.Errorf("unexpected trace ID: %s", TraceID(ctx))
	}
	if SpanID(ctx) != "span-def" {
		t.Errorf("unexpected span ID: %s", SpanID(ctx))
	}
	if AgentPAID(ctx) != "agent-ghi" {
		t.Errorf("unexpected agent PAID: %s", AgentPAID(ctx))
	}
	if Framework(ctx) != "go-openai" {
		t.Errorf("unexpected framework: %s", Framework(ctx))
	}
}

func TestSpanContext(t *testing.T) {
	ctx := context.Background()
	ctx = WithTraceID(ctx, "t1")
	ctx = WithSpanID(ctx, "s1")
	ctx = WithAgentPAID(ctx, "a1")
	ctx = WithFramework(ctx, "fw1")

	sc := CurrentSpanContext(ctx)
	if sc.TraceID != "t1" || sc.SpanID != "s1" || sc.AgentPAID != "a1" || sc.Framework != "fw1" {
		t.Errorf("unexpected span context: %+v", sc)
	}
}

func TestEvents(t *testing.T) {
	call := NewToolCallEvent()
	if call.EventType != EventTypeToolCall {
		t.Errorf("expected event type %d, got %d", EventTypeToolCall, call.EventType)
	}
	if call.EventID == "" {
		t.Error("expected non-empty event ID")
	}
	if call.TimestampNs == 0 {
		t.Error("expected non-zero timestamp")
	}

	resp := NewToolResponseEvent()
	if resp.EventType != EventTypeToolResponse {
		t.Errorf("expected event type %d, got %d", EventTypeToolResponse, resp.EventType)
	}
	if !resp.Success {
		t.Error("expected success=true by default")
	}
}

func TestHashPrompt(t *testing.T) {
	h := HashPrompt("hello world")
	if len(h) != 64 {
		t.Errorf("expected 64-char hex hash, got %d chars", len(h))
	}
	// Same input should produce the same hash
	if HashPrompt("hello world") != h {
		t.Error("hash not deterministic")
	}
}

func TestClientStartStop(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Transport = "buffer"
	cfg.Hooks = "none"

	client := NewClient(cfg)
	if client.Started() {
		t.Error("client should not be started yet")
	}

	if err := client.Start(); err != nil {
		t.Fatalf("start failed: %v", err)
	}
	if !client.Started() {
		t.Error("client should be started")
	}

	if err := client.Stop(); err != nil {
		t.Fatalf("stop failed: %v", err)
	}
	if client.Started() {
		t.Error("client should be stopped")
	}
}

func TestClientDisabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = false

	client := NewClient(cfg)
	_ = client.Start()
	if client.Started() {
		t.Error("disabled client should not start")
	}
}

func TestSafeSerialize(t *testing.T) {
	result := SafeSerialize(map[string]string{"key": "value"}, 100)
	if result == "<unserializable>" {
		t.Error("expected valid JSON")
	}

	// Test truncation
	long := SafeSerialize(map[string]string{"key": "very long value that should be truncated"}, 20)
	if len(long) > 20 {
		t.Errorf("expected truncation to 20, got %d", len(long))
	}
}
