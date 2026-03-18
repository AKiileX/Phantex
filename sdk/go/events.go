// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

package phantex

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// EventType codes — matches proto/phantex/v1/events.proto.
const (
	EventTypeUnspecified     = 0
	EventTypeProcessExec     = 1
	EventTypeProcessExit     = 2
	EventTypeFileOpen        = 10
	EventTypeFileWrite       = 11
	EventTypeFileRead        = 12
	EventTypeNetworkConnect  = 20
	EventTypeNetworkAccept   = 21
	EventTypeNetworkDNS      = 22
	EventTypeMemoryMmap      = 30
	EventTypeAgentDiscovered = 40
	EventTypeAgentTerminated = 41
	EventTypeToolCall        = 50
	EventTypeToolResponse    = 51
	EventTypeAlertFired      = 60
)

// Severity levels — matches proto/phantex/v1/events.proto.
const (
	SeverityUnspecified = 0
	SeverityInfo        = 1
	SeverityLow         = 2
	SeverityMedium      = 3
	SeverityHigh        = 4
	SeverityCritical    = 5
)

// ToolCallEvent represents a captured tool/function call.
type ToolCallEvent struct {
	EventID     string `json:"event_id"`
	EventType   int    `json:"event_type"`
	TimestampNs int64  `json:"timestamp_ns"`

	TenantID  string `json:"tenant_id,omitempty"`
	AgentPAID string `json:"agent_paid,omitempty"`
	PID       int    `json:"pid,omitempty"`

	ToolName  string `json:"tool_name,omitempty"`
	ToolInput string `json:"tool_input,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Framework string `json:"framework,omitempty"`

	ModelName    string `json:"model_name,omitempty"`
	PromptHash   string `json:"prompt_hash,omitempty"`
	InputTokens  int    `json:"input_tokens,omitempty"`
	OutputTokens int    `json:"output_tokens,omitempty"`

	TraceID      string `json:"trace_id,omitempty"`
	SpanID       string `json:"span_id,omitempty"`
	ParentSpanID string `json:"parent_span_id,omitempty"`

	Severity int `json:"severity,omitempty"`
}

// ToolResponseEvent represents a captured tool/function response.
type ToolResponseEvent struct {
	EventID     string `json:"event_id"`
	EventType   int    `json:"event_type"`
	TimestampNs int64  `json:"timestamp_ns"`

	TenantID  string `json:"tenant_id,omitempty"`
	AgentPAID string `json:"agent_paid,omitempty"`
	PID       int    `json:"pid,omitempty"`

	ToolName  string `json:"tool_name,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Framework string `json:"framework,omitempty"`

	Success      bool   `json:"success"`
	DurationNs   int64  `json:"duration_ns,omitempty"`
	OutputSize   int    `json:"output_size,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`

	ModelName    string `json:"model_name,omitempty"`
	InputTokens  int    `json:"input_tokens,omitempty"`
	OutputTokens int    `json:"output_tokens,omitempty"`

	TraceID      string `json:"trace_id,omitempty"`
	SpanID       string `json:"span_id,omitempty"`
	ParentSpanID string `json:"parent_span_id,omitempty"`

	Severity int `json:"severity,omitempty"`
}

// NewToolCallEvent creates a ToolCallEvent with defaults populated.
func NewToolCallEvent() *ToolCallEvent {
	return &ToolCallEvent{
		EventID:     NewTraceID(),
		EventType:   EventTypeToolCall,
		TimestampNs: time.Now().UnixNano(),
		Severity:    SeverityInfo,
	}
}

// NewToolResponseEvent creates a ToolResponseEvent with defaults populated.
func NewToolResponseEvent() *ToolResponseEvent {
	return &ToolResponseEvent{
		EventID:     NewTraceID(),
		EventType:   EventTypeToolResponse,
		TimestampNs: time.Now().UnixNano(),
		Success:     true,
		Severity:    SeverityInfo,
	}
}

// HashPrompt returns the SHA-256 hex digest of prompt content.
func HashPrompt(prompt string) string {
	h := sha256.Sum256([]byte(prompt))
	return hex.EncodeToString(h[:])
}

// SafeSerialize converts an object to a JSON string, truncated to maxBytes.
func SafeSerialize(v interface{}, maxBytes int) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "<unserializable>"
	}
	if len(b) > maxBytes {
		// Truncate at byte level, then backtrack to avoid splitting a UTF-8 rune
		cut := maxBytes - 3
		for cut > 0 && cut < len(b) && b[cut]&0xC0 == 0x80 {
			cut--
		}
		return string(b[:cut]) + "..."
	}
	return string(b)
}

// Event is an interface satisfied by both event types for transport.
type Event interface {
	ToJSON() ([]byte, error)
}

// ToJSON serializes a ToolCallEvent to JSON.
func (e *ToolCallEvent) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// ToJSON serializes a ToolResponseEvent to JSON.
func (e *ToolResponseEvent) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// String returns a human-readable summary.
func (e *ToolCallEvent) String() string {
	return fmt.Sprintf("ToolCall{tool=%s, framework=%s, trace=%s}", e.ToolName, e.Framework, e.TraceID)
}

// String returns a human-readable summary.
func (e *ToolResponseEvent) String() string {
	return fmt.Sprintf("ToolResponse{tool=%s, success=%v, duration=%dns}", e.ToolName, e.Success, e.DurationNs)
}
