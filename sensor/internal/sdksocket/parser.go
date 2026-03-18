// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

package sdksocket

import (
	"encoding/json"
	"fmt"
	"strings"

	pb "github.com/AKiileX/Phantex/proto/gen/go/phantex/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Parser converts SDK NDJSON lines into protobuf PhantexEvent messages.
//
// The Python SDK sends events with this JSON schema:
//
//	{
//	  "event_id":       "hex-uuid",
//	  "event_type":     50,              // 50 = TOOL_CALL, 51 = TOOL_RESPONSE
//	  "timestamp_ns":   1708800000000000000,
//	  "tenant_id":      "...",
//	  "agent_paid":     "ptx-...",
//	  "pid":            12345,
//	  "tool_name":      "web_search",
//	  "tool_input":     "...",            // only TOOL_CALL
//	  "protocol":       "langchain_tool",
//	  "framework":      "langchain",
//	  "model_name":     "gpt-4",
//	  "prompt_hash":    "sha256...",
//	  "input_tokens":   100,
//	  "output_tokens":  200,
//	  "trace_id":       "...",
//	  "span_id":        "...",
//	  "parent_span_id": "...",
//	  "severity":       1,
//	  // TOOL_RESPONSE only:
//	  "success":        true,
//	  "duration_ns":    5000000,
//	  "output_size":    1024,
//	  "error_message":  ""
//	}
type Parser struct {
	sensorID string
	tenantID string
}

// NewParser creates a parser that injects sensor/tenant identity.
func NewParser(sensorID, tenantID string) *Parser {
	return &Parser{
		sensorID: sensorID,
		tenantID: tenantID,
	}
}

// sdkEvent is the raw JSON structure from the Python SDK.
type sdkEvent struct {
	EventID      string `json:"event_id"`
	EventType    int    `json:"event_type"`
	TimestampNs  int64  `json:"timestamp_ns"`
	TenantID     string `json:"tenant_id"`
	AgentPAID    string `json:"agent_paid"`
	PID          uint32 `json:"pid"`
	ToolName     string `json:"tool_name"`
	ToolInput    string `json:"tool_input"`
	Protocol     string `json:"protocol"`
	Framework    string `json:"framework"`
	ModelName    string `json:"model_name"`
	PromptHash   string `json:"prompt_hash"`
	InputTokens  int64  `json:"input_tokens"`
	OutputTokens int64  `json:"output_tokens"`
	TraceID      string `json:"trace_id"`
	SpanID       string `json:"span_id"`
	ParentSpanID string `json:"parent_span_id"`
	Severity     int    `json:"severity"`
	// TOOL_RESPONSE fields
	Success      *bool  `json:"success"` // pointer to distinguish absent from false
	DurationNs   int64  `json:"duration_ns"`
	OutputSize   int64  `json:"output_size"`
	ErrorMessage string `json:"error_message"`
}

const (
	sdkEventTypeToolCall     = 50
	sdkEventTypeToolResponse = 51
)

// Allowed protocols (whitelist — reject unknown to prevent injection)
var allowedProtocols = map[string]bool{
	"langchain_tool":   true,
	"autogen":          true,
	"crewai":           true,
	"http":             true,
	"mcp":              true,
	"mcp_sse":          true,
	"mcp_stdio":        true,
	"function_calling": true,
	"openai":           true,
	"anthropic":        true,
	"":                 true, // empty is OK
}

// Parse converts a single NDJSON line into a protobuf PhantexEvent.
// The peerPID from SO_PEERCRED overrides the self-reported PID to prevent
// spoofing (defense-in-depth: SDK can't claim to be a different process).
func (p *Parser) Parse(line []byte, peerPID uint32) (*pb.PhantexEvent, error) {
	var raw sdkEvent
	if err := json.Unmarshal(line, &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	// ── Validate required fields ──────────────────────────────────────────
	if raw.EventType != sdkEventTypeToolCall && raw.EventType != sdkEventTypeToolResponse {
		return nil, fmt.Errorf("unsupported event_type: %d", raw.EventType)
	}
	if raw.ToolName == "" {
		return nil, fmt.Errorf("missing required field: tool_name")
	}

	// ── Sanitize fields ──────────────────────────────────────────────────
	raw.ToolName = sanitizeString(raw.ToolName, 256)
	raw.ToolInput = sanitizeString(raw.ToolInput, 4096)
	raw.Protocol = sanitizeString(raw.Protocol, 64)
	raw.Framework = sanitizeString(raw.Framework, 64)
	raw.ModelName = sanitizeString(raw.ModelName, 128)
	raw.ErrorMessage = sanitizeString(raw.ErrorMessage, 1024)

	// Validate protocol against whitelist
	if !allowedProtocols[strings.ToLower(raw.Protocol)] {
		raw.Protocol = "unknown"
	}

	// ── Override PID with SO_PEERCRED for defense-in-depth ──────────────
	if peerPID > 0 {
		raw.PID = peerPID
	}

	// ── Use sensor's tenant if SDK didn't provide one ───────────────────
	tenantID := raw.TenantID
	if tenantID == "" {
		tenantID = p.tenantID
	}

	// ── Event ID: use SDK-provided or generate ─────────────────────────
	eventID := raw.EventID
	if eventID == "" {
		eventID = uuidV7()
	}

	// ── Timestamp ──────────────────────────────────────────────────────
	var ts *timestamppb.Timestamp
	if raw.TimestampNs > 0 {
		sec := raw.TimestampNs / 1_000_000_000
		nsec := raw.TimestampNs % 1_000_000_000
		ts = &timestamppb.Timestamp{Seconds: sec, Nanos: int32(nsec)}
	} else {
		ts = timestamppb.Now()
	}

	// ── Severity mapping ──────────────────────────────────────────────
	severity := mapSeverity(raw.Severity)

	// ── Build ProcessContext ──────────────────────────────────────────
	ctx := &pb.ProcessContext{
		AgentPaid: raw.AgentPAID,
	}

	// ── Build event based on type ────────────────────────────────────
	base := &pb.PhantexEvent{
		EventId:   eventID,
		TenantId:  tenantID,
		AgentId:   raw.AgentPAID,
		SensorId:  p.sensorID,
		Timestamp: ts,
		Severity:  severity,
	}

	switch raw.EventType {
	case sdkEventTypeToolCall:
		base.EventType = pb.EventType_EVENT_TYPE_TOOL_CALL
		base.Payload = &pb.PhantexEvent_ToolCall{
			ToolCall: &pb.ToolCallEvent{
				Pid:       raw.PID,
				AgentPaid: raw.AgentPAID,
				ToolName:  raw.ToolName,
				ToolInput: raw.ToolInput,
				Protocol:  raw.Protocol,
				Context:   ctx,
			},
		}

	case sdkEventTypeToolResponse:
		base.EventType = pb.EventType_EVENT_TYPE_TOOL_RESPONSE
		success := true
		if raw.Success != nil {
			success = *raw.Success
		}
		base.Payload = &pb.PhantexEvent_ToolResponse{
			ToolResponse: &pb.ToolResponseEvent{
				Pid:        raw.PID,
				AgentPaid:  raw.AgentPAID,
				ToolName:   raw.ToolName,
				Success:    success,
				DurationNs: raw.DurationNs,
				OutputSize: raw.OutputSize,
				Context:    ctx,
			},
		}
	}

	return base, nil
}

// ── Helpers ─────────────────────────────────────────────────────────────────

// sanitizeString truncates a string to maxLen bytes and strips control characters.
func sanitizeString(s string, maxLen int) string {
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	// Strip control characters (except \n, \t which are OK in tool input)
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\n' || r == '\t' || r >= 0x20 {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// mapSeverity maps SDK severity int to protobuf Severity.
func mapSeverity(s int) pb.Severity {
	switch s {
	case 1:
		return pb.Severity_SEVERITY_INFO
	case 2:
		return pb.Severity_SEVERITY_LOW
	case 3:
		return pb.Severity_SEVERITY_MEDIUM
	case 4:
		return pb.Severity_SEVERITY_HIGH
	case 5:
		return pb.Severity_SEVERITY_CRITICAL
	default:
		return pb.Severity_SEVERITY_INFO
	}
}
