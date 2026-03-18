// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

package phantex

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
)

type contextKey int

const (
	traceIDKey contextKey = iota
	spanIDKey
	parentSpanIDKey
	agentPAIDKey
	frameworkKey
)

// NewTraceID generates a new UUID v4 hex string (32 chars).
func NewTraceID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// NewSpanID generates a new span ID (16 hex chars).
func NewSpanID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// WithTraceID returns a new context with the given trace ID.
func WithTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, traceIDKey, traceID)
}

// TraceID returns the trace ID from the context, generating one if absent.
func TraceID(ctx context.Context) string {
	if v, ok := ctx.Value(traceIDKey).(string); ok && v != "" {
		return v
	}
	return NewTraceID()
}

// WithSpanID returns a new context with the given span ID.
func WithSpanID(ctx context.Context, spanID string) context.Context {
	return context.WithValue(ctx, spanIDKey, spanID)
}

// SpanID returns the span ID from the context.
func SpanID(ctx context.Context) string {
	if v, ok := ctx.Value(spanIDKey).(string); ok {
		return v
	}
	return ""
}

// WithParentSpanID returns a new context with the given parent span ID.
func WithParentSpanID(ctx context.Context, parentSpanID string) context.Context {
	return context.WithValue(ctx, parentSpanIDKey, parentSpanID)
}

// ParentSpanID returns the parent span ID from the context.
func ParentSpanID(ctx context.Context) string {
	if v, ok := ctx.Value(parentSpanIDKey).(string); ok {
		return v
	}
	return ""
}

// WithAgentPAID returns a new context with the given agent PAID.
func WithAgentPAID(ctx context.Context, paid string) context.Context {
	return context.WithValue(ctx, agentPAIDKey, paid)
}

// AgentPAID returns the agent PAID from context, or PHANTEX_AGENT_ID env var.
func AgentPAID(ctx context.Context) string {
	if v, ok := ctx.Value(agentPAIDKey).(string); ok && v != "" {
		return v
	}
	return os.Getenv("PHANTEX_AGENT_ID")
}

// WithFramework returns a new context with the given framework name.
func WithFramework(ctx context.Context, framework string) context.Context {
	return context.WithValue(ctx, frameworkKey, framework)
}

// Framework returns the framework name from the context.
func Framework(ctx context.Context) string {
	if v, ok := ctx.Value(frameworkKey).(string); ok {
		return v
	}
	return ""
}

// SpanContext captures a snapshot of the current tracing context.
type SpanContext struct {
	TraceID      string
	SpanID       string
	ParentSpanID string
	AgentPAID    string
	Framework    string
}

// CurrentSpanContext captures the span context from a Go context.
func CurrentSpanContext(ctx context.Context) SpanContext {
	return SpanContext{
		TraceID:      TraceID(ctx),
		SpanID:       SpanID(ctx),
		ParentSpanID: ParentSpanID(ctx),
		AgentPAID:    AgentPAID(ctx),
		Framework:    Framework(ctx),
	}
}
