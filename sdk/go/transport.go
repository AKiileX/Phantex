// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

package phantex

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	pb "github.com/AKiileX/Phantex/proto/gen/go/phantex/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Transport is the interface for shipping events to the gateway.
type Transport interface {
	Send(event Event) error
	Flush() error
	Close() error
}

// ---------- Buffer Transport (in-memory, for testing) ----------

// BufferTransport stores events in memory. Useful for testing.
type BufferTransport struct {
	mu      sync.Mutex
	events  []json.RawMessage
	maxSize int
}

// NewBufferTransport creates a buffer transport with the given max size.
func NewBufferTransport(maxSize int) *BufferTransport {
	if maxSize <= 0 {
		maxSize = 5000
	}
	return &BufferTransport{maxSize: maxSize}
}

func (t *BufferTransport) Send(event Event) error {
	b, err := event.ToJSON()
	if err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.events) >= t.maxSize {
		t.events = t.events[1:] // drop oldest
	}
	t.events = append(t.events, json.RawMessage(b))
	return nil
}

func (t *BufferTransport) Flush() error { return nil }
func (t *BufferTransport) Close() error { return nil }

// Drain returns and clears all buffered events.
func (t *BufferTransport) Drain() []json.RawMessage {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := t.events
	t.events = nil
	return out
}

// Peek returns all buffered events without clearing.
func (t *BufferTransport) Peek() []json.RawMessage {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]json.RawMessage, len(t.events))
	copy(out, t.events)
	return out
}

// Len returns the number of buffered events.
func (t *BufferTransport) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.events)
}

// ---------- gRPC Transport ----------

// GRPCTransport ships events to the gateway via gRPC streaming.
type GRPCTransport struct {
	mu     sync.Mutex
	conn   *grpc.ClientConn
	client pb.SensorServiceClient
	buffer []Event
	config *Config
	done   chan struct{}
	closed bool
}

// NewGRPCTransport creates a gRPC transport to the given gateway address.
func NewGRPCTransport(cfg *Config) (*GRPCTransport, error) {
	var opts []grpc.DialOption

	// Use TLS in production, insecure only for exact localhost
	host := cfg.GatewayAddr
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		host = host[:idx]
	}
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS12,
		})))
	}

	conn, err := grpc.NewClient(cfg.GatewayAddr, opts...)
	if err != nil {
		return nil, fmt.Errorf("phantex: grpc dial %s: %w", cfg.GatewayAddr, err)
	}

	t := &GRPCTransport{
		conn:   conn,
		client: pb.NewSensorServiceClient(conn),
		buffer: make([]Event, 0, cfg.BatchSize),
		config: cfg,
		done:   make(chan struct{}),
	}

	go t.flushLoop()
	return t, nil
}

func (t *GRPCTransport) Send(event Event) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return fmt.Errorf("phantex: transport closed")
	}
	t.buffer = append(t.buffer, event)
	if len(t.buffer) >= t.config.BatchSize {
		return t.flushLocked()
	}
	return nil
}

func (t *GRPCTransport) Flush() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.flushLocked()
}

func (t *GRPCTransport) flushLocked() error {
	if len(t.buffer) == 0 {
		return nil
	}

	batch := make([]Event, len(t.buffer))
	copy(batch, t.buffer)
	t.buffer = t.buffer[:0]

	// Convert to protobuf and send
	for _, ev := range batch {
		pbEvent := eventToProto(ev)
		if pbEvent == nil {
			continue
		}
		// Use unary IngestEvent RPC — stream could also work
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := t.client.IngestEvent(ctx, pbEvent)
		cancel()
		if err != nil {
			if t.config.Debug {
				log.Printf("phantex: grpc send failed: %v", err)
			}
			// Re-buffer on failure (best effort)
			t.buffer = append(t.buffer, ev)
		}
	}
	return nil
}

func (t *GRPCTransport) flushLoop() {
	ticker := time.NewTicker(time.Duration(t.config.BatchTimeout * float64(time.Second)))
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_ = t.Flush()
		case <-t.done:
			return
		}
	}
}

func (t *GRPCTransport) Close() error {
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
	close(t.done)
	_ = t.Flush()
	return t.conn.Close()
}

// eventToProto converts an SDK event to a protobuf PhantexEvent.
func eventToProto(ev Event) *pb.PhantexEvent {
	switch e := ev.(type) {
	case *ToolCallEvent:
		return &pb.PhantexEvent{
			EventId:   e.EventID,
			TenantId:  e.TenantID,
			AgentId:   e.AgentPAID,
			Timestamp: timestamppb.Now(),
			EventType: pb.EventType_EVENT_TYPE_TOOL_CALL,
			Severity:  pb.Severity(e.Severity),
			Payload: &pb.PhantexEvent_ToolCall{
				ToolCall: &pb.ToolCallEvent{
					ToolName:  e.ToolName,
					InputHash: e.PromptHash,
					Protocol:  e.Protocol,
					Framework: e.Framework,
					ModelName: e.ModelName,
					TraceId:   e.TraceID,
					SpanId:    e.SpanID,
				},
			},
		}
	case *ToolResponseEvent:
		return &pb.PhantexEvent{
			EventId:   e.EventID,
			TenantId:  e.TenantID,
			AgentId:   e.AgentPAID,
			Timestamp: timestamppb.Now(),
			EventType: pb.EventType_EVENT_TYPE_TOOL_RESPONSE,
			Severity:  pb.Severity(e.Severity),
			Payload: &pb.PhantexEvent_ToolResponse{
				ToolResponse: &pb.ToolResponseEvent{
					ToolName:   e.ToolName,
					Success:    e.Success,
					DurationNs: e.DurationNs,
					OutputSize: int64(e.OutputSize),
					TraceId:    e.TraceID,
					SpanId:     e.SpanID,
				},
			},
		}
	default:
		return nil
	}
}

// ---------- HTTP Transport (fallback) ----------

// HTTPTransport ships events as JSON-L batches over HTTPS POST.
type HTTPTransport struct {
	mu       sync.Mutex
	client   *http.Client
	endpoint string
	token    string
	buffer   []Event
	config   *Config
	done     chan struct{}
	closed   bool
}

// NewHTTPTransport creates an HTTP fallback transport.
func NewHTTPTransport(cfg *Config) *HTTPTransport {
	t := &HTTPTransport{
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
		},
		endpoint: cfg.HTTPEndpoint,
		token:    cfg.AuthToken,
		buffer:   make([]Event, 0, cfg.BatchSize),
		config:   cfg,
		done:     make(chan struct{}),
	}
	go t.flushLoop()
	return t
}

func (t *HTTPTransport) Send(event Event) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return fmt.Errorf("phantex: transport closed")
	}
	t.buffer = append(t.buffer, event)
	if len(t.buffer) >= t.config.BatchSize {
		return t.flushLocked()
	}
	return nil
}

func (t *HTTPTransport) Flush() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.flushLocked()
}

func (t *HTTPTransport) flushLocked() error {
	if len(t.buffer) == 0 {
		return nil
	}

	batch := make([]Event, len(t.buffer))
	copy(batch, t.buffer)
	t.buffer = t.buffer[:0]

	// Serialize as JSON Lines
	var buf bytes.Buffer
	for _, ev := range batch {
		b, err := ev.ToJSON()
		if err != nil {
			continue
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}

	req, err := http.NewRequest(http.MethodPost, t.endpoint, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	if t.token != "" {
		req.Header.Set("Authorization", "Bearer "+t.token)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		if t.config.Debug {
			log.Printf("phantex: http send failed: %v", err)
		}
		// Re-buffer on failure — caller already holds t.mu
		t.buffer = append(batch, t.buffer...)
		return err
	}
	resp.Body.Close()
	return nil
}

func (t *HTTPTransport) flushLoop() {
	ticker := time.NewTicker(time.Duration(t.config.BatchTimeout * float64(time.Second)))
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_ = t.Flush()
		case <-t.done:
			return
		}
	}
}

func (t *HTTPTransport) Close() error {
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
	close(t.done)
	_ = t.Flush()
	return nil
}

// ---------- Transport Factory ----------

// CreateTransport auto-selects the best transport based on config.
func CreateTransport(cfg *Config) Transport {
	switch cfg.Transport {
	case "buffer":
		return NewBufferTransport(cfg.BufferSize)
	case "grpc":
		t, err := NewGRPCTransport(cfg)
		if err != nil {
			if cfg.Debug {
				log.Printf("phantex: grpc transport failed, falling back to buffer: %v", err)
			}
			return NewBufferTransport(cfg.BufferSize)
		}
		return t
	case "http":
		return NewHTTPTransport(cfg)
	default: // "auto"
		// Try gRPC first, fall back to HTTP, then buffer
		t, err := NewGRPCTransport(cfg)
		if err == nil {
			return t
		}
		if cfg.Debug {
			log.Printf("phantex: grpc unavailable, trying http: %v", err)
		}
		return NewHTTPTransport(cfg)
	}
}
