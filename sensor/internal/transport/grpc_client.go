// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Package transport provides a gRPC streaming client for sending events
// to the Phantex gateway.
//
// Block A2 shipped a stub (logFlush). Block B2 adds a real gRPC stream
// with batching, backpressure, reconnect with exponential backoff, and
// auth token injection.
package transport

import (
	"context"
	"crypto/tls"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/AKiileX/Phantex/proto/gen/go/phantex/v1"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Client sends protobuf events to the gateway via gRPC streaming.
type Client struct {
	log         *zap.Logger
	gatewayAddr string
	authToken   string
	sensorID    string
	tenantID    string
	version     string

	// Batching
	mu       sync.Mutex
	batch    []*pb.PhantexEvent
	batchCap int

	// Buffer for events when disconnected (up to 10,000)
	bufMu   sync.Mutex
	buffer  []*pb.PhantexEvent
	bufCap  int
	dropped atomic.Int64

	// gRPC connection
	conn   *grpc.ClientConn
	stream pb.SensorService_IngestEventsClient

	// TLS (nil = plaintext)
	tlsConfig *tls.Config

	// Command handler (set by sensor main to execute response actions)
	commandHandler func(cmd *pb.ControlCommand)

	// Metrics provider (set by sensor main to collect health metrics for heartbeats)
	metricsProvider func() *pb.SensorMetrics

	// Stats
	EventsSent  atomic.Int64
	BatchesSent atomic.Int64
	Errors      atomic.Int64
	batchSeq    atomic.Uint64

	// Flags
	connected atomic.Bool
}

// ClientConfig holds transport client configuration.
type ClientConfig struct {
	GatewayAddr string
	AuthToken   string
	SensorID    string
	TenantID    string
	BatchSize   int
	BufferSize  int    // max events to buffer when disconnected (default 10000)
	Version     string // sensor binary version (sent during registration)

	// TLS settings (nil = plaintext / insecure)
	TLSConfig *tls.Config
}

// NewClient creates a gRPC transport client.
func NewClient(cfg ClientConfig, log *zap.Logger) *Client {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 10000
	}
	return &Client{
		log:         log.Named("transport"),
		gatewayAddr: cfg.GatewayAddr,
		authToken:   cfg.AuthToken,
		sensorID:    cfg.SensorID,
		tenantID:    cfg.TenantID,
		version:     cfg.Version,
		batchCap:    cfg.BatchSize,
		batch:       make([]*pb.PhantexEvent, 0, cfg.BatchSize),
		buffer:      make([]*pb.PhantexEvent, 0, cfg.BufferSize),
		bufCap:      cfg.BufferSize,
		tlsConfig:   cfg.TLSConfig,
	}
}

// Send enqueues an event. When the batch is full, it's flushed over gRPC.
// If disconnected, events are buffered (up to bufCap; oldest dropped if full).
func (c *Client) Send(evt *pb.PhantexEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.batch = append(c.batch, evt)
	if len(c.batch) >= c.batchCap {
		c.flushLocked()
	}
}

// Flush sends any buffered events immediately.
func (c *Client) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.flushLocked()
}

func (c *Client) flushLocked() {
	if len(c.batch) == 0 {
		return
	}

	events := make([]*pb.PhantexEvent, len(c.batch))
	copy(events, c.batch)
	c.batch = c.batch[:0]

	if c.connected.Load() && c.stream != nil {
		c.sendBatch(events)
	} else {
		c.bufferEvents(events)
	}
}

// sendBatch sends a batch over the active gRPC stream.
func (c *Client) sendBatch(events []*pb.PhantexEvent) {
	seq := c.batchSeq.Add(1)
	req := &pb.IngestEventsRequest{
		BatchId:       seq,
		SensorId:      c.sensorID,
		TenantId:      c.tenantID,
		Events:        events,
		EventsDropped: uint64(c.dropped.Swap(0)),
	}

	if err := c.stream.Send(req); err != nil {
		c.log.Warn("send batch failed — buffering events",
			zap.Uint64("batch_id", seq),
			zap.Int("events", len(events)),
			zap.Error(err))
		c.Errors.Add(1)
		c.connected.Store(false)
		c.bufferEvents(events)
		return
	}

	c.EventsSent.Add(int64(len(events)))
	c.BatchesSent.Add(1)
}

// bufferEvents stores events for later delivery (when reconnected).
func (c *Client) bufferEvents(events []*pb.PhantexEvent) {
	c.bufMu.Lock()
	defer c.bufMu.Unlock()

	space := c.bufCap - len(c.buffer)
	if space <= 0 {
		// Drop oldest events to make room
		drop := len(events)
		if drop > len(c.buffer) {
			drop = len(c.buffer)
		}
		c.buffer = c.buffer[drop:]
		c.dropped.Add(int64(drop))
		c.log.Warn("buffer full — dropping oldest events",
			zap.Int("dropped", drop),
			zap.Int64("total_dropped", c.dropped.Load()))
	}

	c.buffer = append(c.buffer, events...)
	// Trim to cap
	if len(c.buffer) > c.bufCap {
		excess := len(c.buffer) - c.bufCap
		c.buffer = c.buffer[excess:]
		c.dropped.Add(int64(excess))
	}
}

// drainBuffer sends any buffered events after reconnecting.
func (c *Client) drainBuffer() {
	c.bufMu.Lock()
	if len(c.buffer) == 0 {
		c.bufMu.Unlock()
		return
	}

	events := make([]*pb.PhantexEvent, len(c.buffer))
	copy(events, c.buffer)
	c.buffer = c.buffer[:0]
	c.bufMu.Unlock()

	c.log.Info("draining buffered events after reconnect",
		zap.Int("events", len(events)))

	// Send in batch-sized chunks.
	// Acquire c.mu to serialize with the periodic flush goroutine —
	// gRPC stream.Send is NOT safe for concurrent use.
	for i := 0; i < len(events); i += c.batchCap {
		end := i + c.batchCap
		if end > len(events) {
			end = len(events)
		}
		c.mu.Lock()
		c.sendBatch(events[i:end])
		c.mu.Unlock()
	}
}

// Run starts the connection loop and periodic flush. Call in a goroutine.
// It connects to the gateway, maintains the stream, and reconnects with
// exponential backoff on failure.
func (c *Client) Run(ctx context.Context, flushInterval time.Duration) {
	// Periodic flush goroutine
	go func() {
		ticker := time.NewTicker(flushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				c.Flush()
				return
			case <-ticker.C:
				c.Flush()
			}
		}
	}()

	// Connection loop with exponential backoff
	backoff := time.Second
	maxBackoff := 60 * time.Second

	for {
		select {
		case <-ctx.Done():
			c.mu.Lock()
			c.closeStreamLocked()
			c.mu.Unlock()
			return
		default:
		}

		if err := c.connect(ctx); err != nil {
			c.log.Warn("gateway connection failed",
				zap.String("addr", c.gatewayAddr),
				zap.Duration("retry_in", backoff),
				zap.Error(err))

			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}

			// Exponential backoff: 1s, 2s, 4s, 8s, ... max 60s
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		// Connected — reset backoff
		backoff = time.Second
		c.connected.Store(true)

		c.log.Debug("connected to gateway",
			zap.String("addr", c.gatewayAddr))

		// Register sensor with metadata (hostname, kernel, arch, version)
		c.registerSensor(ctx)

		// Drain any buffered events
		c.drainBuffer()

		// Read acks in background until stream breaks
		c.readAcks(ctx)

		// If we get here, stream broke — will retry
		c.connected.Store(false)
		c.log.Debug("gateway stream reconnecting")
	}
}

// connect establishes the gRPC connection and opens the bidirectional stream.
func (c *Client) connect(ctx context.Context) error {
	// Close any existing connection
	c.mu.Lock()
	c.closeStreamLocked()
	c.mu.Unlock()

	// Dial the gateway
	var transportCreds grpc.DialOption
	if c.tlsConfig != nil {
		transportCreds = grpc.WithTransportCredentials(credentials.NewTLS(c.tlsConfig))
	} else {
		transportCreds = grpc.WithTransportCredentials(insecure.NewCredentials())
	}
	opts := []grpc.DialOption{
		transportCreds,
		grpc.WithBlock(), //nolint:staticcheck // needed for blocking dial with timeout
	}

	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(dialCtx, c.gatewayAddr, opts...) //nolint:staticcheck
	if err != nil {
		return err
	}

	// Create the streaming client with auth metadata
	md := metadata.New(map[string]string{
		"authorization": "Bearer " + c.authToken,
	})
	streamCtx := metadata.NewOutgoingContext(ctx, md)

	client := pb.NewSensorServiceClient(conn)
	stream, err := client.IngestEvents(streamCtx)
	if err != nil {
		conn.Close()
		return err
	}

	// Store conn/stream under lock — flushLocked reads c.stream under c.mu
	c.mu.Lock()
	c.conn = conn
	c.stream = stream
	c.mu.Unlock()

	return nil
}

// registerSensor sends a one-time RegisterSensor RPC to the gateway so
// the backend can persist hostname, kernel, arch, version, and IP.
func (c *Client) registerSensor(ctx context.Context) {
	hostname, _ := os.Hostname()

	var kernel string
	var utsname unix.Utsname
	if err := unix.Uname(&utsname); err == nil {
		kernel = unix.ByteSliceToString(utsname.Release[:])
	}

	md := metadata.New(map[string]string{
		"authorization": "Bearer " + c.authToken,
	})
	regCtx, cancel := context.WithTimeout(
		metadata.NewOutgoingContext(ctx, md), 10*time.Second,
	)
	defer cancel()

	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return
	}

	client := pb.NewSensorServiceClient(conn)
	resp, err := client.RegisterSensor(regCtx, &pb.RegisterSensorRequest{
		SensorId: c.sensorID,
		TenantId: c.tenantID,
		Version:  c.version,
		Hostname: hostname,
		Kernel:   kernel,
		Arch:     runtime.GOARCH,
	})
	if err != nil {
		c.log.Warn("sensor registration failed", zap.Error(err))
		return
	}
	if !resp.Accepted {
		c.log.Warn("sensor registration rejected",
			zap.String("reason", resp.RejectReason))
		return
	}
	c.log.Info("sensor registered with gateway",
		zap.String("hostname", hostname),
		zap.String("kernel", kernel),
		zap.String("arch", runtime.GOARCH),
		zap.String("version", c.version))
}

// readAcks reads IngestEventsResponse messages from the gateway.
// Blocks until the stream is closed or an error occurs.
func (c *Client) readAcks(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Grab stream reference under lock to avoid racing with closeStream.
		c.mu.Lock()
		s := c.stream
		c.mu.Unlock()
		if s == nil {
			return
		}

		ack, err := s.Recv()
		if err != nil {
			if ctx.Err() != nil {
				return // context cancelled
			}
			// DeadlineExceeded is the normal idle-timeout cycle — not an error
			if isDeadlineExceeded(err) {
				c.log.Debug("ack stream idle timeout (normal)", zap.Error(err))
			} else {
				c.log.Warn("ack stream error", zap.Error(err))
			}
			return
		}

		if !ack.Accepted {
			c.log.Warn("batch rejected by gateway",
				zap.Uint64("batch_id", ack.BatchId),
				zap.String("reason", ack.RejectReason))
			c.Errors.Add(1)
		}
	}
}

// closeStreamLocked cleans up the gRPC connection. Must be called with c.mu held.
func (c *Client) closeStreamLocked() {
	if c.stream != nil {
		c.stream.CloseSend() //nolint:errcheck
		c.stream = nil
	}
	if c.conn != nil {
		c.conn.Close() //nolint:errcheck
		c.conn = nil
	}
}

// isDeadlineExceeded returns true if err is a gRPC DeadlineExceeded status.
func isDeadlineExceeded(err error) bool {
	if s, ok := status.FromError(err); ok {
		return s.Code() == codes.DeadlineExceeded
	}
	return false
}

// Close performs final cleanup.
func (c *Client) Close() error {
	c.Flush()

	c.mu.Lock()
	c.closeStreamLocked()
	c.mu.Unlock()

	c.log.Info("transport client closed",
		zap.Int64("total_events_sent", c.EventsSent.Load()),
		zap.Int64("total_batches", c.BatchesSent.Load()),
		zap.Int64("errors", c.Errors.Load()),
		zap.Int64("dropped", c.dropped.Load()),
	)
	return nil
}

// Stats returns transport statistics.
type Stats struct {
	EventsSent  int64
	BatchesSent int64
	Errors      int64
	Dropped     int64
	Connected   bool
	BufferLen   int
}

// GetStats returns current transport statistics.
func (c *Client) GetStats() Stats {
	c.bufMu.Lock()
	bufLen := len(c.buffer)
	c.bufMu.Unlock()

	return Stats{
		EventsSent:  c.EventsSent.Load(),
		BatchesSent: c.BatchesSent.Load(),
		Errors:      c.Errors.Load(),
		Dropped:     c.dropped.Load(),
		Connected:   c.connected.Load(),
		BufferLen:   bufLen,
	}
}

// SetCommandHandler sets the callback for executing response action commands
// received from the gateway via heartbeat. Must be called before Run().
func (c *Client) SetCommandHandler(handler func(cmd *pb.ControlCommand)) {
	c.commandHandler = handler
}

// SetMetricsProvider sets the callback for collecting sensor health metrics
// to include in heartbeat requests. Must be called before RunHeartbeat().
func (c *Client) SetMetricsProvider(provider func() *pb.SensorMetrics) {
	c.metricsProvider = provider
}

// RunHeartbeat starts a periodic heartbeat loop that also receives
// response action commands from the gateway. Blocks until ctx is cancelled.
func (c *Client) RunHeartbeat(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !c.connected.Load() {
				continue
			}

			c.mu.Lock()
			conn := c.conn
			c.mu.Unlock()
			if conn == nil {
				continue
			}

			// Create a separate client on the same connection for heartbeat
			client := pb.NewSensorServiceClient(conn)
			md := metadata.New(map[string]string{
				"authorization": "Bearer " + c.authToken,
			})
			hbCtx, cancel := context.WithTimeout(
				metadata.NewOutgoingContext(ctx, md),
				10*time.Second,
			)

			resp, err := client.Heartbeat(hbCtx, &pb.HeartbeatRequest{
				SensorId: c.sensorID,
				Metrics:  c.collectMetrics(),
			})
			cancel()

			if err != nil {
				c.log.Debug("heartbeat failed", zap.Error(err))
				continue
			}

			// Process any commands from the gateway
			if len(resp.Commands) > 0 && c.commandHandler != nil {
				c.log.Info("received commands from gateway",
					zap.Int("count", len(resp.Commands)))
				for _, cmd := range resp.Commands {
					go c.commandHandler(cmd)
				}
			}
		}
	}
}

// collectMetrics calls the metrics provider if set, otherwise returns
// basic transport stats as a SensorMetrics proto.
func (c *Client) collectMetrics() *pb.SensorMetrics {
	if c.metricsProvider != nil {
		return c.metricsProvider()
	}
	// Fallback: report transport-level stats only
	return &pb.SensorMetrics{
		EventsSent:    uint64(c.EventsSent.Load()),
		EventsDropped: uint64(c.dropped.Load()),
	}
}
