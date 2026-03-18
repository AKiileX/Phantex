// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Package sdksocket provides a Unix domain socket listener that accepts
// NDJSON events from the Phantex Python SDK.
//
// The SDK sends ToolCallEvent / ToolResponseEvent as newline-delimited JSON
// to /var/run/phantex/sdk.sock. This package:
//   - Listens on the Unix socket and accepts connections
//   - Reads NDJSON lines from each connection
//   - Parses JSON into protobuf PhantexEvent
//   - Sends events to a channel where the sensor main loop picks them up
//
// Security:
//   - Socket permissions: 0660 (owner + group only — prevents unprivileged writes)
//   - Per-connection rate limit: 1000 events/sec (prevents SDK-level DoS)
//   - Max connections: configurable (default 50)
//   - Max line size: 64 KB (prevents memory exhaustion)
//   - PID extraction: SO_PEERCRED identifies which process sent the event
//   - Input validation: all fields validated before protobuf conversion
package sdksocket

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/AKiileX/Phantex/proto/gen/go/phantex/v1"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

const (
	// DefaultSocketPath is the default Unix socket path.
	DefaultSocketPath = "/var/run/phantex/sdk.sock"

	// DefaultMaxConns is the maximum concurrent SDK connections.
	DefaultMaxConns = 50

	// DefaultMaxLineSize is the maximum size of a single NDJSON line (64 KB).
	DefaultMaxLineSize = 64 * 1024

	// DefaultRateLimit is the max events per second per connection.
	DefaultRateLimit = 1000
)

// Config controls the SDK socket listener behavior.
type Config struct {
	// SocketPath is the Unix socket file path.
	SocketPath string

	// MaxConns is the maximum concurrent SDK connections.
	MaxConns int

	// MaxLineSize is the maximum size of a single NDJSON line in bytes.
	MaxLineSize int

	// RateLimit is the maximum events per second per connection.
	RateLimit int

	// SensorID and TenantID are injected into events that lack them.
	SensorID string
	TenantID string
}

// DefaultConfig returns a config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		SocketPath:  DefaultSocketPath,
		MaxConns:    DefaultMaxConns,
		MaxLineSize: DefaultMaxLineSize,
		RateLimit:   DefaultRateLimit,
	}
}

// Listener accepts Unix socket connections from the Phantex SDK and
// produces protobuf events on a channel.
type Listener struct {
	cfg     Config
	log     *zap.Logger
	ln      net.Listener
	events  chan *pb.PhantexEvent
	parser  *Parser
	connSem chan struct{} // semaphore for max connections
	wg      sync.WaitGroup
	running atomic.Bool

	// Stats
	EventsReceived atomic.Int64
	EventsDropped  atomic.Int64
	ConnsAccepted  atomic.Int64
	ParseErrors    atomic.Int64
}

// New creates a new SDK socket listener. The event channel is buffered (4096).
func New(cfg Config, log *zap.Logger) *Listener {
	if cfg.SocketPath == "" {
		cfg.SocketPath = DefaultSocketPath
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = DefaultMaxConns
	}
	if cfg.MaxLineSize <= 0 {
		cfg.MaxLineSize = DefaultMaxLineSize
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = DefaultRateLimit
	}

	return &Listener{
		cfg:     cfg,
		log:     log.Named("sdksocket"),
		events:  make(chan *pb.PhantexEvent, 4096),
		parser:  NewParser(cfg.SensorID, cfg.TenantID),
		connSem: make(chan struct{}, cfg.MaxConns),
	}
}

// Events returns the channel of parsed protobuf events.
// The sensor main loop reads from this channel.
func (l *Listener) Events() <-chan *pb.PhantexEvent {
	return l.events
}

// Run starts the Unix socket listener. It blocks until the context is
// cancelled or an unrecoverable error occurs.
func (l *Listener) Run(ctx context.Context) error {
	// Ensure the socket directory exists
	dir := filepath.Dir(l.cfg.SocketPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("create socket dir %s: %w", dir, err)
	}

	// Remove stale socket file (best-effort — WSL2 tmpfs may return
	// EROFS spuriously; if remove fails, net.Listen will clean up or fail)
	if err := os.Remove(l.cfg.SocketPath); err != nil && !os.IsNotExist(err) {
		l.log.Warn("could not remove stale socket, will try to listen anyway",
			zap.String("path", l.cfg.SocketPath), zap.Error(err))
	}

	// Listen on Unix socket
	ln, err := net.Listen("unix", l.cfg.SocketPath)
	if err != nil {
		// If listen fails because socket file exists, force-remove and retry once
		if os.Remove(l.cfg.SocketPath) == nil {
			ln, err = net.Listen("unix", l.cfg.SocketPath)
		}
		if err != nil {
			return fmt.Errorf("listen on %s: %w", l.cfg.SocketPath, err)
		}
	}
	l.ln = ln

	// Set socket permissions: owner + group read/write only
	if err := os.Chmod(l.cfg.SocketPath, 0660); err != nil {
		l.log.Warn("failed to set socket permissions", zap.Error(err))
	}

	l.running.Store(true)
	l.log.Info("SDK socket listening",
		zap.String("path", l.cfg.SocketPath),
		zap.Int("max_conns", l.cfg.MaxConns),
		zap.Int("rate_limit", l.cfg.RateLimit),
	)

	// Close listener on context cancellation
	go func() {
		<-ctx.Done()
		l.running.Store(false)
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if !l.running.Load() {
				break // Context cancelled — clean shutdown
			}
			l.log.Warn("accept error", zap.Error(err))
			continue
		}

		// Enforce max connections via semaphore
		select {
		case l.connSem <- struct{}{}:
			// Acquired connection slot
		default:
			l.log.Warn("max connections reached, rejecting SDK client")
			conn.Close()
			continue
		}

		l.ConnsAccepted.Add(1)
		l.wg.Add(1)
		go l.handleConn(ctx, conn)
	}

	// Wait for all connection handlers to finish
	l.wg.Wait()
	close(l.events)
	l.log.Info("SDK socket listener stopped",
		zap.Int64("events_received", l.EventsReceived.Load()),
		zap.Int64("parse_errors", l.ParseErrors.Load()),
	)
	return nil
}

// handleConn processes a single SDK connection.
func (l *Listener) handleConn(ctx context.Context, conn net.Conn) {
	defer func() {
		conn.Close()
		<-l.connSem // Release connection slot
		l.wg.Done()
	}()

	// Extract peer PID via SO_PEERCRED (Linux only)
	peerPID := l.getPeerPID(conn)
	l.log.Debug("SDK client connected",
		zap.Int("peer_pid", peerPID),
		zap.String("remote", conn.RemoteAddr().String()),
	)

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, l.cfg.MaxLineSize), l.cfg.MaxLineSize)

	// Rate limiter: token bucket (refills every 1/rate seconds)
	limiter := newTokenBucket(l.cfg.RateLimit)

	for {
		// Check context
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Set read deadline so we periodically check context
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))

		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue // Read timeout — check context and retry
				}
				l.log.Debug("SDK connection read error", zap.Error(err), zap.Int("peer_pid", peerPID))
			}
			return // EOF or error — connection closed
		}

		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		// Rate limit check
		if !limiter.allow() {
			l.EventsDropped.Add(1)
			l.log.Debug("SDK event rate-limited", zap.Int("peer_pid", peerPID))
			continue
		}

		// Parse JSON line → protobuf event
		evt, err := l.parser.Parse(line, uint32(peerPID))
		if err != nil {
			l.ParseErrors.Add(1)
			l.log.Debug("SDK event parse error",
				zap.Error(err),
				zap.Int("peer_pid", peerPID),
				zap.Int("line_size", len(line)),
			)
			continue
		}

		// Send to event channel (non-blocking — drop if full)
		select {
		case l.events <- evt:
			l.EventsReceived.Add(1)
		default:
			l.EventsDropped.Add(1)
		}
	}
}

// getPeerPID extracts the PID of the connecting process via SO_PEERCRED.
// Returns 0 if extraction fails (non-Linux or permission denied).
func (l *Listener) getPeerPID(conn net.Conn) int {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return 0
	}

	var pid int
	_ = raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err == nil {
			pid = int(cred.Pid)
		}
	})
	return pid
}

// Close stops the listener. Safe to call multiple times.
func (l *Listener) Close() error {
	l.running.Store(false)
	if l.ln != nil {
		return l.ln.Close()
	}
	return nil
}

// ── Token Bucket Rate Limiter ────────────────────────────────────────────────

type tokenBucket struct {
	tokens   int
	maxRate  int
	lastTime time.Time
	mu       sync.Mutex
}

func newTokenBucket(maxRate int) *tokenBucket {
	return &tokenBucket{
		tokens:   maxRate,
		maxRate:  maxRate,
		lastTime: time.Now(),
	}
}

func (tb *tokenBucket) allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastTime).Seconds()
	tb.lastTime = now

	// Refill tokens
	tb.tokens += int(elapsed * float64(tb.maxRate))
	if tb.tokens > tb.maxRate {
		tb.tokens = tb.maxRate
	}

	if tb.tokens > 0 {
		tb.tokens--
		return true
	}
	return false
}
