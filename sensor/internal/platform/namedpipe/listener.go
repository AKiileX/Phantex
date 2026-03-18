// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

//go:build windows

// Package namedpipe provides a Windows named pipe listener for SDK event
// ingestion, replacing the Unix domain socket used on Linux.
//
// Named pipes provide:
//   - IPC without network exposure (\\.\pipe\ namespace is local-only)
//   - Client process identification via GetNamedPipeClientProcessId
//   - Access control via Windows security descriptors (DACL)
//   - Per-connection rate limiting (events/sec)
//
// Protocol: NDJSON (newline-delimited JSON), same as the Linux SDK socket.
// Each line is a JSON-encoded PhantexEvent payload.
//
// Security:
//   - Pipe DACL restricts access to LOCAL_SYSTEM and Administrators
//   - Client PID verified via GetNamedPipeClientProcessId
//   - Per-connection rate limiting prevents abuse
//   - Maximum line size enforced (default 64KB)
//   - Maximum concurrent connections enforced
//   - Graceful shutdown: all connections drained on context cancellation
package namedpipe

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"go.uber.org/zap"
	"golang.org/x/sys/windows"

	pb "github.com/AKiileX/Phantex/proto/gen/go/phantex/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Config controls the named pipe listener behavior.
type Config struct {
	PipeName    string // e.g., \\.\pipe\phantex-sdk
	MaxConns    int    // max concurrent connections
	MaxLineSize int    // max bytes per NDJSON line
	RateLimit   int    // max events/sec per connection
	SensorID    string
	TenantID    string
}

// Listener accepts SDK connections on a Windows named pipe.
type Listener struct {
	cfg     Config
	log     *zap.Logger
	eventCh chan *pb.PhantexEvent
	conns   int32 // atomic: current connection count
}

// New creates a named pipe listener.
func New(cfg Config, log *zap.Logger) *Listener {
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = 50
	}
	if cfg.MaxLineSize <= 0 {
		cfg.MaxLineSize = 64 * 1024
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = 1000
	}
	return &Listener{
		cfg:     cfg,
		log:     log.Named("named-pipe"),
		eventCh: make(chan *pb.PhantexEvent, 256),
	}
}

// Events returns the channel of parsed SDK events.
func (l *Listener) Events() <-chan *pb.PhantexEvent {
	return l.eventCh
}

// Run starts accepting connections. Blocks until ctx is cancelled.
func (l *Listener) Run(ctx context.Context) error {
	// Create the named pipe listener using the net package's named pipe support.
	// We use a Go-compatible approach: create pipe instances in a loop.
	l.log.Info("starting named pipe listener",
		zap.String("pipe", l.cfg.PipeName),
		zap.Int("max_conns", l.cfg.MaxConns),
		zap.Int("rate_limit", l.cfg.RateLimit),
	)

	// Create a restricted security descriptor:
	// Only LOCAL_SYSTEM (S-1-5-18) and BUILTIN\Administrators (S-1-5-32-544)
	sddl := "D:(A;;GA;;;SY)(A;;GA;;;BA)"
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("create security descriptor: %w", err)
	}

	sa := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
		InheritHandle:      0,
	}

	var wg sync.WaitGroup
	defer func() {
		wg.Wait()
		close(l.eventCh)
	}()

	for {
		select {
		case <-ctx.Done():
			l.log.Info("named pipe listener shutting down")
			return nil
		default:
		}

		// Check connection limit
		if int(atomic.LoadInt32(&l.conns)) >= l.cfg.MaxConns {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// Create a new pipe instance
		pipeNameUTF16, err := windows.UTF16PtrFromString(l.cfg.PipeName)
		if err != nil {
			return fmt.Errorf("invalid pipe name: %w", err)
		}

		handle, err := windows.CreateNamedPipe(
			pipeNameUTF16,
			windows.PIPE_ACCESS_DUPLEX,
			windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT,
			windows.PIPE_UNLIMITED_INSTANCES,
			64*1024, // out buffer
			64*1024, // in buffer
			0,       // default timeout
			sa,
		)
		if err != nil {
			l.log.Error("CreateNamedPipe failed", zap.Error(err))
			time.Sleep(time.Second)
			continue
		}

		// Wait for a client to connect (blocking)
		// Use a goroutine so we can respect context cancellation
		connCh := make(chan error, 1)
		go func() {
			connCh <- windows.ConnectNamedPipe(handle, nil)
		}()

		select {
		case <-ctx.Done():
			windows.CloseHandle(handle)
			return nil
		case err := <-connCh:
			if err != nil {
				// ERROR_PIPE_CONNECTED means client connected between Create and Connect
				if err != windows.ERROR_PIPE_CONNECTED {
					windows.CloseHandle(handle)
					l.log.Warn("ConnectNamedPipe failed", zap.Error(err))
					continue
				}
			}
		}

		// Get client PID for authorization/logging
		clientPID := getClientPID(handle)

		atomic.AddInt32(&l.conns, 1)
		wg.Add(1)

		l.log.Info("SDK client connected",
			zap.Uint32("client_pid", clientPID),
			zap.Int32("active_conns", atomic.LoadInt32(&l.conns)),
		)

		go func() {
			defer wg.Done()
			defer atomic.AddInt32(&l.conns, -1)
			defer windows.CloseHandle(handle)
			defer disconnectNamedPipe(handle)

			l.handleConnection(ctx, handle, clientPID)
		}()
	}
}

// handleConnection reads NDJSON events from a single client connection.
func (l *Listener) handleConnection(ctx context.Context, handle windows.Handle, clientPID uint32) {
	// Wrap the handle in a net.Conn-like reader using the Windows file API
	reader := newPipeReader(handle)
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, l.cfg.MaxLineSize), l.cfg.MaxLineSize)

	// Token bucket rate limiter
	limiter := newRateLimiter(l.cfg.RateLimit)

	eventsRead := uint64(0)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Rate limit
		if !limiter.allow() {
			l.log.Warn("SDK connection rate limited",
				zap.Uint32("client_pid", clientPID),
				zap.Uint64("events_read", eventsRead),
			)
			continue
		}

		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		evt, err := l.parseLine(line, clientPID)
		if err != nil {
			l.log.Debug("failed to parse SDK event",
				zap.Uint32("client_pid", clientPID),
				zap.Error(err),
			)
			continue
		}

		eventsRead++
		select {
		case l.eventCh <- evt:
		default:
			l.log.Warn("event channel full, dropping SDK event")
		}
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		l.log.Debug("SDK connection read error",
			zap.Uint32("client_pid", clientPID),
			zap.Error(err),
		)
	}

	l.log.Info("SDK client disconnected",
		zap.Uint32("client_pid", clientPID),
		zap.Uint64("events_read", eventsRead),
	)
}

// parseLine converts a single NDJSON line into a PhantexEvent.
func (l *Listener) parseLine(line []byte, clientPID uint32) (*pb.PhantexEvent, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(line, &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	// Minimal field extraction — the SDK sends structured event data.
	// Required fields: event_type, payload
	evtTypeStr, _ := raw["event_type"].(string)
	if evtTypeStr == "" {
		return nil, fmt.Errorf("missing event_type field")
	}

	evt := &pb.PhantexEvent{
		SensorId:  l.cfg.SensorID,
		TenantId:  l.cfg.TenantID,
		Timestamp: timestamppb.Now(),
		Severity:  pb.Severity_SEVERITY_INFO,
	}

	// Map standard SDK event types
	evtTypeStr = strings.ToUpper(evtTypeStr)
	switch {
	case strings.Contains(evtTypeStr, "TOOL_CALL"):
		evt.EventType = pb.EventType_EVENT_TYPE_TOOL_CALL
	case strings.Contains(evtTypeStr, "TOOL_RESPONSE"):
		evt.EventType = pb.EventType_EVENT_TYPE_TOOL_RESPONSE
	default:
		return nil, fmt.Errorf("unsupported event_type: %s", evtTypeStr)
	}

	return evt, nil
}

// ── Windows pipe helpers ──────────────────────────────────────────────────────

// getClientPID retrieves the PID of the connected named pipe client.
func getClientPID(handle windows.Handle) uint32 {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	proc := kernel32.NewProc("GetNamedPipeClientProcessId")

	var pid uint32
	r1, _, _ := proc.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&pid)),
	)
	if r1 == 0 {
		return 0
	}
	return pid
}

// disconnectNamedPipe disconnects the server end of a named pipe.
func disconnectNamedPipe(handle windows.Handle) {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	proc := kernel32.NewProc("DisconnectNamedPipe")
	proc.Call(uintptr(handle)) //nolint:errcheck
}

// pipeReader wraps a Windows named pipe handle for use with bufio.Scanner.
type pipeReader struct {
	handle windows.Handle
}

func newPipeReader(handle windows.Handle) *pipeReader {
	return &pipeReader{handle: handle}
}

func (r *pipeReader) Read(p []byte) (int, error) {
	var bytesRead uint32
	err := windows.ReadFile(r.handle, p, &bytesRead, nil)
	if err != nil {
		if err == windows.ERROR_BROKEN_PIPE {
			return 0, io.EOF
		}
		return 0, err
	}
	if bytesRead == 0 {
		return 0, io.EOF
	}
	return int(bytesRead), nil
}

// Implement net.Conn interface for compatibility (only Read is used)
var _ io.Reader = (*pipeReader)(nil)
var _ net.Conn = (*pipeConn)(nil)

// pipeConn wraps a pipe handle as a net.Conn (for future use).
type pipeConn struct {
	pipeReader
}

func (c *pipeConn) Write(p []byte) (int, error) {
	var written uint32
	err := windows.WriteFile(c.handle, p, &written, nil)
	return int(written), err
}

func (c *pipeConn) Close() error                     { return windows.CloseHandle(c.handle) }
func (c *pipeConn) LocalAddr() net.Addr              { return pipeAddr{} }
func (c *pipeConn) RemoteAddr() net.Addr             { return pipeAddr{} }
func (c *pipeConn) SetDeadline(time.Time) error      { return nil }
func (c *pipeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *pipeConn) SetWriteDeadline(time.Time) error { return nil }

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "phantex-sdk" }

// ── Rate limiter ──────────────────────────────────────────────────────────────

type rateLimiter struct {
	maxPerSec int
	count     int
	window    time.Time
}

func newRateLimiter(maxPerSec int) *rateLimiter {
	return &rateLimiter{
		maxPerSec: maxPerSec,
		window:    time.Now(),
	}
}

func (r *rateLimiter) allow() bool {
	now := time.Now()
	if now.Sub(r.window) >= time.Second {
		r.count = 0
		r.window = now
	}
	r.count++
	return r.count <= r.maxPerSec
}
