// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Package ebpf — reader.go
//
// Reads events from the BPF ring buffer, parses the common header,
// then dispatches to type-specific parsing. Parsed events are sent
// to a channel for downstream consumption (enricher → transport).
package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"
	"go.uber.org/zap"
)

// Event is a parsed eBPF event with its typed payload.
type Event struct {
	Header  EventHeader
	Type    EventType
	Payload interface{} // one of: *ExecEvent, *FileOpenEvent, *NetConnectEvent, etc.
}

// Reader reads events from the BPF ring buffer and sends parsed Events
// to the output channel.
type Reader struct {
	log     *zap.Logger
	ring    *ringbuf.Reader
	eventCh chan Event
	stats   ReaderStats
}

// ReaderStats tracks reader metrics.
type ReaderStats struct {
	EventsRead  uint64
	ParseErrors uint64
	RingDrops   uint64
}

// NewReader creates a ring buffer reader.
// bufSize controls the Go-side channel buffer (not the kernel ring buffer).
func NewReader(log *zap.Logger, eventsMap *ringbuf.Reader, chanSize int) *Reader {
	if chanSize <= 0 {
		chanSize = 4096
	}
	return &Reader{
		log:     log,
		ring:    eventsMap,
		eventCh: make(chan Event, chanSize),
	}
}

// NewReaderFromMap creates a ringbuf.Reader from an *ebpf.Map and wraps it.
func NewReaderFromMap(log *zap.Logger, m interface{ FD() int }, chanSize int) (*Reader, error) {
	// cilium/ebpf ringbuf.NewReader expects *ebpf.Map
	// We'll create it outside and pass the ringbuf.Reader in.
	return nil, fmt.Errorf("use NewReader with a pre-created ringbuf.Reader")
}

// Events returns the channel of parsed events.
func (r *Reader) Events() <-chan Event {
	return r.eventCh
}

// Stats returns current reader statistics.
func (r *Reader) Stats() ReaderStats {
	return r.stats
}

// Run starts reading from the ring buffer until ctx is cancelled.
// This should be called in a goroutine.
func (r *Reader) Run(ctx context.Context) {
	defer close(r.eventCh)

	r.log.Info("ring buffer reader started")

	for {
		select {
		case <-ctx.Done():
			r.log.Info("ring buffer reader shutting down",
				zap.Uint64("events_read", r.stats.EventsRead),
				zap.Uint64("parse_errors", r.stats.ParseErrors))
			return
		default:
		}

		record, err := r.ring.Read()
		if err != nil {
			if ctx.Err() != nil {
				return // context cancelled during blocking read
			}
			r.log.Warn("ring buffer read error", zap.Error(err))
			r.stats.RingDrops++
			continue
		}

		evt, err := r.parseRecord(record.RawSample)
		if err != nil {
			r.stats.ParseErrors++
			r.log.Debug("event parse error",
				zap.Error(err),
				zap.Int("raw_len", len(record.RawSample)))
			continue
		}

		r.stats.EventsRead++

		// Non-blocking send — drop if channel is full (backpressure)
		select {
		case r.eventCh <- *evt:
		default:
			r.stats.RingDrops++
		}
	}
}

// Close closes the ring buffer reader.
func (r *Reader) Close() error {
	return r.ring.Close()
}

// ─── Event Parsing ────────────────────────────────────────────────────────────

// parseRecord parses raw ring buffer bytes into a typed Event.
func (r *Reader) parseRecord(raw []byte) (*Event, error) {
	if len(raw) < int(unsafe.Sizeof(EventHeader{})) {
		return nil, fmt.Errorf("record too short: %d bytes (need >= %d)",
			len(raw), unsafe.Sizeof(EventHeader{}))
	}

	// Parse the common header first
	var hdr EventHeader
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &hdr); err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}

	evt := &Event{
		Header: hdr,
		Type:   EventType(hdr.EventType),
	}

	// Parse the full event based on type
	switch EventType(hdr.EventType) {
	case EventProcessExec:
		var e ExecEvent
		if err := readStruct(raw, &e); err != nil {
			return nil, fmt.Errorf("parse exec event: %w", err)
		}
		evt.Payload = &e

	case EventProcessExit:
		var e ExitEvent
		if err := readStruct(raw, &e); err != nil {
			return nil, fmt.Errorf("parse exit event: %w", err)
		}
		evt.Payload = &e

	case EventFileOpen:
		var e FileOpenEvent
		if err := readStruct(raw, &e); err != nil {
			return nil, fmt.Errorf("parse file_open event: %w", err)
		}
		evt.Payload = &e

	case EventFileWrite:
		var e FileWriteEvent
		if err := readStruct(raw, &e); err != nil {
			return nil, fmt.Errorf("parse file_write event: %w", err)
		}
		evt.Payload = &e

	case EventFileRead:
		var e FileReadEvent
		if err := readStruct(raw, &e); err != nil {
			return nil, fmt.Errorf("parse file_read event: %w", err)
		}
		evt.Payload = &e

	case EventNetworkConnect:
		var e NetConnectEvent
		if err := readStruct(raw, &e); err != nil {
			return nil, fmt.Errorf("parse net_connect event: %w", err)
		}
		evt.Payload = &e

	case EventNetworkAccept:
		var e NetAcceptEvent
		if err := readStruct(raw, &e); err != nil {
			return nil, fmt.Errorf("parse net_accept event: %w", err)
		}
		evt.Payload = &e

	case EventNetworkDNS:
		var e DNSEvent
		if err := readStruct(raw, &e); err != nil {
			return nil, fmt.Errorf("parse dns event: %w", err)
		}
		evt.Payload = &e

	case EventMemoryMap:
		var e MmapEvent
		if err := readStruct(raw, &e); err != nil {
			return nil, fmt.Errorf("parse mmap event: %w", err)
		}
		evt.Payload = &e

	default:
		return nil, fmt.Errorf("unknown event type: %d", hdr.EventType)
	}

	return evt, nil
}

// readStruct reads binary data into a struct using little-endian byte order.
func readStruct(data []byte, v interface{}) error {
	return binary.Read(bytes.NewReader(data), binary.LittleEndian, v)
}
