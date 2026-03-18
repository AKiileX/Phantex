// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Package platform defines the interface that each OS-specific event
// source must implement. The Linux sensor uses eBPF/ringbuf; the
// Windows sensor uses ETW + WFP. Both produce the same Event type
// consumed by the converter and transport layers.
//
// This abstraction allows the sensor binary to be built for either
// platform while sharing config, transport, converter, metrics, and TLS.
package platform

import (
	"context"
	"time"
)

// EventType mirrors ebpf.EventType but is platform-independent.
type EventType uint32

const (
	EventProcessExec    EventType = 0
	EventProcessExit    EventType = 1
	EventFileOpen       EventType = 10
	EventFileWrite      EventType = 11
	EventFileRead       EventType = 12
	EventFileDelete     EventType = 13 // Windows: registry + file delete
	EventNetworkConnect EventType = 20
	EventNetworkAccept  EventType = 21
	EventNetworkDNS     EventType = 22
	EventMemoryMap      EventType = 30
	EventRegistrySet    EventType = 50 // Windows-only
	EventRegistryCreate EventType = 51 // Windows-only
	EventRegistryDelete EventType = 52 // Windows-only
	EventImageLoad      EventType = 60 // Windows-only: DLL/EXE image load
)

// Event is the platform-independent event envelope.
type Event struct {
	Type        EventType
	TimestampNs uint64
	PID         uint32
	TID         uint32
	PPID        uint32
	UID         uint32 // Linux UID; on Windows mapped from SID/TokenUser
	Comm        string // Process name (max 260 chars on Windows)
	Payload     interface{}
}

// ── Payload types ─────────────────────────────────────────────────────────

// ProcessExecPayload for process creation events.
type ProcessExecPayload struct {
	Filename      string
	Argv          string
	ParentComm    string
	UserSID       string // Windows-only: full SID string
	SessionID     uint32 // Windows-only: terminal session
	ElevatedToken bool   // Windows-only: running as admin
}

// ProcessExitPayload for process termination events.
type ProcessExitPayload struct {
	ExitCode   int32
	DurationNs uint64
}

// FilePayload for file open/write/read/delete events.
type FilePayload struct {
	Filename  string
	Flags     int32
	ByteCount uint64
	FD        int32 // Linux fd; Windows handle (cast)
}

// NetworkPayload for TCP/UDP connection events.
type NetworkPayload struct {
	SrcAddr   string
	SrcPort   uint16
	DstAddr   string
	DstPort   uint16
	Protocol  uint8 // 6=TCP, 17=UDP
	IPVersion uint8 // 4 or 6
}

// DNSPayload for DNS query events.
type DNSPayload struct {
	QueryName    string
	QueryType    uint16
	DstAddr      string
	DstPort      uint16
	ResponseAddr string // Resolved IP (if available)
}

// RegistryPayload for Windows registry events.
type RegistryPayload struct {
	KeyPath   string
	ValueName string
	ValueType uint32
	ValueData string // Truncated to 1 KB
}

// ImageLoadPayload for DLL/EXE image load events (Windows).
type ImageLoadPayload struct {
	ImagePath  string
	ImageSize  uint64
	IsSigned   bool
	SignerName string
}

// MemoryPayload for memory map events.
type MemoryPayload struct {
	Addr   uint64
	Length uint64
	Prot   int32
	Flags  int32
}

// ── Provider interface ────────────────────────────────────────────────────

// Provider is the OS-specific event source. Each platform implements this.
type Provider interface {
	// Start begins collecting events. It blocks until ctx is cancelled.
	Start(ctx context.Context) error

	// Events returns the channel of platform events.
	Events() <-chan Event

	// Stats returns runtime statistics.
	Stats() ProviderStats

	// Close releases all resources.
	Close() error
}

// ProviderStats reports health metrics.
type ProviderStats struct {
	ProbesLoaded  int
	ProbesTotal   int
	EventsRead    uint64
	EventsDropped uint64
	StartedAt     time.Time
}
