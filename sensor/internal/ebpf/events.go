// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Package ebpf provides the Go-side representation of eBPF events emitted
// by the Phantex kernel probes. These structs mirror the C structs defined in
// sensor/ebpf/include/events.h and must be kept in sync.
//
// IMPORTANT: Field order, sizes, and padding must match the C definitions exactly.
// The ring buffer delivers raw bytes that are unsafely cast into these structs.
package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// ─── Event Type Constants ─────────────────────────────────────────────────────
// Mirror enum ph_event_type in events.h

type EventType uint32

const (
	EventProcessExec    EventType = 0
	EventProcessExit    EventType = 1
	EventFileOpen       EventType = 10
	EventFileWrite      EventType = 11
	EventFileRead       EventType = 12
	EventNetworkConnect EventType = 20
	EventNetworkAccept  EventType = 21
	EventNetworkDNS     EventType = 22
	EventMemoryMap      EventType = 30
)

func (t EventType) String() string {
	switch t {
	case EventProcessExec:
		return "PROCESS_EXEC"
	case EventProcessExit:
		return "PROCESS_EXIT"
	case EventFileOpen:
		return "FILE_OPEN"
	case EventFileWrite:
		return "FILE_WRITE"
	case EventFileRead:
		return "FILE_READ"
	case EventNetworkConnect:
		return "NETWORK_CONNECT"
	case EventNetworkAccept:
		return "NETWORK_ACCEPT"
	case EventNetworkDNS:
		return "NETWORK_DNS"
	case EventMemoryMap:
		return "MEMORY_MAP"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}

// ─── Size Constants ───────────────────────────────────────────────────────────
// Must match #define values in events.h

const (
	TaskCommLen = 16
	MaxFilename = 256
	MaxArgvLen  = 256
	MaxDNSName  = 128
)

// ─── Common Event Header ──────────────────────────────────────────────────────
// Mirrors struct ph_event_hdr (48 bytes).
// Every event starts with this header.

type EventHeader struct {
	TimestampNs uint64
	EventType   uint32
	PID         uint32
	TID         uint32
	UID         uint32
	PPID        uint32
	Pad         uint32
	Comm        [TaskCommLen]byte
}

// CommString returns the process name as a Go string (null-trimmed).
func (h *EventHeader) CommString() string {
	return nullTermString(h.Comm[:])
}

// ─── Process Execution Event ──────────────────────────────────────────────────
// Mirrors struct ph_exec_event

type ExecEvent struct {
	Hdr      EventHeader
	Filename [MaxFilename]byte
	Argv     [MaxArgvLen]byte
	Retcode  int32
	IsExit   uint8
	Pad      [3]byte
}

func (e *ExecEvent) FilenameString() string { return nullTermString(e.Filename[:]) }
func (e *ExecEvent) ArgvString() string     { return nullTermString(e.Argv[:]) }

// ─── Process Exit Event ───────────────────────────────────────────────────────
// Mirrors struct ph_exit_event

type ExitEvent struct {
	Hdr        EventHeader
	ExitCode   int32
	Signal     uint32
	DurationNs uint64
}

// ─── File Open Event ──────────────────────────────────────────────────────────
// Mirrors struct ph_file_open_event

type FileOpenEvent struct {
	Hdr      EventHeader
	Filename [MaxFilename]byte
	Flags    int32
	Retcode  int32
}

func (e *FileOpenEvent) FilenameString() string { return nullTermString(e.Filename[:]) }

// ─── File Write Event ─────────────────────────────────────────────────────────
// Mirrors struct ph_file_write_event

type FileWriteEvent struct {
	Hdr       EventHeader
	FD        int32
	ByteCount uint64
	Retcode   int32
	Pad       uint32
}

// ─── File Read Event ──────────────────────────────────────────────────────────
// Mirrors struct ph_file_read_event

type FileReadEvent struct {
	Hdr       EventHeader
	FD        int32
	ByteCount uint64
	Retcode   int32
	Pad       uint32
}

// ─── Network Connect Event ────────────────────────────────────────────────────
// Mirrors struct ph_net_connect_event

type NetConnectEvent struct {
	Hdr       EventHeader
	SrcAddr   uint32
	DstAddr   uint32
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	IPVersion uint8
	Pad       [2]byte
	SrcAddr6  [16]byte
	DstAddr6  [16]byte
}

// SrcIP returns the source IP as net.IP (handles v4 and v6).
func (e *NetConnectEvent) SrcIP() net.IP {
	if e.IPVersion == 6 {
		return net.IP(e.SrcAddr6[:])
	}
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, e.SrcAddr)
	return ip
}

// DstIP returns the destination IP as net.IP.
func (e *NetConnectEvent) DstIP() net.IP {
	if e.IPVersion == 6 {
		return net.IP(e.DstAddr6[:])
	}
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, e.DstAddr)
	return ip
}

// ─── Network Accept Event ─────────────────────────────────────────────────────
// Mirrors struct ph_net_accept_event (same layout as connect)

type NetAcceptEvent struct {
	Hdr       EventHeader
	SrcAddr   uint32
	DstAddr   uint32
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	IPVersion uint8
	Pad       [2]byte
	SrcAddr6  [16]byte
	DstAddr6  [16]byte
}

func (e *NetAcceptEvent) SrcIP() net.IP {
	if e.IPVersion == 6 {
		return net.IP(e.SrcAddr6[:])
	}
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, e.SrcAddr)
	return ip
}

func (e *NetAcceptEvent) DstIP() net.IP {
	if e.IPVersion == 6 {
		return net.IP(e.DstAddr6[:])
	}
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, e.DstAddr)
	return ip
}

// ─── DNS Event ────────────────────────────────────────────────────────────────
// Mirrors struct ph_dns_event

type DNSEvent struct {
	Hdr       EventHeader
	QueryName [MaxDNSName]byte
	QueryType uint16
	DstPort   uint16
	DstAddr   uint32
}

func (e *DNSEvent) QueryNameString() string {
	// Detect raw DNS wire format (from dns_lite probe): first byte is a
	// label length (1-63), not a printable ASCII char.  Parsed names from
	// the full dns probe start with a printable letter/digit.
	if len(e.QueryName) > 0 && e.QueryName[0] > 0 && e.QueryName[0] <= 63 {
		// Check if this looks like wire format (first byte is a small length)
		first := e.QueryName[0]
		if first < 0x20 { // Control char range → wire format
			return parseDNSWireFormat(e.QueryName[:])
		}
	}
	return nullTermString(e.QueryName[:])
}

// parseDNSWireFormat converts DNS wire-format labels to a dotted name.
// Wire format: \x03www\x06google\x03com\x00 → "www.google.com"
func parseDNSWireFormat(raw []byte) string {
	var result []byte
	i := 0
	for i < len(raw) {
		labelLen := int(raw[i])
		if labelLen == 0 {
			break
		}
		if labelLen > 63 || i+1+labelLen > len(raw) {
			break
		}
		if len(result) > 0 {
			result = append(result, '.')
		}
		result = append(result, raw[i+1:i+1+labelLen]...)
		i += 1 + labelLen
	}
	return string(result)
}

// ─── Memory Map Event ─────────────────────────────────────────────────────────
// Mirrors struct ph_mmap_event

type MmapEvent struct {
	Hdr    EventHeader
	Addr   uint64
	Length uint64
	Prot   uint32
	Flags  uint32
}

// ProtString returns a human-readable protection flags string (e.g., "r-x").
func (e *MmapEvent) ProtString() string {
	var s strings.Builder
	if e.Prot&0x1 != 0 {
		s.WriteByte('r')
	} else {
		s.WriteByte('-')
	}
	if e.Prot&0x2 != 0 {
		s.WriteByte('w')
	} else {
		s.WriteByte('-')
	}
	if e.Prot&0x4 != 0 {
		s.WriteByte('x')
	} else {
		s.WriteByte('-')
	}
	return s.String()
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// nullTermString converts a null-terminated byte slice to a Go string.
func nullTermString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
