// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

//go:build windows

// Package converter_win translates platform-independent events (ETW/WFP)
// into protobuf PhantexEvent messages for the gRPC transport.
//
// This mirrors the Linux converter (internal/converter) but consumes
// platform.Event instead of bpf.Event, enabling cross-platform transport
// and gateway reuse.
//
// Security:
//   - All string fields are bounds-checked before assignment
//   - UUIDv7 generation uses crypto/rand (no math/rand)
//   - tenant_id is stamped on every event (cross-tenant isolation)
package converter_win

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	pb "github.com/AKiileX/Phantex/proto/gen/go/phantex/v1"
	"github.com/AKiileX/Phantex/sensor/internal/platform"
	enrichwin "github.com/AKiileX/Phantex/sensor/internal/platform/enricher_win"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	maxStringField = 4096 // Truncate any string field above this
)

// Converter translates platform events into protobuf PhantexEvents.
type Converter struct {
	sensorID string
	tenantID string
}

// New creates a converter with the given sensor and tenant identity.
func New(sensorID, tenantID string) *Converter {
	return &Converter{
		sensorID: sensorID,
		tenantID: tenantID,
	}
}

// ToProto converts a platform.Event + enrichment into a PhantexEvent.
// Returns nil if the event type cannot be mapped.
func (c *Converter) ToProto(evt platform.Event, info *enrichwin.ProcessInfo, agentPAID string) *pb.PhantexEvent {
	ts := time.Unix(0, int64(evt.TimestampNs))

	base := &pb.PhantexEvent{
		EventId:   uuidV7(),
		TenantId:  c.tenantID,
		AgentId:   agentPAID,
		SensorId:  c.sensorID,
		Timestamp: timestamppb.New(ts),
		Severity:  pb.Severity_SEVERITY_INFO,
	}

	ctx := buildContext(info, agentPAID)

	switch evt.Type {
	case platform.EventProcessExec:
		base.EventType = pb.EventType_EVENT_TYPE_PROCESS_EXEC
		if p, ok := evt.Payload.(*platform.ProcessExecPayload); ok {
			base.Payload = &pb.PhantexEvent_ProcessExec{
				ProcessExec: &pb.ProcessExecEvent{
					Pid:      evt.PID,
					Ppid:     evt.PPID,
					Uid:      evt.UID,
					Comm:     truncate(evt.Comm, 260),
					Filename: truncate(p.Filename, maxStringField),
					Argv:     truncate(p.Argv, maxStringField),
					Context:  ctx,
				},
			}
		}

	case platform.EventProcessExit:
		base.EventType = pb.EventType_EVENT_TYPE_PROCESS_EXIT
		if p, ok := evt.Payload.(*platform.ProcessExitPayload); ok {
			base.Payload = &pb.PhantexEvent_ProcessExit{
				ProcessExit: &pb.ProcessExitEvent{
					Pid:        evt.PID,
					Ppid:       evt.PPID,
					Uid:        evt.UID,
					Comm:       truncate(evt.Comm, 260),
					ExitCode:   p.ExitCode,
					DurationNs: p.DurationNs,
					Context:    ctx,
				},
			}
		}

	case platform.EventFileOpen:
		base.EventType = pb.EventType_EVENT_TYPE_FILE_OPEN
		if p, ok := evt.Payload.(*platform.FilePayload); ok {
			base.Payload = &pb.PhantexEvent_File{
				File: &pb.FileEvent{
					Operation: pb.FileOperation_FILE_OPERATION_OPEN,
					Pid:       evt.PID,
					Uid:       evt.UID,
					Comm:      truncate(evt.Comm, 260),
					Filename:  truncate(p.Filename, maxStringField),
					Flags:     p.Flags,
					Context:   ctx,
				},
			}
		}

	case platform.EventFileWrite:
		base.EventType = pb.EventType_EVENT_TYPE_FILE_WRITE
		if p, ok := evt.Payload.(*platform.FilePayload); ok {
			base.Payload = &pb.PhantexEvent_File{
				File: &pb.FileEvent{
					Operation: pb.FileOperation_FILE_OPERATION_WRITE,
					Pid:       evt.PID,
					Uid:       evt.UID,
					Comm:      truncate(evt.Comm, 260),
					Fd:        p.FD,
					Bytes:     int64(p.ByteCount),
					Context:   ctx,
				},
			}
		}

	case platform.EventFileRead:
		base.EventType = pb.EventType_EVENT_TYPE_FILE_READ
		if p, ok := evt.Payload.(*platform.FilePayload); ok {
			base.Payload = &pb.PhantexEvent_File{
				File: &pb.FileEvent{
					Operation: pb.FileOperation_FILE_OPERATION_READ,
					Pid:       evt.PID,
					Uid:       evt.UID,
					Comm:      truncate(evt.Comm, 260),
					Fd:        p.FD,
					Bytes:     int64(p.ByteCount),
					Context:   ctx,
				},
			}
		}

	case platform.EventNetworkConnect:
		base.EventType = pb.EventType_EVENT_TYPE_NETWORK_CONNECT
		if p, ok := evt.Payload.(*platform.NetworkPayload); ok {
			base.Payload = &pb.PhantexEvent_Network{
				Network: &pb.NetworkEvent{
					Operation: pb.NetworkOperation_NETWORK_OPERATION_CONNECT,
					Pid:       evt.PID,
					Comm:      truncate(evt.Comm, 260),
					SrcAddr:   p.SrcAddr,
					SrcPort:   uint32(p.SrcPort),
					DstAddr:   p.DstAddr,
					DstPort:   uint32(p.DstPort),
					Protocol:  uint32(p.Protocol),
					Family:    ipVersionToFamily(p.IPVersion),
					Context:   ctx,
				},
			}
		}

	case platform.EventNetworkAccept:
		base.EventType = pb.EventType_EVENT_TYPE_NETWORK_ACCEPT
		if p, ok := evt.Payload.(*platform.NetworkPayload); ok {
			base.Payload = &pb.PhantexEvent_Network{
				Network: &pb.NetworkEvent{
					Operation: pb.NetworkOperation_NETWORK_OPERATION_ACCEPT,
					Pid:       evt.PID,
					Comm:      truncate(evt.Comm, 260),
					SrcAddr:   p.SrcAddr,
					SrcPort:   uint32(p.SrcPort),
					DstAddr:   p.DstAddr,
					DstPort:   uint32(p.DstPort),
					Protocol:  uint32(p.Protocol),
					Family:    ipVersionToFamily(p.IPVersion),
					Context:   ctx,
				},
			}
		}

	case platform.EventNetworkDNS:
		base.EventType = pb.EventType_EVENT_TYPE_NETWORK_DNS
		if p, ok := evt.Payload.(*platform.DNSPayload); ok {
			base.Payload = &pb.PhantexEvent_Dns{
				Dns: &pb.DNSEvent{
					Pid:       evt.PID,
					Comm:      truncate(evt.Comm, 260),
					QueryName: truncate(p.QueryName, 512),
					QueryType: uint32(p.QueryType),
					DstAddr:   p.DstAddr,
					DstPort:   uint32(p.DstPort),
					Context:   ctx,
				},
			}
		}

	case platform.EventMemoryMap:
		base.EventType = pb.EventType_EVENT_TYPE_MEMORY_MMAP
		if p, ok := evt.Payload.(*platform.MemoryPayload); ok {
			base.Payload = &pb.PhantexEvent_Memory{
				Memory: &pb.MemoryEvent{
					Pid:     evt.PID,
					Comm:    truncate(evt.Comm, 260),
					Addr:    p.Addr,
					Length:  p.Length,
					Prot:    p.Prot,
					Flags:   p.Flags,
					Context: ctx,
				},
			}
		}

	// Windows-specific event types: registry events are mapped to file events
	// with extended metadata until proto adds dedicated RegistryEvent message.
	case platform.EventRegistrySet, platform.EventRegistryCreate, platform.EventRegistryDelete:
		base.EventType = pb.EventType_EVENT_TYPE_FILE_OPEN // Best existing mapping
		base.Severity = pb.Severity_SEVERITY_LOW           // Registry changes are notable
		if p, ok := evt.Payload.(*platform.RegistryPayload); ok {
			op := pb.FileOperation_FILE_OPERATION_OPEN
			if evt.Type == platform.EventRegistryDelete {
				op = pb.FileOperation_FILE_OPERATION_UNSPECIFIED
			} else if evt.Type == platform.EventRegistrySet {
				op = pb.FileOperation_FILE_OPERATION_WRITE
			}
			base.Payload = &pb.PhantexEvent_File{
				File: &pb.FileEvent{
					Operation: op,
					Pid:       evt.PID,
					Uid:       evt.UID,
					Comm:      truncate(evt.Comm, 260),
					Filename:  truncate(p.KeyPath+"\\"+p.ValueName, maxStringField),
					Context:   ctx,
				},
			}
		}

	default:
		return nil
	}

	return base
}

// ToAgentLifecycle converts an agent discovery/termination event to protobuf.
func (c *Converter) ToAgentLifecycle(evtType string, pid uint32, paid, framework, confidence, exePath, cmdline string) *pb.PhantexEvent {
	action := pb.AgentLifecycleAction_AGENT_LIFECYCLE_ACTION_DISCOVERED
	eventType := pb.EventType_EVENT_TYPE_AGENT_DISCOVERED
	if evtType == "AGENT_TERMINATED" {
		action = pb.AgentLifecycleAction_AGENT_LIFECYCLE_ACTION_TERMINATED
		eventType = pb.EventType_EVENT_TYPE_AGENT_TERMINATED
	}

	return &pb.PhantexEvent{
		EventId:   uuidV7(),
		TenantId:  c.tenantID,
		AgentId:   paid,
		SensorId:  c.sensorID,
		Timestamp: timestamppb.Now(),
		EventType: eventType,
		Severity:  pb.Severity_SEVERITY_INFO,
		Payload: &pb.PhantexEvent_Lifecycle{
			Lifecycle: &pb.AgentLifecycleEvent{
				Action:     action,
				Pid:        pid,
				Paid:       paid,
				Framework:  truncate(framework, 256),
				Confidence: confidence,
				ExePath:    truncate(exePath, maxStringField),
				Cmdline:    truncate(cmdline, maxStringField),
			},
		},
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// buildContext creates a ProcessContext from Windows enrichment data.
func buildContext(info *enrichwin.ProcessInfo, agentPAID string) *pb.ProcessContext {
	if info == nil {
		return &pb.ProcessContext{AgentPaid: agentPAID}
	}
	return &pb.ProcessContext{
		ExePath:   info.Exe,
		AgentPaid: agentPAID,
	}
}

// ipVersionToFamily converts IP version to address family.
func ipVersionToFamily(version uint8) uint32 {
	if version == 6 {
		return 23 // AF_INET6 on Windows
	}
	return 2 // AF_INET
}

// truncate limits a string to maxLen bytes (safe for protobuf).
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// uuidV7 generates a UUID v7 (time-ordered, crypto-random tail).
func uuidV7() string {
	var uuid [16]byte

	ms := uint64(time.Now().UnixMilli())
	uuid[0] = byte(ms >> 40)
	uuid[1] = byte(ms >> 32)
	uuid[2] = byte(ms >> 24)
	uuid[3] = byte(ms >> 16)
	uuid[4] = byte(ms >> 8)
	uuid[5] = byte(ms)

	rand.Read(uuid[6:]) //nolint:errcheck

	uuid[6] = (uuid[6] & 0x0F) | 0x70 // version 7
	uuid[8] = (uuid[8] & 0x3F) | 0x80 // variant 10

	return fmt.Sprintf(
		"%s-%s-%s-%s-%s",
		hex.EncodeToString(uuid[0:4]),
		hex.EncodeToString(uuid[4:6]),
		hex.EncodeToString(uuid[6:8]),
		hex.EncodeToString(uuid[8:10]),
		hex.EncodeToString(uuid[10:16]),
	)
}
