// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Package converter maps internal eBPF event types to Protobuf event
// messages (PhantexEvent). This is the bridge between the kernel-level
// sensor and the transport layer
//
// The converter:
//   - Maps each eBPF event type to its protobuf equivalent
//   - Copies enrichment data (from /proc) into ProcessContext
//   - Generates UUID v7 event IDs (time-ordered for Kafka partitioning)
//   - Sets tenant_id on every event (required for cross-tenant isolation)
package converter

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"syscall"
	"time"

	pb "github.com/AKiileX/Phantex/proto/gen/go/phantex/v1"
	bpf "github.com/AKiileX/Phantex/sensor/internal/ebpf"
	"github.com/AKiileX/Phantex/sensor/internal/enricher"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Converter translates internal eBPF events into protobuf PhantexEvents.
type Converter struct {
	sensorID string
	tenantID string
	bootTime time.Time // wall-clock time when the kernel booted
}

// New creates a converter with the given sensor and tenant identity.
func New(sensorID, tenantID string) *Converter {
	var si syscall.Sysinfo_t
	_ = syscall.Sysinfo(&si)
	boot := time.Now().Add(-time.Duration(si.Uptime) * time.Second)
	return &Converter{
		sensorID: sensorID,
		tenantID: tenantID,
		bootTime: boot,
	}
}

// ToProto converts an internal eBPF event + enrichment info into a PhantexEvent.
// Returns nil if the event type is unknown (should not happen).
func (c *Converter) ToProto(evt bpf.Event, info *enricher.ProcessInfo, agentPAID string) *pb.PhantexEvent {
	// evt.Header.TimestampNs is bpf_ktime_get_boot_ns() — nanoseconds since
	// kernel boot. Convert to wall-clock by adding the boot-time offset.
	ts := c.bootTime.Add(time.Duration(evt.Header.TimestampNs))

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
	case bpf.EventProcessExec:
		base.EventType = pb.EventType_EVENT_TYPE_PROCESS_EXEC
		if e, ok := evt.Payload.(*bpf.ExecEvent); ok {
			base.Payload = &pb.PhantexEvent_ProcessExec{
				ProcessExec: &pb.ProcessExecEvent{
					Pid:      evt.Header.PID,
					Ppid:     evt.Header.PPID,
					Uid:      evt.Header.UID,
					Comm:     evt.Header.CommString(),
					Filename: e.FilenameString(),
					Argv:     e.ArgvString(),
					Context:  ctx,
				},
			}
		}

	case bpf.EventProcessExit:
		base.EventType = pb.EventType_EVENT_TYPE_PROCESS_EXIT
		if e, ok := evt.Payload.(*bpf.ExitEvent); ok {
			base.Payload = &pb.PhantexEvent_ProcessExit{
				ProcessExit: &pb.ProcessExitEvent{
					Pid:        evt.Header.PID,
					Ppid:       evt.Header.PPID,
					Uid:        evt.Header.UID,
					Comm:       evt.Header.CommString(),
					ExitCode:   e.ExitCode,
					DurationNs: e.DurationNs,
					Context:    ctx,
				},
			}
		}

	case bpf.EventFileOpen:
		base.EventType = pb.EventType_EVENT_TYPE_FILE_OPEN
		if e, ok := evt.Payload.(*bpf.FileOpenEvent); ok {
			base.Payload = &pb.PhantexEvent_File{
				File: &pb.FileEvent{
					Operation: pb.FileOperation_FILE_OPERATION_OPEN,
					Pid:       evt.Header.PID,
					Uid:       evt.Header.UID,
					Comm:      evt.Header.CommString(),
					Filename:  e.FilenameString(),
					Flags:     e.Flags,
					Context:   ctx,
				},
			}
		}

	case bpf.EventFileWrite:
		base.EventType = pb.EventType_EVENT_TYPE_FILE_WRITE
		if e, ok := evt.Payload.(*bpf.FileWriteEvent); ok {
			base.Payload = &pb.PhantexEvent_File{
				File: &pb.FileEvent{
					Operation: pb.FileOperation_FILE_OPERATION_WRITE,
					Pid:       evt.Header.PID,
					Uid:       evt.Header.UID,
					Comm:      evt.Header.CommString(),
					Fd:        e.FD,
					Bytes:     int64(e.ByteCount),
					Context:   ctx,
				},
			}
		}

	case bpf.EventFileRead:
		base.EventType = pb.EventType_EVENT_TYPE_FILE_READ
		if e, ok := evt.Payload.(*bpf.FileReadEvent); ok {
			base.Payload = &pb.PhantexEvent_File{
				File: &pb.FileEvent{
					Operation: pb.FileOperation_FILE_OPERATION_READ,
					Pid:       evt.Header.PID,
					Uid:       evt.Header.UID,
					Comm:      evt.Header.CommString(),
					Fd:        e.FD,
					Bytes:     int64(e.ByteCount),
					Context:   ctx,
				},
			}
		}

	case bpf.EventNetworkConnect:
		base.EventType = pb.EventType_EVENT_TYPE_NETWORK_CONNECT
		if e, ok := evt.Payload.(*bpf.NetConnectEvent); ok {
			base.Payload = &pb.PhantexEvent_Network{
				Network: &pb.NetworkEvent{
					Operation: pb.NetworkOperation_NETWORK_OPERATION_CONNECT,
					Pid:       evt.Header.PID,
					Comm:      evt.Header.CommString(),
					SrcAddr:   e.SrcIP().String(),
					SrcPort:   uint32(e.SrcPort),
					DstAddr:   e.DstIP().String(),
					DstPort:   uint32(e.DstPort),
					Protocol:  uint32(e.Protocol),
					Family:    ipVersionToFamily(e.IPVersion),
					Context:   ctx,
				},
			}
		}

	case bpf.EventNetworkAccept:
		base.EventType = pb.EventType_EVENT_TYPE_NETWORK_ACCEPT
		if e, ok := evt.Payload.(*bpf.NetAcceptEvent); ok {
			base.Payload = &pb.PhantexEvent_Network{
				Network: &pb.NetworkEvent{
					Operation: pb.NetworkOperation_NETWORK_OPERATION_ACCEPT,
					Pid:       evt.Header.PID,
					Comm:      evt.Header.CommString(),
					SrcAddr:   e.SrcIP().String(),
					SrcPort:   uint32(e.SrcPort),
					DstAddr:   e.DstIP().String(),
					DstPort:   uint32(e.DstPort),
					Protocol:  uint32(e.Protocol),
					Family:    ipVersionToFamily(e.IPVersion),
					Context:   ctx,
				},
			}
		}

	case bpf.EventNetworkDNS:
		base.EventType = pb.EventType_EVENT_TYPE_NETWORK_DNS
		if e, ok := evt.Payload.(*bpf.DNSEvent); ok {
			ip := make(net.IP, 4)
			binary.BigEndian.PutUint32(ip, e.DstAddr)
			base.Payload = &pb.PhantexEvent_Dns{
				Dns: &pb.DNSEvent{
					Pid:       evt.Header.PID,
					Comm:      evt.Header.CommString(),
					QueryName: e.QueryNameString(),
					QueryType: uint32(e.QueryType),
					DstAddr:   ip.String(),
					DstPort:   uint32(e.DstPort),
					Context:   ctx,
				},
			}
		}

	case bpf.EventMemoryMap:
		base.EventType = pb.EventType_EVENT_TYPE_MEMORY_MMAP
		if e, ok := evt.Payload.(*bpf.MmapEvent); ok {
			base.Payload = &pb.PhantexEvent_Memory{
				Memory: &pb.MemoryEvent{
					Pid:     evt.Header.PID,
					Comm:    evt.Header.CommString(),
					Addr:    e.Addr,
					Length:  e.Length,
					Prot:    int32(e.Prot),
					Flags:   int32(e.Flags),
					Context: ctx,
				},
			}
		}

	default:
		return nil
	}

	return base
}

// ToAgentLifecycle converts an agent discovery/termination event to protobuf.
func (c *Converter) ToAgentLifecycle(evtType string, pid uint32, paid, framework, confidence, exePath, cmdline, containerID string) *pb.PhantexEvent {
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
				Action:      action,
				Pid:         pid,
				Paid:        paid,
				Framework:   framework,
				Confidence:  confidence,
				ExePath:     exePath,
				Cmdline:     cmdline,
				ContainerId: containerID,
			},
		},
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// buildContext creates a ProcessContext from enrichment data.
func buildContext(info *enricher.ProcessInfo, agentPAID string) *pb.ProcessContext {
	if info == nil {
		return &pb.ProcessContext{AgentPaid: agentPAID}
	}
	return &pb.ProcessContext{
		ExePath:     info.Exe,
		ContainerId: info.ContainerID,
		CgroupPath:  info.CgroupPath,
		AgentPaid:   agentPAID,
	}
}

// ipVersionToFamily converts eBPF IP version (4/6) to AF_INET/AF_INET6.
func ipVersionToFamily(version uint8) uint32 {
	if version == 6 {
		return 10 // AF_INET6
	}
	return 2 // AF_INET
}

// uuidV7 generates a UUID v7 (time-ordered, random tail).
// Format: xxxxxxxx-xxxx-7xxx-yxxx-xxxxxxxxxxxx
//
// UUID v7 uses millisecond timestamp in the high 48 bits, giving
// chronological ordering (important for Kafka partitioning and event dedup).
func uuidV7() string {
	var uuid [16]byte

	// High 48 bits: Unix milliseconds
	ms := uint64(time.Now().UnixMilli())
	uuid[0] = byte(ms >> 40)
	uuid[1] = byte(ms >> 32)
	uuid[2] = byte(ms >> 24)
	uuid[3] = byte(ms >> 16)
	uuid[4] = byte(ms >> 8)
	uuid[5] = byte(ms)

	// Fill remaining bytes with crypto-random
	rand.Read(uuid[6:]) //nolint:errcheck

	// Set version (7) and variant (RFC 4122)
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
