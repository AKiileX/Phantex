// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Command phantex-test-sender sends a batch of test events to the gateway
// via gRPC to verify the end-to-end pipeline: sender → gateway → Kafka.
//
// Usage:
//
//	./phantex-test-sender [--addr localhost:50051] [--token phantex-dev-token-do-not-use-in-production] [--count 10]
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"

	pb "github.com/AKiileX/Phantex/proto/gen/go/phantex/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func main() {
	var (
		addr     string
		token    string
		count    int
		sensorID string
		tenantID string
	)
	flag.StringVar(&addr, "addr", "localhost:50051", "Gateway gRPC address")
	flag.StringVar(&token, "token", "phantex-dev-token-do-not-use-in-production", "Auth token")
	flag.IntVar(&count, "count", 10, "Number of test events to send")
	flag.StringVar(&sensorID, "sensor", "test-sensor-001", "Sensor ID")
	flag.StringVar(&tenantID, "tenant", "default-tenant", "Tenant ID")
	flag.Parse()

	fmt.Printf("Phantex Test Sender\n")
	fmt.Printf("  Gateway: %s\n", addr)
	fmt.Printf("  Sensor:  %s\n", sensorID)
	fmt.Printf("  Tenant:  %s\n", tenantID)
	fmt.Printf("  Events:  %d\n\n", count)

	// Connect to gateway
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, addr, //nolint:staticcheck // deprecated but needed for blocking dial
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(), //nolint:staticcheck // needed for blocking dial with timeout
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: dial: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	fmt.Println("Connected to gateway")

	// Open bidirectional stream with auth token
	md := metadata.New(map[string]string{
		"authorization": "Bearer " + token,
	})
	streamCtx := metadata.NewOutgoingContext(ctx, md)

	client := pb.NewSensorServiceClient(conn)
	stream, err := client.IngestEvents(streamCtx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: open stream: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Stream opened")

	// Generate and send test events
	events := generateTestEvents(count, sensorID, tenantID)

	req := &pb.IngestEventsRequest{
		BatchId:  1,
		SensorId: sensorID,
		TenantId: tenantID,
		Events:   events,
	}

	fmt.Printf("Sending batch of %d events...\n", len(events))
	if err := stream.Send(req); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: send: %v\n", err)
		os.Exit(1)
	}

	// Wait for ack
	ack, err := stream.Recv()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: recv ack: %v\n", err)
		os.Exit(1)
	}

	if ack.Accepted {
		fmt.Printf("Batch %d ACCEPTED by gateway\n", ack.BatchId)
	} else {
		fmt.Printf("Batch %d REJECTED: %s\n", ack.BatchId, ack.RejectReason)
	}

	// Close stream
	stream.CloseSend() //nolint:errcheck
	fmt.Println("\nDone. Events should now be in Kafka.")
	fmt.Printf("Verify with: ./phantex-consumer --topic phantex.events.%s\n", tenantID)
}

func generateTestEvents(count int, sensorID, tenantID string) []*pb.PhantexEvent {
	events := make([]*pb.PhantexEvent, count)

	for i := 0; i < count; i++ {
		ts := timestamppb.Now()

		switch i % 5 {
		case 0:
			events[i] = &pb.PhantexEvent{
				EventId:   uuidV7(),
				TenantId:  tenantID,
				SensorId:  sensorID,
				Timestamp: ts,
				EventType: pb.EventType_EVENT_TYPE_PROCESS_EXEC,
				Severity:  pb.Severity_SEVERITY_INFO,
				Payload: &pb.PhantexEvent_ProcessExec{
					ProcessExec: &pb.ProcessExecEvent{
						Pid:      uint32(1000 + i),
						Ppid:     1,
						Uid:      1000,
						Comm:     "python3",
						Filename: "/usr/bin/python3",
						Argv:     "python3 agent.py --model gpt-4",
						Context: &pb.ProcessContext{
							ExePath:   "/usr/bin/python3",
							AgentPaid: "ptx-default-dev-abc123",
						},
					},
				},
			}
		case 1:
			events[i] = &pb.PhantexEvent{
				EventId:   uuidV7(),
				TenantId:  tenantID,
				SensorId:  sensorID,
				Timestamp: ts,
				EventType: pb.EventType_EVENT_TYPE_FILE_OPEN,
				Severity:  pb.Severity_SEVERITY_INFO,
				Payload: &pb.PhantexEvent_File{
					File: &pb.FileEvent{
						Operation: pb.FileOperation_FILE_OPERATION_OPEN,
						Pid:       uint32(1000 + i),
						Uid:       1000,
						Comm:      "python3",
						Filename:  "/etc/passwd",
						Flags:     0,
					},
				},
			}
		case 2:
			events[i] = &pb.PhantexEvent{
				EventId:   uuidV7(),
				TenantId:  tenantID,
				SensorId:  sensorID,
				Timestamp: ts,
				EventType: pb.EventType_EVENT_TYPE_NETWORK_CONNECT,
				Severity:  pb.Severity_SEVERITY_INFO,
				Payload: &pb.PhantexEvent_Network{
					Network: &pb.NetworkEvent{
						Operation: pb.NetworkOperation_NETWORK_OPERATION_CONNECT,
						Pid:       uint32(1000 + i),
						Comm:      "python3",
						SrcAddr:   "10.0.0.1",
						SrcPort:   45678,
						DstAddr:   "api.openai.com",
						DstPort:   443,
						Protocol:  6,
						Family:    2,
					},
				},
			}
		case 3:
			events[i] = &pb.PhantexEvent{
				EventId:   uuidV7(),
				TenantId:  tenantID,
				SensorId:  sensorID,
				Timestamp: ts,
				EventType: pb.EventType_EVENT_TYPE_NETWORK_DNS,
				Severity:  pb.Severity_SEVERITY_INFO,
				Payload: &pb.PhantexEvent_Dns{
					Dns: &pb.DNSEvent{
						Pid:       uint32(1000 + i),
						Comm:      "python3",
						QueryName: "api.openai.com",
						QueryType: 1,
						DstAddr:   "8.8.8.8",
						DstPort:   53,
					},
				},
			}
		case 4:
			events[i] = &pb.PhantexEvent{
				EventId:   uuidV7(),
				TenantId:  tenantID,
				SensorId:  sensorID,
				Timestamp: ts,
				EventType: pb.EventType_EVENT_TYPE_AGENT_DISCOVERED,
				Severity:  pb.Severity_SEVERITY_INFO,
				Payload: &pb.PhantexEvent_Lifecycle{
					Lifecycle: &pb.AgentLifecycleEvent{
						Action:    pb.AgentLifecycleAction_AGENT_LIFECYCLE_ACTION_DISCOVERED,
						Pid:       uint32(1000 + i),
						Paid:      "ptx-default-dev-abc123",
						Framework: "langchain",
					},
				},
			}
		}
	}

	return events
}

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
	uuid[6] = (uuid[6] & 0x0F) | 0x70
	uuid[8] = (uuid[8] & 0x3F) | 0x80
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(uuid[0:4]),
		hex.EncodeToString(uuid[4:6]),
		hex.EncodeToString(uuid[6:8]),
		hex.EncodeToString(uuid[8:10]),
		hex.EncodeToString(uuid[10:16]))
}
