// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Command phantex-consumer is a test tool that reads events from Kafka and
// deserializes them from Protobuf for verification.
//
// Usage:
//
//	./phantex-consumer [--broker localhost:9092] [--topic phantex.events.default-tenant] [--group phantex-debug]
//
// This is a development/debugging tool, not a production service.
// It demonstrates that events flow end-to-end: sensor → gateway → Kafka → consumer.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	pb "github.com/AKiileX/Phantex/proto/gen/go/phantex/v1"
	kafkago "github.com/segmentio/kafka-go"
	"google.golang.org/protobuf/proto"
)

func main() {
	var (
		broker  string
		topic   string
		group   string
		fromEnd bool
	)
	flag.StringVar(&broker, "broker", "localhost:9092", "Kafka broker address")
	flag.StringVar(&topic, "topic", "phantex.events.default-tenant", "Kafka topic to consume")
	flag.StringVar(&group, "group", "phantex-debug", "Consumer group ID")
	flag.BoolVar(&fromEnd, "latest", false, "Start from latest offset (default: earliest)")
	flag.Parse()

	fmt.Printf("Phantex Test Consumer\n")
	fmt.Printf("  Broker: %s\n", broker)
	fmt.Printf("  Topic:  %s\n", topic)
	fmt.Printf("  Group:  %s\n", group)
	fmt.Printf("  Start:  %s\n\n", startOffset(fromEnd))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		cancel()
	}()

	startOff := kafkago.FirstOffset
	if fromEnd {
		startOff = kafkago.LastOffset
	}

	reader := kafkago.NewReader(kafkago.ReaderConfig{
		Brokers:        []string{broker},
		Topic:          topic,
		GroupID:        group,
		StartOffset:    startOff,
		MinBytes:       1,
		MaxBytes:       16 * 1024 * 1024, // 16MB
		CommitInterval: time.Second,
	})
	defer reader.Close()

	fmt.Printf("Listening for events (Ctrl-C to stop)...\n\n")

	count := 0
	for {
		msg, err := reader.ReadMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				break // context cancelled
			}
			fmt.Fprintf(os.Stderr, "ERROR: read: %v\n", err)
			continue
		}

		count++
		evt := &pb.PhantexEvent{}
		if err := proto.Unmarshal(msg.Value, evt); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: unmarshal: %v (raw=%d bytes)\n", err, len(msg.Value))
			continue
		}

		// Print event summary
		fmt.Printf("[%d] %s | partition=%d offset=%d\n",
			count, time.Now().Format("15:04:05.000"), msg.Partition, msg.Offset)
		fmt.Printf("     event_id:  %s\n", evt.EventId)
		fmt.Printf("     type:      %s\n", evt.EventType.String())
		fmt.Printf("     tenant:    %s\n", evt.TenantId)
		fmt.Printf("     sensor:    %s\n", evt.SensorId)
		fmt.Printf("     severity:  %s\n", evt.Severity.String())

		if evt.Timestamp != nil {
			fmt.Printf("     time:      %s\n", evt.Timestamp.AsTime().Format(time.RFC3339Nano))
		}
		if evt.AgentId != "" {
			fmt.Printf("     agent:     %s\n", evt.AgentId)
		}

		// Print payload details
		printPayload(evt)
		fmt.Println()
	}

	fmt.Printf("\nConsumed %d events total.\n", count)
}

func printPayload(evt *pb.PhantexEvent) {
	switch p := evt.Payload.(type) {
	case *pb.PhantexEvent_ProcessExec:
		fmt.Printf("     payload:   EXEC pid=%d ppid=%d comm=%q file=%q\n",
			p.ProcessExec.Pid, p.ProcessExec.Ppid,
			p.ProcessExec.Comm, p.ProcessExec.Filename)
		if p.ProcessExec.Context != nil && p.ProcessExec.Context.ContainerId != "" {
			fmt.Printf("     container: %s\n", p.ProcessExec.Context.ContainerId)
		}

	case *pb.PhantexEvent_ProcessExit:
		fmt.Printf("     payload:   EXIT pid=%d exit_code=%d duration=%dns\n",
			p.ProcessExit.Pid, p.ProcessExit.ExitCode, p.ProcessExit.DurationNs)

	case *pb.PhantexEvent_File:
		fmt.Printf("     payload:   FILE op=%s pid=%d file=%q flags=%d bytes=%d\n",
			p.File.Operation, p.File.Pid, p.File.Filename,
			p.File.Flags, p.File.Bytes)

	case *pb.PhantexEvent_Network:
		fmt.Printf("     payload:   NET op=%s pid=%d %s:%d → %s:%d proto=%d\n",
			p.Network.Operation, p.Network.Pid,
			p.Network.SrcAddr, p.Network.SrcPort,
			p.Network.DstAddr, p.Network.DstPort,
			p.Network.Protocol)

	case *pb.PhantexEvent_Dns:
		fmt.Printf("     payload:   DNS pid=%d query=%q type=%d dst=%s:%d\n",
			p.Dns.Pid, p.Dns.QueryName, p.Dns.QueryType,
			p.Dns.DstAddr, p.Dns.DstPort)

	case *pb.PhantexEvent_Memory:
		fmt.Printf("     payload:   MMAP pid=%d addr=0x%x len=%d prot=%d flags=%d\n",
			p.Memory.Pid, p.Memory.Addr, p.Memory.Length,
			p.Memory.Prot, p.Memory.Flags)

	case *pb.PhantexEvent_Lifecycle:
		fmt.Printf("     payload:   AGENT %s paid=%s framework=%s\n",
			p.Lifecycle.Action, p.Lifecycle.Paid, p.Lifecycle.Framework)

	case *pb.PhantexEvent_Alert:
		fmt.Printf("     payload:   ALERT rule=%q severity=%s\n",
			p.Alert.RuleName, p.Alert.Severity)

	default:
		fmt.Printf("     payload:   (unknown type)\n")
	}
}

func startOffset(fromEnd bool) string {
	if fromEnd {
		return "latest"
	}
	return "earliest"
}
