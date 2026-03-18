// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Package kafka provides event publishers for the Phantex gateway.
//
// Two implementations of the grpcserver.EventPublisher interface:
//
//   - LogPublisher: Logs events to stdout (development/testing)
//   - KafkaPublisher: Publishes protobuf-serialized events to Kafka
//
// The gateway selects the publisher based on configuration:
//
//	kafka.enabled: true  → KafkaPublisher
//	kafka.enabled: false → LogPublisher (default)
package kafka

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/AKiileX/Phantex/proto/gen/go/phantex/v1"
	kafkago "github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/compress"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// ─── Stats ───────────────────────────────────────────────────────────────────

// Stats holds publisher statistics.
type Stats struct {
	EventsTotal  int64
	BatchesTotal int64
	Errors       int64
	BytesWritten int64
}

// ─── KafkaPublisher ──────────────────────────────────────────────────────────

// writerEntry wraps a Kafka writer with LRU tracking.
type writerEntry struct {
	writer   *kafkago.Writer
	lastUsed atomic.Int64 // Unix timestamp (seconds)
}

func (we *writerEntry) touch() {
	we.lastUsed.Store(time.Now().Unix())
}

// KafkaPublisher publishes protobuf-serialized events to Kafka.
// Events are routed to tenant-specific topics: {topicPrefix}.{tenantID}
//
// Writer pool uses LRU eviction: writers unused for 10 minutes are closed.
// Maximum 1000 concurrent writers — returns error if limit exceeded.
type KafkaPublisher struct {
	log         *zap.Logger
	topicPrefix string
	brokers     []string

	// Writer pool: one writer per tenant topic (lazy-init) with LRU eviction
	mu      sync.RWMutex
	writers map[string]*writerEntry

	// LRU settings
	maxWriters int           // Max concurrent writers (default: 1000)
	writerTTL  time.Duration // Evict writers unused for this duration (default: 10m)
	evictStop  chan struct{} // Signal to stop eviction goroutine

	// Writer config
	batchSize    int
	batchTimeout time.Duration

	// TLS (nil = plaintext)
	tlsConfig *tls.Config

	// Stats
	eventsTotal    atomic.Int64
	batchesTotal   atomic.Int64
	errors         atomic.Int64
	bytesWritten   atomic.Int64
	writersEvicted atomic.Int64

	// Topic creator (ensures topics exist before first write)
	topicCreator *TopicCreator
}

// KafkaConfig holds Kafka publisher configuration.
type KafkaConfig struct {
	Brokers      []string
	TopicPrefix  string
	BatchSize    int
	BatchTimeout time.Duration
	TLSConfig    *tls.Config // nil = plaintext
}

// NewKafkaPublisher creates a Kafka-backed event publisher.
func NewKafkaPublisher(log *zap.Logger, cfg KafkaConfig) *KafkaPublisher {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.BatchTimeout <= 0 {
		cfg.BatchTimeout = time.Second
	}
	if cfg.TopicPrefix == "" {
		cfg.TopicPrefix = "phantex.events"
	}

	p := &KafkaPublisher{
		log:          log.Named("kafka"),
		topicPrefix:  cfg.TopicPrefix,
		brokers:      cfg.Brokers,
		writers:      make(map[string]*writerEntry),
		maxWriters:   1000,
		writerTTL:    10 * time.Minute,
		evictStop:    make(chan struct{}),
		batchSize:    cfg.BatchSize,
		batchTimeout: cfg.BatchTimeout,
		topicCreator: NewTopicCreator(log, cfg.Brokers),
	}
	if cfg.TLSConfig != nil {
		p.tlsConfig = cfg.TLSConfig
	}

	// Start background LRU eviction goroutine
	go p.evictLoop()

	return p
}

// Publish serializes events to protobuf and writes them to the tenant's Kafka topic.
func (p *KafkaPublisher) Publish(tenantID string, events []*pb.PhantexEvent) error {
	if len(events) == 0 {
		return nil
	}

	topic := p.topicName(tenantID)
	entry, err := p.getOrCreateWriter(topic)
	if err != nil {
		return err
	}
	entry.touch()
	writer := entry.writer

	// Build Kafka messages from protobuf events
	messages := make([]kafkago.Message, 0, len(events))
	for _, evt := range events {
		data, err := proto.Marshal(evt)
		if err != nil {
			p.log.Error("failed to marshal event",
				zap.String("event_id", evt.EventId),
				zap.Error(err))
			p.errors.Add(1)
			continue
		}

		messages = append(messages, kafkago.Message{
			// Key = event_type:sensor_id — ensures events from same sensor
			// go to same partition (preserves ordering per sensor)
			Key:   []byte(fmt.Sprintf("%s:%s", evt.EventType.String(), evt.SensorId)),
			Value: data,
			Headers: []kafkago.Header{
				{Key: "tenant_id", Value: []byte(tenantID)},
				{Key: "event_type", Value: []byte(evt.EventType.String())},
				{Key: "sensor_id", Value: []byte(evt.SensorId)},
				{Key: "event_id", Value: []byte(evt.EventId)},
			},
		})

		p.bytesWritten.Add(int64(len(data)))
	}

	if len(messages) == 0 {
		return nil
	}

	// Write with a timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := writer.WriteMessages(ctx, messages...); err != nil {
		p.errors.Add(1)
		p.log.Error("kafka write failed",
			zap.String("topic", topic),
			zap.Int("messages", len(messages)),
			zap.Error(err))
		return fmt.Errorf("kafka write to %s: %w", topic, err)
	}

	p.eventsTotal.Add(int64(len(messages)))
	p.batchesTotal.Add(1)

	p.log.Debug("published to kafka",
		zap.String("topic", topic),
		zap.Int("events", len(messages)))

	return nil
}

// validTopicComponent matches safe Kafka topic name segments (alphanumeric, dots, dashes, underscores).
var validTopicComponent = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,249}$`)

// topicName builds the full topic name for a tenant.
func (p *KafkaPublisher) topicName(tenantID string) string {
	if !validTopicComponent.MatchString(tenantID) {
		p.log.Error("invalid tenant_id for topic name — using sanitized fallback",
			zap.String("tenant_id", tenantID))
		return fmt.Sprintf("%s.unknown", p.topicPrefix)
	}
	return fmt.Sprintf("%s.%s", p.topicPrefix, tenantID)
}

// getOrCreateWriter returns a Kafka writer for the given topic (lazy init).
// Returns error if max writer limit is exceeded.
func (p *KafkaPublisher) getOrCreateWriter(topic string) (*writerEntry, error) {
	// Fast path: read lock
	p.mu.RLock()
	if entry, ok := p.writers[topic]; ok {
		p.mu.RUnlock()
		return entry, nil
	}
	p.mu.RUnlock()

	// Slow path: write lock + create
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if entry, ok := p.writers[topic]; ok {
		return entry, nil
	}

	// Enforce max writers limit
	if len(p.writers) >= p.maxWriters {
		p.log.Error("max kafka writers exceeded",
			zap.Int("max", p.maxWriters),
			zap.Int("current", len(p.writers)),
			zap.String("topic", topic))
		return nil, fmt.Errorf("max kafka writers exceeded (%d): rejecting tenant", p.maxWriters)
	}

	// Ensure topic exists before first write
	p.topicCreator.EnsureTopic(topic, 6, 1) // 6 partitions, replication 1 (dev)

	w := &kafkago.Writer{
		Addr:         kafkago.TCP(p.brokers...),
		Topic:        topic,
		Balancer:     &kafkago.Hash{}, // consistent hashing on message key
		BatchSize:    p.batchSize,
		BatchTimeout: p.batchTimeout,
		Compression:  compress.Lz4,
		// RequiredAcks: all in-sync replicas must ack (strongest durability)
		RequiredAcks: kafkago.RequireAll,
		// Async = false: WriteMessages blocks until ack. Safer for Phase 1.
		Async: false,
		// Max message: 16MB (matches gRPC max)
		BatchBytes: 16 * 1024 * 1024,
		// Retry transient failures up to 3 times with backoff
		MaxAttempts: 3,
		// We create topics explicitly via TopicCreator — disable auto-creation
		AllowAutoTopicCreation: false,
	}

	// Wire TLS transport if configured
	if p.tlsConfig != nil {
		w.Transport = &kafkago.Transport{
			TLS:         p.tlsConfig,
			DialTimeout: 10 * time.Second,
			Dial: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		}
	}

	entry := &writerEntry{writer: w}
	entry.touch()
	p.writers[topic] = entry
	p.log.Info("created kafka writer",
		zap.String("topic", topic),
		zap.Strings("brokers", p.brokers),
		zap.Int("total_writers", len(p.writers)))

	return entry, nil
}

// evictLoop runs in a background goroutine and periodically closes
// writers unused for longer than writerTTL.
func (p *KafkaPublisher) evictLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-p.evictStop:
			return
		case <-ticker.C:
			p.evictStale()
		}
	}
}

// evictStale closes writers that haven't been used within writerTTL.
func (p *KafkaPublisher) evictStale() {
	p.mu.Lock()
	defer p.mu.Unlock()

	cutoff := time.Now().Add(-p.writerTTL).Unix()
	var evicted int

	for topic, entry := range p.writers {
		if entry.lastUsed.Load() < cutoff {
			if err := entry.writer.Close(); err != nil {
				p.log.Warn("error closing evicted writer",
					zap.String("topic", topic),
					zap.Error(err))
			}
			delete(p.writers, topic)
			evicted++
		}
	}

	if evicted > 0 {
		p.writersEvicted.Add(int64(evicted))
		p.log.Info("evicted stale kafka writers",
			zap.Int("evicted", evicted),
			zap.Int("remaining", len(p.writers)))
	}
}

// Close shuts down all Kafka writers and stops the eviction goroutine.
func (p *KafkaPublisher) Close() error {
	// Stop eviction goroutine
	close(p.evictStop)

	p.mu.Lock()
	defer p.mu.Unlock()

	var lastErr error
	for topic, entry := range p.writers {
		if err := entry.writer.Close(); err != nil {
			p.log.Error("failed to close kafka writer",
				zap.String("topic", topic),
				zap.Error(err))
			lastErr = err
		}
	}
	p.writers = make(map[string]*writerEntry)

	p.log.Info("kafka publisher closed",
		zap.Int64("total_events", p.eventsTotal.Load()),
		zap.Int64("total_batches", p.batchesTotal.Load()),
		zap.Int64("errors", p.errors.Load()),
		zap.Int64("bytes_written", p.bytesWritten.Load()),
		zap.Int64("writers_evicted", p.writersEvicted.Load()))

	return lastErr
}

// GetStats returns current publisher statistics.
func (p *KafkaPublisher) GetStats() Stats {
	return Stats{
		EventsTotal:  p.eventsTotal.Load(),
		BatchesTotal: p.batchesTotal.Load(),
		Errors:       p.errors.Load(),
		BytesWritten: p.bytesWritten.Load(),
	}
}

// ─── TopicCreator ────────────────────────────────────────────────────────────

// TopicCreator ensures Kafka topics exist before writing.
type TopicCreator struct {
	log     *zap.Logger
	brokers []string

	mu      sync.Mutex
	created map[string]bool
}

// NewTopicCreator creates a topic creator.
func NewTopicCreator(log *zap.Logger, brokers []string) *TopicCreator {
	return &TopicCreator{
		log:     log.Named("topics"),
		brokers: brokers,
		created: make(map[string]bool),
	}
}

// EnsureTopic creates a topic if it doesn't already exist.
func (tc *TopicCreator) EnsureTopic(topic string, partitions, replication int) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	if tc.created[topic] {
		return
	}

	conn, err := kafkago.Dial("tcp", tc.brokers[0])
	if err != nil {
		tc.log.Warn("failed to connect to kafka for topic creation",
			zap.String("topic", topic),
			zap.Error(err))
		return
	}
	defer conn.Close()

	controller, err := conn.Controller()
	if err != nil {
		tc.log.Warn("failed to get kafka controller",
			zap.String("topic", topic),
			zap.Error(err))
		return
	}

	controllerConn, err := kafkago.Dial("tcp", fmt.Sprintf("%s:%d", controller.Host, controller.Port))
	if err != nil {
		tc.log.Warn("failed to connect to kafka controller",
			zap.String("topic", topic),
			zap.Error(err))
		return
	}
	defer controllerConn.Close()

	err = controllerConn.CreateTopics(kafkago.TopicConfig{
		Topic:             topic,
		NumPartitions:     partitions,
		ReplicationFactor: replication,
		ConfigEntries: []kafkago.ConfigEntry{
			{ConfigName: "retention.ms", ConfigValue: "604800000"}, // 7 days
			{ConfigName: "cleanup.policy", ConfigValue: "delete"},
			{ConfigName: "compression.type", ConfigValue: "lz4"},
			{ConfigName: "max.message.bytes", ConfigValue: "16777216"},
		},
	})
	if err != nil {
		// kafka-go returns the error string containing "already exists" when the
		// topic was previously created.  Treat that as success; any other error
		// means creation genuinely failed and we should retry next time.
		errMsg := err.Error()
		if strings.Contains(errMsg, "already exists") || strings.Contains(errMsg, "TopicAlreadyExists") {
			tc.created[topic] = true
			return
		}
		tc.log.Warn("topic creation failed — will retry next publish",
			zap.String("topic", topic),
			zap.Error(err))
		return
	}

	tc.log.Info("created kafka topic",
		zap.String("topic", topic),
		zap.Int("partitions", partitions),
		zap.Int("replication", replication))
	tc.created[topic] = true
}

// ─── LogPublisher ────────────────────────────────────────────────────────────

// LogPublisher is a stub publisher that logs events instead of sending to Kafka.
// Used for development and testing when Kafka is not available.
type LogPublisher struct {
	log          *zap.Logger
	eventsTotal  atomic.Int64
	batchesTotal atomic.Int64
}

// NewLogPublisher creates a log-based event publisher.
func NewLogPublisher(log *zap.Logger) *LogPublisher {
	return &LogPublisher{
		log: log.Named("publisher"),
	}
}

// Publish logs events instead of sending to Kafka
func (p *LogPublisher) Publish(tenantID string, events []*pb.PhantexEvent) error {
	p.batchesTotal.Add(1)
	p.eventsTotal.Add(int64(len(events)))

	for _, evt := range events {
		fields := []zap.Field{
			zap.String("tenant_id", tenantID),
			zap.String("event_id", evt.EventId),
			zap.String("event_type", evt.EventType.String()),
			zap.String("sensor_id", evt.SensorId),
		}

		if evt.AgentId != "" {
			fields = append(fields, zap.String("agent_id", evt.AgentId))
		}

		switch payload := evt.Payload.(type) {
		case *pb.PhantexEvent_ProcessExec:
			fields = append(fields,
				zap.Uint32("pid", payload.ProcessExec.Pid),
				zap.String("comm", payload.ProcessExec.Comm),
				zap.String("filename", payload.ProcessExec.Filename))
		case *pb.PhantexEvent_ProcessExit:
			fields = append(fields,
				zap.Uint32("pid", payload.ProcessExit.Pid),
				zap.Int32("exit_code", payload.ProcessExit.ExitCode))
		case *pb.PhantexEvent_File:
			fields = append(fields,
				zap.Uint32("pid", payload.File.Pid),
				zap.String("op", payload.File.Operation.String()),
				zap.String("filename", payload.File.Filename))
		case *pb.PhantexEvent_Network:
			fields = append(fields,
				zap.Uint32("pid", payload.Network.Pid),
				zap.String("op", payload.Network.Operation.String()),
				zap.String("dst", payload.Network.DstAddr),
				zap.Uint32("dst_port", payload.Network.DstPort))
		case *pb.PhantexEvent_Dns:
			fields = append(fields,
				zap.Uint32("pid", payload.Dns.Pid),
				zap.String("query", payload.Dns.QueryName))
		case *pb.PhantexEvent_Memory:
			fields = append(fields,
				zap.Uint32("pid", payload.Memory.Pid),
				zap.Uint64("addr", payload.Memory.Addr))
		case *pb.PhantexEvent_Lifecycle:
			fields = append(fields,
				zap.String("action", payload.Lifecycle.Action.String()),
				zap.String("paid", payload.Lifecycle.Paid),
				zap.String("framework", payload.Lifecycle.Framework))
		case *pb.PhantexEvent_Alert:
			fields = append(fields,
				zap.String("rule", payload.Alert.RuleName),
				zap.String("severity", payload.Alert.Severity.String()))
		}

		p.log.Info("event", fields...)
	}

	return nil
}

// PublishJSON publishes events as JSON (for debugging and Phase 1 tests).
func (p *LogPublisher) PublishJSON(tenantID string, events []*pb.PhantexEvent) error {
	for _, evt := range events {
		data, err := json.Marshal(evt)
		if err != nil {
			p.log.Error("failed to marshal event", zap.Error(err))
			continue
		}
		p.log.Debug("event_json",
			zap.String("tenant_id", tenantID),
			zap.ByteString("data", data))
	}
	return nil
}

// Close is a no-op for the log publisher.
func (p *LogPublisher) Close() error {
	return nil
}

// GetStats returns current publisher statistics.
func (p *LogPublisher) GetStats() Stats {
	return Stats{
		EventsTotal:  p.eventsTotal.Load(),
		BatchesTotal: p.batchesTotal.Load(),
	}
}
