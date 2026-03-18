// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Package grpcserver implements the Phantex gateway gRPC server.
//
// It receives bidirectional event streams from sensors (SensorService),
// validates authentication and tenant isolation, and publishes events
// to the downstream event bus (Kafka in production, stdout stub in Phase 1).
package grpcserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AKiileX/Phantex/gateway/internal/auth"
	pb "github.com/AKiileX/Phantex/proto/gen/go/phantex/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ── Input validation constants ───────────────────────────────────────────────
const (
	maxBatchSize              = 1000            // Maximum events per single batch
	maxFieldLength            = 4096            // Maximum length for any single string field
	maxSensorIDLength         = 256             // Maximum sensor ID length
	maxEventIDLength          = 128             // Maximum event ID length
	maxSensorsPerTenant       = 10000           // Maximum tracked sensors per tenant (memory guard)
	rateBucketCleanupInterval = 5 * time.Minute // How often to purge stale rate buckets
	streamIdleTimeout         = 5 * time.Minute // Close streams that send no batches for this long
)

// validEventTypes is the set of valid Phantex event types (proto enum values).
var validEventTypes = map[pb.EventType]bool{
	pb.EventType_EVENT_TYPE_PROCESS_EXEC:     true,
	pb.EventType_EVENT_TYPE_PROCESS_EXIT:     true,
	pb.EventType_EVENT_TYPE_FILE_OPEN:        true,
	pb.EventType_EVENT_TYPE_FILE_WRITE:       true,
	pb.EventType_EVENT_TYPE_FILE_READ:        true,
	pb.EventType_EVENT_TYPE_NETWORK_CONNECT:  true,
	pb.EventType_EVENT_TYPE_NETWORK_ACCEPT:   true,
	pb.EventType_EVENT_TYPE_NETWORK_DNS:      true,
	pb.EventType_EVENT_TYPE_MEMORY_MMAP:      true,
	pb.EventType_EVENT_TYPE_AGENT_DISCOVERED: true,
	pb.EventType_EVENT_TYPE_AGENT_TERMINATED: true,
	pb.EventType_EVENT_TYPE_TOOL_CALL:        true,
	pb.EventType_EVENT_TYPE_TOOL_RESPONSE:    true,
	pb.EventType_EVENT_TYPE_ALERT_FIRED:      true,
}

// EventPublisher is the interface for downstream event publishing.
// Kafka producer implements this in production; stdout stub for Phase 1.
type EventPublisher interface {
	// Publish sends a batch of events to the event bus.
	// tenantID is used for topic routing (e.g., phantex.events.{tenant_id}).
	Publish(tenantID string, events []*pb.PhantexEvent) error
}

// Server implements the SensorService gRPC server.
type Server struct {
	pb.UnimplementedSensorServiceServer

	log       *zap.Logger
	publisher EventPublisher

	// Rate limiting: max events per second per tenant
	maxEventsPerSec int64

	// Per-tenant rate tracking for true per-second limiting
	sensorRateMu sync.Mutex
	sensorRates  map[string]*rateBucket

	// Backend API (for command relay)
	backendURL    string
	internalToken string
	httpClient    *http.Client

	// Stats
	mu              sync.RWMutex
	activeSensors   map[string]*sensorState
	totalEvents     atomic.Int64
	totalBatches    atomic.Int64
	rejectedBatches atomic.Int64

	// Cleanup
	stopCleanup chan struct{}
	stopOnce    sync.Once
}

// rateBucket tracks events per second per tenant for rate limiting.
type rateBucket struct {
	count     int64
	windowEnd time.Time
}

// checkRate returns true if the event count is within the rate limit for this key.
// Key should be the authenticated tenantID (not attacker-controlled sensorID).
func (s *Server) checkRate(key string, eventCount int64) bool {
	if s.maxEventsPerSec <= 0 {
		return true
	}
	s.sensorRateMu.Lock()
	defer s.sensorRateMu.Unlock()

	now := time.Now()
	bucket, ok := s.sensorRates[key]
	if !ok || now.After(bucket.windowEnd) {
		// New window
		s.sensorRates[key] = &rateBucket{
			count:     eventCount,
			windowEnd: now.Add(time.Second),
		}
		return eventCount <= s.maxEventsPerSec
	}
	bucket.count += eventCount
	return bucket.count <= s.maxEventsPerSec
}

// cleanupStaleBuckets periodically removes expired rate-limit entries to prevent
// unbounded memory growth. Runs in a background goroutine.
func (s *Server) cleanupStaleBuckets() {
	ticker := time.NewTicker(rateBucketCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.sensorRateMu.Lock()
			now := time.Now()
			for key, bucket := range s.sensorRates {
				if now.After(bucket.windowEnd.Add(rateBucketCleanupInterval)) {
					delete(s.sensorRates, key)
				}
			}
			s.sensorRateMu.Unlock()
		case <-s.stopCleanup:
			return
		}
	}
}

// sensorState tracks per-sensor connection state.
type sensorState struct {
	sensorID    string
	tenantID    string
	connectedAt time.Time
	lastBatchAt time.Time
	eventsRecv  int64
	batchesRecv int64
}

// NewServer creates a new gateway gRPC server.
func NewServer(log *zap.Logger, publisher EventPublisher, maxEventsPerSec int64, backendURL, internalToken string) *Server {
	srv := &Server{
		log:             log.Named("grpc"),
		publisher:       publisher,
		maxEventsPerSec: maxEventsPerSec,
		sensorRates:     make(map[string]*rateBucket),
		activeSensors:   make(map[string]*sensorState),
		stopCleanup:     make(chan struct{}),
		backendURL:      backendURL,
		internalToken:   internalToken,
		httpClient:      &http.Client{Timeout: 5 * time.Second},
	}
	go srv.cleanupStaleBuckets()
	return srv
}

// Stop shuts down background goroutines. Safe to call multiple times.
func (s *Server) Stop() {
	s.stopOnce.Do(func() { close(s.stopCleanup) })
}

// ── Input validation helpers ─────────────────────────────────────────────────

// truncateStr limits a string to maxLen, preventing oversized payloads.
func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// namespaceSensorID creates a tenant-scoped sensor key to prevent cross-tenant
// sensor ID spoofing. A valid token for tenant A cannot claim sensor IDs that
// collide with tenant B's sensors.
func namespaceSensorID(tenantID, sensorID string) string {
	return fmt.Sprintf("%s/%s", tenantID, sensorID)
}

// validateBatch performs input validation on an incoming event batch.
// Returns an error string if validation fails, empty string if OK.
func validateBatch(batch *pb.IngestEventsRequest) string {
	if len(batch.Events) == 0 {
		return "batch contains no events"
	}
	if len(batch.Events) > maxBatchSize {
		return fmt.Sprintf("batch too large: %d events exceeds max %d", len(batch.Events), maxBatchSize)
	}
	if batch.SensorId == "" {
		return "sensor_id is required"
	}
	if len(batch.SensorId) > maxSensorIDLength {
		return fmt.Sprintf("sensor_id too long: %d bytes exceeds max %d", len(batch.SensorId), maxSensorIDLength)
	}
	return ""
}

// validateEvent checks a single event for valid fields. Returns error string or "".
func validateEvent(evt *pb.PhantexEvent) string {
	if len(evt.EventId) > maxEventIDLength {
		return "event_id too long"
	}
	// Reject unspecified (0) and unknown event types
	if _, ok := validEventTypes[evt.EventType]; !ok {
		return fmt.Sprintf("invalid event_type: %d (%s)", int32(evt.EventType), evt.EventType.String())
	}
	return ""
}

// truncatePayloadFields truncates string fields inside each payload variant
// to prevent oversized data from reaching Kafka. Operates on the oneof payload.
func truncatePayloadFields(evt *pb.PhantexEvent) {
	switch p := evt.Payload.(type) {
	case *pb.PhantexEvent_ProcessExec:
		if p.ProcessExec != nil {
			p.ProcessExec.Comm = truncateStr(p.ProcessExec.Comm, maxFieldLength)
			p.ProcessExec.Filename = truncateStr(p.ProcessExec.Filename, maxFieldLength)
			p.ProcessExec.Argv = truncateStr(p.ProcessExec.Argv, maxFieldLength)
			p.ProcessExec.Cgroup = truncateStr(p.ProcessExec.Cgroup, maxFieldLength)
		}
	case *pb.PhantexEvent_File:
		if p.File != nil {
			p.File.Comm = truncateStr(p.File.Comm, maxFieldLength)
			p.File.Filename = truncateStr(p.File.Filename, maxFieldLength)
		}
	case *pb.PhantexEvent_Network:
		if p.Network != nil {
			p.Network.DstAddr = truncateStr(p.Network.DstAddr, maxFieldLength)
		}
	case *pb.PhantexEvent_Dns:
		if p.Dns != nil {
			p.Dns.QueryName = truncateStr(p.Dns.QueryName, maxFieldLength)
			p.Dns.DstAddr = truncateStr(p.Dns.DstAddr, maxFieldLength)
		}
	// ProcessExit, Memory, ToolCall, ToolResponse, Lifecycle, Alert:
	// no large user-controlled string fields in Phase 1
	default:
		// unknown or nil payload — nothing to truncate
	}
}

// IngestEvents handles the bidirectional streaming RPC from sensors.
// Sensor sends IngestEventsRequest (batches), gateway responds with IngestEventsResponse (acks).
func (s *Server) IngestEvents(stream pb.SensorService_IngestEventsServer) error {
	// Extract authenticated tenant ID from context (set by auth interceptor)
	tenantID := auth.TenantIDFromContext(stream.Context())
	if tenantID == "" {
		return status.Error(codes.Unauthenticated, "no tenant ID in context")
	}

	s.log.Info("sensor stream connected",
		zap.String("tenant_id", tenantID))

	// Track this sensor connection (namespaced key)
	var sensorID string     // raw sensor ID from batch
	var namespacedID string // tenantID/sensorID — used as map key
	defer func() {
		if namespacedID != "" {
			s.mu.Lock()
			delete(s.activeSensors, namespacedID)
			s.mu.Unlock()
			s.log.Info("sensor stream disconnected",
				zap.String("sensor_id", sensorID),
				zap.String("tenant_id", tenantID))
		}
	}()

	// Idle timer — reusable, prevents timer churn from time.After in a hot loop.
	// Under high throughput, time.After per iteration would create thousands of
	// pending timers before the first fires, causing allocation churn and GC pressure.
	idleTimer := time.NewTimer(streamIdleTimeout)
	defer idleTimer.Stop()

	for {
		// Idle timeout — close streams that stop sending batches (ADR: defense against
		// authenticated-but-idle connections pinning goroutines and activeSensors slots).
		if err := stream.Context().Err(); err != nil {
			return err
		}

		// Set a per-Recv deadline so idle streams don't block goroutines forever.
		// We use a channel-based pattern to avoid data races between the recv
		// goroutine and the timeout select case.
		type recvResult struct {
			batch *pb.IngestEventsRequest
			err   error
		}
		recvCh := make(chan recvResult, 1)
		go func() {
			b, e := stream.Recv()
			recvCh <- recvResult{batch: b, err: e}
		}()

		var batch *pb.IngestEventsRequest
		var recvErr error

		select {
		case res := <-recvCh:
			batch = res.batch
			recvErr = res.err
			// Reset idle timer after successful receive
			if !idleTimer.Stop() {
				select {
				case <-idleTimer.C:
				default:
				}
			}
			idleTimer.Reset(streamIdleTimeout)
		case <-idleTimer.C:
			s.log.Info("stream idle timeout",
				zap.String("tenant_id", tenantID),
				zap.Duration("idle", streamIdleTimeout))
			return status.Error(codes.DeadlineExceeded, "stream idle timeout")
		}

		err := recvErr
		if err == io.EOF {
			return nil // client closed stream gracefully
		}
		if err != nil {
			return err // connection error
		}

		// ── Input validation ─────────────────────────────────────────
		if reason := validateBatch(batch); reason != "" {
			s.rejectedBatches.Add(1)
			ack := &pb.IngestEventsResponse{
				BatchId:      batch.BatchId,
				Accepted:     false,
				RejectReason: reason,
				ServerTime:   timestamppb.Now(),
			}
			if err := stream.Send(ack); err != nil {
				return err
			}
			continue
		}

		// Validate individual events (truncate oversized fields, reject invalid types)
		validEvents := make([]*pb.PhantexEvent, 0, len(batch.Events))
		for _, evt := range batch.Events {
			if reason := validateEvent(evt); reason != "" {
				s.log.Warn("event validation failed, skipping",
					zap.String("reason", reason),
					zap.String("event_id", truncateStr(evt.EventId, 64)))
				continue
			}
			// Truncate envelope string fields
			evt.EventId = truncateStr(evt.EventId, maxEventIDLength)
			evt.SensorId = truncateStr(evt.SensorId, maxSensorIDLength)
			// Truncate nested payload string fields
			truncatePayloadFields(evt)
			validEvents = append(validEvents, evt)
		}

		if len(validEvents) == 0 {
			s.rejectedBatches.Add(1)
			ack := &pb.IngestEventsResponse{
				BatchId:      batch.BatchId,
				Accepted:     false,
				RejectReason: "all events in batch failed validation",
				ServerTime:   timestamppb.Now(),
			}
			if err := stream.Send(ack); err != nil {
				return err
			}
			continue
		}

		// First batch establishes sensor identity (namespaced by tenant)
		if namespacedID == "" {
			sensorID = truncateStr(batch.SensorId, maxSensorIDLength)
			namespacedID = namespaceSensorID(tenantID, sensorID)

			// Memory guard: limit active sensors per tenant
			s.mu.Lock()
			tenantSensorCount := 0
			for _, st := range s.activeSensors {
				if st.tenantID == tenantID {
					tenantSensorCount++
				}
			}
			if tenantSensorCount >= maxSensorsPerTenant {
				s.mu.Unlock()
				s.log.Warn("too many sensors for tenant",
					zap.String("tenant_id", tenantID),
					zap.Int("count", tenantSensorCount))
				return status.Error(codes.ResourceExhausted, "too many sensors for this tenant")
			}
			s.activeSensors[namespacedID] = &sensorState{
				sensorID:    sensorID,
				tenantID:    tenantID,
				connectedAt: time.Now(),
			}
			s.mu.Unlock()
			s.log.Info("sensor identified",
				zap.String("sensor_id", sensorID),
				zap.String("tenant_id", tenantID))
		}

		// Validate tenant_id on every batch (sensor can only send for its own tenant)
		if batch.TenantId != "" && batch.TenantId != tenantID {
			s.rejectedBatches.Add(1)
			ack := &pb.IngestEventsResponse{
				BatchId:      batch.BatchId,
				Accepted:     false,
				RejectReason: "tenant_id mismatch",
				ServerTime:   timestamppb.Now(),
			}
			if err := stream.Send(ack); err != nil {
				return err
			}
			continue
		}

		// Rate limit check — keyed by authenticated tenantID (not attacker-controlled sensorID)
		eventCount := int64(len(validEvents))
		if !s.checkRate(tenantID, eventCount) {
			s.rejectedBatches.Add(1)
			ack := &pb.IngestEventsResponse{
				BatchId:      batch.BatchId,
				Accepted:     false,
				RejectReason: "rate limit exceeded",
				ServerTime:   timestamppb.Now(),
			}
			if err := stream.Send(ack); err != nil {
				return err
			}
			continue
		}

		// Stamp tenant_id on every event — ENFORCE authenticated tenant
		// Defense in depth: always overwrite with authenticated tenant_id
		// Also stamp sensor_id from the authenticated stream to prevent
		// intra-tenant sensor impersonation.
		for _, evt := range validEvents {
			evt.TenantId = tenantID
			evt.SensorId = sensorID
		}

		// Publish to downstream bus
		if err := s.publisher.Publish(tenantID, validEvents); err != nil {
			s.log.Error("failed to publish batch",
				zap.String("sensor_id", sensorID),
				zap.Uint64("batch_id", batch.BatchId),
				zap.Error(err))

			ack := &pb.IngestEventsResponse{
				BatchId:      batch.BatchId,
				Accepted:     false,
				RejectReason: "internal publish error",
				ServerTime:   timestamppb.Now(),
			}
			if err := stream.Send(ack); err != nil {
				return err
			}
			continue
		}

		// Update stats
		s.totalEvents.Add(eventCount)
		s.totalBatches.Add(1)

		s.mu.Lock()
		if st, ok := s.activeSensors[namespacedID]; ok {
			st.eventsRecv += eventCount
			st.batchesRecv++
			st.lastBatchAt = time.Now()
		}
		s.mu.Unlock()

		if batch.EventsDropped > 0 {
			s.log.Warn("sensor reported dropped events",
				zap.String("sensor_id", sensorID),
				zap.Uint64("events_dropped", batch.EventsDropped))
		}

		// Send acknowledgment
		ack := &pb.IngestEventsResponse{
			BatchId:    batch.BatchId,
			Accepted:   true,
			ServerTime: timestamppb.Now(),
		}
		if err := stream.Send(ack); err != nil {
			return err
		}
	}
}

// sensorIDRe validates sensor IDs to prevent SSRF via path traversal.
// Accepts UUIDs, alphanumeric strings with hyphens/underscores (max 256 chars).
var sensorIDRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_\-]{0,254}[a-zA-Z0-9]$`)

// Heartbeat handles sensor health checks.
func (s *Server) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	tenantID := auth.TenantIDFromContext(ctx)
	if tenantID == "" {
		return nil, status.Error(codes.Unauthenticated, "no tenant ID in context")
	}

	s.log.Debug("heartbeat received",
		zap.String("sensor_id", truncateStr(req.SensorId, maxSensorIDLength)))

	// ── Forward heartbeat to backend for persistence ────────────────
	if s.backendURL != "" && sensorIDRe.MatchString(req.SensorId) {
		go s.forwardHeartbeat(tenantID, req)
	}

	resp := &pb.HeartbeatResponse{
		ServerTime: timestamppb.Now(),
	}

	// ── Command relay: poll backend for queued response actions ──────
	// SECURITY: sensorID comes from the sensor's gRPC request. We validate
	// it against a strict regex before using it in an HTTP URL to prevent
	// SSRF / path-traversal attacks (e.g., "../../admin/secrets").
	if s.backendURL != "" && sensorIDRe.MatchString(req.SensorId) {
		commands, err := s.fetchPendingCommands(ctx, tenantID, req.SensorId)
		if err != nil {
			s.log.Warn("failed to fetch pending commands",
				zap.String("sensor_id", truncateStr(req.SensorId, maxSensorIDLength)),
				zap.Error(err))
			// Non-fatal: return heartbeat without commands
		} else if len(commands) > 0 {
			resp.Commands = commands
			s.log.Info("relaying commands to sensor",
				zap.String("sensor_id", truncateStr(req.SensorId, maxSensorIDLength)),
				zap.Int("count", len(commands)))
		}
	} else if s.backendURL != "" {
		s.log.Warn("invalid sensor_id in heartbeat — skipping command fetch",
			zap.String("sensor_id", truncateStr(req.SensorId, maxSensorIDLength)))
	}

	return resp, nil
}

// ── Backend heartbeat & registration forwarding ──────────────────────────────

// heartbeatPayload is the JSON body for the backend internal heartbeat endpoint.
type heartbeatPayload struct {
	SensorID string                 `json:"sensor_id"`
	TenantID string                 `json:"tenant_id"`
	Metrics  map[string]interface{} `json:"metrics"`
}

// forwardHeartbeat sends a sensor's heartbeat + metrics to the backend internal API.
// Runs in a goroutine — fire-and-forget with a single retry.
func (s *Server) forwardHeartbeat(tenantID string, req *pb.HeartbeatRequest) {
	metrics := make(map[string]interface{})
	if m := req.Metrics; m != nil {
		metrics["events_read"] = m.EventsRead
		metrics["events_sent"] = m.EventsSent
		metrics["events_dropped"] = m.EventsDropped
		metrics["parse_errors"] = m.ParseErrors
		metrics["probes_loaded"] = m.ProbesLoaded
		metrics["probes_total"] = m.ProbesTotal
		metrics["agents_tracked"] = m.AgentsTracked
		metrics["uptime_seconds"] = m.UptimeSeconds
		metrics["cpu_percent"] = m.CpuPercent
		metrics["memory_bytes"] = m.MemoryBytes
		metrics["buffer_used"] = m.BufferUsed
	}

	payload := heartbeatPayload{
		SensorID: truncateStr(req.SensorId, maxSensorIDLength),
		TenantID: tenantID,
		Metrics:  metrics,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		s.log.Error("marshal heartbeat payload", zap.Error(err))
		return
	}

	apiURL := fmt.Sprintf("%s/api/internal/sensors/heartbeat", s.backendURL)

	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			time.Sleep(500 * time.Millisecond)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		httpReq, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(body))
		if reqErr != nil {
			cancel()
			s.log.Error("create heartbeat request", zap.Error(reqErr))
			return
		}
		httpReq.Header.Set("X-Internal-Token", s.internalToken)
		httpReq.Header.Set("Content-Type", "application/json")

		resp, doErr := s.httpClient.Do(httpReq)
		cancel()
		if doErr != nil {
			s.log.Warn("heartbeat forward failed (will retry)",
				zap.String("sensor_id", truncateStr(req.SensorId, maxSensorIDLength)),
				zap.Int("attempt", attempt+1),
				zap.Error(doErr))
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			s.log.Debug("heartbeat forwarded to backend",
				zap.String("sensor_id", truncateStr(req.SensorId, maxSensorIDLength)))
			return
		}

		s.log.Warn("heartbeat forward non-200",
			zap.String("sensor_id", truncateStr(req.SensorId, maxSensorIDLength)),
			zap.Int("status_code", resp.StatusCode))
	}
}

// registrationPayload is the JSON body for the backend internal register endpoint.
type registrationPayload struct {
	SensorID     string `json:"sensor_id"`
	TenantID     string `json:"tenant_id"`
	Hostname     string `json:"hostname,omitempty"`
	IPAddress    string `json:"ip_address,omitempty"`
	Kernel       string `json:"kernel,omitempty"`
	Arch         string `json:"arch,omitempty"`
	Version      string `json:"version,omitempty"`
	OsType       string `json:"os_type,omitempty"`
	ProbesLoaded int    `json:"probes_loaded"`
	ProbesTotal  int    `json:"probes_total"`
}

// forwardRegistration sends a sensor's registration to the backend internal API.
// Retries up to 3 times with backoff — registration is important.
func (s *Server) forwardRegistration(tenantID, peerIP string, req *pb.RegisterSensorRequest) {
	// Infer OS type from kernel version string
	osType := "linux" // default for eBPF sensors
	kernel := truncateStr(req.Kernel, maxFieldLength)
	if kernel != "" {
		lower := kernel
		for _, sig := range []string{"microsoft", "windows", "win32"} {
			if containsCI(lower, sig) {
				osType = "windows"
				break
			}
		}
		for _, sig := range []string{"darwin", "xnu"} {
			if containsCI(lower, sig) {
				osType = "macos"
				break
			}
		}
	}

	payload := registrationPayload{
		SensorID:  truncateStr(req.SensorId, maxSensorIDLength),
		TenantID:  tenantID,
		Hostname:  truncateStr(req.Hostname, maxFieldLength),
		IPAddress: peerIP,
		Kernel:    kernel,
		Arch:      truncateStr(req.Arch, 32),
		Version:   truncateStr(req.Version, maxFieldLength),
		OsType:    osType,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		s.log.Error("marshal registration payload", zap.Error(err))
		return
	}

	apiURL := fmt.Sprintf("%s/api/internal/sensors/register", s.backendURL)

	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*attempt) * 500 * time.Millisecond)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		httpReq, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(body))
		if reqErr != nil {
			cancel()
			s.log.Error("create registration request", zap.Error(reqErr))
			return
		}
		httpReq.Header.Set("X-Internal-Token", s.internalToken)
		httpReq.Header.Set("Content-Type", "application/json")

		resp, doErr := s.httpClient.Do(httpReq)
		cancel()
		if doErr != nil {
			s.log.Warn("registration forward failed (will retry)",
				zap.String("sensor_id", truncateStr(req.SensorId, maxSensorIDLength)),
				zap.Int("attempt", attempt+1),
				zap.Error(doErr))
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			s.log.Info("sensor registration forwarded to backend",
				zap.String("sensor_id", truncateStr(req.SensorId, maxSensorIDLength)),
				zap.String("tenant_id", tenantID))
			return
		}

		s.log.Warn("registration forward non-200",
			zap.String("sensor_id", truncateStr(req.SensorId, maxSensorIDLength)),
			zap.Int("status_code", resp.StatusCode))
	}

	s.log.Error("registration forward failed after 3 attempts",
		zap.String("sensor_id", truncateStr(req.SensorId, maxSensorIDLength)))
}

// containsCI checks if s contains substr, case-insensitive.
func containsCI(s, substr string) bool {
	return len(s) >= len(substr) &&
		len(substr) > 0 &&
		// Simple ASCII lowercase comparison
		func() bool {
			sl := make([]byte, len(s))
			for i := range s {
				c := s[i]
				if c >= 'A' && c <= 'Z' {
					c += 32
				}
				sl[i] = c
			}
			sub := make([]byte, len(substr))
			for i := range substr {
				c := substr[i]
				if c >= 'A' && c <= 'Z' {
					c += 32
				}
				sub[i] = c
			}
			for i := 0; i <= len(sl)-len(sub); i++ {
				match := true
				for j := 0; j < len(sub); j++ {
					if sl[i+j] != sub[j] {
						match = false
						break
					}
				}
				if match {
					return true
				}
			}
			return false
		}()
}

// ── Backend command polling ──────────────────────────────────────────────────

// backendCommand represents a pending command from the backend API.
type backendCommand struct {
	ID          string                 `json:"id"`
	CommandType string                 `json:"command_type"`
	Parameters  map[string]interface{} `json:"parameters"`
	AlertID     string                 `json:"alert_id,omitempty"`
	Reason      string                 `json:"reason"`
}

// commandTypeToAction maps backend command_type strings to proto ControlAction values.
var commandTypeToAction = map[string]pb.ControlAction{
	"isolate_host":      pb.ControlAction_CONTROL_ACTION_ISOLATE_HOST,
	"unisolate_host":    pb.ControlAction_CONTROL_ACTION_UNISOLATE_HOST,
	"kill_process":      pb.ControlAction_CONTROL_ACTION_KILL_PROCESS,
	"block_ip":          pb.ControlAction_CONTROL_ACTION_BLOCK_IP,
	"unblock_ip":        pb.ControlAction_CONTROL_ACTION_UNBLOCK_IP,
	"quarantine_file":   pb.ControlAction_CONTROL_ACTION_QUARANTINE_FILE,
	"collect_forensics": pb.ControlAction_CONTROL_ACTION_COLLECT_FORENSICS,
}

// fetchPendingCommands calls the backend internal API to get queued commands.
// SECURITY: sensorID is pre-validated by the caller against sensorIDRe.
// tenantID comes from the authenticated gRPC context (cannot be spoofed).
func (s *Server) fetchPendingCommands(ctx context.Context, tenantID, sensorID string) ([]*pb.ControlCommand, error) {
	// URL-encode sensorID as an additional defense layer against path traversal
	safeSensorID := url.PathEscape(sensorID)
	apiURL := fmt.Sprintf("%s/api/internal/commands/pending/%s", s.backendURL, safeSensorID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("X-Internal-Token", s.internalToken)
	// Pass tenant ID so the backend can scope the query (defense-in-depth)
	req.Header.Set("X-Tenant-ID", tenantID)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("backend returned %d", resp.StatusCode)
	}

	// Limit response body to 10 MB to prevent OOM from malicious/broken backend
	limitedBody := io.LimitReader(resp.Body, 10*1024*1024)

	var cmds []backendCommand
	if err := json.NewDecoder(limitedBody).Decode(&cmds); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	if len(cmds) == 0 {
		return nil, nil
	}

	// Convert backend commands → proto ControlCommand
	var protoCommands []*pb.ControlCommand
	for _, cmd := range cmds {
		action, ok := commandTypeToAction[cmd.CommandType]
		if !ok {
			s.log.Warn("unknown command type from backend",
				zap.String("command_type", cmd.CommandType),
				zap.String("command_id", cmd.ID))
			continue
		}

		// Flatten parameters to string map for proto
		params := make(map[string]string)
		for k, v := range cmd.Parameters {
			switch val := v.(type) {
			case string:
				params[k] = val
			default:
				b, _ := json.Marshal(val)
				params[k] = string(b)
			}
		}

		protoCommands = append(protoCommands, &pb.ControlCommand{
			Action:    action,
			Params:    params,
			CommandId: cmd.ID,
		})

		// Mark as dispatched in background (fire-and-forget)
		go s.ackCommand(cmd.ID, "dispatched", nil)
	}

	return protoCommands, nil
}

// commandAckPayload is the JSON body for the backend /ack endpoint.
type commandAckPayload struct {
	CommandID string                 `json:"command_id"`
	Status    string                 `json:"status"`
	Result    map[string]interface{} `json:"result,omitempty"`
}

// ackCommand reports command status back to the backend API.
// Retries up to 3 times with exponential backoff to prevent silent failures
// that could cause duplicate command dispatch.
func (s *Server) ackCommand(commandID, ackStatus string, result map[string]interface{}) {
	payload := commandAckPayload{
		CommandID: commandID,
		Status:    ackStatus,
		Result:    result,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		s.log.Error("marshal ack payload", zap.Error(err))
		return
	}

	apiURL := fmt.Sprintf("%s/api/internal/commands/ack", s.backendURL)

	// Retry loop with exponential backoff
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*attempt) * 500 * time.Millisecond) // 0, 500ms, 2s
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(body))
		if reqErr != nil {
			cancel()
			s.log.Error("create ack request", zap.Error(reqErr))
			return // non-retryable
		}
		req.Header.Set("X-Internal-Token", s.internalToken)
		req.Header.Set("Content-Type", "application/json")

		resp, doErr := s.httpClient.Do(req)
		cancel()
		if doErr != nil {
			s.log.Warn("ack command failed (will retry)",
				zap.String("command_id", commandID),
				zap.Int("attempt", attempt+1),
				zap.Error(doErr))
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			return // success
		}

		s.log.Warn("ack command non-200 (will retry)",
			zap.String("command_id", commandID),
			zap.Int("attempt", attempt+1),
			zap.Int("status_code", resp.StatusCode))
	}

	s.log.Error("ack command failed after 3 attempts — command may be re-dispatched",
		zap.String("command_id", commandID),
		zap.String("status", ackStatus))
}

// RegisterSensor handles sensor registration on startup.
func (s *Server) RegisterSensor(ctx context.Context, req *pb.RegisterSensorRequest) (*pb.RegisterSensorResponse, error) {
	tenantID := auth.TenantIDFromContext(ctx)
	if tenantID == "" {
		return nil, status.Error(codes.Unauthenticated, "no tenant ID in context")
	}

	// Validate that the sensor's claimed tenant matches the token's tenant
	if req.TenantId != "" && req.TenantId != tenantID {
		return &pb.RegisterSensorResponse{
			Accepted:     false,
			RejectReason: "tenant_id mismatch",
		}, nil
	}

	s.log.Info("sensor registered",
		zap.String("sensor_id", truncateStr(req.SensorId, maxSensorIDLength)),
		zap.String("tenant_id", tenantID),
		zap.String("version", truncateStr(req.Version, maxFieldLength)),
		zap.String("hostname", truncateStr(req.Hostname, maxFieldLength)),
		zap.String("kernel", truncateStr(req.Kernel, maxFieldLength)),
		zap.String("arch", truncateStr(req.Arch, 32)))

	// Forward registration to backend for persistence
	if s.backendURL != "" && sensorIDRe.MatchString(req.SensorId) {
		var peerIP string
		if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
			peerIP = p.Addr.String()
			// Strip port
			if host, _, err := net.SplitHostPort(peerIP); err == nil {
				peerIP = host
			}
		}
		go s.forwardRegistration(tenantID, peerIP, req)
	}

	return &pb.RegisterSensorResponse{
		Accepted: true,
	}, nil
}

// ─── Stats ────────────────────────────────────────────────────────────────────

// Stats returns current gateway statistics.
type Stats struct {
	ActiveSensors   int
	TotalEvents     int64
	TotalBatches    int64
	RejectedBatches int64
}

// GetStats returns current gateway statistics.
func (s *Server) GetStats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Stats{
		ActiveSensors:   len(s.activeSensors),
		TotalEvents:     s.totalEvents.Load(),
		TotalBatches:    s.totalBatches.Load(),
		RejectedBatches: s.rejectedBatches.Load(),
	}
}
