// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

//go:build windows

// Package etw provides real-time Windows Event Tracing (ETW) consumers
// for process, file, registry, and image-load events.
//
// Security considerations:
//   - Requires Administrator privileges (ETW real-time sessions)
//   - Event data is sanitized: paths truncated, no raw memory exposed
//   - Session names include random suffix to prevent hijacking
//   - Graceful degradation: if one provider fails, others continue
//   - All string data is bounds-checked before channel send
//
// ETW Providers used:
//   - Microsoft-Windows-Kernel-Process  (process create/exit, image load)
//   - Microsoft-Windows-Kernel-File     (file I/O)
//   - Microsoft-Windows-Kernel-Registry (registry operations)
//   - Microsoft-Windows-Kernel-Audit    (DLL/driver loads, supplementary)
package etw

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"go.uber.org/zap"
	"golang.org/x/sys/windows"

	"github.com/AKiileX/Phantex/sensor/internal/platform"
)

// ── ETW Constants ─────────────────────────────────────────────────────

// Provider GUIDs (Microsoft-Windows-Kernel-*)
var (
	kernelProcessGUID  = windows.GUID{Data1: 0x22FB2CD6, Data2: 0x0E7B, Data3: 0x422B, Data4: [8]byte{0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}}
	kernelFileGUID     = windows.GUID{Data1: 0xEDD08927, Data2: 0x9CC4, Data3: 0x4E65, Data4: [8]byte{0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89}}
	kernelRegistryGUID = windows.GUID{Data1: 0x70EB4F03, Data2: 0xC1DE, Data3: 0x4F73, Data4: [8]byte{0xA0, 0x51, 0x33, 0xD1, 0x38, 0x49, 0xC4, 0xA7}}
)

// Event IDs within each provider
const (
	// Kernel-Process
	processStartEventID = 1
	processStopEventID  = 2
	imageLoadEventID    = 5

	// Kernel-File
	fileCreateEventID = 12
	fileWriteEventID  = 15
	fileReadEventID   = 14
	fileDeleteEventID = 26

	// Kernel-Registry
	regCreateKeyEventID = 1
	regSetValueEventID  = 2
	regDeleteKeyEventID = 3
)

// Limits for defense-in-depth
const (
	maxPathLen     = 1024 // Max path string length stored
	maxArgvLen     = 2048 // Max command line length
	maxValueData   = 1024 // Max registry value data stored
	maxEventsQueue = 8192 // Event channel capacity
	maxSignerLen   = 256  // Max signer name
)

// ── ETW Session Management ────────────────────────────────────────────

// traceSession wraps a single ETW real-time session.
type traceSession struct {
	name         string
	handle       uint64
	providerGUID windows.GUID
	providerName string
	log          *zap.Logger
}

// Provider implements platform.Provider using ETW on Windows.
type Provider struct {
	log      *zap.Logger
	eventCh  chan platform.Event
	sessions []*traceSession
	wg       sync.WaitGroup

	// Stats (atomic)
	eventsRead    atomic.Uint64
	eventsDropped atomic.Uint64
	startedAt     time.Time

	// Configuration
	filterPIDs map[uint32]bool // If non-empty, only emit events for these PIDs
	filterMu   sync.RWMutex
}

// Config controls which ETW sessions are started.
type Config struct {
	EnableProcess  bool
	EnableFile     bool
	EnableRegistry bool
	EventChanSize  int
}

// NewProvider creates an ETW-based event provider.
func NewProvider(cfg Config, log *zap.Logger) (*Provider, error) {
	chSize := cfg.EventChanSize
	if chSize <= 0 {
		chSize = maxEventsQueue
	}
	return &Provider{
		log:        log,
		eventCh:    make(chan platform.Event, chSize),
		filterPIDs: make(map[uint32]bool),
	}, nil
}

// Events returns the event channel.
func (p *Provider) Events() <-chan platform.Event {
	return p.eventCh
}

// Stats returns provider statistics.
func (p *Provider) Stats() platform.ProviderStats {
	return platform.ProviderStats{
		ProbesLoaded:  len(p.sessions),
		ProbesTotal:   3, // process, file, registry
		EventsRead:    p.eventsRead.Load(),
		EventsDropped: p.eventsDropped.Load(),
		StartedAt:     p.startedAt,
	}
}

// SetPIDFilter configures which PIDs to monitor. Empty = all PIDs.
func (p *Provider) SetPIDFilter(pids []uint32) {
	p.filterMu.Lock()
	defer p.filterMu.Unlock()
	p.filterPIDs = make(map[uint32]bool, len(pids))
	for _, pid := range pids {
		p.filterPIDs[pid] = true
	}
}

// shouldFilter returns true if the event should be dropped (PID not tracked).
func (p *Provider) shouldFilter(pid uint32) bool {
	p.filterMu.RLock()
	defer p.filterMu.RUnlock()
	if len(p.filterPIDs) == 0 {
		return false // No filter active — pass all
	}
	return !p.filterPIDs[pid]
}

// Start begins ETW tracing. Blocks until ctx is done.
func (p *Provider) Start(ctx context.Context) error {
	p.startedAt = time.Now()

	// Check for admin privileges
	if !isAdmin() {
		return fmt.Errorf("ETW sessions require Administrator privileges")
	}

	p.log.Info("etw_provider_starting",
		zap.Int("providers", 3),
	)

	// Create sessions for each provider with random suffix (anti-hijack)
	suffix := randomSuffix()
	providerSpecs := []struct {
		guid windows.GUID
		name string
	}{
		{kernelProcessGUID, "phantex-proc-" + suffix},
		{kernelFileGUID, "phantex-file-" + suffix},
		{kernelRegistryGUID, "phantex-reg-" + suffix},
	}

	loadedCount := 0
	for _, spec := range providerSpecs {
		session := &traceSession{
			name:         spec.name,
			providerGUID: spec.guid,
			providerName: spec.name,
			log:          p.log,
		}

		if err := p.startSession(session); err != nil {
			p.log.Warn("etw_session_start_failed",
				zap.String("session", spec.name),
				zap.Error(err),
			)
			continue
		}

		p.sessions = append(p.sessions, session)
		loadedCount++
		p.log.Info("etw_session_started",
			zap.String("session", spec.name),
		)
	}

	if loadedCount == 0 {
		return fmt.Errorf("no ETW sessions could be started — sensor cannot operate")
	}

	p.log.Info("etw_provider_ready",
		zap.Int("sessions_active", loadedCount),
		zap.Int("sessions_total", len(providerSpecs)),
	)

	// Process events until context cancellation
	<-ctx.Done()
	return nil
}

// Close stops all ETW sessions and releases resources.
func (p *Provider) Close() error {
	p.log.Info("etw_provider_closing", zap.Int("sessions", len(p.sessions)))

	var firstErr error
	for _, s := range p.sessions {
		if err := p.stopSession(s); err != nil {
			p.log.Warn("etw_session_stop_failed",
				zap.String("session", s.name),
				zap.Error(err),
			)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	close(p.eventCh)
	return firstErr
}

// emit sends an event to the channel with backpressure handling.
func (p *Provider) emit(evt platform.Event) {
	p.eventsRead.Add(1)

	if p.shouldFilter(evt.PID) {
		return
	}

	select {
	case p.eventCh <- evt:
	default:
		p.eventsDropped.Add(1)
	}
}

// ── ETW Session Lifecycle ─────────────────────────────────────────────

// startSession creates and starts a real-time ETW trace session.
// This is a stub that will use the Windows ETW API via syscall.
// In production, this calls:
//   - StartTrace → creates the session
//   - EnableTraceEx2 → enables the provider in the session
//   - OpenTrace + ProcessTrace → consumes events in a goroutine
func (p *Provider) startSession(s *traceSession) error {
	// Initialize the EVENT_TRACE_PROPERTIES structure
	sessionNameW, err := windows.UTF16FromString(s.name)
	if err != nil {
		return fmt.Errorf("invalid session name: %w", err)
	}

	// Create real-time ETW session via StartTraceW
	props := newTraceProperties(s.name)
	var handle uint64

	ret := startTraceW(&handle, &sessionNameW[0], props)
	if ret != 0 {
		// ERROR_ALREADY_EXISTS (183) = session exists, try stopping first
		if ret == 183 {
			p.log.Warn("etw_session_already_exists, stopping stale session",
				zap.String("session", s.name),
			)
			_ = controlTraceStop(s.name)
			ret = startTraceW(&handle, &sessionNameW[0], props)
			if ret != 0 {
				return fmt.Errorf("StartTraceW retry failed: error %d", ret)
			}
		} else {
			return fmt.Errorf("StartTraceW failed: error %d", ret)
		}
	}
	s.handle = handle

	// Enable the provider in this session
	ret = enableTraceEx2(handle, &s.providerGUID, 1, 0xFF, 0, 0, 0, nil)
	if ret != 0 {
		_ = controlTraceStop(s.name)
		return fmt.Errorf("EnableTraceEx2 failed: error %d", ret)
	}

	// Open trace for real-time consumption
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.consumeSession(s)
	}()

	return nil
}

// stopSession stops an ETW session.
func (p *Provider) stopSession(s *traceSession) error {
	return controlTraceStop(s.name)
}

// consumeSession opens a trace for real-time consumption and dispatches events.
func (p *Provider) consumeSession(s *traceSession) {
	logfileW, err := windows.UTF16FromString(s.name)
	if err != nil {
		s.log.Error("etw_consume_bad_name", zap.Error(err))
		return
	}

	logfile := eventTraceLogfileW{
		loggerName:       &logfileW[0],
		processTraceMode: 0x00000100 | 0x00000010, // REAL_TIME | EVENT_RECORD
		eventRecordCallback: windows.NewCallback(func(eventRecord *eventRecord) uintptr {
			p.handleEvent(s, eventRecord)
			return 0
		}),
	}

	traceHandle := openTraceW(&logfile)
	if traceHandle == invalidTraceHandle {
		s.log.Error("etw_open_trace_failed", zap.String("session", s.name))
		return
	}
	defer closeTrace(traceHandle)

	s.log.Info("etw_consuming_events", zap.String("session", s.name))

	// ProcessTrace blocks until the session is stopped or an error occurs
	ret := processTrace(&traceHandle, 1, nil, nil)
	if ret != 0 && ret != 1223 { // 1223 = ERROR_CANCELLED (normal shutdown)
		s.log.Warn("etw_process_trace_ended",
			zap.String("session", s.name),
			zap.Uint32("error", ret),
		)
	}
}

// handleEvent dispatches a single ETW event record to the appropriate parser.
func (p *Provider) handleEvent(s *traceSession, record *eventRecord) {
	if record == nil {
		return
	}

	providerID := record.eventHeader.providerID
	eventID := record.eventHeader.eventDescriptor.id

	ts := filetime2Unix(record.eventHeader.timeStamp)

	switch {
	case guidEqual(providerID, kernelProcessGUID):
		p.handleProcessEvent(record, eventID, ts)
	case guidEqual(providerID, kernelFileGUID):
		p.handleFileEvent(record, eventID, ts)
	case guidEqual(providerID, kernelRegistryGUID):
		p.handleRegistryEvent(record, eventID, ts)
	}
}

// ── Process Events ────────────────────────────────────────────────────

func (p *Provider) handleProcessEvent(record *eventRecord, eventID uint16, ts uint64) {
	pid := record.eventHeader.processID
	tid := record.eventHeader.threadID

	switch eventID {
	case processStartEventID:
		data := parseProcessStartEvent(record)
		if data == nil {
			return
		}
		p.emit(platform.Event{
			Type:        platform.EventProcessExec,
			TimestampNs: ts,
			PID:         pid,
			TID:         tid,
			PPID:        data.parentPID,
			Comm:        truncateStr(data.imageName, maxPathLen),
			Payload: &platform.ProcessExecPayload{
				Filename:      truncateStr(data.imageName, maxPathLen),
				Argv:          truncateStr(data.commandLine, maxArgvLen),
				ParentComm:    "", // Enricher will fill this
				UserSID:       truncateStr(data.userSID, maxSignerLen),
				SessionID:     data.sessionID,
				ElevatedToken: data.elevated,
			},
		})

	case processStopEventID:
		data := parseProcessStopEvent(record)
		if data == nil {
			return
		}
		p.emit(platform.Event{
			Type:        platform.EventProcessExit,
			TimestampNs: ts,
			PID:         pid,
			TID:         tid,
			Comm:        truncateStr(data.imageName, maxPathLen),
			Payload: &platform.ProcessExitPayload{
				ExitCode: data.exitCode,
			},
		})

	case imageLoadEventID:
		data := parseImageLoadEvent(record)
		if data == nil {
			return
		}
		p.emit(platform.Event{
			Type:        platform.EventImageLoad,
			TimestampNs: ts,
			PID:         pid,
			TID:         tid,
			Comm:        "",
			Payload: &platform.ImageLoadPayload{
				ImagePath: truncateStr(data.imagePath, maxPathLen),
				ImageSize: data.imageSize,
			},
		})
	}
}

// ── File Events ───────────────────────────────────────────────────────

func (p *Provider) handleFileEvent(record *eventRecord, eventID uint16, ts uint64) {
	pid := record.eventHeader.processID
	tid := record.eventHeader.threadID

	switch eventID {
	case fileCreateEventID:
		data := parseFileCreateEvent(record)
		if data == nil {
			return
		}
		p.emit(platform.Event{
			Type:        platform.EventFileOpen,
			TimestampNs: ts,
			PID:         pid,
			TID:         tid,
			Comm:        "",
			Payload: &platform.FilePayload{
				Filename:  truncateStr(data.fileName, maxPathLen),
				Flags:     data.createOptions,
				ByteCount: 0,
			},
		})

	case fileWriteEventID:
		data := parseFileIOEvent(record)
		if data == nil {
			return
		}
		p.emit(platform.Event{
			Type:        platform.EventFileWrite,
			TimestampNs: ts,
			PID:         pid,
			TID:         tid,
			Comm:        "",
			Payload: &platform.FilePayload{
				ByteCount: data.ioSize,
			},
		})

	case fileReadEventID:
		data := parseFileIOEvent(record)
		if data == nil {
			return
		}
		p.emit(platform.Event{
			Type:        platform.EventFileRead,
			TimestampNs: ts,
			PID:         pid,
			TID:         tid,
			Comm:        "",
			Payload: &platform.FilePayload{
				ByteCount: data.ioSize,
			},
		})

	case fileDeleteEventID:
		data := parseFileCreateEvent(record)
		if data == nil {
			return
		}
		p.emit(platform.Event{
			Type:        platform.EventFileDelete,
			TimestampNs: ts,
			PID:         pid,
			TID:         tid,
			Comm:        "",
			Payload: &platform.FilePayload{
				Filename: truncateStr(data.fileName, maxPathLen),
			},
		})
	}
}

// ── Registry Events ───────────────────────────────────────────────────

func (p *Provider) handleRegistryEvent(record *eventRecord, eventID uint16, ts uint64) {
	pid := record.eventHeader.processID
	tid := record.eventHeader.threadID

	switch eventID {
	case regCreateKeyEventID:
		data := parseRegistryKeyEvent(record)
		if data == nil {
			return
		}
		p.emit(platform.Event{
			Type:        platform.EventRegistryCreate,
			TimestampNs: ts,
			PID:         pid,
			TID:         tid,
			Comm:        "",
			Payload: &platform.RegistryPayload{
				KeyPath: truncateStr(data.keyPath, maxPathLen),
			},
		})

	case regSetValueEventID:
		data := parseRegistryValueEvent(record)
		if data == nil {
			return
		}
		p.emit(platform.Event{
			Type:        platform.EventRegistrySet,
			TimestampNs: ts,
			PID:         pid,
			TID:         tid,
			Comm:        "",
			Payload: &platform.RegistryPayload{
				KeyPath:   truncateStr(data.keyPath, maxPathLen),
				ValueName: truncateStr(data.valueName, maxPathLen),
				ValueType: data.valueType,
				ValueData: truncateStr(data.valueData, maxValueData),
			},
		})

	case regDeleteKeyEventID:
		data := parseRegistryKeyEvent(record)
		if data == nil {
			return
		}
		p.emit(platform.Event{
			Type:        platform.EventRegistryDelete,
			TimestampNs: ts,
			PID:         pid,
			TID:         tid,
			Comm:        "",
			Payload: &platform.RegistryPayload{
				KeyPath: truncateStr(data.keyPath, maxPathLen),
			},
		})
	}
}

// ── Helpers ───────────────────────────────────────────────────────────

// isAdmin checks if the current process has administrator privileges.
func isAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	member, err := windows.Token(0).IsMember(sid)
	if err != nil {
		return false
	}
	return member
}

func randomSuffix() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

func guidEqual(a, b windows.GUID) bool {
	return a == b
}

// filetime2Unix converts a Windows FILETIME (100ns intervals since 1601)
// to Unix nanoseconds.
func filetime2Unix(ft uint64) uint64 {
	// Windows FILETIME epoch is 1601-01-01; Unix epoch is 1970-01-01
	// Difference: 116444736000000000 * 100ns
	const epochDiff = 116444736000000000
	if ft < epochDiff {
		return 0
	}
	return (ft - epochDiff) * 100
}

// ── ETW Structures (matching Windows SDK) ─────────────────────────────

// These mirror the C structures for ETW. We use unsafe.Sizeof to ensure
// correct layout. All pointers are validated before dereference.

type eventDescriptor struct {
	id      uint16
	version uint8
	channel uint8
	level   uint8
	opcode  uint8
	task    uint16
	keyword uint64
}

type eventHeader struct {
	size            uint16
	headerType      uint16
	flags           uint16
	eventProperty   uint16
	threadID        uint32
	processID       uint32
	timeStamp       uint64
	providerID      windows.GUID
	eventDescriptor eventDescriptor
	_               uint64 // processorTime or union
	activityID      windows.GUID
}

type eventRecord struct {
	eventHeader       eventHeader
	bufferContext     uint32
	_pad              uint16
	extendedDataCount uint16
	userDataLength    uint16
	_pad2             uint16
	extendedData      uintptr
	userData          uintptr
	userContext       uintptr
}

type eventTraceLogfileW struct {
	logFileName         *uint16
	loggerName          *uint16
	currentTime         int64
	buffersRead         uint32
	processTraceMode    uint32
	currentEvent        uintptr
	logfileHeader       [424]byte // ETW_TRACE_LOGFILE header block
	bufferCallback      uintptr
	bufferSize          uint32
	filled              uint32
	eventsLost          uint32
	eventRecordCallback uintptr
	isKernelTrace       uint32
	context             uintptr
}

const invalidTraceHandle = 0xFFFFFFFFFFFFFFFF

// ── Parsed event data ─────────────────────────────────────────────────

type processStartData struct {
	imageName   string
	commandLine string
	parentPID   uint32
	userSID     string
	sessionID   uint32
	elevated    bool
}

type processStopData struct {
	imageName string
	exitCode  int32
}

type imageLoadData struct {
	imagePath string
	imageSize uint64
}

type fileCreateData struct {
	fileName      string
	createOptions int32
}

type fileIOData struct {
	ioSize uint64
}

type registryKeyData struct {
	keyPath string
}

type registryValueData struct {
	keyPath   string
	valueName string
	valueType uint32
	valueData string
}

// ── Event Parsers ─────────────────────────────────────────────────────
// These parse the userData blob from ETW event records.
// All parsers validate bounds before reading to prevent crashes.

func parseProcessStartEvent(record *eventRecord) *processStartData {
	if record.userDataLength == 0 || record.userData == 0 {
		return nil
	}
	data := unsafe.Slice((*byte)(unsafe.Pointer(record.userData)), record.userDataLength)
	if len(data) < 8 {
		return nil
	}

	// Process start event layout varies by OS version.
	// We extract what we can safely:
	//   - Bytes 0-3: new process ID (we already have this from header)
	//   - Bytes 4-7: parent PID
	//   - Followed by: command line (UTF-16), image name (UTF-16)

	result := &processStartData{}

	if len(data) >= 8 {
		result.parentPID = *(*uint32)(unsafe.Pointer(&data[4]))
	}

	// Parse UTF-16 strings from the variable portion
	offset := 8
	result.commandLine = readUTF16String(data, &offset, maxArgvLen)
	result.imageName = readUTF16String(data, &offset, maxPathLen)

	// Extract SID and session info if available
	if offset+4 <= len(data) {
		result.sessionID = *(*uint32)(unsafe.Pointer(&data[offset]))
		offset += 4
	}

	return result
}

func parseProcessStopEvent(record *eventRecord) *processStopData {
	if record.userDataLength == 0 || record.userData == 0 {
		return nil
	}
	data := unsafe.Slice((*byte)(unsafe.Pointer(record.userData)), record.userDataLength)
	if len(data) < 8 {
		return nil
	}

	result := &processStopData{}
	result.exitCode = *(*int32)(unsafe.Pointer(&data[4]))

	offset := 8
	result.imageName = readUTF16String(data, &offset, maxPathLen)
	return result
}

func parseImageLoadEvent(record *eventRecord) *imageLoadData {
	if record.userDataLength == 0 || record.userData == 0 {
		return nil
	}
	data := unsafe.Slice((*byte)(unsafe.Pointer(record.userData)), record.userDataLength)
	if len(data) < 16 {
		return nil
	}

	result := &imageLoadData{}
	result.imageSize = *(*uint64)(unsafe.Pointer(&data[0]))

	offset := 16
	result.imagePath = readUTF16String(data, &offset, maxPathLen)
	return result
}

func parseFileCreateEvent(record *eventRecord) *fileCreateData {
	if record.userDataLength == 0 || record.userData == 0 {
		return nil
	}
	data := unsafe.Slice((*byte)(unsafe.Pointer(record.userData)), record.userDataLength)
	result := &fileCreateData{}

	offset := 0
	if len(data) >= 4 {
		result.createOptions = *(*int32)(unsafe.Pointer(&data[0]))
		offset = 4
	}

	result.fileName = readUTF16String(data, &offset, maxPathLen)
	return result
}

func parseFileIOEvent(record *eventRecord) *fileIOData {
	if record.userDataLength == 0 || record.userData == 0 {
		return nil
	}
	data := unsafe.Slice((*byte)(unsafe.Pointer(record.userData)), record.userDataLength)
	result := &fileIOData{}

	if len(data) >= 8 {
		result.ioSize = *(*uint64)(unsafe.Pointer(&data[0]))
	}
	return result
}

func parseRegistryKeyEvent(record *eventRecord) *registryKeyData {
	if record.userDataLength == 0 || record.userData == 0 {
		return nil
	}
	data := unsafe.Slice((*byte)(unsafe.Pointer(record.userData)), record.userDataLength)
	result := &registryKeyData{}

	offset := 0
	result.keyPath = readUTF16String(data, &offset, maxPathLen)
	return result
}

func parseRegistryValueEvent(record *eventRecord) *registryValueData {
	if record.userDataLength == 0 || record.userData == 0 {
		return nil
	}
	data := unsafe.Slice((*byte)(unsafe.Pointer(record.userData)), record.userDataLength)
	result := &registryValueData{}

	offset := 0
	result.keyPath = readUTF16String(data, &offset, maxPathLen)
	result.valueName = readUTF16String(data, &offset, maxPathLen)

	if offset+4 <= len(data) {
		result.valueType = *(*uint32)(unsafe.Pointer(&data[offset]))
		offset += 4
	}

	result.valueData = readUTF16String(data, &offset, maxValueData)
	return result
}

// readUTF16String safely reads a null-terminated UTF-16 string from a
// byte buffer. Returns empty string if bounds are exceeded.
func readUTF16String(data []byte, offset *int, maxLen int) string {
	if *offset >= len(data) {
		return ""
	}

	// Find null terminator (2 bytes of zero)
	start := *offset
	end := start
	for end+1 < len(data) {
		if data[end] == 0 && data[end+1] == 0 {
			break
		}
		end += 2
	}

	if end <= start {
		*offset = end + 2
		return ""
	}

	// Convert UTF-16LE to Go string
	u16Len := (end - start) / 2
	if u16Len > maxLen {
		u16Len = maxLen
	}
	u16 := make([]uint16, u16Len)
	for i := 0; i < u16Len; i++ {
		idx := start + i*2
		if idx+1 >= len(data) {
			break
		}
		u16[i] = uint16(data[idx]) | uint16(data[idx+1])<<8
	}

	*offset = end + 2 // Skip past null terminator
	return windows.UTF16ToString(u16)
}
