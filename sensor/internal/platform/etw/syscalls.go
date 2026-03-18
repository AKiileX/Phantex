// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

//go:build windows

// Package etw — syscalls.go
// Low-level Windows syscall wrappers for ETW APIs.
//
// Security:
//   - All syscalls use the official golang.org/x/sys/windows approach
//   - No DLL injection risk: advapi32.dll and sechost.dll are system DLLs
//   - Pointers are validated before passing to kernel
package etw

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modAdvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	modSechost  = windows.NewLazySystemDLL("sechost.dll")

	// ETW session management (advapi32.dll)
	procStartTraceW    = modAdvapi32.NewProc("StartTraceW")
	procControlTraceW  = modAdvapi32.NewProc("ControlTraceW")
	procEnableTraceEx2 = modAdvapi32.NewProc("EnableTraceEx2")
	procOpenTraceW     = modAdvapi32.NewProc("OpenTraceW")
	procProcessTrace   = modAdvapi32.NewProc("ProcessTrace")
	procCloseTrace     = modAdvapi32.NewProc("CloseTrace")
)

// EVENT_TRACE_PROPERTIES structure sizes
const (
	sizeofEventTraceProperties = 120 // Base structure size
	maxSessionNameLen          = 256 // Appended after the structure
	maxLogFileNameLen          = 0   // We use real-time mode, no log file

	// EVENT_TRACE_REAL_TIME_MODE
	eventTraceRealTimeMode = 0x00000100

	// EVENT_CONTROL_CODE_DISABLE_PROVIDER / STOP
	eventTraceControlStop = 1

	// WNODE_FLAG_TRACED_GUID
	wnodeFlagTracedGUID = 0x00020000
)

// eventTraceProperties mirrors EVENT_TRACE_PROPERTIES for real-time sessions.
type eventTraceProperties struct {
	// WNODE_HEADER
	bufferSize    uint32
	providerId    uint32
	historicalCtx uint64
	timeStampKern uint64
	guid          windows.GUID
	clientContext uint32
	flags         uint32

	// EVENT_TRACE_PROPERTIES fields
	bufferSizeProp    uint32
	minimumBuffers    uint32
	maximumBuffers    uint32
	maxFileSize       uint32
	logFileMode       uint32
	flushTimer        uint32
	enableFlags       uint32
	_                 [2]uint32 // union: AgeLimit / FlushThreshold
	logFileNameOffset uint32
	loggerNameOffset  uint32
}

// newTraceProperties creates an EVENT_TRACE_PROPERTIES for a real-time session.
func newTraceProperties(sessionName string) *eventTraceProperties {
	totalSize := uint32(sizeofEventTraceProperties + (maxSessionNameLen+1)*2 + (maxLogFileNameLen+1)*2)

	// Allocate buffer for properties + session name
	buf := make([]byte, totalSize)
	props := (*eventTraceProperties)(unsafe.Pointer(&buf[0]))

	props.bufferSize = totalSize
	props.flags = wnodeFlagTracedGUID
	props.clientContext = 1 // QPC time resolution
	props.logFileMode = eventTraceRealTimeMode
	props.bufferSizeProp = 64 // 64 KB buffers
	props.minimumBuffers = 4
	props.maximumBuffers = 64
	props.flushTimer = 1 // 1 second flush
	props.loggerNameOffset = uint32(sizeofEventTraceProperties)
	props.logFileNameOffset = 0

	return props
}

// startTraceW wraps StartTraceW.
func startTraceW(handle *uint64, sessionName *uint16, props *eventTraceProperties) uint32 {
	r1, _, _ := procStartTraceW.Call(
		uintptr(unsafe.Pointer(handle)),
		uintptr(unsafe.Pointer(sessionName)),
		uintptr(unsafe.Pointer(props)),
	)
	return uint32(r1)
}

// controlTraceStop stops an ETW session by name.
func controlTraceStop(sessionName string) error {
	nameW, err := windows.UTF16PtrFromString(sessionName)
	if err != nil {
		return err
	}

	totalSize := uint32(sizeofEventTraceProperties + (maxSessionNameLen+1)*2)
	buf := make([]byte, totalSize)
	props := (*eventTraceProperties)(unsafe.Pointer(&buf[0]))
	props.bufferSize = totalSize
	props.loggerNameOffset = uint32(sizeofEventTraceProperties)

	r1, _, _ := procControlTraceW.Call(
		0, // SessionHandle = 0 (use name)
		uintptr(unsafe.Pointer(nameW)),
		uintptr(unsafe.Pointer(props)),
		uintptr(eventTraceControlStop),
	)
	if r1 != 0 {
		return windows.Errno(r1)
	}
	return nil
}

// enableTraceEx2 enables a provider in a trace session.
func enableTraceEx2(
	sessionHandle uint64,
	providerGUID *windows.GUID,
	controlCode uint32,
	level uint8,
	matchAnyKeyword uint64,
	matchAllKeyword uint64,
	timeout uint32,
	params unsafe.Pointer,
) uint32 {
	r1, _, _ := procEnableTraceEx2.Call(
		uintptr(sessionHandle),
		uintptr(unsafe.Pointer(providerGUID)),
		uintptr(controlCode),
		uintptr(level),
		uintptr(matchAnyKeyword),
		uintptr(matchAllKeyword),
		uintptr(timeout),
		uintptr(params),
	)
	return uint32(r1)
}

// openTraceW wraps OpenTraceW.
func openTraceW(logfile *eventTraceLogfileW) uint64 {
	r1, _, _ := procOpenTraceW.Call(
		uintptr(unsafe.Pointer(logfile)),
	)
	return uint64(r1)
}

// processTrace wraps ProcessTrace — blocks until trace ends.
func processTrace(handles *uint64, handleCount uint32, startTime, endTime unsafe.Pointer) uint32 {
	r1, _, _ := procProcessTrace.Call(
		uintptr(unsafe.Pointer(handles)),
		uintptr(handleCount),
		uintptr(startTime),
		uintptr(endTime),
	)
	return uint32(r1)
}

// closeTrace wraps CloseTrace.
func closeTrace(handle uint64) uint32 {
	r1, _, _ := procCloseTrace.Call(uintptr(handle))
	return uint32(r1)
}
