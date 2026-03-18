// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Package enricher resolves kernel-level event metadata into
// human-readable context:
//   - PID → process name, executable path
//   - PID → container ID (via cgroup)
//   - PID → cgroup namespace
//
// This is a lightweight /proc-based enricher. It caches lookups
// to avoid repeated filesystem reads for the same PID.
package enricher

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ProcessInfo contains enriched metadata for a process.
type ProcessInfo struct {
	PID         uint32
	Comm        string // short name (from /proc/pid/comm)
	Exe         string // full executable path (from /proc/pid/exe)
	ContainerID string // 64-char hex container ID (empty if not in container)
	CgroupPath  string // raw cgroup path
	CachedAt    time.Time
}

// Enricher provides PID → metadata resolution with caching.
type Enricher struct {
	log   *zap.Logger
	mu    sync.RWMutex
	cache map[uint32]*ProcessInfo
	ttl   time.Duration
}

// New creates a new process enricher.
// ttl controls how long cached entries are valid (0 = no expiry).
func New(log *zap.Logger, ttl time.Duration) *Enricher {
	if ttl == 0 {
		ttl = 30 * time.Second
	}
	return &Enricher{
		log:   log,
		cache: make(map[uint32]*ProcessInfo),
		ttl:   ttl,
	}
}

// Enrich returns enriched process info for a PID.
// Returns cached data if available and not expired.
func (e *Enricher) Enrich(pid uint32) *ProcessInfo {
	// Check cache first
	e.mu.RLock()
	if info, ok := e.cache[pid]; ok && time.Since(info.CachedAt) < e.ttl {
		e.mu.RUnlock()
		return info
	}
	e.mu.RUnlock()

	// Cache miss — read from /proc
	info := e.readProc(pid)

	e.mu.Lock()
	e.cache[pid] = info
	e.mu.Unlock()

	return info
}

// Evict removes a PID from the cache (call when process exits).
func (e *Enricher) Evict(pid uint32) {
	e.mu.Lock()
	delete(e.cache, pid)
	e.mu.Unlock()
}

// CacheSize returns the current number of cached entries.
func (e *Enricher) CacheSize() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.cache)
}

// readProc reads process info from /proc filesystem.
func (e *Enricher) readProc(pid uint32) *ProcessInfo {
	info := &ProcessInfo{
		PID:      pid,
		CachedAt: time.Now(),
	}

	procDir := fmt.Sprintf("/proc/%d", pid)

	// Read comm (process name)
	if data, err := os.ReadFile(procDir + "/comm"); err == nil {
		info.Comm = strings.TrimSpace(string(data))
	}

	// Read exe (executable path, symlink)
	if target, err := os.Readlink(procDir + "/exe"); err == nil {
		info.Exe = target
	}

	// Read cgroup to extract container ID
	if data, err := os.ReadFile(procDir + "/cgroup"); err == nil {
		info.CgroupPath, info.ContainerID = parseCgroup(string(data))
	}

	return info
}

// parseCgroup extracts the cgroup path and container ID from /proc/pid/cgroup.
//
// Docker cgroup v2 format:
//
//	0::/system.slice/docker-<containerID>.scope
//
// Docker cgroup v1 format:
//
//	12:memory:/docker/<containerID>
//
// K8s format:
//
//	0::/kubepods/besteffort/pod<podUID>/<containerID>
func parseCgroup(data string) (cgroupPath, containerID string) {
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		cgroupPath = parts[2]

		// Try to extract container ID
		// Docker cgroup v2: .../docker-<64hex>.scope
		if idx := strings.Index(cgroupPath, "docker-"); idx != -1 {
			id := cgroupPath[idx+7:]
			if dot := strings.Index(id, "."); dot != -1 {
				id = id[:dot]
			}
			if len(id) == 64 && isHex(id) {
				containerID = id
				return
			}
		}

		// Docker cgroup v1: .../docker/<64hex>
		if idx := strings.Index(cgroupPath, "/docker/"); idx != -1 {
			id := cgroupPath[idx+8:]
			if len(id) >= 64 && isHex(id[:64]) {
				containerID = id[:64]
				return
			}
		}

		// K8s containerd: .../<64hex>
		segments := strings.Split(cgroupPath, "/")
		if last := segments[len(segments)-1]; len(last) == 64 && isHex(last) {
			containerID = last
			return
		}
	}
	return
}

// isHex checks if a string contains only hexadecimal characters.
func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}
