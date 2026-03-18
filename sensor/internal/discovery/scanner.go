// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Package discovery — scanner.go
//
// Scans /proc to find processes that are AI agents. Runs on startup
// and then periodically (default every 30s).
//
// Scanning flow:
//  1. List /proc/<pid> directories (numeric only)
//  2. Read /proc/<pid>/comm → skip if not an interpreter (python, node, etc.)
//  3. Read /proc/<pid>/maps → check for framework signatures (high confidence)
//  4. Read /proc/<pid>/cmdline → check for framework signatures (medium confidence)
//  5. Optionally read /proc/<pid>/environ → check for signatures (low confidence, needs caps)
//  6. If any match ≥ ConfidenceMedium → classify as agent → generate PAID → emit event
package discovery

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Agent represents a discovered AI agent process.
type Agent struct {
	PID          uint32
	PAID         string // Phantex Agent ID
	Framework    Framework
	Confidence   Confidence
	Comm         string // short process name
	ExePath      string // resolved /proc/<pid>/exe
	Cmdline      string
	ContainerID  string
	StartTime    uint64 // from /proc/<pid>/stat
	DiscoveredAt time.Time
}

// AgentEvent is emitted when an agent is discovered or terminated.
type AgentEvent struct {
	Type  AgentEventType
	Agent Agent
}

// AgentEventType distinguishes discovery from termination.
type AgentEventType int

const (
	AgentDiscovered AgentEventType = iota
	AgentTerminated
)

func (t AgentEventType) String() string {
	switch t {
	case AgentDiscovered:
		return "AGENT_DISCOVERED"
	case AgentTerminated:
		return "AGENT_TERMINATED"
	default:
		return "UNKNOWN"
	}
}

// ScannerConfig controls scanner behavior.
type ScannerConfig struct {
	ScanInterval       time.Duration // how often to re-scan (default 30s)
	ProcPath           string        // /proc override for testing
	PAIDConfig         PAIDConfig    // tenant/env for PAID generation
	CheckEnviron       bool          // whether to read /proc/<pid>/environ (needs ptrace cap)
	WatchBinaries      []string      // additional binary names to treat as agents (Go/Rust/C++)
	ExcludePatterns    []string      // cmdline substrings that should never be agents
	ExcludeSelf        bool          // exclude PHANTEX infrastructure processes (default true)
	DeduplicateWorkers bool          // group forked workers under parent agent (default true)
}

// DefaultScannerConfig returns sensible defaults.
func DefaultScannerConfig() ScannerConfig {
	return ScannerConfig{
		ScanInterval:       30 * time.Second,
		ProcPath:           "/proc",
		PAIDConfig:         PAIDConfig{TenantSlug: "default", EnvTag: "dev"},
		CheckEnviron:       false, // don't read environ by default (needs extra caps)
		ExcludeSelf:        true,
		DeduplicateWorkers: true,
	}
}

// Scanner discovers AI agent processes by scanning /proc.
type Scanner struct {
	log        *zap.Logger
	cfg        ScannerConfig
	signatures []Signature
	eventCh    chan AgentEvent

	mu     sync.RWMutex
	agents map[uint32]*Agent // tracked agents by PID

	// selfPID is the sensor's own PID, always excluded from discovery.
	selfPID uint32

	// parentAgents maps PPID+Framework to the primary agent PID.
	// Used for worker deduplication: forked workers share the parent's entry.
	parentAgents map[workerGroupKey]uint32
}

// workerGroupKey groups worker processes by parent PID and framework.
type workerGroupKey struct {
	PPID      uint32
	Framework Framework
}

// phantexInfraPatterns are cmdline substrings that identify PHANTEX platform
// services. Processes matching these are excluded when ExcludeSelf is true.
var phantexInfraPatterns = []string{
	"uvicorn app.main:app",   // PHANTEX backend API
	"celery -A",              // PHANTEX Celery workers
	"celery worker",          // PHANTEX Celery workers (alt)
	"phantex-storage-writer", // ClickHouse writer
	"phantex-rule-engine",    // Rule engine
	"phantex-gateway",        // gRPC gateway
	"phantex-sensor",         // Sensor itself
	"phantex-consumer",       // Kafka consumer
	"gunicorn app.main:app",  // PHANTEX backend via gunicorn
}

// NewScanner creates an agent discovery scanner.
func NewScanner(log *zap.Logger, cfg ScannerConfig) *Scanner {
	sigs := BuiltinSignatures()
	if len(cfg.WatchBinaries) > 0 {
		sigs = append(sigs, WatchlistSignatures(cfg.WatchBinaries)...)
		log.Info("watchlist binaries registered",
			zap.Strings("patterns", cfg.WatchBinaries))
	}
	s := &Scanner{
		log:          log.Named("discovery"),
		cfg:          cfg,
		signatures:   sigs,
		eventCh:      make(chan AgentEvent, 64),
		agents:       make(map[uint32]*Agent),
		selfPID:      uint32(os.Getpid()),
		parentAgents: make(map[workerGroupKey]uint32),
	}
	if cfg.ExcludeSelf {
		s.log.Info("self-exclusion enabled",
			zap.Uint32("sensor_pid", s.selfPID),
			zap.Strings("infra_patterns", phantexInfraPatterns))
	}
	if len(cfg.ExcludePatterns) > 0 {
		s.log.Info("custom exclude patterns registered",
			zap.Strings("patterns", cfg.ExcludePatterns))
	}
	return s
}

// Events returns the channel of agent discovery/termination events.
func (s *Scanner) Events() <-chan AgentEvent {
	return s.eventCh
}

// Agents returns a snapshot of all currently tracked agents.
func (s *Scanner) Agents() map[uint32]*Agent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[uint32]*Agent, len(s.agents))
	for k, v := range s.agents {
		copy := *v
		out[k] = &copy
	}
	return out
}

// AgentByPID returns the agent for a given PID (nil if not an agent).
func (s *Scanner) AgentByPID(pid uint32) *Agent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if a, ok := s.agents[pid]; ok {
		copy := *a
		return &copy
	}
	return nil
}

// Run starts the periodic scan loop. Call in a goroutine.
func (s *Scanner) Run(ctx context.Context) {
	defer close(s.eventCh)

	// Initial scan immediately on startup
	s.scan()

	ticker := time.NewTicker(s.cfg.ScanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.log.Info("scanner shutting down",
				zap.Int("tracked_agents", len(s.agents)))
			return
		case <-ticker.C:
			s.scan()
		}
	}
}

// SeedScan performs a single synchronous /proc scan.
// Call before starting the ring buffer reader to populate the PID filter
// map so BPF probes don't emit events for non-agent processes on startup.
func (s *Scanner) SeedScan() {
	s.scan()
}

// scan performs one full /proc scan cycle.
func (s *Scanner) scan() {
	entries, err := os.ReadDir(s.cfg.ProcPath)
	if err != nil {
		s.log.Error("failed to read /proc", zap.Error(err))
		return
	}

	seen := make(map[uint32]bool)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue // not a PID directory
		}

		pid32 := uint32(pid)
		seen[pid32] = true

		// Skip the sensor's own PID — never discover ourselves
		if pid32 == s.selfPID {
			continue
		}

		// Skip if already tracked
		s.mu.RLock()
		_, tracked := s.agents[pid32]
		s.mu.RUnlock()
		if tracked {
			continue
		}

		// Check if this is an interpreter process or a watchlist binary.
		// First check comm, then fall back to /proc/<pid>/exe for Python
		// wrappers (gunicorn, uvicorn, celery, etc.) whose comm doesn't
		// match "python3" but whose actual binary is a Python interpreter.
		comm := s.readComm(pid32)
		if comm == "" {
			continue
		}
		isWatchlist := s.isWatchlistBinary(comm, pid32)
		isInterp := IsInterpreter(comm)
		if !isInterp && !isWatchlist {
			// Fallback: check if exe resolves to an interpreter
			exePath, _ := os.Readlink(filepath.Join(s.cfg.ProcPath, fmt.Sprintf("%d", pid32), "exe"))
			if IsInterpreterExe(exePath) {
				isInterp = true
				s.log.Debug("interpreter detected via exe fallback",
					zap.Uint32("pid", pid32),
					zap.String("comm", comm),
					zap.String("exe", exePath),
				)
			}
		}
		if !isInterp && !isWatchlist {
			continue
		}

		// Run framework signature matching
		matches := s.matchSignatures(pid32)
		if len(matches) == 0 {
			continue
		}

		best := BestMatch(matches)
		if best == nil || best.Confidence < ConfidenceMedium {
			continue // too uncertain
		}

		// ── Self-exclusion: skip PHANTEX platform processes ──────────
		cmdlineForExclude := s.readCmdline(pid32)
		if s.isExcluded(pid32, cmdlineForExclude) {
			s.log.Debug("excluded PHANTEX infrastructure process",
				zap.Uint32("pid", pid32),
				zap.String("comm", comm),
				zap.String("framework", string(best.Framework)),
			)
			continue
		}

		// ── Worker deduplication: group forked workers under parent ──
		if s.cfg.DeduplicateWorkers {
			ppid := s.readPPID(pid32)
			if ppid > 0 {
				key := workerGroupKey{PPID: ppid, Framework: best.Framework}
				s.mu.RLock()
				primaryPID, exists := s.parentAgents[key]
				s.mu.RUnlock()
				if exists {
					s.log.Debug("skipping duplicate worker process",
						zap.Uint32("pid", pid32),
						zap.Uint32("ppid", ppid),
						zap.Uint32("primary_pid", primaryPID),
						zap.String("framework", string(best.Framework)),
					)
					continue
				}
				// Also check if the parent itself is already tracked
				// with the same framework (we discovered parent first)
				s.mu.RLock()
				parentAgent, parentTracked := s.agents[ppid]
				s.mu.RUnlock()
				if parentTracked && parentAgent.Framework == best.Framework {
					s.log.Debug("skipping worker — parent already tracked",
						zap.Uint32("pid", pid32),
						zap.Uint32("ppid", ppid),
						zap.String("framework", string(best.Framework)),
					)
					s.mu.Lock()
					s.parentAgents[key] = ppid
					s.mu.Unlock()
					continue
				}
				// Register this PID as the primary for this parent+framework group
				s.mu.Lock()
				s.parentAgents[key] = pid32
				s.mu.Unlock()
			}
		}

		// Found an agent — build identity and generate PAID
		agent := s.buildAgent(pid32, comm, best)

		s.mu.Lock()
		s.agents[pid32] = agent
		s.mu.Unlock()

		s.log.Info("AI agent discovered",
			zap.Uint32("pid", pid32),
			zap.String("paid", agent.PAID),
			zap.String("framework", string(agent.Framework)),
			zap.String("confidence", confidenceStr(agent.Confidence)),
			zap.String("exe", agent.ExePath),
		)

		// Emit event (non-blocking)
		select {
		case s.eventCh <- AgentEvent{Type: AgentDiscovered, Agent: *agent}:
		default:
			s.log.Warn("agent event channel full, dropping discovery event",
				zap.Uint32("pid", pid32))
		}
	}

	// Detect terminated agents: tracked PIDs no longer in /proc
	s.detectTerminations(seen)
}

// detectTerminations finds agents whose PIDs no longer exist in /proc.
func (s *Scanner) detectTerminations(seen map[uint32]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for pid, agent := range s.agents {
		if seen[pid] {
			continue
		}

		s.log.Info("AI agent terminated",
			zap.Uint32("pid", pid),
			zap.String("paid", agent.PAID),
			zap.String("framework", string(agent.Framework)),
		)

		// Emit termination event (non-blocking)
		select {
		case s.eventCh <- AgentEvent{Type: AgentTerminated, Agent: *agent}:
		default:
			s.log.Warn("agent event channel full, dropping termination event",
				zap.Uint32("pid", pid))
		}

		delete(s.agents, pid)
	}

	// Clean up worker dedup entries for terminated agents
	for key, primaryPID := range s.parentAgents {
		if !seen[primaryPID] {
			delete(s.parentAgents, key)
		}
	}
}

// isExcluded returns true if a process should be excluded from agent discovery.
// It checks the sensor's own PID, built-in PHANTEX infrastructure patterns
// (when ExcludeSelf is enabled), and user-configured ExcludePatterns.
func (s *Scanner) isExcluded(pid uint32, cmdline string) bool {
	if pid == s.selfPID {
		return true
	}

	cmdlineLower := strings.ToLower(cmdline)

	// Check built-in PHANTEX infrastructure patterns
	if s.cfg.ExcludeSelf {
		for _, pattern := range phantexInfraPatterns {
			if strings.Contains(cmdlineLower, strings.ToLower(pattern)) {
				return true
			}
		}
	}

	// Check user-configured exclude patterns
	for _, pattern := range s.cfg.ExcludePatterns {
		if strings.Contains(cmdlineLower, strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}

// readPPID reads the parent PID from /proc/<pid>/stat (field 4).
func (s *Scanner) readPPID(pid uint32) uint32 {
	data, err := os.ReadFile(filepath.Join(s.cfg.ProcPath, fmt.Sprintf("%d", pid), "stat"))
	if err != nil {
		return 0
	}
	str := string(data)
	closeIdx := strings.LastIndex(str, ")")
	if closeIdx == -1 || closeIdx+2 >= len(str) {
		return 0
	}
	// Fields after (comm): state(3) ppid(4) ...
	// ppid is index 1 in the post-comm fields (field 3=state is index 0)
	fields := strings.Fields(str[closeIdx+2:])
	if len(fields) < 2 {
		return 0
	}
	val, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		return 0
	}
	return uint32(val)
}

// isWatchlistBinary checks if a process matches a user-configured binary watchlist.
// This enables detection of Go/Rust/C++ AI agents that don't use interpreters.
func (s *Scanner) isWatchlistBinary(comm string, pid uint32) bool {
	if len(s.cfg.WatchBinaries) == 0 {
		return false
	}
	commLower := strings.ToLower(comm)
	for _, pattern := range s.cfg.WatchBinaries {
		if strings.Contains(commLower, strings.ToLower(pattern)) {
			return true
		}
	}
	// Also check the full cmdline for longer patterns
	cmdline := s.readCmdline(pid)
	if cmdline == "" {
		return false
	}
	cmdlineLower := strings.ToLower(cmdline)
	for _, pattern := range s.cfg.WatchBinaries {
		if strings.Contains(cmdlineLower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// matchSignatures checks a process against all framework signatures.
func (s *Scanner) matchSignatures(pid uint32) []Match {
	var matches []Match

	// Pre-read the proc files we'll need
	mapsData := s.readFile(pid, "maps")
	cmdline := s.readCmdline(pid)

	var environ string
	if s.cfg.CheckEnviron {
		environ = s.readFile(pid, "environ")
	}

	// Lazily resolve site-packages path for Python processes.
	// This is only computed if we encounter a SourceSitePackages signature.
	var sitePackagesPath string
	var sitePackagesResolved bool

	for _, sig := range s.signatures {
		switch sig.Source {
		case SourceMaps:
			if mapsData == "" {
				continue
			}
			idx := strings.Index(strings.ToLower(mapsData), strings.ToLower(sig.Pattern))
			if idx == -1 {
				continue
			}
			evidence := extractEvidence(mapsData, idx, sig.Pattern)
			matches = append(matches, Match{
				Framework: sig.Framework, Confidence: sig.Confidence,
				Source: sig.Source, Pattern: sig.Pattern, Evidence: evidence,
			})

		case SourceCmdline:
			if cmdline == "" {
				continue
			}
			idx := strings.Index(strings.ToLower(cmdline), strings.ToLower(sig.Pattern))
			if idx == -1 {
				continue
			}
			evidence := extractEvidence(cmdline, idx, sig.Pattern)
			matches = append(matches, Match{
				Framework: sig.Framework, Confidence: sig.Confidence,
				Source: sig.Source, Pattern: sig.Pattern, Evidence: evidence,
			})

		case SourceEnviron:
			if !s.cfg.CheckEnviron || environ == "" {
				continue
			}
			idx := strings.Index(strings.ToLower(environ), strings.ToLower(sig.Pattern))
			if idx == -1 {
				continue
			}
			evidence := extractEvidence(environ, idx, sig.Pattern)
			matches = append(matches, Match{
				Framework: sig.Framework, Confidence: sig.Confidence,
				Source: sig.Source, Pattern: sig.Pattern, Evidence: evidence,
			})

		case SourceSitePackages:
			if !sitePackagesResolved {
				sitePackagesResolved = true
				sitePackagesPath = s.findSitePackages(pid)
			}
			if sitePackagesPath == "" {
				continue
			}
			pkgDir := filepath.Join(sitePackagesPath, sig.Pattern)
			if info, err := os.Stat(pkgDir); err == nil && info.IsDir() {
				matches = append(matches, Match{
					Framework: sig.Framework, Confidence: sig.Confidence,
					Source: sig.Source, Pattern: sig.Pattern, Evidence: pkgDir,
				})
			}

		default:
			continue
		}

		// Early exit on high-confidence match
		if len(matches) > 0 && matches[len(matches)-1].Confidence == ConfidenceHigh {
			return matches
		}
	}

	return matches
}

// buildAgent constructs an Agent from the process info and match result.
func (s *Scanner) buildAgent(pid uint32, comm string, match *Match) *Agent {
	exePath, _ := os.Readlink(filepath.Join(s.cfg.ProcPath, fmt.Sprintf("%d", pid), "exe"))
	cmdline := s.readCmdline(pid)
	startTime := s.readStartTime(pid)
	containerID := s.readContainerID(pid)

	id := AgentIdentity{
		ContainerID: containerID,
		ExePath:     exePath,
		Cmdline:     cmdline,
		StartTime:   startTime,
	}

	paid := GeneratePAID(s.cfg.PAIDConfig, id)

	return &Agent{
		PID:          pid,
		PAID:         paid,
		Framework:    match.Framework,
		Confidence:   match.Confidence,
		Comm:         comm,
		ExePath:      exePath,
		Cmdline:      cmdline,
		ContainerID:  containerID,
		StartTime:    startTime,
		DiscoveredAt: time.Now(),
	}
}

// ─── /proc helpers ────────────────────────────────────────────────────────────

// readComm reads /proc/<pid>/comm (process short name).
func (s *Scanner) readComm(pid uint32) string {
	data, err := os.ReadFile(filepath.Join(s.cfg.ProcPath, fmt.Sprintf("%d", pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// readCmdline reads /proc/<pid>/cmdline (null-separated → space-separated).
func (s *Scanner) readCmdline(pid uint32) string {
	data, err := os.ReadFile(filepath.Join(s.cfg.ProcPath, fmt.Sprintf("%d", pid), "cmdline"))
	if err != nil {
		return ""
	}
	// cmdline uses \0 as separator
	return strings.ReplaceAll(strings.TrimRight(string(data), "\x00"), "\x00", " ")
}

// readFile reads an arbitrary /proc/<pid>/<name> file.
func (s *Scanner) readFile(pid uint32, name string) string {
	data, err := os.ReadFile(filepath.Join(s.cfg.ProcPath, fmt.Sprintf("%d", pid), name))
	if err != nil {
		return ""
	}
	return string(data)
}

// readStartTime reads the process start time from /proc/<pid>/stat.
// Field 22 (1-indexed) is starttime in clock ticks since boot.
func (s *Scanner) readStartTime(pid uint32) uint64 {
	data, err := os.ReadFile(filepath.Join(s.cfg.ProcPath, fmt.Sprintf("%d", pid), "stat"))
	if err != nil {
		return 0
	}

	// /proc/<pid>/stat format: pid (comm) state ... field22
	// The comm field can contain spaces and parentheses, so we find the last ')' first.
	str := string(data)
	closeIdx := strings.LastIndex(str, ")")
	if closeIdx == -1 || closeIdx+2 >= len(str) {
		return 0
	}

	// Fields after (comm) are space-separated, starting with state (field 3)
	fields := strings.Fields(str[closeIdx+2:])
	// starttime is field 22, which is index 19 in the post-comm fields (field 3 = index 0)
	if len(fields) < 20 {
		return 0
	}

	val, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0
	}
	return val
}

// readContainerID extracts container ID from /proc/<pid>/cgroup.
func (s *Scanner) readContainerID(pid uint32) string {
	data := s.readFile(pid, "cgroup")
	if data == "" {
		return ""
	}

	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		cgroupPath := parts[2]

		// Docker cgroup v2: docker-<64hex>.scope
		if idx := strings.Index(cgroupPath, "docker-"); idx != -1 {
			id := cgroupPath[idx+7:]
			if dot := strings.Index(id, "."); dot != -1 {
				id = id[:dot]
			}
			if len(id) == 64 && isHex(id) {
				return id
			}
		}

		// Docker cgroup v1: /docker/<64hex>
		if idx := strings.Index(cgroupPath, "/docker/"); idx != -1 {
			id := cgroupPath[idx+8:]
			if len(id) >= 64 && isHex(id[:64]) {
				return id[:64]
			}
		}

		// K8s containerd: last segment is 64-char hex
		segments := strings.Split(cgroupPath, "/")
		if last := segments[len(segments)-1]; len(last) == 64 && isHex(last) {
			return last
		}
	}
	return ""
}

// isHex checks if a string is all hex characters.
func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// findSitePackages locates the Python site-packages directory for a process.
// It tries, in order:
//  1. VIRTUAL_ENV from /proc/<pid>/environ → <venv>/lib/python*/site-packages
//  2. Exe path containing "/venv/" or "/.venv/" → derive venv root
//  3. Cmdline first arg containing a venv path
//
// Returns the path to scene-packages, or "" if not found.
func (s *Scanner) findSitePackages(pid uint32) string {
	// Strategy 1: read VIRTUAL_ENV from environ
	environ := s.readFile(pid, "environ")
	if environ != "" {
		for _, item := range strings.Split(environ, "\x00") {
			if strings.HasPrefix(item, "VIRTUAL_ENV=") {
				venvRoot := strings.TrimPrefix(item, "VIRTUAL_ENV=")
				if sp := s.globSitePackages(venvRoot); sp != "" {
					return sp
				}
			}
		}
	}

	// Strategy 2: derive from exe path (e.g., /home/user/app/venv/bin/python3.12)
	exePath, _ := os.Readlink(filepath.Join(s.cfg.ProcPath, fmt.Sprintf("%d", pid), "exe"))
	if exePath != "" {
		// Look for venv indicator in the exe path
		for _, marker := range []string{"/venv/", "/.venv/", "/virtualenv/", "/.virtualenv/"} {
			if idx := strings.Index(exePath, marker); idx != -1 {
				venvRoot := exePath[:idx+len(marker)-1]
				if sp := s.globSitePackages(venvRoot); sp != "" {
					return sp
				}
			}
		}
	}

	// Strategy 3: derive from cmdline (first arg is the Python binary)
	cmdline := s.readCmdline(pid)
	if cmdline != "" {
		firstArg := strings.Fields(cmdline)[0]
		for _, marker := range []string{"/venv/", "/.venv/", "/virtualenv/", "/.virtualenv/"} {
			if idx := strings.Index(firstArg, marker); idx != -1 {
				venvRoot := firstArg[:idx+len(marker)-1]
				if sp := s.globSitePackages(venvRoot); sp != "" {
					return sp
				}
			}
		}
	}

	return ""
}

// globSitePackages finds lib/python*/site-packages under a venv root.
func (s *Scanner) globSitePackages(venvRoot string) string {
	pattern := filepath.Join(venvRoot, "lib", "python*", "site-packages")
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return ""
	}
	return matches[0]
}

// extractEvidence pulls a short context string around a match.
func extractEvidence(haystack string, matchIdx int, pattern string) string {
	// Find the line containing the match
	start := matchIdx
	for start > 0 && haystack[start-1] != '\n' {
		start--
	}
	end := matchIdx + len(pattern)
	for end < len(haystack) && haystack[end] != '\n' {
		end++
	}

	line := haystack[start:end]
	if len(line) > 200 {
		line = line[:200] + "..."
	}
	return line
}

func confidenceStr(c Confidence) string {
	switch c {
	case ConfidenceLow:
		return "low"
	case ConfidenceMedium:
		return "medium"
	case ConfidenceHigh:
		return "high"
	default:
		return "unknown"
	}
}
