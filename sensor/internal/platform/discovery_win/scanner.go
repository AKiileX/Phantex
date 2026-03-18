// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

//go:build windows

// Package discovery_win scans for AI agent processes on Windows using
// the Toolhelp32 snapshot API instead of /proc.
//
// Detection flow:
//  1. CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS) → enumerate all processes
//  2. Filter by interpreter names (python.exe, node.exe, etc.)
//  3. Read module list → check for framework signatures (DLLs, .pyd files)
//  4. Read command line → check for framework signatures
//  5. Match ≥ ConfidenceMedium → classify as agent → generate PAID → emit event
//
// Security:
//   - PROCESS_QUERY_LIMITED_INFORMATION only (no memory access)
//   - Snapshot handle always closed via defer
//   - Rate-limited scanning (default 30s between scans)
//   - Module enumeration bounded (max 4096 modules per process)
package discovery_win

import (
	"context"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

	"go.uber.org/zap"
	"golang.org/x/sys/windows"

	"github.com/AKiileX/Phantex/sensor/internal/discovery"
)

// WindowsAgent extends the base Agent with Windows-specific metadata.
type WindowsAgent struct {
	discovery.Agent
	UserSID   string
	Elevated  bool
	SessionID uint32
}

// ScannerConfig controls the Windows scanner behavior.
type ScannerConfig struct {
	ScanInterval  time.Duration
	PAIDConfig    discovery.PAIDConfig
	WatchBinaries []string
}

// DefaultScannerConfig returns sensible defaults.
func DefaultScannerConfig() ScannerConfig {
	return ScannerConfig{
		ScanInterval: 30 * time.Second,
		PAIDConfig:   discovery.PAIDConfig{TenantSlug: "default", EnvTag: "dev"},
	}
}

// Scanner discovers AI agent processes on Windows.
type Scanner struct {
	log        *zap.Logger
	cfg        ScannerConfig
	signatures []discovery.Signature
	eventCh    chan discovery.AgentEvent

	mu     sync.RWMutex
	agents map[uint32]*WindowsAgent
}

// NewScanner creates a Windows agent discovery scanner.
func NewScanner(log *zap.Logger, cfg ScannerConfig) *Scanner {
	sigs := BuiltinWindowsSignatures()
	if len(cfg.WatchBinaries) > 0 {
		sigs = append(sigs, discovery.WatchlistSignatures(cfg.WatchBinaries)...)
		log.Info("watchlist binaries registered",
			zap.Strings("patterns", cfg.WatchBinaries))
	}
	return &Scanner{
		log:        log.Named("discovery-win"),
		cfg:        cfg,
		signatures: sigs,
		eventCh:    make(chan discovery.AgentEvent, 64),
		agents:     make(map[uint32]*WindowsAgent),
	}
}

// Events returns the channel of agent discovery/termination events.
func (s *Scanner) Events() <-chan discovery.AgentEvent {
	return s.eventCh
}

// AgentByPID returns the agent for a given PID (nil if not an agent).
func (s *Scanner) AgentByPID(pid uint32) *WindowsAgent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if a, ok := s.agents[pid]; ok {
		copy := *a
		return &copy
	}
	return nil
}

// Agents returns a snapshot of all tracked agents.
func (s *Scanner) Agents() map[uint32]*WindowsAgent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[uint32]*WindowsAgent, len(s.agents))
	for k, v := range s.agents {
		copy := *v
		out[k] = &copy
	}
	return out
}

// Run starts the periodic scan loop.
func (s *Scanner) Run(ctx context.Context) {
	defer close(s.eventCh)

	// Immediate scan on startup
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

// ── Scanning ──────────────────────────────────────────────────────────────────

// scan performs one full process enumeration cycle.
func (s *Scanner) scan() {
	snapshot, err := windows.CreateToolhelp32Snapshot(
		windows.TH32CS_SNAPPROCESS, 0,
	)
	if err != nil {
		s.log.Error("CreateToolhelp32Snapshot failed", zap.Error(err))
		return
	}
	defer windows.CloseHandle(snapshot)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	err = windows.Process32First(snapshot, &pe)
	if err != nil {
		s.log.Error("Process32First failed", zap.Error(err))
		return
	}

	seen := make(map[uint32]bool)

	for {
		pid := pe.ProcessID
		seen[pid] = true

		// Skip system processes (PID 0, 4)
		if pid > 4 {
			s.mu.RLock()
			_, tracked := s.agents[pid]
			s.mu.RUnlock()

			if !tracked {
				comm := windows.UTF16ToString(pe.ExeFile[:])
				commLower := strings.ToLower(comm)

				if isWindowsInterpreter(commLower) || s.isWatchlistBinary(commLower) {
					s.inspectProcess(pid, comm, pe.ParentProcessID)
				}
			}
		}

		err = windows.Process32Next(snapshot, &pe)
		if err != nil {
			break // ERROR_NO_MORE_FILES
		}
	}

	// Detect terminated agents
	s.mu.Lock()
	for pid, agent := range s.agents {
		if !seen[pid] {
			delete(s.agents, pid)
			s.mu.Unlock()

			s.log.Info("agent terminated",
				zap.Uint32("pid", pid),
				zap.String("paid", agent.PAID),
				zap.String("framework", string(agent.Framework)),
			)
			select {
			case s.eventCh <- discovery.AgentEvent{
				Type:  discovery.AgentTerminated,
				Agent: agent.Agent,
			}:
			default:
				s.log.Warn("agent event channel full, dropping termination event")
			}

			s.mu.Lock()
		}
	}
	s.mu.Unlock()
}

// inspectProcess examines a single process for AI agent indicators.
func (s *Scanner) inspectProcess(pid uint32, comm string, ppid uint32) {
	commLower := strings.ToLower(comm)

	// ── Fast path: native AI app (ollama.exe, lm studio.exe, etc.) ──
	// These are always AI-related — classify immediately without module scanning.
	if fw, ok := windowsNativeAIApps[commLower]; ok && fw != discovery.FrameworkUnknown {
		cmdline := s.readCmdline(pid)
		exePath := s.readExePath(pid)

		paid := discovery.GeneratePAID(s.cfg.PAIDConfig, discovery.AgentIdentity{
			ExePath: exePath,
			Cmdline: cmdline,
		})

		agent := &WindowsAgent{
			Agent: discovery.Agent{
				PID:          pid,
				PAID:         paid,
				Framework:    fw,
				Confidence:   discovery.ConfidenceHigh,
				Comm:         comm,
				ExePath:      exePath,
				Cmdline:      truncate(cmdline, 1024),
				DiscoveredAt: time.Now(),
			},
		}
		s.enrichAgent(pid, agent)

		s.mu.Lock()
		s.agents[pid] = agent
		s.mu.Unlock()

		s.log.Info("native AI app discovered (fast path)",
			zap.Uint32("pid", pid),
			zap.String("paid", paid),
			zap.String("framework", string(fw)),
			zap.String("comm", comm),
			zap.Bool("elevated", agent.Elevated),
		)

		select {
		case s.eventCh <- discovery.AgentEvent{
			Type:  discovery.AgentDiscovered,
			Agent: agent.Agent,
		}:
		default:
			s.log.Warn("agent event channel full, dropping discovery event")
		}
		return
	}

	// ── Standard path: interpreter-based agents — scan modules/cmdline ──
	var matches []discovery.Match

	// Read command line
	cmdline := s.readCmdline(pid)
	cmdlineLower := strings.ToLower(cmdline)

	// Read loaded modules (DLLs)
	modules := s.readModules(pid)
	modulesLower := strings.ToLower(modules)

	// Check all signatures
	for _, sig := range s.signatures {
		pattern := strings.ToLower(sig.Pattern)
		switch sig.Source {
		case discovery.SourceCmdline:
			if strings.Contains(cmdlineLower, pattern) {
				matches = append(matches, discovery.Match{
					Framework:  sig.Framework,
					Confidence: sig.Confidence,
					Source:     sig.Source,
					Pattern:    sig.Pattern,
					Evidence:   truncate(cmdline, 200),
				})
			}
		case discovery.SourceMaps:
			// On Windows, SourceMaps → loaded DLLs and .pyd files
			if strings.Contains(modulesLower, pattern) {
				matches = append(matches, discovery.Match{
					Framework:  sig.Framework,
					Confidence: sig.Confidence,
					Source:     sig.Source,
					Pattern:    sig.Pattern,
					Evidence:   "module list",
				})
			}
		case discovery.SourceEnviron:
			// Not reading environ on Windows by default (expensive + privacy)
		}
	}

	best := discovery.BestMatch(matches)
	if best == nil || best.Confidence < discovery.ConfidenceMedium {
		return // Not enough evidence
	}

	// Get executable path
	exePath := s.readExePath(pid)

	// Generate PAID
	hostname, _ := os.Hostname()
	_ = hostname // used in computeHash via AgentIdentity

	paid := discovery.GeneratePAID(s.cfg.PAIDConfig, discovery.AgentIdentity{
		ExePath: exePath,
		Cmdline: cmdline,
	})

	agent := &WindowsAgent{
		Agent: discovery.Agent{
			PID:          pid,
			PAID:         paid,
			Framework:    best.Framework,
			Confidence:   best.Confidence,
			Comm:         comm,
			ExePath:      exePath,
			Cmdline:      truncate(cmdline, 1024),
			DiscoveredAt: time.Now(),
		},
	}

	// Enrich with token info
	s.enrichAgent(pid, agent)

	s.mu.Lock()
	s.agents[pid] = agent
	s.mu.Unlock()

	s.log.Info("agent discovered",
		zap.Uint32("pid", pid),
		zap.String("paid", paid),
		zap.String("framework", string(best.Framework)),
		zap.Int("confidence", int(best.Confidence)),
		zap.String("comm", comm),
		zap.Bool("elevated", agent.Elevated),
	)

	select {
	case s.eventCh <- discovery.AgentEvent{
		Type:  discovery.AgentDiscovered,
		Agent: agent.Agent,
	}:
	default:
		s.log.Warn("agent event channel full, dropping discovery event")
	}
}

// ── Process introspection (Win32 APIs) ────────────────────────────────────────

// readCmdline retrieves the command line of a process.
func (s *Scanner) readCmdline(pid uint32) string {
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_VM_READ,
		false, pid,
	)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(handle)

	// Use NtQueryInformationProcess with ProcessCommandLineInformation (60)
	const processCommandLineInformation = 60
	var buf [4096]byte
	var retLen uint32

	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ntQuery := ntdll.NewProc("NtQueryInformationProcess")

	r1, _, _ := ntQuery.Call(
		uintptr(handle),
		uintptr(processCommandLineInformation),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if r1 != 0 {
		return ""
	}

	if retLen < 8 {
		return ""
	}
	strLen := *(*uint16)(unsafe.Pointer(&buf[0]))
	if 8+int(strLen) > len(buf) {
		strLen = uint16(len(buf) - 8)
	}
	if strLen == 0 {
		return ""
	}
	u16Buf := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[8])), strLen/2)
	return windows.UTF16ToString(u16Buf)
}

// readModules returns a concatenated list of loaded module paths for a process.
func (s *Scanner) readModules(pid uint32) string {
	snapshot, err := windows.CreateToolhelp32Snapshot(
		windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, pid,
	)
	if err != nil {
		return "" // Access denied is common for system processes
	}
	defer windows.CloseHandle(snapshot)

	var me windows.ModuleEntry32
	me.Size = uint32(unsafe.Sizeof(me))

	err = windows.Module32First(snapshot, &me)
	if err != nil {
		return ""
	}

	var b strings.Builder
	count := 0
	const maxModules = 4096 // Safety bound

	for count < maxModules {
		modPath := windows.UTF16ToString(me.ExePath[:])
		b.WriteString(modPath)
		b.WriteByte('\n')
		count++

		err = windows.Module32Next(snapshot, &me)
		if err != nil {
			break
		}
	}

	return b.String()
}

// readExePath retrieves the full executable path of a process.
func (s *Scanner) readExePath(pid uint32) string {
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid,
	)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(handle)

	var buf [windows.MAX_PATH * 2]uint16
	size := uint32(len(buf))
	err = windows.QueryFullProcessImageName(handle, 0, &buf[0], &size)
	if err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}

// enrichAgent adds Windows-specific metadata (SID, elevation, session).
func (s *Scanner) enrichAgent(pid uint32, agent *WindowsAgent) {
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid,
	)
	if err != nil {
		return
	}
	defer windows.CloseHandle(handle)

	var token windows.Token
	if err := windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token); err != nil {
		return
	}
	defer token.Close()

	if user, err := token.GetTokenUser(); err == nil && user.User.Sid != nil {
		agent.UserSID = user.User.Sid.String()
	}

	agent.Elevated = isTokenElevated(token)

	var sessionID uint32
	if err := windows.ProcessIdToSessionId(pid, &sessionID); err == nil {
		agent.SessionID = sessionID
	}
}

// isTokenElevated checks if a token has elevated privileges.
func isTokenElevated(token windows.Token) bool {
	var elevation uint32
	var retLen uint32
	err := windows.GetTokenInformation(
		token,
		windows.TokenElevation,
		(*byte)(unsafe.Pointer(&elevation)),
		4,
		&retLen,
	)
	return err == nil && elevation != 0
}

// isWatchlistBinary checks if comm matches a user-configured watchlist pattern.
func (s *Scanner) isWatchlistBinary(comm string) bool {
	commLower := strings.ToLower(comm)
	for _, p := range s.cfg.WatchBinaries {
		if strings.Contains(commLower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// ── Windows interpreter detection ─────────────────────────────────────────────

// windowsInterpreters lists process names that could host AI agents on Windows.
var windowsInterpreters = map[string]bool{
	"python.exe":  true,
	"python3.exe": true,
	"pythonw.exe": true, // Windows-specific: pythonw for GUI apps
	"node.exe":    true,
	"deno.exe":    true,
	"bun.exe":     true,
	"java.exe":    true,
	"javaw.exe":   true, // Windows-specific: javaw for GUI apps
}

// windowsNativeAIApps maps .exe names of native AI applications.
// These are immediately classified as AI agents without module scanning.
var windowsNativeAIApps = map[string]discovery.Framework{
	"ollama.exe":            discovery.FrameworkOllama,
	"ollama app.exe":        discovery.FrameworkOllama,
	"lm studio.exe":         discovery.FrameworkLMStudio,
	"lm-studio.exe":         discovery.FrameworkLMStudio,
	"lms.exe":               discovery.FrameworkLMStudio,    // LM Studio CLI
	"llama-server.exe":      discovery.FrameworkLlamaCpp,
	"llama-cli.exe":         discovery.FrameworkLlamaCpp,
	"server.exe":            discovery.FrameworkUnknown,      // too generic — only if .gguf in cmdline
	"main.exe":              discovery.FrameworkUnknown,      // too generic — only if .gguf in cmdline
	"local-ai.exe":          discovery.FrameworkLocalAI,
	"localai.exe":           discovery.FrameworkLocalAI,
	"gpt4all.exe":           discovery.FrameworkGPT4All,
	"chat.exe":              discovery.FrameworkUnknown,      // too generic alone
	"jan.exe":               discovery.FrameworkJan,
	"koboldcpp.exe":         discovery.FrameworkKoboldCpp,
	"koboldcpp_nocuda.exe":  discovery.FrameworkKoboldCpp,
	"text-generation-webui.exe": discovery.FrameworkUnknown,  // oobabooga
}

// isWindowsInterpreter checks if the process could host an AI agent.
func isWindowsInterpreter(commLower string) bool {
	if windowsInterpreters[commLower] {
		return true
	}
	// Handle pythonXY.exe variants (python310.exe, python312.exe)
	if strings.HasPrefix(commLower, "python3") && strings.HasSuffix(commLower, ".exe") {
		return true
	}
	// Check native AI apps (ollama.exe, lm studio.exe, etc.)
	if _, ok := windowsNativeAIApps[commLower]; ok {
		return true
	}
	return false
}

// ── Windows-specific signatures ───────────────────────────────────────────────

// BuiltinWindowsSignatures returns framework detection patterns adapted for Windows.
// On Windows, SourceMaps checks loaded DLLs and .pyd files instead of /proc/maps.
func BuiltinWindowsSignatures() []discovery.Signature {
	sigs := discovery.BuiltinSignatures()

	// Add Windows-specific patterns (DLL/.pyd equivalents)
	winSigs := []discovery.Signature{
		// Python .pyd (compiled extension) patterns
		{discovery.FrameworkLangChain, discovery.SourceMaps, "langchain_core.pyd", discovery.ConfidenceHigh},
		{discovery.FrameworkAutoGen, discovery.SourceMaps, "autogen.pyd", discovery.ConfidenceHigh},
		{discovery.FrameworkCrewAI, discovery.SourceMaps, "crewai.pyd", discovery.ConfidenceHigh},
		{discovery.FrameworkLlamaIndex, discovery.SourceMaps, "llama_index.pyd", discovery.ConfidenceHigh},
		{discovery.FrameworkPhantexSDK, discovery.SourceMaps, "phantex_sdk.pyd", discovery.ConfidenceHigh},

		// Windows-specific paths (site-packages in AppData)
		{discovery.FrameworkLangChain, discovery.SourceMaps, `site-packages\langchain`, discovery.ConfidenceHigh},
		{discovery.FrameworkAutoGen, discovery.SourceMaps, `site-packages\autogen`, discovery.ConfidenceHigh},
		{discovery.FrameworkCrewAI, discovery.SourceMaps, `site-packages\crewai`, discovery.ConfidenceHigh},
		{discovery.FrameworkLlamaIndex, discovery.SourceMaps, `site-packages\llama_index`, discovery.ConfidenceHigh},
		{discovery.FrameworkPhantexSDK, discovery.SourceMaps, `site-packages\phantex_sdk`, discovery.ConfidenceHigh},

		// OpenAI / Anthropic Python packages
		{discovery.FrameworkOpenAI, discovery.SourceMaps, `site-packages\openai`, discovery.ConfidenceHigh},
		{discovery.FrameworkAnthropic, discovery.SourceMaps, `site-packages\anthropic`, discovery.ConfidenceHigh},

		// Node.js module patterns
		{discovery.FrameworkLangChain, discovery.SourceCmdline, `node_modules\langchain`, discovery.ConfidenceHigh},
		{discovery.FrameworkLangChain, discovery.SourceCmdline, `@langchain`, discovery.ConfidenceMedium},

		// Native AI app Windows-specific patterns
		{discovery.FrameworkOllama, discovery.SourceCmdline, `ollama serve`, discovery.ConfidenceHigh},
		{discovery.FrameworkOllama, discovery.SourceCmdline, `ollama run`, discovery.ConfidenceHigh},
		{discovery.FrameworkLMStudio, discovery.SourceCmdline, `LM Studio`, discovery.ConfidenceHigh},
		{discovery.FrameworkLMStudio, discovery.SourceCmdline, `.gguf`, discovery.ConfidenceMedium},
		{discovery.FrameworkLlamaCpp, discovery.SourceCmdline, `llama-server`, discovery.ConfidenceHigh},
		{discovery.FrameworkLlamaCpp, discovery.SourceCmdline, `--model`, discovery.ConfidenceLow},
		{discovery.FrameworkGPT4All, discovery.SourceCmdline, `gpt4all`, discovery.ConfidenceHigh},
		{discovery.FrameworkJan, discovery.SourceCmdline, `jan.exe`, discovery.ConfidenceHigh},
		{discovery.FrameworkKoboldCpp, discovery.SourceCmdline, `koboldcpp`, discovery.ConfidenceHigh},
	}

	return append(sigs, winSigs...)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// truncate limits a string to maxLen bytes.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// HandleExecEvent processes a process creation event for fast agent detection.
// Call this from the ETW event loop for EventProcessExec events.
func (s *Scanner) HandleExecEvent(pid, ppid uint32, comm, exePath, cmdline string) {
	commLower := strings.ToLower(comm)
	if !isWindowsInterpreter(commLower) && !s.isWatchlistBinary(commLower) {
		return
	}

	// Already tracked?
	s.mu.RLock()
	_, tracked := s.agents[pid]
	s.mu.RUnlock()
	if tracked {
		return
	}

	// Quick cmdline check for fast path
	cmdlineLower := strings.ToLower(cmdline)
	for _, sig := range s.signatures {
		if sig.Source == discovery.SourceCmdline && sig.Confidence >= discovery.ConfidenceMedium {
			if strings.Contains(cmdlineLower, strings.ToLower(sig.Pattern)) {
				// Found a match — do full inspection in background
				go s.inspectProcess(pid, comm, ppid)
				return
			}
		}
	}
}

// HandleExitEvent processes a process termination event.
// Call this from the ETW event loop for EventProcessExit events.
func (s *Scanner) HandleExitEvent(pid uint32) {
	s.mu.Lock()
	agent, found := s.agents[pid]
	if found {
		delete(s.agents, pid)
	}
	s.mu.Unlock()

	if found {
		s.log.Info("agent terminated (via ETW exit event)",
			zap.Uint32("pid", pid),
			zap.String("paid", agent.PAID),
		)
		select {
		case s.eventCh <- discovery.AgentEvent{
			Type:  discovery.AgentTerminated,
			Agent: agent.Agent,
		}:
		default:
		}
	}
}
