// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Package discovery — lifecycle.go
//
// Bridges eBPF process events with agent discovery to provide fast
// agent lifecycle tracking:
//
//   - Process exec event → if interpreter, trigger immediate signature scan
//     (instead of waiting for next 30s poll cycle)
//   - Process exit event → if tracked agent, emit AgentTerminated immediately
//     (within event pipeline latency, typically <100ms vs 30s poll)
//
// This gives us:
//   - Discovery within ~1s of agent start (vs 30s poll-only)
//   - Termination within ~100ms (vs 30s poll-only)
//   - The periodic scanner remains as a safety net for racy edge cases
package discovery

import (
	"go.uber.org/zap"

	bpf "github.com/AKiileX/Phantex/sensor/internal/ebpf"
)

// LifecycleTracker listens to eBPF process events and triggers
// fast discovery/termination for AI agent processes.
type LifecycleTracker struct {
	log     *zap.Logger
	scanner *Scanner
}

// NewLifecycleTracker creates a tracker that bridges eBPF events to agent discovery.
func NewLifecycleTracker(log *zap.Logger, scanner *Scanner) *LifecycleTracker {
	return &LifecycleTracker{
		log:     log.Named("lifecycle"),
		scanner: scanner,
	}
}

// HandleEvent dispatches an eBPF event to the appropriate handler.
// Exported so main.go can call it inline from the event loop.
func (lt *LifecycleTracker) HandleEvent(evt bpf.Event) {
	switch evt.Type {
	case bpf.EventProcessExec:
		lt.handleExec(evt)
	case bpf.EventProcessExit:
		lt.handleExit(evt)
	}
}

// handleExec triggers an immediate scan when an interpreter process starts.
func (lt *LifecycleTracker) handleExec(evt bpf.Event) {
	comm := evt.Header.CommString()

	if !IsInterpreter(comm) {
		return
	}

	pid := evt.Header.PID

	// Already tracked?
	if lt.scanner.AgentByPID(pid) != nil {
		return
	}

	lt.log.Debug("interpreter process started, scanning for framework",
		zap.Uint32("pid", pid),
		zap.String("comm", comm),
	)

	// Run signature matching on this specific PID
	matches := lt.scanner.matchSignatures(pid)
	if len(matches) == 0 {
		return
	}

	best := BestMatch(matches)
	if best == nil || best.Confidence < ConfidenceMedium {
		return
	}

	// Build and register the agent
	agent := lt.scanner.buildAgent(pid, comm, best)

	lt.scanner.mu.Lock()
	lt.scanner.agents[pid] = agent
	lt.scanner.mu.Unlock()

	lt.log.Info("AI agent discovered (via exec event)",
		zap.Uint32("pid", pid),
		zap.String("paid", agent.PAID),
		zap.String("framework", string(agent.Framework)),
	)

	// Emit discovery event
	select {
	case lt.scanner.eventCh <- AgentEvent{Type: AgentDiscovered, Agent: *agent}:
	default:
		lt.log.Warn("event channel full, dropping exec-triggered discovery",
			zap.Uint32("pid", pid))
	}
}

// handleExit immediately terminates an agent when its process exits.
func (lt *LifecycleTracker) handleExit(evt bpf.Event) {
	pid := evt.Header.PID

	lt.scanner.mu.Lock()
	agent, tracked := lt.scanner.agents[pid]
	if !tracked {
		lt.scanner.mu.Unlock()
		return
	}

	agentCopy := *agent
	delete(lt.scanner.agents, pid)
	lt.scanner.mu.Unlock()

	lt.log.Info("AI agent terminated (via exit event)",
		zap.Uint32("pid", pid),
		zap.String("paid", agentCopy.PAID),
		zap.String("framework", string(agentCopy.Framework)),
	)

	select {
	case lt.scanner.eventCh <- AgentEvent{Type: AgentTerminated, Agent: agentCopy}:
	default:
		lt.log.Warn("event channel full, dropping exit-triggered termination",
			zap.Uint32("pid", pid))
	}
}
