// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Package ebpf — maps.go
//
// Provides high-level operations on the shared BPF maps:
//   - PID filter: add/remove/list tracked PIDs
//   - Config map: enable/disable PID filtering
//
// These operations are called by the agent discovery module (A3)
// and the main sensor loop.
package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
)

// MapManager provides high-level operations on shared BPF maps.
type MapManager struct {
	log          *zap.Logger
	pidFilterMap *ebpf.Map
	configMap    *ebpf.Map
}

// NewMapManager creates a manager for BPF map operations.
func NewMapManager(log *zap.Logger, pidFilter, configMap *ebpf.Map) *MapManager {
	return &MapManager{
		log:          log,
		pidFilterMap: pidFilter,
		configMap:    configMap,
	}
}

// ─── PID Filter Operations ────────────────────────────────────────────────────

// TrackPID adds a PID to the filter map so its events are captured.
func (m *MapManager) TrackPID(pid uint32) error {
	if m.pidFilterMap == nil {
		return fmt.Errorf("pid_filter map not available")
	}
	val := uint8(1)
	if err := m.pidFilterMap.Put(pid, val); err != nil {
		return fmt.Errorf("add PID %d to filter: %w", pid, err)
	}
	m.log.Debug("tracking PID", zap.Uint32("pid", pid))
	return nil
}

// UntrackPID removes a PID from the filter map.
func (m *MapManager) UntrackPID(pid uint32) error {
	if m.pidFilterMap == nil {
		return fmt.Errorf("pid_filter map not available")
	}
	if err := m.pidFilterMap.Delete(pid); err != nil {
		return fmt.Errorf("remove PID %d from filter: %w", pid, err)
	}
	m.log.Debug("untracking PID", zap.Uint32("pid", pid))
	return nil
}

// IsTracked checks if a PID is in the filter map.
func (m *MapManager) IsTracked(pid uint32) (bool, error) {
	if m.pidFilterMap == nil {
		return false, fmt.Errorf("pid_filter map not available")
	}
	var val uint8
	err := m.pidFilterMap.Lookup(pid, &val)
	if err != nil {
		return false, nil // not found = not tracked
	}
	return val == 1, nil
}

// TrackedPIDs returns all PIDs currently in the filter map.
func (m *MapManager) TrackedPIDs() ([]uint32, error) {
	if m.pidFilterMap == nil {
		return nil, fmt.Errorf("pid_filter map not available")
	}

	var pids []uint32
	var key uint32
	var val uint8

	iter := m.pidFilterMap.Iterate()
	for iter.Next(&key, &val) {
		pids = append(pids, key)
	}
	if err := iter.Err(); err != nil {
		return pids, fmt.Errorf("iterate pid_filter: %w", err)
	}

	return pids, nil
}

// ClearPIDFilter removes all PIDs from the filter.
func (m *MapManager) ClearPIDFilter() error {
	pids, err := m.TrackedPIDs()
	if err != nil {
		return err
	}
	for _, pid := range pids {
		_ = m.UntrackPID(pid) // best-effort
	}
	m.log.Info("PID filter cleared", zap.Int("removed", len(pids)))
	return nil
}

// ─── Config Map Operations ────────────────────────────────────────────────────

// PhantexConfig mirrors struct phantex_config in maps.h
type PhantexConfig struct {
	FilterEnabled uint8
	Pad           [7]byte
}

// EnablePIDFilter turns on PID-based filtering (only tracked PIDs emit events).
func (m *MapManager) EnablePIDFilter() error {
	return m.setConfig(PhantexConfig{FilterEnabled: 1})
}

// DisablePIDFilter turns off PID-based filtering (all processes emit events).
func (m *MapManager) DisablePIDFilter() error {
	return m.setConfig(PhantexConfig{FilterEnabled: 0})
}

// IsFilterEnabled checks if PID filtering is currently enabled.
func (m *MapManager) IsFilterEnabled() (bool, error) {
	if m.configMap == nil {
		return false, fmt.Errorf("config_map not available")
	}
	var cfg PhantexConfig
	key := uint32(0)
	if err := m.configMap.Lookup(key, &cfg); err != nil {
		return false, fmt.Errorf("read config: %w", err)
	}
	return cfg.FilterEnabled == 1, nil
}

func (m *MapManager) setConfig(cfg PhantexConfig) error {
	if m.configMap == nil {
		return fmt.Errorf("config_map not available")
	}
	key := uint32(0)
	if err := m.configMap.Put(key, cfg); err != nil {
		return fmt.Errorf("update config: %w", err)
	}
	m.log.Info("config updated", zap.Bool("filter_enabled", cfg.FilterEnabled == 1))
	return nil
}
