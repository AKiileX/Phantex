// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Package identity provides hardware-backed agent identity for the Phantex sensor.
//
// Supports TPM 2.0 (Linux tpm2-tss, Windows NCrypt), macOS Secure Enclave,
// and remote attestation to prove key binding and platform integrity.
// Part of Phase 4, Block AS (Hardware-Backed Agent Identity).
package identity

import (
	"crypto"
	"fmt"
	"sync"

	"go.uber.org/zap"
)

// Level represents the agent identity assurance level (0–4).
type Level int

const (
	LevelNone      Level = 0 // No identity binding
	LevelSoftware  Level = 1 // Software key in file
	LevelOS        Level = 2 // OS keystore (Keychain, CNG)
	LevelHardware  Level = 3 // TPM / Secure Enclave backed
	LevelAttested  Level = 4 // Hardware + remote attestation verified
)

func (l Level) String() string {
	switch l {
	case LevelNone:
		return "none"
	case LevelSoftware:
		return "software"
	case LevelOS:
		return "os"
	case LevelHardware:
		return "hardware"
	case LevelAttested:
		return "attested"
	default:
		return fmt.Sprintf("unknown(%d)", int(l))
	}
}

// KeyInfo holds metadata about a hardware-bound key.
type KeyInfo struct {
	// AgentID is the stable agent identifier derived from the key.
	AgentID string

	// Level is the identity assurance level for this key.
	Level Level

	// Backend describes the key backend ("tpm2", "enclave", "software").
	Backend string

	// PublicKeyDER is the DER-encoded public key.
	PublicKeyDER []byte
}

// Signer provides signing operations backed by hardware or software keys.
type Signer interface {
	// Sign signs digest using the hardware-bound private key.
	Sign(digest []byte) ([]byte, error)

	// Public returns the public key portion.
	Public() crypto.PublicKey

	// Info returns metadata about the key.
	Info() KeyInfo

	// Close releases hardware resources.
	Close() error
}

// Manager coordinates identity key lifecycle across backends.
type Manager struct {
	log    *zap.Logger
	mu     sync.RWMutex
	signer Signer
	level  Level
}

// NewManager creates a new identity manager.
func NewManager(log *zap.Logger) *Manager {
	return &Manager{
		log:   log.Named("identity"),
		level: LevelNone,
	}
}

// Initialize attempts to establish the highest available identity level.
// It probes TPM → Secure Enclave → OS keystore → software key.
func (m *Manager) Initialize(agentID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Try TPM first (Linux + Windows)
	if signer, err := openTPM(agentID, m.log); err == nil {
		m.signer = signer
		m.level = LevelHardware
		m.log.Info("identity_initialized", zap.String("backend", "tpm2"), zap.String("level", m.level.String()))
		return nil
	}

	// Try Secure Enclave (macOS)
	if signer, err := openEnclave(agentID, m.log); err == nil {
		m.signer = signer
		m.level = LevelHardware
		m.log.Info("identity_initialized", zap.String("backend", "enclave"), zap.String("level", m.level.String()))
		return nil
	}

	// Fallback: software key
	signer, err := newSoftwareKey(agentID, m.log)
	if err != nil {
		return fmt.Errorf("all identity backends failed: %w", err)
	}
	m.signer = signer
	m.level = LevelSoftware
	m.log.Warn("identity_fallback_software", zap.String("agent_id", agentID))
	return nil
}

// Signer returns the current identity signer.
func (m *Manager) Signer() Signer {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.signer
}

// Level returns the current identity assurance level.
func (m *Manager) Level() Level {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.level
}

// UpgradeToAttested upgrades identity level to 4 after successful attestation.
func (m *Manager) UpgradeToAttested() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.level >= LevelHardware {
		m.level = LevelAttested
		m.log.Info("identity_upgraded_to_attested")
	}
}

// Close releases all hardware resources.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.signer != nil {
		return m.signer.Close()
	}
	return nil
}
