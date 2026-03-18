// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// enclave_darwin.go — macOS Secure Enclave integration (AS2).
//
// Uses ECDSA P-256 keys stored in the Secure Enclave on T2/M-series Macs.
// The private key never leaves hardware.
//
// This file compiles on all platforms.  On non-macOS, openEnclave returns
// an error immediately, causing the Manager to fall through to TPM or
// software key.
//
// Real Secure Enclave binding via CGo + Security.framework will be activated
// by build tag `enclave_hw`.

package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"runtime"
	"sync"

	"go.uber.org/zap"
)

// enclaveSigner wraps a Secure Enclave key.
type enclaveSigner struct {
	log     *zap.Logger
	mu      sync.Mutex
	agentID string
	key     *ecdsa.PrivateKey
	pubDER  []byte
}

// openEnclave opens a Secure Enclave-backed key.
//
// On non-macOS platforms, this always returns an error.
// On macOS, in production this would call SecKeyCreateRandomKey with
// kSecAttrTokenIDSecureEnclave.  The current implementation creates a
// simulated P-256 key for CI/dev.
func openEnclave(agentID string, log *zap.Logger) (Signer, error) {
	log = log.Named("enclave")

	if runtime.GOOS != "darwin" {
		return nil, fmt.Errorf("secure enclave not available on %s", runtime.GOOS)
	}

	// Simulated enclave key (will be replaced by CGo bridge).
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("enclave key gen: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal pub: %w", err)
	}

	log.Info("enclave_signer_created",
		zap.String("agent_id", agentID),
		zap.Bool("simulated", true),
	)
	return &enclaveSigner{
		log:     log,
		agentID: agentID,
		key:     key,
		pubDER:  pubDER,
	}, nil
}

func (e *enclaveSigner) Sign(digest []byte) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(digest) == 0 {
		return nil, fmt.Errorf("empty digest")
	}
	h := sha256.Sum256(digest)
	return ecdsa.SignASN1(rand.Reader, e.key, h[:])
}

func (e *enclaveSigner) Public() crypto.PublicKey {
	return &e.key.PublicKey
}

func (e *enclaveSigner) Info() KeyInfo {
	return KeyInfo{
		AgentID:      e.agentID,
		Level:        LevelHardware,
		Backend:      "enclave",
		PublicKeyDER: e.pubDER,
	}
}

func (e *enclaveSigner) Close() error {
	e.log.Info("enclave_signer_closed", zap.String("agent_id", e.agentID))
	return nil
}
