// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Package ebpf — verify.go
//
// Ed25519 signature verification for eBPF bytecode (ADR-014).
// Each .bpf.o file must have an accompanying .bpf.o.sig file containing
// a 64-byte raw Ed25519 signature.
//
// The public key is provided at build time via ldflags:
//
//	go build -ldflags "-X github.com/AKiileX/Phantex/sensor/internal/ebpf.bpfPubKeyHex=<hex>"
//
// Or at runtime via the PHANTEX_BPF_PUBKEY_PATH environment variable
// (hex-encoded 32-byte public key in a file).
//
// Set PHANTEX_BPF_SKIP_VERIFY=1 to bypass verification in development.
package ebpf

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"
)

// bpfPubKeyHex is injected at build time via:
//
//	go build -ldflags "-X github.com/AKiileX/Phantex/sensor/internal/ebpf.bpfPubKeyHex=..."
var bpfPubKeyHex string

var (
	ErrNoPublicKey   = errors.New("ebpf: no Ed25519 public key configured")
	ErrInvalidPubKey = errors.New("ebpf: invalid Ed25519 public key (expected 64 hex chars / 32 bytes)")
	ErrSigMissing    = errors.New("ebpf: signature file missing for BPF object")
	ErrSigInvalid    = errors.New("ebpf: Ed25519 signature verification failed — bytecode may be tampered")
	ErrSigWrongSize  = errors.New("ebpf: signature must be exactly 64 bytes")
)

// resolvePublicKey returns the Ed25519 public key from build-time embed or env path.
func resolvePublicKey() (ed25519.PublicKey, error) {
	// 1. Build-time linker flag (preferred — baked into binary)
	if bpfPubKeyHex != "" {
		return decodePubKey(bpfPubKeyHex)
	}

	// 2. Runtime file path (for testing / key rotation)
	path := os.Getenv("PHANTEX_BPF_PUBKEY_PATH")
	if path == "" {
		return nil, ErrNoPublicKey
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ebpf: read public key %s: %w", path, err)
	}

	return decodePubKey(strings.TrimSpace(string(data)))
}

// decodePubKey decodes a hex-encoded 32-byte Ed25519 public key.
func decodePubKey(hexStr string) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(hexStr))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, ErrInvalidPubKey
	}
	return ed25519.PublicKey(raw), nil
}

// VerifyBytecode checks the Ed25519 signature of eBPF object file data.
// sig must be exactly 64 bytes (raw Ed25519 signature).
func VerifyBytecode(pubKey ed25519.PublicKey, data, sig []byte) error {
	if len(sig) != ed25519.SignatureSize {
		return ErrSigWrongSize
	}
	if !ed25519.Verify(pubKey, data, sig) {
		return ErrSigInvalid
	}
	return nil
}

// verifyOrSkip performs bytecode verification, or warns and skips in dev mode
// (PHANTEX_BPF_SKIP_VERIFY=1).
func verifyOrSkip(log *zap.Logger, objFile string, data, sig []byte) error {
	skip := os.Getenv("PHANTEX_BPF_SKIP_VERIFY") == "1"

	// No signature file embedded
	if sig == nil {
		if skip {
			log.Warn("BPF signature file MISSING — skipped (dev mode)",
				zap.String("obj", objFile))
			return nil
		}
		return fmt.Errorf("verify %s: %w", objFile, ErrSigMissing)
	}

	// Resolve public key
	pubKey, err := resolvePublicKey()
	if err != nil {
		if skip {
			log.Warn("BPF verification skipped (dev mode) — no public key",
				zap.String("obj", objFile), zap.Error(err))
			return nil
		}
		return fmt.Errorf("verify %s: %w", objFile, err)
	}

	// Verify
	if err := VerifyBytecode(pubKey, data, sig); err != nil {
		if skip {
			log.Warn("BPF signature INVALID — skipped (dev mode)",
				zap.String("obj", objFile), zap.Error(err))
			return nil
		}
		return fmt.Errorf("verify %s: %w", objFile, err)
	}

	log.Debug("BPF bytecode signature verified OK", zap.String("obj", objFile))
	return nil
}
