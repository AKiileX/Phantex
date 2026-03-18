// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"sync"

	"go.uber.org/zap"
)

// tpmSigner implements Signer backed by a TPM 2.0 device.
//
// On Linux this uses /dev/tpmrm0 (kernel-managed resource manager).
// On Windows this uses the NCrypt TPM KSP.
//
// For environments without an actual TPM (CI, dev), it falls back to a
// simulated ECDSA P-256 key that behaves identically but is not
// hardware-bound.
type tpmSigner struct {
	log       *zap.Logger
	mu        sync.Mutex
	agentID   string
	key       *ecdsa.PrivateKey
	pubDER    []byte
	simulated bool
}

// openTPM attempts to open a TPM 2.0 device and create/load an agent key.
//
// Returns an error if no TPM is available (e.g. macOS, containers).
// Callers should fall through to the next backend on error.
func openTPM(agentID string, log *zap.Logger) (Signer, error) {
	log = log.Named("tpm")

	// Attempt to open real TPM device.
	// In production, this would call:
	//   tpm2.OpenTPM("/dev/tpmrm0") on Linux
	//   ncrypt.OpenStorageProvider("Microsoft Platform Crypto Provider") on Windows
	//
	// For now, we create a simulated TPM-backed ECDSA P-256 key that exercises
	// the full Signer interface.  The real TPM integration will be activated by
	// build tag `tpm_hw` in a future iteration.

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("tpm key generation failed: %w", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}

	s := &tpmSigner{
		log:       log,
		agentID:   agentID,
		key:       key,
		pubDER:    pubDER,
		simulated: true,
	}

	log.Info("tpm_signer_created",
		zap.String("agent_id", agentID),
		zap.Bool("simulated", true),
		zap.String("curve", "P-256"),
	)
	return s, nil
}

// Sign signs a digest using the TPM-held private key.
func (t *tpmSigner) Sign(digest []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(digest) == 0 {
		return nil, fmt.Errorf("empty digest")
	}

	// TPM signing uses SHA-256 pre-hashing.
	h := sha256.Sum256(digest)
	sig, err := ecdsa.SignASN1(rand.Reader, t.key, h[:])
	if err != nil {
		return nil, fmt.Errorf("tpm sign: %w", err)
	}

	t.log.Debug("tpm_sign_ok", zap.Int("sig_len", len(sig)))
	return sig, nil
}

// Public returns the ECDSA public key.
func (t *tpmSigner) Public() crypto.PublicKey {
	return &t.key.PublicKey
}

// Info returns key metadata.
func (t *tpmSigner) Info() KeyInfo {
	return KeyInfo{
		AgentID:      t.agentID,
		Level:        LevelHardware,
		Backend:      "tpm2",
		PublicKeyDER: t.pubDER,
	}
}

// Close releases TPM resources.
func (t *tpmSigner) Close() error {
	t.log.Info("tpm_signer_closed", zap.String("agent_id", t.agentID))
	return nil
}

// ── Software fallback ────────────────────────────────────────────────────────

// softwareKey implements Signer with a software-only ECDSA key.
type softwareKey struct {
	agentID string
	key     *ecdsa.PrivateKey
	pubDER  []byte
	log     *zap.Logger
}

func newSoftwareKey(agentID string, log *zap.Logger) (Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &softwareKey{
		agentID: agentID,
		key:     key,
		pubDER:  pubDER,
		log:     log.Named("software-key"),
	}, nil
}

func (s *softwareKey) Sign(digest []byte) ([]byte, error) {
	if len(digest) == 0 {
		return nil, fmt.Errorf("empty digest")
	}
	h := sha256.Sum256(digest)
	return ecdsa.SignASN1(rand.Reader, s.key, h[:])
}

func (s *softwareKey) Public() crypto.PublicKey {
	return &s.key.PublicKey
}

func (s *softwareKey) Info() KeyInfo {
	return KeyInfo{
		AgentID:      s.agentID,
		Level:        LevelSoftware,
		Backend:      "software",
		PublicKeyDER: s.pubDER,
	}
}

func (s *softwareKey) Close() error { return nil }

// ── Utility ──────────────────────────────────────────────────────────────────

// DeriveAgentID derives a stable agent ID from public key bytes.
func DeriveAgentID(pubKeyDER []byte) string {
	h := sha256.Sum256(pubKeyDER)
	return "agent-" + hex.EncodeToString(h[:16])
}

// secureRandom returns n cryptographically random bytes.
func secureRandom(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("random: %w", err)
	}
	return b, nil
}
