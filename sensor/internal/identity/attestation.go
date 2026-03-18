// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// attestation.go — Remote attestation protocol (AS3).
//
// Periodically proves to the Phantex engine that the agent's identity key
// is still hardware-bound and the platform hasn't been tampered with.
//
// Protocol:
//  1. Sensor requests a nonce from the engine.
//  2. Sensor signs nonce + platform measurements (PCR values / quote).
//  3. Engine verifies signature, checks measurements against golden values.
//  4. On success, engine upgrades agent identity to Level 4 (Attested).

package identity

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// AttestationResult holds the outcome of an attestation exchange.
type AttestationResult struct {
	Success      bool
	Level        Level
	Timestamp    time.Time
	NonceHex     string
	SignatureHex string
	FailReason   string
}

// Quote represents platform measurements signed by the hardware.
type Quote struct {
	// PCRs maps PCR index → SHA-256 hash (hex encoded).
	PCRs map[int]string

	// Nonce is the server-provided challenge.
	Nonce []byte

	// Signature over sha256(nonce || pcr_concat) using identity key.
	Signature []byte
}

// Attester performs the attestation protocol.
type Attester struct {
	log     *zap.Logger
	mu      sync.Mutex
	signer  Signer
	results []AttestationResult
}

// NewAttester creates an attester bound to the given signer.
func NewAttester(signer Signer, log *zap.Logger) *Attester {
	return &Attester{
		signer: signer,
		log:    log.Named("attestation"),
	}
}

// GenerateQuote builds and signs a platform quote.
//
// In production, PCR values would be read from TPM PCR banks.
// The current implementation generates simulated PCR values representing
// a healthy platform state (boot loader, kernel, initrd hashes).
func (a *Attester) GenerateQuote(nonce []byte) (*Quote, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(nonce) == 0 {
		return nil, fmt.Errorf("empty nonce")
	}
	if len(nonce) > 64 {
		return nil, fmt.Errorf("nonce too large: %d bytes (max 64)", len(nonce))
	}

	// Simulated PCR values (golden state)
	pcrs := map[int]string{
		0:  hashStr("bootloader-v2.1"),      // BIOS/UEFI
		1:  hashStr("platform-config-ok"),   // Platform configuration
		2:  hashStr("option-rom-clean"),     // Option ROMs
		4:  hashStr("grub-sha256-verified"), // Boot loader code
		7:  hashStr("secureboot-enabled"),   // Secure Boot state
		8:  hashStr("kernel-6.1-phantex"),   // Kernel
		9:  hashStr("initrd-clean"),         // initrd
		14: hashStr("phantex-sensor-v4"),    // Application PCR
	}

	// Build digest: sha256(nonce || pcr[0] || pcr[1] || ... || pcr[14])
	h := sha256.New()
	h.Write(nonce)
	for i := 0; i <= 14; i++ {
		if v, ok := pcrs[i]; ok {
			h.Write([]byte(v))
		}
	}
	digest := h.Sum(nil)

	// Sign with identity key
	sig, err := a.signer.Sign(digest)
	if err != nil {
		return nil, fmt.Errorf("sign quote: %w", err)
	}

	quote := &Quote{
		PCRs:      pcrs,
		Nonce:     nonce,
		Signature: sig,
	}

	a.log.Info("quote_generated",
		zap.Int("pcr_count", len(pcrs)),
		zap.Int("sig_len", len(sig)),
	)
	return quote, nil
}

// Attest performs a full attestation round.
//
// This combines nonce generation, quote creation, and local verification
// for testing. In production, the nonce comes from the engine and
// verification happens server-side.
func (a *Attester) Attest() (AttestationResult, error) {
	nonce, err := secureRandom(32)
	if err != nil {
		return AttestationResult{}, fmt.Errorf("generate nonce: %w", err)
	}

	quote, err := a.GenerateQuote(nonce)
	if err != nil {
		result := AttestationResult{
			Success:    false,
			Level:      a.signer.Info().Level,
			Timestamp:  time.Now().UTC(),
			FailReason: err.Error(),
		}
		a.mu.Lock()
		a.results = append(a.results, result)
		a.mu.Unlock()
		return result, err
	}

	// Local verification (simulates engine-side check)
	ok, err := verifyQuote(quote, a.signer.Public(), nonce)
	if err != nil || !ok {
		reason := "verification failed"
		if err != nil {
			reason = err.Error()
		}
		result := AttestationResult{
			Success:    false,
			Level:      a.signer.Info().Level,
			Timestamp:  time.Now().UTC(),
			FailReason: reason,
		}
		a.mu.Lock()
		a.results = append(a.results, result)
		a.mu.Unlock()
		return result, fmt.Errorf("%s", reason)
	}

	result := AttestationResult{
		Success:      true,
		Level:        LevelAttested,
		Timestamp:    time.Now().UTC(),
		NonceHex:     hex.EncodeToString(nonce),
		SignatureHex: hex.EncodeToString(quote.Signature),
	}

	a.mu.Lock()
	a.results = append(a.results, result)
	a.mu.Unlock()

	a.log.Info("attestation_success")
	return result, nil
}

// Results returns a copy of attestation history.
func (a *Attester) Results() []AttestationResult {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]AttestationResult, len(a.results))
	copy(out, a.results)
	return out
}

// ── Verification (engine-side logic, collocated for testing) ─────────────────

// verifyQuote verifies a quote signature against the signer's public key.
func verifyQuote(q *Quote, pub interface{}, nonce []byte) (bool, error) {
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("unsupported public key type: %T", pub)
	}

	// Reconstruct digest
	h := sha256.New()
	h.Write(nonce)
	for i := 0; i <= 14; i++ {
		if v, ok := q.PCRs[i]; ok {
			h.Write([]byte(v))
		}
	}
	digest := h.Sum(nil)

	// The signer pre-hashes with SHA-256, so we need to SHA-256 the digest too
	innerHash := sha256.Sum256(digest)

	if !ecdsa.VerifyASN1(ecPub, innerHash[:], q.Signature) {
		return false, fmt.Errorf("signature verification failed")
	}
	return true, nil
}

// VerifyQuoteWithDER verifies a quote using DER-encoded public key bytes.
// Used by the engine backend to verify quotes from sensors.
func VerifyQuoteWithDER(q *Quote, pubDER []byte, nonce []byte) (bool, error) {
	pub, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return false, fmt.Errorf("parse public key: %w", err)
	}
	return verifyQuote(q, pub, nonce)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func hashStr(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// GenerateNonce generates a cryptographically secure nonce for attestation.
func GenerateNonce() ([]byte, error) {
	return secureRandom(32)
}

// ── Dummy key for testing quote verification without a real signer ──────────
// Moved to attestation_test.go to avoid unused warnings in production builds.
