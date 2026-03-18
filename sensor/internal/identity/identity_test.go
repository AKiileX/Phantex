// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

package identity

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"testing"

	"go.uber.org/zap"
)

func testLogger() *zap.Logger {
	l, _ := zap.NewDevelopment()
	return l
}

// ── Identity Manager ─────────────────────────────────────────────────────────

func TestManagerInitialize(t *testing.T) {
	m := NewManager(testLogger())
	if err := m.Initialize("agent-test-001"); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	defer m.Close()

	if m.Signer() == nil {
		t.Fatal("expected signer after init")
	}
	info := m.Signer().Info()
	if info.AgentID != "agent-test-001" {
		t.Errorf("agent_id = %q, want 'agent-test-001'", info.AgentID)
	}
	if len(info.PublicKeyDER) == 0 {
		t.Error("public key DER is empty")
	}
}

func TestManagerLevel(t *testing.T) {
	m := NewManager(testLogger())
	if m.Level() != LevelNone {
		t.Errorf("initial level = %v, want None", m.Level())
	}
	if err := m.Initialize("agent-lvl"); err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	// Should be at least software level
	if m.Level() < LevelSoftware {
		t.Errorf("post-init level = %v, want >= Software", m.Level())
	}
}

func TestManagerUpgradeToAttested(t *testing.T) {
	m := NewManager(testLogger())
	if err := m.Initialize("agent-upgrade"); err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	// Force level to hardware for test
	m.mu.Lock()
	m.level = LevelHardware
	m.mu.Unlock()

	m.UpgradeToAttested()
	if m.Level() != LevelAttested {
		t.Errorf("level = %v, want Attested", m.Level())
	}
}

func TestManagerUpgradeIgnoredBelowHardware(t *testing.T) {
	m := NewManager(testLogger())
	if err := m.Initialize("agent-no-upgrade"); err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	m.mu.Lock()
	m.level = LevelSoftware
	m.mu.Unlock()

	m.UpgradeToAttested()
	if m.Level() != LevelSoftware {
		t.Errorf("level = %v, want Software (unchanged)", m.Level())
	}
}

func TestLevelString(t *testing.T) {
	tests := []struct {
		l    Level
		want string
	}{
		{LevelNone, "none"},
		{LevelSoftware, "software"},
		{LevelOS, "os"},
		{LevelHardware, "hardware"},
		{LevelAttested, "attested"},
		{Level(99), "unknown(99)"},
	}
	for _, tt := range tests {
		if got := tt.l.String(); got != tt.want {
			t.Errorf("Level(%d).String() = %q, want %q", int(tt.l), got, tt.want)
		}
	}
}

// ── TPM Signer ───────────────────────────────────────────────────────────────

func TestTPMSignerSign(t *testing.T) {
	s, err := openTPM("agent-tpm", testLogger())
	if err != nil {
		t.Fatalf("openTPM: %v", err)
	}
	defer s.Close()

	data := []byte("hello world")
	sig, err := s.Sign(data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Error("empty signature")
	}

	// Sign() internally computes sha256(data) then signs that hash.
	// Verify: sha256(data) is the hash that was signed.
	digest := sha256.Sum256(data)
	pub := s.Public().(*ecdsa.PublicKey)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Error("signature verification failed")
	}
}

func TestTPMSignerEmptyDigest(t *testing.T) {
	s, _ := openTPM("agent-empty", testLogger())
	defer s.Close()
	_, err := s.Sign([]byte{})
	if err == nil {
		t.Error("expected error for empty digest")
	}
}

func TestTPMSignerInfo(t *testing.T) {
	s, _ := openTPM("agent-info", testLogger())
	defer s.Close()
	info := s.Info()
	if info.Backend != "tpm2" {
		t.Errorf("backend = %q, want 'tpm2'", info.Backend)
	}
	if info.Level != LevelHardware {
		t.Errorf("level = %v, want Hardware", info.Level)
	}
}

// ── Software Key ─────────────────────────────────────────────────────────────

func TestSoftwareKeySign(t *testing.T) {
	s, err := newSoftwareKey("agent-sw", testLogger())
	if err != nil {
		t.Fatalf("newSoftwareKey: %v", err)
	}
	sig, err := s.Sign([]byte("test data"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Error("empty signature")
	}
}

func TestSoftwareKeyInfo(t *testing.T) {
	s, _ := newSoftwareKey("agent-sw-info", testLogger())
	info := s.Info()
	if info.Backend != "software" {
		t.Errorf("backend = %q, want 'software'", info.Backend)
	}
	if info.Level != LevelSoftware {
		t.Errorf("level = %v, want Software", info.Level)
	}
}

// ── Attestation ──────────────────────────────────────────────────────────────

func TestAttesterGenerateQuote(t *testing.T) {
	s, _ := openTPM("agent-attest", testLogger())
	defer s.Close()
	a := NewAttester(s, testLogger())

	nonce, _ := GenerateNonce()
	q, err := a.GenerateQuote(nonce)
	if err != nil {
		t.Fatalf("GenerateQuote: %v", err)
	}
	if len(q.PCRs) == 0 {
		t.Error("no PCR values in quote")
	}
	if len(q.Signature) == 0 {
		t.Error("empty signature in quote")
	}
}

func TestAttesterEmptyNonce(t *testing.T) {
	s, _ := openTPM("agent-empty-nonce", testLogger())
	defer s.Close()
	a := NewAttester(s, testLogger())
	_, err := a.GenerateQuote([]byte{})
	if err == nil {
		t.Error("expected error for empty nonce")
	}
}

func TestAttesterNonceTooLarge(t *testing.T) {
	s, _ := openTPM("agent-big-nonce", testLogger())
	defer s.Close()
	a := NewAttester(s, testLogger())
	bigNonce := make([]byte, 65)
	_, err := a.GenerateQuote(bigNonce)
	if err == nil {
		t.Error("expected error for oversized nonce")
	}
}

func TestAttesterFullAttest(t *testing.T) {
	s, _ := openTPM("agent-full-attest", testLogger())
	defer s.Close()
	a := NewAttester(s, testLogger())

	result, err := a.Attest()
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if !result.Success {
		t.Errorf("attestation failed: %s", result.FailReason)
	}
	if result.Level != LevelAttested {
		t.Errorf("level = %v, want Attested", result.Level)
	}
	if result.NonceHex == "" {
		t.Error("empty nonce hex")
	}
	if result.SignatureHex == "" {
		t.Error("empty signature hex")
	}
}

func TestAttesterResults(t *testing.T) {
	s, _ := openTPM("agent-results", testLogger())
	defer s.Close()
	a := NewAttester(s, testLogger())

	_, _ = a.Attest()
	_, _ = a.Attest()
	results := a.Results()
	if len(results) != 2 {
		t.Errorf("len(results) = %d, want 2", len(results))
	}
}

func TestVerifyQuoteWithValidSignature(t *testing.T) {
	s, _ := openTPM("agent-verify", testLogger())
	defer s.Close()
	a := NewAttester(s, testLogger())

	nonce, _ := GenerateNonce()
	q, _ := a.GenerateQuote(nonce)

	ok, err := verifyQuote(q, s.Public(), nonce)
	if err != nil {
		t.Fatalf("verifyQuote: %v", err)
	}
	if !ok {
		t.Error("valid quote failed verification")
	}
}

func TestVerifyQuoteWithWrongNonce(t *testing.T) {
	s, _ := openTPM("agent-wrong-nonce", testLogger())
	defer s.Close()
	a := NewAttester(s, testLogger())

	nonce, _ := GenerateNonce()
	q, _ := a.GenerateQuote(nonce)

	// Verify with different nonce → should fail
	wrongNonce := make([]byte, 32)
	copy(wrongNonce, nonce)
	wrongNonce[0] ^= 0xFF

	ok, err := verifyQuote(q, s.Public(), wrongNonce)
	if ok || err == nil {
		t.Error("expected verification failure with wrong nonce")
	}
}

func TestVerifyQuoteWithDER(t *testing.T) {
	s, _ := openTPM("agent-der", testLogger())
	defer s.Close()
	a := NewAttester(s, testLogger())

	nonce, _ := GenerateNonce()
	q, _ := a.GenerateQuote(nonce)

	ok, err := VerifyQuoteWithDER(q, s.Info().PublicKeyDER, nonce)
	if err != nil {
		t.Fatalf("VerifyQuoteWithDER: %v", err)
	}
	if !ok {
		t.Error("DER-based verification failed")
	}
}

func TestDeriveAgentID(t *testing.T) {
	id := DeriveAgentID([]byte("test-key-material"))
	if len(id) == 0 {
		t.Error("empty derived agent ID")
	}
	if id[:6] != "agent-" {
		t.Errorf("id prefix = %q, want 'agent-'", id[:6])
	}
	// Deterministic
	id2 := DeriveAgentID([]byte("test-key-material"))
	if id != id2 {
		t.Error("DeriveAgentID not deterministic")
	}
}

func TestGenerateNonce(t *testing.T) {
	n1, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}
	if len(n1) != 32 {
		t.Errorf("nonce len = %d, want 32", len(n1))
	}
	n2, _ := GenerateNonce()
	if string(n1) == string(n2) {
		t.Error("two nonces are identical — weak PRNG?")
	}
}
