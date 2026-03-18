// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
)

// generateSensorTestCerts creates a CA + leaf cert pair in a temp dir.
func generateSensorTestCerts(t *testing.T, eku ...x509.ExtKeyUsage) (certFile, keyFile, caFile string) {
	t.Helper()
	dir := t.TempDir()

	// CA key + cert
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatal(err)
	}
	caFile = filepath.Join(dir, "ca.pem")
	writeSensorPEM(t, caFile, "CERTIFICATE", caCertDER)

	if len(eku) == 0 {
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	}

	// Leaf key + cert
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  eku,
		DNSNames:     []string{"localhost"},
	}
	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	certFile = filepath.Join(dir, "leaf.pem")
	writeSensorPEM(t, certFile, "CERTIFICATE", leafCertDER)

	keyFile = filepath.Join(dir, "leaf-key.pem")
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	writeSensorPEM(t, keyFile, "EC PRIVATE KEY", keyDER)

	return certFile, keyFile, caFile
}

func writeSensorPEM(t *testing.T, path, blockType string, data []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: data}); err != nil {
		t.Fatal(err)
	}
}

// ── NewProvider ─────────────────────────────────────────────────────────────

func TestNewProvider_LoadsCerts(t *testing.T) {
	certFile, keyFile, caFile := generateSensorTestCerts(t)
	log := zap.NewNop()

	p, err := NewProvider(Config{
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   caFile,
	}, log)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	defer p.Stop()

	if p.cert == nil {
		t.Fatal("expected cert to be loaded")
	}
	if p.caPool == nil {
		t.Fatal("expected CA pool to be loaded")
	}
}

func TestNewProvider_NoCert_OK(t *testing.T) {
	_, _, caFile := generateSensorTestCerts(t)
	log := zap.NewNop()

	// Sensor can be created with just CA (no client cert)
	p, err := NewProvider(Config{
		CAFile: caFile,
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	if p.cert != nil {
		t.Error("expected nil cert when no cert file provided")
	}
}

func TestNewProvider_MissingCert_Error(t *testing.T) {
	log := zap.NewNop()
	_, err := NewProvider(Config{
		CertFile: "/nonexistent/cert.pem",
		KeyFile:  "/nonexistent/key.pem",
	}, log)
	if err == nil {
		t.Fatal("expected error for missing cert files")
	}
}

func TestNewProvider_BadCA_Error(t *testing.T) {
	certFile, keyFile, _ := generateSensorTestCerts(t)
	log := zap.NewNop()

	// Write garbage CA file
	badCA := filepath.Join(t.TempDir(), "bad-ca.pem")
	if err := os.WriteFile(badCA, []byte("not a certificate"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := NewProvider(Config{
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   badCA,
	}, log)
	if err == nil {
		t.Fatal("expected error for bad CA file")
	}
}

func TestDefaultMinVersion_TLS13(t *testing.T) {
	_, _, caFile := generateSensorTestCerts(t)
	log := zap.NewNop()

	p, err := NewProvider(Config{CAFile: caFile}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	if p.cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected default TLS 1.3, got %d", p.cfg.MinVersion)
	}
}

// ── ClientTLSConfig ─────────────────────────────────────────────────────────

func TestClientTLSConfig_WithCertAndCA(t *testing.T) {
	certFile, keyFile, caFile := generateSensorTestCerts(t)
	log := zap.NewNop()

	p, err := NewProvider(Config{
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   caFile,
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	cfg := p.ClientTLSConfig()

	if cfg.RootCAs == nil {
		t.Error("expected RootCAs to be set")
	}
	if cfg.GetClientCertificate == nil {
		t.Error("expected GetClientCertificate to be set")
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected TLS 1.3, got %d", cfg.MinVersion)
	}
}

func TestClientTLSConfig_VerifyPeerCertificate_Set(t *testing.T) {
	certFile, keyFile, caFile := generateSensorTestCerts(t)
	log := zap.NewNop()

	p, err := NewProvider(Config{
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   caFile,
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	cfg := p.ClientTLSConfig()
	if cfg.VerifyPeerCertificate == nil {
		t.Error("expected VerifyPeerCertificate callback to be set for CA hot-reload")
	}
}

func TestClientTLSConfig_NoCert(t *testing.T) {
	_, _, caFile := generateSensorTestCerts(t)
	log := zap.NewNop()

	p, err := NewProvider(Config{CAFile: caFile}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	cfg := p.ClientTLSConfig()
	if cfg.GetClientCertificate != nil {
		t.Error("expected nil GetClientCertificate when no client cert loaded")
	}
	// Should still have RootCAs
	if cfg.RootCAs == nil {
		t.Error("expected RootCAs to be set")
	}
}

func TestClientTLSConfig_NoCA(t *testing.T) {
	certFile, keyFile, _ := generateSensorTestCerts(t)
	log := zap.NewNop()

	p, err := NewProvider(Config{
		CertFile: certFile,
		KeyFile:  keyFile,
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	cfg := p.ClientTLSConfig()
	if cfg.RootCAs != nil {
		t.Error("expected nil RootCAs when no CA provided")
	}
	if cfg.VerifyPeerCertificate != nil {
		t.Error("expected nil VerifyPeerCertificate when no CA")
	}
}

// ── verifyServerCert ────────────────────────────────────────────────────────

func TestVerifyServerCert_ValidChain(t *testing.T) {
	certFile, _, caFile := generateSensorTestCerts(t, x509.ExtKeyUsageServerAuth)
	log := zap.NewNop()

	p, err := NewProvider(Config{CAFile: caFile}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	// Read the leaf cert DER
	certPEM, _ := os.ReadFile(certFile)
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode PEM")
	}

	err = p.verifyServerCert([][]byte{block.Bytes}, nil)
	if err != nil {
		t.Fatalf("verifyServerCert failed for valid cert: %v", err)
	}
}

func TestVerifyServerCert_NoCerts(t *testing.T) {
	_, _, caFile := generateSensorTestCerts(t)
	log := zap.NewNop()

	p, err := NewProvider(Config{CAFile: caFile}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	err = p.verifyServerCert(nil, nil)
	if err == nil {
		t.Fatal("expected error for empty cert chain")
	}
}

func TestVerifyServerCert_WrongCA(t *testing.T) {
	// Generate two separate CAs — cert from CA1, verify against CA2
	_, _, caFile1 := generateSensorTestCerts(t, x509.ExtKeyUsageServerAuth)
	certFile2, _, _ := generateSensorTestCerts(t, x509.ExtKeyUsageServerAuth)

	log := zap.NewNop()

	// Provider trusts CA1
	p, err := NewProvider(Config{CAFile: caFile1}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	// Try to verify cert from CA2 against CA1 — should fail
	certPEM, _ := os.ReadFile(certFile2)
	block, _ := pem.Decode(certPEM)

	err = p.verifyServerCert([][]byte{block.Bytes}, nil)
	if err == nil {
		t.Fatal("expected error for cert signed by different CA")
	}
}

// ── CA Fingerprint Pinning ──────────────────────────────────────────────────

func TestVerifyServerCert_FingerprintMatch(t *testing.T) {
	certFile, _, caFile := generateSensorTestCerts(t, x509.ExtKeyUsageServerAuth)

	// Compute the CA fingerprint
	caPEM, _ := os.ReadFile(caFile)
	caBlock, _ := pem.Decode(caPEM)
	fp := sha256.Sum256(caBlock.Bytes)
	pin := hex.EncodeToString(fp[:])

	log := zap.NewNop()
	p, err := NewProvider(Config{
		CAFile:        caFile,
		CAFingerprint: pin,
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	leafPEM, _ := os.ReadFile(certFile)
	leafBlock, _ := pem.Decode(leafPEM)

	if err := p.verifyServerCert([][]byte{leafBlock.Bytes}, nil); err != nil {
		t.Fatalf("expected fingerprint match, got error: %v", err)
	}
}

func TestVerifyServerCert_FingerprintMismatch(t *testing.T) {
	certFile, _, caFile := generateSensorTestCerts(t, x509.ExtKeyUsageServerAuth)
	wrongPin := "0000000000000000000000000000000000000000000000000000000000000000"

	log := zap.NewNop()
	p, err := NewProvider(Config{
		CAFile:        caFile,
		CAFingerprint: wrongPin,
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	leafPEM, _ := os.ReadFile(certFile)
	leafBlock, _ := pem.Decode(leafPEM)

	if err := p.verifyServerCert([][]byte{leafBlock.Bytes}, nil); err == nil {
		t.Fatal("expected fingerprint mismatch error")
	}
}

func TestVerifyServerCert_NilCAPool(t *testing.T) {
	log := zap.NewNop()
	certFile, keyFile, _ := generateSensorTestCerts(t)

	// No CA file — caPool will be nil
	p, err := NewProvider(Config{
		CertFile: certFile,
		KeyFile:  keyFile,
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	err = p.verifyServerCert([][]byte{{0x30, 0x82}}, nil) // garbage DER
	if err == nil {
		t.Fatal("expected error when caPool is nil")
	}
}

// ── StartReloader / Stop ────────────────────────────────────────────────────

func TestStartReloader_DisabledByDefault(t *testing.T) {
	_, _, caFile := generateSensorTestCerts(t)
	log := zap.NewNop()

	p, err := NewProvider(Config{
		CAFile:         caFile,
		ReloadInterval: 0, // disabled
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	// StartReloader should be a no-op when interval=0
	p.StartReloader()
	p.Stop()
}

func TestStartReloader_WithInterval(t *testing.T) {
	certFile, keyFile, caFile := generateSensorTestCerts(t)
	log := zap.NewNop()

	p, err := NewProvider(Config{
		CertFile:       certFile,
		KeyFile:        keyFile,
		CAFile:         caFile,
		ReloadInterval: 50 * time.Millisecond,
	}, log)
	if err != nil {
		t.Fatal(err)
	}

	p.StartReloader()
	time.Sleep(150 * time.Millisecond) // at least 2-3 reloads
	p.Stop()
}
