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

	"go.uber.org/zap/zaptest"
)

// generateTestCerts creates a CA + leaf cert pair in a temp dir.
func generateTestCerts(t *testing.T) (certFile, keyFile, caFile string) {
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
	writePEM(t, caFile, "CERTIFICATE", caCertDER)

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
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"localhost"},
	}
	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	certFile = filepath.Join(dir, "leaf.pem")
	writePEM(t, certFile, "CERTIFICATE", leafCertDER)

	keyFile = filepath.Join(dir, "leaf-key.pem")
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, keyFile, "EC PRIVATE KEY", keyDER)

	return certFile, keyFile, caFile
}

func writePEM(t *testing.T, path, blockType string, data []byte) {
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

func TestNewProvider(t *testing.T) {
	certFile, keyFile, caFile := generateTestCerts(t)
	log := zaptest.NewLogger(t)

	p, err := NewProvider(Config{
		CertFile:          certFile,
		KeyFile:           keyFile,
		CAFile:            caFile,
		RequireClientCert: true,
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

func TestServerTLSConfig_RequiresClientCert(t *testing.T) {
	certFile, keyFile, caFile := generateTestCerts(t)
	log := zaptest.NewLogger(t)

	p, err := NewProvider(Config{
		CertFile:          certFile,
		KeyFile:           keyFile,
		CAFile:            caFile,
		RequireClientCert: true,
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	cfg := p.ServerTLSConfig()
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("expected RequireAndVerifyClientCert, got %v", cfg.ClientAuth)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected TLS 1.3, got %d", cfg.MinVersion)
	}
	if cfg.ClientCAs == nil {
		t.Error("expected ClientCAs to be set")
	}
}

func TestClientTLSConfig(t *testing.T) {
	certFile, keyFile, caFile := generateTestCerts(t)
	log := zaptest.NewLogger(t)

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
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected TLS 1.3, got %d", cfg.MinVersion)
	}
	if cfg.GetClientCertificate == nil {
		t.Error("expected GetClientCertificate to be set")
	}
}

func TestProviderWithMissingCert(t *testing.T) {
	log := zaptest.NewLogger(t)
	_, err := NewProvider(Config{
		CertFile: "/nonexistent/cert.pem",
		KeyFile:  "/nonexistent/key.pem",
	}, log)
	if err == nil {
		t.Fatal("expected error for missing cert files")
	}
}

func TestDefaultMinVersion(t *testing.T) {
	certFile, keyFile, _ := generateTestCerts(t)
	log := zaptest.NewLogger(t)

	p, err := NewProvider(Config{
		CertFile: certFile,
		KeyFile:  keyFile,
		// No MinVersion set — should default to TLS 1.3
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	if p.cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected default TLS 1.3, got %d", p.cfg.MinVersion)
	}
}

func TestVerifyCAFingerprint_Match(t *testing.T) {
	// Read the CA cert generated by generateTestCerts to compute its fingerprint
	certFile, keyFile, caFile := generateTestCerts(t)
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(caPEM)
	fp := sha256.Sum256(block.Bytes)
	pin := hex.EncodeToString(fp[:])

	log := zaptest.NewLogger(t)
	p, err := NewProvider(Config{
		CertFile:          certFile,
		KeyFile:           keyFile,
		CAFile:            caFile,
		RequireClientCert: true,
		CAFingerprint:     pin,
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	// Verify that verifyClientCert succeeds with matching fingerprint.
	// Construct a raw cert chain from our test leaf cert.
	leafPEM, _ := os.ReadFile(certFile)
	leafBlock, _ := pem.Decode(leafPEM)
	err = p.verifyClientCert([][]byte{leafBlock.Bytes}, nil)
	if err != nil {
		t.Fatalf("expected fingerprint match, got error: %v", err)
	}
}

func TestVerifyCAFingerprint_Mismatch(t *testing.T) {
	certFile, keyFile, caFile := generateTestCerts(t)
	wrongPin := "0000000000000000000000000000000000000000000000000000000000000000"

	log := zaptest.NewLogger(t)
	p, err := NewProvider(Config{
		CertFile:          certFile,
		KeyFile:           keyFile,
		CAFile:            caFile,
		RequireClientCert: true,
		CAFingerprint:     wrongPin,
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	leafPEM, _ := os.ReadFile(certFile)
	leafBlock, _ := pem.Decode(leafPEM)
	err = p.verifyClientCert([][]byte{leafBlock.Bytes}, nil)
	if err == nil {
		t.Fatal("expected fingerprint mismatch error")
	}
}
