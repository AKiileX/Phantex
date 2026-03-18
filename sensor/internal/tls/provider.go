// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Package tls provides TLS configuration helpers for the Phantex sensor.
//
// Supports mTLS with automatic certificate reloading for Vault-issued
// short-lived certs. Shared pattern with gateway/internal/tls.
package tls

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Config holds TLS file paths and behavior settings.
type Config struct {
	// Client certificate and key (for mTLS)
	CertFile string
	KeyFile  string

	// CA certificate for verifying the server (gateway)
	CAFile string

	// SHA-256 fingerprint of the trusted CA certificate (hex-encoded).
	// When set, the root CA in the gateway's chain must match this fingerprint.
	// This provides certificate pinning on top of standard x509 verification.
	CAFingerprint string

	// Minimum TLS version (default: TLS 1.3)
	MinVersion uint16

	// Auto-reload interval (0 = disabled)
	ReloadInterval time.Duration
}

// Provider manages TLS configuration with optional hot-reloading.
type Provider struct {
	cfg    Config
	log    *zap.Logger
	mu     sync.RWMutex
	cert   *tls.Certificate
	caPool *x509.CertPool
	stopCh chan struct{}
	once   sync.Once
}

// NewProvider creates a TLS provider that loads certs from disk.
func NewProvider(cfg Config, log *zap.Logger) (*Provider, error) {
	if cfg.MinVersion == 0 {
		cfg.MinVersion = tls.VersionTLS13
	}
	p := &Provider{
		cfg:    cfg,
		log:    log.Named("tls"),
		stopCh: make(chan struct{}),
	}
	if err := p.loadCertificates(); err != nil {
		return nil, fmt.Errorf("initial cert load: %w", err)
	}
	return p, nil
}

// loadCertificates reads cert, key, and CA from disk.
func (p *Provider) loadCertificates() error {
	var cert *tls.Certificate
	if p.cfg.CertFile != "" && p.cfg.KeyFile != "" {
		c, err := tls.LoadX509KeyPair(p.cfg.CertFile, p.cfg.KeyFile)
		if err != nil {
			return fmt.Errorf("load keypair (%s, %s): %w", p.cfg.CertFile, p.cfg.KeyFile, err)
		}
		cert = &c
	}

	var caPool *x509.CertPool
	if p.cfg.CAFile != "" {
		caPEM, err := os.ReadFile(p.cfg.CAFile)
		if err != nil {
			return fmt.Errorf("read CA file %s: %w", p.cfg.CAFile, err)
		}
		caPool = x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caPEM) {
			return fmt.Errorf("failed to parse CA certificate from %s", p.cfg.CAFile)
		}
	}

	p.mu.Lock()
	p.cert = cert
	p.caPool = caPool
	p.mu.Unlock()

	p.log.Info("tls_certificates_loaded",
		zap.String("cert", p.cfg.CertFile),
		zap.String("ca", p.cfg.CAFile))

	return nil
}

// ClientTLSConfig returns a *tls.Config suitable for gRPC dial options.
// The VerifyPeerCertificate callback re-reads p.caPool under lock so that
// CA rotations via hot-reload take effect without restarting the sensor.
func (p *Provider) ClientTLSConfig() *tls.Config {
	p.mu.RLock()
	defer p.mu.RUnlock()

	cfg := &tls.Config{
		MinVersion: p.cfg.MinVersion,
	}

	// Client certificate for mTLS
	if p.cert != nil {
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			p.mu.RLock()
			defer p.mu.RUnlock()
			return p.cert, nil
		}
	}

	// CA for server verification — set as baseline + callback for hot-reload
	if p.caPool != nil {
		cfg.RootCAs = p.caPool
		cfg.VerifyPeerCertificate = p.verifyServerCert
	}

	return cfg
}

// verifyServerCert re-verifies the server certificate chain against the
// current (possibly hot-reloaded) CA pool.
func (p *Provider) verifyServerCert(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("no server certificate presented")
	}

	p.mu.RLock()
	pool := p.caPool
	p.mu.RUnlock()

	if pool == nil {
		return fmt.Errorf("no CA pool configured")
	}

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("parse server cert: %w", err)
	}

	intermediates := x509.NewCertPool()
	for _, raw := range rawCerts[1:] {
		ic, err := x509.ParseCertificate(raw)
		if err == nil {
			intermediates.AddCert(ic)
		}
	}

	chains, err := cert.Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return err
	}

	// CA fingerprint pinning — if configured, verify the root CA's SHA-256
	// fingerprint matches the pinned value.
	if pin := p.cfg.CAFingerprint; pin != "" {
		if err := verifyCAFingerprint(chains, pin); err != nil {
			return err
		}
	}

	return nil
}

// verifyCAFingerprint checks that the root CA in at least one verified chain
// matches the expected SHA-256 fingerprint.
func verifyCAFingerprint(chains [][]*x509.Certificate, expected string) error {
	normalized := strings.ReplaceAll(strings.ToLower(expected), ":", "")
	for _, chain := range chains {
		if len(chain) == 0 {
			continue
		}
		root := chain[len(chain)-1]
		fp := sha256.Sum256(root.Raw)
		if hex.EncodeToString(fp[:]) == normalized {
			return nil
		}
	}
	return fmt.Errorf("CA fingerprint mismatch: none of the verified chains contain a root matching %s", expected)
}

// StartReloader launches a background goroutine that periodically reloads
// certificates from disk.
func (p *Provider) StartReloader() {
	if p.cfg.ReloadInterval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(p.cfg.ReloadInterval)
		defer ticker.Stop()
		for {
			select {
			case <-p.stopCh:
				return
			case <-ticker.C:
				if err := p.loadCertificates(); err != nil {
					p.log.Warn("tls_cert_reload_failed", zap.Error(err))
				}
			}
		}
	}()
	p.log.Info("tls_cert_reloader_started",
		zap.Duration("interval", p.cfg.ReloadInterval))
}

// Stop signals the reload goroutine to exit. Safe to call multiple times.
func (p *Provider) Stop() {
	p.once.Do(func() { close(p.stopCh) })
}
