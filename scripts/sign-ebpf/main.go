// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// sign-ebpf — Ed25519 signing tool for Phantex eBPF bytecode.
//
// Usage:
//
//	# Generate a new Ed25519 keypair
//	go run scripts/sign-ebpf/main.go -genkey -out keys/
//
//	# Sign all .bpf.o files in sensor/internal/ebpf/bpf/
//	go run scripts/sign-ebpf/main.go -key keys/ebpf-sign.seed -dir sensor/internal/ebpf/bpf/
//
// Each .bpf.o file gets a companion .bpf.o.sig containing 64 bytes (raw Ed25519).
//
// In CI, fetch the seed from Vault:
//
//	vault kv get -field=seed secret/phantex/ebpf-signing > /tmp/ebpf-sign.seed
//	go run scripts/sign-ebpf/main.go -key /tmp/ebpf-sign.seed -dir sensor/internal/ebpf/bpf/
//
// The public key (printed during -genkey) should be embedded at build time:
//
//	go build -ldflags "-X github.com/AKiileX/Phantex/sensor/internal/ebpf.bpfPubKeyHex=<hex>"
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	genkey := flag.Bool("genkey", false, "Generate a new Ed25519 keypair")
	outDir := flag.String("out", ".", "Output directory for generated keys")
	keyPath := flag.String("key", "", "Path to hex-encoded 32-byte Ed25519 seed")
	bpfDir := flag.String("dir", "", "Directory containing .bpf.o files to sign")
	flag.Parse()

	if *genkey {
		generateKeypair(*outDir)
		return
	}

	if *keyPath == "" || *bpfDir == "" {
		fmt.Fprintln(os.Stderr, "Usage: sign-ebpf -key <seed-file> -dir <bpf-dir>")
		fmt.Fprintln(os.Stderr, "       sign-ebpf -genkey -out <key-dir>")
		os.Exit(1)
	}

	signAll(*keyPath, *bpfDir)
}

func generateKeypair(outDir string) {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		fatal("create output dir: %v", err)
	}

	// Ed25519 keypair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatal("generate keypair: %v", err)
	}

	// Save seed (first 32 bytes of 64-byte private key)
	seed := priv.Seed()
	seedHex := hex.EncodeToString(seed)
	seedPath := filepath.Join(outDir, "ebpf-sign.seed")
	if err := os.WriteFile(seedPath, []byte(seedHex+"\n"), 0600); err != nil {
		fatal("write seed: %v", err)
	}

	// Save public key
	pubHex := hex.EncodeToString(pub)
	pubPath := filepath.Join(outDir, "ebpf-sign.pub")
	if err := os.WriteFile(pubPath, []byte(pubHex+"\n"), 0644); err != nil {
		fatal("write public key: %v", err)
	}

	fmt.Printf("Ed25519 keypair generated:\n")
	fmt.Printf("  Seed (KEEP SECRET): %s\n", seedPath)
	fmt.Printf("  Public key:         %s\n", pubPath)
	fmt.Printf("\nPublic key hex (for -ldflags):\n  %s\n", pubHex)
	fmt.Printf("\nBuild sensor with:\n")
	fmt.Printf("  go build -ldflags \"-X github.com/AKiileX/Phantex/sensor/internal/ebpf.bpfPubKeyHex=%s\"\n", pubHex)
}

func signAll(keyPath, bpfDir string) {
	// Read seed
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		fatal("read key: %v", err)
	}
	seedBytes, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seedBytes) != ed25519.SeedSize {
		fatal("invalid seed: expected %d hex-encoded bytes (got %d decoded)", ed25519.SeedSize, len(seedBytes))
	}
	privKey := ed25519.NewKeyFromSeed(seedBytes)

	// Find .bpf.o files
	pattern := filepath.Join(bpfDir, "*.bpf.o")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		fatal("glob %s: %v", pattern, err)
	}
	if len(matches) == 0 {
		fatal("no .bpf.o files found in %s", bpfDir)
	}

	// Sign each
	for _, objPath := range matches {
		data, err := os.ReadFile(objPath)
		if err != nil {
			fatal("read %s: %v", objPath, err)
		}

		sig := ed25519.Sign(privKey, data)
		sigPath := objPath + ".sig"
		if err := os.WriteFile(sigPath, sig, 0644); err != nil {
			fatal("write %s: %v", sigPath, err)
		}

		fmt.Printf("  signed: %s → %s (%d bytes, sig %d bytes)\n",
			filepath.Base(objPath), filepath.Base(sigPath), len(data), len(sig))
	}

	pubHex := hex.EncodeToString(privKey.Public().(ed25519.PublicKey))
	fmt.Printf("\nSigned %d BPF objects. Public key: %s\n", len(matches), pubHex)
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "sign-ebpf: "+format+"\n", args...)
	os.Exit(1)
}
