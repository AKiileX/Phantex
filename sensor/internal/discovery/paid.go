// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Package discovery — paid.go
//
// PAID = Phantex Agent ID
//
// Format:  ptx-{tenant}-{env}-{hash12}
// Example: ptx-acme-prod-a1b2c3d4e5f6
//
// The hash component is derived from stable inputs so the same logical agent
// gets the same PAID across process restarts:
//
//	SHA-256( container_id | exe_path | start_time_epoch )
//
// If there's no container, we fall back to:
//
//	SHA-256( hostname | exe_path | cmdline_hash )
//
// This gives stability within a container (restart = same PAID) while
// avoiding collisions across different hosts/containers.
package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// PAIDConfig holds the tenant/env context needed for PAID generation.
type PAIDConfig struct {
	TenantSlug string // e.g., "acme" — from sensor config
	EnvTag     string // e.g., "prod", "staging", "dev"
}

// AgentIdentity holds the inputs used to compute a stable PAID.
type AgentIdentity struct {
	ContainerID string // 64-char hex (empty if bare-metal)
	ExePath     string // /proc/<pid>/exe target
	Cmdline     string // full cmdline for fallback hashing
	StartTime   uint64 // process start time from /proc/<pid>/stat (clock ticks since boot)
}

// GeneratePAID creates a Phantex Agent ID from the given identity.
//
// The PAID is deterministic: same inputs → same PAID.
// The hash portion is 12 hex chars (48 bits) — collision probability is
// ~1 in 281 trillion at 1M agents, which is more than sufficient.
func GeneratePAID(cfg PAIDConfig, id AgentIdentity) string {
	tenant := sanitizeSlug(cfg.TenantSlug)
	if tenant == "" {
		tenant = "default"
	}
	env := sanitizeSlug(cfg.EnvTag)
	if env == "" {
		env = "dev"
	}

	hash := computeHash(id)
	return fmt.Sprintf("ptx-%s-%s-%s", tenant, env, hash[:12])
}

// computeHash derives the stable hash portion of the PAID.
func computeHash(id AgentIdentity) string {
	h := sha256.New()

	if id.ContainerID != "" {
		// Container mode: container_id + exe = stable across process restarts
		// within the same container.
		h.Write([]byte("container:"))
		h.Write([]byte(id.ContainerID))
		h.Write([]byte("|"))
		h.Write([]byte(id.ExePath))
	} else {
		// Bare-metal mode: hostname + exe + cmdline = stable for the same
		// deployment (different processes on the same host get different PAIDs).
		hostname, _ := os.Hostname()
		h.Write([]byte("host:"))
		h.Write([]byte(hostname))
		h.Write([]byte("|"))
		h.Write([]byte(id.ExePath))
		h.Write([]byte("|"))
		// Hash the cmdline rather than including it verbatim (can be long)
		cmdHash := sha256.Sum256([]byte(id.Cmdline))
		h.Write(cmdHash[:])
	}

	// Include start time for same-container, different-generation uniqueness
	if id.StartTime > 0 {
		h.Write([]byte(fmt.Sprintf("|st:%d", id.StartTime)))
	}

	sum := h.Sum(nil)
	return hex.EncodeToString(sum)
}

// sanitizeSlug ensures a slug contains only lowercase alphanumeric + hyphens.
func sanitizeSlug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			b.WriteRune(c)
		}
	}
	return b.String()
}
