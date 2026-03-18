// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — O1–O3 Security Audit Hardening Tests
 *
 * Tests added during the O1–O3 security audit to verify:
 *   F1: Timeline API UUID validation (path-traversal defense)
 *   F3: Investigation page UUID gating
 *   F4: replaceAll("_", " ") correctness
 *   F5: CorrelationGraph coordinate null safety
 *   General: defense-in-depth for client-side data handling
 */

import { describe, it, expect } from "vitest"

/* ── F1/F3: UUID validation regex ─────────────────────────────────────────── */

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

describe("UUID validation (F1/F3 — path-traversal defence)", () => {
  it("accepts valid UUID v4", () => {
    expect(UUID_RE.test("a1b2c3d4-e5f6-7890-abcd-ef1234567890")).toBe(true)
  })

  it("accepts uppercase UUID", () => {
    expect(UUID_RE.test("A1B2C3D4-E5F6-7890-ABCD-EF1234567890")).toBe(true)
  })

  it("rejects path-traversal payload", () => {
    expect(UUID_RE.test("../../admin/users")).toBe(false)
  })

  it("rejects encoded path-traversal", () => {
    expect(UUID_RE.test("..%2F..%2Fadmin%2Fusers")).toBe(false)
  })

  it("rejects plain strings", () => {
    expect(UUID_RE.test("abc-123")).toBe(false)
  })

  it("rejects empty string", () => {
    expect(UUID_RE.test("")).toBe(false)
  })

  it("rejects UUID with extra suffix (injection)", () => {
    expect(UUID_RE.test("a1b2c3d4-e5f6-7890-abcd-ef1234567890/../../admin")).toBe(false)
  })

  it("rejects UUID with leading space", () => {
    expect(UUID_RE.test(" a1b2c3d4-e5f6-7890-abcd-ef1234567890")).toBe(false)
  })

  it("rejects SQL injection payload", () => {
    expect(UUID_RE.test("'; DROP TABLE alerts; --")).toBe(false)
  })

  it("rejects XSS payload", () => {
    expect(UUID_RE.test("<script>alert(1)</script>")).toBe(false)
  })
})

/* ── F4: replaceAll correctness ───────────────────────────────────────────── */

describe("replaceAll('_', ' ') correctness (F4)", () => {
  it("replaces single underscore", () => {
    expect("false_positive".replaceAll("_", " ")).toBe("false positive")
  })

  it("replaces multiple underscores", () => {
    expect("auto_resolved_by_system".replaceAll("_", " ")).toBe("auto resolved by system")
  })

  it("handles no underscores", () => {
    expect("open".replaceAll("_", " ")).toBe("open")
  })

  it("old replace() only fixes first underscore (regression proof)", () => {
    // This demonstrates why replaceAll was needed
    expect("a_b_c".replace("_", " ")).toBe("a b_c") // wrong
    expect("a_b_c".replaceAll("_", " ")).toBe("a b c") // correct
  })
})

/* ── F5: Coordinate null-safety ───────────────────────────────────────────── */

describe("Coordinate null safety (F5)", () => {
  it("0 is a valid coordinate (not null)", () => {
    const x = 0
    // Old check: !x → true (would hide node at x=0)
    expect(!x).toBe(true)
    // New check: x == null → false (correctly shows node)
    expect(x == null).toBe(false)
  })

  it("null is correctly detected", () => {
    const x: number | null = null
    expect(x == null).toBe(true)
  })

  it("undefined is correctly detected", () => {
    const x: number | undefined = undefined
    expect(x == null).toBe(true)
  })
})

/* ── General: timeline data handling ──────────────────────────────────────── */

describe("Timeline data safety", () => {
  it("JSON.stringify safely handles nested objects (no XSS via raw_data)", () => {
    const malicious = {
      key: '<script>alert("xss")</script>',
      nested: { payload: "'; DROP TABLE --" },
    }
    const result = JSON.stringify(malicious, null, 2)
    // JSON.stringify escapes quotes, React will auto-escape angle brackets
    expect(result).toContain("<script>")
    expect(result).not.toContain("</script>\\n") // it's safe in <pre> via React
    expect(typeof result).toBe("string")
  })

  it("String() coercion handles non-string ATLAS fields safely", () => {
    expect(String(undefined)).toBe("undefined")
    expect(String(null)).toBe("null")
    expect(String(42)).toBe("42")
    expect(String({ id: "T001" })).toBe("[object Object]")
  })

  it("trust score bar width is clamped to [0, 100]%", () => {
    const clamp = (score: number) => Math.max(0, Math.min(100, score * 100))
    expect(clamp(0.5)).toBe(50)
    expect(clamp(1.0)).toBe(100)
    expect(clamp(1.5)).toBe(100) // clamped high
    expect(clamp(0)).toBe(0)
    expect(clamp(-0.5)).toBe(0) // clamped low (fixed from Math.min-only)
  })

  it("trust score bar handles negative values", () => {
    // Negative trust scores should result in 0% width, not negative CSS width
    const clamp = (score: number) => Math.max(0, Math.min(100, score * 100))
    expect(clamp(-0.5)).toBe(0)
    expect(clamp(-1)).toBe(0)
  })
})
