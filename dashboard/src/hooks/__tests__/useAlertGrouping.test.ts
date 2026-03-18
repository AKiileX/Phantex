// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — useAlertGrouping unit tests.
 *
 * Tests grouping logic: same rule+agent within time window = one group,
 * severity escalation, multi-group scenarios, disabled grouping.
 */

import { describe, it, expect } from "vitest"
import { renderHook } from "@testing-library/react"
import { useAlertGrouping } from "@/hooks/useAlertGrouping"
import type { AlertSummary } from "@/types"

function makeAlert(overrides: Partial<AlertSummary> = {}): AlertSummary {
  return {
    id: crypto.randomUUID(),
    severity: "medium",
    title: "Test Alert",
    status: "open",
    created_at: new Date().toISOString(),
    agent_id: "agent-1",
    rule_id: "rule-1",
    event_id: null,
    ...overrides,
  }
}

describe("useAlertGrouping", () => {
  it("groups alerts with same rule_id + agent_id in same time window", () => {
    const now = Date.now()
    const alerts = [
      makeAlert({ id: "1", rule_id: "r1", agent_id: "a1", created_at: new Date(now).toISOString() }),
      makeAlert({ id: "2", rule_id: "r1", agent_id: "a1", created_at: new Date(now + 1000).toISOString() }),
      makeAlert({ id: "3", rule_id: "r1", agent_id: "a1", created_at: new Date(now + 2000).toISOString() }),
    ]

    const { result } = renderHook(() => useAlertGrouping(alerts, { windowMs: 300_000 }))

    expect(result.current.groups).toHaveLength(1)
    expect(result.current.groups![0].count).toBe(3)
    expect(result.current.isGrouped).toBe(true)
  })

  it("keeps different rules in separate groups", () => {
    const now = Date.now()
    const alerts = [
      makeAlert({ id: "1", rule_id: "r1", agent_id: "a1", created_at: new Date(now).toISOString() }),
      makeAlert({ id: "2", rule_id: "r2", agent_id: "a1", created_at: new Date(now).toISOString() }),
    ]

    const { result } = renderHook(() => useAlertGrouping(alerts, { windowMs: 300_000 }))

    expect(result.current.groups).toHaveLength(2)
    expect(result.current.groups![0].count).toBe(1)
    expect(result.current.groups![1].count).toBe(1)
  })

  it("keeps different agents in separate groups", () => {
    const now = Date.now()
    const alerts = [
      makeAlert({ id: "1", rule_id: "r1", agent_id: "a1", created_at: new Date(now).toISOString() }),
      makeAlert({ id: "2", rule_id: "r1", agent_id: "a2", created_at: new Date(now).toISOString() }),
    ]

    const { result } = renderHook(() => useAlertGrouping(alerts, { windowMs: 300_000 }))

    expect(result.current.groups).toHaveLength(2)
  })

  it("escalates severity to highest in group", () => {
    const now = Date.now()
    const alerts = [
      makeAlert({ id: "1", rule_id: "r1", agent_id: "a1", severity: "low", created_at: new Date(now).toISOString() }),
      makeAlert({ id: "2", rule_id: "r1", agent_id: "a1", severity: "critical", created_at: new Date(now + 1000).toISOString() }),
      makeAlert({ id: "3", rule_id: "r1", agent_id: "a1", severity: "medium", created_at: new Date(now + 2000).toISOString() }),
    ]

    const { result } = renderHook(() => useAlertGrouping(alerts, { windowMs: 300_000 }))

    expect(result.current.groups![0].severity).toBe("critical")
  })

  it("separates alerts in different time windows", () => {
    const now = Date.now()
    const alerts = [
      makeAlert({ id: "1", rule_id: "r1", agent_id: "a1", created_at: new Date(now).toISOString() }),
      // 10 minutes later — outside 5-min window
      makeAlert({ id: "2", rule_id: "r1", agent_id: "a1", created_at: new Date(now + 600_000).toISOString() }),
    ]

    const { result } = renderHook(() => useAlertGrouping(alerts, { windowMs: 300_000 }))

    expect(result.current.groups).toHaveLength(2)
  })

  it("returns null groups when disabled", () => {
    const alerts = [makeAlert({ id: "1" })]

    const { result } = renderHook(() => useAlertGrouping(alerts, { enabled: false }))

    expect(result.current.groups).toBeNull()
    expect(result.current.isGrouped).toBe(false)
  })

  it("handles empty alert list", () => {
    const { result } = renderHook(() => useAlertGrouping([]))

    expect(result.current.groups).toHaveLength(0)
    expect(result.current.groupCount).toBe(0)
    expect(result.current.isGrouped).toBe(false)
  })

  it("sorts groups by most recent alert descending", () => {
    const now = Date.now()
    const alerts = [
      makeAlert({ id: "1", rule_id: "r1", agent_id: "a1", created_at: new Date(now - 60000).toISOString() }),
      makeAlert({ id: "2", rule_id: "r2", agent_id: "a2", created_at: new Date(now).toISOString() }),
    ]

    const { result } = renderHook(() => useAlertGrouping(alerts, { windowMs: 300_000 }))

    // Most recent group first
    expect(result.current.groups![0].rule_id).toBe("r2")
    expect(result.current.groups![1].rule_id).toBe("r1")
  })
})
