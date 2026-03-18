// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — useAlertCorrelation unit tests.
 *
 * Tests correlation edge computation: same_rule, same_agent,
 * time windowing, Union-Find clustering, node cap, disabled state.
 */

import { describe, it, expect } from "vitest"
import { renderHook } from "@testing-library/react"
import { useAlertCorrelation } from "@/hooks/useAlertCorrelation"
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

describe("useAlertCorrelation", () => {
  it("creates same_rule edges for alerts with matching rule_id within 10-min window", () => {
    const now = Date.now()
    const alerts = [
      makeAlert({ id: "a1", rule_id: "r1", agent_id: "ag1", created_at: new Date(now).toISOString() }),
      makeAlert({ id: "a2", rule_id: "r1", agent_id: "ag2", created_at: new Date(now + 60_000).toISOString() }),
    ]

    const { result } = renderHook(() => useAlertCorrelation(alerts))

    expect(result.current.hasCorrelations).toBe(true)
    expect(result.current.correlation!.edges.some((e) => e.reason === "same_rule")).toBe(true)
    expect(result.current.correlation!.groups).toHaveLength(1)
    expect(result.current.correlation!.groups[0].alerts).toHaveLength(2)
  })

  it("creates same_agent edges for alerts with matching agent_id + different rules", () => {
    const now = Date.now()
    const alerts = [
      makeAlert({ id: "a1", rule_id: "r1", agent_id: "ag1", created_at: new Date(now).toISOString() }),
      makeAlert({ id: "a2", rule_id: "r2", agent_id: "ag1", created_at: new Date(now + 60_000).toISOString() }),
    ]

    const { result } = renderHook(() => useAlertCorrelation(alerts))

    expect(result.current.hasCorrelations).toBe(true)
    expect(result.current.correlation!.edges.some((e) => e.reason === "same_agent")).toBe(true)
  })

  it("does NOT create edges for alerts outside 10-min window", () => {
    const now = Date.now()
    const alerts = [
      makeAlert({ id: "a1", rule_id: "r1", agent_id: "ag1", created_at: new Date(now).toISOString() }),
      // 15 min later → outside window
      makeAlert({ id: "a2", rule_id: "r1", agent_id: "ag2", created_at: new Date(now + 15 * 60_000).toISOString() }),
    ]

    const { result } = renderHook(() => useAlertCorrelation(alerts))

    expect(result.current.hasCorrelations).toBe(false)
    expect(result.current.edgeCount).toBe(0)
  })

  it("groups 3 alerts with same rule into one cluster", () => {
    const now = Date.now()
    const alerts = [
      makeAlert({ id: "a1", rule_id: "r1", agent_id: "ag1", created_at: new Date(now).toISOString() }),
      makeAlert({ id: "a2", rule_id: "r1", agent_id: "ag2", created_at: new Date(now + 30_000).toISOString() }),
      makeAlert({ id: "a3", rule_id: "r1", agent_id: "ag3", created_at: new Date(now + 60_000).toISOString() }),
    ]

    const { result } = renderHook(() => useAlertCorrelation(alerts))

    expect(result.current.correlation!.groups).toHaveLength(1)
    expect(result.current.correlation!.groups[0].alerts).toHaveLength(3)
  })

  it("escalates severity to highest in correlation group", () => {
    const now = Date.now()
    const alerts = [
      makeAlert({ id: "a1", rule_id: "r1", agent_id: "ag1", severity: "low", created_at: new Date(now).toISOString() }),
      makeAlert({ id: "a2", rule_id: "r1", agent_id: "ag2", severity: "critical", created_at: new Date(now + 30_000).toISOString() }),
    ]

    const { result } = renderHook(() => useAlertCorrelation(alerts))

    expect(result.current.correlation!.groups[0].severity).toBe("critical")
  })

  it("creates separate groups for unrelated alerts", () => {
    const now = Date.now()
    const alerts = [
      makeAlert({ id: "a1", rule_id: "r1", agent_id: "ag1", created_at: new Date(now).toISOString() }),
      makeAlert({ id: "a2", rule_id: "r1", agent_id: "ag2", created_at: new Date(now + 30_000).toISOString() }),
      // Different rule, different agent, outside window
      makeAlert({ id: "a3", rule_id: "r99", agent_id: "ag99", created_at: new Date(now + 15 * 60_000).toISOString() }),
    ]

    const { result } = renderHook(() => useAlertCorrelation(alerts))

    // Only group of 2 (a1+a2), a3 is singleton → not in groups
    expect(result.current.correlation!.groups).toHaveLength(1)
    expect(result.current.correlation!.groups[0].alerts).toHaveLength(2)
  })

  it("returns null when disabled", () => {
    const alerts = [makeAlert({ id: "a1" })]

    const { result } = renderHook(() =>
      useAlertCorrelation(alerts, { enabled: false }),
    )

    expect(result.current.correlation).toBeNull()
    expect(result.current.hasCorrelations).toBe(false)
  })

  it("returns null for empty alert list", () => {
    const { result } = renderHook(() => useAlertCorrelation([]))

    expect(result.current.correlation).toBeNull()
    expect(result.current.hasCorrelations).toBe(false)
  })

  it("does not create same_agent edge when alerts have same rule (already covered)", () => {
    const now = Date.now()
    const alerts = [
      makeAlert({ id: "a1", rule_id: "r1", agent_id: "ag1", created_at: new Date(now).toISOString() }),
      makeAlert({ id: "a2", rule_id: "r1", agent_id: "ag1", created_at: new Date(now + 30_000).toISOString() }),
    ]

    const { result } = renderHook(() => useAlertCorrelation(alerts))

    // Should only have same_rule edge, not duplicate same_agent edge
    const agentEdges = result.current.correlation!.edges.filter((e) => e.reason === "same_agent")
    expect(agentEdges).toHaveLength(0)
  })
})
