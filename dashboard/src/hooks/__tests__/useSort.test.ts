// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — useSort hook unit tests.
 *
 * Verifies:
 *   - Default sort direction applied
 *   - Toggle reverses direction
 *   - Different column sets new key (asc)
 *   - Null values sort to bottom
 *   - Numeric sort (not lexicographic)
 */

import { describe, it, expect } from "vitest"
import { renderHook, act } from "@testing-library/react"
import { useSort } from "@/hooks/useSort"

const ITEMS = [
  { name: "Charlie", age: 30, joined: "2024-03-01" },
  { name: "Alice", age: 25, joined: "2024-01-15" },
  { name: "Bob", age: 35, joined: "2024-02-10" },
  { name: "Diana", age: null as number | null, joined: null as string | null },
]

describe("useSort", () => {
  it("sorts ascending by default key", () => {
    const { result } = renderHook(() => useSort(ITEMS, { key: "name", dir: "asc" }))

    expect(result.current.sorted.map((i) => i.name)).toEqual([
      "Alice", "Bob", "Charlie", "Diana",
    ])
  })

  it("sorts descending", () => {
    const { result } = renderHook(() => useSort(ITEMS, { key: "name", dir: "desc" }))

    expect(result.current.sorted.map((i) => i.name)).toEqual([
      "Diana", "Charlie", "Bob", "Alice",
    ])
  })

  it("toggleSort reverses direction on same key", () => {
    const { result } = renderHook(() => useSort(ITEMS, { key: "name", dir: "asc" }))

    act(() => result.current.toggleSort("name"))
    expect(result.current.sortState).toEqual({ key: "name", dir: "desc" })
  })

  it("toggleSort sets asc when switching to new key", () => {
    const { result } = renderHook(() => useSort(ITEMS, { key: "name", dir: "desc" }))

    act(() => result.current.toggleSort("age"))
    expect(result.current.sortState).toEqual({ key: "age", dir: "asc" })
  })

  it("sorts numbers correctly (not lexicographic)", () => {
    const { result } = renderHook(() => useSort(ITEMS, { key: "age", dir: "asc" }))

    const ages = result.current.sorted.map((i) => i.age)
    // null sorts last; numbers in ascending order
    expect(ages).toEqual([25, 30, 35, null])
  })

  it("sorts date strings correctly", () => {
    const { result } = renderHook(() => useSort(ITEMS, { key: "joined", dir: "asc" }))

    const dates = result.current.sorted.map((i) => i.joined)
    expect(dates).toEqual(["2024-01-15", "2024-02-10", "2024-03-01", null])
  })

  it("does not mutate original array", () => {
    const original = [...ITEMS]
    renderHook(() => useSort(ITEMS, { key: "name", dir: "desc" }))

    expect(ITEMS).toEqual(original)
  })
})
