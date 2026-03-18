// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Client-side sort hook for data tables.
 *
 * Generic, type-safe sort with asc/desc toggling and a comparator
 * that handles strings, numbers, dates, and nulls.
 */

import { useState, useMemo, useCallback } from "react"

export type SortDir = "asc" | "desc"

export interface SortState<K extends string = string> {
  key: K
  dir: SortDir
}

/**
 * useSort — manage sort state + produce a sorted copy of `items`.
 *
 * @param items   - array of objects to sort (typically from a query)
 * @param initial - default sort column + direction
 * @returns { sorted, sortState, toggleSort }
 */
export function useSort<T, K extends string = string>(
  items: T[],
  initial: SortState<K>,
) {
  const [sortState, setSortState] = useState<SortState<K>>(initial)

  const toggleSort = useCallback(
    (key: string) => {
      setSortState((prev) => ({
        key: key as K,
        dir: prev.key === key && prev.dir === "asc" ? "desc" : "asc",
      }))
    },
    [],
  )

  const sorted = useMemo(() => {
    const { key, dir } = sortState
    const copy = [...items]
    copy.sort((a, b) => {
      const av = (a as Record<string, unknown>)[key]
      const bv = (b as Record<string, unknown>)[key]

      // Nulls always sort last
      if (av == null && bv == null) return 0
      if (av == null) return 1
      if (bv == null) return -1

      let cmp = 0
      if (typeof av === "number" && typeof bv === "number") {
        cmp = av - bv
      } else {
        cmp = String(av).localeCompare(String(bv), undefined, {
          sensitivity: "base",
          numeric: true,
        })
      }

      return dir === "asc" ? cmp : -cmp
    })
    return copy
  }, [items, sortState])

  return { sorted, sortState, toggleSort } as const
}
