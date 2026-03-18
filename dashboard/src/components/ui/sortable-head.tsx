// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Sortable table column header.
 *
 * Renders a clickable `<TableHead>` with ascending/descending arrow indicators.
 * Works with the `useSort` hook — pass `sortState` and `onSort` through.
 */

import { ArrowUp, ArrowDown, ArrowUpDown } from "lucide-react"
import { TableHead } from "@/components/ui/table"
import type { SortDir } from "@/hooks/useSort"
import { cn } from "@/lib/utils"

interface SortableHeadProps extends React.ThHTMLAttributes<HTMLTableCellElement> {
  /** Sort key this column represents */
  sortKey: string
  /** Current active sort key */
  activeKey: string
  /** Current sort direction */
  activeDir: SortDir
  /** Called when header is clicked */
  onSort: (key: string) => void
  children: React.ReactNode
}

export function SortableHead({
  sortKey,
  activeKey,
  activeDir,
  onSort,
  children,
  className,
  ...rest
}: SortableHeadProps) {
  const isActive = activeKey === sortKey
  const Icon = isActive
    ? activeDir === "asc"
      ? ArrowUp
      : ArrowDown
    : ArrowUpDown

  return (
    <TableHead
      className={cn("cursor-pointer select-none hover:text-foreground transition-colors", className)}
      onClick={() => onSort(sortKey)}
      {...rest}
    >
      <span className="inline-flex items-center gap-1">
        {children}
        <Icon
          size={12}
          className={cn(
            "shrink-0 transition-opacity",
            isActive ? "opacity-100 text-foreground" : "opacity-30",
          )}
        />
      </span>
    </TableHead>
  )
}
