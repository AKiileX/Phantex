// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — VirtualTable: generic virtualized table component.
 *
 * Uses @tanstack/react-virtual for efficient rendering of large datasets.
 * Only renders rows visible in the viewport + overscan buffer.
 *
 * Features:
 *   - Configurable row height (default 44px — matches existing table rows)
 *   - Overscan: renders 20 extra rows above/below viewport for smooth scrolling
 *   - Auto-scroll: sticks to bottom when new items arrive (toggleable)
 *   - Memory cap: configurable max items (default 100K)
 *   - Stable column layout via sticky header
 *
 * @module components/ui/virtual-table
 */

import {
  useRef,
  useEffect,
  useCallback,
  useState,
  type ReactNode,
  type CSSProperties,
} from "react"
import { useVirtualizer } from "@tanstack/react-virtual"
import { cn } from "@/lib/utils"

/* ── Types ─────────────────────────────────────────────────────────────────── */

export interface VirtualTableColumn<T> {
  /** Unique key for the column. */
  key: string
  /** Header label. */
  header: ReactNode
  /** Width CSS value (e.g. "120px", "1fr", "minmax(100px, 1fr)"). */
  width?: string
  /** Cell renderer. */
  render: (item: T, index: number) => ReactNode
  /** Optional className for the cell. */
  className?: string
  /** Optional className for the header cell. */
  headerClassName?: string
}

export interface VirtualTableProps<T> {
  /** Data items to render. */
  items: T[]
  /** Column definitions. */
  columns: VirtualTableColumn<T>[]
  /** Unique key extractor for each item. */
  getItemKey: (item: T) => string | number
  /** Row height in pixels. Default 44. */
  rowHeight?: number
  /** Extra rows rendered above/below viewport. Default 20. */
  overscan?: number
  /** Max items to retain in memory. Default 100_000. */
  maxItems?: number
  /** Container height CSS. Default "calc(100vh - 320px)". */
  height?: string
  /** Whether to auto-scroll to bottom on new items. Default false. */
  autoScroll?: boolean
  /** Called when a row is clicked. */
  onRowClick?: (item: T, index: number) => void
  /** Optional empty state component. */
  emptyState?: ReactNode
  /** Optional loading indicator. */
  isLoading?: boolean
  /** Loading state component. */
  loadingState?: ReactNode
  /** Optional CSS class for the outer container. */
  className?: string
  /** Optional: called when user scrolls near the end (for infinite loading). */
  onEndReached?: () => void
  /** Distance from end (in px) to trigger onEndReached. Default 500. */
  endReachedThreshold?: number
}

/* ── Component ─────────────────────────────────────────────────────────────── */

export function VirtualTable<T>({
  items,
  columns,
  getItemKey,
  rowHeight = 44,
  overscan = 20,
  maxItems = 100_000,
  height = "calc(100vh - 320px)",
  autoScroll = false,
  onRowClick,
  emptyState,
  isLoading = false,
  loadingState,
  className,
  onEndReached,
  endReachedThreshold = 500,
}: VirtualTableProps<T>) {
  const parentRef = useRef<HTMLDivElement>(null)
  const [isAtBottom, setIsAtBottom] = useState(true)
  const prevItemCountRef = useRef(items.length)
  const endReachedCalledRef = useRef(false)

  // Enforce memory cap — keep only the most recent items
  const cappedItems = items.length > maxItems ? items.slice(-maxItems) : items

  // eslint-disable-next-line react-hooks/incompatible-library -- TanStack Virtual API limitation
  const rowVirtualizer = useVirtualizer({
    count: cappedItems.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => rowHeight,
    overscan,
    getItemKey: (index) => getItemKey(cappedItems[index]),
  })

  // Track whether user is at the bottom of the scroll area
  const handleScroll = useCallback(() => {
    const el = parentRef.current
    if (!el) return
    const distanceFromBottom = el.scrollHeight - el.scrollTop - el.clientHeight
    setIsAtBottom(distanceFromBottom < rowHeight * 2)

    // Trigger onEndReached when near the bottom
    if (onEndReached && distanceFromBottom < endReachedThreshold) {
      if (!endReachedCalledRef.current) {
        endReachedCalledRef.current = true
        onEndReached()
      }
    } else {
      endReachedCalledRef.current = false
    }
  }, [rowHeight, onEndReached, endReachedThreshold])

  // Auto-scroll to bottom when new items arrive (only if user was at bottom)
  useEffect(() => {
    if (autoScroll && isAtBottom && cappedItems.length > prevItemCountRef.current) {
      rowVirtualizer.scrollToIndex(cappedItems.length - 1, { align: "end" })
    }
    prevItemCountRef.current = cappedItems.length
  }, [cappedItems.length, autoScroll, isAtBottom, rowVirtualizer])

  // Build grid template for columns
  const gridTemplate = columns
    .map((col) => col.width ?? "1fr")
    .join(" ")

  const headerStyle: CSSProperties = {
    display: "grid",
    gridTemplateColumns: gridTemplate,
  }

  const rowStyle: CSSProperties = {
    display: "grid",
    gridTemplateColumns: gridTemplate,
    alignItems: "center",
  }

  /* ── Loading state ─────────────────────────────────────── */
  if (isLoading) {
    return (
      <div className={cn("bg-card backdrop-blur-xl border border-border/50 rounded-xl overflow-hidden shadow-[0_0_0_1px_rgba(255,255,255,0.03)]", className)}>
        {/* Header */}
        <div
          style={headerStyle}
          className="bg-white/[0.02] border-b border-border/40 sticky top-0 z-10"
        >
          {columns.map((col) => (
            <div
              key={col.key}
              className={cn(
                "h-9 px-3 flex items-center text-xs uppercase tracking-wider font-medium text-muted-foreground",
                col.headerClassName,
              )}
            >
              {col.header}
            </div>
          ))}
        </div>
        {loadingState ?? (
          <div className="text-center py-12 text-muted-foreground text-sm">
            Loading…
          </div>
        )}
      </div>
    )
  }

  /* ── Empty state ───────────────────────────────────────── */
  if (cappedItems.length === 0) {
    return (
      <div className={cn("bg-card backdrop-blur-xl border border-border/50 rounded-xl overflow-hidden shadow-[0_0_0_1px_rgba(255,255,255,0.03)]", className)}>
        {/* Header */}
        <div
          style={headerStyle}
          className="bg-white/[0.02] border-b border-border/40"
        >
          {columns.map((col) => (
            <div
              key={col.key}
              className={cn(
                "h-9 px-3 flex items-center text-xs uppercase tracking-wider font-medium text-muted-foreground",
                col.headerClassName,
              )}
            >
              {col.header}
            </div>
          ))}
        </div>
        {emptyState ?? (
          <div className="text-center py-16 text-muted-foreground text-sm">
            No items
          </div>
        )}
      </div>
    )
  }

  /* ── Virtual table ─────────────────────────────────────── */
  return (
    <div className={cn("bg-card backdrop-blur-xl border border-border/50 rounded-xl overflow-hidden shadow-[0_0_0_1px_rgba(255,255,255,0.03)]", className)}>
      {/* Sticky header */}
      <div
        style={headerStyle}
        className="bg-white/[0.02] border-b border-border/40 sticky top-0 z-10"
      >
        {columns.map((col) => (
          <div
            key={col.key}
            className={cn(
              "h-9 px-3 flex items-center text-xs uppercase tracking-wider font-medium text-muted-foreground",
              col.headerClassName,
            )}
          >
            {col.header}
          </div>
        ))}
      </div>

      {/* Scroll container */}
      <div
        ref={parentRef}
        onScroll={handleScroll}
        style={{ height, overflow: "auto" }}
        className="relative"
      >
        <div
          style={{
            height: `${rowVirtualizer.getTotalSize()}px`,
            width: "100%",
            position: "relative",
          }}
        >
          {rowVirtualizer.getVirtualItems().map((virtualRow) => {
            const item = cappedItems[virtualRow.index]
            return (
              <div
                key={virtualRow.key}
                data-index={virtualRow.index}
                ref={rowVirtualizer.measureElement}
                style={{
                  ...rowStyle,
                  position: "absolute",
                  top: 0,
                  left: 0,
                  width: "100%",
                  height: `${virtualRow.size}px`,
                  transform: `translateY(${virtualRow.start}px)`,
                }}
                className={cn(
                  "border-b border-border/40 transition-colors duration-200 hover:bg-white/[0.02]",
                  onRowClick && "cursor-pointer active:bg-surface-3/30",
                )}
                onClick={onRowClick ? () => onRowClick(item, virtualRow.index) : undefined}
              >
                {columns.map((col) => (
                  <div
                    key={col.key}
                    className={cn("px-3 py-2.5 flex items-center", col.className)}
                  >
                    {col.render(item, virtualRow.index)}
                  </div>
                ))}
              </div>
            )
          })}
        </div>
      </div>

      {/* Auto-scroll indicator */}
      {autoScroll && !isAtBottom && cappedItems.length > 0 && (
        <button
          onClick={() => {
            rowVirtualizer.scrollToIndex(cappedItems.length - 1, { align: "end" })
            setIsAtBottom(true)
          }}
          className="absolute bottom-4 right-4 z-20 flex items-center gap-1.5 rounded-full bg-primary/90 px-3 py-1.5 text-xs font-medium text-primary-foreground shadow-lg hover:bg-primary transition-colors cursor-pointer"
        >
          ↓ New alerts
        </button>
      )}
    </div>
  )
}
