// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Badge component (premium severity-aware).
 *
 * Pill-shaped badges with subtle colored halo. Status-dot indicator
 * rendered via CSS ::before pseudo-element.
 */

import { cva } from "class-variance-authority"
import type { VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

const badgeVariants = cva(
  "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[10px] font-medium tracking-wider uppercase transition-all duration-200",
  {
    variants: {
      variant: {
        default: "border-primary/20 bg-primary/5 text-primary/90",
        secondary: "border-border/50 bg-white/[0.03] text-muted-foreground",
        outline: "border-border/50 text-muted-foreground",
        critical:
          "border-severity-critical/20 bg-severity-critical/5 text-severity-critical/90 shadow-[0_0_8px_-2px_rgba(239,68,68,0.15)]" +
          " before:inline-block before:w-1.5 before:h-1.5 before:rounded-full before:bg-severity-critical before:shrink-0",
        high:
          "border-severity-high/20 bg-severity-high/5 text-severity-high/90 shadow-[0_0_8px_-2px_rgba(249,115,22,0.12)]" +
          " before:inline-block before:w-1.5 before:h-1.5 before:rounded-full before:bg-severity-high before:shrink-0",
        medium:
          "border-severity-medium/20 bg-severity-medium/5 text-severity-medium/90 shadow-[0_0_8px_-2px_rgba(234,179,8,0.1)]" +
          " before:inline-block before:w-1.5 before:h-1.5 before:rounded-full before:bg-severity-medium before:shrink-0",
        low:
          "border-severity-low/20 bg-severity-low/5 text-severity-low/90 shadow-[0_0_8px_-2px_rgba(59,130,246,0.1)]" +
          " before:inline-block before:w-1.5 before:h-1.5 before:rounded-full before:bg-severity-low before:shrink-0",
        info:
          "border-border/50 bg-white/[0.02] text-muted-foreground" +
          " before:inline-block before:w-1.5 before:h-1.5 before:rounded-full before:bg-severity-info before:shrink-0",
        active:
          "border-status-active/20 bg-status-active/5 text-status-active/90 shadow-[0_0_8px_-2px_rgba(34,197,94,0.12)]" +
          " before:inline-block before:w-1.5 before:h-1.5 before:rounded-full before:bg-status-active before:shrink-0",
        stale:
          "border-status-stale/20 bg-status-stale/5 text-status-stale/90" +
          " before:inline-block before:w-1.5 before:h-1.5 before:rounded-full before:bg-status-stale before:shrink-0",
        terminated:
          "border-border/50 bg-white/[0.02] text-muted-foreground" +
          " before:inline-block before:w-1.5 before:h-1.5 before:rounded-full before:bg-status-terminated before:shrink-0",
        offline:
          "border-border/50 bg-white/[0.02] text-muted-foreground" +
          " before:inline-block before:w-1.5 before:h-1.5 before:rounded-full before:bg-status-terminated before:shrink-0",
        quarantined:
          "border-severity-critical/20 bg-severity-critical/5 text-severity-critical/90" +
          " before:inline-block before:w-1.5 before:h-1.5 before:rounded-full before:bg-severity-critical before:shrink-0",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  },
)

type BadgeProps = React.HTMLAttributes<HTMLDivElement> &
  VariantProps<typeof badgeVariants>

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  )
}

// eslint-disable-next-line react-refresh/only-export-components
export { Badge, badgeVariants }
