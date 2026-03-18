// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — AnimatedNumber component.
 *
 * Counts up from 0 to target value with a smooth spring animation.
 * Uses requestAnimationFrame for buttery-smooth 60fps rendering.
 * Only re-animates when the numeric value actually changes.
 */

import { useEffect, useRef, useState } from "react"

const defaultFormatter = (n: number) => n.toLocaleString()

interface AnimatedNumberProps {
  value: number
  duration?: number
  className?: string
  formatter?: (n: number) => string
}

export function AnimatedNumber({
  value,
  duration = 600,
  className,
  formatter,
}: AnimatedNumberProps) {
  // Store formatter in a ref so the effect always reads the latest
  // version without needing it in the dependency array.
  const fmt = formatter ?? defaultFormatter
  const fmtRef = useRef(fmt)
  useEffect(() => { fmtRef.current = fmt }, [fmt])

  const [display, setDisplay] = useState(() => fmt(value))
  const prevValue = useRef(value)
  const frameRef = useRef(0)

  useEffect(() => {
    const fmt = fmtRef.current
    const start = prevValue.current
    const diff = value - start

    // No change — just ensure display is current, skip animation
    if (diff === 0) {
      setDisplay(fmt(value))
      return
    }

    const startTime = performance.now()

    function step(now: number) {
      const elapsed = now - startTime
      const progress = Math.min(elapsed / duration, 1)
      // Ease-out cubic
      const eased = 1 - Math.pow(1 - progress, 3)
      const current = Math.round(start + diff * eased)
      setDisplay(fmtRef.current(current))

      if (progress < 1) {
        frameRef.current = requestAnimationFrame(step)
      } else {
        prevValue.current = value
      }
    }

    frameRef.current = requestAnimationFrame(step)
    return () => cancelAnimationFrame(frameRef.current)
  }, [value, duration])

  return <span className={className}>{display}</span>
}
