// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — BarChart component (pure SVG, no dependencies).
 *
 * Renders a simple horizontal or vertical bar chart with:
 *   - Animated bar entrance
 *   - Labels and values
 *   - Hover tooltips
 *   - Configurable colors
 */

import { useState, useMemo } from "react"

export interface BarData {
  label: string
  value: number
  color?: string
}

interface BarChartProps {
  data: BarData[]
  height?: number
  className?: string
  /** Bar direction: "horizontal" renders left-to-right, "vertical" renders bottom-to-top */
  direction?: "horizontal" | "vertical"
}

const DEFAULT_COLORS = [
  "#10b981", // emerald
  "#3b82f6", // blue
  "#f97316", // orange
  "#eab308", // yellow
  "#ef4444", // red
  "#8b5cf6", // purple
  "#06b6d4", // cyan
]

export function BarChart({
  data,
  height = 200,
  className,
  direction = "horizontal",
}: BarChartProps) {
  const [hovered, setHovered] = useState<number | null>(null)

  const maxValue = useMemo(
    () => Math.max(...data.map((d) => d.value), 1),
    [data],
  )

  if (data.length === 0) return null

  if (direction === "horizontal") {
    const barHeight = 28
    const gap = 8
    const labelWidth = 100
    const valueWidth = 50
    const chartHeight = data.length * (barHeight + gap) - gap + 8
    const barAreaWidth = 300

    return (
      <svg
        viewBox={`0 0 ${labelWidth + barAreaWidth + valueWidth + 16} ${chartHeight}`}
        className={className}
        style={{ width: "100%", height: chartHeight }}
      >
        {data.map((d, i) => {
          const y = i * (barHeight + gap) + 4
          const pct = d.value / maxValue
          const barW = pct * barAreaWidth
          const color = d.color ?? DEFAULT_COLORS[i % DEFAULT_COLORS.length]
          const isHov = hovered === i

          return (
            <g
              key={d.label}
              onMouseEnter={() => setHovered(i)}
              onMouseLeave={() => setHovered(null)}
              className="cursor-default"
            >
              {/* Label */}
              <text
                x={labelWidth - 8}
                y={y + barHeight / 2 + 1}
                textAnchor="end"
                fill={isHov ? "#fafafa" : "#a1a1aa"}
                fontSize="11"
                fontFamily="var(--font-sans)"
                dominantBaseline="middle"
                style={{ transition: "fill 0.15s ease" }}
              >
                {d.label.length > 14 ? d.label.slice(0, 12) + "…" : d.label}
              </text>

              {/* Bar background */}
              <rect
                x={labelWidth}
                y={y}
                width={barAreaWidth}
                height={barHeight}
                rx={6}
                fill="rgba(255,255,255,0.02)"
              />

              {/* Bar fill */}
              <rect
                x={labelWidth}
                y={y}
                width={barW}
                height={barHeight}
                rx={6}
                fill={color}
                opacity={isHov ? 0.9 : 0.6}
                style={{
                  transition: "width 0.5s cubic-bezier(0.16,1,0.3,1), opacity 0.15s ease",
                }}
              />

              {/* Value */}
              <text
                x={labelWidth + barAreaWidth + 10}
                y={y + barHeight / 2 + 1}
                fill={isHov ? "#fafafa" : "#71717a"}
                fontSize="11"
                fontWeight="600"
                fontFamily="var(--font-mono)"
                dominantBaseline="middle"
                style={{ transition: "fill 0.15s ease" }}
              >
                {d.value}
              </text>
            </g>
          )
        })}
      </svg>
    )
  }

  // Vertical bars
  const barWidth = 36
  const gap = 12
  const chartWidth = data.length * (barWidth + gap) - gap + 32
  const paddingTop = 16
  const paddingBottom = 28
  const barArea = height - paddingTop - paddingBottom

  return (
    <svg
      viewBox={`0 0 ${chartWidth} ${height}`}
      className={className}
      style={{ width: "100%", height }}
    >
      {data.map((d, i) => {
        const x = 16 + i * (barWidth + gap)
        const pct = d.value / maxValue
        const barH = pct * barArea
        const color = d.color ?? DEFAULT_COLORS[i % DEFAULT_COLORS.length]
        const isHov = hovered === i

        return (
          <g
            key={d.label}
            onMouseEnter={() => setHovered(i)}
            onMouseLeave={() => setHovered(null)}
            className="cursor-default"
          >
            {/* Bar background */}
            <rect
              x={x}
              y={paddingTop}
              width={barWidth}
              height={barArea}
              rx={6}
              fill="rgba(255,255,255,0.02)"
            />

            {/* Bar fill */}
            <rect
              x={x}
              y={paddingTop + barArea - barH}
              width={barWidth}
              height={barH}
              rx={6}
              fill={color}
              opacity={isHov ? 0.9 : 0.6}
              style={{
                transition:
                  "height 0.5s cubic-bezier(0.16,1,0.3,1), y 0.5s cubic-bezier(0.16,1,0.3,1), opacity 0.15s ease",
              }}
            />

            {/* Value on top */}
            <text
              x={x + barWidth / 2}
              y={paddingTop + barArea - barH - 6}
              textAnchor="middle"
              fill={isHov ? "#fafafa" : "#71717a"}
              fontSize="10"
              fontWeight="600"
              fontFamily="var(--font-mono)"
              style={{ transition: "fill 0.15s ease" }}
            >
              {d.value}
            </text>

            {/* Label below */}
            <text
              x={x + barWidth / 2}
              y={height - 6}
              textAnchor="middle"
              fill="#a1a1aa"
              fontSize="9"
              fontFamily="var(--font-sans)"
            >
              {d.label.length > 6 ? d.label.slice(0, 5) + "…" : d.label}
            </text>
          </g>
        )
      })}
    </svg>
  )
}
