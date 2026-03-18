// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Brand logo.
 *
 * Shield silhouette with embedded radar sweep.
 * The sweep rotates continuously — "always scanning."
 * Pure SVG, no external assets.
 */

interface PhantexLogoProps {
  size?: number
  className?: string
  /** Show animated radar sweep */
  animated?: boolean
}

export function PhantexLogo({
  size = 48,
  className = "",
  animated = true,
}: PhantexLogoProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={`block ${className}`}
    >
      <defs>
        {/* Shield clipping path */}
        <clipPath id="shield-clip">
          <path d="M32 4 L56 16 V36 C56 48 44 58 32 62 C20 58 8 48 8 36 V16 Z" />
        </clipPath>

        {/* Radar sweep gradient — fades from solid to transparent */}
        <linearGradient id="sweep-fade" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0%" stopColor="#00ff9d" stopOpacity="0" />
          <stop offset="70%" stopColor="#00ff9d" stopOpacity="0.15" />
          <stop offset="100%" stopColor="#00ff9d" stopOpacity="0.35" />
        </linearGradient>

        {/* Glow filter */}
        <filter id="logo-glow" x="-30%" y="-30%" width="160%" height="160%">
          <feGaussianBlur in="SourceGraphic" stdDeviation="2" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>

      {/* Shield outline */}
      <path
        d="M32 4 L56 16 V36 C56 48 44 58 32 62 C20 58 8 48 8 36 V16 Z"
        stroke="#00ff9d"
        strokeWidth="1.5"
        strokeOpacity="0.5"
        fill="none"
        filter="url(#logo-glow)"
      />

      {/* Inner content clipped to shield shape */}
      <g clipPath="url(#shield-clip)">
        {/* Dark shield fill */}
        <path
          d="M32 4 L56 16 V36 C56 48 44 58 32 62 C20 58 8 48 8 36 V16 Z"
          fill="#060b14"
          fillOpacity="0.8"
        />

        {/* Radar rings centered at shield center (32, 34) */}
        <circle cx="32" cy="34" r="8" stroke="#00ff9d" strokeWidth="0.5" strokeOpacity="0.12" fill="none" />
        <circle cx="32" cy="34" r="16" stroke="#00ff9d" strokeWidth="0.5" strokeOpacity="0.1" fill="none" />
        <circle cx="32" cy="34" r="24" stroke="#00ff9d" strokeWidth="0.5" strokeOpacity="0.08" fill="none" />

        {/* Crosshairs */}
        <line x1="32" y1="10" x2="32" y2="58" stroke="#00ff9d" strokeWidth="0.5" strokeOpacity="0.08" />
        <line x1="8" y1="34" x2="56" y2="34" stroke="#00ff9d" strokeWidth="0.5" strokeOpacity="0.08" />

        {/* Radar sweep — rotating wedge */}
        <g
          style={
            animated
              ? { transformOrigin: "32px 34px", animation: "radar-sweep 3s linear infinite" }
              : { transform: "rotate(45deg)", transformOrigin: "32px 34px" }
          }
        >
          <path
            d="M32 34 L32 10 A24 24 0 0 1 51 24 Z"
            fill="url(#sweep-fade)"
          />
        </g>

        {/* Center dot */}
        <circle cx="32" cy="34" r="1.5" fill="#00ff9d" fillOpacity="0.7" />

        {/* Blips — detected agents */}
        <circle cx="38" cy="26" r="1" fill="#00ff9d" fillOpacity="0.6">
          {animated && (
            <animate attributeName="opacity" values="0;0.7;0" dur="3s" repeatCount="indefinite" />
          )}
        </circle>
        <circle cx="24" cy="30" r="0.8" fill="#00ff9d" fillOpacity="0.4">
          {animated && (
            <animate attributeName="opacity" values="0;0.5;0" dur="3s" begin="1s" repeatCount="indefinite" />
          )}
        </circle>
        <circle cx="40" cy="42" r="0.8" fill="#ff2d55" fillOpacity="0.5">
          {animated && (
            <animate attributeName="opacity" values="0;0.6;0" dur="3s" begin="2s" repeatCount="indefinite" />
          )}
        </circle>
      </g>
    </svg>
  )
}
