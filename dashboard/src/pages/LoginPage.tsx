// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Login page.
 *
 * Email + password form → JWT auth → redirect to dashboard.
 */

import { useState } from "react"
import type { FormEvent } from "react"
import { Navigate } from "react-router-dom"
import { Loader2, KeyRound } from "lucide-react"
import { useAuth } from "@/hooks/useAuth"
import { useAuthStore } from "@/stores/authStore"
import { initiateOIDCLogin, initiateSAMLLogin } from "@/api/auth"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { PhantexLogo } from "@/components/PhantexLogo"

export function LoginPage() {
  const { login } = useAuth()
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)

  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [ssoLoading, setSsoLoading] = useState(false)

  // Already logged in → go to dashboard
  if (isAuthenticated) {
    return <Navigate to="/" replace />
  }

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    setLoading(true)

    try {
      await login(email, password)
    } catch (err: unknown) {
      const axiosErr = err as { response?: { data?: { detail?: string | { message?: string } } } }
      const detail = axiosErr.response?.data?.detail
      if (typeof detail === "string") {
        setError(detail)
      } else if (detail && typeof detail === "object" && "message" in detail) {
        setError(detail.message ?? "Authentication failed")
      } else {
        setError("Authentication failed. Check your credentials.")
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden">
      {/* ── Radar Background ────────────────────────────────── */}
      <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
        {/* Ambient glow at center */}
        <div className="absolute h-[500px] w-[500px] rounded-full bg-primary/[0.03] blur-[120px]" />

        {/* Concentric scan rings */}
        {[200, 360, 520, 680, 840].map((size) => (
          <div
            key={size}
            className="absolute rounded-full border border-primary/[0.05]"
            style={{ width: size, height: size }}
          />
        ))}

        {/* Crosshair lines */}
        <div className="absolute h-full w-px bg-gradient-to-b from-transparent via-primary/[0.05] to-transparent" />
        <div className="absolute h-px w-full bg-gradient-to-r from-transparent via-primary/[0.05] to-transparent" />

        {/* Radar sweep */}
        <div
          className="absolute rounded-full"
          style={{
            width: 840,
            height: 840,
            background: "conic-gradient(from 0deg, transparent 0deg, rgba(0,255,157,0.05) 15deg, rgba(0,255,157,0.015) 40deg, transparent 70deg)",
            animation: "radar-sweep 4s linear infinite",
          }}
        />

        {/* Subtle blips */}
        <div
          className="absolute h-1.5 w-1.5 rounded-full bg-primary/50"
          style={{ top: "22%", left: "58%", animation: "radar-blip 4s ease-out infinite" }}
        />
        <div
          className="absolute h-1.5 w-1.5 rounded-full bg-primary/40"
          style={{ top: "38%", left: "28%", animation: "radar-blip 4s ease-out infinite 1.5s" }}
        />
        <div
          className="absolute h-1.5 w-1.5 rounded-full bg-primary/45"
          style={{ top: "68%", left: "72%", animation: "radar-blip 4s ease-out infinite 3s" }}
        />

        {/* Center dot */}
        <div className="absolute h-1.5 w-1.5 rounded-full bg-primary/30 shadow-[0_0_6px_rgba(0,255,157,0.2)]" />
      </div>

      {/* ── Login Content ───────────────────────────────────── */}
      <div className="relative z-10 flex w-full max-w-[400px] flex-col items-center animate-float-in px-6">

        {/* Logo — block-level, perfectly centered */}
        <PhantexLogo size={88} animated className="block mb-6" />

        {/* Brand name */}
        <h1 className="text-[2.75rem] font-bold tracking-[0.08em] text-foreground leading-none">
          PHANTEX
        </h1>
        <p className="mt-2.5 text-[13px] font-medium tracking-[0.12em] text-foreground/40">
          RUNTIME SECURITY PLATFORM
        </p>

        {/* Form — clean, borderless, floating */}
        <form onSubmit={handleSubmit} className="mt-10 w-full space-y-5">
          <div className="space-y-2">
            <label htmlFor="email" className="text-xs font-medium tracking-wider text-foreground/40">
              EMAIL
            </label>
            <Input
              id="email"
              type="email"
              placeholder="you@company.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              autoComplete="email"
              autoFocus
            />
          </div>

          <div className="space-y-2">
            <label htmlFor="password" className="text-xs font-medium tracking-wider text-foreground/40">
              PASSWORD
            </label>
            <Input
              id="password"
              type="password"
              placeholder="••••••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              autoComplete="current-password"
            />
          </div>

          {error && (
            <div className="rounded-lg border border-destructive/20 bg-destructive/10 p-3 text-sm text-destructive">
              {error}
            </div>
          )}

          <Button type="submit" className="w-full h-11 text-sm font-semibold" disabled={loading}>
            {loading ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Signing in...
              </>
            ) : (
              "Sign In"
            )}
          </Button>
        </form>

        {/* SSO Divider */}
        <div className="flex items-center gap-3 w-full mt-6">
          <div className="flex-1 h-px bg-foreground/10" />
          <span className="text-[11px] font-medium tracking-wider text-foreground/25">OR</span>
          <div className="flex-1 h-px bg-foreground/10" />
        </div>

        {/* SSO Login Button */}
        <button
          onClick={async () => {
            setSsoLoading(true)
            setError(null)
            try {
              // Try OIDC first, fall back to SAML
              let redirectUrl: string
              try {
                redirectUrl = await initiateOIDCLogin()
              } catch {
                try {
                  redirectUrl = await initiateSAMLLogin()
                } catch {
                  throw new Error("No SSO provider configured. Ask your admin to set up SSO under Settings.")
                }
              }
              // Redirect browser to IdP
              window.location.href = redirectUrl
            } catch (err: unknown) {
              const msg = err instanceof Error ? err.message : "SSO login failed"
              setError(msg)
              setSsoLoading(false)
            }
          }}
          disabled={ssoLoading}
          className="mt-4 flex w-full items-center justify-center gap-2 rounded-lg border border-foreground/10 bg-foreground/[0.03] px-4 py-2.5 text-sm font-medium text-foreground/70 transition-colors hover:bg-foreground/[0.06] hover:text-foreground disabled:opacity-50"
        >
          {ssoLoading ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <KeyRound size={16} />
          )}
          Sign in with SSO
        </button>

        {/* Footer */}
        <p className="mt-10 text-[11px] font-medium tracking-[0.08em] text-foreground/25">
          PHANTEX &middot; v0.1.0
        </p>
      </div>
    </div>
  )
}
