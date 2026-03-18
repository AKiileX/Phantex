// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Change Password Dialog (voluntary, from user menu).
 *
 * Reuses the same password strength validation as ForceChangePasswordModal
 * but presented as a dismissible dialog triggered from the header user card.
 */

import { useState, useRef, useEffect } from "react"
import type { FormEvent } from "react"
import { Key, Eye, EyeOff, Check, X, Loader2 } from "lucide-react"
import { changePassword } from "@/api/auth"
import { useAuthStore } from "@/stores/authStore"

interface Rule {
  label: string
  test: (pw: string) => boolean
}

const PASSWORD_RULES: Rule[] = [
  { label: "At least 12 characters", test: (pw) => pw.length >= 12 },
  { label: "One uppercase letter", test: (pw) => /[A-Z]/.test(pw) },
  { label: "One lowercase letter", test: (pw) => /[a-z]/.test(pw) },
  { label: "One digit", test: (pw) => /\d/.test(pw) },
  { label: "One special character", test: (pw) => /[!@#$%^&*()_+\-=[\]{}|;:'",.<>?/`~\\]/.test(pw) },
]

interface ChangePasswordDialogProps {
  onClose: () => void
}

export function ChangePasswordDialog({ onClose }: ChangePasswordDialogProps) {
  const token = useAuthStore((s) => s.token)
  const clearAuth = useAuthStore((s) => s.clearAuth)
  const ref = useRef<HTMLDivElement>(null)

  const [currentPassword, setCurrentPassword] = useState("")
  const [newPassword, setNewPassword] = useState("")
  const [confirmPassword, setConfirmPassword] = useState("")
  const [showCurrent, setShowCurrent] = useState(false)
  const [showNew, setShowNew] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState(false)
  const [loading, setLoading] = useState(false)

  // Close on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose()
    }
    document.addEventListener("mousedown", handler)
    return () => document.removeEventListener("mousedown", handler)
  }, [onClose])

  // Close on Escape
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose()
    }
    document.addEventListener("keydown", handler)
    return () => document.removeEventListener("keydown", handler)
  }, [onClose])

  const allRulesPassed = PASSWORD_RULES.every((r) => r.test(newPassword))
  const passwordsMatch = newPassword === confirmPassword && newPassword.length > 0
  const canSubmit = allRulesPassed && passwordsMatch && currentPassword.length > 0 && !loading

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    if (!canSubmit || !token) return

    setError(null)
    setLoading(true)

    try {
      await changePassword(currentPassword, newPassword, token)
      setSuccess(true)
      // Backend revoked all tokens — redirect to login after brief delay
      setTimeout(() => {
        clearAuth()
        window.location.href = "/login"
      }, 1500)
    } catch (err: unknown) {
      const axiosErr = err as { response?: { data?: { detail?: string | { message?: string; violations?: string[] } } } }
      const detail = axiosErr.response?.data?.detail
      if (typeof detail === "string") {
        setError(detail)
      } else if (detail && typeof detail === "object") {
        const violations = (detail as { violations?: string[] }).violations
        setError(violations?.join(", ") ?? (detail as { message?: string }).message ?? "Password change failed")
      } else {
        setError("Password change failed. Please try again.")
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-[90] flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div
        ref={ref}
        className="w-full max-w-sm rounded-xl border border-border/30 bg-background shadow-2xl shadow-black/40 overflow-hidden animate-slide-up"
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border/30 px-5 py-3">
          <div className="flex items-center gap-2">
            <Key size={16} className="text-primary" />
            <h3 className="text-sm font-semibold text-foreground">Change Password</h3>
          </div>
          <button
            onClick={onClose}
            className="flex h-6 w-6 items-center justify-center rounded text-muted-foreground/50 hover:text-foreground hover:bg-white/[0.04] transition-all"
          >
            <X size={14} />
          </button>
        </div>

        {success ? (
          <div className="flex flex-col items-center gap-3 p-8">
            <div className="flex h-12 w-12 items-center justify-center rounded-full bg-status-active/15">
              <Check size={24} className="text-status-active" />
            </div>
            <p className="text-sm font-medium text-foreground">Password changed successfully</p>
            <p className="text-xs text-muted-foreground">Redirecting to login...</p>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-3 p-5">
            {/* Current password */}
            <div className="space-y-1">
              <label className="text-[10px] font-medium tracking-wider text-foreground/40">CURRENT PASSWORD</label>
              <div className="relative">
                <input
                  type={showCurrent ? "text" : "password"}
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  required
                  autoFocus
                  autoComplete="current-password"
                  className="w-full rounded-lg border border-border/40 bg-white/[0.02] px-3 py-2 pr-9 text-sm text-foreground placeholder-muted-foreground/40 focus:border-primary/50 focus:outline-none focus:ring-1 focus:ring-primary/30"
                  placeholder="Current password"
                />
                <button
                  type="button"
                  onClick={() => setShowCurrent((v) => !v)}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground/40 hover:text-foreground"
                  tabIndex={-1}
                >
                  {showCurrent ? <EyeOff size={13} /> : <Eye size={13} />}
                </button>
              </div>
            </div>

            {/* New password */}
            <div className="space-y-1">
              <label className="text-[10px] font-medium tracking-wider text-foreground/40">NEW PASSWORD</label>
              <div className="relative">
                <input
                  type={showNew ? "text" : "password"}
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  required
                  autoComplete="new-password"
                  className="w-full rounded-lg border border-border/40 bg-white/[0.02] px-3 py-2 pr-9 text-sm text-foreground placeholder-muted-foreground/40 focus:border-primary/50 focus:outline-none focus:ring-1 focus:ring-primary/30"
                  placeholder="New password (12+ chars)"
                />
                <button
                  type="button"
                  onClick={() => setShowNew((v) => !v)}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground/40 hover:text-foreground"
                  tabIndex={-1}
                >
                  {showNew ? <EyeOff size={13} /> : <Eye size={13} />}
                </button>
              </div>
              {newPassword.length > 0 && (
                <div className="space-y-0.5 pt-0.5">
                  {PASSWORD_RULES.map((rule, i) => {
                    const passed = rule.test(newPassword)
                    return (
                      <div key={i} className="flex items-center gap-1.5 text-[10px]">
                        {passed ? (
                          <Check size={10} className="text-status-active flex-shrink-0" />
                        ) : (
                          <X size={10} className="text-muted-foreground/30 flex-shrink-0" />
                        )}
                        <span className={passed ? "text-status-active" : "text-muted-foreground/40"}>
                          {rule.label}
                        </span>
                      </div>
                    )
                  })}
                </div>
              )}
            </div>

            {/* Confirm */}
            <div className="space-y-1">
              <label className="text-[10px] font-medium tracking-wider text-foreground/40">CONFIRM PASSWORD</label>
              <input
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
                autoComplete="new-password"
                className="w-full rounded-lg border border-border/40 bg-white/[0.02] px-3 py-2 text-sm text-foreground placeholder-muted-foreground/40 focus:border-primary/50 focus:outline-none focus:ring-1 focus:ring-primary/30"
                placeholder="Confirm new password"
              />
              {confirmPassword.length > 0 && !passwordsMatch && (
                <p className="text-[10px] text-severity-critical">Passwords do not match</p>
              )}
            </div>

            {error && (
              <div className="rounded-lg border border-severity-critical/20 bg-severity-critical/10 p-2 text-xs text-severity-critical">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={!canSubmit}
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground transition-all hover:bg-primary/90 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {loading ? (
                <Loader2 size={14} className="animate-spin" />
              ) : (
                "Change Password"
              )}
            </button>
          </form>
        )}
      </div>
    </div>
  )
}
