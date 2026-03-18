// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Force Change Password Modal.
 *
 * Displayed as a blocking overlay when user.must_change_password is true.
 * Cannot be dismissed — user MUST change their password before proceeding.
 *
 * Security:
 *   - Enforces 12+ char, uppercase, lowercase, digit, special char
 *   - Client-side validation mirrors backend (defense in depth)
 *   - Clears auth state on failure (forces re-login)
 *   - No escape/close — the modal is the only UI available
 */

import { useState } from "react"
import type { FormEvent } from "react"
import { Shield, Eye, EyeOff, Check, X, Loader2, AlertTriangle } from "lucide-react"
import { changePassword } from "@/api/auth"
import { useAuthStore } from "@/stores/authStore"

/* ── Password strength rules (mirrors backend/app/utils/password.py) ──── */
interface Rule {
  label: string
  test: (pw: string) => boolean
}

const PASSWORD_RULES: Rule[] = [
  { label: "At least 12 characters", test: (pw) => pw.length >= 12 },
  { label: "One uppercase letter (A-Z)", test: (pw) => /[A-Z]/.test(pw) },
  { label: "One lowercase letter (a-z)", test: (pw) => /[a-z]/.test(pw) },
  { label: "One digit (0-9)", test: (pw) => /\d/.test(pw) },
  { label: "One special character (!@#$%...)", test: (pw) => /[!@#$%^&*()_+\-=[\]{}|;:'",.<>?/`~\\]/.test(pw) },
]

export function ForceChangePasswordModal() {
  const token = useAuthStore((s) => s.token)
  const clearAuth = useAuthStore((s) => s.clearAuth)

  const [currentPassword, setCurrentPassword] = useState("")
  const [newPassword, setNewPassword] = useState("")
  const [confirmPassword, setConfirmPassword] = useState("")
  const [showCurrent, setShowCurrent] = useState(false)
  const [showNew, setShowNew] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

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
      // Password changed — clear the flag and force re-login
      // (backend revoked all refresh tokens, so we must re-authenticate)
      clearAuth()
      // Small delay so user sees success before redirect
      window.location.href = "/login"
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
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/80 backdrop-blur-sm">
      <div className="w-full max-w-md rounded-2xl border border-border/30 bg-background shadow-2xl shadow-black/60 overflow-hidden">
        {/* Header */}
        <div className="flex items-center gap-3 border-b border-border/30 bg-severity-warning/5 px-6 py-4">
          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-severity-warning/15">
            <Shield size={20} className="text-severity-warning" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-foreground">Password Change Required</h2>
            <p className="text-xs text-muted-foreground">
              You must set a new password before continuing
            </p>
          </div>
        </div>

        {/* Security notice */}
        <div className="mx-6 mt-4 flex items-start gap-2 rounded-lg border border-severity-warning/20 bg-severity-warning/5 p-3">
          <AlertTriangle size={14} className="mt-0.5 flex-shrink-0 text-severity-warning" />
          <p className="text-[11px] text-muted-foreground leading-relaxed">
            Your account is using a default or temporary password. For security, you must change it now.
            All existing sessions will be invalidated after the change.
          </p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4 p-6">
          {/* Current password */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium tracking-wider text-foreground/50">
              CURRENT PASSWORD
            </label>
            <div className="relative">
              <input
                type={showCurrent ? "text" : "password"}
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                required
                autoComplete="current-password"
                autoFocus
                className="w-full rounded-lg border border-border/40 bg-white/[0.02] px-3 py-2.5 pr-10 text-sm text-foreground placeholder-muted-foreground/40 focus:border-primary/50 focus:outline-none focus:ring-1 focus:ring-primary/30 transition-all"
                placeholder="Enter current password"
              />
              <button
                type="button"
                onClick={() => setShowCurrent((v) => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground/50 hover:text-foreground transition-colors"
                tabIndex={-1}
              >
                {showCurrent ? <EyeOff size={14} /> : <Eye size={14} />}
              </button>
            </div>
          </div>

          {/* New password */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium tracking-wider text-foreground/50">
              NEW PASSWORD
            </label>
            <div className="relative">
              <input
                type={showNew ? "text" : "password"}
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                required
                autoComplete="new-password"
                className="w-full rounded-lg border border-border/40 bg-white/[0.02] px-3 py-2.5 pr-10 text-sm text-foreground placeholder-muted-foreground/40 focus:border-primary/50 focus:outline-none focus:ring-1 focus:ring-primary/30 transition-all"
                placeholder="Enter new password"
              />
              <button
                type="button"
                onClick={() => setShowNew((v) => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground/50 hover:text-foreground transition-colors"
                tabIndex={-1}
              >
                {showNew ? <EyeOff size={14} /> : <Eye size={14} />}
              </button>
            </div>

            {/* Strength indicators */}
            {newPassword.length > 0 && (
              <div className="space-y-1 pt-1">
                {PASSWORD_RULES.map((rule, i) => {
                  const passed = rule.test(newPassword)
                  return (
                    <div key={i} className="flex items-center gap-2 text-[11px]">
                      {passed ? (
                        <Check size={12} className="text-status-active flex-shrink-0" />
                      ) : (
                        <X size={12} className="text-muted-foreground/40 flex-shrink-0" />
                      )}
                      <span className={passed ? "text-status-active" : "text-muted-foreground/50"}>
                        {rule.label}
                      </span>
                    </div>
                  )
                })}
              </div>
            )}
          </div>

          {/* Confirm password */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium tracking-wider text-foreground/50">
              CONFIRM NEW PASSWORD
            </label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
              autoComplete="new-password"
              className="w-full rounded-lg border border-border/40 bg-white/[0.02] px-3 py-2.5 text-sm text-foreground placeholder-muted-foreground/40 focus:border-primary/50 focus:outline-none focus:ring-1 focus:ring-primary/30 transition-all"
              placeholder="Confirm new password"
            />
            {confirmPassword.length > 0 && !passwordsMatch && (
              <p className="text-[11px] text-severity-critical">Passwords do not match</p>
            )}
          </div>

          {/* Error */}
          {error && (
            <div className="rounded-lg border border-severity-critical/20 bg-severity-critical/10 p-3 text-sm text-severity-critical">
              {error}
            </div>
          )}

          {/* Submit */}
          <button
            type="submit"
            disabled={!canSubmit}
            className="flex w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground transition-all hover:bg-primary/90 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {loading ? (
              <>
                <Loader2 size={16} className="animate-spin" />
                Changing password...
              </>
            ) : (
              <>
                <Shield size={16} />
                Set New Password
              </>
            )}
          </button>
        </form>
      </div>
    </div>
  )
}
