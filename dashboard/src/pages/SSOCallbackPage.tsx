// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — SSO Callback Page.
 *
 * The IdP redirects the browser to the backend OIDC/SAML callback,
 * which then redirects here with tokens in the URL hash fragment:
 *   /sso/callback#access_token=...&refresh_token=...&expires_in=...
 *
 * This page extracts the tokens, fetches the user profile,
 * stores everything in the auth store, then redirects to /.
 */

import { useEffect, useState } from "react"
import { Navigate } from "react-router-dom"
import { Loader2, AlertTriangle } from "lucide-react"
import { useAuthStore } from "@/stores/authStore"
import { fetchMe } from "@/api/auth"
import { PhantexLogo } from "@/components/PhantexLogo"

export function SSOCallbackPage() {
  const setAuth = useAuthStore((s) => s.setAuth)
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState(false)

  useEffect(() => {
    const processCallback = async () => {
      try {
        // Parse hash fragment: #access_token=...&refresh_token=...&expires_in=...
        const hash = window.location.hash.substring(1) // remove leading #
        if (!hash) {
          setError("No authentication data received. Please try again.")
          return
        }

        const params = new URLSearchParams(hash)
        const accessToken = params.get("access_token")
        const refreshToken = params.get("refresh_token")

        if (!accessToken || !refreshToken) {
          // Clean hash even on error to prevent token leakage
          window.history.replaceState(null, "", "/sso/callback")
          setError("Incomplete authentication response. Missing tokens.")
          return
        }

        // Fetch user profile with the SSO-issued token
        const user = await fetchMe(accessToken)

        // Store in auth store (same as password login)
        setAuth(accessToken, refreshToken, user)

        // Clean up hash fragment from URL
        window.history.replaceState(null, "", "/sso/callback")

        setDone(true)
      } catch (err: unknown) {
        // Clean hash on error to prevent token leakage in URL
        window.history.replaceState(null, "", "/sso/callback")
        const msg =
          err instanceof Error ? err.message : "SSO authentication failed"
        setError(msg)
      }
    }

    processCallback()
  }, [setAuth])

  // Redirect to dashboard once authenticated
  if (done || isAuthenticated) {
    return <Navigate to="/" replace />
  }

  return (
    <div className="flex min-h-screen items-center justify-center">
      <div className="flex flex-col items-center text-center space-y-4">
        <PhantexLogo size={48} />
        {error ? (
          <>
            <div className="flex items-center gap-2 text-destructive">
              <AlertTriangle size={20} />
              <span className="text-sm font-medium">SSO Authentication Failed</span>
            </div>
            <p className="text-sm text-muted-foreground max-w-[360px]">{error}</p>
            <a
              href="/login"
              className="text-sm text-primary hover:underline mt-2"
            >
              Return to login
            </a>
          </>
        ) : (
          <>
            <Loader2 className="h-6 w-6 animate-spin text-primary" />
            <p className="text-sm text-muted-foreground">
              Completing SSO authentication...
            </p>
          </>
        )}
      </div>
    </div>
  )
}
