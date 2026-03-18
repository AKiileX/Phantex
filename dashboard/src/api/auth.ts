// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Auth API functions (no TanStack Query — imperative calls).
 */

import axios from "axios"
import type { TokenResponse, User } from "@/types"

const BASE = "/api/v1/auth"
const SSO_BASE = "/api/v1/sso"

/** Authenticate with email + password → token pair. */
export async function login(
  email: string,
  password: string,
): Promise<TokenResponse> {
  const { data } = await axios.post<TokenResponse>(`${BASE}/login`, {
    email,
    password,
  })
  return data
}

/** Fetch current user profile using a specific token. */
export async function fetchMe(token: string): Promise<User> {
  const { data } = await axios.get<User>(`${BASE}/me`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  return data
}

/** Exchange refresh token for new token pair. */
export async function refreshTokens(
  refreshToken: string,
): Promise<TokenResponse> {
  const { data } = await axios.post<TokenResponse>(`${BASE}/refresh`, {
    refresh_token: refreshToken,
  })
  return data
}

/** Change own password (requires current password). */
export async function changePassword(
  currentPassword: string,
  newPassword: string,
  token: string,
): Promise<{ message: string }> {
  const { data } = await axios.post<{ message: string }>(
    `${BASE}/password`,
    { current_password: currentPassword, new_password: newPassword },
    { headers: { Authorization: `Bearer ${token}` } },
  )
  return data
}

/* ── SSO Login Initiation ─────────────────────────────────────────── */

interface SSOLoginResponse {
  redirect_url: string
  state?: string
  nonce?: string
  relay_state?: string
}

/**
 * Initiate OIDC SSO — returns a redirect URL to the IdP.
 * The browser should navigate to this URL.
 */
export async function initiateOIDCLogin(tenantId?: string): Promise<string> {
  const params = tenantId ? { tenant_id: tenantId } : {}
  const { data } = await axios.post<SSOLoginResponse>(
    `${SSO_BASE}/oidc/login`,
    null,
    { params },
  )
  return data.redirect_url
}

/**
 * Initiate SAML SSO — returns a redirect URL to the IdP.
 */
export async function initiateSAMLLogin(tenantId?: string): Promise<string> {
  const params = tenantId ? { tenant_id: tenantId } : {}
  const { data } = await axios.post<SSOLoginResponse>(
    `${SSO_BASE}/saml/login`,
    null,
    { params },
  )
  return data.redirect_url
}
