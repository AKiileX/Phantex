// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — Axios API client with JWT auth interceptor.
 *
 * Auto-attaches Bearer token from Zustand store.
 * On 401, attempts token refresh; on failure, redirects to login.
 */

import axios from "axios"
import { useAuthStore } from "@/stores/authStore"

const apiClient = axios.create({
  baseURL: "/api/v1",
  headers: { "Content-Type": "application/json" },
})

/* ── Request interceptor: attach JWT ──────────────────────────────────────── */

apiClient.interceptors.request.use((config) => {
  const token = useAuthStore.getState().token
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

/* ── Response interceptor: handle 401 with token refresh ──────────────────── */

apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config

    if (
      error.response?.status === 401 &&
      !originalRequest._retry &&
      originalRequest.url !== "/auth/refresh" &&
      originalRequest.url !== "/auth/login"
    ) {
      originalRequest._retry = true

      const refreshToken = useAuthStore.getState().refreshToken
      if (refreshToken) {
        try {
          const { data } = await axios.post("/api/v1/auth/refresh", {
            refresh_token: refreshToken,
          })
          useAuthStore
            .getState()
            .updateTokens(data.access_token, data.refresh_token)
          originalRequest.headers.Authorization = `Bearer ${data.access_token}`
          return apiClient(originalRequest)
        } catch {
          /* refresh failed — fall through to clearAuth */
        }
      }

      useAuthStore.getState().clearAuth()
      window.location.href = "/login"
    }

    return Promise.reject(error)
  },
)

export default apiClient
