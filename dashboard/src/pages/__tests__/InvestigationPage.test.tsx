// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — InvestigationPage smoke tests.
 *
 * Tests: renders agent/alert investigation headers, invalid route handling,
 * loading state, controls visibility.
 */

import { describe, it, expect, vi, beforeEach } from "vitest"
import { render, screen } from "@testing-library/react"
import { MemoryRouter, Route, Routes } from "react-router-dom"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { InvestigationPage } from "@/pages/InvestigationPage"

/* ── Mocks ─────────────────────────────────────────────────────────────────── */

vi.mock("@/api/timeline", () => ({
  useAgentTimeline: vi.fn(() => ({
    data: undefined,
    isLoading: false,
    isError: false,
    refetch: vi.fn(),
  })),
  useAlertTimeline: vi.fn(() => ({
    data: undefined,
    isLoading: false,
    isError: false,
    refetch: vi.fn(),
  })),
}))

vi.mock("@/stores/authStore", () => ({
  useAuthStore: vi.fn((selector: (s: Record<string, unknown>) => unknown) =>
    selector({
      isAuthenticated: true,
      user: { role: "admin", email: "test@test.com" },
      token: "test-token",
    }),
  ),
}))

/* ── Helpers ───────────────────────────────────────────────────────────────── */

function renderWithRoute(path: string) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })

  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/investigate/:type/:id" element={<InvestigationPage />} />
          <Route path="*" element={<InvestigationPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

/* ── Tests ──────────────────────────────────────────────────────────────────── */

const VALID_UUID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

describe("InvestigationPage", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("renders alert investigation header", () => {
    renderWithRoute(`/investigate/alert/${VALID_UUID}`)
    expect(screen.getByText("Alert Investigation")).toBeInTheDocument()
    expect(screen.getByText(new RegExp(VALID_UUID))).toBeInTheDocument()
  })

  it("renders agent investigation header", () => {
    renderWithRoute(`/investigate/agent/${VALID_UUID}`)
    expect(screen.getByText("Agent Investigation")).toBeInTheDocument()
    expect(screen.getByText(new RegExp(VALID_UUID))).toBeInTheDocument()
  })

  it("shows invalid URL message for bad type", () => {
    renderWithRoute(`/investigate/unknown/${VALID_UUID}`)
    expect(
      screen.getByText(/Invalid investigation URL/),
    ).toBeInTheDocument()
  })

  it("renders no events message when data is empty", () => {
    renderWithRoute(`/investigate/alert/${VALID_UUID}`)
    expect(
      screen.getByText(/No events found/),
    ).toBeInTheDocument()
  })

  it("shows back button", () => {
    renderWithRoute(`/investigate/alert/${VALID_UUID}`)
    expect(screen.getByLabelText("Go back")).toBeInTheDocument()
  })

  /* ── Security hardening tests ──────────────────────────── */

  it("rejects non-UUID id (path traversal attempt)", () => {
    renderWithRoute("/investigate/agent/../../admin/users")
    expect(
      screen.getByText(/Invalid investigation URL/),
    ).toBeInTheDocument()
  })

  it("rejects encoded path traversal in id", () => {
    renderWithRoute("/investigate/alert/..%2F..%2Fadmin%2Fusers")
    expect(
      screen.getByText(/Invalid investigation URL/),
    ).toBeInTheDocument()
  })

  it("rejects plain string id (non-UUID)", () => {
    renderWithRoute("/investigate/agent/abc-123")
    expect(
      screen.getByText(/Invalid investigation URL/),
    ).toBeInTheDocument()
  })

  it("rejects empty id segment", () => {
    renderWithRoute("/investigate/agent/")
    expect(
      screen.getByText(/Invalid investigation URL/),
    ).toBeInTheDocument()
  })
})
