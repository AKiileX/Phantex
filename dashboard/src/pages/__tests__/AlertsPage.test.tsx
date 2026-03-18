// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — AlertsPage tests (O1 — virtual scrolling + grouping).
 *
 * Verifies:
 *   - Page renders with title
 *   - Status filter tabs present
 *   - Loading state shown initially
 *   - Group/Flat toggle rendered
 *   - Live mode toggle rendered
 *   - Tab interaction doesn't crash
 */

import { describe, it, expect } from "vitest"
import { screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { AlertsPage } from "@/pages/AlertsPage"
import { renderWithProviders } from "@/test/test-utils"

describe("AlertsPage", () => {
  it("renders the page title", () => {
    renderWithProviders(<AlertsPage />)

    expect(screen.getByRole("heading", { name: "Alerts" })).toBeInTheDocument()
  })

  it("renders status filter tabs", () => {
    renderWithProviders(<AlertsPage />)

    // Status tab buttons rendered among other UI elements — use getAllByText where duplicates exist
    expect(screen.getAllByText("All").length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText("Open").length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText("Acknowledged").length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText("Resolved").length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText("False Positive").length).toBeGreaterThanOrEqual(1)
  })

  it("renders group/flat toggle", () => {
    renderWithProviders(<AlertsPage />)

    // Default is grouped mode
    expect(screen.getByText("Grouped")).toBeInTheDocument()
  })

  it("renders live mode toggle", () => {
    renderWithProviders(<AlertsPage />)

    expect(screen.getByText("Auto")).toBeInTheDocument()
  })

  it("shows loading state", () => {
    renderWithProviders(<AlertsPage />)

    expect(screen.getByText(/loading alerts/i)).toBeInTheDocument()
  })

  it("can switch status tab", async () => {
    const user = userEvent.setup()
    renderWithProviders(<AlertsPage />)

    const openButtons = screen.getAllByText("Open")
    await user.click(openButtons[0])

    // Tab should still be visible (no crash)
    expect(screen.getAllByText("Open").length).toBeGreaterThanOrEqual(1)
  })

  it("can toggle between grouped and flat view", async () => {
    const user = userEvent.setup()
    renderWithProviders(<AlertsPage />)

    const groupButton = screen.getByText("Grouped")
    await user.click(groupButton)

    // After clicking, should switch to Flat
    expect(screen.getByText("Flat")).toBeInTheDocument()
  })

  it("can toggle live mode", async () => {
    const user = userEvent.setup()
    renderWithProviders(<AlertsPage />)

    const autoButton = screen.getByText("Auto")
    await user.click(autoButton)

    // After clicking, should switch to Live
    expect(screen.getByText("Live")).toBeInTheDocument()
  })
})
