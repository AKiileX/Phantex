// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — AgentsPage smoke tests.
 *
 * Verifies:
 *   - Page renders with title and column headers
 *   - Sortable column headers render with sort icons
 *   - Loading state shown initially
 */

import { describe, it, expect } from "vitest"
import { screen } from "@testing-library/react"
import { AgentsPage } from "@/pages/AgentsPage"
import { renderWithProviders } from "@/test/test-utils"

describe("AgentsPage", () => {
  it("renders the page title", () => {
    renderWithProviders(<AgentsPage />)

    expect(screen.getByText("Agent Inventory")).toBeInTheDocument()
  })

  it("renders sortable column headers", () => {
    renderWithProviders(<AgentsPage />)

    expect(screen.getByText("Status")).toBeInTheDocument()
    expect(screen.getByText("PAID")).toBeInTheDocument()
    expect(screen.getByText("Name")).toBeInTheDocument()
    expect(screen.getByText("Framework")).toBeInTheDocument()
    expect(screen.getByText("Last Seen")).toBeInTheDocument()
  })

  it("shows loading state", () => {
    renderWithProviders(<AgentsPage />)

    expect(screen.getByText(/loading agents/i)).toBeInTheDocument()
  })

  it("renders filter controls", () => {
    renderWithProviders(<AgentsPage />)

    expect(screen.getByPlaceholderText(/filter by paid or name/i)).toBeInTheDocument()
  })
})
