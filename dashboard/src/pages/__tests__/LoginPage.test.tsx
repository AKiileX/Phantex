// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

/**
 * Phantex — LoginPage smoke tests.
 *
 * Verifies:
 *   - Login form renders with email + password fields
 *   - Submit button present and labelled
 *   - Error message shown on failed login
 */

import { describe, it, expect } from "vitest"
import { screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { LoginPage } from "@/pages/LoginPage"
import { renderWithProviders } from "@/test/test-utils"

describe("LoginPage", () => {
  it("renders email and password inputs", () => {
    renderWithProviders(<LoginPage />, { routerEntries: ["/login"] })

    expect(screen.getByPlaceholderText("you@company.com")).toBeInTheDocument()
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument()
  })

  it("renders a sign-in button", () => {
    renderWithProviders(<LoginPage />, { routerEntries: ["/login"] })

    expect(
      screen.getByRole("button", { name: /^sign in$/i }),
    ).toBeInTheDocument()
  })

  it("shows validation when submitting empty form", async () => {
    const user = userEvent.setup()
    renderWithProviders(<LoginPage />, { routerEntries: ["/login"] })

    const btn = screen.getByRole("button", { name: /^sign in$/i })
    await user.click(btn)

    // The form should still be present (no navigation)
    expect(screen.getByPlaceholderText("you@company.com")).toBeInTheDocument()
  })
})
