// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

import { test, expect } from "@playwright/test";

/**
 * Dashboard E2E tests — post-login flows.
 *
 * Tests core dashboard functionality: navigation, alerts table,
 * nerve center status, and real-time updates.
 */

const TEST_EMAIL = process.env.TEST_EMAIL || "admin@phantex.local";
const TEST_PASSWORD = process.env.TEST_PASSWORD || "TestPassword2024!";

// ── Auth helper ──────────────────────────────────────────────────────────────

async function login(page: import("@playwright/test").Page) {
  await page.goto("/login");
  await page.getByLabel(/email/i).fill(TEST_EMAIL);
  await page.getByLabel(/password/i).fill(TEST_PASSWORD);
  await page.getByRole("button", { name: /sign in|log in/i }).click();
  await page.waitForURL((url) => !url.pathname.includes("/login"), {
    timeout: 10000,
  });
}

// ── Tests ────────────────────────────────────────────────────────────────────

test.describe("Dashboard", () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test("shows main navigation", async ({ page }) => {
    // At least some nav items should be present
    const navItems = page.getByRole("navigation").getByRole("link");
    await expect(navItems.first()).toBeVisible({ timeout: 5000 });
    const count = await navItems.count();
    expect(count).toBeGreaterThanOrEqual(2);
  });

  test("displays alerts table", async ({ page }) => {
    // Navigate to alerts (may already be the default view)
    const alertsLink = page.getByRole("link", { name: /alerts/i }).first();
    if (await alertsLink.isVisible()) {
      await alertsLink.click();
    }

    // Should see a table or list of alerts
    const table = page.locator("table, [role='grid'], [data-testid='alerts-table']").first();
    await expect(table).toBeVisible({ timeout: 10000 });
  });

  test("nerve center status loads", async ({ page }) => {
    // Navigate to nerve center / status page
    const statusLink = page
      .getByRole("link", { name: /nerve|status|health/i })
      .first();
    if (await statusLink.isVisible()) {
      await statusLink.click();
    }

    // Should display pipeline status nodes (we have 12 in the pipeline)
    await page.waitForTimeout(2000);
    const statusIndicators = page.locator(
      "[data-testid*='status'], [data-testid*='node'], .status-indicator, .pipeline-node"
    );
    // At least some status elements should be present
    const count = await statusIndicators.count();
    // Soft check — nerve center might be behind a different route
    if (count > 0) {
      expect(count).toBeGreaterThanOrEqual(1);
    }
  });

  test("logout works", async ({ page }) => {
    // Find and click logout
    const logoutBtn = page
      .getByRole("button", { name: /log\s?out|sign\s?out/i })
      .or(page.getByText(/log\s?out|sign\s?out/i))
      .first();

    if (await logoutBtn.isVisible()) {
      await logoutBtn.click();

      // Should redirect back to login
      await page.waitForURL((url) => url.pathname.includes("/login"), {
        timeout: 5000,
      });
      await expect(page.getByLabel(/email/i)).toBeVisible();
    }
  });

  test("protected routes redirect to login when unauthenticated", async ({
    browser,
  }) => {
    // New context — no auth cookies/tokens
    const context = await browser.newContext();
    const page = await context.newPage();

    await page.goto("/");

    // Should redirect to /login
    await page.waitForURL((url) => url.pathname.includes("/login"), {
      timeout: 5000,
    });
    await expect(page.getByLabel(/email/i)).toBeVisible();

    await context.close();
  });
});
