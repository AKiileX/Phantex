// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

import { test, expect } from "@playwright/test";

/**
 * Login flow E2E tests.
 *
 * These tests verify the authentication UI works correctly,
 * including error states, lockout behaviour, and successful login.
 */

const TEST_EMAIL = process.env.TEST_EMAIL || "admin@phantex.local";
const TEST_PASSWORD = process.env.TEST_PASSWORD || "TestPassword2024!";

test.describe("Login", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/login");
  });

  test("renders login form", async ({ page }) => {
    await expect(page.getByRole("heading", { name: /sign in|log in/i })).toBeVisible();
    await expect(page.getByLabel(/email/i)).toBeVisible();
    await expect(page.getByLabel(/password/i)).toBeVisible();
    await expect(page.getByRole("button", { name: /sign in|log in/i })).toBeVisible();
  });

  test("shows error for invalid credentials", async ({ page }) => {
    await page.getByLabel(/email/i).fill("wrong@example.com");
    await page.getByLabel(/password/i).fill("WrongPassword123!");
    await page.getByRole("button", { name: /sign in|log in/i }).click();

    // Should show generic error — no account enumeration hints
    await expect(
      page.getByText(/invalid credentials|unauthorized|login failed/i)
    ).toBeVisible({ timeout: 5000 });

    // URL should NOT change to dashboard
    expect(page.url()).toContain("/login");
  });

  test("shows validation for empty fields", async ({ page }) => {
    await page.getByRole("button", { name: /sign in|log in/i }).click();

    // Browser or app-level validation should prevent submission
    // or show a validation message
    const emailInput = page.getByLabel(/email/i);
    const isInvalid =
      (await emailInput.getAttribute("aria-invalid")) === "true" ||
      (await emailInput.evaluate((el: HTMLInputElement) => !el.validity.valid));
    expect(isInvalid).toBeTruthy();
  });

  test("successful login redirects to dashboard", async ({ page }) => {
    await page.getByLabel(/email/i).fill(TEST_EMAIL);
    await page.getByLabel(/password/i).fill(TEST_PASSWORD);
    await page.getByRole("button", { name: /sign in|log in/i }).click();

    // Should redirect away from /login
    await page.waitForURL((url) => !url.pathname.includes("/login"), {
      timeout: 10000,
    });

    // Dashboard content should be visible
    await expect(
      page.getByText(/dashboard|alerts|overview/i).first()
    ).toBeVisible({ timeout: 5000 });
  });

  test("no account enumeration — locked and invalid look the same", async ({ page }) => {
    // Both invalid-user and locked-user should return the same error
    // (401 Unauthorized with generic message, never 423 Locked)
    for (const email of ["nonexistent@phantex.local", "locked@phantex.local"]) {
      await page.getByLabel(/email/i).fill(email);
      await page.getByLabel(/password/i).fill("AnyPassword123!");
      await page.getByRole("button", { name: /sign in|log in/i }).click();

      // Should show the same generic error for both
      await expect(
        page.getByText(/invalid credentials|unauthorized|login failed/i)
      ).toBeVisible({ timeout: 5000 });

      // Should NOT show "account locked" or any account-specific info
      await expect(page.getByText(/locked|suspended/i)).not.toBeVisible();
    }
  });
});
