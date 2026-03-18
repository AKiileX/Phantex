-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- Migration 029: Add must_change_password column to users table.
--
-- When TRUE, the backend returns a flag in the login response and the
-- dashboard forces a password-change modal before allowing any navigation.
-- Cleared automatically after a successful password change.
--
-- All existing seed/dev users default to TRUE so that first-login in
-- production mode always requires a password reset.

ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT TRUE;

-- Existing users in dev environments already have known passwords,
-- so set them to TRUE to enforce the change-on-first-login flow.
-- In production, the quickstart script generates a random password AND
-- sets this flag, so the admin MUST change it immediately.
