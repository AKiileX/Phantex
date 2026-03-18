-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- Migration 034: Add copilot.use permission
-- The copilot.use permission was missing from the permissions table,
-- causing the Copilot FAB to be hidden for all users (including admin).
-- It existed in the legacy ABAC fallback map but not in the DB.

BEGIN;

-- Insert the copilot.use permission
INSERT INTO permissions (resource, action, description)
VALUES ('copilot', 'use', 'Access the AI Copilot assistant')
ON CONFLICT (resource, action) DO NOTHING;

-- Grant copilot.use to admin role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'admin'
  AND p.resource = 'copilot' AND p.action = 'use'
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Grant copilot.use to analyst role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'analyst'
  AND p.resource = 'copilot' AND p.action = 'use'
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Track migration
INSERT INTO schema_migrations (version, description)
VALUES ('034', 'Add copilot.use permission for admin and analyst roles')
ON CONFLICT (version) DO NOTHING;

COMMIT;
