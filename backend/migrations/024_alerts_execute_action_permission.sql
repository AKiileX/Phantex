-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- 024: Add alerts.execute_action permission (post-security-audit).
--
-- Response actions (isolate, block, kill, quarantine) are high-impact operations.
-- They get their own permission separate from alerts.acknowledge so that
-- organizations can grant triage (acknowledge) without granting response execution.
--
-- Assigned to admin + analyst roles by default.

BEGIN;

-- 1. Insert the permission itself
INSERT INTO permissions (resource, action, description)
VALUES ('alerts', 'execute_action', 'Execute response actions (isolate, block, kill, quarantine)')
ON CONFLICT DO NOTHING;

-- 2. Grant to admin role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'admin'
  AND p.resource = 'alerts' AND p.action = 'execute_action'
ON CONFLICT DO NOTHING;

-- 3. Grant to analyst role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = 'analyst'
  AND p.resource = 'alerts' AND p.action = 'execute_action'
ON CONFLICT DO NOTHING;

COMMIT;
