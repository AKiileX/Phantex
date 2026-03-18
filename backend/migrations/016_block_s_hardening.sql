-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2025-2026 The Phantex Authors

-- ============================================================================
-- 016: Block S Hardening Fixes
-- L-5: Add DELETE grant on roles table for phantex_app
-- M-9: Add periodic cleanup for expired SAML assertion IDs
-- ============================================================================

BEGIN;

-- L-5: Missing DELETE grant on roles table
GRANT DELETE ON roles TO phantex_app;

-- M-9: Create a function to clean up expired SAML assertion IDs
CREATE OR REPLACE FUNCTION cleanup_expired_assertion_ids()
RETURNS integer AS $$
DECLARE
    deleted_count integer;
BEGIN
    DELETE FROM sso_assertion_ids WHERE expires_at < now();
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Grant execute to app user
GRANT EXECUTE ON FUNCTION cleanup_expired_assertion_ids() TO phantex_app;

COMMIT;
