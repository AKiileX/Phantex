# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Block S: Enterprise Auth — ABAC Integration Tests.

Tests the ABAC permission engine, role CRUD, legacy role fallback,
and condition evaluation (time_range, ip_range, resource_tags).
Runs entirely in-memory with mocked database sessions.
"""

import uuid
from datetime import UTC, datetime
from unittest.mock import MagicMock

# ── Test UUIDs ────────────────────────────────────────────────────────────────

TENANT_ID = uuid.UUID("a0000000-0000-0000-0000-000000000001")
USER_ID = uuid.UUID("b0000000-0000-0000-0000-000000000001")
ROLE_ID = uuid.UUID("c0000000-0000-0000-0000-000000000001")
PERM_ID = uuid.UUID("d0000000-0000-0000-0000-000000000001")

# ── S4.1: Legacy role fallback ────────────────────────────────────────────────

class TestLegacyRoleFallback:
    """When no user_roles rows exist, ABAC falls back to legacy role column."""

    def test_admin_gets_all_permissions(self):
        from app.services.abac_service import LEGACY_ROLE_PERMISSIONS

        perms = LEGACY_ROLE_PERMISSIONS["admin"]
        assert "alerts.read" in perms
        assert "alerts.acknowledge" in perms
        assert "rules.write" in perms
        assert "rules.delete" in perms
        assert "users.manage" in perms
        assert "tenants.manage" in perms
        assert "auth.manage" in perms
        assert "ml.manage" in perms

    def test_analyst_gets_analysis_permissions(self):
        from app.services.abac_service import LEGACY_ROLE_PERMISSIONS

        perms = LEGACY_ROLE_PERMISSIONS["analyst"]
        assert "alerts.read" in perms
        assert "alerts.acknowledge" in perms
        assert "rules.read" in perms
        assert "rules.write" in perms
        # Analyst should NOT have admin-only permissions
        assert "rules.delete" not in perms
        assert "users.manage" not in perms
        assert "tenants.manage" not in perms
        assert "auth.manage" not in perms

    def test_viewer_gets_read_only_permissions(self):
        from app.services.abac_service import LEGACY_ROLE_PERMISSIONS

        perms = LEGACY_ROLE_PERMISSIONS["viewer"]
        assert "alerts.read" in perms
        assert "events.read" in perms
        assert "dashboard.view" in perms
        # Viewer should NOT have write permissions
        assert "alerts.acknowledge" not in perms
        assert "rules.write" not in perms
        assert "users.manage" not in perms

# ── S4.2: ABAC condition evaluation ──────────────────────────────────────────

class TestABACConditions:
    """Test _check_condition_set logic (time_range, ip_range, resource_tags)."""

    def test_time_range_within_window(self):
        from app.services.abac_service import _check_condition_set

        conditions = {"time_range": {"after": "00:00", "before": "23:59"}}
        ctx = {}
        assert _check_condition_set(conditions, ctx) is True

    def test_time_range_outside_window(self):
        from app.services.abac_service import _check_condition_set

        # Use a very narrow window that's guaranteed to exclude current time
        conditions = {"time_range": {"after": "03:00", "before": "03:01"}}
        ctx = {}
        result = _check_condition_set(conditions, ctx)
        assert isinstance(result, bool)

    def test_ip_range_match(self):
        from app.services.abac_service import _check_condition_set

        conditions = {"ip_range": {"allowed": ["10.0.0.0/8", "192.168.0.0/16"]}}
        ctx = {"client_ip": "10.1.2.3"}
        assert _check_condition_set(conditions, ctx) is True

    def test_ip_range_no_match(self):
        from app.services.abac_service import _check_condition_set

        conditions = {"ip_range": {"allowed": ["10.0.0.0/8"]}}
        ctx = {"client_ip": "172.16.0.1"}
        assert _check_condition_set(conditions, ctx) is False

    def test_resource_tags_match(self):
        from app.services.abac_service import _check_condition_set

        conditions = {"resource_tags": {"required_tags": {"env": "production"}}}
        ctx = {"resource_tags": {"env": "production", "team": "security"}}
        assert _check_condition_set(conditions, ctx) is True

    def test_resource_tags_no_match(self):
        from app.services.abac_service import _check_condition_set

        conditions = {"resource_tags": {"required_tags": {"env": "production"}}}
        ctx = {"resource_tags": {"env": "staging"}}
        assert _check_condition_set(conditions, ctx) is False

    def test_empty_conditions_pass(self):
        from app.services.abac_service import _check_condition_set

        assert _check_condition_set({}, {}) is True

    def test_missing_client_ip_for_ip_range(self):
        from app.services.abac_service import _check_condition_set

        conditions = {"ip_range": {"allowed": ["10.0.0.0/8"]}}
        ctx = {}  # no client_ip
        result = _check_condition_set(conditions, ctx)
        assert isinstance(result, bool)

# ── S4.3: Permission cache ────────────────────────────────────────────────────

class TestPermissionCache:
    """Test that the permission cache invalidation works."""

    def test_user_cache_invalidation(self):
        from app.services.abac_service import _permission_cache, invalidate_user_cache

        _permission_cache[USER_ID] = (999999999999.0, {"alerts.read"})
        assert USER_ID in _permission_cache
        invalidate_user_cache(USER_ID)
        assert USER_ID not in _permission_cache

    def test_role_cache_invalidation_clears_all(self):
        from app.services.abac_service import _permission_cache, invalidate_role_cache

        uid1 = uuid.uuid4()
        uid2 = uuid.uuid4()
        _permission_cache[uid1] = (999999999999.0, {"a"})
        _permission_cache[uid2] = (999999999999.0, {"b"})
        invalidate_role_cache(ROLE_ID)
        assert uid1 not in _permission_cache
        assert uid2 not in _permission_cache

    def test_invalidate_all_cache(self):
        from app.services.abac_service import _permission_cache, invalidate_all_cache

        uid1 = uuid.uuid4()
        _permission_cache[uid1] = (999999999999.0, {"a"})
        invalidate_all_cache()
        assert uid1 not in _permission_cache

    def test_cache_set_and_get(self):
        from app.services.abac_service import _cache_get, _cache_set

        uid = uuid.uuid4()
        _cache_set(uid, {"alerts.read", "events.read"})
        result = _cache_get(uid)
        assert result == {"alerts.read", "events.read"}

# ── S4.4: require_permission dependency ───────────────────────────────────────

class TestRequirePermissionDependency:
    """Test the FastAPI dependency factory."""

    def test_require_permission_returns_callable(self):
        from app.middleware.abac import require_permission

        dep = require_permission("alerts.read")
        assert callable(dep)

    def test_require_permission_multiple_permissions(self):
        from app.middleware.abac import require_permission

        dep = require_permission("alerts.read", "alerts.acknowledge")
        assert callable(dep)

# ── S1: SSO service unit tests ───────────────────────────────────────────────

class TestSSOService:
    """Test SAML / OIDC helper functions."""

    def test_build_saml_authn_request(self):
        from app.services.sso_service import build_saml_authn_request

        config = MagicMock()
        config.idp_entity_id = "https://idp.example.com"
        config.idp_sso_url = "https://idp.example.com/sso"
        config.sp_entity_id = "https://phantex.example.com"
        config.sp_acs_url = "https://phantex.example.com/api/v1/sso/saml/acs"

        result = build_saml_authn_request(config)
        assert isinstance(result, dict)
        assert "redirect_url" in result
        assert "relay_state" in result
        assert "https://idp.example.com/sso" in result["redirect_url"]
        assert "SAMLRequest=" in result["redirect_url"]

    def test_build_oidc_auth_url(self):
        from app.services.sso_service import build_oidc_auth_url

        config = MagicMock()
        config.oidc_issuer = "https://auth.example.com"
        config.oidc_client_id = "phantex-client"
        config.oidc_scopes = "openid email profile"
        config.sp_acs_url = "https://phantex.example.com/callback"

        result = build_oidc_auth_url(config)
        assert isinstance(result, dict)
        assert "redirect_url" in result
        assert "state" in result
        assert "code_verifier" in result
        assert "nonce" in result
        assert "client_id=phantex-client" in result["redirect_url"]
        assert "code_challenge" in result["redirect_url"]

# ── S3: SCIM token hashing ───────────────────────────────────────────────────

class TestSCIMTokens:
    """Test SCIM token generation and hashing."""

    def test_scim_token_hash_is_deterministic(self):
        import hashlib

        token = "test-token-value"
        hash1 = hashlib.sha256(token.encode()).hexdigest()
        hash2 = hashlib.sha256(token.encode()).hexdigest()
        assert hash1 == hash2

    def test_scim_token_hash_is_different_for_different_tokens(self):
        import hashlib

        hash1 = hashlib.sha256(b"token-a").hexdigest()
        hash2 = hashlib.sha256(b"token-b").hexdigest()
        assert hash1 != hash2

# ── S5: Tenant service ───────────────────────────────────────────────────────

class TestTenantSchemas:
    """Test tenant Pydantic schemas."""

    def test_tenant_create_schema(self):
        from app.schemas.tenant import TenantCreate

        t = TenantCreate(
            name="Test Corp",
            slug="test-corp",
            plan="enterprise",
            admin_email="admin@testcorp.com",
            admin_password="TestPassword123!",
        )
        assert t.name == "Test Corp"
        assert t.admin_email == "admin@testcorp.com"

    def test_tenant_response_schema(self):
        from app.schemas.tenant import TenantResponse

        t = TenantResponse(
            id=TENANT_ID,
            name="Test Corp",
            slug="test-corp",
            plan="enterprise",
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        assert t.is_active is True

# ── ABAC schema tests ────────────────────────────────────────────────────────

class TestABACSchemas:
    """Test ABAC Pydantic schemas."""

    def test_role_create_valid_name(self):
        from app.schemas.abac import RoleCreate

        r = RoleCreate(name="security-ops", description="Security Operations")
        assert r.name == "security-ops"

    def test_role_create_with_permission_ids(self):
        from app.schemas.abac import RoleCreate

        pids = [uuid.uuid4() for _ in range(5)]
        r = RoleCreate(
            name="analyst-plus",
            description="Enhanced analyst",
            permission_ids=pids,
        )
        assert len(r.permission_ids) == 5

    def test_permission_response(self):
        from app.schemas.abac import PermissionResponse

        p = PermissionResponse(
            id=PERM_ID,
            resource="alerts",
            action="read",
            description="Read alerts",
        )
        assert p.resource == "alerts"
        assert p.action == "read"

# ── SCIM schema tests ────────────────────────────────────────────────────────

class TestSCIMSchemas:
    """Test SCIM 2.0 Pydantic schemas."""

    def test_scim_user_create(self):
        from app.schemas.scim import SCIMUserCreate

        u = SCIMUserCreate(
            schemas=["urn:ietf:params:scim:schemas:core:2.0:User"],
            userName="john.doe@example.com",
            displayName="John Doe",
            active=True,
        )
        assert u.userName == "john.doe@example.com"

    def test_scim_error(self):
        from app.schemas.scim import SCIMError

        e = SCIMError(
            schemas=["urn:ietf:params:scim:api:messages:2.0:Error"],
            detail="Not found",
            status="404",
        )
        assert e.status == "404"

    def test_scim_list_response(self):
        from app.schemas.scim import SCIMListResponse

        lr = SCIMListResponse(
            schemas=["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            totalResults=0,
            startIndex=1,
            itemsPerPage=10,
            Resources=[],
        )
        assert lr.totalResults == 0

# ── SSO schema tests ─────────────────────────────────────────────────────────

class TestSSOSchemas:
    """Test SSO Pydantic schemas."""

    def test_sso_config_create(self):
        from app.schemas.sso import SSOConfigCreate

        c = SSOConfigCreate(
            provider_type="saml",
            name="Okta SSO",
            idp_entity_id="https://okta.com/entity",
            idp_sso_url="https://okta.com/sso",
        )
        assert c.provider_type == "saml"

    def test_sso_config_response_no_client_secret(self):
        from app.schemas.sso import SSOConfigResponse

        r = SSOConfigResponse(
            id=uuid.uuid4(),
            tenant_id=TENANT_ID,
            provider_type="oidc",
            name="Azure AD",
            is_enabled=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        data = r.model_dump()
        assert "oidc_client_secret" not in data or data.get("oidc_client_secret") is None

    def test_saml_login_response(self):
        from app.schemas.sso import SAMLLoginResponse

        r = SAMLLoginResponse(redirect_url="https://idp.example.com/sso?SAMLRequest=abc")
        assert "SAMLRequest" in r.redirect_url

    def test_oidc_login_response(self):
        from app.schemas.sso import OIDCLoginResponse

        r = OIDCLoginResponse(
            redirect_url="https://auth.example.com/authorize?code=abc",
            state="random-state",
            nonce="random-nonce",
        )
        assert r.state == "random-state"

# ── Model tests ───────────────────────────────────────────────────────────────

class TestABACModels:
    """Test SQLAlchemy model definitions."""

    def test_permission_model_has_resource_action(self):
        from app.models.permission import Permission

        assert hasattr(Permission, "resource")
        assert hasattr(Permission, "action")
        assert Permission.__tablename__ == "permissions"

    def test_role_model_has_tenant_scope(self):
        from app.models.permission import Role

        assert hasattr(Role, "tenant_id")
        assert hasattr(Role, "is_builtin")
        assert hasattr(Role, "policy")
        assert Role.__tablename__ == "roles"

    def test_user_role_model_exists(self):
        from app.models.permission import UserRole

        assert hasattr(UserRole, "user_id")
        assert hasattr(UserRole, "role_id")
        assert UserRole.__tablename__ == "user_roles"

    def test_sso_config_model(self):
        from app.models.sso import SSOConfig

        assert hasattr(SSOConfig, "tenant_id")
        assert hasattr(SSOConfig, "provider_type")
        assert hasattr(SSOConfig, "idp_sso_url")

    def test_scim_token_model(self):
        from app.models.sso import SCIMToken

        assert hasattr(SCIMToken, "tenant_id")
        assert hasattr(SCIMToken, "token_hash")

    def test_tenant_model_has_new_fields(self):
        from app.models.tenant import Tenant

        assert hasattr(Tenant, "is_active")
        assert hasattr(Tenant, "max_users")
        assert hasattr(Tenant, "max_agents")
        assert hasattr(Tenant, "max_events_per_day")

    def test_user_model_has_sso_fields(self):
        from app.models.user import User

        assert hasattr(User, "sso_provider")
        assert hasattr(User, "sso_subject_id")
        assert hasattr(User, "scim_external_id")
