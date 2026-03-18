# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — SSO Service (SAML 2.0 + OIDC).

Handles:
  - SAML SP-initiated SSO flow + assertion validation
  - OIDC Authorization Code + PKCE flow
  - JIT user provisioning on first SSO login
  - SSO session binding to Phantex JWT
"""

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt as pyjwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.sso import SSOAssertionID, SSOConfig
from app.models.user import User
from app.services.auth_service import hash_password
from app.utils.logging import get_logger

logger = get_logger("phantex.services.sso")
settings = get_settings()

# ── SSO Config CRUD ───────────────────────────────────────────────────────────

async def get_sso_config(db: AsyncSession, tenant_id: uuid.UUID, provider_type: str) -> SSOConfig | None:
    """Get active SSO config for a tenant."""
    result = await db.execute(
        select(SSOConfig).where(
            SSOConfig.tenant_id == tenant_id,
            SSOConfig.provider_type == provider_type,
            SSOConfig.is_enabled == True,  # noqa: E712
        )
    )
    return result.scalar_one_or_none()

async def get_sso_config_by_id(db: AsyncSession, config_id: uuid.UUID) -> SSOConfig | None:
    """Get SSO config by ID."""
    result = await db.execute(select(SSOConfig).where(SSOConfig.id == config_id))
    return result.scalar_one_or_none()

async def list_sso_configs(db: AsyncSession, tenant_id: uuid.UUID) -> list[SSOConfig]:
    """List all SSO configs for a tenant."""
    result = await db.execute(
        select(SSOConfig).where(SSOConfig.tenant_id == tenant_id).order_by(SSOConfig.provider_type)
    )
    return list(result.scalars().all())

async def create_sso_config(db: AsyncSession, tenant_id: uuid.UUID, data: dict) -> SSOConfig:
    """Create a new SSO config. M-1: Encrypts OIDC client_secret before storage."""
    # M-1: Encrypt OIDC client_secret at rest
    if data.get("oidc_client_secret"):
        from app.services.secret_encryption import encrypt_secret

        data = dict(data)  # avoid mutating caller's dict
        data["oidc_client_secret"] = await encrypt_secret(data["oidc_client_secret"])

    config = SSOConfig(tenant_id=tenant_id, **data)
    db.add(config)
    await db.flush()
    logger.info("sso_config_created", config_id=str(config.id), provider=config.provider_type)
    return config

async def update_sso_config(db: AsyncSession, config: SSOConfig, data: dict) -> SSOConfig:
    """Update existing SSO config. M-7: Uses explicit allowlist to prevent attribute injection.
    M-1: Encrypts OIDC client_secret before storage."""
    _MUTABLE_SSO_FIELDS = {
        "is_enabled",
        "provider_type",
        "idp_entity_id",
        "idp_sso_url",
        "idp_certificate",
        "sp_entity_id",
        "sp_acs_url",
        "oidc_client_id",
        "oidc_client_secret",
        "oidc_issuer",
        "oidc_scopes",
        "attribute_mapping",
        "jit_provisioning",
        "default_role",
    }
    # M-1: Encrypt OIDC client_secret if being updated
    if data.get("oidc_client_secret"):
        from app.services.secret_encryption import encrypt_secret

        data = dict(data)  # avoid mutating caller's dict
        data["oidc_client_secret"] = await encrypt_secret(data["oidc_client_secret"])

    for key, value in data.items():
        if key in _MUTABLE_SSO_FIELDS and value is not None:
            setattr(config, key, value)
    config.updated_at = datetime.now(UTC)
    await db.flush()
    return config

# ── SAML 2.0 ──────────────────────────────────────────────────────────────────

def build_saml_authn_request(config: SSOConfig) -> dict[str, str]:
    """
    Build a SAML AuthnRequest and return the redirect URL + RelayState.

    Returns {"redirect_url": "...", "relay_state": "..."}
    """
    request_id = f"_phantex_{uuid.uuid4().hex}"
    relay_state = secrets.token_urlsafe(32)
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Build minimal SAML AuthnRequest XML
    authn_request = f"""<samlp:AuthnRequest
        xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        ID="{request_id}"
        Version="2.0"
        IssueInstant="{now}"
        Destination="{config.idp_sso_url}"
        AssertionConsumerServiceURL="{config.sp_acs_url}"
        ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
        <saml:Issuer>{config.sp_entity_id}</saml:Issuer>
        <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress"
                            AllowCreate="true"/>
    </samlp:AuthnRequest>"""

    import base64
    import zlib

    # Deflate + Base64 encode for HTTP-Redirect binding
    deflated = zlib.compress(authn_request.encode("utf-8"))[2:-4]  # raw deflate
    encoded = base64.b64encode(deflated).decode("utf-8")

    params = urlencode(
        {
            "SAMLRequest": encoded,
            "RelayState": relay_state,
        }
    )

    redirect_url = f"{config.idp_sso_url}?{params}"

    return {"redirect_url": redirect_url, "relay_state": relay_state}

async def validate_saml_response(
    db: AsyncSession,
    config: SSOConfig,
    saml_response: str,
) -> dict[str, Any]:
    """
    Validate a SAML Response and extract user attributes.

    Returns: {"email": "...", "name": "...", "groups": [...], "subject_id": "..."}
    Raises ValueError on validation failure.
    """
    import base64

    # Decode Base64 SAML Response
    try:
        response_xml = base64.b64decode(saml_response).decode("utf-8")
    except Exception:
        raise ValueError("Invalid SAML response encoding")

    # Parse XML (defusedxml for XXE / Billion Laughs protection — M-5)
    try:
        import defusedxml.ElementTree as SafeET

        root = SafeET.fromstring(response_xml)
    except Exception:
        raise ValueError("Invalid SAML response XML")

    # ── Verify XML-DSig signature against IdP certificate (C-2 hardening) ──
    if config.idp_certificate:
        try:
            from signxml import XMLVerifier

            XMLVerifier().verify(response_xml, x509_cert=config.idp_certificate)
        except Exception as e:
            raise ValueError(f"SAML signature verification failed: {e}")
    else:
        raise ValueError("IdP certificate not configured — cannot verify SAML response")

    ns = {
        "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
        "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
        "ds": "http://www.w3.org/2000/09/xmldsig#",
    }

    # Check status
    status_elem = root.find(".//samlp:StatusCode", ns)
    if status_elem is not None:
        status_value = status_elem.get("Value", "")
        if "Success" not in status_value:
            raise ValueError(f"SAML authentication failed: {status_value}")

    # Extract assertion
    assertion = root.find(".//saml:Assertion", ns)
    if assertion is None:
        raise ValueError("No assertion found in SAML response")

    # Replay protection — check assertion ID (H-1: require ID attribute)
    assertion_id = assertion.get("ID")
    if not assertion_id:
        raise ValueError("SAML assertion missing required ID attribute")

    existing = await db.execute(select(SSOAssertionID).where(SSOAssertionID.assertion_id == assertion_id))
    if existing.scalar_one_or_none():
        raise ValueError("SAML assertion replay detected")

    # Store consumed assertion ID
    db.add(
        SSOAssertionID(
            assertion_id=assertion_id,
            tenant_id=config.tenant_id,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    )

    # Validate conditions (time-based)
    conditions = assertion.find("saml:Conditions", ns)
    if conditions is not None:
        not_before = conditions.get("NotBefore")
        not_on_or_after = conditions.get("NotOnOrAfter")
        now = datetime.now(UTC)

        if not_before:
            nb = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
            if now < nb - timedelta(minutes=2):  # 2-minute clock skew tolerance
                raise ValueError("SAML assertion not yet valid")

        if not_on_or_after:
            noa = datetime.fromisoformat(not_on_or_after.replace("Z", "+00:00"))
            if now >= noa + timedelta(minutes=2):
                raise ValueError("SAML assertion expired")

        # H-7: Validate AudienceRestriction to prevent cross-service replay
        audience_restriction = conditions.find("saml:AudienceRestriction/saml:Audience", ns)
        if audience_restriction is not None and audience_restriction.text:
            if audience_restriction.text.strip() != config.sp_entity_id:
                raise ValueError("SAML assertion audience mismatch")

    # Extract NameID (subject)
    name_id = assertion.find(".//saml:NameID", ns)
    subject_id = name_id.text if name_id is not None else None

    if not subject_id:
        raise ValueError("No NameID in SAML assertion")

    # Extract attributes
    attrs: dict[str, list[str]] = {}
    for attr_stmt in assertion.findall("saml:AttributeStatement/saml:Attribute", ns):
        attr_name = attr_stmt.get("Name", "")
        values = [v.text for v in attr_stmt.findall("saml:AttributeValue", ns) if v.text]
        if attr_name and values:
            attrs[attr_name] = values

    # Map attributes using config.attribute_mapping
    mapping = config.attribute_mapping or {}
    email = subject_id  # Default: NameID is email
    if mapping.get("email"):
        email_vals = attrs.get(mapping["email"], [])
        if email_vals:
            email = email_vals[0]

    name = None
    if mapping.get("name"):
        name_vals = attrs.get(mapping["name"], [])
        if name_vals:
            name = name_vals[0]
    elif mapping.get("firstName") and mapping.get("lastName"):
        fn = attrs.get(mapping["firstName"], [""])[0]
        ln = attrs.get(mapping["lastName"], [""])[0]
        name = f"{fn} {ln}".strip() or None

    groups: list[str] = []
    if mapping.get("groups"):
        groups = attrs.get(mapping["groups"], [])

    return {
        "email": email.lower().strip(),
        "name": name,
        "groups": groups,
        "subject_id": subject_id,
    }

# ── OIDC ──────────────────────────────────────────────────────────────────────

def build_oidc_auth_url(config: SSOConfig) -> dict[str, str]:
    """
    Build OIDC authorization URL with PKCE.

    Returns {"redirect_url": "...", "state": "...", "nonce": "...", "code_verifier": "..."}
    """
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(64)

    # PKCE challenge (S256)
    code_challenge = hashlib.sha256(code_verifier.encode("ascii")).digest()
    import base64

    code_challenge_b64 = base64.urlsafe_b64encode(code_challenge).rstrip(b"=").decode("ascii")

    params = {
        "response_type": "code",
        "client_id": config.oidc_client_id,
        "redirect_uri": config.sp_acs_url or f"{settings.cors_origins[0]}/api/v1/sso/oidc/callback",
        "scope": config.oidc_scopes or "openid email profile",
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge_b64,
        "code_challenge_method": "S256",
    }

    auth_endpoint = f"{config.oidc_issuer}/authorize"
    redirect_url = f"{auth_endpoint}?{urlencode(params)}"

    return {
        "redirect_url": redirect_url,
        "state": state,
        "nonce": nonce,
        "code_verifier": code_verifier,
    }

async def exchange_oidc_code(
    config: SSOConfig,
    code: str,
    code_verifier: str,
    expected_nonce: str | None = None,
) -> dict[str, Any]:
    """
    Exchange OIDC authorization code for tokens and extract user claims.

    Returns: {"email": "...", "name": "...", "groups": [...], "subject_id": "..."}
    """
    token_endpoint = f"{config.oidc_issuer}/token"

    # M-1: Decrypt client_secret from storage
    from app.services.secret_encryption import decrypt_secret

    client_secret = await decrypt_secret(config.oidc_client_secret or "")

    async with httpx.AsyncClient(timeout=10.0) as client:
        # Token exchange
        token_response = await client.post(
            token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": config.sp_acs_url,
                "client_id": config.oidc_client_id,
                "client_secret": client_secret,
                "code_verifier": code_verifier,
            },
        )

        if token_response.status_code != 200:
            logger.error("oidc_token_exchange_failed", status=token_response.status_code)
            raise ValueError(f"OIDC token exchange failed: {token_response.status_code}")

        token_data = token_response.json()

    id_token = token_data.get("id_token")
    if not id_token:
        raise ValueError("No id_token in OIDC response")

    # ── Verify id_token signature via JWKS (C-1 hardening) ────────────
    try:
        jwks_client = pyjwt.PyJWKClient(
            f"{config.oidc_issuer}/.well-known/jwks.json",
            cache_keys=True,
            lifespan=3600,
        )
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)
        claims = pyjwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256", "ES256", "PS256"],
            audience=config.oidc_client_id,
            issuer=config.oidc_issuer,
        )
    except pyjwt.exceptions.PyJWTError as e:
        logger.error("oidc_id_token_verification_failed", error=str(e))
        raise ValueError(f"OIDC id_token verification failed: {e}")

    # H-2: Verify nonce to prevent id_token injection/replay
    if expected_nonce:
        token_nonce = claims.get("nonce")
        if token_nonce != expected_nonce:
            raise ValueError("OIDC nonce mismatch — possible replay attack")

    email = claims.get("email", "")
    name = claims.get("name") or claims.get("preferred_username")
    groups = claims.get("groups", [])
    subject_id = claims.get("sub", "")

    if not email:
        raise ValueError("No email claim in OIDC id_token")

    return {
        "email": email.lower().strip(),
        "name": name,
        "groups": groups,
        "subject_id": subject_id,
    }

# ── JIT Provisioning ─────────────────────────────────────────────────────────

async def jit_provision_or_link(
    db: AsyncSession,
    config: SSOConfig,
    user_attrs: dict[str, Any],
    provider_type: str,
) -> tuple[User, bool]:
    """
    Just-In-Time provisioning: find existing user or create new one.

    Returns (user, is_new_user).
    """
    email = user_attrs["email"]

    # Try to find existing user
    result = await db.execute(
        select(User).where(
            User.tenant_id == config.tenant_id,
            User.email == email,
        )
    )
    user = result.scalar_one_or_none()

    if user:
        # Link SSO identity if not already linked
        if not user.sso_provider:
            user.sso_provider = provider_type
            user.sso_subject_id = user_attrs.get("subject_id")
        user.last_login = datetime.now(UTC)
        await db.flush()
        return user, False

    if not config.jit_provisioning:
        raise ValueError("User not found and JIT provisioning is disabled")

    # Determine role from group mapping
    role = config.default_role
    group_role_map = config.attribute_mapping.get("group_role_map", {})
    for group in user_attrs.get("groups", []):
        if group in group_role_map:
            role = group_role_map[group]
            break

    # Create new user
    user = User(
        tenant_id=config.tenant_id,
        email=email,
        password_hash=hash_password(secrets.token_urlsafe(32)),  # Random password (SSO-only)
        role=role,
        name=user_attrs.get("name"),
        sso_provider=provider_type,
        sso_subject_id=user_attrs.get("subject_id"),
        is_active=True,
    )
    db.add(user)
    await db.flush()

    logger.info(
        "sso_user_provisioned",
        user_id=str(user.id),
        email=email,
        provider=provider_type,
        tenant_id=str(config.tenant_id),
    )
    return user, True
