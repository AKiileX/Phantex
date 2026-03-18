# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex Copilot — Configuration API Router.

Admin-only endpoints for managing Copilot LLM provider settings.

Routes:
  GET    /api/v1/settings/copilot              — Get current config (masked key)
  PUT    /api/v1/settings/copilot              — Update config
  POST   /api/v1/settings/copilot/test         — Test connection + auto-detect
  GET    /api/v1/settings/copilot/models       — List available models on endpoint

Security:
  - Admin-only (auth.manage permission)
  - API keys encrypted at rest with Fernet (derived from JWT secret)
  - Data policy enforcement: local_only blocks non-private endpoints
  - Audit logging on all configuration changes
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import socket
from typing import Annotated
from urllib.parse import urlparse

import httpx
import structlog
from cryptography.fernet import Fernet
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.middleware.abac import require_permission
from app.middleware.auth import get_current_active_user
from app.middleware.tenant import enforce_tenant_isolation
from app.schemas.auth import CurrentUser

logger = structlog.get_logger("phantex.copilot.config")
settings = get_settings()

# ── Router ────────────────────────────────────────────────────────────────────

router = APIRouter(
    prefix="/api/v1/settings/copilot",
    tags=["copilot-settings"],
    dependencies=[
        Depends(require_permission("auth.manage")),
    ],
)

# ── Encryption helpers ────────────────────────────────────────────────────────

def _get_fernet() -> Fernet:
    """Derive a Fernet key from the JWT secret (deterministic)."""
    jwt_secret = getattr(settings, "jwt_secret", "") or "phantex-dev-jwt-secret"
    key_material = hashlib.sha256(jwt_secret.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(key_material)
    return Fernet(fernet_key)

def _encrypt_key(plain: str) -> str:
    """Encrypt an API key."""
    if not plain:
        return ""
    return _get_fernet().encrypt(plain.encode()).decode()

def _decrypt_key(cipher: str) -> str:
    """Decrypt an API key."""
    if not cipher:
        return ""
    try:
        return _get_fernet().decrypt(cipher.encode()).decode()
    except Exception:
        return ""

def _mask_key(plain: str) -> str:
    """Mask an API key for display: sk-abc...xyz"""
    if not plain or len(plain) < 8:
        return "***" if plain else ""
    return f"{plain[:6]}...{plain[-4:]}"

# ── Network helpers ───────────────────────────────────────────────────────────

# Cloud metadata IPs that must NEVER be accessed via SSRF
_BLOCKED_HOSTS = {
    "169.254.169.254",  # AWS/GCP IMDS
    "metadata.google.internal",
    "metadata.gke.internal",
    "100.100.100.200",  # Alibaba metadata
}

_ALLOWED_LLM_PATHS = {"/v1", "/v1/", "/api", "/api/"}

def _validate_base_url(url: str) -> tuple[bool, str]:
    """Validate that a base_url is safe (no SSRF, valid scheme, no credentials)."""
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL format"

    # Scheme check
    if parsed.scheme not in ("http", "https"):
        return False, f"Invalid scheme '{parsed.scheme}' — only http/https allowed"

    # No credentials in URL
    if parsed.username or parsed.password:
        return False, "URL must not contain credentials"

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return False, "URL must have a hostname"

    # Block cloud metadata endpoints
    if hostname in _BLOCKED_HOSTS:
        return False, f"Blocked endpoint: {hostname} (cloud metadata)"

    # local range (169.254.x.x / fe80::)
    try:
        addr = ipaddress.ip_address(hostname)
        if addr.is_link_local:
            return False, f"Link-local addresses are blocked: {hostname}"
    except ValueError:
        pass

    # DNS resolution check for cloud metadata
    try:
        resolved = socket.gethostbyname(hostname)
        if resolved in _BLOCKED_HOSTS:
            return False, f"Hostname resolves to blocked metadata IP: {resolved}"
        resolved_addr = ipaddress.ip_address(resolved)
        if resolved_addr.is_link_local:
            return False, f"Hostname resolves to link-local address: {resolved}"
    except (socket.gaierror, ValueError):
        pass

    # Warn if query params present (may contain keys)
    if parsed.query:
        logger.warning("copilot_config_url_has_query_params: %s", hostname)

    return True, ""

def _is_private_endpoint(url: str) -> bool:
    """Check if a URL points to a private/local endpoint (safe for local_only policy)."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        # Localhost variants
        if hostname in ("localhost", "127.0.0.1", "::1", "host.docker.internal"):
            return True

        # Docker internal hostnames
        if hostname.startswith("phantex-") or hostname.endswith(".internal"):
            return True

        # Try to resolve and check RFC1918
        try:
            addr = ipaddress.ip_address(hostname)
            return addr.is_private or addr.is_loopback or addr.is_link_local
        except ValueError:
            pass

        # Try DNS resolution
        try:
            resolved = socket.gethostbyname(hostname)
            addr = ipaddress.ip_address(resolved)
            return addr.is_private or addr.is_loopback or addr.is_link_local
        except (socket.gaierror, ValueError):
            pass

        return False
    except Exception:
        return False

# ── Request / Response schemas ────────────────────────────────────────────────

class CopilotConfigResponse(BaseModel):
    """Current copilot configuration (safe for frontend — masked API key)."""

    provider: str
    base_url: str
    model: str
    api_key_masked: str  # e.g. "sk-abc...xyz" or ""
    has_api_key: bool
    max_tokens: int
    temperature: float
    data_policy: str  # "local_only" | "allow_cloud"
    enabled: bool
    # Computed fields
    endpoint_type: str  # "private" | "public" | "unknown"
    updated_at: str | None

class CopilotConfigUpdate(BaseModel):
    """Update copilot configuration."""

    provider: str = Field("local", pattern=r"^(local|openai|anthropic|custom)$")
    base_url: str = Field("http://host.docker.internal:1234/v1", max_length=512)
    model: str = Field("mistral", max_length=128)
    api_key: str | None = Field(None, max_length=512, description="API key — omit to keep current")
    max_tokens: int = Field(4096, ge=256, le=32768)
    temperature: float = Field(0.3, ge=0.0, le=2.0)
    data_policy: str = Field("local_only", pattern=r"^(local_only|allow_cloud)$")
    enabled: bool = Field(True)

class TestConnectionRequest(BaseModel):
    """Test an LLM endpoint."""

    base_url: str = Field(..., max_length=512)
    api_key: str | None = Field(None, max_length=512)
    model: str | None = Field(None, max_length=128)

class TestConnectionResponse(BaseModel):
    """Connection test results."""

    reachable: bool
    detected_server: str  # "lm_studio" | "ollama" | "vllm" | "openai" | "anthropic" | "unknown"
    available_models: list[str]
    endpoint_type: str  # "private" | "public"
    latency_ms: float
    error: str | None = None
    server_version: str | None = None

# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("", response_model=CopilotConfigResponse, summary="Get copilot configuration")
async def get_copilot_config(
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Get current copilot LLM configuration for the tenant."""
    tenant_id = str(current_user.tenant_id)

    query = text(
        "SELECT provider, base_url, model, api_key_enc, max_tokens, temperature, "
        "data_policy, enabled, updated_at "
        "FROM copilot_config WHERE tenant_id = :tid"
    )
    result = await db.execute(query, {"tid": tenant_id})
    row = result.mappings().first()

    if not row:
        # Return defaults if no config exists yet
        return CopilotConfigResponse(
            provider="local",
            base_url="http://host.docker.internal:1234/v1",
            model="mistral",
            api_key_masked="",
            has_api_key=False,
            max_tokens=4096,
            temperature=0.3,
            data_policy="local_only",
            enabled=True,
            endpoint_type="private",
            updated_at=None,
        )

    api_key_plain = _decrypt_key(row["api_key_enc"] or "")

    return CopilotConfigResponse(
        provider=row["provider"],
        base_url=row["base_url"],
        model=row["model"],
        api_key_masked=_mask_key(api_key_plain),
        has_api_key=bool(api_key_plain),
        max_tokens=row["max_tokens"],
        temperature=row["temperature"],
        data_policy=row["data_policy"],
        enabled=row["enabled"],
        endpoint_type="private" if _is_private_endpoint(row["base_url"]) else "public",
        updated_at=str(row["updated_at"]) if row["updated_at"] else None,
    )

@router.put("", response_model=CopilotConfigResponse, summary="Update copilot configuration")
async def update_copilot_config(
    req: CopilotConfigUpdate,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Update copilot LLM configuration for the tenant."""
    tenant_id = str(current_user.tenant_id)
    user_id = str(current_user.user_id)

    # SSRF validation: block dangerous URLs
    url_ok, url_err = _validate_base_url(req.base_url)
    if not url_ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid base URL: {url_err}",
        )

    # Data policy enforcement: block public endpoints if local_only
    if req.data_policy == "local_only" and not _is_private_endpoint(req.base_url):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Data policy is set to 'local_only' but the endpoint URL resolves to a "
                "public address. Either change the URL to a private/localhost endpoint, "
                "or set data_policy to 'allow_cloud' to permit external LLM providers."
            ),
        )

    # Encrypt API key if provided, otherwise keep existing
    api_key_enc = None
    if req.api_key is not None:
        api_key_enc = _encrypt_key(req.api_key) if req.api_key else ""

    # Upsert
    if api_key_enc is not None:
        query = text("""
            INSERT INTO copilot_config (tenant_id, provider, base_url, model, api_key_enc,
                                        max_tokens, temperature, data_policy, enabled, updated_by)
            VALUES (:tid, :provider, :base_url, :model, :api_key_enc,
                    :max_tokens, :temp, :data_policy, :enabled, :uid)
            ON CONFLICT (tenant_id) DO UPDATE SET
                provider = EXCLUDED.provider,
                base_url = EXCLUDED.base_url,
                model = EXCLUDED.model,
                api_key_enc = EXCLUDED.api_key_enc,
                max_tokens = EXCLUDED.max_tokens,
                temperature = EXCLUDED.temperature,
                data_policy = EXCLUDED.data_policy,
                enabled = EXCLUDED.enabled,
                updated_by = EXCLUDED.updated_by
        """)
        await db.execute(
            query,
            {
                "tid": tenant_id,
                "provider": req.provider,
                "base_url": req.base_url,
                "model": req.model,
                "api_key_enc": api_key_enc,
                "max_tokens": req.max_tokens,
                "temp": req.temperature,
                "data_policy": req.data_policy,
                "enabled": req.enabled,
                "uid": user_id,
            },
        )
    else:
        # Don't overwrite API key
        query = text("""
            INSERT INTO copilot_config (tenant_id, provider, base_url, model,
                                        max_tokens, temperature, data_policy, enabled, updated_by)
            VALUES (:tid, :provider, :base_url, :model,
                    :max_tokens, :temp, :data_policy, :enabled, :uid)
            ON CONFLICT (tenant_id) DO UPDATE SET
                provider = EXCLUDED.provider,
                base_url = EXCLUDED.base_url,
                model = EXCLUDED.model,
                max_tokens = EXCLUDED.max_tokens,
                temperature = EXCLUDED.temperature,
                data_policy = EXCLUDED.data_policy,
                enabled = EXCLUDED.enabled,
                updated_by = EXCLUDED.updated_by
        """)
        await db.execute(
            query,
            {
                "tid": tenant_id,
                "provider": req.provider,
                "base_url": req.base_url,
                "model": req.model,
                "max_tokens": req.max_tokens,
                "temp": req.temperature,
                "data_policy": req.data_policy,
                "enabled": req.enabled,
                "uid": user_id,
            },
        )

    await db.commit()

    logger.info(
        "copilot_config_updated",
        tenant_id=tenant_id,
        user_id=user_id,
        provider=req.provider,
        model=req.model,
        data_policy=req.data_policy,
    )

    # Invalidate cached LLM provider for this tenant
    _invalidate_llm_cache(tenant_id)

    return await get_copilot_config(db, current_user)

@router.post("/test", response_model=TestConnectionResponse, summary="Test LLM endpoint")
async def test_connection(
    req: TestConnectionRequest,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """
    Probe an LLM endpoint to check connectivity and auto-detect the server type.
    Returns available models, server type, and latency.
    """
    import time

    base_url = req.base_url.rstrip("/")

    # SSRF validation
    url_ok, url_err = _validate_base_url(base_url)
    if not url_ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid URL: {url_err}",
        )

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if req.api_key:
        headers["Authorization"] = f"Bearer {req.api_key}"

    endpoint_type = "private" if _is_private_endpoint(base_url) else "public"

    async with httpx.AsyncClient(timeout=10) as client:
        t0 = time.monotonic()

        # ── Try OpenAI-compatible /models endpoint ────────────────
        detected = "unknown"
        models: list[str] = []
        server_version: str | None = None
        error: str | None = None

        try:
            resp = await client.get(f"{base_url}/models", headers=headers)
            latency = round((time.monotonic() - t0) * 1000, 1)

            if resp.status_code == 200:
                data = resp.json()
                models = [m.get("id", "") for m in data.get("data", [])][:50]

                # Auto-detect from headers and response shape
                server_header = resp.headers.get("server", "").lower()
                powered_by = resp.headers.get("x-powered-by", "").lower()

                if "lm studio" in server_header or "lm-studio" in server_header or "lmstudio" in powered_by:
                    detected = "lm_studio"
                elif "ollama" in server_header or "ollama" in powered_by:
                    detected = "ollama"
                elif "vllm" in server_header or "vllm" in powered_by:
                    detected = "vllm"
                elif "openai" in str(resp.headers) or "api.openai.com" in base_url:
                    detected = "openai"
                elif "anthropic" in str(resp.headers) or "anthropic.com" in base_url:
                    detected = "anthropic"
                elif "text-generation" in server_header:
                    detected = "text_generation_webui"
                elif "localai" in server_header:
                    detected = "localai"
                else:
                    # Check response shape for clues
                    if any("gpt-" in m for m in models):
                        detected = "openai"
                    elif resp.headers.get("x-request-id"):
                        detected = "openai_compatible"
                    else:
                        detected = "openai_compatible"

                return TestConnectionResponse(
                    reachable=True,
                    detected_server=detected,
                    available_models=models,
                    endpoint_type=endpoint_type,
                    latency_ms=latency,
                    server_version=server_version,
                )
            else:
                error = f"HTTP {resp.status_code}"

        except httpx.ConnectError as exc:
            latency = round((time.monotonic() - t0) * 1000, 1)
            error = f"Connection refused — is the LLM server running? ({str(exc)[:100]})"
        except httpx.TimeoutException:
            latency = round((time.monotonic() - t0) * 1000, 1)
            error = "Connection timed out (>10s)"
        except Exception as exc:
            latency = round((time.monotonic() - t0) * 1000, 1)
            error = str(exc)[:200]

        # ── Fallback: try Ollama native /api/tags ─────────────────
        if error:
            ollama_base = base_url.replace("/v1", "")
            try:
                t1 = time.monotonic()
                resp2 = await client.get(f"{ollama_base}/api/tags", timeout=5)
                if resp2.status_code == 200:
                    tags = resp2.json()
                    models = [m.get("name", "") for m in tags.get("models", [])][:50]
                    return TestConnectionResponse(
                        reachable=True,
                        detected_server="ollama",
                        available_models=models,
                        endpoint_type=endpoint_type,
                        latency_ms=round((time.monotonic() - t1) * 1000, 1),
                    )
            except Exception:
                pass

        # ── Fallback: try Anthropic messages endpoint ─────────────
        if error and req.api_key and "anthropic" in base_url:
            try:
                t1 = time.monotonic()
                resp3 = await client.get(
                    f"{base_url}/v1/messages",
                    headers={"x-api-key": req.api_key, "anthropic-version": "2023-06-01"},
                    timeout=5,
                )
                # 405 = alive
                if resp3.status_code in (200, 405):
                    return TestConnectionResponse(
                        reachable=True,
                        detected_server="anthropic",
                        available_models=["claude-3-5-sonnet-20241022", "claude-3-haiku-20240307"],
                        endpoint_type=endpoint_type,
                        latency_ms=round((time.monotonic() - t1) * 1000, 1),
                    )
            except Exception:
                pass

        return TestConnectionResponse(
            reachable=False,
            detected_server="unknown",
            available_models=[],
            endpoint_type=endpoint_type,
            latency_ms=latency,
            error=error,
        )

@router.get("/models", summary="List available models")
async def list_models(
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Fetch available models from the currently configured LLM endpoint."""
    tenant_id = str(current_user.tenant_id)

    query = text("SELECT base_url, api_key_enc FROM copilot_config WHERE tenant_id = :tid")
    result = await db.execute(query, {"tid": tenant_id})
    row = result.mappings().first()

    base_url = row["base_url"] if row else "http://host.docker.internal:1234/v1"
    api_key = _decrypt_key(row["api_key_enc"] or "") if row else ""

    headers: dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.get(f"{base_url.rstrip('/')}/models", headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                models = [m.get("id", "") for m in data.get("data", [])][:50]
                return {"models": models}
        except Exception:
            pass

        # Ollama fallback
        ollama_base = base_url.replace("/v1", "")
        try:
            resp2 = await client.get(f"{ollama_base}/api/tags", timeout=5)
            if resp2.status_code == 200:
                tags = resp2.json()
                return {"models": [m.get("name", "") for m in tags.get("models", [])][:50]}
        except Exception:
            pass

    return {"models": [], "error": "Could not fetch models from endpoint"}

# ── Cache invalidation ────────────────────────────────────────────────────────

def _invalidate_llm_cache(tenant_id: str) -> None:
    """Invalidate the per-tenant LLM cache so next request reloads config from DB."""
    from app.routers.copilot import invalidate_tenant_cache

    invalidate_tenant_cache(tenant_id)
