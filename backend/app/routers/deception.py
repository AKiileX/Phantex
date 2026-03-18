# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Deception Technology Router

CRUD endpoints for deception assets:
  - /api/v1/deception/decoys          — Decoy agent management
  - /api/v1/deception/canary-mcp      — Canary MCP server management
  - /api/v1/deception/canary-tokens   — Canary token management
  - /api/v1/deception/events          — Honeypot event log (read-only)
  - /api/v1/deception/stats           — Aggregated stats for dashboard

Security:
  - All endpoints require authentication (get_current_active_user)
  - Deception management requires 'deception.manage' permission
  - Event reading requires 'deception.read' permission
  - Tenant isolation via RLS on all queries
  - Input validation via Pydantic schemas
  - Rate limiting via standard middleware
"""

from __future__ import annotations

import re
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field, field_validator

from app.database import get_raw_db
from app.middleware.abac import require_permission
from app.middleware.auth import get_current_active_user
from app.middleware.rate_limit import rate_limit
from app.services.deception import (
    create_canary_mcp_server,
    create_canary_token,
    create_decoy_agent,
    delete_canary_mcp_server,
    delete_canary_token,
    delete_decoy_agent,
    get_deception_stats,
    list_canary_mcp_servers,
    list_canary_tokens,
    list_decoy_agents,
    list_honeypot_events,
    record_honeypot_event,
    toggle_canary_mcp_server,
    toggle_canary_token,
    toggle_decoy_agent,
)
from app.utils.logging import get_logger

logger = get_logger("phantex.router.deception")

router = APIRouter(
    prefix="/api/v1/deception",
    tags=["deception"],
    dependencies=[Depends(rate_limit)],
)

# ── Pydantic Schemas ──────────────────────────────────────────────────────────

# --- Decoy Agents ---

_VALID_FRAMEWORKS = {"langchain", "autogen", "crewai", "openai", "anthropic", "custom"}

class DecoyAgentCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str | None = Field(None, max_length=1000)
    framework: str = Field("langchain", max_length=64)
    framework_ver: str = Field("0.1.0", max_length=32)
    decoy_profile: dict[str, Any] = Field(default_factory=dict)
    network_config: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True

    @field_validator("framework")
    @classmethod
    def validate_framework(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in _VALID_FRAMEWORKS:
            raise ValueError(f"Framework must be one of: {', '.join(sorted(_VALID_FRAMEWORKS))}")
        return v

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        v = v.strip()
        if not re.match(r"^[\w\s\-\.]+$", v):
            raise ValueError("Name must contain only letters, numbers, spaces, hyphens, dots, and underscores")
        return v

class DecoyAgentToggle(BaseModel):
    enabled: bool

# --- Canary MCP Servers ---

_VALID_PROTOCOLS = {"sse", "stdio", "streamable-http"}

class CanaryMCPCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str | None = Field(None, max_length=1000)
    server_url: str = Field(..., min_length=1, max_length=512)
    advertised_tools: list[dict[str, Any]] = Field(default_factory=list)
    protocol: str = Field("sse", max_length=16)
    tls_enabled: bool = True
    rotate_identity: bool = False
    rotation_interval_hours: int = Field(168, ge=1, le=8760)
    enabled: bool = True

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in _VALID_PROTOCOLS:
            raise ValueError(f"Protocol must be one of: {', '.join(sorted(_VALID_PROTOCOLS))}")
        return v

    @field_validator("server_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("https://", "http://", "mcp://")):
            raise ValueError("URL must start with https://, http://, or mcp://")
        return v

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        v = v.strip()
        if not re.match(r"^[\w\s\-\.]+$", v):
            raise ValueError("Name must contain only letters, numbers, spaces, hyphens, dots, and underscores")
        return v

    @field_validator("advertised_tools")
    @classmethod
    def validate_tools(cls, v: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if len(v) > 50:
            raise ValueError("Maximum 50 advertised tools allowed")
        for i, tool in enumerate(v):
            if "name" not in tool:
                raise ValueError(f"Tool {i}: 'name' field required")
            if len(str(tool.get("name", ""))) > 128:
                raise ValueError(f"Tool {i}: name too long (max 128 chars)")
        return v

class CanaryMCPToggle(BaseModel):
    enabled: bool

# --- Canary Tokens ---

_VALID_TOKEN_TYPES = {"api_key", "credential", "pii", "dns", "url"}

class CanaryTokenCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str | None = Field(None, max_length=1000)
    token_type: str = Field(..., max_length=32)
    placement: dict[str, Any] = Field(default_factory=dict)
    alert_on_read: bool = False
    alert_on_use: bool = True
    enabled: bool = True

    @field_validator("token_type")
    @classmethod
    def validate_token_type(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in _VALID_TOKEN_TYPES:
            raise ValueError(f"Token type must be one of: {', '.join(sorted(_VALID_TOKEN_TYPES))}")
        return v

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        v = v.strip()
        if not re.match(r"^[\w\s\-\.]+$", v):
            raise ValueError("Name must contain only letters, numbers, spaces, hyphens, dots, and underscores")
        return v

class CanaryTokenToggle(BaseModel):
    enabled: bool

# --- Honeypot Event (for manual reporting / testing) ---

class HoneypotEventCreate(BaseModel):
    source_type: str = Field(..., pattern=r"^(decoy_agent|canary_mcp|canary_token)$")
    source_id: str = Field(..., min_length=1, max_length=64)
    source_name: str = Field(..., min_length=1, max_length=200)
    interaction_type: str = Field(..., min_length=1, max_length=64)
    interaction_data: dict[str, Any] = Field(default_factory=dict)
    agent_id: str | None = None
    agent_paid: str | None = None
    source_ip: str | None = None
    severity: str = Field("critical", pattern=r"^(critical|high|medium|low|info)$")
    attack_class: str | None = Field(None, max_length=64)
    mitre_tactic: str | None = Field(None, max_length=64)
    mitre_technique: str | None = Field(None, max_length=64)

# ── Decoy Agent Endpoints ────────────────────────────────────────────────────

@router.get("/decoys", dependencies=[Depends(require_permission("deception.read"))])
async def get_decoy_agents(
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """List all decoy agents for the current tenant."""
    decoys = await list_decoy_agents(db, user.tenant_id)
    return {"decoys": decoys, "total": len(decoys)}

@router.post("/decoys", status_code=201, dependencies=[Depends(require_permission("deception.manage"))])
async def create_decoy(
    body: DecoyAgentCreate,
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Create a new decoy agent with cryptographic identity."""
    try:
        decoy = await create_decoy_agent(
            db,
            tenant_id=user.tenant_id,
            created_by=str(user.user_id),
            name=body.name,
            description=body.description,
            framework=body.framework,
            framework_ver=body.framework_ver,
            decoy_profile=body.decoy_profile,
            network_config=body.network_config,
            enabled=body.enabled,
        )
        return decoy
    except Exception as e:
        if "unique" in str(e).lower() or "duplicate" in str(e).lower():
            raise HTTPException(status_code=409, detail="A decoy with that name already exists")
        logger.error("decoy_create_failed", error=str(e))
        raise HTTPException(status_code=400, detail=str(e))

@router.patch("/decoys/{decoy_id}", dependencies=[Depends(require_permission("deception.manage"))])
async def update_decoy_status(
    body: DecoyAgentToggle,
    decoy_id: Annotated[str, Path()],
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Enable or disable a decoy agent."""
    result = await toggle_decoy_agent(db, user.tenant_id, decoy_id, body.enabled)
    if not result:
        raise HTTPException(status_code=404, detail="Decoy agent not found")
    return result

@router.delete("/decoys/{decoy_id}", status_code=204, dependencies=[Depends(require_permission("deception.manage"))])
async def remove_decoy(
    decoy_id: Annotated[str, Path()],
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Delete a decoy agent."""
    deleted = await delete_decoy_agent(db, user.tenant_id, decoy_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Decoy agent not found")

# ── Canary MCP Server Endpoints ──────────────────────────────────────────────

@router.get("/canary-mcp", dependencies=[Depends(require_permission("deception.read"))])
async def get_canary_mcp_servers(
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """List all canary MCP servers for the current tenant."""
    servers = await list_canary_mcp_servers(db, user.tenant_id)
    return {"canary_mcp_servers": servers, "total": len(servers)}

@router.post("/canary-mcp", status_code=201, dependencies=[Depends(require_permission("deception.manage"))])
async def create_canary_mcp(
    body: CanaryMCPCreate,
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Create a new canary MCP server."""
    try:
        server = await create_canary_mcp_server(
            db,
            tenant_id=user.tenant_id,
            created_by=str(user.user_id),
            name=body.name,
            description=body.description,
            server_url=body.server_url,
            advertised_tools=body.advertised_tools,
            protocol=body.protocol,
            tls_enabled=body.tls_enabled,
            rotate_identity=body.rotate_identity,
            rotation_interval_hours=body.rotation_interval_hours,
            enabled=body.enabled,
        )
        return server
    except Exception as e:
        if "unique" in str(e).lower() or "duplicate" in str(e).lower():
            raise HTTPException(status_code=409, detail="A canary MCP server with that name already exists")
        logger.error("canary_mcp_create_failed", error=str(e))
        raise HTTPException(status_code=400, detail=str(e))

@router.patch("/canary-mcp/{canary_id}", dependencies=[Depends(require_permission("deception.manage"))])
async def update_canary_mcp_status(
    body: CanaryMCPToggle,
    canary_id: Annotated[str, Path()],
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Enable or disable a canary MCP server."""
    result = await toggle_canary_mcp_server(db, user.tenant_id, canary_id, body.enabled)
    if not result:
        raise HTTPException(status_code=404, detail="Canary MCP server not found")
    return result

@router.delete(
    "/canary-mcp/{canary_id}", status_code=204, dependencies=[Depends(require_permission("deception.manage"))]
)
async def remove_canary_mcp(
    canary_id: Annotated[str, Path()],
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Delete a canary MCP server."""
    deleted = await delete_canary_mcp_server(db, user.tenant_id, canary_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Canary MCP server not found")

# ── Canary Token Endpoints ────────────────────────────────────────────────────

@router.get("/canary-tokens", dependencies=[Depends(require_permission("deception.read"))])
async def get_canary_tokens(
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """List all canary tokens for the current tenant (values never returned)."""
    tokens = await list_canary_tokens(db, user.tenant_id)
    return {"canary_tokens": tokens, "total": len(tokens)}

@router.post("/canary-tokens", status_code=201, dependencies=[Depends(require_permission("deception.manage"))])
async def create_token(
    body: CanaryTokenCreate,
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """
    Create a new canary token.

    The raw_value is returned ONCE in the response — copy it now.
    It is stored as a SHA-256 hash and cannot be retrieved later.
    """
    try:
        token = await create_canary_token(
            db,
            tenant_id=user.tenant_id,
            created_by=str(user.user_id),
            name=body.name,
            description=body.description,
            token_type=body.token_type,
            placement=body.placement,
            alert_on_read=body.alert_on_read,
            alert_on_use=body.alert_on_use,
            enabled=body.enabled,
        )
        return token
    except Exception as e:
        if "unique" in str(e).lower() or "duplicate" in str(e).lower():
            raise HTTPException(status_code=409, detail="A canary token with that name already exists")
        logger.error("canary_token_create_failed", error=str(e))
        raise HTTPException(status_code=400, detail=str(e))

@router.patch("/canary-tokens/{token_id}", dependencies=[Depends(require_permission("deception.manage"))])
async def update_token_status(
    body: CanaryTokenToggle,
    token_id: Annotated[str, Path()],
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Enable or disable a canary token."""
    result = await toggle_canary_token(db, user.tenant_id, token_id, body.enabled)
    if not result:
        raise HTTPException(status_code=404, detail="Canary token not found")
    return result

@router.delete(
    "/canary-tokens/{token_id}", status_code=204, dependencies=[Depends(require_permission("deception.manage"))]
)
async def remove_token(
    token_id: Annotated[str, Path()],
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Delete a canary token."""
    deleted = await delete_canary_token(db, user.tenant_id, token_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Canary token not found")

# ── Honeypot Event Endpoints ─────────────────────────────────────────────────

@router.get("/events", dependencies=[Depends(require_permission("deception.read"))])
async def get_events(
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    source_type: str | None = Query(None, pattern=r"^(decoy_agent|canary_mcp|canary_token)$"),
    severity: str | None = Query(None, pattern=r"^(critical|high|medium|low|info)$"),
):
    """List honeypot events with pagination and optional filters."""
    events, total = await list_honeypot_events(
        db,
        user.tenant_id,
        limit=limit,
        offset=offset,
        source_type=source_type,
        severity=severity,
    )
    return {"events": events, "total": total, "limit": limit, "offset": offset}

@router.post("/events", status_code=201, dependencies=[Depends(require_permission("deception.deploy"))])
async def create_event(
    body: HoneypotEventCreate,
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """
    Record a honeypot event (for testing or manual reporting).

    In production, events are recorded automatically when deception assets
    detect interaction. This endpoint is for testing / manual use.
    """
    event = await record_honeypot_event(
        db,
        tenant_id=user.tenant_id,
        source_type=body.source_type,
        source_id=body.source_id,
        source_name=body.source_name,
        interaction_type=body.interaction_type,
        interaction_data=body.interaction_data,
        agent_id=body.agent_id,
        agent_paid=body.agent_paid,
        source_ip=body.source_ip,
        severity=body.severity,
        attack_class=body.attack_class,
        mitre_tactic=body.mitre_tactic,
        mitre_technique=body.mitre_technique,
    )
    return event

# ── Stats Endpoint ────────────────────────────────────────────────────────────

@router.get("/stats", dependencies=[Depends(require_permission("deception.read"))])
async def get_stats(
    user=Depends(get_current_active_user),
    db=Depends(get_raw_db),
):
    """Get aggregated deception statistics for the dashboard."""
    stats = await get_deception_stats(db, user.tenant_id)
    return stats

# ── Token Types + Source Types (reference data) ──────────────────────────────

@router.get("/token-types")
async def get_token_types():
    """List available canary token types."""
    return {
        "token_types": [
            {"type": "api_key", "label": "Fake API Key", "description": "Planted API key that triggers on use"},
            {
                "type": "credential",
                "label": "Fake Credential",
                "description": "Planted password/secret that triggers on authentication",
            },
            {
                "type": "pii",
                "label": "Fake PII",
                "description": "Planted PII record (SSN, email, etc.) that triggers on exfiltration",
            },
            {"type": "dns", "label": "Canary DNS", "description": "Unique DNS name that triggers when resolved"},
            {"type": "url", "label": "Canary URL", "description": "Unique URL that triggers when fetched"},
        ]
    }

@router.get("/frameworks")
async def get_frameworks():
    """List available decoy agent frameworks."""
    return {
        "frameworks": [
            {"name": "langchain", "label": "LangChain"},
            {"name": "autogen", "label": "AutoGen"},
            {"name": "crewai", "label": "CrewAI"},
            {"name": "openai", "label": "OpenAI Agents"},
            {"name": "anthropic", "label": "Anthropic"},
            {"name": "custom", "label": "Custom Framework"},
        ]
    }
