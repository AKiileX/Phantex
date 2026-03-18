# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex Copilot — API Router.

REST + WebSocket endpoints for the AI-assisted security operations copilot.

Routes:
  POST   /api/v1/copilot/chat           — Send a message (non-streaming, tool calling)
  POST   /api/v1/copilot/triage         — Batch triage alerts
  POST   /api/v1/copilot/suggest-rule   — Generate PRL rule from NL description
  POST   /api/v1/copilot/refine-rule    — Refine an existing PRL rule
  GET    /api/v1/copilot/health         — LLM provider health check
  POST   /api/v1/copilot/ws/ticket      — WebSocket ticket for streaming chat
  WS     /ws/copilot                     — Streaming chat WebSocket

Security:
  - Admin + Analyst only (copilot.use permission)
  - Content firewall on all input/output
  - Rate-limited (10 req/min for chat, 5/min for triage)
  - Tenant-scoped data access via RLS
  - Audit logging on all interactions
"""

from __future__ import annotations

from typing import Annotated, Any

import httpx
import structlog
from fastapi import APIRouter, Depends, HTTPException, Path, Query, WebSocket, status
from pydantic import BaseModel, Field
from sqlalchemy import text as sa_text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.middleware.abac import require_permission
from app.middleware.auth import get_current_active_user
from app.middleware.rate_limit import _rate_limiter, _redis_rate_limiter, rate_limit
from app.middleware.tenant import enforce_tenant_isolation
from app.schemas.auth import CurrentUser
from app.services.copilot.briefing import ThreatBriefingService
from app.services.copilot.firewall import CopilotFirewall
from app.services.copilot.investigator import InvestigationAssistant
from app.services.copilot.llm_provider import LLMConfig, LLMProvider
from app.services.copilot.memory import CopilotMemory
from app.services.copilot.playbooks import PlaybookService
from app.services.copilot.rule_generator import RuleSuggestionEngine
from app.services.copilot.triage import AlertTriageAssistant
from app.services.ws_ticket import WSTicketStore

logger = structlog.get_logger("phantex.copilot.router")
settings = get_settings()

# ── Router ────────────────────────────────────────────────────────────────────

router = APIRouter(
    prefix="/api/v1/copilot",
    tags=["copilot"],
    dependencies=[
        Depends(rate_limit),
        Depends(require_permission("copilot.use")),
    ],
)

# ── Per-tenant LLM cache (DB config → env var fallback) ──────────────────────

import contextlib
import time as _time

from app.routers.copilot_config import _decrypt_key

_firewall: CopilotFirewall | None = None
_memory: CopilotMemory | None = None
_ticket_store = WSTicketStore()

# Per-tenant cache: tenant_id → (config_key, LLMProvider, services, timestamp)
_tenant_cache: dict[
    str,
    tuple[
        str,
        LLMProvider,
        InvestigationAssistant,
        AlertTriageAssistant,
        RuleSuggestionEngine,
        ThreatBriefingService,
        PlaybookService,
        float,
    ],
] = {}
_CACHE_TTL = 300  # seconds — re-check DB every 5 min

def _get_firewall() -> CopilotFirewall:
    global _firewall
    if _firewall is None:
        _firewall = CopilotFirewall()
    return _firewall

def _get_memory() -> CopilotMemory:
    global _memory
    if _memory is None:
        # Memory uses env-based LLM as fallback (just for title summarisation)
        _memory = CopilotMemory(llm=LLMProvider(LLMConfig.from_env()))
    return _memory

async def _load_llm_config(db: AsyncSession, tenant_id: str) -> LLMConfig:
    """Load LLM config from DB for the tenant, falling back to env vars."""
    try:
        result = await db.execute(
            sa_text(
                "SELECT provider, base_url, model, api_key_enc, max_tokens, temperature, enabled "
                "FROM copilot_config WHERE tenant_id = :tid"
            ),
            {"tid": tenant_id},
        )
        row = result.mappings().first()
    except Exception:
        row = None

    if not row:
        return LLMConfig.from_env()

    api_key_plain = _decrypt_key(row["api_key_enc"] or "")
    return LLMConfig.from_db_row(
        {
            "provider": row["provider"],
            "base_url": row["base_url"],
            "model": row["model"],
            "api_key_plain": api_key_plain,
            "max_tokens": row["max_tokens"],
            "temperature": row["temperature"],
        }
    )

async def _get_tenant_services(
    db: AsyncSession, tenant_id: str
) -> tuple[
    LLMProvider,
    InvestigationAssistant,
    AlertTriageAssistant,
    RuleSuggestionEngine,
    ThreatBriefingService,
    PlaybookService,
]:
    """Get or create LLM provider and services for a tenant, with TTL cache."""
    now = _time.monotonic()
    cached = _tenant_cache.get(tenant_id)
    if cached is not None:
        config_key, llm, inv, tri, rule, brief, pb, ts = cached
        if now - ts < _CACHE_TTL:
            return llm, inv, tri, rule, brief, pb

    config = await _load_llm_config(db, tenant_id)
    new_key = config.config_key()

    # Reuse existing instances if config hasn't changed
    if cached is not None and cached[0] == new_key:
        _, llm, inv, tri, rule, brief, pb, _ = cached
        _tenant_cache[tenant_id] = (new_key, llm, inv, tri, rule, brief, pb, now)
        return llm, inv, tri, rule, brief, pb

    # Build new provider and services
    fw = _get_firewall()
    mem = _get_memory()
    llm = LLMProvider(config)
    inv = InvestigationAssistant(llm, fw, mem)
    tri = AlertTriageAssistant(llm)
    rule = RuleSuggestionEngine(llm)
    brief = ThreatBriefingService(llm, fw)
    pb = PlaybookService(llm, fw)
    _tenant_cache[tenant_id] = (new_key, llm, inv, tri, rule, brief, pb, now)
    logger.info(
        "copilot_llm_loaded",
        tenant_id=tenant_id,
        provider=config.provider,
        model=config.model,
        source="db" if llm else "env",
    )
    return llm, inv, tri, rule, brief, pb

def invalidate_tenant_cache(tenant_id: str) -> None:
    """Called by copilot_config router when config is updated."""
    _tenant_cache.pop(tenant_id, None)
    logger.info("copilot_tenant_cache_invalidated", tenant_id=tenant_id)

# ── Request / Response Schemas ────────────────────────────────────────────────

class ChatRequest(BaseModel):
    """Chat message request."""

    message: str = Field(..., min_length=1, max_length=8192, description="User message")
    history: list[dict[str, Any]] = Field(
        default_factory=list, max_length=100, description="Conversation history (max 100 turns)"
    )
    context: dict[str, Any] | None = Field(None, description="Page context (current alert, agent, etc.)")
    session_id: str | None = Field(
        None,
        max_length=36,
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        description="Session UUID for multi-turn memory",
    )
    stream: bool = Field(False, description="Use streaming mode (prefer WebSocket instead)")

class ChatResponse(BaseModel):
    """Chat response."""

    response: str
    tool_calls: list[str] = []
    usage: dict[str, Any] = {}
    firewall_findings: list[str] = []

class TriageRequest(BaseModel):
    """Alert triage request."""

    alert_ids: list[str] = Field(..., min_length=1, max_length=100, description="Alert UUIDs to triage")

class TriageResponse(BaseModel):
    """Alert triage response."""

    results: list[dict[str, Any]]
    usage: dict[str, Any] = {}

class RuleRequest(BaseModel):
    """Rule generation request."""

    description: str = Field(..., min_length=3, max_length=2000, description="NL description of what to detect")
    severity_hint: str | None = Field(None, description="Optional severity level hint")

class RuleRefineRequest(BaseModel):
    """Rule refinement request."""

    original_rule: str = Field(..., description="Existing PRL rule text")
    feedback: str = Field(..., min_length=5, max_length=2000, description="Analyst feedback")

class RuleResponse(BaseModel):
    """Rule suggestion response."""

    rule_text: str
    name: str
    severity: str
    is_valid: bool
    validation_errors: list[str] = []
    confidence: float
    usage: dict[str, Any] = {}

# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/chat", response_model=ChatResponse, summary="Send a copilot message")
async def chat(
    req: ChatRequest,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """
    Send a message to the Copilot assistant.

    The assistant can call tools to look up alerts, events, agents, and trust
    scores before responding. All data access is tenant-scoped via RLS.
    """
    tenant_id = str(current_user.tenant_id)

    logger.info(
        "copilot_chat",
        user_id=str(current_user.user_id),
        tenant_id=tenant_id,
        message_length=len(req.message),
    )

    _, investigator, _, _, _, _ = await _get_tenant_services(db, tenant_id)

    try:
        response, usage, tool_calls = await investigator.investigate(
            user_message=req.message,
            history=req.history,
            db=db,
            tenant_id=tenant_id,
            context=req.context,
            session_id=req.session_id,
        )
    except httpx.ConnectError:
        logger.error("copilot_chat_llm_unreachable")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="LLM server unreachable. Check that your local LLM (LM Studio, Ollama, etc.) is running. Configure in Admin → Settings → Copilot AI.",
        )
    except Exception as exc:
        logger.error("copilot_chat_error", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Copilot request failed. The LLM server may be overloaded or misconfigured. Check Admin → Settings → Copilot AI.",
        )

    return ChatResponse(
        response=response,
        tool_calls=tool_calls,
        usage={
            "prompt_tokens": usage.prompt_tokens,
            "completion_tokens": usage.completion_tokens,
            "total_tokens": usage.total_tokens,
            "estimated_cost_usd": usage.estimated_cost_usd,
            "latency_ms": usage.latency_ms,
            "model": usage.model,
            "provider": usage.provider,
        },
    )

@router.post("/triage", response_model=TriageResponse, summary="Triage alerts")
async def triage_alerts(
    req: TriageRequest,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """
    Automated alert triage. Classifies alerts as TP/FP/needs_investigation
    with confidence scores and suggested actions.
    """
    tenant_id = str(current_user.tenant_id)

    logger.info(
        "copilot_triage",
        user_id=str(current_user.user_id),
        alert_count=len(req.alert_ids),
    )

    _, _, triage, _, _, _ = await _get_tenant_services(db, tenant_id)

    try:
        results, usage = await triage.triage_alerts(req.alert_ids, db, tenant_id)
    except httpx.ConnectError:
        logger.error("copilot_triage_llm_unreachable")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="LLM server unreachable. Start your local LLM server or configure a provider in Admin → Settings → Copilot AI.",
        )
    except Exception as exc:
        logger.error("copilot_triage_error", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Triage request failed. The LLM server may be unreachable or overloaded.",
        )

    # Firewall: scan triage reasoning outputs
    firewall = _get_firewall()
    sanitized_results = []
    for r in results:
        reasoning = r.reasoning
        output_verdict = firewall.scan_output(reasoning)
        if output_verdict.redacted_output:
            reasoning = output_verdict.redacted_output
        sanitized_results.append(
            {
                "alert_id": r.alert_id,
                "classification": r.classification,
                "confidence": r.confidence,
                "reasoning": reasoning,
                "suggested_action": r.suggested_action,
                "priority": r.priority,
            }
        )

    return TriageResponse(
        results=sanitized_results,
        usage={
            "total_tokens": usage.total_tokens,
            "latency_ms": usage.latency_ms,
            "model": usage.model,
        },
    )

@router.post("/suggest-rule", response_model=RuleResponse, summary="Generate PRL rule")
async def suggest_rule(
    req: RuleRequest,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """
    Generate a PRL detection rule from a natural language description.
    The generated rule requires human approval before activation.
    """
    logger.info(
        "copilot_suggest_rule",
        user_id=str(current_user.user_id),
        description_length=len(req.description),
    )

    # Firewall: scan user description
    firewall = _get_firewall()
    input_verdict = firewall.scan_input(req.description)
    if not input_verdict.allowed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=input_verdict.blocked_reason or "Description blocked by content firewall.",
        )
    safe_description = input_verdict.sanitized_input or req.description
    tenant_id = str(current_user.tenant_id)

    _, _, _, engine, _, _ = await _get_tenant_services(db, tenant_id)

    try:
        suggestion, usage = await engine.generate(
            safe_description,
            severity_hint=req.severity_hint,
        )
    except httpx.ConnectError:
        logger.error("copilot_rule_gen_llm_unreachable")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="LLM server unreachable. Start your local LLM server or configure a provider in Admin → Settings → Copilot AI.",
        )
    except Exception as exc:
        logger.error("copilot_rule_gen_error", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Rule generation failed. The LLM server may be unreachable or overloaded.",
        )

    return RuleResponse(
        rule_text=suggestion.rule_text,
        name=suggestion.name,
        severity=suggestion.severity,
        is_valid=suggestion.is_valid,
        validation_errors=suggestion.validation_errors,
        confidence=suggestion.confidence,
        usage={
            "total_tokens": usage.total_tokens,
            "latency_ms": usage.latency_ms,
            "model": usage.model,
        },
    )

@router.post("/refine-rule", response_model=RuleResponse, summary="Refine PRL rule")
async def refine_rule(
    req: RuleRefineRequest,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Refine an existing PRL rule based on analyst feedback."""
    # Firewall: scan feedback
    firewall = _get_firewall()
    input_verdict = firewall.scan_input(req.feedback)
    if not input_verdict.allowed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=input_verdict.blocked_reason or "Feedback blocked by content firewall.",
        )
    safe_feedback = input_verdict.sanitized_input or req.feedback
    tenant_id = str(current_user.tenant_id)

    _, _, _, engine, _, _ = await _get_tenant_services(db, tenant_id)

    try:
        suggestion, usage = await engine.refine(req.original_rule, safe_feedback)
    except Exception as exc:
        logger.error("copilot_rule_refine_error", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Rule refinement failed. Please try again.",
        )

    return RuleResponse(
        rule_text=suggestion.rule_text,
        name=suggestion.name,
        severity=suggestion.severity,
        is_valid=suggestion.is_valid,
        validation_errors=suggestion.validation_errors,
        confidence=suggestion.confidence,
        usage={
            "total_tokens": usage.total_tokens,
            "latency_ms": usage.latency_ms,
            "model": usage.model,
        },
    )

# ── AB1: Threat Briefing ──────────────────────────────────────────────────────

class BriefingRequest(BaseModel):
    """Briefing request options."""

    hours: int = Field(24, ge=1, le=168, description="Lookback period in hours (1–168)")
    use_llm: bool = Field(True, description="Use LLM summarisation (falls back to structured if unavailable)")

class BriefingResponse(BaseModel):
    """Threat briefing response."""

    briefing: str
    data: dict[str, Any] = {}
    usage: dict[str, Any] = {}

@router.post("/briefing", response_model=BriefingResponse, summary="Generate threat briefing")
async def generate_briefing(
    req: BriefingRequest,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """
    Generate an NL threat briefing summarising the last N hours.

    Pulls alert and event data, then optionally uses LLM for NL summarisation.
    Falls back to structured Markdown if LLM is unavailable.
    """
    tenant_id = str(current_user.tenant_id)

    logger.info(
        "copilot_briefing",
        user_id=str(current_user.user_id),
        tenant_id=tenant_id,
        hours=req.hours,
    )

    _, _, _, _, svc, _ = await _get_tenant_services(db, tenant_id)

    try:
        text, data, usage = await svc.generate_briefing(
            db,
            tenant_id,
            hours=req.hours,
            use_llm=req.use_llm,
        )
    except httpx.ConnectError:
        logger.error("copilot_briefing_llm_unreachable")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="LLM server unreachable. Briefing will use structured-data mode.",
        )
    except Exception as exc:
        logger.error("copilot_briefing_error", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Briefing generation failed.",
        )

    from dataclasses import asdict

    return BriefingResponse(
        briefing=text,
        data=asdict(data) if data else {},
        usage={
            "total_tokens": usage.total_tokens,
            "latency_ms": usage.latency_ms,
            "model": usage.model,
        },
    )

# ── AB2: IR Playbooks ────────────────────────────────────────────────────────

class PlaybookContextRequest(BaseModel):
    """Request to contextualise a playbook against an alert."""

    alert_data: dict[str, Any] = Field(..., description="Alert details for contextualisation")

@router.get("/playbooks", summary="List available IR playbooks")
async def list_playbooks(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """List all available IR playbooks with metadata."""
    raw = PlaybookService.list_playbooks()
    # Normalise field names for frontend contract
    playbooks = [
        {
            "attack_class": p["attack_class"],
            "name": p["title"],
            "severity": p["severity_default"],
            "description": p["description"],
        }
        for p in raw
    ]
    return {"playbooks": playbooks}

# Allowed attack classes (matches rules/core/manifest.json)
_VALID_ATTACK_CLASSES = frozenset(
    {
        "dos",
        "exfiltration",
        "prompt_injection",
        "credential_theft",
        "supply_chain",
        "lateral_movement",
        "behavioral_anomaly",
        "unauthorized_access",
        "trust_degradation",
        "privilege_escalation",
    }
)

@router.get("/playbook/{attack_class}", summary="Get IR playbook")
async def get_playbook(
    attack_class: str,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """
    Get the IR playbook for a specific attack class.

    Returns a structured 5-phase incident response guide.
    """
    # Validate attack_class against known set
    if attack_class not in _VALID_ATTACK_CLASSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown attack class: {attack_class}. Valid: {', '.join(sorted(_VALID_ATTACK_CLASSES))}",
        )

    tenant_id = str(current_user.tenant_id)
    _, _, _, _, _, svc = await _get_tenant_services(db, tenant_id)
    playbook = svc.get_playbook(attack_class)
    if playbook is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No playbook for attack class: {attack_class}",
        )
    from dataclasses import asdict

    return {
        "attack_class": playbook.attack_class,
        "title": playbook.title,
        "severity_default": playbook.severity_default,
        "description": playbook.description,
        "markdown": playbook.to_markdown(),
        "phases": asdict(playbook)["phases"],
        "references": playbook.references,
    }

@router.post("/playbook/{attack_class}/contextualise", summary="Contextualise playbook")
async def contextualise_playbook(
    attack_class: str,
    req: PlaybookContextRequest,
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """
    Contextualise an IR playbook against a specific alert using LLM.

    The LLM replaces generic steps with concrete actions based on the alert data.
    Falls back to static playbook if LLM is unavailable.
    """
    # Validate attack_class
    if attack_class not in _VALID_ATTACK_CLASSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown attack class: {attack_class}.",
        )

    tenant_id = str(current_user.tenant_id)

    # Firewall: scan alert_data serialised form for injection attempts
    import json as _json

    firewall = _get_firewall()
    alert_text = _json.dumps(req.alert_data, default=str)[:8000]
    input_verdict = firewall.scan_input(alert_text)
    if not input_verdict.allowed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=input_verdict.blocked_reason or "Alert data blocked by content firewall.",
        )

    logger.info(
        "copilot_playbook_contextualise",
        user_id=str(current_user.user_id),
        attack_class=attack_class,
    )

    _, _, _, _, _, svc = await _get_tenant_services(db, tenant_id)
    text, usage = await svc.get_contextualised(
        attack_class,
        req.alert_data,
        db,
        tenant_id,
    )

    return {
        "attack_class": attack_class,
        "contextualised_playbook": text,
        "usage": {
            "total_tokens": usage.total_tokens,
            "latency_ms": usage.latency_ms,
            "model": usage.model,
        },
    }

# ── AB3: Session Memory ──────────────────────────────────────────────────────

class SessionCreateRequest(BaseModel):
    """Create a new copilot conversation session."""

    title: str = Field("Investigation", min_length=1, max_length=200, description="Session display title")

@router.post("/sessions", summary="Create copilot session")
async def create_session(
    req: SessionCreateRequest,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Create a new multi-turn conversation session."""
    import uuid

    session_id = str(uuid.uuid4())
    memory = _get_memory()
    session = await memory.create_session(
        tenant_id=str(current_user.tenant_id),
        user_id=str(current_user.user_id),
        session_id=session_id,
        title=req.title,
    )
    return {
        "session_id": session.session_id,
        "title": req.title,
        "created_at": session.created_at,
        "message_count": 0,
    }

@router.get("/sessions", summary="List copilot sessions")
async def list_sessions(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """List active conversation sessions for the current tenant."""
    memory = _get_memory()
    sessions = await memory.list_sessions(str(current_user.tenant_id))
    return {"sessions": sessions}

@router.delete("/sessions/{session_id}", summary="Delete copilot session")
async def delete_session(
    session_id: Annotated[str, Path(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")],
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Delete a conversation session."""
    memory = _get_memory()
    deleted = await memory.delete_session(str(current_user.tenant_id), session_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    return {"deleted": True}

@router.get("/health", summary="Copilot LLM health check")
async def copilot_health(
    db: Annotated[AsyncSession, Depends(enforce_tenant_isolation)],
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Check LLM provider connectivity and available models."""
    tenant_id = str(current_user.tenant_id)
    llm, _, _, _, _, _ = await _get_tenant_services(db, tenant_id)
    health = await llm.health_check()
    return {
        "copilot_status": health.get("status", "unknown"),
        "provider": health.get("provider", ""),
        "model": health.get("model", ""),
        "available_models": health.get("available_models", []),
        "firewall": "active",
        "features": [
            "investigation",
            "triage",
            "rule_generation",
            "streaming",
            "briefing",
            "playbooks",
            "memory",
            "sessions",
        ],
    }

# ── WebSocket ticket endpoint ────────────────────────────────────────────────

@router.post("/ws/ticket", summary="Get streaming chat WS ticket")
async def copilot_ws_ticket(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Generate a single-use WebSocket ticket for copilot streaming chat."""
    tenant_id = str(getattr(current_user, "tenant_id", ""))
    user_id = str(getattr(current_user, "user_id", ""))
    role = str(getattr(current_user, "role", "viewer"))

    if not tenant_id:
        raise HTTPException(status_code=403, detail="Missing tenant_id")

    try:
        ticket = _ticket_store.create_ticket(
            tenant_id=tenant_id,
            user_id=user_id,
            role=role,
        )
    except RuntimeError as e:
        raise HTTPException(status_code=429, detail=str(e))

    return {"ticket": ticket, "expires_in": 30}

# ── WebSocket endpoint for streaming chat ─────────────────────────────────────
# NOTE: This is registered separately (not under /api/v1 prefix)

ws_router = APIRouter(tags=["copilot"])

@ws_router.websocket("/ws/copilot")
async def ws_copilot(
    websocket: WebSocket,
    ticket: str | None = Query(None, description="Single-use WS ticket"),
):
    """
    WebSocket endpoint for streaming copilot chat.

    Connect: ws://host:port/ws/copilot?ticket=<ticket>

    Client sends:
        { "type": "chat", "message": "...", "history": [...], "context": {...} }

    Server sends:
        { "type": "connected", "copilot_status": "..." }
        { "type": "token", "content": "..." }        # Streaming token
        { "type": "done", "tool_calls": [...] }       # Stream complete
        { "type": "error", "detail": "..." }          # Error
    """
    # Rate limit
    client_ip = websocket.client.host if websocket.client else "unknown"
    ws_key = f"ws:copilot:{client_ip}"
    if _redis_rate_limiter is not None:
        allowed = await _redis_rate_limiter.allow(ws_key)
    else:
        allowed = _rate_limiter.allow(ws_key)
    if not allowed:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Rate limit exceeded")
        return

    # Authenticate via ticket
    if not ticket:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Missing ticket")
        return

    ws_ticket = _ticket_store.consume_ticket(ticket)
    if ws_ticket is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid or expired ticket")
        return

    # Check role — copilot is admin/analyst only
    role = getattr(ws_ticket, "role", "viewer")
    if role not in ("admin", "analyst"):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Insufficient permissions")
        return

    await websocket.accept()

    # Send connected message — use env-based fallback (no DB session in WS)
    _env_config = LLMConfig.from_env()
    _env_llm = LLMProvider(_env_config)
    health = await _env_llm.health_check()
    await websocket.send_json(
        {
            "type": "connected",
            "copilot_status": health.get("status", "unknown"),
            "provider": health.get("provider", ""),
            "model": health.get("model", ""),
        }
    )

    fw = _get_firewall()
    mem = _get_memory()
    investigator = InvestigationAssistant(_env_llm, fw, mem)

    try:
        while True:
            data = await websocket.receive_json()
            msg_type = data.get("type", "")

            if msg_type == "chat":
                message = data.get("message", "")
                history = data.get("history", [])
                context = data.get("context")

                if not message:
                    await websocket.send_json({"type": "error", "detail": "Empty message"})
                    continue

                # Stream response
                try:
                    async for chunk in investigator.stream_investigate(
                        user_message=message,
                        history=history,
                        context=context,
                    ):
                        await websocket.send_json({"type": "token", "content": chunk})

                    await websocket.send_json({"type": "done", "tool_calls": []})
                except Exception as exc:
                    logger.error("copilot_ws_stream_error", error=str(exc))
                    await websocket.send_json({"type": "error", "detail": "Stream processing error. Please try again."})

            elif msg_type == "ping":
                await websocket.send_json({"type": "pong"})

    except Exception:
        # Client disconnected
        pass
    finally:
        with contextlib.suppress(Exception):
            await websocket.close()
