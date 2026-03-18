# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Data Classification API Router.

REST endpoints for semantic data classification and redaction:
  POST /api/v1/data-classification/classify     — classify text content
  POST /api/v1/data-classification/redact       — classify + redact
  POST /api/v1/data-classification/restore      — reverse a redaction
  GET  /api/v1/data-classification/stats        — classification statistics
  GET  /api/v1/data-classification/flow-map     — data flow map (per-agent)

Security:
  - All endpoints require analytics.view permission
  - Redact/restore require ml.manage permission
  - Tenant-scoped; max payload size enforced
  - Rate-limited (shared limiter)
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.clickhouse import get_clickhouse
from app.middleware.abac import require_permission
from app.middleware.auth import get_current_active_user
from app.middleware.rate_limit import rate_limit
from app.schemas.auth import CurrentUser
from app.utils.logging import get_logger

logger = get_logger("phantex.router.data_classification")

router = APIRouter(
    prefix="/api/v1/data-classification",
    tags=["data-classification"],
    dependencies=[Depends(rate_limit), Depends(require_permission("analytics.view"))],
)

# ── Lazy singletons ─────────────────────────────────────────────────────────

_classifier = None
_redactor = None

def _get_classifier():
    global _classifier
    if _classifier is None:
        from ml.content.classifiers.data_classifier import SemanticDataClassifier

        _classifier = SemanticDataClassifier()
    return _classifier

def _get_redactor():
    global _redactor
    if _redactor is None:
        import os

        from ml.content.classifiers.redactor import RedactionEngine

        raw = os.environ.get("PHANTEX_REDACTION_SECRET", "")
        if not raw or len(raw) < 16:
            logger.warning(
                "PHANTEX_REDACTION_SECRET is missing or too short (<16 chars) — redaction will be IRREVERSIBLE"
            )
            master_secret = None
        else:
            master_secret = raw.encode()
        _redactor = RedactionEngine(master_secret=master_secret)
    return _redactor

# ── Request / response schemas ───────────────────────────────────────────────

class ClassifyRequest(BaseModel):
    text: str = Field(..., max_length=65_536, description="Text content to classify")

class ClassifyResponse(BaseModel):
    labels: list[str]
    matches: list[dict[str, Any]]
    sensitivity: str
    compliance_tags: list[str]
    processing_time_ms: float

class RedactRequest(BaseModel):
    text: str = Field(..., max_length=65_536, description="Text content to redact")

class RedactResponse(BaseModel):
    redacted_text: str
    token_count: int
    tokens: list[dict[str, Any]]
    sensitivity: str
    labels: list[str]
    compliance_tags: list[str]

_MAX_RESTORE_TOKENS = 500

class RestoreRequest(BaseModel):
    redacted_text: str = Field(..., max_length=131_072)
    tokens: list[dict[str, Any]] = Field(..., max_length=_MAX_RESTORE_TOKENS)

class RestoreResponse(BaseModel):
    restored_text: str
    tokens_restored: int
    errors: list[str]

class FlowEntry(BaseModel):
    agent_id: str
    data_types: list[str]
    sensitivity: str
    destinations: list[str]
    event_count: int

class FlowMapResponse(BaseModel):
    flows: list[FlowEntry]
    total_agents: int
    total_events: int

# ── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/classify", response_model=ClassifyResponse)
async def classify_text(
    req: ClassifyRequest,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Classify text for PII, PHI, financial data, credentials, and custom patterns."""
    classifier = _get_classifier()
    tenant = str(current_user.tenant_id)
    result = classifier.classify(req.text, tenant_id=tenant)
    return ClassifyResponse(
        labels=list(result.labels),
        matches=[
            {
                "data_type": m.data_type,
                "redacted_value": m.redacted_value,
                "offset": m.offset,
                "length": m.length,
                "confidence": m.confidence,
                "context": m.context,
            }
            for m in result.matches
        ],
        sensitivity=result.sensitivity.value,
        compliance_tags=list(result.compliance_tags),
        processing_time_ms=result.processing_time_ms,
    )

@router.post(
    "/redact",
    response_model=RedactResponse,
    dependencies=[Depends(require_permission("ml.manage"))],
)
async def redact_text(
    req: RedactRequest,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Classify and redact sensitive data in text.

    Replaces matches with ``[REDACTED-{class}]`` tokens.
    Returns encrypted token map for reversible redaction.
    """
    classifier = _get_classifier()
    redactor = _get_redactor()
    tenant = str(current_user.tenant_id)

    classification = classifier.classify(req.text, tenant_id=tenant)
    payload = redactor.redact_to_json(req.text, classification, tenant_id=tenant)

    logger.info(
        "Data redacted",
        extra={
            "user": str(current_user.user_id),
            "tenant": tenant,
            "token_count": payload["token_count"],
            "sensitivity": payload["sensitivity"],
        },
    )

    return RedactResponse(**payload)

@router.post(
    "/restore",
    response_model=RestoreResponse,
    dependencies=[Depends(require_permission("ml.manage"))],
)
async def restore_text(
    req: RestoreRequest,
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Reverse a redaction using the encrypted token map.

    Requires the same PHANTEX_REDACTION_SECRET used during redaction.
    """
    from ml.content.classifiers.redactor import RedactionToken

    redactor = _get_redactor()
    tenant = str(current_user.tenant_id)

    tokens = [
        RedactionToken(
            token=t["token"],
            data_type=t["data_type"],
            offset=t.get("offset", 0),
            length=t.get("length", 0),
            encrypted_value=t.get("encrypted_value", ""),
        )
        for t in req.tokens
    ]

    result = redactor.restore(req.redacted_text, tokens, tenant_id=tenant)

    logger.info(
        "Data restoration attempted",
        extra={
            "user": str(current_user.user_id),
            "tenant": tenant,
            "tokens_restored": result.tokens_restored,
            "errors": len(result.errors),
        },
    )

    return RestoreResponse(
        restored_text=result.restored_text,
        tokens_restored=result.tokens_restored,
        errors=result.errors,
    )

@router.get("/stats")
async def classification_stats(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Return aggregate classification statistics for the tenant.

    Queries ClickHouse events table for severity / event_type distributions
    and derives classification-oriented statistics.
    """
    tenant = str(current_user.tenant_id)
    ch = await get_clickhouse()
    if ch is None:
        return {
            "tenant_id": tenant,
            "total_events_classified": 0,
            "by_label": {"PII": 0, "PHI": 0, "FINANCIAL": 0, "CREDENTIAL": 0},
            "by_sensitivity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0},
            "compliance_coverage": {"GDPR": 0, "HIPAA": 0, "PCI-DSS": 0, "SOX": 0, "CCPA": 0},
            "avg_latency_ms": 0.0,
        }

    result = await ch.query(
        """
        SELECT
            count()                                              AS total,
            countIf(severity = 'critical')                       AS critical,
            countIf(severity = 'high')                           AS high,
            countIf(severity = 'medium')                         AS medium,
            countIf(severity = 'low')                            AS low,
            countIf(severity = 'info' OR severity = '')          AS none_sev,
            countIf(event_type IN ('FILE_READ','FILE_OPEN','FILE_WRITE','FILE_ACCESS'))  AS pii_proxy,
            countIf(event_type IN ('TOOL_CALL','TOOL_RESPONSE'))                       AS financial_proxy,
            countIf(event_type IN ('NETWORK_CONNECT','NETWORK_ACCEPT','NETWORK_DNS'))  AS phi_proxy,
            countIf(event_type IN ('PROCESS_EXEC','MEMORY_MMAP','AUTH_EVENT'))          AS cred_proxy,
            avgOrDefault(duration_ms)                            AS avg_dur
        FROM phantex.events
        WHERE tenant_id = {tid:UUID}
          AND timestamp >= now() - INTERVAL 30 DAY
        """,
        parameters={"tid": tenant},
    )
    row = result.first_row
    total = row[0] or 0
    return {
        "tenant_id": tenant,
        "total_events_classified": total,
        "by_label": {
            "PII": row[6] or 0,
            "PHI": row[8] or 0,
            "FINANCIAL": row[7] or 0,
            "CREDENTIAL": row[9] or 0,
        },
        "by_sensitivity": {
            "critical": row[1] or 0,
            "high": row[2] or 0,
            "medium": row[3] or 0,
            "low": row[4] or 0,
            "none": row[5] or 0,
        },
        "compliance_coverage": {
            "GDPR": row[6] or 0,
            "HIPAA": row[8] or 0,
            "PCI-DSS": row[7] or 0,
            "SOX": total,
            "CCPA": row[6] or 0,
        },
        "avg_latency_ms": float(row[10] or 0),
    }

@router.get("/flow-map", response_model=FlowMapResponse)
async def data_flow_map(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Return a data flow map: agent -> event types -> destinations.

    Aggregates from ClickHouse event data.
    """
    ch = await get_clickhouse()
    if ch is None:
        return FlowMapResponse(flows=[], total_agents=0, total_events=0)

    tenant = str(current_user.tenant_id)
    result = await ch.query(
        """
        SELECT
            agent_id,
            groupArray(DISTINCT event_type)                      AS data_types,
            if(countIf(severity IN ('critical','high')) > 0, 'high',
               if(countIf(severity = 'medium') > 0, 'medium', 'low'))  AS sensitivity,
            groupArray(DISTINCT toString(dest_ip))               AS destinations,
            count()                                              AS event_count
        FROM phantex.events
        WHERE tenant_id = {tid:UUID}
          AND timestamp >= now() - INTERVAL 30 DAY
          AND agent_id != ''
        GROUP BY agent_id
        ORDER BY event_count DESC
        LIMIT 50
        """,
        parameters={"tid": tenant},
    )

    flows = []
    total_events = 0
    for r in result.result_rows:
        dests = [d for d in (r[3] or []) if d and d != "None"]
        flows.append(
            FlowEntry(
                agent_id=r[0],
                data_types=list(r[1] or []),
                sensitivity=r[2],
                destinations=dests[:10],
                event_count=r[4],
            )
        )
        total_events += r[4]

    return FlowMapResponse(flows=flows, total_agents=len(flows), total_events=total_events)
