# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
PRL Action Executors — alert() and log().

When a PRL rule matches an event, the engine calls the action executor to:
1. Create an alert in PostgreSQL (via alert_service.create_alert)
2. Optionally log the match for debugging/audit

In Phase 1, actions are hardcoded: every matched rule produces an alert.
Future phases may add PRL action expressions (block, isolate, quarantine).
"""

from __future__ import annotations

import uuid
from typing import Any

import structlog

from engine.utils.truncate import truncate_dict

logger = structlog.get_logger("phantex.engine.actions")

async def create_alert_action(
    db_session: Any,
    *,
    tenant_id: uuid.UUID,
    rule_id: uuid.UUID,
    rule_name: str,
    rule_severity: str,
    event_id: uuid.UUID | None,
    agent_id: str | None,
    event_type: str,
    event_data: dict[str, Any],
) -> Any:
    """
    Create an alert in the database when a rule matches.

    This imports the Alert model at call time to avoid circular imports.
    The caller must provide a database session with tenant context already set.
    """
    from app.models.alert import Alert

    alert = Alert(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        agent_id=agent_id,
        event_id=event_id,
        rule_id=rule_id,
        severity=rule_severity,
        title=f"Rule matched: {rule_name}",
        description=(f"Rule '{rule_name}' triggered on {event_type} event. Severity: {rule_severity}."),
        status="open",
        context={
            "event_type": event_type,
            "rule_name": rule_name,
            "event_snapshot": truncate_dict(event_data, max_size=4096),
        },
    )

    db_session.add(alert)
    await db_session.flush()
    await db_session.refresh(alert)

    logger.info(
        "alert_created",
        alert_id=str(alert.id),
        rule_id=str(rule_id),
        rule_name=rule_name,
        severity=rule_severity,
        event_type=event_type,
        tenant_id=str(tenant_id),
    )

    return alert

def log_match_action(
    *,
    rule_name: str,
    rule_severity: str,
    event_type: str,
    tenant_id: str,
    matched: bool,
) -> None:
    """Log a rule evaluation result for debugging."""
    if matched:
        logger.info(
            "rule_matched",
            rule_name=rule_name,
            severity=rule_severity,
            event_type=event_type,
            tenant_id=tenant_id,
        )
    else:
        logger.debug(
            "rule_not_matched",
            rule_name=rule_name,
            event_type=event_type,
            tenant_id=tenant_id,
        )
