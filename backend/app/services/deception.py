# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Deception Technology Service

Core service layer for managing deception assets:
  - Decoy agents (fake AI agents that act as honeypots)
  - Canary MCP servers (fake tool servers)
  - Canary tokens (fake API keys, credentials, PII, DNS, URLs)
  - Honeypot event recording and stats

Security:
  - All DB queries are tenant-scoped (RLS enforced)
  - Canary token values stored as SHA-256 hashes only
  - Ed25519 keypairs generated for decoy agent identities
  - Honeypot events are append-only (no update/delete)
"""

from __future__ import annotations

import hashlib
import os
import secrets
import uuid
from datetime import UTC, datetime
from typing import Any

from app.utils.logging import get_logger

logger = get_logger("phantex.service.deception")

# ── Crypto helpers ────────────────────────────────────────────────────────────

def generate_canary_token_value(token_type: str) -> tuple[str, str, str]:
    """
    Generate a canary token raw value, its SHA-256 hash, and a hint.

    Returns (raw_value, sha256_hash, hint).
    The raw_value is shown ONCE at creation — never stored in DB.
    """
    if token_type == "api_key":
        raw = f"sk-canary-{secrets.token_hex(24)}"
        hint = f"sk-...{raw[-4:]}"
    elif token_type == "credential":
        raw = f"canary-pwd-{secrets.token_hex(16)}"
        hint = f"canary-...{raw[-4:]}"
    elif token_type == "pii":
        # Fake SSN-like pattern
        raw = f"000-{secrets.randbelow(100):02d}-{secrets.randbelow(10000):04d}"
        hint = f"000-**-{raw[-4:]}"
    elif token_type == "dns":
        tag = secrets.token_hex(8)
        raw = f"{tag}.canary.phantex.internal"
        hint = f"...{tag[:4]}.canary.phantex.internal"
    elif token_type == "url":
        tag = secrets.token_hex(12)
        raw = f"https://canary.phantex.internal/{tag}"
        hint = f"https://canary.phantex.internal/...{tag[-4:]}"
    else:
        raw = secrets.token_hex(32)
        hint = f"...{raw[-4:]}"

    value_hash = hashlib.sha256(raw.encode()).hexdigest()
    return raw, value_hash, hint

def generate_paid(tenant_id: str) -> str:
    """Generate a realistic-looking PAID for a decoy agent."""
    suffix = secrets.token_hex(4)
    return f"ptx-decoy-{suffix}"

def hash_token(value: str) -> str:
    """SHA-256 hash a canary token value."""
    return hashlib.sha256(value.encode()).hexdigest()

# ── Decoy Agent Service ──────────────────────────────────────────────────────

async def list_decoy_agents(db: Any, tenant_id: Any) -> list[dict]:
    """List all decoy agents for a tenant."""
    await db.set_tenant(str(tenant_id))
    rows = await db.fetch(
        """
        SELECT id, tenant_id, name, description, paid, framework, framework_ver,
               public_key, decoy_profile, network_config, enabled,
               interaction_count, last_triggered, created_by, created_at, updated_at
        FROM decoy_agents
        WHERE tenant_id = $1 AND deleted_at IS NULL
        ORDER BY created_at DESC
        """,
        tenant_id,
    )
    return [_decoy_to_dict(r) for r in rows]

async def create_decoy_agent(
    db: Any,
    tenant_id: Any,
    created_by: str,
    name: str,
    description: str | None,
    framework: str,
    framework_ver: str,
    decoy_profile: dict,
    network_config: dict,
    enabled: bool = True,
) -> dict:
    """Create a new decoy agent with cryptographic identity."""
    await db.set_tenant(str(tenant_id))

    paid = generate_paid(str(tenant_id))

    # Generate Ed25519 keypair for the decoy agent identity
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private_key = Ed25519PrivateKey.generate()
        public_pem = (
            private_key.public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )
        # Passphrase sourced from env var. For Vault integration, inject PHANTEX_DECOY_KEY_PASSPHRASE via Vault Agent/CSI.
        # Private key is also behind RLS + DB-level encryption at rest.
        _passphrase = os.environ.get("PHANTEX_DECOY_KEY_PASSPHRASE", "phantex-decoy-key").encode()
        private_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(_passphrase),
        ).decode()
    except ImportError:
        logger.warning("cryptography_not_available", msg="Ed25519 keypair not generated")
        public_pem = None
        private_pem = None

    import json as _json

    row = await db.fetchrow(
        """
        INSERT INTO decoy_agents (
            id, tenant_id, name, description, paid, framework, framework_ver,
            public_key, private_key_enc, decoy_profile, network_config,
            enabled, created_by
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        RETURNING id, tenant_id, name, description, paid, framework, framework_ver,
                  public_key, decoy_profile, network_config, enabled,
                  interaction_count, last_triggered, created_by, created_at, updated_at
        """,
        str(uuid.uuid4()),
        tenant_id,
        name,
        description,
        paid,
        framework,
        framework_ver,
        public_pem,
        private_pem,
        _json.dumps(decoy_profile),
        _json.dumps(network_config),
        enabled,
        created_by,
    )

    logger.info("decoy_agent_created", decoy_id=row["id"], paid=paid, tenant_id=str(tenant_id))
    return _decoy_to_dict(row)

async def delete_decoy_agent(db: Any, tenant_id: Any, decoy_id: str) -> bool:
    """Soft-delete a decoy agent."""
    await db.set_tenant(str(tenant_id))
    result = await db.execute(
        "UPDATE decoy_agents SET deleted_at = now() WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL",
        decoy_id,
        tenant_id,
    )
    return result != "UPDATE 0"

async def toggle_decoy_agent(db: Any, tenant_id: Any, decoy_id: str, enabled: bool) -> dict | None:
    """Enable or disable a decoy agent."""
    await db.set_tenant(str(tenant_id))
    row = await db.fetchrow(
        """
        UPDATE decoy_agents SET enabled = $3, updated_at = now()
        WHERE id = $1 AND tenant_id = $2
        RETURNING id, tenant_id, name, description, paid, framework, framework_ver,
                  public_key, decoy_profile, network_config, enabled,
                  interaction_count, last_triggered, created_by, created_at, updated_at
        """,
        decoy_id,
        tenant_id,
        enabled,
    )
    return _decoy_to_dict(row) if row else None

# ── Canary MCP Server Service ────────────────────────────────────────────────

async def list_canary_mcp_servers(db: Any, tenant_id: Any) -> list[dict]:
    """List all canary MCP servers for a tenant."""
    await db.set_tenant(str(tenant_id))
    rows = await db.fetch(
        """
        SELECT id, tenant_id, name, description, server_url, advertised_tools,
               protocol, tls_enabled, rotate_identity, rotation_interval_hours,
               last_rotated, enabled, interaction_count, last_triggered,
               created_by, created_at, updated_at
        FROM canary_mcp_servers
        WHERE tenant_id = $1 AND deleted_at IS NULL
        ORDER BY created_at DESC
        """,
        tenant_id,
    )
    return [_canary_mcp_to_dict(r) for r in rows]

async def create_canary_mcp_server(
    db: Any,
    tenant_id: Any,
    created_by: str,
    name: str,
    description: str | None,
    server_url: str,
    advertised_tools: list[dict],
    protocol: str = "sse",
    tls_enabled: bool = True,
    rotate_identity: bool = False,
    rotation_interval_hours: int = 168,
    enabled: bool = True,
) -> dict:
    """Create a new canary MCP server."""
    await db.set_tenant(str(tenant_id))

    import json as _json

    row = await db.fetchrow(
        """
        INSERT INTO canary_mcp_servers (
            id, tenant_id, name, description, server_url, advertised_tools,
            protocol, tls_enabled, rotate_identity, rotation_interval_hours,
            enabled, created_by
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        RETURNING *
        """,
        str(uuid.uuid4()),
        tenant_id,
        name,
        description,
        server_url,
        _json.dumps(advertised_tools),
        protocol,
        tls_enabled,
        rotate_identity,
        rotation_interval_hours,
        enabled,
        created_by,
    )

    logger.info("canary_mcp_created", canary_id=row["id"], tenant_id=str(tenant_id))
    return _canary_mcp_to_dict(row)

async def delete_canary_mcp_server(db: Any, tenant_id: Any, canary_id: str) -> bool:
    """Soft-delete a canary MCP server."""
    await db.set_tenant(str(tenant_id))
    result = await db.execute(
        "UPDATE canary_mcp_servers SET deleted_at = now() WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL",
        canary_id,
        tenant_id,
    )
    return result != "UPDATE 0"

async def toggle_canary_mcp_server(db: Any, tenant_id: Any, canary_id: str, enabled: bool) -> dict | None:
    """Enable or disable a canary MCP server."""
    await db.set_tenant(str(tenant_id))
    row = await db.fetchrow(
        """
        UPDATE canary_mcp_servers SET enabled = $3, updated_at = now()
        WHERE id = $1 AND tenant_id = $2
        RETURNING *
        """,
        canary_id,
        tenant_id,
        enabled,
    )
    return _canary_mcp_to_dict(row) if row else None

# ── Canary Token Service ─────────────────────────────────────────────────────

async def list_canary_tokens(db: Any, tenant_id: Any) -> list[dict]:
    """List all canary tokens for a tenant."""
    await db.set_tenant(str(tenant_id))
    rows = await db.fetch(
        """
        SELECT id, tenant_id, name, description, token_type, token_hint,
               placement, alert_on_read, alert_on_use, enabled,
               trigger_count, last_triggered, created_by, created_at, updated_at
        FROM canary_tokens
        WHERE tenant_id = $1 AND deleted_at IS NULL
        ORDER BY created_at DESC
        """,
        tenant_id,
    )
    return [_canary_token_to_dict(r) for r in rows]

async def create_canary_token(
    db: Any,
    tenant_id: Any,
    created_by: str,
    name: str,
    description: str | None,
    token_type: str,
    placement: dict,
    alert_on_read: bool = False,
    alert_on_use: bool = True,
    enabled: bool = True,
) -> dict:
    """
    Create a new canary token.

    Returns the token dict WITH the raw_value field — shown once at creation.
    """
    await db.set_tenant(str(tenant_id))

    raw_value, value_hash, hint = generate_canary_token_value(token_type)

    import json as _json

    row = await db.fetchrow(
        """
        INSERT INTO canary_tokens (
            id, tenant_id, name, description, token_type, token_value_hash,
            token_hint, placement, alert_on_read, alert_on_use, enabled, created_by
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        RETURNING id, tenant_id, name, description, token_type, token_hint,
                  placement, alert_on_read, alert_on_use, enabled,
                  trigger_count, last_triggered, created_by, created_at, updated_at
        """,
        str(uuid.uuid4()),
        tenant_id,
        name,
        description,
        token_type,
        value_hash,
        hint,
        _json.dumps(placement),
        alert_on_read,
        alert_on_use,
        enabled,
        created_by,
    )

    result = _canary_token_to_dict(row)
    result["raw_value"] = raw_value  # Shown ONCE at creation — never again
    logger.info("canary_token_created", token_id=row["id"], token_type=token_type, tenant_id=str(tenant_id))
    return result

async def delete_canary_token(db: Any, tenant_id: Any, token_id: str) -> bool:
    """Soft-delete a canary token."""
    await db.set_tenant(str(tenant_id))
    result = await db.execute(
        "UPDATE canary_tokens SET deleted_at = now() WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL",
        token_id,
        tenant_id,
    )
    return result != "UPDATE 0"

async def toggle_canary_token(db: Any, tenant_id: Any, token_id: str, enabled: bool) -> dict | None:
    """Enable or disable a canary token."""
    await db.set_tenant(str(tenant_id))
    row = await db.fetchrow(
        """
        UPDATE canary_tokens SET enabled = $3, updated_at = now()
        WHERE id = $1 AND tenant_id = $2
        RETURNING id, tenant_id, name, description, token_type, token_hint,
                  placement, alert_on_read, alert_on_use, enabled,
                  trigger_count, last_triggered, created_by, created_at, updated_at
        """,
        token_id,
        tenant_id,
        enabled,
    )
    return _canary_token_to_dict(row) if row else None

async def check_canary_token(db: Any, candidate_value: str) -> dict | None:
    """
    Check if a value matches any canary token hash (cross-tenant lookup by hash).

    This is called from the detection pipeline when a suspicious credential
    or API key is observed.  Returns token info if match found, None otherwise.

    SECURITY NOTE — INTERNAL ONLY:
      This function intentionally skips set_tenant() and performs a cross-tenant
      hash lookup. It is NEVER exposed via the HTTP router. It must only be
      called from internal detection pipeline code running with a superuser
      or RLS-bypassed connection. Do NOT add a router endpoint for this.
    """
    value_hash = hash_token(candidate_value)
    # Cross-tenant lookup (no set_tenant) — internal detection pipeline only.
    row = await db.fetchrow(
        """
        SELECT id, tenant_id, name, token_type, token_hint, enabled
        FROM canary_tokens
        WHERE token_value_hash = $1 AND enabled = true AND deleted_at IS NULL
        """,
        value_hash,
    )
    if row:
        return {
            "id": str(row["id"]),
            "tenant_id": str(row["tenant_id"]),
            "name": row["name"],
            "token_type": row["token_type"],
            "token_hint": row["token_hint"],
        }
    return None

# ── Honeypot Events ──────────────────────────────────────────────────────────

async def record_honeypot_event(
    db: Any,
    tenant_id: Any,
    source_type: str,
    source_id: str,
    source_name: str,
    interaction_type: str,
    interaction_data: dict,
    agent_id: str | None = None,
    agent_paid: str | None = None,
    source_ip: str | None = None,
    severity: str = "critical",
    attack_class: str | None = None,
    mitre_tactic: str | None = None,
    mitre_technique: str | None = None,
    auto_response: dict | None = None,
) -> dict:
    """
    Record a honeypot interaction event (append-only).

    Also increments the interaction counter on the source deception asset.
    """
    await db.set_tenant(str(tenant_id))

    import json as _json

    event_id = str(uuid.uuid4())
    now = datetime.now(UTC)

    row = await db.fetchrow(
        """
        INSERT INTO honeypot_events (
            id, tenant_id, source_type, source_id, source_name,
            agent_id, agent_paid, source_ip,
            interaction_type, interaction_data,
            severity, attack_class, mitre_tactic, mitre_technique,
            auto_response, triggered_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
        RETURNING *
        """,
        event_id,
        tenant_id,
        source_type,
        source_id,
        source_name,
        agent_id,
        agent_paid,
        source_ip,
        interaction_type,
        _json.dumps(interaction_data),
        severity,
        attack_class,
        mitre_tactic,
        mitre_technique,
        _json.dumps(auto_response or {}),
        now,
    )

    # Increment the interaction counter on the source asset
    if source_type == "decoy_agent":
        await db.execute(
            "UPDATE decoy_agents SET interaction_count = interaction_count + 1, last_triggered = $3 WHERE id = $1 AND tenant_id = $2",
            source_id,
            tenant_id,
            now,
        )
    elif source_type == "canary_mcp":
        await db.execute(
            "UPDATE canary_mcp_servers SET interaction_count = interaction_count + 1, last_triggered = $3 WHERE id = $1 AND tenant_id = $2",
            source_id,
            tenant_id,
            now,
        )
    elif source_type == "canary_token":
        await db.execute(
            "UPDATE canary_tokens SET trigger_count = trigger_count + 1, last_triggered = $3 WHERE id = $1 AND tenant_id = $2",
            source_id,
            tenant_id,
            now,
        )

    logger.warning(
        "honeypot_triggered",
        event_id=event_id,
        source_type=source_type,
        source_id=source_id,
        agent_id=agent_id,
        severity=severity,
        tenant_id=str(tenant_id),
    )

    return _event_to_dict(row)

async def list_honeypot_events(
    db: Any,
    tenant_id: Any,
    limit: int = 100,
    offset: int = 0,
    source_type: str | None = None,
    severity: str | None = None,
) -> tuple[list[dict], int]:
    """List honeypot events with pagination and optional filters."""
    await db.set_tenant(str(tenant_id))

    where_clauses = ["tenant_id = $1"]
    params: list[Any] = [tenant_id]
    idx = 2

    if source_type:
        where_clauses.append(f"source_type = ${idx}")
        params.append(source_type)
        idx += 1
    if severity:
        where_clauses.append(f"severity = ${idx}")
        params.append(severity)
        idx += 1

    where_sql = " AND ".join(where_clauses)

    count_row = await db.fetchrow(
        f"SELECT count(*) as cnt FROM honeypot_events WHERE {where_sql}",
        *params,
    )
    total = count_row["cnt"] if count_row else 0

    rows = await db.fetch(
        f"""
        SELECT * FROM honeypot_events
        WHERE {where_sql}
        ORDER BY triggered_at DESC
        LIMIT ${idx} OFFSET ${idx + 1}
        """,
        *params,
        limit,
        offset,
    )

    return [_event_to_dict(r) for r in rows], total

async def get_deception_stats(db: Any, tenant_id: Any) -> dict:
    """Get aggregated deception stats for the dashboard."""
    await db.set_tenant(str(tenant_id))

    decoy_count = await db.fetchrow(
        "SELECT count(*) as cnt FROM decoy_agents WHERE tenant_id = $1",
        tenant_id,
    )
    mcp_count = await db.fetchrow(
        "SELECT count(*) as cnt FROM canary_mcp_servers WHERE tenant_id = $1",
        tenant_id,
    )
    token_count = await db.fetchrow(
        "SELECT count(*) as cnt FROM canary_tokens WHERE tenant_id = $1",
        tenant_id,
    )
    event_total = await db.fetchrow(
        "SELECT count(*) as cnt FROM honeypot_events WHERE tenant_id = $1",
        tenant_id,
    )
    events_24h = await db.fetchrow(
        "SELECT count(*) as cnt FROM honeypot_events WHERE tenant_id = $1 AND triggered_at > now() - interval '24 hours'",
        tenant_id,
    )
    events_7d = await db.fetchrow(
        "SELECT count(*) as cnt FROM honeypot_events WHERE tenant_id = $1 AND triggered_at > now() - interval '7 days'",
        tenant_id,
    )
    last_event = await db.fetchrow(
        "SELECT max(triggered_at) as last_at FROM honeypot_events WHERE tenant_id = $1",
        tenant_id,
    )

    return {
        "total_decoy_agents": decoy_count["cnt"] if decoy_count else 0,
        "total_canary_mcp": mcp_count["cnt"] if mcp_count else 0,
        "total_canary_tokens": token_count["cnt"] if token_count else 0,
        "total_honeypot_events": event_total["cnt"] if event_total else 0,
        "events_last_24h": events_24h["cnt"] if events_24h else 0,
        "events_last_7d": events_7d["cnt"] if events_7d else 0,
        "last_event_at": str(last_event["last_at"]) if last_event and last_event["last_at"] else None,
    }

# ── Row converters ────────────────────────────────────────────────────────────

def _parse_json(val: Any) -> Any:
    """Parse JSON string or return as-is if already a dict/list."""
    if val is None:
        return {}
    if isinstance(val, dict | list):
        return val
    import json as _json

    try:
        return _json.loads(val)
    except (ValueError, TypeError):
        return {}

def _decoy_to_dict(row: Any) -> dict:
    return {
        "id": str(row["id"]),
        "tenant_id": str(row["tenant_id"]),
        "name": row["name"],
        "description": row.get("description"),
        "paid": row["paid"],
        "framework": row["framework"],
        "framework_ver": row["framework_ver"],
        "public_key": row.get("public_key"),
        "decoy_profile": _parse_json(row.get("decoy_profile")),
        "network_config": _parse_json(row.get("network_config")),
        "enabled": row["enabled"],
        "interaction_count": row["interaction_count"],
        "last_triggered": str(row["last_triggered"]) if row.get("last_triggered") else None,
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
    }

def _canary_mcp_to_dict(row: Any) -> dict:
    return {
        "id": str(row["id"]),
        "tenant_id": str(row["tenant_id"]),
        "name": row["name"],
        "description": row.get("description"),
        "server_url": row["server_url"],
        "advertised_tools": _parse_json(row.get("advertised_tools")),
        "protocol": row["protocol"],
        "tls_enabled": row["tls_enabled"],
        "rotate_identity": row["rotate_identity"],
        "rotation_interval_hours": row["rotation_interval_hours"],
        "last_rotated": str(row["last_rotated"]) if row.get("last_rotated") else None,
        "enabled": row["enabled"],
        "interaction_count": row["interaction_count"],
        "last_triggered": str(row["last_triggered"]) if row.get("last_triggered") else None,
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
    }

def _canary_token_to_dict(row: Any) -> dict:
    return {
        "id": str(row["id"]),
        "tenant_id": str(row["tenant_id"]),
        "name": row["name"],
        "description": row.get("description"),
        "token_type": row["token_type"],
        "token_hint": row.get("token_hint"),
        "placement": _parse_json(row.get("placement")),
        "alert_on_read": row["alert_on_read"],
        "alert_on_use": row["alert_on_use"],
        "enabled": row["enabled"],
        "trigger_count": row["trigger_count"],
        "last_triggered": str(row["last_triggered"]) if row.get("last_triggered") else None,
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
    }

def _event_to_dict(row: Any) -> dict:
    return {
        "id": str(row["id"]),
        "tenant_id": str(row["tenant_id"]),
        "source_type": row["source_type"],
        "source_id": str(row["source_id"]),
        "source_name": row["source_name"],
        "agent_id": str(row["agent_id"]) if row.get("agent_id") else None,
        "agent_paid": row.get("agent_paid"),
        "source_ip": str(row["source_ip"]) if row.get("source_ip") else None,
        "interaction_type": row["interaction_type"],
        "interaction_data": _parse_json(row.get("interaction_data")),
        "severity": row["severity"],
        "attack_class": row.get("attack_class"),
        "mitre_tactic": row.get("mitre_tactic"),
        "mitre_technique": row.get("mitre_technique"),
        "auto_response": _parse_json(row.get("auto_response")),
        "triggered_at": str(row["triggered_at"]),
        "created_at": str(row["created_at"]),
    }
