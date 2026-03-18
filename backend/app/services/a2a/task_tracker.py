# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — A2A Task Flow Tracker.

Tracks every A2A task delegation across its full lifecycle:
  submitted → working → completed / failed

Builds a directed graph of delegation chains:
  who delegated → to whom → what data → what result.

Stores task records in-memory (production: ClickHouse + PostgreSQL).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from app.utils.logging import get_logger

logger = get_logger("phantex.a2a.task_tracker")

class TaskStatus(StrEnum):
    SUBMITTED = "submitted"
    WORKING = "working"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    BLOCKED = "blocked"  # Blocked by policy

@dataclass
class A2ATask:
    """Represents a single A2A task delegation."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    task_id: str  # External A2A task ID
    initiator_agent_id: str  # Who started the chain
    source_agent_id: str  # Who delegated this step
    target_agent_id: str  # Who received the delegation
    capability: str  # What capability was requested
    status: TaskStatus = TaskStatus.SUBMITTED
    chain_depth: int = 0  # Depth in delegation chain
    parent_task_id: str | None = None  # Parent A2A task (if sub-delegation)
    description: str = ""
    result_summary: str = ""
    error: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

@dataclass
class DelegationChain:
    """Full delegation chain from initiator to final executor."""

    initiator: str
    tasks: list[A2ATask]
    total_depth: int
    has_cycle: bool = False
    cycle_agents: list[str] = field(default_factory=list)

class TaskFlowTracker:
    """Track A2A task delegations with lifecycle monitoring.

    Production: backed by PostgreSQL + ClickHouse for analytics.
    """

    _MAX_CHAIN_DEPTH = 10

    def __init__(self) -> None:
        # {tenant_id: {internal_id: A2ATask}}
        self._tasks: dict[uuid.UUID, dict[uuid.UUID, A2ATask]] = {}

    # ── Record task events ────────────────────────────────────────────

    def record_delegation(
        self,
        tenant_id: uuid.UUID,
        source_agent_id: str,
        target_agent_id: str,
        capability: str,
        *,
        task_id: str = "",
        parent_task_id: str | None = None,
        description: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> A2ATask:
        """Record a new task delegation."""
        # Determine chain depth
        chain_depth = 0
        initiator = source_agent_id
        if parent_task_id:
            parent = self._find_by_task_id(tenant_id, parent_task_id)
            if parent:
                chain_depth = parent.chain_depth + 1
                initiator = parent.initiator_agent_id

        if chain_depth > self._MAX_CHAIN_DEPTH:
            logger.warning(
                "a2a_delegation_depth_exceeded",
                tenant_id=str(tenant_id),
                source=source_agent_id,
                target=target_agent_id,
                depth=chain_depth,
            )
            raise ValueError(f"Delegation chain depth {chain_depth} exceeds maximum {self._MAX_CHAIN_DEPTH}")

        # Cycle detection
        if self._detect_cycle(tenant_id, source_agent_id, target_agent_id, parent_task_id):
            logger.warning(
                "a2a_circular_delegation_detected",
                tenant_id=str(tenant_id),
                source=source_agent_id,
                target=target_agent_id,
            )
            raise ValueError(f"Circular delegation detected: {source_agent_id} → {target_agent_id}")

        task = A2ATask(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            task_id=task_id or uuid.uuid4().hex[:16],
            initiator_agent_id=initiator,
            source_agent_id=source_agent_id,
            target_agent_id=target_agent_id,
            capability=capability,
            chain_depth=chain_depth,
            parent_task_id=parent_task_id,
            description=description,
            metadata=metadata or {},
        )

        self._tasks.setdefault(tenant_id, {})[task.id] = task
        logger.info(
            "a2a_task_delegated",
            tenant_id=str(tenant_id),
            task_id=task.task_id,
            source=source_agent_id,
            target=target_agent_id,
            capability=capability,
            depth=chain_depth,
        )
        return task

    def update_status(
        self,
        tenant_id: uuid.UUID,
        task_id: str,
        status: TaskStatus,
        *,
        result_summary: str = "",
        error: str = "",
    ) -> A2ATask | None:
        """Update a task's lifecycle status."""
        task = self._find_by_task_id(tenant_id, task_id)
        if not task:
            return None

        task.status = status
        task.updated_at = datetime.now(UTC)
        if result_summary:
            task.result_summary = result_summary
        if error:
            task.error = error
        if status in (TaskStatus.COMPLETED, TaskStatus.FAILED):
            task.completed_at = datetime.now(UTC)

        logger.info(
            "a2a_task_status_updated",
            task_id=task_id,
            status=status.value,
        )
        return task

    # ── Chain analysis ────────────────────────────────────────────────

    def get_delegation_chain(
        self,
        tenant_id: uuid.UUID,
        task_id: str,
    ) -> DelegationChain | None:
        """Build the full delegation chain for a task."""
        task = self._find_by_task_id(tenant_id, task_id)
        if not task:
            return None

        # Walk up to find root
        chain: list[A2ATask] = [task]
        seen_agents: set[str] = {task.source_agent_id, task.target_agent_id}
        has_cycle = False
        cycle_agents: list[str] = []

        current = task
        while current.parent_task_id:
            parent = self._find_by_task_id(tenant_id, current.parent_task_id)
            if not parent:
                break
            chain.insert(0, parent)
            if parent.source_agent_id in seen_agents:
                has_cycle = True
                cycle_agents.append(parent.source_agent_id)
            seen_agents.add(parent.source_agent_id)
            current = parent

        return DelegationChain(
            initiator=chain[0].source_agent_id,
            tasks=chain,
            total_depth=len(chain),
            has_cycle=has_cycle,
            cycle_agents=cycle_agents,
        )

    # ── Queries ───────────────────────────────────────────────────────

    def list_tasks(
        self,
        tenant_id: uuid.UUID,
        *,
        status: TaskStatus | None = None,
        agent_id: str | None = None,
        limit: int = 100,
    ) -> list[A2ATask]:
        """List tasks, optionally filtered."""
        tasks = sorted(
            self._tasks.get(tenant_id, {}).values(),
            key=lambda t: t.created_at,
            reverse=True,
        )
        if status:
            tasks = [t for t in tasks if t.status == status]
        if agent_id:
            tasks = [t for t in tasks if t.source_agent_id == agent_id or t.target_agent_id == agent_id]
        return tasks[:limit]

    def stats(self, tenant_id: uuid.UUID) -> dict[str, Any]:
        """Summary statistics for A2A tasks."""
        tasks = list(self._tasks.get(tenant_id, {}).values())
        status_counts: dict[str, int] = {}
        for t in tasks:
            status_counts[t.status.value] = status_counts.get(t.status.value, 0) + 1

        agents_involved: set[str] = set()
        for t in tasks:
            agents_involved.add(t.source_agent_id)
            agents_involved.add(t.target_agent_id)

        max_depth = max((t.chain_depth for t in tasks), default=0)

        return {
            "total_tasks": len(tasks),
            "by_status": status_counts,
            "unique_agents": len(agents_involved),
            "max_chain_depth": max_depth,
            "active_tasks": sum(1 for t in tasks if t.status in (TaskStatus.SUBMITTED, TaskStatus.WORKING)),
        }

    # ── Communication graph ───────────────────────────────────────────

    def communication_graph(self, tenant_id: uuid.UUID) -> dict[str, Any]:
        """Build a graph of agent-to-agent communications."""
        tasks = list(self._tasks.get(tenant_id, {}).values())
        nodes: dict[str, dict[str, Any]] = {}
        edges: list[dict[str, Any]] = []
        edge_counts: dict[tuple[str, str], int] = {}

        for t in tasks:
            for aid in (t.source_agent_id, t.target_agent_id):
                if aid not in nodes:
                    nodes[aid] = {"id": aid, "delegations_out": 0, "delegations_in": 0}

            nodes[t.source_agent_id]["delegations_out"] += 1
            nodes[t.target_agent_id]["delegations_in"] += 1

            key = (t.source_agent_id, t.target_agent_id)
            edge_counts[key] = edge_counts.get(key, 0) + 1

        for (src, tgt), count in edge_counts.items():
            edges.append({"source": src, "target": tgt, "weight": count})

        return {
            "nodes": list(nodes.values()),
            "edges": edges,
        }

    # ── Internal ──────────────────────────────────────────────────────

    def _find_by_task_id(self, tenant_id: uuid.UUID, task_id: str) -> A2ATask | None:
        for t in self._tasks.get(tenant_id, {}).values():
            if t.task_id == task_id:
                return t
        return None

    def _detect_cycle(
        self,
        tenant_id: uuid.UUID,
        source: str,
        target: str,
        parent_task_id: str | None,
    ) -> bool:
        """Check if delegating source→target creates a cycle."""
        if source == target:
            return True
        if not parent_task_id:
            return False

        seen = {source, target}
        current_id = parent_task_id
        while current_id:
            task = self._find_by_task_id(tenant_id, current_id)
            if not task:
                break
            if task.source_agent_id in seen:
                return True
            seen.add(task.source_agent_id)
            current_id = task.parent_task_id
        return False
