# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Pydantic schemas — Dashboard (aggregate stats)."""

from pydantic import BaseModel

class DashboardStats(BaseModel):
    """Dashboard summary statistics for the current tenant."""

    total_agents: int = 0
    active_agents: int = 0
    total_events: int = 0
    events_last_24h: int = 0
    total_alerts: int = 0
    open_alerts: int = 0
    critical_alerts: int = 0
    total_rules: int = 0
    enabled_rules: int = 0

class AlertsByDay(BaseModel):
    """Alert count grouped by day (for charts)."""

    date: str
    count: int

class EventsByType(BaseModel):
    """Event count grouped by type (for charts)."""

    event_type: str
    count: int
