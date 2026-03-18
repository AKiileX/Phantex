# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — SQLAlchemy Models.

Import all models here so SQLAlchemy can resolve relationships.
"""

from app.models.agent import Agent  # noqa: F401
from app.models.agent_policy import AlertRoutingRule, MaintenanceWindow, RuleExemption  # noqa: F401
from app.models.alert import Alert  # noqa: F401
from app.models.audit import AuditLog, RefreshToken  # noqa: F401
from app.models.event import Event  # noqa: F401

from app.models.mcp import MCPAnomaly, MCPScanResult, MCPServer  # noqa: F401

from app.models.permission import Permission, Role, RolePermission, UserRole  # noqa: F401
from app.models.policy import Policy, PolicyVersion  # noqa: F401
from app.models.rule import Rule  # noqa: F401
from app.models.sso import SCIMToken, SSOAssertionID, SSOConfig  # noqa: F401
from app.models.tenant import Tenant  # noqa: F401
from app.models.sensor import Sensor  # noqa: F401
from app.models.user import User  # noqa: F401
