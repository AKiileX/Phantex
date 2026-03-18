# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Integration Registry (N1).

Maps platform names to their integration classes. Provides factory
method to instantiate integration adapters by name.
"""

from __future__ import annotations

from typing import Any

from app.integrations.base import BaseSIEMIntegration, IntegrationError

# Registry: platform_name → integration class
_REGISTRY: dict[str, type[BaseSIEMIntegration]] = {}

def register(cls: type[BaseSIEMIntegration]) -> type[BaseSIEMIntegration]:
    """Decorator to register an integration class."""
    _REGISTRY[cls.platform_name] = cls
    return cls

def get_integration(
    platform: str,
    *,
    tenant_id: str,
    config: dict[str, Any],
    rate_limit_per_min: int | None = None,
) -> BaseSIEMIntegration:
    """Create an integration instance by platform name.

    Raises IntegrationError if the platform is not registered.
    """
    cls = _REGISTRY.get(platform)
    if cls is None:
        raise IntegrationError(
            f"Unknown integration platform: {platform}. Available: {', '.join(sorted(_REGISTRY.keys()))}",
            retryable=False,
        )
    return cls(
        tenant_id=tenant_id,
        config=config,
        rate_limit_per_min=rate_limit_per_min,
    )

def list_platforms() -> list[dict[str, Any]]:
    """Return all registered integration platforms with metadata."""
    return [
        {
            "platform": name,
            "max_batch_size": cls.max_batch_size,
            "default_rate_limit": cls.default_rate_limit,
        }
        for name, cls in sorted(_REGISTRY.items())
    ]

# ── Register all P0 adapters ────────────────────────────────────────────────

def _register_all() -> None:
    """Import and register all built-in integrations."""
    from app.integrations.azure_sentinel import AzureSentinelIntegration
    from app.integrations.crowdstrike_logscale import CrowdStrikeLogScaleIntegration
    from app.integrations.elastic_siem import ElasticSIEMIntegration
    from app.integrations.splunk_hec import SplunkHECIntegration
    from app.integrations.syslog_cef import SyslogCEFIntegration

    register(SplunkHECIntegration)
    register(AzureSentinelIntegration)
    register(ElasticSIEMIntegration)
    register(CrowdStrikeLogScaleIntegration)
    register(SyslogCEFIntegration)

_register_all()
