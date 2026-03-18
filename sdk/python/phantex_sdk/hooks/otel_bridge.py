# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex SDK — OpenTelemetry OTLP Export Bridge.

When customers have existing OTel infrastructure (Jaeger, Tempo, etc.),
this bridge exports Phantex SDK events as OTel spans to an OTLP collector.

Activation: Set PHANTEX_OTEL_ENDPOINT (e.g., "http://localhost:4317").
The bridge is additive — events still go to the normal Phantex transport.

Security:
- No credentials embedded; auth via OTEL_EXPORTER_OTLP_HEADERS env var
- No PII in span attributes — tool_input is hashed, prompts never exported
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any

logger = logging.getLogger("phantex.otel")

# ── Lazy OTel imports (heavy deps — only load when used) ──────────────────────

_tracer = None
_OTEL_AVAILABLE = False
_tracer_lock = threading.Lock()

def _init_otel_tracer():
    """Initialize OTel tracer if OTLP endpoint is configured."""
    global _tracer, _OTEL_AVAILABLE
    if _tracer is not None:
        return _tracer

    with _tracer_lock:
        # Double-check under lock
        if _tracer is not None:
            return _tracer

        endpoint = os.environ.get("PHANTEX_OTEL_ENDPOINT", "")
        if not endpoint:
            return None

        try:
            from opentelemetry import trace
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor

            resource = Resource.create(
                {
                    "service.name": "phantex-sdk",
                    "service.version": os.environ.get("PHANTEX_SDK_VERSION", "2.0.0"),
                }
            )

            provider = TracerProvider(resource=resource)
            exporter = OTLPSpanExporter(endpoint=endpoint, insecure=endpoint.startswith("http://"))
            provider.add_span_processor(BatchSpanProcessor(exporter))
            trace.set_tracer_provider(provider)

            _tracer = trace.get_tracer("phantex.sdk", "2.0.0")
            _OTEL_AVAILABLE = True
            logger.info("OTel bridge initialized → %s", endpoint)
            return _tracer
        except ImportError:
            logger.debug("opentelemetry packages not installed — OTel bridge disabled")
            return None
        except Exception as e:
            logger.warning("OTel bridge init failed: %s", type(e).__name__)
            return None

def is_otel_enabled() -> bool:
    """Check if OTel export is active."""
    return _OTEL_AVAILABLE and _tracer is not None

class OTelBridge:
    """
    Bridges Phantex SDK events to OpenTelemetry spans.

    Usage:
        bridge = OTelBridge()
        if bridge.enabled:
            ctx = bridge.start_span("tool_call", {"tool.name": "search"})
            # ... do work ...
            bridge.end_span(ctx, success=True)
    """

    def __init__(self) -> None:
        self._tracer = _init_otel_tracer()

    @property
    def enabled(self) -> bool:
        return self._tracer is not None

    def start_span(
        self,
        operation: str,
        attributes: dict[str, Any] | None = None,
    ) -> Any | None:
        """Start an OTel span. Returns opaque context or None if disabled."""
        if not self._tracer:
            return None

        try:
            from opentelemetry import context as otel_ctx
            from opentelemetry import trace

            span = self._tracer.start_span(
                name=f"phantex.{operation}",
                attributes=_sanitize_attributes(attributes or {}),
            )
            ctx = trace.set_span_in_context(span)
            token = otel_ctx.attach(ctx)
            return _SpanHandle(span=span, token=token)
        except Exception as e:
            logger.debug("OTel start_span failed: %s", type(e).__name__)
            return None

    def end_span(
        self,
        handle: Any | None,
        success: bool = True,
        attributes: dict[str, Any] | None = None,
    ) -> None:
        """End a previously started span."""
        if handle is None or not isinstance(handle, _SpanHandle):
            return

        try:
            from opentelemetry import context as otel_ctx
            from opentelemetry.trace import StatusCode

            if attributes:
                for k, v in _sanitize_attributes(attributes).items():
                    handle.span.set_attribute(k, v)

            status = StatusCode.OK if success else StatusCode.ERROR
            handle.span.set_status(status)
            handle.span.end()
            otel_ctx.detach(handle.token)
        except Exception as e:
            logger.debug("OTel end_span failed: %s", type(e).__name__)

class _SpanHandle:
    """Opaque handle for an active OTel span."""

    __slots__ = ("span", "token")

    def __init__(self, span: Any, token: Any) -> None:
        self.span = span
        self.token = token

def _sanitize_attributes(attrs: dict[str, Any]) -> dict[str, str | int | float | bool]:
    """
    Sanitize attributes for OTel — only primitive types allowed.
    Truncate strings to 256 chars. Never export raw prompts.
    """
    result: dict[str, str | int | float | bool] = {}
    _FORBIDDEN_KEYS = {"prompt", "prompt_content", "tool_input_raw", "password", "secret", "token"}

    for k, v in attrs.items():
        if k.lower() in _FORBIDDEN_KEYS:
            continue
        if isinstance(v, bool | int | float):
            result[k] = v
        elif isinstance(v, str):
            result[k] = v[:256]
        else:
            result[k] = str(v)[:256]

    return result
