# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex Rule Engine — PRL-based detection engine.

Consumes events from Kafka (consumer group `rule-engine`), evaluates
them against all enabled PRL rules, and creates alerts when rules match.

Architecture:
    Kafka topic: phantex.events.{tenant_id}
    Consumer group: rule-engine
    On startup: load all enabled rules from PostgreSQL, parse PRL → AST
    Hot reload: every 60s, re-fetch rules to pick up changes
    Per event:
      1. Deserialize JSON event from Kafka
      2. Build evaluation context dict
      3. Evaluate all enabled rules (skip disabled)
      4. If rule matches → create alert in PostgreSQL
      5. Record event in sliding window for count()/time_since()

Dependencies:
    - aiokafka (async Kafka consumer)
    - asyncpg via SQLAlchemy (database)
    - structlog (logging)

This module can be run standalone:
    python -m backend.engine.rule_engine

Or imported and started programmatically.
"""

from __future__ import annotations

import asyncio
import json
import signal
import time
import uuid
from dataclasses import dataclass
from typing import Any

import structlog

from engine.actions.actions import create_alert_action, log_match_action
from engine.evaluator.evaluator import EvalError, Evaluator
from engine.evaluator.functions import BuiltinRegistry, FunctionContext
from engine.parser import ast as ast_nodes
from engine.parser.parser import ParseError, Parser

logger = structlog.get_logger("phantex.engine")

# ── Configuration ─────────────────────────────────────────────────────────────

@dataclass
class EngineConfig:
    """Rule engine configuration."""

    kafka_bootstrap: str = "localhost:9092"
    consumer_group: str = "rule-engine"
    topic_pattern: str = r"phantex\.events\..*"

    # Alert publishing
    alert_topic_prefix: str = "phantex.alerts"

    # Database
    db_url: str = "postgresql+asyncpg://phantex_app:phantex_app@localhost:5432/phantex"

    # Hot reload interval (seconds)
    rule_reload_interval: float = 60.0

    # Performance
    max_rules_per_event: int = 500
    eval_timeout_ms: float = 10.0  # Per-event warn threshold

    # Graceful shutdown timeout
    shutdown_timeout: float = 10.0

# ── Compiled Rule Cache ───────────────────────────────────────────────────────

@dataclass
class CompiledRule:
    """A PRL rule compiled to an AST, ready for evaluation."""

    rule_id: uuid.UUID
    tenant_id: uuid.UUID | None
    name: str
    severity: str
    attack_class: str | None
    prl_source: str
    ast: ast_nodes.Rule
    enabled: bool = True
    version: int = 1

    # Counters
    match_count: int = 0
    eval_count: int = 0
    error_count: int = 0
    last_matched_at: float | None = None

# ── Rule Engine ───────────────────────────────────────────────────────────────

class RuleEngine:
    """
    The main rule engine. Loads rules, consumes Kafka events, evaluates
    rules, and creates alerts.

    Usage:
        engine = RuleEngine(config)
        await engine.start()  # Blocks until shutdown
    """

    # ── Default allowlists ─────────────────────────────────────────────────
    # Known-good destinations / paths / processes that AI agents use in normal
    # operation.  Operators can extend any of these via the dashboard or DB
    # config — no code deploy or rule restart required (hot-reload every 60s).

    # --- Network destinations (domains) ---
    _DEFAULT_ALLOWED_NETWORK_DESTS: set[str] = {
        # ── AI model API providers ──
        "api.openai.com",
        "api.anthropic.com",
        "generativelanguage.googleapis.com",
        "api.cohere.ai",
        "api.mistral.ai",
        "api.together.xyz",
        "api.replicate.com",
        "api.groq.com",
        "api.perplexity.ai",
        "api.deepseek.com",
        "api.x.ai",
        "api.fireworks.ai",
        "api.anyscale.com",
        "api.cerebras.ai",
        "inference.cerebras.ai",
        "api.sambanova.ai",
        # ── AI model hubs & registries ──
        "huggingface.co",
        "api-inference.huggingface.co",
        "cdn-lfs.huggingface.co",
        "cdn-lfs-us-1.huggingface.co",
        "ollama.com",
        "registry.ollama.ai",
        "civitai.com",
        # ── Google AI / Vertex ──
        "aiplatform.googleapis.com",
        "us-central1-aiplatform.googleapis.com",
        "europe-west1-aiplatform.googleapis.com",
        "asia-east1-aiplatform.googleapis.com",
        # ── Azure OpenAI ──
        "openai.azure.com",
        "cognitiveservices.azure.com",
        # ── AWS Bedrock ──
        "bedrock-runtime.us-east-1.amazonaws.com",
        "bedrock-runtime.us-west-2.amazonaws.com",
        "bedrock-runtime.eu-west-1.amazonaws.com",
        "bedrock.us-east-1.amazonaws.com",
        # ── Agent framework telemetry ──
        "api.smith.langchain.com",
        "api.langfuse.com",
        "api.wandb.ai",
        "api.comet.com",
        "api.helicone.ai",
        "otel.highlight.io",
        # ── Dev / package / container registries ──
        "api.github.com",
        "github.com",
        "gitlab.com",
        "pypi.org",
        "files.pythonhosted.org",
        "registry.npmjs.org",
        "www.npmjs.com",
        "registry.yarnpkg.com",
        "crates.io",
        "proxy.golang.org",
        "index.docker.io",
        "registry-1.docker.io",
        "ghcr.io",
        "mcr.microsoft.com",
        "www.googleapis.com",
        "storage.googleapis.com",
        # ── Common SaaS integrations ──
        "slack.com",
        "hooks.slack.com",
        "discord.com",
        "api.notion.com",
        "api.linear.app",
        "api.atlassian.com",
    }

    # --- File paths that are normal for AI agents to read ---
    _DEFAULT_ALLOWED_FILE_PATHS: set[str] = {
        # TLS / CA certificate stores (every HTTPS client reads these)
        "/etc/ssl/certs/",
        "/etc/ssl/cert.pem",
        "/usr/share/ca-certificates/",
        "/usr/local/share/ca-certificates/",
        "/etc/pki/tls/certs/",
        "/etc/ca-certificates/",
        "/usr/lib/ssl/certs/",
        # Model weight caches (local inference runtimes)
        "/.ollama/",
        "/.cache/huggingface/",
        "/.cache/lm-studio/",
        "/.cache/torch/",
        "/.cache/whisper/",
        "/.local/share/nomic.ai/",
        "/.cache/vllm/",
        # Python / Node standard library & site-packages
        "/usr/lib/python",
        "/usr/local/lib/python",
        "/usr/lib/node_modules/",
        # System timezone / locale data (queried by many runtimes)
        "/usr/share/zoneinfo/",
        "/etc/localtime",
        "/usr/share/locale/",
    }

    # --- Process names (comm) that are known AI runtime binaries ---
    _DEFAULT_ALLOWED_PROCESS_COMMS: set[str] = {
        # Local LLM inference servers
        "ollama",
        "ollama-runner",
        "llama-server",
        "llama-cli",
        "llamacpp",
        "lms",               # LM Studio CLI
        "lmstudio-server",
        "vllm",
        "text-generation",   # text-generation-inference (HuggingFace TGI)
        "tritonserver",      # NVIDIA Triton
        "localai",
        # Python / Node runtimes (AI agent host processes)
        "python",
        "python3",
        "python3.10",
        "python3.11",
        "python3.12",
        "python3.13",
        "node",
        # Package managers (legitimate installs by agents)
        "pip",
        "pip3",
        "npm",
        "uv",
    }

    def __init__(self, config: EngineConfig | None = None) -> None:
        self.config = config or EngineConfig()
        self._rules: dict[uuid.UUID, CompiledRule] = {}
        self._evaluator = Evaluator(functions=BuiltinRegistry())
        self._func_ctx = FunctionContext()
        self._running = False
        self._shutdown_event = asyncio.Event()

        # Seed default allowlists so that rules don't alert on known,
        # legitimate AI agent operations.  Operators extend via dashboard.
        self._func_ctx.allowlists["allowed_network_destinations"] = set(self._DEFAULT_ALLOWED_NETWORK_DESTS)
        self._func_ctx.allowlists["allowed_file_paths"] = set(self._DEFAULT_ALLOWED_FILE_PATHS)
        self._func_ctx.allowlists["allowed_process_comms"] = set(self._DEFAULT_ALLOWED_PROCESS_COMMS)
        logger.info(
            "allowlists_initialized",
            allowed_network_destinations=len(self._DEFAULT_ALLOWED_NETWORK_DESTS),
            allowed_file_paths=len(self._DEFAULT_ALLOWED_FILE_PATHS),
            allowed_process_comms=len(self._DEFAULT_ALLOWED_PROCESS_COMMS),
        )

        # Alert publisher (initialized in start())
        self._alert_publisher = None

        # Metrics
        self._events_processed: int = 0
        self._events_errored: int = 0
        self._alerts_created: int = 0
        self._eval_errors: int = 0
        self._last_reload: float = 0

    # ── Public API ────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start the rule engine: load rules, start alert publisher, start Kafka consumer."""
        logger.info("engine_starting", config=self.config)
        self._running = True

        # Initialize alert publisher
        await self._start_alert_publisher()

        # Seed core rules from .prl files into database (idempotent)
        try:
            from rules.loader import seed_core_rules
            result = await seed_core_rules()
            logger.info("core_rules_seeded", **result)
        except Exception as e:
            logger.warning("core_rule_seeding_failed", error=str(e))

        # Load rules from database
        await self._load_rules()

        # Start Kafka consumer and reload tasks
        try:
            await asyncio.gather(
                self._consume_loop(),
                self._reload_loop(),
            )
        except asyncio.CancelledError:
            logger.info("engine_cancelled")
        finally:
            self._running = False
            await self._stop_alert_publisher()
            logger.info(
                "engine_stopped",
                events_processed=self._events_processed,
                alerts_created=self._alerts_created,
            )

    async def stop(self) -> None:
        """Signal graceful shutdown."""
        logger.info("engine_stop_requested")
        self._running = False
        self._shutdown_event.set()

    async def _start_alert_publisher(self) -> None:
        """Initialize and start the Kafka alert publisher."""
        try:
            from engine.alerting.publisher import AlertPublisher

            self._alert_publisher = AlertPublisher(
                kafka_bootstrap=self.config.kafka_bootstrap,
                topic_prefix=self.config.alert_topic_prefix,
            )
            await self._alert_publisher.start()
            logger.info("alert_publisher_initialized")
        except Exception as e:
            logger.warning(
                "alert_publisher_init_failed",
                error=str(e),
                msg="Alerts will be written to DB only (no Kafka publish)",
            )
            self._alert_publisher = None

    async def _stop_alert_publisher(self) -> None:
        """Stop the Kafka alert publisher."""
        if self._alert_publisher:
            try:
                await self._alert_publisher.stop()
            except Exception as e:
                logger.warning("alert_publisher_stop_failed", error=str(e))

    def evaluate_event(
        self,
        event_data: dict[str, Any],
        tenant_id: str | None = None,
    ) -> list[CompiledRule]:
        """
        Evaluate an event against all enabled rules.
        Returns list of rules that matched.

        This is the core hot path — must be fast.
        Can be called directly for testing without Kafka.
        """
        matched: list[CompiledRule] = []
        context = self._build_context(event_data)

        for rule in self._rules.values():
            if not rule.enabled:
                continue

            # Filter by tenant
            if rule.tenant_id is not None and tenant_id is not None and str(rule.tenant_id) != tenant_id:
                continue

            rule.eval_count += 1

            try:
                result = self._evaluator.evaluate(
                    rule.ast,
                    context,
                    self._func_ctx,
                )
                if result:
                    rule.match_count += 1
                    rule.last_matched_at = time.time()
                    matched.append(rule)

                    # Only log matches — non-match logging at DEBUG is too
                    # expensive on the hot path (500K calls/sec at scale).
                    log_match_action(
                        rule_name=rule.name,
                        rule_severity=rule.severity,
                        event_type=event_data.get("event_type", "unknown"),
                        tenant_id=tenant_id or "global",
                        matched=True,
                    )

                    # E-03: Enforce max_rules_per_event cap
                    if len(matched) >= self.config.max_rules_per_event:
                        logger.warning(
                            "max_rules_per_event_reached",
                            limit=self.config.max_rules_per_event,
                            event_type=event_data.get("event_type", "unknown"),
                        )
                        break
            except EvalError as e:
                rule.error_count += 1
                self._eval_errors += 1
                logger.warning(
                    "rule_eval_error",
                    rule_name=rule.name,
                    rule_id=str(rule.rule_id),
                    error=str(e),
                )

        return matched

    def load_rule(self, rule_id: uuid.UUID, prl_source: str, **kwargs: Any) -> CompiledRule:
        """
        Compile and register a single rule. Used for testing and hot-reload.
        Raises ParseError if the PRL is invalid.
        """
        parser = Parser(prl_source)
        ast = parser.parse()

        compiled = CompiledRule(
            rule_id=rule_id,
            tenant_id=kwargs.get("tenant_id"),
            name=kwargs.get("name", "unnamed"),
            severity=kwargs.get("severity", "medium"),
            attack_class=kwargs.get("attack_class"),
            prl_source=prl_source,
            ast=ast,
            enabled=kwargs.get("enabled", True),
            version=kwargs.get("version", 1),
        )

        self._rules[rule_id] = compiled
        return compiled

    @property
    def rules(self) -> dict[uuid.UUID, CompiledRule]:
        return self._rules

    @property
    def func_ctx(self) -> FunctionContext:
        return self._func_ctx

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "events_processed": self._events_processed,
            "alerts_created": self._alerts_created,
            "eval_errors": self._eval_errors,
            "rules_loaded": len(self._rules),
            "rules_enabled": sum(1 for r in self._rules.values() if r.enabled),
        }

    # ── Event Context Builder ─────────────────────────────────────────────

    @staticmethod
    def _build_context(event_data: dict[str, Any]) -> dict[str, Any]:
        """
        Build the evaluation context from a raw event dict.

        The context exposes:
          event.type, event.severity, event.agent_id, event.raw_data.*
          event.sensor_id, event.timestamp
        """
        # Cap for raw_data string parsing to prevent memory abuse (1 MB)
        _MAX_RAW_DATA_STR = 1_048_576

        raw_data = event_data.get("raw_data", {})
        if isinstance(raw_data, str):
            if len(raw_data) > _MAX_RAW_DATA_STR:
                raw_data = {}
            else:
                try:
                    raw_data = json.loads(raw_data)
                except (json.JSONDecodeError, TypeError):
                    raw_data = {}

        # Flatten protobuf oneof payload wrapper.
        # _protobuf_to_dict wraps payload in {"tool_call": {...}} or
        # {"process_exec": {...}} etc.  PRL rules expect flat access like
        # event.raw_data.tool_input, so unwrap the single-key wrapper.
        # We also preserve the original wrapper key so that rules can
        # reference nested paths (e.g. event.raw_data.network.dst_addr).
        if isinstance(raw_data, dict) and len(raw_data) == 1:
            key = next(iter(raw_data))
            val = raw_data[key]
            if isinstance(val, dict):
                merged = dict(val)
                merged[key] = val
                raw_data = merged

        return {
            "event": {
                "type": event_data.get("event_type", ""),
                "severity": event_data.get("severity", "info"),
                "agent_id": str(event_data.get("agent_id", "")),
                "sensor_id": str(event_data.get("sensor_id", "")),
                "timestamp": event_data.get("timestamp", ""),
                "raw_data": raw_data,
            },
        }

    # ── Kafka Consumer Loop ───────────────────────────────────────────────

    async def _consume_loop(self) -> None:
        """
        Main Kafka consumption loop.

        Imports aiokafka at runtime to allow the engine module to be imported
        without Kafka installed (for testing).
        """
        try:
            from aiokafka import AIOKafkaConsumer
        except ImportError:
            logger.error(
                "aiokafka_not_installed",
                msg="Install aiokafka: pip install aiokafka",
            )
            return

        consumer = AIOKafkaConsumer(
            bootstrap_servers=self.config.kafka_bootstrap,
            group_id=self.config.consumer_group,
            auto_offset_reset="latest",
            enable_auto_commit=True,
            auto_commit_interval_ms=5000,
        )

        # Subscribe to topic pattern
        consumer.subscribe(pattern=self.config.topic_pattern)

        await consumer.start()
        logger.info("kafka_consumer_started", group=self.config.consumer_group)

        try:
            while self._running:
                try:
                    batch = await asyncio.wait_for(
                        consumer.getmany(timeout_ms=1000, max_records=100),
                        timeout=5.0,
                    )
                except TimeoutError:
                    continue

                for tp, messages in batch.items():
                    for msg in messages:
                        event_data = self._deserialize(msg.value)
                        if event_data is not None:
                            await self._process_event(event_data, tp.topic)

        finally:
            await consumer.stop()
            logger.info("kafka_consumer_stopped")

    def _deserialize(self, raw: bytes | None) -> dict[str, Any] | None:
        """Deserialize a Kafka message value (JSON or protobuf)."""
        if not raw:
            return None
        # Fast-path: JSON starts with '{'
        if raw[0:1] == b"{":
            try:
                return json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
        # Fallback: try protobuf
        try:
            from app.consumers.base_consumer import _protobuf_to_dict

            result = _protobuf_to_dict(raw)
            if result is not None:
                return result
        except ImportError:
            pass
        # Final fallback: try JSON anyway
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._events_errored += 1
            return None

    async def _process_event(self, event_data: dict[str, Any], topic: str) -> None:
        """Process one event from Kafka."""
        self._events_processed += 1
        event_type = event_data.get("event_type", "unknown")

        # Extract tenant_id from topic (phantex.events.<tenant_id>)
        tenant_id = None
        parts = topic.split(".")
        if len(parts) >= 3:
            tenant_id = parts[2]

        # Extract agent_id from event data
        agent_id = event_data.get("agent_id")

        # Build field_values for count_distinct tracking
        field_values: dict[str, str] = {}
        raw_data = event_data.get("raw_data") or {}
        if isinstance(raw_data, dict):
            # Flatten protobuf oneof wrapper for field extraction
            if len(raw_data) == 1:
                first_val = next(iter(raw_data.values()))
                if isinstance(first_val, dict):
                    raw_data = first_val
            # Track filename for FILE_READ/FILE_OPEN events
            if "filename" in raw_data:
                field_values["raw_data.filename"] = str(raw_data["filename"])
            # Track tool_name for TOOL_CALL events
            if "tool_name" in raw_data:
                field_values["raw_data.tool_name"] = str(raw_data["tool_name"])
            # Track dst_addr for NETWORK_CONNECT events
            network = raw_data.get("network") or {}
            if isinstance(network, dict) and "dst_addr" in network:
                field_values["raw_data.network.dst_addr"] = str(network["dst_addr"])

        # Record in sliding window for count()/count_distinct()/time_since() — scoped per tenant+agent
        self._func_ctx.record_event(
            event_type,
            tenant_id=tenant_id,
            agent_id=agent_id,
            field_values=field_values if field_values else None,
        )

        # Evaluate against all rules
        start = time.monotonic()
        matched_rules = self.evaluate_event(event_data, tenant_id)
        elapsed_ms = (time.monotonic() - start) * 1000

        if elapsed_ms > self.config.eval_timeout_ms:
            logger.warning(
                "slow_evaluation",
                elapsed_ms=round(elapsed_ms, 2),
                event_type=event_type,
                rules_count=len(self._rules),
            )

        # Create alerts for matched rules
        if matched_rules and tenant_id:
            await self._create_alerts(matched_rules, event_data, tenant_id)

    async def _create_alerts(
        self,
        matched_rules: list[CompiledRule],
        event_data: dict[str, Any],
        tenant_id: str,
    ) -> None:
        """Create alerts in PostgreSQL for all matched rules, then publish to Kafka."""
        try:
            from app.database import get_tenant_session
        except ImportError:
            logger.warning("database_not_available", msg="Cannot import app.database")
            return

        # Parse UUIDs once before the loop (E-02 fix)
        try:
            tenant_uuid = uuid.UUID(tenant_id)
        except (ValueError, AttributeError):
            logger.error("invalid_tenant_id", tenant_id=tenant_id)
            return

        event_id: uuid.UUID | None = None
        agent_id: str | None = None
        try:
            event_id_str = event_data.get("event_id")
            event_id = uuid.UUID(event_id_str) if event_id_str else None
        except (ValueError, AttributeError):
            logger.warning("invalid_event_id", event_id=event_data.get("event_id"))

        # agent_id is a PAID string (e.g. ptx-default-dev-...), not a UUID
        agent_id_str = event_data.get("agent_id")
        agent_id = agent_id_str if agent_id_str else None

        try:
            async with get_tenant_session(tenant_id) as session:
                for rule in matched_rules:
                    try:
                        alert = await create_alert_action(
                            session,
                            tenant_id=tenant_uuid,
                            rule_id=rule.rule_id,
                            rule_name=rule.name,
                            rule_severity=rule.severity,
                            event_id=event_id,
                            agent_id=agent_id,
                            event_type=event_data.get("event_type", "unknown"),
                            event_data=event_data,
                        )
                        self._alerts_created += 1

                        # Publish to Kafka + WebSocket broadcast
                        await self._publish_alert(
                            alert=alert,
                            rule=rule,
                            event_data=event_data,
                            tenant_id=tenant_id,
                        )

                        # ── Auto-Response Decision Layer ──────────────
                        # Evaluate alert against response policies and
                        # dispatch enforcement (or shadow-log) if matched.
                        # Wrapped in try/except — MUST NOT block alerts.
                        try:
                            await self._evaluate_auto_response(
                                session=session,
                                alert=alert,
                                rule=rule,
                                event_data=event_data,
                                tenant_id=tenant_id,
                            )
                        except Exception as ar_err:
                            logger.error(
                                "auto_response_evaluation_failed",
                                alert_id=str(alert.id),
                                error=str(ar_err),
                            )
                    except Exception as e:
                        logger.error(
                            "alert_creation_failed",
                            rule_name=rule.name,
                            error=str(e),
                        )
        except Exception as e:
            logger.error("db_session_failed", error=str(e), tenant_id=tenant_id)

    async def _evaluate_auto_response(
        self,
        session: Any,
        alert: Any,
        rule: CompiledRule,
        event_data: dict[str, Any],
        tenant_id: str,
    ) -> None:
        """
        Evaluate an alert against auto-response policies and dispatch if matched.

        This is the integration point between the detection pipeline and the
        response decision layer. It MUST NOT raise — callers wrap in try/except.
        """
        try:
            from app.services.response.orchestrator import handle_alert
        except ImportError:
            # Auto-response module not available (e.g., test environment)
            return

        confidence = 0.0
        if hasattr(rule, "confidence"):
            confidence = float(rule.confidence)
        elif isinstance(event_data, dict):
            confidence = float(event_data.get("confidence", event_data.get("ml_confidence", 0.0)))

        result = await handle_alert(
            session,
            tenant_id=tenant_id,
            alert_id=str(alert.id),
            agent_id=str(alert.agent_id) if alert.agent_id else None,
            severity=rule.severity or "medium",
            confidence=confidence,
            attack_class=rule.attack_class or "",
            event_type=event_data.get("event_type", "unknown"),
            event_data=event_data,
        )

        if result:
            logger.info(
                "auto_response_result",
                alert_id=str(alert.id),
                action=result.action,
                decision=result.decision,
                success=result.success,
            )

    async def _publish_alert(
        self,
        alert: Any,
        rule: CompiledRule,
        event_data: dict[str, Any],
        tenant_id: str,
    ) -> None:
        """Publish an alert to Kafka topic and in-memory broadcast."""
        if not self._alert_publisher:
            return

        try:
            from engine.alerting.publisher import build_alert_payload

            payload = build_alert_payload(
                alert_id=alert.id,
                tenant_id=alert.tenant_id,
                rule_id=rule.rule_id,
                rule_name=rule.name,
                severity=rule.severity,
                attack_class=rule.attack_class,
                agent_id=alert.agent_id,
                event_id=alert.event_id,
                event_type=event_data.get("event_type", "unknown"),
                event_data=event_data,
                title=alert.title,
                description=alert.description or "",
                timestamp=alert.created_at.isoformat() if alert.created_at else None,
            )

            await self._alert_publisher.publish_alert(payload, tenant_id)

        except Exception as e:
            logger.warning(
                "alert_publish_failed",
                alert_id=str(alert.id),
                error=str(e),
            )

    # ── Rule Reload Loop ──────────────────────────────────────────────────

    async def _reload_loop(self) -> None:
        """Periodically reload rules from the database."""
        while self._running:
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=self.config.rule_reload_interval,
                )
                break  # Shutdown was signaled
            except TimeoutError:
                pass  # Timeout = time to reload

            try:
                await self._load_rules()
            except Exception as e:
                logger.error("rule_reload_failed", error=str(e))

    async def _load_rules(self) -> None:
        """Load all enabled rules from the database and compile them."""
        try:
            from sqlalchemy import select

            from app.database import admin_session_factory
            from app.models.rule import Rule
        except ImportError:
            logger.warning(
                "database_not_available",
                msg="Cannot import database modules. Using existing rules.",
            )
            return

        try:
            async with admin_session_factory() as session:
                result = await session.execute(select(Rule).where(Rule.enabled.is_(True)))
                db_rules = list(result.scalars().all())

            new_rules: dict[uuid.UUID, CompiledRule] = {}
            compile_errors = 0

            for db_rule in db_rules:
                try:
                    parser = Parser(db_rule.prl_source)
                    ast = parser.parse()

                    # Preserve counters from existing compiled rule
                    existing = self._rules.get(db_rule.id)

                    compiled = CompiledRule(
                        rule_id=db_rule.id,
                        tenant_id=db_rule.tenant_id,
                        name=db_rule.name,
                        severity=db_rule.severity,
                        attack_class=db_rule.attack_class,
                        prl_source=db_rule.prl_source,
                        ast=ast,
                        enabled=db_rule.enabled,
                        version=db_rule.version,
                    )

                    if existing:
                        compiled.match_count = existing.match_count
                        compiled.eval_count = existing.eval_count
                        compiled.error_count = existing.error_count
                        compiled.last_matched_at = existing.last_matched_at

                    new_rules[db_rule.id] = compiled

                except ParseError as e:
                    compile_errors += 1
                    logger.error(
                        "rule_compile_error",
                        rule_id=str(db_rule.id),
                        rule_name=db_rule.name,
                        error=str(e),
                    )

            self._rules = new_rules
            self._last_reload = time.time()

            logger.info(
                "rules_loaded",
                total=len(db_rules),
                compiled=len(new_rules),
                errors=compile_errors,
            )

        except Exception as e:
            logger.error("rule_load_failed", error=str(e))

# ── Standalone Entry Point ────────────────────────────────────────────────────

async def main() -> None:
    """Run the rule engine as a standalone process."""
    import os

    config = EngineConfig(
        kafka_bootstrap=os.getenv("PHANTEX_KAFKA_BOOTSTRAP", os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")),
        db_url=os.getenv(
            "DATABASE_URL",
            "postgresql+asyncpg://{}:{}@{}:{}/{}".format(
                os.getenv("PHANTEX_DB_USER", "phantex_app"),
                os.getenv("PHANTEX_DB_PASSWORD", "phantex_app"),
                os.getenv("PHANTEX_DB_HOST", "localhost"),
                os.getenv("PHANTEX_DB_PORT", "5432"),
                os.getenv("PHANTEX_DB_NAME", "phantex"),
            ),
        ),
    )

    engine = RuleEngine(config)

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, lambda: asyncio.create_task(engine.stop()))
        except NotImplementedError:
            pass  # Windows doesn't support add_signal_handler

    await engine.start()

if __name__ == "__main__":
    asyncio.run(main())
