# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex Backend — FastAPI Application Entry Point.

Creates the FastAPI app with:
- All API routers mounted
- CORS middleware (restricted origins)
- Security headers middleware
- Rate limiting
- Structured logging
- OpenAPI docs at /docs
"""

import asyncio
from contextlib import asynccontextmanager, suppress

from fastapi import Depends, FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# ── Routers ───────────────────────────────────────────────────────────────────
import app.models  # noqa: F401 — ensure all SQLAlchemy models are registered
from app.config import get_settings

# System Nerve Center

# Response Actions (gateway ↔ backend internal API)

from app.routers import (
    a2a,
    agents,
    alerts,
    analytics,
    analytics_v2,
    audit_recording,
    auth,
    cloud_telemetry,
    compliance,
    copilot,
    copilot_config,
    dashboard,
    data_classification,
    deception,
    drift,
    events,
    exports,
    finops,
    health,
    integrations,
    internal_commands,
    internal_sensors,
    investigation,
    mcp_supply_chain,
    ml,
    nerve_center,
    notifications,
    policies,
    red_team,
    roles,
    rules,
    sensors,
    soar,
    sso,
    telemetry,
    tenants,
    threat_intel,
    timeline,
    trust,
    users,
    verification,
    ws,
)

# Automated Response Engine (decision layer)
from app.routers import response as response_router
from app.routers.agent_policy import exemption_router, routing_router, tag_router, window_router
from app.routers.scim import scim_router
from app.routers.scim import token_router as scim_token_router
from app.utils.logging import get_logger, setup_logging

settings = get_settings()
logger = get_logger("phantex.main")

# ── Lifespan (startup / shutdown) ────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown hooks."""
    setup_logging()
    logger.info(
        "phantex_api_starting",
        version=settings.app_version,
        environment=settings.environment,
        host=settings.host,
        port=settings.port,
    )

    # ── Initialize AlertBroadcaster + WebSocket manager ──────────────
    from app.middleware.rate_limit import cleanup_all as rate_limit_cleanup
    from app.routers.ws import set_ws_manager
    from app.services.auth_service import (
        cleanup_email_attempts,
        close_vault_jwt_signer,
        init_vault_jwt_signer,
    )
    from app.services.kafka_bridge import KafkaAlertBridge
    from app.services.pdr_schedule_runner import PDRScheduleRunner
    from engine.alerting.publisher import AlertBroadcaster
    from engine.alerting.ws_manager import WebSocketAlertManager

    # ── Vault Transit JWT signing (RS256, key never leaves Vault) ────
    await init_vault_jwt_signer()

    broadcaster = AlertBroadcaster()
    ws_manager = WebSocketAlertManager(
        broadcaster,
        max_connections_per_tenant=settings.ws_max_connections_per_tenant,
    )
    set_ws_manager(ws_manager)

    # Store broadcaster on app.state so the rule engine can access it
    app.state.alert_broadcaster = broadcaster

    logger.info("alert_websocket_initialized")

    # ── Start Kafka → WebSocket bridge ───────────────────────────────
    kafka_ssl_ctx = None
    if settings.kafka_tls_enabled:
        import ssl as _ssl

        kafka_ssl_ctx = _ssl.create_default_context()
        if settings.kafka_tls_ca_file:
            kafka_ssl_ctx.load_verify_locations(settings.kafka_tls_ca_file)
        if settings.kafka_tls_cert_file and settings.kafka_tls_key_file:
            kafka_ssl_ctx.load_cert_chain(settings.kafka_tls_cert_file, settings.kafka_tls_key_file)
        logger.info("kafka_tls_enabled", ca=settings.kafka_tls_ca_file)

    kafka_bridge = KafkaAlertBridge(
        broadcaster,
        bootstrap_servers=settings.kafka_bootstrap,
        topic_pattern=rf"^{settings.kafka_alert_topic_prefix}\..+$",
        consumer_group=settings.kafka_consumer_group,
        ssl_context=kafka_ssl_ctx,
    )
    await kafka_bridge.start()
    app.state.kafka_bridge = kafka_bridge

    logger.info("kafka_bridge_initialized")

    # ── Scheduled PDR exports ───────────────────────────────────────
    pdr_schedule_runner = PDRScheduleRunner()
    await pdr_schedule_runner.start()
    app.state.pdr_schedule_runner = pdr_schedule_runner

    # ── Redis (I1 — rate limiting, WS tickets, pub/sub) ─────────────
    from app.middleware.rate_limit import set_redis_rate_limiters
    from app.services.redis_client import close_redis, get_redis
    from app.services.redis_rate_limit import RedisSlidingWindowLimiter

    redis_client = await get_redis()
    if redis_client is not None:
        try:
            pong = await redis_client.ping()
            if pong:
                # Wire Redis-backed rate limiters
                general_limiter = RedisSlidingWindowLimiter(
                    redis_client,
                    rate=float(settings.rate_limit_per_second),
                    window_seconds=1.0,
                    key_prefix="rl:general:",
                )
                auth_limiter = RedisSlidingWindowLimiter(
                    redis_client,
                    rate=5.0,
                    window_seconds=1.0,
                    key_prefix="rl:auth:",
                )
                sso_limiter = RedisSlidingWindowLimiter(
                    redis_client,
                    rate=10.0 / 60.0,
                    window_seconds=60.0,
                    key_prefix="rl:sso:",
                )
                set_redis_rate_limiters(general_limiter, auth_limiter, sso_limiter)
                logger.info("redis_rate_limiters_initialized")
        except Exception as e:
            logger.warning("redis_init_failed", error=str(e), msg="Falling back to in-memory rate limiter")

    # ── Periodic rate-limit cleanup (every 60s) ──────────────────────
    _cleanup_running = True

    async def _rate_limit_cleanup_loop() -> None:
        """Remove stale rate-limiter buckets and email attempt entries every 60 seconds."""
        while _cleanup_running:
            await asyncio.sleep(60)
            try:
                removed = rate_limit_cleanup()
                email_removed = cleanup_email_attempts()
                if removed > 0 or email_removed > 0:
                    logger.debug("rate_limit_cleanup", entries_removed=removed, email_entries_removed=email_removed)
            except Exception as e:
                logger.warning("rate_limit_cleanup_error", error=str(e))

    cleanup_task = asyncio.create_task(_rate_limit_cleanup_loop(), name="rate-limit-cleanup")

    # ── Periodic sensor status refresh (every 60s) ──────────────────
    _sensor_refresh_running = True

    async def _sensor_status_refresh_loop() -> None:
        """Mark sensors as degraded/offline based on last_heartbeat age."""
        from app.database import async_session_factory
        from app.services.sensor_service import refresh_sensor_statuses

        while _sensor_refresh_running:
            await asyncio.sleep(60)
            try:
                async with async_session_factory() as db:
                    updated = await refresh_sensor_statuses(db)
                    await db.commit()
                    if updated > 0:
                        logger.info("sensor_status_refresh", sensors_updated=updated)
            except Exception as e:
                logger.warning("sensor_status_refresh_error", error=str(e))

    sensor_refresh_task = asyncio.create_task(
        _sensor_status_refresh_loop(), name="sensor-status-refresh"
    )

    # ── Periodic agent status refresh (every 60s) ───────────────────
    _agent_refresh_running = True

    async def _agent_status_refresh_loop() -> None:
        """Mark agents as stale/offline based on last_seen age."""
        from app.database import async_session_factory
        from app.services.agent_service import refresh_agent_statuses

        while _agent_refresh_running:
            await asyncio.sleep(60)
            try:
                async with async_session_factory() as db:
                    updated = await refresh_agent_statuses(db)
                    await db.commit()
                    if updated > 0:
                        logger.info("agent_status_refresh", agents_updated=updated)
            except Exception as e:
                logger.warning("agent_status_refresh_error", error=str(e))

    agent_refresh_task = asyncio.create_task(
        _agent_status_refresh_loop(), name="agent-status-refresh"
    )

    # ── ML components (model loader, retrain, meta-detection) ────────
    _retrain_worker_instance = None
    try:
        from app.routers.ml import set_ml_components
        from ml.meta.accuracy_tracker import AccuracyTracker
        from ml.meta.alerter import MetaAlerter
        from ml.meta.drift_detector import DriftDetector
        from ml.registry.model_registry import ModelRegistry
        from ml.retrain.pipeline import RetrainPipeline
        from ml.retrain.scheduler import RetrainScheduler
        from ml.retrain.worker import RetrainWorker
        from ml.serving.model_loader import ModelLoader

        ml_registry = ModelRegistry()
        ml_loader = ModelLoader(ml_registry)
        ml_scheduler = RetrainScheduler()
        ml_pipeline = RetrainPipeline(ml_registry, ml_loader, ml_scheduler)
        _retrain_worker_instance = RetrainWorker(ml_pipeline, ml_scheduler)
        ml_accuracy = AccuracyTracker()
        ml_drift = DriftDetector()
        ml_meta = MetaAlerter()

        set_ml_components(
            model_loader=ml_loader,
            retrain_scheduler=ml_scheduler,
            retrain_worker=_retrain_worker_instance,
            retrain_pipeline=ml_pipeline,
            accuracy_tracker=ml_accuracy,
            drift_detector=ml_drift,
            meta_alerter=ml_meta,
        )

        # ── Eagerly load global model from registry so /ml/global-model
        #    reflects the real state (the inference consumer process
        #    trains & saves the model; the API process just needs to
        #    discover it from the shared filesystem registry).
        try:
            _gm = ml_loader.get_global_ensemble()
            if _gm is not None:
                logger.info("global_model_loaded_in_api", version=ml_loader.global_manager.version)
            else:
                logger.info("global_model_not_yet_available")
        except Exception as _e:
            logger.warning("global_model_eager_load_failed", error=str(_e))

        # ── Start retraining background worker ───────────────────────
        if _retrain_worker_instance and not _retrain_worker_instance.is_running:
            _retrain_task = asyncio.create_task(_retrain_worker_instance.run(), name="retrain-worker")
            logger.info("retrain_worker_started")

        logger.info("ml_components_initialized")
    except Exception as e:
        logger.warning("ml_components_init_failed", error=str(e), msg="ML endpoints will return 503")

    yield

    # ── Shutdown ─────────────────────────────────────────────────────
    _cleanup_running = False
    cleanup_task.cancel()
    with suppress(asyncio.CancelledError):
        await cleanup_task

    _sensor_refresh_running = False
    sensor_refresh_task.cancel()
    with suppress(asyncio.CancelledError):
        await sensor_refresh_task

    await kafka_bridge.stop()
    if getattr(app.state, "pdr_schedule_runner", None) is not None:
        await app.state.pdr_schedule_runner.stop()
    await close_redis()

    # ── Stop retrain worker ──────────────────────────────────────────
    if _retrain_worker_instance is not None:
        _retrain_worker_instance.stop()

    # ── ClickHouse shutdown ──────────────────────────────────────────
    from app.clickhouse import close_clickhouse

    await close_clickhouse()

    # ── Neo4j shutdown ───────────────────────────────────────────────
    from app.neo4j_client import close_neo4j

    await close_neo4j()

    # ── Vault JWT signer shutdown ────────────────────────────────────
    await close_vault_jwt_signer()

    set_ws_manager(None)
    logger.info("phantex_api_shutting_down")

# ── App Factory ───────────────────────────────────────────────────────────────

# Gate OpenAPI docs in production — only expose in development
_docs_url = "/docs" if settings.environment != "production" else None
_redoc_url = "/redoc" if settings.environment != "production" else None
_openapi_url = "/openapi.json" if settings.environment != "production" else None

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "Phantex — Runtime Security Platform for AI Agents.\n\n"
        "Provides REST API for managing agents, events, alerts, and detection rules.\n"
        "All endpoints are tenant-isolated with Row-Level Security."
    ),
    docs_url=_docs_url,
    redoc_url=_redoc_url,
    openapi_url=_openapi_url,
    lifespan=lifespan,
)

# ── Middleware ────────────────────────────────────────────────────────────────

# CORS — restricted to dashboard origin only (no wildcard)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

@app.middleware("http")
async def limit_request_body(request: Request, call_next):
    """Reject oversized request bodies before they're read into memory."""
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            cl = int(content_length)
        except (ValueError, OverflowError):
            return JSONResponse(
                status_code=400,
                content={"error": "Invalid Content-Length header"},
            )
        if cl > 1_048_576:  # 1 MB
            return JSONResponse(
                status_code=413,
                content={"error": "Request body too large", "max_bytes": 1_048_576},
            )
    return await call_next(request)

@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Add security headers to all responses and strip server identity."""
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "0"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"

    # Strip ALL server/technology fingerprints (CWE-200 information exposure)
    for hdr in ("server", "x-powered-by", "x-aspnet-version", "x-runtime"):
        if hdr in response.headers:
            del response.headers[hdr]

    return response

# ── Global Exception Handler ─────────────────────────────────────────────────

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Catch-all exception handler.
    Never leak stack traces, internal paths, or DB schema to the client.
    """
    logger.error(
        "unhandled_exception",
        path=request.url.path,
        method=request.method,
        error=str(exc),
        exc_info=True,
    )

    # In development, include the error message for debugging
    detail = str(exc) if settings.debug else "Internal server error"

    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": detail},
    )

# ── Mount Routers ─────────────────────────────────────────────────────────────

app.include_router(health.router)
app.include_router(auth.router)
app.include_router(agents.router)
app.include_router(events.router)
app.include_router(alerts.router)
app.include_router(rules.router)
app.include_router(users.router)
app.include_router(dashboard.router)
app.include_router(analytics.router)
app.include_router(investigation.router)
app.include_router(timeline.router)
app.include_router(integrations.router)
app.include_router(exports.router)
app.include_router(ml.router)
app.include_router(telemetry.router)
app.include_router(cloud_telemetry.router)
app.include_router(notifications.router)
app.include_router(tag_router)
app.include_router(exemption_router)
app.include_router(routing_router)
app.include_router(window_router)
app.include_router(policies.router)
app.include_router(trust.router)
app.include_router(ws.router)

app.include_router(sso.router)
app.include_router(scim_router)
app.include_router(scim_token_router)
app.include_router(tenants.router)
app.include_router(roles.router)

app.include_router(compliance.router)

app.include_router(mcp_supply_chain.router)
# System Nerve Center
app.include_router(nerve_center.router)

app.include_router(copilot.router)
app.include_router(copilot.ws_router)
app.include_router(copilot_config.router)
# Response Actions (internal gateway commands API)
app.include_router(internal_commands.router)
# Sensor Fleet Management — public + internal APIs
app.include_router(sensors.router)
app.include_router(internal_sensors.router)
# Automated Response Engine (decision layer)
app.include_router(response_router.router)

app.include_router(soar.router)

app.include_router(deception.router)

app.include_router(drift.router)

app.include_router(red_team.router)

app.include_router(analytics_v2.router)

app.include_router(verification.router)

app.include_router(data_classification.router)

app.include_router(finops.router)

app.include_router(a2a.router)

app.include_router(audit_recording.router)

app.include_router(threat_intel.router)

from strawberry.fastapi import GraphQLRouter as _StrawberryRouter

from app.graphql import get_graphql_context as _gql_ctx
from app.graphql import schema as _gql_schema
from app.middleware.rate_limit import rate_limit

_graphql_app = _StrawberryRouter(
    _gql_schema,
    context_getter=_gql_ctx,
    # IDE off by default — opt in via PHANTEX_GRAPHQL_IDE_ENABLED=true
    graphql_ide="graphiql" if settings.graphql_ide_enabled else None,
    # Disable batch queries to prevent batching attacks
    allow_queries_via_get=False,
)
app.include_router(
    _graphql_app,
    prefix="/graphql",
    dependencies=[Depends(rate_limit)],  # Same rate limiting as REST
)

# ── Root ──────────────────────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
async def root():
    """API root — minimal info."""
    return {
        "name": settings.app_name,
        "docs": "/docs",
    }
