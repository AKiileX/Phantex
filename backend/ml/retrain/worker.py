# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Q2: Background Retrain Worker.

Lightweight background task that periodically checks the RetrainScheduler
and processes pending retrains. Designed to run as an asyncio task in
the main application loop.

Architecture:
  - Non-blocking: uses asyncio.sleep between checks
  - Self-healing: catches and logs all exceptions
  - Graceful shutdown: respects cancellation via stop()
  - Thread-safe: delegates to synchronous RetrainPipeline via run_in_executor

Security:
  - Rate-limited by scheduler (max_concurrent_retrains)
  - Per-tenant isolation (no cross-tenant data access)
  - Full audit trail from training pipeline
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from ml.config import get_ml_config
from ml.retrain.pipeline import RetrainPipeline
from ml.retrain.scheduler import RetrainScheduler

logger = structlog.get_logger("phantex.ml.retrain.worker")

class RetrainWorker:
    """Background worker that processes pending retrains.

    Usage:
        worker = RetrainWorker(pipeline, scheduler)
        task = asyncio.create_task(worker.run())
        # ... later ...
        worker.stop()
        await task
    """

    def __init__(
        self,
        pipeline: RetrainPipeline,
        scheduler: RetrainScheduler,
    ) -> None:
        self._pipeline = pipeline
        self._scheduler = scheduler
        self._cfg = get_ml_config().auto_retrain
        self._running = False
        self._task: asyncio.Task | None = None
        self._retrains_completed: int = 0
        self._retrains_failed: int = 0

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "running": self._running,
            "retrains_completed": self._retrains_completed,
            "retrains_failed": self._retrains_failed,
            "check_interval_seconds": self._cfg.check_interval_seconds,
            "enabled": self._cfg.enabled,
        }

    async def run(self) -> None:
        """Main worker loop. Runs until stop() is called.

        Each iteration:
          1. Checks scheduler for pending retrains
          2. Processes each trigger via RetrainPipeline
          3. Sleeps for check_interval_seconds
        """
        self._running = True
        logger.info(
            "retrain_worker_started",
            check_interval=self._cfg.check_interval_seconds,
        )

        try:
            while self._running:
                try:
                    await self._check_and_retrain()
                except asyncio.CancelledError:
                    break
                except Exception:
                    logger.exception("retrain_worker_iteration_error")

                # Sleep between checks (interruptible)
                try:
                    await asyncio.sleep(self._cfg.check_interval_seconds)
                except asyncio.CancelledError:
                    break
        finally:
            self._running = False
            logger.info(
                "retrain_worker_stopped",
                completed=self._retrains_completed,
                failed=self._retrains_failed,
            )

    def stop(self) -> None:
        """Signal the worker to stop after the current iteration."""
        self._running = False
        if self._task is not None:
            self._task.cancel()

    async def _check_and_retrain(self) -> None:
        """Check for pending retrains and process them."""
        if not self._scheduler.enabled:
            return

        triggers = self._scheduler.check_all()
        if not triggers:
            return

        logger.info(
            "retrain_triggers_found",
            count=len(triggers),
            tenants=[t.tenant_id for t in triggers],
        )

        for trigger in triggers:
            if not self._running:
                break

            try:
                # Run training in executor to avoid blocking event loop
                loop = asyncio.get_running_loop()
                result = await loop.run_in_executor(
                    None,
                    self._pipeline.retrain_from_trigger,
                    trigger,
                )

                if result.success:
                    self._retrains_completed += 1
                    logger.info(
                        "retrain_worker_success",
                        tenant_id=trigger.tenant_id,
                        version=result.version,
                    )
                else:
                    self._retrains_failed += 1
                    logger.warning(
                        "retrain_worker_failure",
                        tenant_id=trigger.tenant_id,
                        reason=result.reason,
                    )

            except Exception:
                self._retrains_failed += 1
                logger.exception(
                    "retrain_worker_error",
                    tenant_id=trigger.tenant_id,
                )
