# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Formal Verification API Router

Endpoints for viewing verification specs, viewing last results,
running Z3 checks on demand, and reading spec source files.
"""

from __future__ import annotations

import logging
from dataclasses import asdict
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from app.middleware.abac import require_permission
from app.middleware.auth import get_current_active_user
from app.middleware.rate_limit import rate_limit
from app.schemas.auth import CurrentUser
from app.services import verification_service as svc

logger = logging.getLogger("phantex.verification_router")

router = APIRouter(
    prefix="/api/v1/verification",
    tags=["verification"],
    dependencies=[Depends(rate_limit), Depends(require_permission("analytics.view"))],
)

@router.get("/specs")
async def list_specs():
    """List all known formal verification specs and their properties."""
    return {"specs": svc.list_specs()}

@router.get("/results")
async def get_results():
    """Return cached results from the last CI run (if available)."""
    return {"results": svc.get_last_results()}

@router.post("/run/z3")
async def run_z3(
    current_user: Annotated[CurrentUser, Depends(get_current_active_user)],
):
    """Execute Z3 trust graph verification on demand.

    Requires analytics.view permission. The check runs in a subprocess
    with a 60-second timeout. Limited to 1 concurrent execution.
    """
    logger.info(
        "On-demand Z3 verification triggered",
        extra={"user": str(current_user.user_id), "tenant": str(current_user.tenant_id)},
    )
    result = await svc.run_z3_checks()
    return asdict(result)

@router.get("/spec/{spec_name}/source")
async def get_spec_source(spec_name: str):
    """Read the source code of a formal spec for display."""
    _ALLOWED_SPECS = {"rule_evaluation", "policy_engine", "sandbox_isolation", "trust_graph"}
    if spec_name not in _ALLOWED_SPECS:
        raise HTTPException(status_code=404, detail="Spec not found")

    source = svc.get_spec_source(spec_name)
    if source is None:
        raise HTTPException(status_code=404, detail="Spec file not found")
    return {"spec_name": spec_name, "source": source}
