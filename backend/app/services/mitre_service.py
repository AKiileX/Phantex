# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — MITRE ATLAS Service (L2).

Provides MITRE ATLAS technique lookup, rule/alert enrichment, and
coverage reporting.  Loads the mapping data from ``atlas_mapping.json``
at import time — immutable, no runtime I/O.

All public functions are pure (no side effects, no DB). They accept
explicit parameters and return typed results.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.utils.logging import get_logger

logger = get_logger("phantex.mitre")

# ── Load Atlas mapping (once, at import) ──────────────────────────────────────

_MAPPING_PATH = Path(__file__).resolve().parent.parent / "data" / "atlas_mapping.json"

_atlas_data: dict[str, Any] = {}

def _load_mapping() -> dict[str, Any]:
    """Load ATLAS mapping from JSON. Cached in module global."""
    global _atlas_data
    if _atlas_data:
        return _atlas_data
    try:
        with open(_MAPPING_PATH, encoding="utf-8") as f:
            _atlas_data = json.load(f)
        logger.info("atlas_mapping_loaded", techniques=len(_atlas_data.get("techniques", {})))
    except Exception:
        logger.exception("atlas_mapping_load_failed", path=str(_MAPPING_PATH))
        _atlas_data = {
            "techniques": {},
            "rule_mappings": {},
            "ml_model_mappings": {},
            "content_classifier_mappings": {},
            "attack_class_to_atlas": {},
        }
    return _atlas_data

def _data() -> dict[str, Any]:
    """Return the loaded mapping (lazy init)."""
    if not _atlas_data:
        _load_mapping()
    return _atlas_data

# ── Technique Lookup ──────────────────────────────────────────────────────────

def get_technique(technique_id: str) -> dict[str, Any] | None:
    """Return full technique info for a single ATLAS ID, or None."""
    return _data().get("techniques", {}).get(technique_id)

def get_all_techniques() -> dict[str, dict[str, Any]]:
    """Return the full technique catalogue."""
    return _data().get("techniques", {})

# ── Rule → ATLAS ──────────────────────────────────────────────────────────────

def techniques_for_rule(rule_name: str) -> list[str]:
    """Return ATLAS technique IDs that a PRL rule maps to."""
    entry = _data().get("rule_mappings", {}).get(rule_name, {})
    return list(entry.get("atlas_techniques", []))

def rule_mapping_detail(rule_name: str) -> dict[str, Any] | None:
    """Return full rule mapping (techniques + confidence + rationale)."""
    return _data().get("rule_mappings", {}).get(rule_name)

# ── Attack class → ATLAS ──────────────────────────────────────────────────────

def techniques_for_attack_class(attack_class: str) -> list[str]:
    """Return ATLAS technique IDs that an attack_class maps to."""
    return list(_data().get("attack_class_to_atlas", {}).get(attack_class, []))

# ── ML model → ATLAS ─────────────────────────────────────────────────────────

def techniques_for_ml_model(
    model_name: str,
    *,
    predicted_class: str | None = None,
) -> list[str]:
    """Return ATLAS technique IDs for an ML model detection.

    For xgboost_attack_class, also accepts ``predicted_class`` to resolve
    per-attack-class mappings.
    """
    entry = _data().get("ml_model_mappings", {}).get(model_name, {})
    # Direct techniques
    techniques = list(entry.get("atlas_techniques", []))
    # Per-class mapping (XGBoost)
    if predicted_class and "attack_class_mapping" in entry:
        class_techs = entry["attack_class_mapping"].get(predicted_class, [])
        techniques.extend(class_techs)
    return list(dict.fromkeys(techniques))  # dedupe, preserve order

# ── Content classifier → ATLAS ────────────────────────────────────────────────

def techniques_for_content_classifier(classifier_name: str) -> list[str]:
    """Return ATLAS technique IDs for a content analysis classifier."""
    entry = _data().get("content_classifier_mappings", {}).get(classifier_name, {})
    return list(entry.get("atlas_techniques", []))

# ── Alert Enrichment ──────────────────────────────────────────────────────────

def enrich_alert_context(
    context: dict[str, Any],
    *,
    rule_name: str | None = None,
    attack_class: str | None = None,
) -> dict[str, Any]:
    """Add ``atlas_techniques`` to an alert context dict (returns new dict).

    Resolution order:
    1. If rule_name has a direct mapping, use it.
    2. Else fall back to attack_class → ATLAS mapping.
    3. For each technique ID, attach name + URL from the catalogue.
    """
    enriched = dict(context)  # shallow copy

    technique_ids: list[str] = []

    # 1. Rule-based
    if rule_name:
        technique_ids.extend(techniques_for_rule(rule_name))

    # 2. Attack-class fallback
    if not technique_ids and attack_class:
        technique_ids.extend(techniques_for_attack_class(attack_class))

    # Deduplicate
    technique_ids = list(dict.fromkeys(technique_ids))

    if technique_ids:
        techniques_data = _data().get("techniques", {})
        atlas_entries = []
        for tid in technique_ids:
            info = techniques_data.get(tid)
            if info:
                atlas_entries.append(
                    {
                        "id": tid,
                        "name": info["name"],
                        "tactic": info.get("tactic", ""),
                        "url": info.get("url", ""),
                    }
                )
            else:
                atlas_entries.append({"id": tid, "name": tid, "tactic": "", "url": ""})
        enriched["atlas_techniques"] = atlas_entries

    return enriched

# ── Coverage Report ───────────────────────────────────────────────────────────

def coverage_report() -> dict[str, Any]:
    """Return an ATLAS coverage matrix: which techniques are detected and by what.

    Returns::

        {
            "total_techniques": 14,
            "detected_techniques": 12,
            "coverage_pct": 85.7,
            "techniques": [
                {
                    "id": "AML.T0051",
                    "name": "...",
                    "detected_by": ["prompt_injection_pattern", ...],
                    "detection_source": "prl_rule",
                    "confidence": "high"
                },
                ...
            ]
        }
    """
    data = _data()
    all_techniques = data.get("techniques", {})
    rule_mappings = data.get("rule_mappings", {})
    ml_mappings = data.get("ml_model_mappings", {})
    content_mappings = data.get("content_classifier_mappings", {})

    # Build reverse index: technique_id → list of detectors
    coverage: dict[str, list[dict[str, str]]] = {tid: [] for tid in all_techniques}

    # Rules
    for rule_name, mapping in rule_mappings.items():
        for tid in mapping.get("atlas_techniques", []):
            if tid in coverage:
                coverage[tid].append(
                    {
                        "name": rule_name,
                        "source": "prl_rule",
                        "confidence": mapping.get("confidence", "medium"),
                    }
                )

    # ML models
    for model_name, mapping in ml_mappings.items():
        for tid in mapping.get("atlas_techniques", []):
            if tid in coverage:
                coverage[tid].append(
                    {
                        "name": model_name,
                        "source": "ml_model",
                        "confidence": mapping.get("confidence", "medium"),
                    }
                )
        # Per-class mapping
        for cls_name, tids in mapping.get("attack_class_mapping", {}).items():
            for tid in tids:
                if tid in coverage:
                    coverage[tid].append(
                        {
                            "name": f"{model_name}:{cls_name}",
                            "source": "ml_model",
                            "confidence": mapping.get("confidence", "medium"),
                        }
                    )

    # Content classifiers
    for clf_name, mapping in content_mappings.items():
        for tid in mapping.get("atlas_techniques", []):
            if tid in coverage:
                coverage[tid].append(
                    {
                        "name": clf_name,
                        "source": "content_classifier",
                        "confidence": mapping.get("confidence", "medium"),
                    }
                )

    # Build result
    technique_list = []
    detected_count = 0
    for tid, info in all_techniques.items():
        detectors = coverage.get(tid, [])
        is_detected = len(detectors) > 0
        if is_detected:
            detected_count += 1
        # Best confidence among detectors
        best_confidence = "none"
        if detectors:
            conf_order = {"high": 3, "medium": 2, "low": 1, "none": 0}
            best_confidence = max(
                detectors,
                key=lambda d: conf_order.get(d.get("confidence", "none"), 0),
            )["confidence"]

        technique_list.append(
            {
                "id": tid,
                "name": info["name"],
                "tactic": info.get("tactic", ""),
                "url": info.get("url", ""),
                "detected": is_detected,
                "detected_by": detectors,
                "best_confidence": best_confidence,
            }
        )

    total = len(all_techniques)
    return {
        "total_techniques": total,
        "detected_techniques": detected_count,
        "coverage_pct": round(detected_count / total * 100, 1) if total else 0.0,
        "techniques": technique_list,
    }
