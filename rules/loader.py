# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Core Rule Loader — reads PRL rule files from the rules/core/ directory
and seeds them into the PostgreSQL rules table.

This module provides:
  - load_core_rules(): reads all .prl files + manifest.json, returns parsed rules
  - seed_core_rules(): inserts core rules into the database (idempotent)

Usage (standalone):
    python -m rules.loader

Usage (from code):
    from rules.loader import load_core_rules, seed_core_rules
    rules = load_core_rules()  # returns list of dicts
    await seed_core_rules()    # inserts into PostgreSQL
"""

from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import Any

from engine.parser.parser import Parser, ParseError

# ── Path resolution ───────────────────────────────────────────────────────────

RULES_DIR = Path(__file__).parent / "core"
MANIFEST_PATH = RULES_DIR / "manifest.json"

def load_core_rules() -> list[dict[str, Any]]:
    """
    Load all core PRL rules from disk.

    Returns a list of dicts, each with:
        name, file, severity, attack_class, description, prl_source, parsed (bool)

    Raises no exceptions — parse failures are recorded in the result.
    """
    if not MANIFEST_PATH.exists():
        raise FileNotFoundError(f"Rule manifest not found: {MANIFEST_PATH}")

    with open(MANIFEST_PATH, "r") as f:
        manifest: list[dict[str, Any]] = json.load(f)

    results: list[dict[str, Any]] = []

    for entry in manifest:
        prl_path = (RULES_DIR / entry["file"]).resolve()
        # Defense-in-depth: reject manifest entries that escape RULES_DIR
        if not prl_path.is_relative_to(RULES_DIR.resolve()):
            results.append({
                "name": entry.get("name", "unknown"),
                "file": entry["file"],
                "parsed": False,
                "parse_error": f"Path traversal blocked: {entry['file']}",
            })
            continue
        rule_info: dict[str, Any] = {
            "name": entry["name"],
            "severity": entry["severity"],
            "attack_class": entry["attack_class"],
            "description": entry["description"],
            "file": entry["file"],
            "prl_source": "",
            "parsed": False,
            "parse_error": None,
        }

        if not prl_path.exists():
            rule_info["parse_error"] = f"File not found: {prl_path}"
            results.append(rule_info)
            continue

        # Read PRL source (strip comment-only lines for metadata, keep for parsing)
        prl_source = prl_path.read_text(encoding="utf-8").strip()

        # Multi-rule files use '---' as separator.  Extract the section
        # whose ``# Rule: <name>`` comment matches this manifest entry.
        sections = re.split(r"\n---+\n?", prl_source)
        rule_name = entry["name"]
        matched_section: str | None = None
        for section in sections:
            # Check if section's header comment matches the rule name
            if re.search(rf"^#\s*Rule:\s*{re.escape(rule_name)}\s*$", section, re.MULTILINE):
                matched_section = section
                break
        if matched_section is None:
            # Single-rule file or no header — use the first section
            matched_section = sections[0]

        rule_info["prl_source"] = matched_section

        # Extract only the expression (non-comment lines)
        expression_lines = [
            line for line in matched_section.split("\n")
            if line.strip() and not line.strip().startswith("#")
        ]
        expression = "\n".join(expression_lines)

        try:
            parser = Parser(expression)
            parser.parse()
            rule_info["parsed"] = True
        except ParseError as e:
            rule_info["parse_error"] = str(e)

        results.append(rule_info)

    return results

async def seed_core_rules(tenant_id: str | None = None) -> dict[str, Any]:
    """
    Insert core rules into the PostgreSQL rules table.

    Idempotent: rules are matched by name. Existing rules are updated,
    new rules are inserted.

    Args:
        tenant_id: If provided, rules are created for this specific tenant.
                   If None, rules are created as global (tenant_id=NULL).

    Returns:
        Summary dict: {inserted: int, updated: int, errors: list[str]}
    """
    from app.database import admin_session_factory
    from app.models.rule import Rule
    from sqlalchemy import select

    rules = load_core_rules()
    summary: dict[str, Any] = {"inserted": 0, "updated": 0, "errors": []}

    async with admin_session_factory() as session:
        for rule_info in rules:
            if not rule_info["parsed"]:
                summary["errors"].append(
                    f"{rule_info['name']}: {rule_info['parse_error']}"
                )
                continue

            # Extract expression (non-comment lines)
            expression_lines = [
                line for line in rule_info["prl_source"].split("\n")
                if line.strip() and not line.strip().startswith("#")
            ]
            expression = "\n".join(expression_lines)

            # Check if rule already exists
            result = await session.execute(
                select(Rule).where(Rule.name == rule_info["name"])
            )
            existing = result.scalar_one_or_none()

            if existing:
                # Update existing rule
                existing.prl_source = expression
                existing.severity = rule_info["severity"]
                existing.attack_class = rule_info["attack_class"]
                existing.description = rule_info["description"]
                existing.version = existing.version + 1
                summary["updated"] += 1
            else:
                # Insert new rule
                new_rule = Rule(
                    id=uuid.uuid4(),
                    tenant_id=uuid.UUID(tenant_id) if tenant_id else None,
                    name=rule_info["name"],
                    description=rule_info["description"],
                    severity=rule_info["severity"],
                    attack_class=rule_info["attack_class"],
                    prl_source=expression,
                    enabled=True,
                    version=1,
                    author="phantex-core",
                )
                session.add(new_rule)
                summary["inserted"] += 1

        await session.commit()

    return summary

# ── CLI Entry Point ───────────────────────────────────────────────────────────

def main() -> None:
    """CLI: validate all core rules and print results."""
    rules = load_core_rules()

    print(f"\n{'─' * 60}")
    print(f"  Phantex Core Rules — Validation Report")
    print(f"{'─' * 60}\n")

    passed = 0
    failed = 0

    for rule in rules:
        status = "✅" if rule["parsed"] else "❌"
        if rule["parsed"]:
            passed += 1
        else:
            failed += 1

        print(f"  {status}  {rule['name']:<30s}  [{rule['severity']:<8s}]  {rule['attack_class']}")
        if rule["parse_error"]:
            print(f"       Error: {rule['parse_error']}")

    print(f"\n{'─' * 60}")
    print(f"  Total: {len(rules)}  |  Passed: {passed}  |  Failed: {failed}")
    print(f"{'─' * 60}\n")

    if failed > 0:
        exit(1)

if __name__ == "__main__":
    main()
