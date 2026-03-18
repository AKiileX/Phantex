# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — Internal Leak Detector (JB3).

Detects internal infrastructure details in agent output that should
never be exposed: RFC1918 IP addresses, internal hostnames, file paths,
internal URLs, and cloud metadata endpoints.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

@dataclass(frozen=True)
class InternalLeakHit:
    """A detected internal information leak."""

    pattern_name: str
    matched_text: str
    position: int
    description: str = ""

# ── Patterns ─────────────────────────────────────────────────────────────────

_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    # RFC1918 private IPs
    (
        "rfc1918_10",
        re.compile(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
        "RFC1918 Class A private IP (10.x.x.x)",
    ),
    (
        "rfc1918_172",
        re.compile(r"\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b"),
        "RFC1918 Class B private IP (172.16-31.x.x)",
    ),
    (
        "rfc1918_192",
        re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b"),
        "RFC1918 Class C private IP (192.168.x.x)",
    ),
    # Localhost / loopback
    (
        "loopback",
        re.compile(r"\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
        "Loopback IP address",
    ),
    # Internal hostnames (common patterns)
    (
        "internal_hostname",
        re.compile(r"\b[a-z0-9-]+\.(?:internal|local|corp|intra|private)\b", re.I),
        "Internal hostname (.internal, .local, .corp)",
    ),
    # Unix file paths
    (
        "unix_path",
        re.compile(r"(?:/etc/|/var/|/home/|/root/|/opt/|/tmp/|/proc/|/sys/)[a-zA-Z0-9._/-]+"),
        "Unix system path in output",
    ),
    # Windows file paths (backslash)
    (
        "windows_path",
        re.compile(r"[A-Z]:\\(?:Users|Windows|Program Files|AppData|System32)\\[^\s]+", re.I),
        "Windows system path in output",
    ),
    # Cloud metadata endpoints
    (
        "aws_metadata",
        re.compile(r"169\.254\.169\.254"),
        "AWS instance metadata endpoint",
    ),
    (
        "gcp_metadata",
        re.compile(r"metadata\.google\.internal"),
        "GCP instance metadata endpoint",
    ),
    (
        "azure_metadata",
        re.compile(r"169\.254\.169\.254.*?metadata/instance", re.I),
        "Azure instance metadata endpoint",
    ),
    # Kubernetes internal
    (
        "k8s_service",
        re.compile(r"\b[a-z0-9-]+\.(?:svc\.cluster\.local|default\.svc)\b", re.I),
        "Kubernetes service DNS name",
    ),
    # Docker internal
    (
        "docker_socket",
        re.compile(r"/var/run/docker\.sock"),
        "Docker socket path",
    ),
]

def scan_for_internal_leaks(text: str) -> list[InternalLeakHit]:
    """Scan *text* for internal infrastructure leaks.

    Returns a list of ``InternalLeakHit`` sorted by position.
    """
    hits: list[InternalLeakHit] = []
    for name, pattern, description in _PATTERNS:
        for m in pattern.finditer(text):
            hits.append(
                InternalLeakHit(
                    pattern_name=name,
                    matched_text=m.group(0)[:120],
                    position=m.start(),
                    description=description,
                ),
            )
    hits.sort(key=lambda h: h.position)
    return hits
