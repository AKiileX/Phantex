# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — Secret Patterns (JB3).

30+ compiled regex patterns for API keys, tokens, credentials, and
private keys across 15+ providers.  All patterns are pre-compiled and
ReDoS-tested.

Matched values are **never** stored in results — only the pattern name,
position, and a redacted preview.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

@dataclass(frozen=True)
class SecretPattern:
    """A single secret-detection pattern."""

    name: str
    provider: str
    pattern: re.Pattern[str]
    severity: str = "high"  # "critical" for private keys
    description: str = ""

# ── API Key patterns ─────────────────────────────────────────────────────────

_PATTERNS: list[SecretPattern] = [
    # OpenAI
    SecretPattern(
        name="openai_api_key",
        provider="OpenAI",
        pattern=re.compile(r"sk-[A-Za-z0-9]{20,}"),
        description="OpenAI API key (sk-...)",
    ),
    SecretPattern(
        name="openai_project_key",
        provider="OpenAI",
        pattern=re.compile(r"sk-proj-[A-Za-z0-9_-]{20,}"),
        description="OpenAI project API key",
    ),
    # AWS
    SecretPattern(
        name="aws_access_key_id",
        provider="AWS",
        pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
        description="AWS Access Key ID",
    ),
    SecretPattern(
        name="aws_secret_key",
        provider="AWS",
        pattern=re.compile(r"(?:aws_secret_access_key|secret_key)\s*[=:]\s*[A-Za-z0-9/+=]{40}"),
        severity="critical",
        description="AWS Secret Access Key",
    ),
    # GitHub
    SecretPattern(
        name="github_pat",
        provider="GitHub",
        pattern=re.compile(r"ghp_[A-Za-z0-9]{36,}"),
        description="GitHub Personal Access Token",
    ),
    SecretPattern(
        name="github_oauth",
        provider="GitHub",
        pattern=re.compile(r"gho_[A-Za-z0-9]{36,}"),
        description="GitHub OAuth token",
    ),
    SecretPattern(
        name="github_fine_grained",
        provider="GitHub",
        pattern=re.compile(r"github_pat_[A-Za-z0-9_]{22,}"),
        description="GitHub fine-grained PAT",
    ),
    # Google Cloud
    SecretPattern(
        name="gcp_api_key",
        provider="GCP",
        pattern=re.compile(r"AIza[A-Za-z0-9_-]{35}"),
        description="Google Cloud API key",
    ),
    SecretPattern(
        name="gcp_service_account",
        provider="GCP",
        pattern=re.compile(r'"type"\s*:\s*"service_account"'),
        description="GCP service account JSON key",
    ),
    # Azure
    SecretPattern(
        name="azure_subscription_key",
        provider="Azure",
        pattern=re.compile(r"[a-f0-9]{32}(?=.*(?:cognitive|azure|subscription))", re.I),
        description="Azure Cognitive Services subscription key",
    ),
    # Slack
    SecretPattern(
        name="slack_bot_token",
        provider="Slack",
        pattern=re.compile(r"xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}"),
        description="Slack bot token",
    ),
    SecretPattern(
        name="slack_user_token",
        provider="Slack",
        pattern=re.compile(r"xoxp-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}"),
        description="Slack user token",
    ),
    SecretPattern(
        name="slack_webhook",
        provider="Slack",
        pattern=re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}"),
        description="Slack webhook URL",
    ),
    # Stripe
    SecretPattern(
        name="stripe_secret_key",
        provider="Stripe",
        pattern=re.compile(r"sk_live_[A-Za-z0-9]{24,}"),
        description="Stripe live secret key",
    ),
    SecretPattern(
        name="stripe_publishable",
        provider="Stripe",
        pattern=re.compile(r"pk_live_[A-Za-z0-9]{24,}"),
        description="Stripe live publishable key",
    ),
    # Twilio
    SecretPattern(
        name="twilio_api_key",
        provider="Twilio",
        pattern=re.compile(r"SK[a-f0-9]{32}"),
        description="Twilio API key",
    ),
    # SendGrid
    SecretPattern(
        name="sendgrid_api_key",
        provider="SendGrid",
        pattern=re.compile(r"SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{43,}"),
        description="SendGrid API key",
    ),
    # Anthropic
    SecretPattern(
        name="anthropic_api_key",
        provider="Anthropic",
        pattern=re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),
        description="Anthropic (Claude) API key",
    ),
    # HuggingFace
    SecretPattern(
        name="huggingface_token",
        provider="HuggingFace",
        pattern=re.compile(r"hf_[A-Za-z0-9]{34,}"),
        description="HuggingFace access token",
    ),
    # Mailgun
    SecretPattern(
        name="mailgun_api_key",
        provider="Mailgun",
        pattern=re.compile(r"key-[A-Za-z0-9]{32,}"),
        description="Mailgun API key",
    ),
    # Generic high-entropy near keywords
    SecretPattern(
        name="generic_password_assignment",
        provider="Generic",
        pattern=re.compile(
            r"(?:password|passwd|token|secret|api_key|apikey|access_token)\s*[=:]\s*['\"]?[A-Za-z0-9/+=_-]{16,}",
            re.I,
        ),
        description="Generic credential assignment",
    ),
    # Private keys
    SecretPattern(
        name="rsa_private_key",
        provider="Crypto",
        pattern=re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
        severity="critical",
        description="RSA private key (PEM)",
    ),
    SecretPattern(
        name="ec_private_key",
        provider="Crypto",
        pattern=re.compile(r"-----BEGIN EC PRIVATE KEY-----"),
        severity="critical",
        description="Elliptic curve private key (PEM)",
    ),
    SecretPattern(
        name="openssh_private_key",
        provider="Crypto",
        pattern=re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
        severity="critical",
        description="OpenSSH private key",
    ),
    SecretPattern(
        name="generic_private_key",
        provider="Crypto",
        pattern=re.compile(r"-----BEGIN PRIVATE KEY-----"),
        severity="critical",
        description="Generic PKCS#8 private key",
    ),
    SecretPattern(
        name="pgp_private_key",
        provider="Crypto",
        pattern=re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
        severity="critical",
        description="PGP private key block",
    ),
    # Connection strings
    SecretPattern(
        name="postgresql_connection",
        provider="Database",
        pattern=re.compile(r"postgres(?:ql)?://[^:]+:[^@]+@[^\s]+"),
        description="PostgreSQL connection string with credentials",
    ),
    SecretPattern(
        name="mongodb_connection",
        provider="Database",
        pattern=re.compile(r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s]+"),
        description="MongoDB connection string with credentials",
    ),
    SecretPattern(
        name="redis_connection",
        provider="Database",
        pattern=re.compile(r"redis://:[^@]+@[^\s]+"),
        description="Redis connection string with password",
    ),
    SecretPattern(
        name="mysql_connection",
        provider="Database",
        pattern=re.compile(r"mysql://[^:]+:[^@]+@[^\s]+"),
        description="MySQL connection string with credentials",
    ),
    # JWT
    SecretPattern(
        name="jwt_token",
        provider="Auth",
        pattern=re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"),
        description="JSON Web Token",
    ),
]

ALL_SECRET_PATTERNS: tuple[SecretPattern, ...] = tuple(_PATTERNS)
SECRET_PATTERN_COUNT = len(ALL_SECRET_PATTERNS)

@dataclass(frozen=True)
class SecretHit:
    """A detected secret — value is redacted."""

    pattern_name: str
    provider: str
    severity: str
    position: int  # char offset in scanned text
    redacted_preview: str  # e.g. "sk-***...***xyz"
    length: int  # length of the matched value

def scan_for_secrets(text: str) -> list[SecretHit]:
    """Scan *text* for secret patterns and return hits.

    Returns a list sorted by severity (critical first), then position.
    **Matched values are redacted in results.**
    """
    hits: list[SecretHit] = []
    for pat in ALL_SECRET_PATTERNS:
        for m in pat.pattern.finditer(text):
            raw = m.group(0)
            hits.append(
                SecretHit(
                    pattern_name=pat.name,
                    provider=pat.provider,
                    severity=pat.severity,
                    position=m.start(),
                    redacted_preview=_redact(raw),
                    length=len(raw),
                ),
            )
    # Sort: critical first, then by position
    _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    hits.sort(key=lambda h: (_sev_order.get(h.severity, 9), h.position))
    return hits

def _redact(value: str, show_chars: int = 4) -> str:
    """Redact a value, showing only first/last *show_chars* characters.

    Only shows prefix/suffix when value is long enough (> show_chars * 3)
    to prevent leaking too much of short secrets.
    """
    if len(value) <= show_chars * 3:
        return "***"
    return f"{value[:show_chars]}***{value[-show_chars:]}"
