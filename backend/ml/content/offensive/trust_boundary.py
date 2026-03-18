# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — Trust Boundary Scanner (JB7c).

Detects malicious patterns in trust-boundary files that coding agents and
AI assistants automatically parse:

  - package.json (npm scripts, postinstall hooks)
  - Makefile / Justfile targets
  - .claude/settings.json, .claude/permissions.json
  - .vscode/tasks.json, .vscode/settings.json
  - docker-compose.yml (command overrides, volume mounts)
  - GitHub Actions / CI configs (.github/workflows/*.yml)
  - pyproject.toml / setup.py / setup.cfg (build scripts)
  - .env files (credential exposure)
  - Dockerfile (RUN commands with suspicious payloads)

This scanner prevents the "opening a repo = opening an attachment" attack
vector — a malicious repo file should not silently execute commands or
exfiltrate credentials before trust prompts appear.

Design:
  - File-type detection by name/path pattern
  - Content-specific regex patterns per file type
  - Compound scoring: multiple suspicious signals in one file = higher score
  - Returns structured results with file type, match details, risk level
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

@dataclass(frozen=True)
class TrustBoundaryHit:
    """A suspicious pattern found in a trust-boundary file."""

    file_type: str  # "package_json", "makefile", "claude_config", etc.
    pattern_name: str  # Human-readable pattern identifier
    matched_text: str  # The matched content (capped to 200 chars)
    risk: str  # "critical", "high", "medium", "low"
    description: str  # Why this is dangerous
    metadata: dict[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class TrustBoundaryScanResult:
    """Aggregate result after scanning a trust-boundary file."""

    file_type: str
    file_path: str
    risk_score: float  # 0.0–1.0
    hits: tuple[TrustBoundaryHit, ...]
    is_trust_boundary: bool  # True if the filename is a known trust-boundary file

# ─── File-type detection ─────────────────────────────────────────────────────

_FILE_TYPE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?:^|/)package\.json$", re.I), "package_json"),
    (re.compile(r"(?:^|/)(?:Makefile|Justfile|GNUmakefile)$", re.I), "makefile"),
    (re.compile(r"(?:^|/)\.claude/(?:settings|permissions)\.json$", re.I), "claude_config"),
    (re.compile(r"(?:^|/)\.vscode/(?:tasks|settings|launch)\.json$", re.I), "vscode_config"),
    (re.compile(r"(?:^|/)docker-compose[^/]*\.ya?ml$", re.I), "docker_compose"),
    (re.compile(r"(?:^|/)\.github/workflows/[^/]+\.ya?ml$", re.I), "github_actions"),
    (re.compile(r"(?:^|/)(?:Dockerfile|\.dockerignore)$", re.I), "dockerfile"),
    (re.compile(r"(?:^|/)pyproject\.toml$", re.I), "pyproject"),
    (re.compile(r"(?:^|/)setup\.(?:py|cfg)$", re.I), "setup_py"),
    (re.compile(r"(?:^|/)\.env(?:\.\w+)?$", re.I), "dotenv"),
    (re.compile(r"(?:^|/)(?:\.npmrc|\.yarnrc|\.bowerrc)$", re.I), "npm_config"),
    (re.compile(r"(?:^|/)(?:Gemfile|Rakefile)$", re.I), "ruby_config"),
    (re.compile(r"(?:^|/)(?:\.gitlab-ci|\.travis|\.circleci)\.ya?ml$", re.I), "ci_config"),
    (re.compile(r"(?:^|/)(?:Vagrantfile|Procfile)$", re.I), "infra_config"),
]

def detect_file_type(file_path: str) -> str:
    """Return the trust-boundary file type, or empty string if not one."""
    for pattern, ftype in _FILE_TYPE_PATTERNS:
        if pattern.search(file_path):
            return ftype
    return ""

def is_trust_boundary_file(file_path: str) -> bool:
    """Return True if *file_path* matches a known trust-boundary pattern."""
    return bool(detect_file_type(file_path))

# ─── Content patterns per file type ──────────────────────────────────────────

# Each tuple: (pattern_name, regex, risk_level, description)
_ContentPattern = tuple[str, re.Pattern[str], str, str]

_PACKAGE_JSON_PATTERNS: list[_ContentPattern] = [
    (
        "npm_postinstall_shell",
        re.compile(
            r'"(?:postinstall|preinstall|prepare|install)"\s*:\s*"[^"]*(?:curl|wget|bash|sh\s+-c|node\s+-e|powershell)',
            re.I,
        ),
        "critical",
        "npm lifecycle script executing shell/download command",
    ),
    (
        "npm_script_eval",
        re.compile(
            r'"(?:pre\w+|post\w+|start|test|build)"\s*:\s*"[^"]*(?:eval|exec|`)',
            re.I,
        ),
        "high",
        "npm script with eval/exec/backtick execution",
    ),
    (
        "npm_env_exfil",
        re.compile(
            r'"[^"]*"\s*:\s*"[^"]*(?:\$\{?(?:API_KEY|SECRET|TOKEN|PASSWORD|AWS_|GITHUB_TOKEN)|process\.env)',
            re.I,
        ),
        "high",
        "npm script accessing environment credentials",
    ),
    (
        "npm_suspicious_url",
        re.compile(
            r'"[^"]*"\s*:\s*"[^"]*(?:ngrok|webhook\.site|requestbin|pipedream|burpcollaborator)',
            re.I,
        ),
        "critical",
        "npm script contacting suspicious exfiltration endpoint",
    ),
]

_MAKEFILE_PATTERNS: list[_ContentPattern] = [
    (
        "make_curl_pipe_sh",
        re.compile(r"(?:curl|wget)\s+[^\n]+\|\s*(?:bash|sh|python|perl)", re.I),
        "critical",
        "Makefile downloads and pipes to shell interpreter",
    ),
    (
        "make_reverse_shell",
        re.compile(r"(?:/dev/tcp/|mkfifo|nc\s+.*-e\s+/bin)", re.I),
        "critical",
        "Makefile contains reverse shell pattern",
    ),
    (
        "make_env_exfil",
        re.compile(r"(?:curl|wget|nc)\s+.*\$\(?(?:API_KEY|SECRET|TOKEN|AWS_)", re.I),
        "critical",
        "Makefile exfiltrating environment variables",
    ),
    (
        "make_hidden_target",
        re.compile(r"^\.[A-Z_]+\s*:.*(?:curl|wget|nc|bash\s+-c)", re.I | re.M),
        "high",
        "Makefile hidden target (dot-prefixed) with network command",
    ),
]

_CLAUDE_CONFIG_PATTERNS: list[_ContentPattern] = [
    (
        "claude_allow_all",
        re.compile(r'"allow(?:_all|ed_tools?)"\s*:\s*(?:true|\["\*"\])', re.I),
        "critical",
        "Claude config granting unrestricted tool access",
    ),
    (
        "claude_shell_access",
        re.compile(
            r'"(?:allowed_tools?|permissions?)"\s*:\s*\[[^\]]*"(?:shell|exec|terminal|bash|cmd|run_command)"',
            re.I,
        ),
        "high",
        "Claude config allowing shell/exec access",
    ),
    (
        "claude_disable_safety",
        re.compile(
            r'"(?:safety|security|restrictions?)"\s*:\s*(?:false|"off"|"disabled")',
            re.I,
        ),
        "critical",
        "Claude config disabling safety/security features",
    ),
    (
        "claude_custom_instructions",
        re.compile(
            r'"(?:system_prompt|custom_instructions|override)"\s*:\s*"[^"]{50,}',
            re.I,
        ),
        "high",
        "Claude config injecting custom instructions via settings file",
    ),
]

_VSCODE_CONFIG_PATTERNS: list[_ContentPattern] = [
    (
        "vscode_task_shell",
        re.compile(
            r'"command"\s*:\s*"(?:curl|wget|bash|sh|powershell|cmd|nc)[^"]*"',
            re.I,
        ),
        "high",
        "VSCode task executing shell/download command",
    ),
    (
        "vscode_task_env_leak",
        re.compile(
            r'"(?:args|command)"\s*:\s*"[^"]*(?:\$\{env:|process\.env)',
            re.I,
        ),
        "medium",
        "VSCode task accessing environment variables",
    ),
    (
        "vscode_extension_install",
        re.compile(
            r'"(?:recommendations|extensions\.json)"\s*:\s*\[.*"(?:\.vsix|http)',
            re.I,
        ),
        "high",
        "VSCode config installing extensions from external sources",
    ),
]

_DOCKER_COMPOSE_PATTERNS: list[_ContentPattern] = [
    (
        "docker_privileged",
        re.compile(r"privileged\s*:\s*true", re.I),
        "critical",
        "Docker container running in privileged mode",
    ),
    (
        "docker_host_mount",
        re.compile(
            r"volumes\s*:[\s\S]{0,500}(?:/etc|/root|/home|/var/run/docker\.sock|\.ssh)",
            re.I,
        ),
        "high",
        "Docker mounting sensitive host paths",
    ),
    (
        "docker_host_network",
        re.compile(r"network_mode\s*:\s*['\"]?host", re.I),
        "high",
        "Docker container using host network mode",
    ),
    (
        "docker_env_secrets",
        re.compile(
            r"environment\s*:[\s\S]{0,500}(?:PASSWORD|SECRET|TOKEN|API_KEY)\s*[:=]",
            re.I,
        ),
        "medium",
        "Docker compose hardcoding secrets in environment",
    ),
]

_GITHUB_ACTIONS_PATTERNS: list[_ContentPattern] = [
    (
        "gha_curl_pipe",
        re.compile(r"run\s*:.*(?:curl|wget)\s+[^\n]+\|\s*(?:bash|sh|python)", re.I),
        "critical",
        "GitHub Actions downloading and executing remote script",
    ),
    (
        "gha_secret_echo",
        re.compile(r"run\s*:.*(?:echo|printf|cat)\s+.*\$\{\{?\s*secrets\.", re.I),
        "critical",
        "GitHub Actions leaking secrets to stdout",
    ),
    (
        "gha_third_party_action",
        re.compile(r"uses\s*:\s*[^/]+/[^@]+@[a-f0-9]{40}", re.I),
        "medium",
        "GitHub Actions pinned to commit hash (verify source)",
    ),
    (
        "gha_permissions_write",
        re.compile(
            r"permissions\s*:[\s\S]{0,500}(?:contents|packages|id-token)\s*:\s*write",
            re.I,
        ),
        "medium",
        "GitHub Actions requesting write permissions",
    ),
]

_DOCKERFILE_PATTERNS: list[_ContentPattern] = [
    (
        "docker_curl_pipe",
        re.compile(r"RUN\s+.*(?:curl|wget)\s+[^\n]+\|\s*(?:bash|sh)", re.I),
        "high",
        "Dockerfile downloading and piping to shell",
    ),
    (
        "docker_add_remote",
        re.compile(r"ADD\s+https?://", re.I),
        "high",
        "Dockerfile ADD from remote URL",
    ),
    (
        "docker_run_as_root",
        re.compile(r"RUN\s+.*(?:chmod\s+4755|setuid|chown\s+root)", re.I),
        "high",
        "Dockerfile setting SUID/root permissions",
    ),
]

_PYPROJECT_PATTERNS: list[_ContentPattern] = [
    (
        "pyproject_build_script",
        re.compile(
            r"\[(?:tool\.setuptools|build-system)\][\s\S]{0,500}(?:os\.system|subprocess|exec\s*\()",
            re.I,
        ),
        "critical",
        "pyproject.toml build script executing commands",
    ),
    (
        "pyproject_postinstall",
        re.compile(r"(?:cmdclass|scripts)\s*=.*(?:curl|wget|bash|subprocess)", re.I),
        "critical",
        "Python package with post-install command execution",
    ),
]

_DOTENV_PATTERNS: list[_ContentPattern] = [
    (
        "dotenv_real_creds",
        re.compile(
            r"(?:^|\n)\s*(?:AWS_SECRET|GITHUB_TOKEN|API_KEY|DATABASE_URL|"
            r"SECRET_KEY|PRIVATE_KEY|PASSWORD)\s*=\s*\S{8,}",
            re.I,
        ),
        "critical",
        ".env file containing real credentials",
    ),
]

# Map file_type → content patterns
_FILE_PATTERNS: dict[str, list[_ContentPattern]] = {
    "package_json": _PACKAGE_JSON_PATTERNS,
    "makefile": _MAKEFILE_PATTERNS,
    "claude_config": _CLAUDE_CONFIG_PATTERNS,
    "vscode_config": _VSCODE_CONFIG_PATTERNS,
    "docker_compose": _DOCKER_COMPOSE_PATTERNS,
    "github_actions": _GITHUB_ACTIONS_PATTERNS,
    "dockerfile": _DOCKERFILE_PATTERNS,
    "pyproject": _PYPROJECT_PATTERNS,
    "setup_py": _PYPROJECT_PATTERNS,  # Reuse same patterns
    "dotenv": _DOTENV_PATTERNS,
    "ci_config": _GITHUB_ACTIONS_PATTERNS,  # Similar patterns
    "npm_config": _PACKAGE_JSON_PATTERNS,  # Similar patterns
    "ruby_config": _MAKEFILE_PATTERNS,  # Rakefile is Make-like
    "infra_config": _MAKEFILE_PATTERNS,  # Procfile/Vagrantfile can run commands
}

# ─── Risk scoring ────────────────────────────────────────────────────────────

_RISK_SCORE: dict[str, float] = {
    "critical": 1.0,
    "high": 0.7,
    "medium": 0.4,
    "low": 0.2,
}

# Maximum content length to scan (prevent unbounded regex on large files)
_MAX_SCAN_LENGTH = 65_536  # 64 KB

# ─── Public API ──────────────────────────────────────────────────────────────

class TrustBoundaryScanner:
    """Scan trust-boundary file content for malicious patterns.

    Usage::

        scanner = TrustBoundaryScanner()
        result = scanner.scan("package.json", content)
        if result.risk_score > 0.5:
            # Alert or block
    """

    def scan(
        self,
        file_path: str,
        content: str,
    ) -> TrustBoundaryScanResult:
        """Scan *content* of a trust-boundary file.

        Parameters
        ----------
        file_path:
            The path or filename (used for file-type detection).
        content:
            The raw text content of the file.

        Returns
        -------
        TrustBoundaryScanResult with risk_score and individual hits.
        """
        file_type = detect_file_type(file_path)
        if not file_type:
            return TrustBoundaryScanResult(
                file_type="",
                file_path=file_path,
                risk_score=0.0,
                hits=(),
                is_trust_boundary=False,
            )

        patterns = _FILE_PATTERNS.get(file_type, [])
        hits: list[TrustBoundaryHit] = []

        # Cap content to prevent unbounded regex on very large files
        capped = content[:_MAX_SCAN_LENGTH]

        for pattern_name, regex, risk, description in patterns:
            m = regex.search(capped)
            if m:
                hits.append(
                    TrustBoundaryHit(
                        file_type=file_type,
                        pattern_name=pattern_name,
                        matched_text=m.group(0)[:200],
                        risk=risk,
                        description=description,
                    ),
                )

        # Score: worst-case risk + compound bonus for multiple hits
        if not hits:
            risk_score = 0.0
        else:
            max_risk = max(_RISK_SCORE.get(h.risk, 0.0) for h in hits)
            compound = min(0.2, len(hits) * 0.05)  # +0.05 per extra hit, max +0.2
            risk_score = round(min(1.0, max_risk + compound), 4)

        return TrustBoundaryScanResult(
            file_type=file_type,
            file_path=file_path,
            risk_score=risk_score,
            hits=tuple(hits),
            is_trust_boundary=True,
        )

    def scan_batch(
        self,
        files: list[tuple[str, str]],
    ) -> list[TrustBoundaryScanResult]:
        """Scan a batch of (file_path, content) tuples.

        Returns only results for trust-boundary files (non-boundary
        files are skipped).
        """
        results: list[TrustBoundaryScanResult] = []
        for file_path, content in files:
            result = self.scan(file_path, content)
            if result.is_trust_boundary:
                results.append(result)
        return results
