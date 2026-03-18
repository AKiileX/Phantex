# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| main (latest) | Yes |
| Older commits | Best-effort |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Any security issues can be reported to the main author at **starxsec@proton.me**. All communications are private.

### Scope

The following are in scope:

- Authentication and authorization bypass
- SQL injection, command injection, or code injection
- Cross-site scripting (XSS) in the dashboard
- Sensitive data exposure (credentials, tokens, PII)
- gRPC / mTLS bypass in the gateway
- Trust score manipulation
- eBPF sensor privilege escalation
- eBPF probe bytecode tampering or signature bypass (Ed25519 per-deployment signing)
- Supply chain attacks on ML models or dependencies
- Cryptographic weaknesses

### Out of Scope

- Denial of service via resource exhaustion (unless trivially exploitable)
- Issues in third-party dependencies (report upstream; let us know so we can update)
- Social engineering attacks
- Issues requiring physical access

## Security Design Principles

PhanTeX follows defense-in-depth:

- **TLS/mTLS support** between services (configurable per deployment)
- **Row-Level Security (RLS)** enforced at the PostgreSQL level
- **JWT with short-lived access tokens** (15 min) + refresh rotation
- **RBAC** with 3 roles: `viewer`, `analyst`, `admin`
- **Vault integration** for secrets management in production
- **Content Security Policy** headers on the dashboard
- **Signed ML models** with provenance manifests
- **Per-deployment eBPF probe signing** — Ed25519 keypair generated locally; no pre-compiled probes distributed
- **Input validation** at every API boundary

## Disclosure Policy

All vulnerability reports are handled privately via email. Fixes are released as regular updates.
