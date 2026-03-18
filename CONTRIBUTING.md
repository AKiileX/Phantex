# Contributing to PhanTeX

Thank you for your interest in contributing to PhanTeX! This document explains how to get involved.

## Code of Conduct

All contributors must follow our [Code of Conduct](CODE_OF_CONDUCT.md). Be respectful, inclusive, and constructive.

## Getting Started

### Prerequisites

| Tool | Version |
|------|---------|
| Docker & Docker Compose | 24+ |
| Python | 3.12+ |
| Go | 1.23+ |
| Rust | 1.85+ |
| Node.js | 20+ |
| protoc (protobuf compiler) | 3.21+ |

### Development Setup

```bash
# Clone the repo
git clone https://github.com/AKiileX/Phantex.git
cd Phantex

# Copy environment config
cp .env.example .env

# Bring up infrastructure services
docker compose -f docker-compose.dev.yml up -d

# Backend (Python)
cd backend
python -m venv .venv && source .venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Dashboard (React)
cd dashboard
npm install
npm run dev

# Gateway (Go)
cd gateway
go build -o phantex-gateway ./cmd/phantex-gateway
./phantex-gateway

# Trust Engine (Rust)
cd trust-engine
cargo build --release
```

### Running Tests

```bash
# Backend unit tests
cd backend && pytest -x --tb=short

# Dashboard tests
cd dashboard && npm test

# Gateway tests
cd gateway && go test ./...

# End-to-end
cd dashboard && npx playwright test
```

## How to Contribute

### Reporting Bugs

1. Search [existing issues](https://github.com/AKiileX/Phantex/issues) first.
2. Open a new issue with:
   - PhanTeX version / commit hash
   - Steps to reproduce
   - Expected vs. actual behavior
   - Logs / stack traces

### Suggesting Features

Open a [Discussion](https://github.com/AKiileX/Phantex/discussions) before writing code for large features. This lets us align on design before you invest time.

### Pull Requests

1. Fork the repo and create a branch: `git checkout -b feat/my-feature`
2. Make your changes with clear commit messages.
3. Add or update tests for any changed behavior.
4. Ensure all tests pass locally.
5. Open a PR against `main` with a clear description.

### PR Guidelines

- **One concern per PR.** Don't bundle unrelated changes.
- **Tests required.** Every behavioral change needs a test.
- **No secrets.** Never commit credentials, API keys, or tokens.
- **Type hints** for Python, **strict TypeScript** for dashboard.
- **Conventional commits** preferred: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `ci:`.

## Architecture Overview

| Component | Language | Directory |
|-----------|----------|-----------|
| Backend API | Python (FastAPI) | `backend/` |
| Dashboard | TypeScript (React 19) | `dashboard/` |
| Gateway | Go (gRPC + mTLS) | `gateway/` |
| Trust Engine | Rust | `trust-engine/` |
| ML Pipeline | Python (scikit-learn) | `backend/ml/` |
| eBPF Sensor | Go + C | `sensor/` |
| Rule Engine | Python | `rules/` + `engine/` |
| SDKs | Python, Node.js, Go, .NET, Java, Ruby | `sdk/` |
| Proto definitions | Protobuf | `proto/` |

## Coding Standards

- **Python**: Ruff for linting, Black for formatting, type hints everywhere.
- **TypeScript**: ESLint + Prettier, strict mode.
- **Go**: `gofmt`, standard project layout.
- **Rust**: `cargo fmt`, `cargo clippy` clean.

## Security Vulnerabilities

If you discover a security vulnerability, **do NOT open a public issue**. Report it privately to **starxsec@proton.me**.

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
