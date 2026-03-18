# PHANTEX — Backend Single-Binary Packaging

This directory contains the PyInstaller build system for producing a single
distributable binary of the PHANTEX backend.

## Quick Start

```bash
cd packaging/backend
pip install pyinstaller>=6.0
python build.py
```

## Output

Binaries are written to `packaging/backend/dist/`:

| Binary | Description |
|--------|-------------|
| `phantex-api` | FastAPI backend server |
| `phantex-consumer` | Kafka storage writer |
| `phantex-rule-engine` | PRL rule evaluation engine |
| `phantex-ml-features` | ML feature extraction consumer |
| `phantex-ml-inference` | ML inference consumer |
| `phantex-ml-baseline` | ML baseline tracker |
| `phantex-ml-content` | ML content classifier |

## Build Individual Components

```bash
python build.py --mode api           # API server only
python build.py --mode rule-engine   # Rule engine only
python build.py --mode all           # Everything (default)
```

## Configuration

The binary reads configuration from:
1. `phantex.yaml` (in the same directory as the binary)
2. Environment variables (override YAML values)

See `phantex.yaml.example` for all available options.

## Requirements

- Python 3.12+ (build host only — not needed on target)
- PyInstaller >= 6.0
- All backend dependencies (`pip install -r backend/requirements.txt`)

## Target Machine Requirements

- No Python installation required
- Linux x86_64 or Windows x64
- Network access to PostgreSQL, Kafka, Redis, ClickHouse, Neo4j
