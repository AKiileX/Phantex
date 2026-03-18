# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

# ─────────────────────────────────────────────────────────────────────────────
# PHANTEX — PyInstaller Build Specification
#
# Produces a single distributable binary of the PHANTEX backend.
# Supports modes: api (default), consumer, rule-engine, ml-features,
#                 ml-inference, ml-baseline, ml-content
#
# Usage:
#   pip install pyinstaller
#   python build.py              # build all binaries
#   python build.py --mode api   # build API server only
#
# Output: packaging/backend/dist/phantex-backend[.exe]
# ─────────────────────────────────────────────────────────────────────────────
import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent  # project root
BACKEND = ROOT / "backend"
DIST = Path(__file__).resolve().parent / "dist"
BUILD = Path(__file__).resolve().parent / "build"

# Entrypoints for each operational mode
MODES = {
    "api": {
        "name": "phantex-api",
        "script": "app.main:app",
        "description": "FastAPI backend server",
        "entry": "entry_api.py",
    },
    "consumer": {
        "name": "phantex-consumer",
        "script": "app.main_consumer",
        "description": "Kafka storage writer",
        "entry": "entry_consumer.py",
    },
    "rule-engine": {
        "name": "phantex-rule-engine",
        "script": "engine.rule_engine",
        "description": "PRL rule evaluation engine",
        "entry": "entry_rule_engine.py",
    },
    "ml-features": {
        "name": "phantex-ml-features",
        "script": "ml.main_features",
        "description": "ML feature extraction consumer",
        "entry": "entry_ml_features.py",
    },
    "ml-inference": {
        "name": "phantex-ml-inference",
        "script": "ml.main_inference",
        "description": "ML inference consumer",
        "entry": "entry_ml_inference.py",
    },
    "ml-baseline": {
        "name": "phantex-ml-baseline",
        "script": "ml.main_baseline",
        "description": "ML baseline tracker",
        "entry": "entry_ml_baseline.py",
    },
    "ml-content": {
        "name": "phantex-ml-content",
        "script": "ml.main_content",
        "description": "ML content classifier",
        "entry": "entry_ml_content.py",
    },
}

# Large data files to include as binary data
DATAS = [
    # ML model artifacts
    (str(BACKEND / "models"), "models"),
    # Migration SQL files
    (str(BACKEND / "migrations"), "migrations"),
    # PRL rule files
    (str(ROOT / "rules"), "rules"),
]

# Hidden imports PyInstaller may miss
HIDDEN_IMPORTS = [
    "uvicorn",
    "uvicorn.logging",
    "uvicorn.loops",
    "uvicorn.loops.auto",
    "uvicorn.protocols",
    "uvicorn.protocols.http",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.websockets",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan",
    "uvicorn.lifespan.on",
    "uvloop",
    "httptools",
    "fastapi",
    "pydantic",
    "asyncpg",
    "asyncpg.protocol",
    "confluent_kafka",
    "redis",
    "grpcio",
    "google.protobuf",
    "sklearn",
    "sklearn.ensemble",
    "sklearn.neural_network",
    "xgboost",
    "torch",
    "torch.nn",
    "cryptography",
    "cryptography.hazmat.primitives.asymmetric.ed25519",
    "yaml",
    "jinja2",
]

def create_entry_script(mode: str, mode_cfg: dict) -> Path:
    """Generate a shim entry script for PyInstaller."""
    entry_dir = Path(__file__).resolve().parent / "entries"
    entry_dir.mkdir(exist_ok=True)
    entry_file = entry_dir / mode_cfg["entry"]

    if mode == "api":
        code = '''#!/usr/bin/env python3
"""PHANTEX Backend — API Server entry point."""
import os
import sys
import multiprocessing

# Frozen-app support
if getattr(sys, "frozen", False):
    os.chdir(os.path.dirname(sys.executable))
    sys.path.insert(0, os.path.dirname(sys.executable))

def main():
    import uvicorn
    workers = int(os.environ.get("PHANTEX_WORKERS", "2"))
    host = os.environ.get("PHANTEX_HOST", "0.0.0.0")
    port = int(os.environ.get("PHANTEX_PORT", "8000"))
    uvicorn.run("app.main:app", host=host, port=port, workers=workers,
                proxy_headers=True, log_level="info")

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
'''
    else:
        module = mode_cfg["script"]
        code = f'''#!/usr/bin/env python3
"""PHANTEX Backend — {mode_cfg["description"]} entry point."""
import os
import sys

if getattr(sys, "frozen", False):
    os.chdir(os.path.dirname(sys.executable))
    sys.path.insert(0, os.path.dirname(sys.executable))

if __name__ == "__main__":
    from {module} import main
    main()
'''

    entry_file.write_text(code, encoding="utf-8")
    return entry_file

def build_mode(mode: str, mode_cfg: dict) -> Path:
    """Build a single mode binary with PyInstaller."""
    entry = create_entry_script(mode, mode_cfg)

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--name", mode_cfg["name"],
        "--distpath", str(DIST),
        "--workpath", str(BUILD / mode),
        "--specpath", str(BUILD),
        "--noconfirm",
        "--clean",
        # Add backend source
        "--paths", str(BACKEND),
        "--paths", str(ROOT),
    ]

    # Data files
    for src, dst in DATAS:
        if os.path.exists(src):
            cmd.extend(["--add-data", f"{src}{os.pathsep}{dst}"])

    # Hidden imports
    for imp in HIDDEN_IMPORTS:
        cmd.extend(["--hidden-import", imp])

    # Exclude unused heavy packages
    for exc in ["matplotlib", "scipy.spatial", "scipy.integrate", "PIL", "tkinter"]:
        cmd.extend(["--exclude-module", exc])

    cmd.append(str(entry))

    print(f"\n{'='*60}")
    print(f"  Building: {mode_cfg['name']} ({mode_cfg['description']})")
    print(f"{'='*60}\n")

    result = subprocess.run(cmd, cwd=str(BACKEND))
    if result.returncode != 0:
        print(f"\nERROR: Build failed for {mode}")
        sys.exit(1)

    binary = DIST / mode_cfg["name"]
    if platform.system() == "Windows":
        binary = binary.with_suffix(".exe")

    size_mb = binary.stat().st_size / (1024 * 1024)
    print(f"\n  ✓ {mode_cfg['name']} → {binary} ({size_mb:.1f} MB)")
    return binary

def main():
    parser = argparse.ArgumentParser(description="PHANTEX Backend Binary Builder")
    parser.add_argument("--mode", choices=list(MODES.keys()) + ["all"], default="all",
                        help="Which component to build (default: all)")
    args = parser.parse_args()

    # Ensure PyInstaller is installed
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("Installing PyInstaller...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller>=6.0"])

    DIST.mkdir(parents=True, exist_ok=True)

    modes_to_build = MODES if args.mode == "all" else {args.mode: MODES[args.mode]}
    results = {}

    for mode, cfg in modes_to_build.items():
        binary = build_mode(mode, cfg)
        results[mode] = binary

    print(f"\n{'='*60}")
    print(f"  Build Summary")
    print(f"{'='*60}")
    total_size = 0
    for mode, binary in results.items():
        size = binary.stat().st_size / (1024 * 1024)
        total_size += size
        print(f"  {MODES[mode]['name']:30s} {size:8.1f} MB")
    print(f"  {'─'*40}")
    print(f"  {'Total':30s} {total_size:8.1f} MB")
    print(f"\n  Output: {DIST}/")

if __name__ == "__main__":
    main()
