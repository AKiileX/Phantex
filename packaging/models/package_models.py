#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

# ─────────────────────────────────────────────────────────────────────────────
# PHANTEX — Offline Model Packager
#
# Packages ML model artifacts into a signed, versioned archive for air-gap
# deployment.  Uses Ed25519 digital signatures for tamper detection.
#
# Usage:
#   # Generate signing keypair (one time)
#   python package_models.py keygen --out keys/
#
#   # Package all models for a tenant
#   python package_models.py pack \
#       --models-dir backend/models/global \
#       --signing-key keys/phantex-signing.key \
#       --version 2026.03.06 \
#       --output dist/phantex-models-2026.03.06.tar.gz
#
#   # Verify + extract on target
#   python package_models.py verify \
#       --package dist/phantex-models-2026.03.06.tar.gz \
#       --public-key keys/phantex-signing.pub
#
#   # Install into running instance
#   python package_models.py install \
#       --package dist/phantex-models-2026.03.06.tar.gz \
#       --public-key keys/phantex-signing.pub \
#       --target-dir /opt/phantex/models
# ─────────────────────────────────────────────────────────────────────────────
import argparse
import datetime
import hashlib
import io
import json
import os
import shutil
import struct
import sys
import tarfile
import tempfile
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
except ImportError:
    print("ERROR: 'cryptography' package required. Install: pip install cryptography>=41.0")
    sys.exit(1)

# ── Constants ────────────────────────────────────────────────────────────────

MAGIC = b"PHXM"                    # Package magic bytes
FORMAT_VERSION = 1                 # Package format version
MODEL_STAGES = ["stage1.pkl", "stage2.pkl", "stage3.pkl"]
METADATA_FILES = ["manifest.json", "feature_names.json"]

# ── Keygen ───────────────────────────────────────────────────────────────────

def cmd_keygen(args):
    """Generate Ed25519 signing keypair."""
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    key_path = out_dir / "phantex-signing.key"
    pub_path = out_dir / "phantex-signing.pub"

    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    os.chmod(str(key_path), 0o600)

    pub_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    print(f"  Private key: {key_path}")
    print(f"  Public key:  {pub_path}")
    print(f"\n  Keep the private key secure. Distribute the public key to targets.")

def load_private_key(path: str) -> Ed25519PrivateKey:
    """Load Ed25519 private key from PEM file."""
    data = Path(path).read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"Key at {path} is not Ed25519")
    return key

def load_public_key(path: str) -> Ed25519PublicKey:
    """Load Ed25519 public key from PEM file."""
    data = Path(path).read_bytes()
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(f"Key at {path} is not Ed25519")
    return key

# ── Pack ─────────────────────────────────────────────────────────────────────

def sha256_file(path: Path) -> str:
    """Compute SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def build_manifest(models_dir: Path, version: str) -> dict:
    """Build a package manifest with hashes for all files."""
    manifest = {
        "format_version": FORMAT_VERSION,
        "package_version": version,
        "created_at": datetime.datetime.utcnow().isoformat() + "Z",
        "platform": "phantex",
        "models": {},
    }

    # Scan for model directories (tenant/version structure or flat)
    model_files = sorted(models_dir.rglob("*.pkl"))
    if not model_files:
        print(f"WARNING: No .pkl model files found in {models_dir}")

    # Build file inventory
    files = {}
    total_size = 0
    for f in sorted(models_dir.rglob("*")):
        if f.is_file():
            rel = f.relative_to(models_dir)
            size = f.stat().st_size
            total_size += size
            files[str(rel)] = {
                "sha256": sha256_file(f),
                "size": size,
            }

    # Identify model stages
    for stage in MODEL_STAGES:
        matches = [p for p in files if p.endswith(stage)]
        manifest["models"][stage] = {
            "count": len(matches),
            "paths": matches,
        }

    manifest["files"] = files
    manifest["total_files"] = len(files)
    manifest["total_size_bytes"] = total_size

    # Read existing training manifest if present
    training_manifest = models_dir / "manifest.json"
    if training_manifest.exists():
        try:
            manifest["training_manifest"] = json.loads(training_manifest.read_text())
        except json.JSONDecodeError:
            pass

    return manifest

def cmd_pack(args):
    """Package model artifacts into a signed archive."""
    models_dir = Path(args.models_dir).resolve()
    if not models_dir.is_dir():
        print(f"ERROR: Models directory not found: {models_dir}")
        sys.exit(1)

    private_key = load_private_key(args.signing_key)
    version = args.version or datetime.date.today().isoformat()
    output = Path(args.output or f"phantex-models-{version}.tar.gz")

    print(f"  Models dir:  {models_dir}")
    print(f"  Version:     {version}")
    print(f"  Output:      {output}")

    # Stage 1: Build manifest
    manifest = build_manifest(models_dir, version)
    manifest_json = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")

    # Stage 2: Sign manifest
    signature = private_key.sign(manifest_json)
    manifest["_signature_ed25519"] = signature.hex()

    # Signed manifest (includes signature field)
    signed_manifest_json = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")

    # Stage 3: Build tarball
    output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(str(output), "w:gz") as tar:
        # Add manifest first
        info = tarfile.TarInfo(name="MANIFEST.json")
        info.size = len(signed_manifest_json)
        tar.addfile(info, io.BytesIO(signed_manifest_json))

        # Add raw signature file
        sig_data = signature
        info = tarfile.TarInfo(name="MANIFEST.sig")
        info.size = len(sig_data)
        tar.addfile(info, io.BytesIO(sig_data))

        # Add all model files
        for f in sorted(models_dir.rglob("*")):
            if f.is_file():
                rel = f.relative_to(models_dir)
                tar.add(str(f), arcname=f"models/{rel}")

    size_mb = output.stat().st_size / (1024 * 1024)
    print(f"\n  ✓ Package created: {output} ({size_mb:.1f} MB)")
    print(f"    Files: {manifest['total_files']}")
    print(f"    Stages: {', '.join(f'{s}={manifest["models"][s]["count"]}' for s in MODEL_STAGES)}")
    print(f"    Signature: Ed25519 ({signature.hex()[:32]}...)")

# ── Verify ───────────────────────────────────────────────────────────────────

def verify_package(package_path: Path, public_key: Ed25519PublicKey) -> dict:
    """Verify package signature and file integrity. Returns manifest on success."""
    with tarfile.open(str(package_path), "r:gz") as tar:
        # Extract manifest
        manifest_member = tar.getmember("MANIFEST.json")
        manifest_data = tar.extractfile(manifest_member).read()
        manifest = json.loads(manifest_data)

        # Extract signature
        sig_member = tar.getmember("MANIFEST.sig")
        signature = tar.extractfile(sig_member).read()

        # Rebuild unsigned manifest for verification
        manifest_unsigned = {k: v for k, v in manifest.items() if k != "_signature_ed25519"}
        manifest_unsigned_json = json.dumps(manifest_unsigned, indent=2, sort_keys=True).encode("utf-8")

        # Verify Ed25519 signature
        try:
            public_key.verify(signature, manifest_unsigned_json)
        except InvalidSignature:
            raise ValueError("SIGNATURE VERIFICATION FAILED — package may be tampered")

        # Verify file integrity
        files_spec = manifest.get("files", {})
        errors = []
        for member in tar.getmembers():
            if member.name.startswith("models/"):
                rel_path = member.name[len("models/"):]
                if rel_path in files_spec:
                    expected_hash = files_spec[rel_path]["sha256"]
                    actual_data = tar.extractfile(member).read()
                    actual_hash = sha256_bytes(actual_data)
                    if actual_hash != expected_hash:
                        errors.append(f"Hash mismatch: {rel_path}")

        if errors:
            raise ValueError(f"FILE INTEGRITY ERRORS:\n" + "\n".join(errors))

    return manifest

def cmd_verify(args):
    """Verify package signature and file integrity."""
    package = Path(args.package)
    public_key = load_public_key(args.public_key)

    print(f"  Package:    {package}")
    print(f"  Public key: {args.public_key}")
    print()

    try:
        manifest = verify_package(package, public_key)
        print(f"  ✓ Signature: VALID (Ed25519)")
        print(f"  ✓ Files:     {manifest['total_files']} verified")
        print(f"  ✓ Version:   {manifest['package_version']}")
        print(f"  ✓ Created:   {manifest['created_at']}")
    except ValueError as e:
        print(f"  ✗ VERIFICATION FAILED: {e}")
        sys.exit(1)

# ── Install ──────────────────────────────────────────────────────────────────

def cmd_install(args):
    """Verify and install model package to target directory."""
    package = Path(args.package)
    public_key = load_public_key(args.public_key)
    target = Path(args.target_dir)

    print(f"  Package:    {package}")
    print(f"  Target:     {target}")
    print()

    # Step 1: Verify
    print("  [1/4] Verifying package signature...")
    manifest = verify_package(package, public_key)
    print(f"         ✓ Signature valid, {manifest['total_files']} files verified")

    # Step 2: Backup current models
    backup_dir = target.parent / f"{target.name}.backup.{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    if target.exists():
        print(f"  [2/4] Backing up current models → {backup_dir.name}")
        shutil.copytree(target, backup_dir)
    else:
        print(f"  [2/4] No existing models to backup")
        target.mkdir(parents=True, exist_ok=True)

    # Step 3: Extract
    print(f"  [3/4] Extracting models...")
    with tempfile.TemporaryDirectory() as tmpdir:
        with tarfile.open(str(package), "r:gz") as tar:
            # Safe extraction — only extract models/ prefix with path traversal guard
            for member in tar.getmembers():
                if not member.name.startswith("models/"):
                    continue
                # Strip "models/" prefix
                rel_name = member.name[len("models/"):]
                # ── PATH TRAVERSAL DEFENCE ──────────────────────────────
                # Reject any component that escapes the target directory
                resolved = (target / rel_name).resolve()
                if not str(resolved).startswith(str(target.resolve())):
                    raise ValueError(
                        f"Path traversal detected: {member.name} resolves outside target"
                    )
                if ".." in rel_name.split("/"):
                    raise ValueError(
                        f"Path traversal detected: {member.name} contains '..'"
                    )
                member.name = rel_name
                tar.extract(member, target)

    # Step 4: Write version marker
    version_file = target / ".phantex-model-version"
    version_file.write_text(json.dumps({
        "version": manifest["package_version"],
        "installed_at": datetime.datetime.utcnow().isoformat() + "Z",
        "package_sha256": sha256_file(package),
        "files": manifest["total_files"],
    }, indent=2))

    print(f"  [4/4] Version marker written")
    print(f"\n  ✓ Models installed: v{manifest['package_version']}")
    print(f"    Backup: {backup_dir}" if backup_dir.exists() else "")

    # Rollback instructions
    if backup_dir.exists():
        print(f"\n  To rollback: rm -rf {target} && mv {backup_dir} {target}")

# ── Rollback ─────────────────────────────────────────────────────────────────

def cmd_rollback(args):
    """Rollback to the most recent backup."""
    target = Path(args.target_dir)
    parent = target.parent

    # Find latest backup
    backups = sorted(parent.glob(f"{target.name}.backup.*"), reverse=True)
    if not backups:
        print(f"  ERROR: No backups found in {parent}")
        sys.exit(1)

    latest = backups[0]
    print(f"  Rolling back to: {latest.name}")

    if target.exists():
        shutil.rmtree(target)
    shutil.move(str(latest), str(target))

    print(f"  ✓ Rollback complete. Removed {len(backups) - 1} older backups available.")

# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="PHANTEX Offline Model Packager — Ed25519-signed model distribution"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # keygen
    kg = sub.add_parser("keygen", help="Generate Ed25519 signing keypair")
    kg.add_argument("--out", required=True, help="Output directory for keys")

    # pack
    pk = sub.add_parser("pack", help="Package models into signed archive")
    pk.add_argument("--models-dir", required=True, help="Path to model artifacts")
    pk.add_argument("--signing-key", required=True, help="Ed25519 private key (PEM)")
    pk.add_argument("--version", help="Package version (default: today's date)")
    pk.add_argument("--output", "-o", help="Output .tar.gz path")

    # verify
    vf = sub.add_parser("verify", help="Verify package signature + integrity")
    vf.add_argument("--package", required=True, help="Path to .tar.gz package")
    vf.add_argument("--public-key", required=True, help="Ed25519 public key (PEM)")

    # install
    ins = sub.add_parser("install", help="Verify + install models to target directory")
    ins.add_argument("--package", required=True, help="Path to .tar.gz package")
    ins.add_argument("--public-key", required=True, help="Ed25519 public key (PEM)")
    ins.add_argument("--target-dir", required=True, help="Target models directory")

    # rollback
    rb = sub.add_parser("rollback", help="Rollback to latest model backup")
    rb.add_argument("--target-dir", required=True, help="Target models directory")

    args = parser.parse_args()

    commands = {
        "keygen": cmd_keygen,
        "pack": cmd_pack,
        "verify": cmd_verify,
        "install": cmd_install,
        "rollback": cmd_rollback,
    }
    commands[args.command](args)

if __name__ == "__main__":
    main()
