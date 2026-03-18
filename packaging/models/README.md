# PHANTEX — Offline Model Packaging

Ed25519-signed model distribution for air-gap and on-premises deployments.

## Workflow

### 1. Generate Signing Keys (One Time)

```bash
python package_models.py keygen --out keys/
```

This creates:
- `keys/phantex-signing.key` — private key (keep secure, build server only)
- `keys/phantex-signing.pub` — public key (distribute to all targets)

### 2. Package Models

```bash
python package_models.py pack \
    --models-dir ../../backend/models/global \
    --signing-key keys/phantex-signing.key \
    --version 2026.03.06 \
    --output dist/phantex-models-2026.03.06.tar.gz
```

The package contains:
- `MANIFEST.json` — file inventory with SHA-256 hashes + training metadata
- `MANIFEST.sig` — Ed25519 detached signature
- `models/` — all model artifacts (stage1.pkl, stage2.pkl, stage3.pkl, etc.)

### 3. Transfer to Air-Gap Environment

Copy the `.tar.gz` package and `phantex-signing.pub` to the target via:
- USB drive
- Secure file transfer
- Optical media

### 4. Verify on Target

```bash
python package_models.py verify \
    --package phantex-models-2026.03.06.tar.gz \
    --public-key phantex-signing.pub
```

Checks:
1. Ed25519 signature on manifest
2. SHA-256 hash of every file in the archive

### 5. Install

```bash
python package_models.py install \
    --package phantex-models-2026.03.06.tar.gz \
    --public-key phantex-signing.pub \
    --target-dir /opt/phantex/models
```

This will:
1. Verify signature + file integrity
2. Backup current models (timestamped copy)
3. Extract new models
4. Write version marker

### 6. Rollback

```bash
python package_models.py rollback --target-dir /opt/phantex/models
```

Restores the most recent backup created during install.

## Package Contents

| File | Description |
|------|-------------|
| `MANIFEST.json` | Version, creation date, file inventory with SHA-256 hashes |
| `MANIFEST.sig` | Ed25519 detached signature (64 bytes) |
| `models/stage1.pkl` | IsolationForest anomaly detector (~1.3 MB) |
| `models/stage2.pkl` | XGBoost classifier (~3 MB) |
| `models/stage3.pkl` | Autoencoder reconstruction (~58 KB) |
| `models/manifest.json` | Training provenance metadata |
| `models/feature_names.json` | Feature schema |

## Security Model

- **Ed25519 signatures** — 128-bit security level, quantum-resistant pre-image
- **SHA-256 per-file hashes** — tamper detection for individual artifacts
- **Private key never leaves build server** — only public key on targets
- **No pickle execution during verification** — manifest checked before any model loading
- **Automatic backup before install** — safe rollback path
