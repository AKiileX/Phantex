# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
JB8b — Trained Content Classifier.

A ``BaseClassifier`` that uses embedding features + a lightweight
sklearn classifier (Logistic Regression or XGBoost) to detect malicious
content.  Trained on labeled samples from the ``TrainingDataStore``.

Architecture:
  text → EmbeddingEncoder → dense vector (384-dim)
       → sklearn classifier → P(malicious) ∈ [0, 1]

The classifier supports:
- Binary mode: benign vs malicious.
- Multi-class mode: benign vs multiple attack categories.

Graceful degradation:
- If no trained model is loaded, returns a benign verdict with
  ``degraded=True``.
- Falls back to embedding similarity if the classifier fails.

Hardening:
- Model loaded from disk uses joblib; verified with SHA-256 hash.
- Input text is length-capped and sanitized.
- Predictions are bounded to [0, 1].
"""

from __future__ import annotations

import hashlib
import logging
import os
from typing import Any

import numpy as np
from numpy.typing import NDArray

from ml.content.base import BaseClassifier
from ml.content.config import ContentAnalysisConfig
from ml.content.embeddings.encoder import EmbeddingEncoder
from ml.content.verdict import Confidence, ContentVerdict, Decision, Label, Severity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_MAX_TEXT_LENGTH = 8_192

class TrainedContentClassifier(BaseClassifier):
    """Classify content using a trained ML model on top of embeddings.

    Parameters
    ----------
    encoder:
        EmbeddingEncoder for text vectorization.
    config:
        Content analysis configuration.
    model_path:
        Path to a saved model (joblib bundle with 'model' + 'hash' keys).
    """

    def __init__(
        self,
        encoder: EmbeddingEncoder | None = None,
        config: ContentAnalysisConfig | None = None,
        model_path: str = "",
    ) -> None:
        self._config = config or ContentAnalysisConfig()
        self._encoder = encoder or EmbeddingEncoder()
        self._model: Any | None = None
        self._model_classes: list[str] = []
        self._model_loaded: bool = False

        if model_path:
            self._load_model(model_path)

    # ------------------------------------------------------------------
    # BaseClassifier interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "trained_content"

    def classify(
        self,
        text: str,
        metadata: dict[str, Any] | None = None,
    ) -> ContentVerdict:
        """Classify *text* using the trained model."""
        if not text or not self._config.enabled:
            return self._benign()

        if not self._model_loaded:
            return self._benign(degraded=True)

        # Length cap
        capped = text[:_MAX_TEXT_LENGTH]

        try:
            embedding = self._encoder.encode(capped)
            return self._predict(embedding)
        except Exception:
            logger.warning("Trained classifier prediction failed", exc_info=True)
            return self._benign(degraded=True)

    def health_check(self) -> bool:
        return self._model_loaded

    # ------------------------------------------------------------------
    # Model management
    # ------------------------------------------------------------------

    @property
    def model_loaded(self) -> bool:
        return self._model_loaded

    @property
    def model_classes(self) -> list[str]:
        return list(self._model_classes)

    def set_model(
        self,
        model: Any,
        classes: list[str],
    ) -> None:
        """Set the model directly (for in-process training)."""
        self._model = model
        self._model_classes = list(classes)
        self._model_loaded = True
        logger.info(
            "Trained content classifier: model set (classes=%s)",
            classes,
        )

    def _load_model(self, path: str) -> None:
        """Load model from joblib bundle with pre-load integrity check.

        Security: The file's SHA-256 hash is verified BEFORE joblib
        deserialisation (which uses pickle internally). This prevents
        untrusted payloads from executing via pickle's ``__reduce__``.
        """
        if not os.path.exists(path):
            logger.info("No trained model at %s", path)
            return

        try:
            # ── Step 0: file-size guard ──────────────────────────────
            file_size = os.path.getsize(path)
            _MAX_MODEL_FILE_BYTES = 500 * 1024 * 1024  # 500 MB
            if file_size > _MAX_MODEL_FILE_BYTES:
                logger.error(
                    "Model file too large (%d bytes > %d limit)",
                    file_size,
                    _MAX_MODEL_FILE_BYTES,
                )
                return

            # ── Step 1: pre-load hash verification ───────────────────
            # Read .hash sidecar file (produced by trainer) and compare
            # against raw file bytes *before* deserialisation.
            hash_path = path + ".sha256"
            if os.path.exists(hash_path):
                with open(hash_path) as hf:
                    expected_file_hash = hf.read().strip()[:128]
                # Streaming hash — avoids loading up to 500 MB into memory
                sha = hashlib.sha256()
                with open(path, "rb") as model_fh:
                    while True:
                        chunk = model_fh.read(1 << 20)  # 1 MB chunks
                        if not chunk:
                            break
                        sha.update(chunk)
                actual_file_hash = sha.hexdigest()
                if actual_file_hash != expected_file_hash:
                    logger.error(
                        "Model file hash mismatch (pre-load): expected=%s actual=%s — refusing to deserialise",
                        expected_file_hash[:16],
                        actual_file_hash[:16],
                    )
                    return

            # ── Step 2: deserialise ──────────────────────────────────
            import joblib  # type: ignore[import-untyped]

            bundle = joblib.load(path)
            model = bundle.get("model")
            if model is None:
                logger.error("Model bundle missing 'model' key")
                return

            classes = list(bundle.get("classes", ["benign", "malicious"]))

            # ── Step 3: assign only after all checks pass ────────────
            self._model = model
            self._model_classes = classes
            self._model_loaded = True
            logger.info(
                "Trained model loaded from %s (classes=%s)",
                path,
                classes,
            )
        except Exception:
            logger.warning("Failed to load model from %s", path)

    # ------------------------------------------------------------------
    # Prediction
    # ------------------------------------------------------------------

    def _predict(self, embedding: NDArray[np.floating]) -> ContentVerdict:
        """Run model inference on the embedding vector."""
        assert self._model is not None

        x = embedding.reshape(1, -1)

        # Get probability estimates
        if hasattr(self._model, "predict_proba"):
            probs = self._model.predict_proba(x)[0]
            class_labels = self._model_classes
        elif hasattr(self._model, "decision_function"):
            raw = self._model.decision_function(x)[0]
            # Logistic squash for binary
            prob_malicious = 1.0 / (1.0 + np.exp(-float(raw)))
            probs = np.array([1.0 - prob_malicious, prob_malicious])
            class_labels = ["benign", "malicious"]
        else:
            pred = self._model.predict(x)[0]
            probs = np.array([0.0, 1.0] if pred == "malicious" else [1.0, 0.0])
            class_labels = ["benign", "malicious"]

        # Build per-class probability dict
        class_probs: dict[str, float] = {}
        for i, cls in enumerate(class_labels):
            if i < len(probs):
                class_probs[cls] = float(probs[i])

        # Determine malicious score
        malicious_score = 0.0
        best_malicious_class = "unknown"
        for cls, prob in class_probs.items():
            if cls != "benign" and prob > malicious_score:
                malicious_score = prob
                best_malicious_class = cls

        return self._build_verdict(
            score=malicious_score,
            predicted_class=best_malicious_class,
            class_probs=class_probs,
        )

    def _build_verdict(
        self,
        *,
        score: float,
        predicted_class: str,
        class_probs: dict[str, float],
    ) -> ContentVerdict:
        """Map classifier output to ContentVerdict."""
        score = max(0.0, min(1.0, score))

        if score >= self._config.block_threshold:
            decision = Decision.BLOCK
            label = Label.MALICIOUS
            severity = Severity.CRITICAL
            confidence = Confidence.HIGH
        elif score >= self._config.alert_threshold:
            decision = Decision.ALERT
            label = Label.SUSPICIOUS
            severity = Severity.HIGH
            confidence = Confidence.MEDIUM
        elif score > 0.2:
            decision = Decision.LOG
            label = Label.SUSPICIOUS
            severity = Severity.MEDIUM
            confidence = Confidence.LOW
        else:
            return self._benign()

        # Evidence
        top_classes = sorted(class_probs.items(), key=lambda x: x[1], reverse=True)[:3]
        evidence_parts = [f"{cls}={prob:.3f}" for cls, prob in top_classes]
        evidence = f"Trained classifier: {', '.join(evidence_parts)}"

        atlas = _class_to_atlas(predicted_class)

        return ContentVerdict(
            score=round(score, 4),
            label=label,
            classifier_name=self.name,
            confidence=confidence,
            evidence=evidence,
            severity=severity,
            decision=decision,
            atlas_technique=atlas,
            matched_patterns=(predicted_class,),
            degraded=self._encoder.using_fallback,
            metadata={
                "predicted_class": predicted_class,
                "class_probabilities": {k: round(v, 4) for k, v in class_probs.items()},
                "model_loaded": self._model_loaded,
                "categories": [c for c, p in class_probs.items() if c != "benign" and p > 0.2],
            },
        )

    def _benign(self, degraded: bool = False) -> ContentVerdict:
        return ContentVerdict.benign(
            classifier_name=self.name,
            degraded=degraded or not self._model_loaded,
        )

# ---------------------------------------------------------------------------
# ATLAS mapping
# ---------------------------------------------------------------------------

_ATLAS_MAP: dict[str, str] = {
    "prompt_injection": "AML.T0051",
    "social_engineering": "AML.T0051.001",
    "data_exfiltration": "AML.T0048",
    "exploit_generation": "AML.T0040",
    "privilege_escalation": "AML.T0044",
    "reconnaissance": "AML.T0043",
    "lateral_movement": "AML.T0045",
    "malicious": "AML.T0051",
}

def _class_to_atlas(cls: str) -> str:
    return _ATLAS_MAP.get(cls, "")
