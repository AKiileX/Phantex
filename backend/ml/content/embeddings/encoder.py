# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
JB8a — Sentence Embedding Encoder.

Wraps sentence-transformers (or a TF-IDF fallback) to produce fixed-size
embedding vectors from raw text.

Graceful degradation:
- If ``sentence-transformers`` is installed → use the configured model.
- Otherwise → fall back to a hashed TF-IDF representation (lower quality
  but zero extra dependencies).

Thread-safety: the encoder is immutable after ``__init__``; the underlying
models are read-only.
"""

from __future__ import annotations

import hashlib
import logging
import math
import re
from collections.abc import Sequence
from typing import Any

import numpy as np
from numpy.typing import NDArray

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_DEFAULT_MODEL_NAME = "all-MiniLM-L6-v2"
_DEFAULT_DIM = 384  # all-MiniLM-L6-v2 output dimension
_FALLBACK_DIM = 384  # TF-IDF fallback dimension (kept identical)
_MAX_TEXT_LENGTH = 8_192  # Truncate text before embedding (hardening)
_TOKEN_PATTERN = re.compile(r"\b\w{2,}\b", re.UNICODE)

class EmbeddingEncoder:
    """Produce normalized embedding vectors from text.

    Parameters
    ----------
    model_name:
        HuggingFace model identifier for sentence-transformers.
    device:
        ``"cpu"`` (default) or ``"cuda"``.
    """

    def __init__(
        self,
        model_name: str = _DEFAULT_MODEL_NAME,
        device: str = "cpu",
    ) -> None:
        self._model_name = model_name
        self._device = device
        self._st_model: Any | None = None
        self._dim: int = _DEFAULT_DIM
        self._using_fallback: bool = False
        self._load_model()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def dimension(self) -> int:
        """Embedding dimension (constant per model)."""
        return self._dim

    @property
    def using_fallback(self) -> bool:
        """True if running the TF-IDF fallback instead of sentence-transformers."""
        return self._using_fallback

    def encode(self, text: str) -> NDArray[np.floating]:
        """Embed a single text string → normalized vector of shape ``(dim,)``."""
        return self.encode_batch([text])[0]

    def encode_batch(self, texts: Sequence[str]) -> NDArray[np.floating]:
        """Embed multiple texts → ``(n, dim)`` array of unit-norm vectors.

        All texts are truncated to ``_MAX_TEXT_LENGTH`` before encoding.
        Empty strings produce the zero vector.
        """
        if not texts:
            return np.zeros((0, self._dim), dtype=np.float32)

        # Hardening: length-cap each text
        capped = [t[:_MAX_TEXT_LENGTH] if t else "" for t in texts]

        if self._st_model is not None:
            return self._encode_st(capped)
        return self._encode_fallback(capped)

    def health_check(self) -> bool:
        """Return True if the encoder is operational (even in fallback)."""
        try:
            vec = self.encode("health check probe")
            return vec.shape == (self._dim,)
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Sentence-transformers path
    # ------------------------------------------------------------------

    def _load_model(self) -> None:
        """Attempt to load sentence-transformers; fall back to TF-IDF."""
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore[import-untyped]

            self._st_model = SentenceTransformer(self._model_name, device=self._device)
            dim = self._st_model.get_sentence_embedding_dimension()
            if dim:
                self._dim = int(dim)
            logger.info(
                "EmbeddingEncoder: loaded %s (dim=%d, device=%s)",
                self._model_name,
                self._dim,
                self._device,
            )
        except Exception as exc:
            logger.warning(
                "EmbeddingEncoder: sentence-transformers not available (%s); using TF-IDF fallback",
                exc,
            )
            self._st_model = None
            self._dim = _FALLBACK_DIM
            self._using_fallback = True

    def _encode_st(self, texts: list[str]) -> NDArray[np.floating]:
        """Encode via sentence-transformers."""
        assert self._st_model is not None
        embeddings = self._st_model.encode(
            texts,
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=False,
            batch_size=min(len(texts), 64),
        )
        return np.asarray(embeddings, dtype=np.float32)

    # ------------------------------------------------------------------
    # TF-IDF Hashed Fallback (no external model needed)
    # ------------------------------------------------------------------

    def _encode_fallback(self, texts: list[str]) -> NDArray[np.floating]:
        """Hashed TF-IDF fallback — deterministic, no ML model required."""
        embeddings = np.zeros((len(texts), self._dim), dtype=np.float32)

        for i, text in enumerate(texts):
            if not text.strip():
                continue
            embeddings[i] = self._tfidf_hash(text)

        return embeddings

    def _tfidf_hash(self, text: str) -> NDArray[np.floating]:
        """Feature-hash text tokens into a fixed-size normalized vector."""
        text_lower = text.lower()
        tokens = _TOKEN_PATTERN.findall(text_lower)
        if not tokens:
            return np.zeros(self._dim, dtype=np.float32)

        # Count term frequencies
        tf: dict[str, int] = {}
        for tok in tokens:
            tf[tok] = tf.get(tok, 0) + 1

        vec = np.zeros(self._dim, dtype=np.float32)
        n_tokens = len(tokens)

        for term, count in tf.items():
            # Feature hashing: deterministic bucket from term
            h = hashlib.sha256(term.encode("utf-8")).digest()
            bucket = int.from_bytes(h[:4], "big") % self._dim
            sign = 1.0 if h[4] & 1 else -1.0  # ±1 sign trick

            # TF * IDF approximation (IDF estimated from token frequency)
            tfidf = (count / n_tokens) * math.log(1.0 + n_tokens / count)
            vec[bucket] += sign * tfidf

        # L2 normalize
        norm = np.linalg.norm(vec)
        if norm > 1e-8:
            vec /= norm

        return vec

    # ------------------------------------------------------------------
    # Repr
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        mode = "fallback" if self._using_fallback else self._model_name
        return f"EmbeddingEncoder(mode={mode}, dim={self._dim})"
