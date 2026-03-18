# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Tests for JB8a — Embedding Encoder."""

import numpy as np
import pytest

from ml.content.embeddings.encoder import EmbeddingEncoder

@pytest.fixture
def encoder():
    """Create encoder (will use TF-IDF fallback in test env)."""
    return EmbeddingEncoder()

class TestEncoderBasics:
    def test_creates_without_error(self, encoder):
        assert encoder is not None

    def test_dimension_is_positive(self, encoder):
        assert encoder.dimension > 0
        assert encoder.dimension == 384

    def test_encode_returns_correct_shape(self, encoder):
        vec = encoder.encode("hello world")
        assert vec.shape == (encoder.dimension,)

    def test_encode_batch_returns_correct_shape(self, encoder):
        texts = ["hello", "world", "test"]
        vecs = encoder.encode_batch(texts)
        assert vecs.shape == (3, encoder.dimension)

    def test_encode_empty_list(self, encoder):
        vecs = encoder.encode_batch([])
        assert vecs.shape == (0, encoder.dimension)

    def test_encode_empty_string_is_zero_vector(self, encoder):
        vec = encoder.encode("")
        assert np.allclose(vec, 0.0)

    def test_health_check_passes(self, encoder):
        assert encoder.health_check() is True

    def test_repr(self, encoder):
        r = repr(encoder)
        assert "EmbeddingEncoder" in r

class TestEncoderNormalization:
    def test_vectors_are_unit_norm(self, encoder):
        vec = encoder.encode("This is a test sentence.")
        # Fallback vectors should be L2-normalized (or zero)
        norm = np.linalg.norm(vec)
        if norm > 1e-8:
            assert abs(norm - 1.0) < 0.01

    def test_batch_vectors_are_unit_norm(self, encoder):
        texts = ["first sentence", "second sentence", "third one"]
        vecs = encoder.encode_batch(texts)
        for vec in vecs:
            norm = np.linalg.norm(vec)
            if norm > 1e-8:
                assert abs(norm - 1.0) < 0.01

class TestEncoderDeterminism:
    def test_same_input_same_output(self, encoder):
        v1 = encoder.encode("deterministic test")
        v2 = encoder.encode("deterministic test")
        assert np.allclose(v1, v2)

    def test_different_input_different_output(self, encoder):
        v1 = encoder.encode("the quick brown fox")
        v2 = encoder.encode("a completely different sentence")
        assert not np.allclose(v1, v2)

class TestEncoderHardening:
    def test_long_text_is_capped(self, encoder):
        """Encoder should handle very long text without error."""
        long_text = "word " * 100_000
        vec = encoder.encode(long_text)
        assert vec.shape == (encoder.dimension,)

    def test_unicode_text(self, encoder):
        vec = encoder.encode("こんにちは世界 🌍")
        assert vec.shape == (encoder.dimension,)

    def test_control_characters(self, encoder):
        vec = encoder.encode("text\x00with\x01control\x02chars")
        assert vec.shape == (encoder.dimension,)

    def test_null_bytes(self, encoder):
        vec = encoder.encode("\x00\x00\x00")
        assert vec.shape == (encoder.dimension,)

class TestFallbackMode:
    def test_fallback_flag_set(self, encoder):
        # In test env without sentence-transformers, should be in fallback
        # But this could be either way depending on env
        assert isinstance(encoder.using_fallback, bool)

    def test_fallback_still_produces_vectors(self):
        """Force fallback mode by using an invalid model name."""
        enc = EmbeddingEncoder(model_name="nonexistent_model_xyz_12345")
        assert enc.using_fallback is True
        vec = enc.encode("test sentence")
        assert vec.shape == (enc.dimension,)
