# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Tests for JB8b — Content Trainer & Validator."""

import pytest

from ml.content.embeddings.encoder import EmbeddingEncoder
from ml.content.trained.data_store import TrainingDataStore
from ml.content.trained.trainer import ContentTrainer, TrainingResult
from ml.content.trained.validator import ContentValidator, ValidationResult


@pytest.fixture
def encoder():
    return EmbeddingEncoder()

@pytest.fixture
def store():
    """Seed store augmented to exceed _MIN_SAMPLES after train/test split."""
    s = TrainingDataStore(load_seeds=True)
    # Seeds = 58; 80% train ≈ 46 which is < 50.  Add extras to clear the gate.
    for i in range(20):
        s.add_sample(text=f"Malicious probe variant {i}", label="malicious", category="prompt_injection")
        s.add_sample(text=f"Benign developer question {i}", label="benign", category="benign")
    return s

@pytest.fixture
def trainer(encoder):
    return ContentTrainer(encoder)

# =========================================================================
# Trainer tests
# =========================================================================

class TestTrainerBasics:
    def test_insufficient_data(self, trainer):
        empty = TrainingDataStore(load_seeds=False)
        for i in range(5):
            empty.add_sample(text=f"sample {i}", label="benign")
        result = trainer.train(empty)
        assert result.success is False
        assert "Insufficient" in result.error

    def test_train_with_seeds(self, trainer, store):
        """Full pipeline on seed data — may not pass gate but should run."""
        result = trainer.train(store)
        assert isinstance(result, TrainingResult)
        assert result.metrics is not None
        assert result.model_hash != ""
        assert result.duration_seconds >= 0

    def test_train_binary_mode(self, trainer, store):
        result = trainer.train(store, mode="binary")
        assert isinstance(result, TrainingResult)
        if result.success:
            assert "benign" in result.classes
            assert "malicious" in result.classes

    def test_train_multiclass_mode(self, trainer, store):
        result = trainer.train(store, mode="multiclass")
        assert isinstance(result, TrainingResult)
        if result.success:
            assert len(result.classes) > 2

    def test_training_result_to_dict(self, trainer, store):
        result = trainer.train(store)
        d = result.to_dict()
        assert "success" in d
        assert "model_hash" in d
        assert "duration_seconds" in d
        assert "metrics" in d

class TestTrainerMetrics:
    def test_metrics_fields(self, trainer, store):
        result = trainer.train(store)
        if result.metrics:
            m = result.metrics
            assert 0 <= m.precision <= 1
            assert 0 <= m.recall <= 1
            assert 0 <= m.fpr <= 1
            assert 0 <= m.f1 <= 1
            assert m.train_samples > 0

    def test_metrics_to_dict(self, trainer, store):
        result = trainer.train(store)
        if result.metrics:
            d = result.metrics.to_dict()
            assert "precision" in d
            assert "recall" in d
            assert "fpr" in d
            assert "passed_gate" in d

class TestTrainerQualityGate:
    def test_custom_thresholds(self, encoder):
        # Very loose thresholds — should pass
        t = ContentTrainer(
            encoder,
            precision_threshold=0.01,
            recall_threshold=0.01,
            fpr_threshold=0.99,
        )
        store = TrainingDataStore(load_seeds=True)
        result = t.train(store)
        # With loose thresholds, should likely pass
        assert isinstance(result, TrainingResult)

class TestTrainerSampleWeights:
    def test_weight_computation(self):
        from ml.content.trained.data_store import TrainingSample

        samples = [
            TrainingSample(text="a", label="malicious", source="analyst", confidence=1.0),
            TrainingSample(text="b", label="benign", source="seed", confidence=1.0),
            TrainingSample(text="c", label="benign", source="synthetic", confidence=0.5),
        ]
        weights = ContentTrainer._compute_sample_weights(samples)
        assert len(weights) == 3
        # Analyst (3.0) should have highest weight
        assert weights[0] > weights[1]
        # Synthetic with low confidence should have lowest
        assert weights[2] < weights[1]
        # Mean should be ~1 (normalized)
        assert abs(weights.mean() - 1.0) < 0.01

class TestTrainerAlgorithms:
    def test_logistic_regression(self, encoder, store):
        t = ContentTrainer(encoder)
        result = t.train(store, algorithm="logistic_regression")
        assert isinstance(result, TrainingResult)
        assert result.model is not None

    def test_xgboost(self, encoder, store):
        t = ContentTrainer(encoder)
        result = t.train(store, algorithm="xgboost")
        assert isinstance(result, TrainingResult)
        assert result.model is not None

class TestTrainerReproducibility:
    def test_deterministic_seed(self, encoder, store):
        t1 = ContentTrainer(encoder, seed=42)
        t2 = ContentTrainer(encoder, seed=42)
        r1 = t1.train(store)
        r2 = t2.train(store)
        # Same seed should produce same hash
        assert r1.model_hash == r2.model_hash

# =========================================================================
# Validator tests
# =========================================================================

class TestValidatorBasics:
    def test_no_samples(self, encoder):
        v = ContentValidator(encoder)
        result = v.validate(model=None, test_samples=[])
        assert result.passed is False
        assert "No test samples" in result.errors[0]

    def test_too_few_samples(self, encoder):
        from ml.content.trained.data_store import TrainingSample

        samples = [TrainingSample(text=f"s{i}", label="benign") for i in range(5)]
        v = ContentValidator(encoder)
        result = v.validate(model=None, test_samples=samples)
        assert result.passed is False

class TestValidatorWithTrainedModel:
    def test_validate_trained_model(self, encoder, store):
        """Train, then validate on test split."""
        t = ContentTrainer(encoder, precision_threshold=0.01, recall_threshold=0.01, fpr_threshold=0.99)
        train_result = t.train(store)

        if train_result.model is not None:
            _, test_samples = store.get_training_split()
            if len(test_samples) >= 10:
                v = ContentValidator(encoder)
                val_result = v.validate(train_result.model, test_samples)
                assert isinstance(val_result, ValidationResult)
                assert 0 <= val_result.precision <= 1
                assert 0 <= val_result.recall <= 1

    def test_validation_result_fields(self, encoder, store):
        t = ContentTrainer(encoder, precision_threshold=0.01, recall_threshold=0.01, fpr_threshold=0.99)
        train_result = t.train(store)

        if train_result.model is not None:
            _, test_samples = store.get_training_split()
            if len(test_samples) >= 10:
                v = ContentValidator(encoder)
                val_result = v.validate(train_result.model, test_samples)
                assert hasattr(val_result, "precision")
                assert hasattr(val_result, "recall")
                assert hasattr(val_result, "fpr")
                assert hasattr(val_result, "f1")
                assert hasattr(val_result, "n_samples")
