# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Tests for JB8b — Training Data Store."""

import tempfile

import pytest

from ml.content.trained.data_store import (
    TrainingDataStore,
    _build_seed_data,
)

@pytest.fixture
def store():
    return TrainingDataStore(load_seeds=True)

@pytest.fixture
def empty_store():
    return TrainingDataStore(load_seeds=False)

class TestDataStoreBasics:
    def test_seed_data_loaded(self, store):
        assert store.size > 50

    def test_empty_store(self, empty_store):
        assert empty_store.size == 0

    def test_label_counts(self, store):
        counts = store.label_counts
        assert "malicious" in counts
        assert "benign" in counts
        assert counts["malicious"] > 0
        assert counts["benign"] > 0

    def test_category_counts(self, store):
        counts = store.category_counts
        assert "prompt_injection" in counts
        assert "benign" in counts

    def test_source_counts(self, store):
        counts = store.source_counts
        assert counts.get("seed", 0) == store.size

class TestDataStoreAddSample:
    def test_add_sample(self, empty_store):
        empty_store.add_sample(
            text="test attack",
            label="malicious",
            category="test",
        )
        assert empty_store.size == 1

    def test_add_sample_default_source(self, empty_store):
        empty_store.add_sample(text="x", label="benign")
        samples = empty_store.get_samples()
        assert samples[0].source == "analyst"

    def test_add_sample_custom_source(self, empty_store):
        empty_store.add_sample(text="x", label="benign", source="synthetic")
        samples = empty_store.get_samples()
        assert samples[0].source == "synthetic"

    def test_confidence_clamped(self, empty_store):
        empty_store.add_sample(text="x", label="benign", confidence=5.0)
        samples = empty_store.get_samples()
        assert samples[0].confidence == 1.0

        empty_store.add_sample(text="y", label="benign", confidence=-1.0)
        # Last sample
        all_s = empty_store.get_samples()
        assert all_s[-1].confidence == 0.0

    def test_text_length_capped(self, empty_store):
        long_text = "a" * 100_000
        empty_store.add_sample(text=long_text, label="benign")
        samples = empty_store.get_samples()
        assert len(samples[0].text) <= 8_192

class TestDataStoreFilter:
    def test_filter_by_label(self, store):
        malicious = store.get_samples(label="malicious")
        assert all(s.label == "malicious" for s in malicious)

    def test_filter_by_source(self, store):
        seeds = store.get_samples(source="seed")
        assert all(s.source == "seed" for s in seeds)

    def test_filter_by_confidence(self, store):
        high_conf = store.get_samples(min_confidence=0.9)
        assert all(s.confidence >= 0.9 for s in high_conf)

class TestDataStoreTrainTestSplit:
    def test_split_returns_two_lists(self, store):
        train, test = store.get_training_split()
        assert len(train) > 0
        assert isinstance(train, list)
        assert isinstance(test, list)

    def test_split_covers_all_samples(self, store):
        train, test = store.get_training_split(min_confidence=0.0)
        assert len(train) + len(test) == store.size

    def test_split_fraction(self, store):
        train, test = store.get_training_split(test_fraction=0.3, min_confidence=0.0)
        total = len(train) + len(test)
        # Test should be ~30% of total
        assert abs(len(test) / total - 0.3) < 0.1

class TestDataStorePersistence:
    def test_save_and_load(self, store):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            store.save(path)

            new_store = TrainingDataStore(load_seeds=False)
            new_store.load(path)

            assert new_store.size == store.size
        finally:
            import os

            os.unlink(path)

    def test_load_missing_file(self, empty_store):
        empty_store.load("/nonexistent/file.json")
        assert empty_store.size == 0

class TestDataStoreEviction:
    def test_evicts_at_capacity(self):
        store = TrainingDataStore(load_seeds=False, max_samples=5)
        for i in range(10):
            store.add_sample(
                text=f"sample {i}",
                label="benign",
                source="synthetic",
            )
        assert store.size <= 5

class TestSeedData:
    def test_seed_data_nonempty(self):
        seeds = _build_seed_data()
        assert len(seeds) > 50

    def test_seeds_balanced(self):
        seeds = _build_seed_data()
        malicious = sum(1 for s in seeds if s.label == "malicious")
        benign = sum(1 for s in seeds if s.label == "benign")
        assert malicious > 20
        assert benign > 20

    def test_seeds_valid_fields(self):
        seeds = _build_seed_data()
        for s in seeds:
            assert s.text
            assert s.label in ("malicious", "benign")
            assert s.source == "seed"
            assert s.confidence == 1.0
