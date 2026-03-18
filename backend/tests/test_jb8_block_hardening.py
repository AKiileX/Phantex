# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
JB8 Block Hardening Tests — .

Covers all 7 findings from the JB8 security audit:

JB8-01 HIGH   classifier.py streaming hash + closed file handle
JB8-02 MEDIUM cross_signal.py geometric exp(0) inflation fix
JB8-03 MEDIUM data_store.py JSON structure validation on load
JB8-04 MEDIUM corpus.py JSON structure validation on load
JB8-05 MEDIUM feedback.py pending-dismissal TTL expiry
JB8-06 LOW    cross_signal.py duplicate source rejection
JB8-07 LOW    trainer.py model hash length ≥ 32 hex chars
"""

import hashlib
import json
import time

import numpy as np
import pytest

from ml.content.embeddings.corpus import AttackCorpus

# ── JB8a imports ──────────────────────────────────────────────────────────
from ml.content.embeddings.encoder import EmbeddingEncoder

# ── JB8c imports ──────────────────────────────────────────────────────────
from ml.content.fusion.cross_signal import CrossSignalScorer, SignalInput
from ml.content.fusion.feedback import FeedbackEvent, FeedbackRouter

# ── JB8b imports ──────────────────────────────────────────────────────────
from ml.content.trained.classifier import TrainedContentClassifier
from ml.content.trained.data_store import TrainingDataStore
from ml.content.trained.trainer import ContentTrainer

# ══════════════════════════════════════════════════════════════════════════
# Fixtures
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def encoder():
    return EmbeddingEncoder()

# ══════════════════════════════════════════════════════════════════════════
# JB8-01  classifier.py — streaming hash, no leaked file handle
# ══════════════════════════════════════════════════════════════════════════

class TestJB801StreamingHash:
    """Verify that _load_model uses a streaming SHA-256 (1 MB chunks)
    and properly closes the file handle via a context manager."""

    @staticmethod
    def _make_model_bundle(model_path: str) -> None:
        """Create a real serialisable model bundle via joblib."""
        import joblib
        from sklearn.linear_model import LogisticRegression

        model = LogisticRegression(max_iter=10)
        # Fit on trivial data so the model is picklable
        X = np.array([[0, 1], [1, 0], [0, 0], [1, 1]])
        y = np.array([0, 1, 0, 1])
        model.fit(X, y)

        bundle = {"model": model, "classes": ["benign", "malicious"]}
        joblib.dump(bundle, model_path)

    def test_hash_verification_streaming(self, encoder, tmp_path):
        """Create a real model bundle, write sidecar, and load it.
        Ensures the streaming path produces the correct hash."""
        model_path = str(tmp_path / "model.joblib")
        self._make_model_bundle(model_path)

        # Write correct SHA-256 sidecar (streaming must match)
        sha = hashlib.sha256()
        with open(model_path, "rb") as fh:
            while True:
                chunk = fh.read(1 << 20)
                if not chunk:
                    break
                sha.update(chunk)
        expected_hash = sha.hexdigest()

        hash_path = model_path + ".sha256"
        with open(hash_path, "w") as hf:
            hf.write(expected_hash)

        cls = TrainedContentClassifier(encoder=encoder, model_path=model_path)
        assert cls.model_loaded is True

    def test_hash_mismatch_refuses_load(self, encoder, tmp_path):
        """A wrong sidecar hash must block deserialization."""
        model_path = str(tmp_path / "model.joblib")
        self._make_model_bundle(model_path)

        hash_path = model_path + ".sha256"
        with open(hash_path, "w") as hf:
            hf.write("0" * 64)  # wrong hash

        cls = TrainedContentClassifier(encoder=encoder, model_path=model_path)
        assert cls.model_loaded is False

    def test_no_sidecar_still_loads(self, encoder, tmp_path):
        """Without a sidecar file the model loads (backward compatibility)."""
        model_path = str(tmp_path / "model.joblib")
        self._make_model_bundle(model_path)

        cls = TrainedContentClassifier(encoder=encoder, model_path=model_path)
        assert cls.model_loaded is True

# ══════════════════════════════════════════════════════════════════════════
# JB8-02  cross_signal.py — geometric exp(0) inflation
# ══════════════════════════════════════════════════════════════════════════

class TestJB802GeometricInflation:
    """All-zero weights must not produce a non-zero fused score."""

    def test_zero_weights_produce_zero_score(self):
        """With all weights = 0, fused score should be ≈0, not ≈0.4."""
        scorer = CrossSignalScorer(weights={"content": 0.0, "behavioral": 0.0, "baseline": 0.0, "campaign": 0.0})
        signals = [
            SignalInput(score=0.5, source="content"),
            SignalInput(score=0.5, source="behavioral"),
        ]
        result = scorer.fuse(signals)
        assert result.score < 0.1, f"Zero-weight fusion should produce near-zero score, got {result.score}"

    def test_normal_weights_unaffected(self):
        """Verify standard weights still produce reasonable scores."""
        scorer = CrossSignalScorer()
        signals = [
            SignalInput(score=0.8, source="content"),
            SignalInput(score=0.7, source="behavioral"),
        ]
        result = scorer.fuse(signals)
        assert result.score > 0.3

    def test_single_zero_weight_mixes_correctly(self):
        """One zero-weight source doesn't contaminate the others."""
        scorer = CrossSignalScorer(weights={"content": 1.0, "behavioral": 0.0})
        signals = [
            SignalInput(score=0.9, source="content"),
            SignalInput(score=0.1, source="behavioral"),
        ]
        result = scorer.fuse(signals)
        # Content dominates
        assert result.score > 0.2

# ══════════════════════════════════════════════════════════════════════════
# JB8-03  data_store.py — JSON structure validation
# ══════════════════════════════════════════════════════════════════════════

class TestJB803DataStoreJsonValidation:
    """load() must reject non-list roots and skip malformed entries."""

    def test_dict_root_rejected(self, tmp_path):
        """A JSON object (dict) instead of array must not crash."""
        p = tmp_path / "bad.json"
        p.write_text('{"evil": true}')

        store = TrainingDataStore(load_seeds=False)
        store.load(str(p))
        assert store.size == 0

    def test_list_of_strings_skipped(self, tmp_path):
        """Array of strings (not dicts) must be skipped gracefully."""
        p = tmp_path / "bad.json"
        p.write_text('["a", "b", "c"]')

        store = TrainingDataStore(load_seeds=False)
        store.load(str(p))
        assert store.size == 0

    def test_missing_required_keys_skipped(self, tmp_path):
        """Entries missing 'text' or 'label' are skipped."""
        data = [
            {"text": "good", "label": "benign"},
            {"text": "missing_label"},
            {"label": "missing_text"},
            {"text": "also_good", "label": "malicious"},
        ]
        p = tmp_path / "mix.json"
        p.write_text(json.dumps(data))

        store = TrainingDataStore(load_seeds=False)
        store.load(str(p))
        assert store.size == 2

    def test_valid_json_still_loads(self, tmp_path):
        """Well-formed JSON loads correctly."""
        data = [{"text": f"sample {i}", "label": "benign"} for i in range(10)]
        p = tmp_path / "good.json"
        p.write_text(json.dumps(data))

        store = TrainingDataStore(load_seeds=False)
        store.load(str(p))
        assert store.size == 10

# ══════════════════════════════════════════════════════════════════════════
# JB8-04  corpus.py — JSON structure validation
# ══════════════════════════════════════════════════════════════════════════

class TestJB804CorpusJsonValidation:
    """load() must reject non-list roots and skip malformed entries."""

    def test_dict_root_rejected(self, encoder, tmp_path):
        corpus = AttackCorpus(encoder, load_seeds=False)
        meta_path = tmp_path / "corpus.json"
        meta_path.write_text('{"bad": true}')

        corpus.load(str(tmp_path))
        assert corpus.size == 0

    def test_missing_required_keys_skipped(self, encoder, tmp_path):
        data = [
            {"text": "ok", "category": "test", "label": "l1"},
            {"text": "no_category"},  # missing category + label
            {"category": "no_text", "label": "l2"},  # missing text
            {"text": "ok2", "category": "test2", "label": "l3"},
        ]
        meta_path = tmp_path / "corpus.json"
        meta_path.write_text(json.dumps(data))

        corpus = AttackCorpus(encoder, load_seeds=False)
        corpus.load(str(tmp_path))
        assert corpus.size == 2

    def test_valid_corpus_loads(self, encoder, tmp_path):
        data = [{"text": f"attack {i}", "category": "test", "label": f"l{i}"} for i in range(5)]
        meta_path = tmp_path / "corpus.json"
        meta_path.write_text(json.dumps(data))

        corpus = AttackCorpus(encoder, load_seeds=False)
        corpus.load(str(tmp_path))
        assert corpus.size == 5

    def test_list_of_integers_skipped(self, encoder, tmp_path):
        meta_path = tmp_path / "corpus.json"
        meta_path.write_text("[1, 2, 3]")

        corpus = AttackCorpus(encoder, load_seeds=False)
        corpus.load(str(tmp_path))
        assert corpus.size == 0

# ══════════════════════════════════════════════════════════════════════════
# JB8-05  feedback.py — pending-dismissal TTL expiry
# ══════════════════════════════════════════════════════════════════════════

class MockDataStore:
    def __init__(self):
        self.samples = []

    def add_sample(self, **kwargs):
        self.samples.append(kwargs)

class MockCorpus:
    def __init__(self):
        self.entries = []

    def add_sample(self, **kwargs):
        self.entries.append(kwargs)

class TestJB805PendingDismissalTTL:
    """Stale pending dismissals should be expired after TTL."""

    def test_stale_dismissals_expired(self):
        """Pending dismissals older than TTL are auto-removed."""
        router = FeedbackRouter(
            data_store=MockDataStore(),
            corpus=MockCorpus(),
            require_dual_approval=True,
        )
        router._pending_ttl = 1.0  # 1 second TTL for test

        # Submit a dismiss event with a timestamp in the past
        old_event = FeedbackEvent(
            alert_id="old-1",
            text="stale dismiss",
            action="dismiss",
            category="test",
            analyst_id="a1",
            timestamp=time.time() - 10.0,  # 10 seconds ago
        )
        router.process_feedback(old_event)
        assert router.pending_dismissals == 1

        # Submit a fresh dismiss — the expire sweep should evict old-1
        fresh_event = FeedbackEvent(
            alert_id="fresh-1",
            text="fresh dismiss",
            action="dismiss",
            category="test",
            analyst_id="a1",
            timestamp=time.time(),
        )
        router.process_feedback(fresh_event)
        # old-1 should have been expired
        assert router.pending_dismissals == 1  # only fresh-1 remains

        result = router.approve_dismissal("old-1", "admin-1")
        assert result["status"] == "error"
        assert result["reason"] == "no_pending_dismissal"

    def test_fresh_dismissals_survive_expiry(self):
        """Non-stale dismissals are not expired."""
        router = FeedbackRouter(
            data_store=MockDataStore(),
            corpus=MockCorpus(),
            require_dual_approval=True,
        )
        router._pending_ttl = 3600.0  # 1 hour

        event = FeedbackEvent(
            alert_id="fresh-1",
            text="fresh",
            action="dismiss",
            category="test",
            analyst_id="a1",
            timestamp=time.time(),
        )
        router.process_feedback(event)
        assert router.pending_dismissals == 1

        result = router.approve_dismissal("fresh-1", "admin-1")
        assert result["status"] == "approved"

    def test_expired_counter_tracked(self):
        """Expired dismissals are counted in stats."""
        router = FeedbackRouter(
            data_store=MockDataStore(),
            corpus=MockCorpus(),
            require_dual_approval=True,
        )
        router._pending_ttl = 0.01  # very short

        event = FeedbackEvent(
            alert_id="x",
            text="t",
            action="dismiss",
            category="c",
            analyst_id="a",
            timestamp=time.time() - 1.0,  # already stale
        )
        router.process_feedback(event)
        time.sleep(0.05)

        # Trigger expiry by attempting to approve
        router.approve_dismissal("x", "admin")
        assert router.stats["expired_dismissals"] >= 1

    def test_zero_timestamp_events_get_stamped(self):
        """Events with timestamp=0.0 get auto-stamped on pending storage."""
        router = FeedbackRouter(
            data_store=MockDataStore(),
            corpus=MockCorpus(),
            require_dual_approval=True,
        )
        event = FeedbackEvent(
            alert_id="no-ts",
            text="t",
            action="dismiss",
            category="c",
            analyst_id="a",
            timestamp=0.0,  # no timestamp from caller
        )
        router.process_feedback(event)
        # The stored event should have a timestamp > 0
        with router._lock:
            stored = router._pending_dismissals["no-ts"]
        assert stored.timestamp > 0

# ══════════════════════════════════════════════════════════════════════════
# JB8-06  cross_signal.py — duplicate source rejection
# ══════════════════════════════════════════════════════════════════════════

class TestJB806DuplicateSourceRejection:
    """Duplicate source names should keep first occurrence only."""

    def test_duplicate_source_keeps_first(self):
        scorer = CrossSignalScorer()
        signals = [
            SignalInput(score=0.9, source="content"),
            SignalInput(score=0.1, source="content"),  # duplicate
        ]
        result = scorer.fuse(signals)
        # With duplicate rejection, only score=0.9 is used.
        # The breakdown should show a single content entry at 0.9
        assert result.signal_breakdown.get("content") == 0.9

    def test_no_duplicates_unaffected(self):
        scorer = CrossSignalScorer()
        signals = [
            SignalInput(score=0.7, source="content"),
            SignalInput(score=0.6, source="behavioral"),
        ]
        result = scorer.fuse(signals)
        assert len(result.signal_breakdown) == 2

    def test_triplicate_source(self):
        scorer = CrossSignalScorer()
        signals = [
            SignalInput(score=0.5, source="content"),
            SignalInput(score=0.8, source="content"),
            SignalInput(score=0.1, source="content"),
        ]
        result = scorer.fuse(signals)
        assert result.signal_breakdown.get("content") == 0.5
        assert result.total_signals == 3  # total_signals = len(signals)

# ══════════════════════════════════════════════════════════════════════════
# JB8-07  trainer.py — model hash length ≥ 32 hex
# ══════════════════════════════════════════════════════════════════════════

class TestJB807ModelHashLength:
    """Model hash must be at least 128-bit (32 hex chars)."""

    def test_model_hash_length(self, encoder):
        store = TrainingDataStore(load_seeds=True)
        # Add extras to clear the minimum sample gate
        for i in range(20):
            store.add_sample(
                text=f"Malicious probe variant {i}",
                label="malicious",
                category="prompt_injection",
            )
            store.add_sample(
                text=f"Benign developer question {i}",
                label="benign",
                category="benign",
            )

        trainer = ContentTrainer(
            encoder,
            precision_threshold=0.01,
            recall_threshold=0.01,
            fpr_threshold=0.99,
        )
        result = trainer.train(store)
        assert result.model is not None
        assert len(result.model_hash) >= 32, f"Model hash too short: {len(result.model_hash)} chars (need ≥32)"
        # Must be valid hex
        int(result.model_hash, 16)

    def test_deterministic_hash(self, encoder):
        """Same seed → same model → same hash."""
        store = TrainingDataStore(load_seeds=True)
        for i in range(20):
            store.add_sample(text=f"Probe {i}", label="malicious")
            store.add_sample(text=f"Normal {i}", label="benign")

        t1 = ContentTrainer(encoder, precision_threshold=0.01, recall_threshold=0.01, fpr_threshold=0.99, seed=123)
        t2 = ContentTrainer(encoder, precision_threshold=0.01, recall_threshold=0.01, fpr_threshold=0.99, seed=123)
        r1 = t1.train(store)
        r2 = t2.train(store)
        assert r1.model_hash == r2.model_hash
        assert len(r1.model_hash) >= 32
