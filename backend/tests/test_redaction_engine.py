# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Tests for Phase 4, Block AO — Redaction Engine + Credential Integration.

Covers:
- RedactionEngine.redact() produces [REDACTED-{class}] tokens
- RedactionEngine.restore() reverses redaction with correct key
- Restore fails gracefully with wrong key
- Irreversible mode (no master_secret)
- Credential scanning integrated into SemanticDataClassifier
- Sensitivity map includes credential types
- AES-256-GCM encrypt/decrypt round-trip
"""

from __future__ import annotations

import pytest

from ml.content.classifiers.data_classifier import (
    DataClassification,
    DataMatch,
    SemanticDataClassifier,
)
from ml.content.classifiers.redactor import (
    RedactionEngine,
    _aes_gcm_decrypt,
    _aes_gcm_encrypt,
    _derive_key,
)
from ml.content.classifiers.sensitivity import (
    SensitivityLevel,
    classify_sensitivity,
)

# ═══════════════════════════════════════════════════════════════════════
# ──  Credential Integration Tests
# ═══════════════════════════════════════════════════════════════════════

class TestCredentialIntegration:
    """Verify credential scanning is wired into SemanticDataClassifier."""

    def test_api_key_detected(self):
        """An OpenAI-style API key should be detected and classified."""
        classifier = SemanticDataClassifier()
        text = "Use this key: sk-abcdefghijklmnopqrstuvwxyz1234 for auth"
        result = classifier.classify(text)
        cred_matches = [
            m
            for m in result.matches
            if "secret" in m.context.lower()
            or "API_KEY" in m.data_type
            or "SECRET_KEY" in m.data_type
            or "CREDENTIAL" in m.data_type
        ]
        assert len(cred_matches) >= 1, f"Expected credential match, got {result.matches}"

    def test_aws_key_detected(self):
        """An AWS access key should be detected."""
        classifier = SemanticDataClassifier()
        text = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
        result = classifier.classify(text)
        cred_matches = [
            m
            for m in result.matches
            if "secret" in m.context.lower() or m.data_type in ("API_KEY", "SECRET_KEY", "CREDENTIAL")
        ]
        assert len(cred_matches) >= 1

    def test_credential_sensitivity_critical(self):
        """Credential data types should map to CRITICAL sensitivity."""
        result = classify_sensitivity(["API_KEY"])
        assert result.level == SensitivityLevel.CRITICAL

    def test_credential_label(self):
        """Credential data types should produce CREDENTIAL label."""
        result = classify_sensitivity(["API_KEY", "SECRET_KEY"])
        assert "CREDENTIAL" in result.data_labels

    def test_credential_compliance_sox(self):
        """Credential types should have SOX compliance tag."""
        result = classify_sensitivity(["API_KEY"])
        assert "SOX" in result.compliance_tags

# ═══════════════════════════════════════════════════════════════════════
# ──  AES-256-GCM Round-Trip Tests
# ═══════════════════════════════════════════════════════════════════════

class TestAesGcm:
    """Basic AES-GCM encrypt/decrypt round-trip."""

    def test_round_trip(self):
        key = _derive_key(b"test-master-secret-32-bytes-long!", "tenant-1")
        plaintext = b"Hello sensitive world"
        blob = _aes_gcm_encrypt(key, plaintext)
        recovered = _aes_gcm_decrypt(key, blob)
        assert recovered == plaintext

    def test_different_tenant_fails(self):
        key1 = _derive_key(b"test-master-secret-32-bytes-long!", "tenant-1")
        key2 = _derive_key(b"test-master-secret-32-bytes-long!", "tenant-2")
        blob = _aes_gcm_encrypt(key1, b"secret data")
        with pytest.raises(Exception):
            _aes_gcm_decrypt(key2, blob)

    def test_derive_key_deterministic(self):
        k1 = _derive_key(b"seed", "t")
        k2 = _derive_key(b"seed", "t")
        assert k1 == k2
        assert len(k1) == 32

    def test_derive_key_rejects_empty_tenant(self):
        """Empty tenant_id must be rejected to prevent shared key derivation."""
        with pytest.raises(ValueError, match="tenant_id must not be empty"):
            _derive_key(b"seed", "")

# ═══════════════════════════════════════════════════════════════════════
# ──  Redaction Engine Tests
# ═══════════════════════════════════════════════════════════════════════

class TestRedactionEngine:
    """Tests for reversible inline redaction."""

    @staticmethod
    def _make_classification(matches: list[DataMatch]) -> DataClassification:
        """Build a minimal DataClassification for testing."""
        return DataClassification(
            labels=("PII",),
            matches=tuple(matches),
            sensitivity=SensitivityLevel.HIGH,
            compliance_tags=("GDPR",),
        )

    def test_redact_replaces_with_token(self):
        text = "SSN is 123-45-6789 here"
        match = DataMatch(
            data_type="SSN",
            redacted_value="***-**-6789",
            offset=7,
            length=11,
            confidence=0.95,
        )
        engine = RedactionEngine(master_secret=b"secret-key-for-testing-32-bytes!")
        result = engine.redact(text, self._make_classification([match]), "t1")
        assert "[REDACTED-SSN]" in result.redacted_text
        assert "123-45-6789" not in result.redacted_text
        assert result.token_count == 1

    def test_redact_restore_round_trip(self):
        text = "Email: john@example.com, SSN: 123-45-6789"
        matches = [
            DataMatch(data_type="EMAIL", redacted_value="***@example.com", offset=7, length=16, confidence=0.99),
            DataMatch(data_type="SSN", redacted_value="***-**-6789", offset=30, length=11, confidence=0.95),
        ]
        secret = b"round-trip-master-secret-32bytes"
        engine = RedactionEngine(master_secret=secret)
        classification = self._make_classification(matches)
        redacted = engine.redact(text, classification, "t1")
        assert "john@example.com" not in redacted.redacted_text
        assert "123-45-6789" not in redacted.redacted_text

        restored = engine.restore(redacted.redacted_text, redacted.tokens, "t1")
        assert restored.restored_text == text
        assert restored.tokens_restored == 2
        assert not restored.errors

    def test_redact_no_matches_passthrough(self):
        text = "Nothing sensitive here"
        classification = DataClassification(
            labels=(),
            matches=(),
            sensitivity=SensitivityLevel.NONE,
            compliance_tags=(),
        )
        engine = RedactionEngine(master_secret=b"x" * 32)
        result = engine.redact(text, classification, "t1")
        assert result.redacted_text == text
        assert result.token_count == 0

    def test_irreversible_without_secret(self):
        text = "SSN: 123-45-6789"
        match = DataMatch(data_type="SSN", redacted_value="***-**-6789", offset=5, length=11, confidence=0.95)
        engine = RedactionEngine(master_secret=None)
        result = engine.redact(text, self._make_classification([match]))
        assert "[REDACTED-SSN]" in result.redacted_text
        # Tokens have no encrypted value
        assert result.tokens[0].encrypted_value == ""

        restored = engine.restore(result.redacted_text, result.tokens)
        assert restored.tokens_restored == 0
        assert len(restored.errors) > 0

    def test_wrong_key_fails_restore(self):
        text = "CC: 4111111111111111"
        match = DataMatch(data_type="CREDIT_CARD", redacted_value="****1111", offset=4, length=16, confidence=0.95)
        engine1 = RedactionEngine(master_secret=b"key1-32-bytes-long-for-testing!!")
        engine2 = RedactionEngine(master_secret=b"key2-different-secret-for-test!!")
        classification = self._make_classification([match])

        redacted = engine1.redact(text, classification, "t1")
        restored = engine2.restore(redacted.redacted_text, redacted.tokens, "t1")
        assert restored.tokens_restored == 0
        assert len(restored.errors) > 0

    def test_duplicate_types_disambiguated(self):
        text = "SSN1: 111-22-3333, SSN2: 444-55-6666"
        matches = [
            DataMatch(data_type="SSN", redacted_value="***-**-3333", offset=6, length=11, confidence=0.95),
            DataMatch(data_type="SSN", redacted_value="***-**-6666", offset=26, length=11, confidence=0.95),
        ]
        engine = RedactionEngine(master_secret=b"test-master-secret-32-bytes-ok!!")
        result = engine.redact(text, self._make_classification(matches), "t1")
        assert "[REDACTED-SSN#" in result.redacted_text
        assert result.token_count == 2

    def test_redact_to_json(self):
        text = "My email is alice@example.com"
        match = DataMatch(data_type="EMAIL", redacted_value="***@example.com", offset=12, length=17, confidence=0.99)
        engine = RedactionEngine(master_secret=b"json-test-secret-32-bytes-long!!")
        classification = self._make_classification([match])
        payload = engine.redact_to_json(text, classification, "t1")
        assert "redacted_text" in payload
        assert "tokens" in payload
        assert payload["token_count"] == 1
        assert payload["sensitivity"] == "high"

# ═══════════════════════════════════════════════════════════════════════
# ──  End-to-End: Classify → Redact → Restore
# ═══════════════════════════════════════════════════════════════════════

class TestEndToEnd:
    """Full pipeline: SemanticDataClassifier → RedactionEngine → restore."""

    def test_full_pipeline(self):
        text = "Patient John Doe, SSN 123-45-6789, email john@hospital.org. MRN: 987654321. Card: 4111111111111111."
        classifier = SemanticDataClassifier()
        classification = classifier.classify(text)
        assert len(classification.matches) >= 3  # SSN + email + CC at least

        secret = b"e2e-pipeline-master-secret-32b!!"
        engine = RedactionEngine(master_secret=secret)
        redacted = engine.redact(text, classification, "test-tenant")
        assert "123-45-6789" not in redacted.redacted_text
        assert "john@hospital.org" not in redacted.redacted_text
        assert "[REDACTED-" in redacted.redacted_text

        restored = engine.restore(redacted.redacted_text, redacted.tokens, "test-tenant")
        assert restored.restored_text == text
        assert restored.errors == []
