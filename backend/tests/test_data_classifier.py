# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Tests for JB4 — Semantic Data Classifier.

Covers:
- PII detection (SSN, email, phone, address, DOB, passport, DL)
- PHI detection (MRN, ICD-10, drugs, lab results, patient IDs)
- Financial detection (credit card + Luhn, bank account, IBAN, SWIFT, crypto)
- Sensitivity scoring + compliance tag mapping
- SemanticDataClassifier orchestrator
- Custom proprietary patterns per tenant
- False-positive resistance
- Redaction safety (no raw values in results)
- Performance (< 10ms for ≤ 8KB)
"""

from __future__ import annotations

import time

import pytest

from ml.content.classifiers.data_classifier import (
    DataClassification,
    SemanticDataClassifier,
)
from ml.content.classifiers.sensitivity import (
    SensitivityLevel,
    classify_sensitivity,
)
from ml.content.data.financial_patterns import (
    luhn_check,
    scan_for_financial,
)
from ml.content.data.phi_patterns import scan_for_phi
from ml.content.data.pii_patterns import scan_for_pii

# ═══════════════════════════════════════════════════════════════════════
# ──  PII Pattern Tests
# ═══════════════════════════════════════════════════════════════════════

class TestPIIPatterns:
    """Tests for pii_patterns.py."""

    # ── SSN ──────────────────────────────────────────────────────────

    @pytest.mark.parametrize(
        "ssn",
        [
            "123-45-6789",
            "078-05-1120",
            "219-09-9999",
            "001-01-0001",
        ],
    )
    def test_ssn_detected(self, ssn: str):
        hits = scan_for_pii(f"SSN is {ssn}")
        ssn_hits = [h for h in hits if h.data_type == "SSN"]
        assert len(ssn_hits) >= 1
        # Redacted: last 4 visible
        assert ssn[-4:] in ssn_hits[0].redacted_value
        assert ssn not in ssn_hits[0].redacted_value

    @pytest.mark.parametrize(
        "invalid",
        [
            "000-12-3456",  # Area 000 invalid
            "666-12-3456",  # Area 666 invalid
            "900-12-3456",  # 900-999 invalid
            "123-00-3456",  # Group 00 invalid
            "123-45-0000",  # Serial 0000 invalid
        ],
    )
    def test_ssn_invalid_rejected(self, invalid: str):
        """Format validation rejects known-invalid SSNs."""
        hits = scan_for_pii(f"Value: {invalid}")
        ssn_hits = [h for h in hits if h.data_type == "SSN"]
        assert len(ssn_hits) == 0

    # ── Email ────────────────────────────────────────────────────────

    @pytest.mark.parametrize(
        "email",
        [
            "user@example.com",
            "first.last@company.co.uk",
            "test+tag@gmail.com",
        ],
    )
    def test_email_detected(self, email: str):
        hits = scan_for_pii(f"Contact: {email}")
        email_hits = [h for h in hits if h.data_type == "EMAIL"]
        assert len(email_hits) >= 1
        # Domain visible, username redacted
        assert "***@" in email_hits[0].redacted_value

    # ── Phone ────────────────────────────────────────────────────────

    @pytest.mark.parametrize(
        "phone",
        [
            "(555) 123-4567",
            "555-123-4567",
            "+1-555-123-4567",
            "+15551234567",
        ],
    )
    def test_phone_detected(self, phone: str):
        hits = scan_for_pii(f"Call {phone} for info")
        phone_hits = [h for h in hits if h.data_type == "PHONE"]
        assert len(phone_hits) >= 1

    # ── DOB ──────────────────────────────────────────────────────────

    def test_dob_near_keyword(self):
        text = "Date of Birth: 01/15/1990"
        hits = scan_for_pii(text)
        dob_hits = [h for h in hits if h.data_type == "DOB"]
        assert len(dob_hits) >= 1

    def test_date_without_dob_keyword_ignored(self):
        """A date without DOB context should NOT trigger."""
        text = "Meeting scheduled for 01/15/2024"
        hits = scan_for_pii(text)
        dob_hits = [h for h in hits if h.data_type == "DOB"]
        assert len(dob_hits) == 0

    # ── Passport ─────────────────────────────────────────────────────

    def test_passport_near_keyword(self):
        text = "Passport number: C12345678"
        hits = scan_for_pii(text)
        pp_hits = [h for h in hits if h.data_type == "PASSPORT"]
        assert len(pp_hits) >= 1
        # Redacted
        assert "C12345678" not in pp_hits[0].redacted_value

    def test_alphanumeric_without_passport_keyword_ignored(self):
        text = "Reference: C12345678"
        hits = scan_for_pii(text)
        pp_hits = [h for h in hits if h.data_type == "PASSPORT"]
        assert len(pp_hits) == 0

    # ── Driver's License ─────────────────────────────────────────────

    def test_dl_near_keyword(self):
        text = "Driver's license number: D1234567"
        hits = scan_for_pii(text)
        dl_hits = [h for h in hits if h.data_type == "DRIVERS_LICENSE"]
        assert len(dl_hits) >= 1

    def test_alphanumeric_without_dl_keyword_ignored(self):
        text = "Order: D1234567"
        hits = scan_for_pii(text)
        dl_hits = [h for h in hits if h.data_type == "DRIVERS_LICENSE"]
        assert len(dl_hits) == 0

# ═══════════════════════════════════════════════════════════════════════
# ──  PHI Pattern Tests
# ═══════════════════════════════════════════════════════════════════════

class TestPHIPatterns:
    """Tests for phi_patterns.py."""

    def test_mrn_detected(self):
        text = "MRN: 123456789"
        hits = scan_for_phi(text)
        mrn_hits = [h for h in hits if h.data_type == "MRN"]
        assert len(mrn_hits) >= 1
        assert "123456789" not in mrn_hits[0].redacted_value

    def test_icd10_with_context(self):
        text = "Primary diagnosis: ICD-10 code E11.9 (Type 2 diabetes)"
        hits = scan_for_phi(text)
        icd_hits = [h for h in hits if h.data_type == "ICD10"]
        assert len(icd_hits) >= 1

    def test_icd10_without_context_ignored(self):
        """ICD-10-like code without medical context → not flagged."""
        text = "Product code: A12.3"
        hits = scan_for_phi(text)
        icd_hits = [h for h in hits if h.data_type == "ICD10"]
        assert len(icd_hits) == 0

    def test_drug_with_prescription_context(self):
        text = "Patient prescribed lisinopril 10mg once daily"
        hits = scan_for_phi(text)
        drug_hits = [h for h in hits if h.data_type == "DRUG"]
        assert len(drug_hits) >= 1

    def test_drug_without_context_ignored(self):
        """Drug name mentioned casually (no prescription context) → not flagged."""
        text = "The company Pfizer makes vaccines."
        hits = scan_for_phi(text)
        drug_hits = [h for h in hits if h.data_type == "DRUG"]
        assert len(drug_hits) == 0

    def test_lab_result_detected(self):
        text = "Lab: glucose: 126 mg/dL, A1C: 7.2%"
        hits = scan_for_phi(text)
        lab_hits = [h for h in hits if h.data_type == "LAB_RESULT"]
        assert len(lab_hits) >= 1

    def test_patient_id_detected(self):
        text = "Patient name: John Smith"
        hits = scan_for_phi(text)
        pt_hits = [h for h in hits if h.data_type == "PATIENT_ID"]
        assert len(pt_hits) >= 1
        assert "John Smith" not in pt_hits[0].redacted_value

# ═══════════════════════════════════════════════════════════════════════
# ──  Financial Pattern Tests
# ═══════════════════════════════════════════════════════════════════════

class TestFinancialPatterns:
    """Tests for financial_patterns.py."""

    # ── Luhn algorithm ───────────────────────────────────────────────

    @pytest.mark.parametrize(
        "number,valid",
        [
            ("4111111111111111", True),  # Visa test card (Luhn-valid)
            ("5500000000000004", True),  # Mastercard test
            ("371449635398431", True),  # Amex test
            ("6011111111111117", True),  # Discover test
            ("4111111111111112", False),  # Visa invalid (last digit wrong)
            ("1234567890123456", False),  # Random 16 digits
            ("0000000000000000", True),  # Trivially Luhn-valid
        ],
    )
    def test_luhn_check(self, number: str, valid: bool):
        assert luhn_check(number) is valid

    def test_luhn_rejects_too_short(self):
        assert luhn_check("123456") is False

    # ── Credit card detection ────────────────────────────────────────

    def test_visa_test_card_detected(self):
        """Acceptance: CC with Luhn → detected."""
        text = "Card: 4111 1111 1111 1111"
        hits = scan_for_financial(text)
        cc_hits = [h for h in hits if h.data_type == "CREDIT_CARD"]
        assert len(cc_hits) >= 1
        assert cc_hits[0].confidence >= 0.99
        assert "Luhn" in cc_hits[0].context

    def test_random_16_digits_not_flagged(self):
        """Acceptance: Random 16-digit without valid Luhn → NOT flagged."""
        text = "Reference: 1234567890123456"
        hits = scan_for_financial(text)
        cc_hits = [h for h in hits if h.data_type == "CREDIT_CARD"]
        assert len(cc_hits) == 0

    def test_cc_redacted(self):
        text = "4111111111111111"
        hits = scan_for_financial(text)
        if hits:
            cc = hits[0]
            assert "4111111111111111" not in cc.redacted_value
            assert "1111" in cc.redacted_value  # Last 4

    @pytest.mark.parametrize(
        "card,brand",
        [
            ("4111111111111111", "Visa"),
            ("5500000000000004", "Mastercard"),
            ("371449635398431", "Amex"),
        ],
    )
    def test_card_brand_detected(self, card: str, brand: str):
        hits = scan_for_financial(card)
        cc_hits = [h for h in hits if h.data_type == "CREDIT_CARD"]
        assert len(cc_hits) >= 1
        assert brand in cc_hits[0].context

    # ── Bank routing / account ───────────────────────────────────────

    def test_routing_number_detected(self):
        text = "Routing number: 021000021"
        hits = scan_for_financial(text)
        rt_hits = [h for h in hits if h.data_type == "ROUTING_NUMBER"]
        assert len(rt_hits) >= 1

    def test_bank_account_detected(self):
        text = "Bank account number: 123456789012"
        hits = scan_for_financial(text)
        acct_hits = [h for h in hits if h.data_type == "BANK_ACCOUNT"]
        assert len(acct_hits) >= 1

    # ── IBAN ─────────────────────────────────────────────────────────

    def test_iban_with_context(self):
        text = "IBAN: DE89370400440532013000"
        hits = scan_for_financial(text)
        iban_hits = [h for h in hits if h.data_type == "IBAN"]
        assert len(iban_hits) >= 1

    def test_iban_without_context_ignored(self):
        text = "Code: DE89370400440532013000"
        hits = scan_for_financial(text)
        iban_hits = [h for h in hits if h.data_type == "IBAN"]
        assert len(iban_hits) == 0

    # ── SWIFT ────────────────────────────────────────────────────────

    def test_swift_with_context(self):
        text = "SWIFT code: DEUTDEFF"
        hits = scan_for_financial(text)
        swift_hits = [h for h in hits if h.data_type == "SWIFT"]
        assert len(swift_hits) >= 1

    # ── Crypto ───────────────────────────────────────────────────────

    def test_eth_address_detected(self):
        text = "Send to 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD09"
        hits = scan_for_financial(text)
        eth_hits = [h for h in hits if h.data_type == "CRYPTO_ETH"]
        assert len(eth_hits) >= 1

# ═══════════════════════════════════════════════════════════════════════
# ──  Sensitivity Scorer Tests
# ═══════════════════════════════════════════════════════════════════════

class TestSensitivityScorer:
    """Tests for sensitivity.py."""

    def test_no_data_types_none(self):
        result = classify_sensitivity([])
        assert result.level == SensitivityLevel.NONE
        assert result.compliance_tags == ()
        assert result.data_labels == ()

    def test_ssn_critical_gdpr(self):
        result = classify_sensitivity(["SSN"])
        assert result.level == SensitivityLevel.CRITICAL
        assert "GDPR" in result.compliance_tags
        assert "CCPA" in result.compliance_tags
        assert "PII" in result.data_labels

    def test_credit_card_critical_pci(self):
        result = classify_sensitivity(["CREDIT_CARD"])
        assert result.level == SensitivityLevel.CRITICAL
        assert "PCI-DSS" in result.compliance_tags
        assert "FINANCIAL" in result.data_labels

    def test_mrn_critical_hipaa(self):
        result = classify_sensitivity(["MRN"])
        assert result.level == SensitivityLevel.CRITICAL
        assert "HIPAA" in result.compliance_tags
        assert "PHI" in result.data_labels

    def test_email_medium_gdpr(self):
        result = classify_sensitivity(["EMAIL"])
        assert result.level == SensitivityLevel.MEDIUM
        assert "GDPR" in result.compliance_tags

    def test_mixed_types_worst_case(self):
        """Multiple types → worst-case sensitivity level."""
        result = classify_sensitivity(["EMAIL", "SSN", "CREDIT_CARD"])
        assert result.level == SensitivityLevel.CRITICAL
        assert "GDPR" in result.compliance_tags
        assert "PCI-DSS" in result.compliance_tags
        assert "PII" in result.data_labels
        assert "FINANCIAL" in result.data_labels

    def test_phi_tags(self):
        result = classify_sensitivity(["MRN", "ICD10", "DRUG"])
        assert "HIPAA" in result.compliance_tags
        assert "PHI" in result.data_labels

    def test_unknown_type_ignored(self):
        result = classify_sensitivity(["UNKNOWN_TYPE"])
        assert result.level == SensitivityLevel.NONE

# ═══════════════════════════════════════════════════════════════════════
# ──  SemanticDataClassifier Orchestrator Tests
# ═══════════════════════════════════════════════════════════════════════

class TestSemanticDataClassifier:
    """Tests for data_classifier.py."""

    def test_empty_text(self):
        cls = SemanticDataClassifier()
        result = cls.classify("")
        assert result.sensitivity == SensitivityLevel.NONE
        assert len(result.matches) == 0

    def test_ssn_classified(self):
        cls = SemanticDataClassifier()
        result = cls.classify("SSN: 123-45-6789")
        assert result.sensitivity == SensitivityLevel.CRITICAL
        assert "GDPR" in result.compliance_tags
        assert "PII" in result.labels
        # Value must be redacted
        for m in result.matches:
            assert "123-45-6789" not in m.redacted_value

    def test_credit_card_classified(self):
        cls = SemanticDataClassifier()
        result = cls.classify("Card: 4111 1111 1111 1111")
        cc_matches = [m for m in result.matches if m.data_type == "CREDIT_CARD"]
        assert len(cc_matches) >= 1
        assert "PCI-DSS" in result.compliance_tags
        assert "FINANCIAL" in result.labels

    def test_phi_classified(self):
        cls = SemanticDataClassifier()
        result = cls.classify("MRN: 123456789. Diagnosis ICD-10 E11.9")
        assert "PHI" in result.labels
        assert "HIPAA" in result.compliance_tags

    def test_mixed_pii_financial(self):
        cls = SemanticDataClassifier()
        text = "SSN 123-45-6789, Card 4111111111111111"
        result = cls.classify(text)
        assert result.sensitivity == SensitivityLevel.CRITICAL
        assert "PII" in result.labels
        assert "FINANCIAL" in result.labels

    def test_benign_text_no_matches(self):
        cls = SemanticDataClassifier()
        text = "The quarterly report shows strong growth across all sectors."
        result = cls.classify(text)
        assert len(result.matches) == 0
        assert result.sensitivity == SensitivityLevel.NONE

    def test_processing_time_tracked(self):
        cls = SemanticDataClassifier()
        result = cls.classify("Test text for timing")
        assert result.processing_time_ms >= 0

    # ── Custom patterns ──────────────────────────────────────────────

    def test_custom_pattern_detected(self):
        cls = SemanticDataClassifier()
        cls.register_custom_pattern(
            tenant_id="t1",
            name="project_codename",
            regex=r"\bProject\s+Titan\b",
            data_type="PROPRIETARY",
        )
        result = cls.classify("Working on Project Titan deliverables", tenant_id="t1")
        prop_matches = [m for m in result.matches if m.data_type == "PROPRIETARY"]
        assert len(prop_matches) >= 1

    def test_custom_pattern_tenant_isolated(self):
        cls = SemanticDataClassifier()
        cls.register_custom_pattern(
            tenant_id="t1",
            name="secret_project",
            regex=r"\bAlpha\s+Protocol\b",
        )
        # Same text, different tenant → no match
        result = cls.classify("Alpha Protocol is active", tenant_id="t2")
        prop_matches = [m for m in result.matches if m.data_type == "PROPRIETARY"]
        assert len(prop_matches) == 0

    def test_custom_pattern_redos_rejected(self):
        cls = SemanticDataClassifier()
        with pytest.raises(ValueError, match="nested quantifiers"):
            cls.register_custom_pattern(
                tenant_id="t1",
                name="bad_regex",
                regex=r"(a+)+b",  # noqa: S105 — intentional ReDoS for rejection test
            )

    def test_clear_custom_patterns(self):
        cls = SemanticDataClassifier()
        cls.register_custom_pattern("t1", "test", r"foo")
        assert cls.clear_custom_patterns("t1") == 1
        assert cls.clear_custom_patterns("t1") == 0

    # ── Redaction safety ─────────────────────────────────────────────

    def test_all_matches_redacted(self):
        """Acceptance: DataClassification.matches never contains unredacted sensitive values."""
        cls = SemanticDataClassifier()
        ssn = "123-45-6789"
        email = "john.doe@secretcorp.com"
        cc = "4111111111111111"
        text = f"SSN: {ssn}, Email: {email}, Card: {cc}"
        result = cls.classify(text)
        for m in result.matches:
            assert ssn not in m.redacted_value
            assert "john.doe" not in m.redacted_value
            assert cc not in m.redacted_value

    # ── Truncation ───────────────────────────────────────────────────

    def test_oversized_content_truncated(self):
        cls = SemanticDataClassifier(max_content_length=100)
        text = "A" * 200
        result = cls.classify(text)
        assert result.metadata["truncated"] is True

    def test_normal_content_not_truncated(self):
        cls = SemanticDataClassifier()
        result = cls.classify("Short text")
        assert result.metadata["truncated"] is False

    # ── Frozen result ────────────────────────────────────────────────

    def test_data_classification_frozen(self):
        result = DataClassification(
            labels=("PII",),
            matches=(),
            sensitivity=SensitivityLevel.HIGH,
            compliance_tags=("GDPR",),
        )
        with pytest.raises(AttributeError):
            result.labels = ("OTHER",)  # type: ignore[misc]

# ═══════════════════════════════════════════════════════════════════════
# ──  False-Positive Resistance
# ═══════════════════════════════════════════════════════════════════════

class TestFalsePositives:
    """Normal business text should not trigger data classification."""

    @pytest.mark.parametrize(
        "text",
        [
            "Revenue increased by 15% in Q3 2024.",
            "The team meeting is at 3:00 PM in conference room B.",
            "Please review the attached quarterly report.",
            "The software version is 2.1.0-beta and supports Python 3.12.",
            "Error code 500 returned from the API endpoint.",
            "The temperature today is 72 degrees Fahrenheit.",
        ],
    )
    def test_benign_text_no_classification(self, text: str):
        cls = SemanticDataClassifier()
        result = cls.classify(text)
        # No PII/PHI/financial matches
        sensitive = [
            m
            for m in result.matches
            if m.data_type
            in {
                "SSN",
                "CREDIT_CARD",
                "BANK_ACCOUNT",
                "MRN",
                "PATIENT_ID",
                "PASSPORT",
                "DRIVERS_LICENSE",
            }
        ]
        assert len(sensitive) == 0

# ═══════════════════════════════════════════════════════════════════════
# ──  Performance Tests
# ═══════════════════════════════════════════════════════════════════════

class TestPerformance:
    """Acceptance: Classification latency < 10ms for content ≤ 8KB."""

    def test_classify_latency_under_10ms(self):
        cls = SemanticDataClassifier()
        text = "The quarterly earnings call is at 2pm. Revenue was $1.2B. " * 50  # ~3KB
        # Warm up
        cls.classify(text)
        iterations = 100
        start = time.perf_counter()
        for _ in range(iterations):
            cls.classify(text)
        elapsed = time.perf_counter() - start
        avg_ms = (elapsed / iterations) * 1000
        assert avg_ms < 10.0, f"Average classify latency {avg_ms:.2f}ms exceeds 10ms"

    def test_classify_with_pii_under_10ms(self):
        cls = SemanticDataClassifier()
        text = ("SSN: 123-45-6789, Email: user@test.com, Card: 4111111111111111 ") * 10  # ~600 bytes
        cls.classify(text)
        iterations = 50
        start = time.perf_counter()
        for _ in range(iterations):
            cls.classify(text)
        elapsed = time.perf_counter() - start
        avg_ms = (elapsed / iterations) * 1000
        assert avg_ms < 10.0, f"Average classify latency {avg_ms:.2f}ms exceeds 10ms"
