# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for AS block — Hardware-Backed Agent Identity.

Covers:
  AS4 — Identity Hierarchy (identity_hierarchy.py)
  AS5 — Trust Graph Boost (trust.py integration)
"""

from __future__ import annotations

import time

import pytest

from app.services.identity_hierarchy import (
    _LEVEL_TRUST_BOOST,
    _UPGRADE_PATHS,
    AgentIdentity,
    IdentityLevel,
    clear_store,
    compute_identity_features,
    delete_identity,
    downgrade_identity,
    get_identity,
    get_trust_boost,
    list_identities,
    record_verification,
    register_agent,
    upgrade_identity,
)

# ── Fixtures ──────────────────────────────────────────────────────────────

TENANT = "tenant-001"
AGENT = "agent-alpha"

@pytest.fixture(autouse=True)
def _clean_store():
    clear_store()
    yield
    clear_store()

# ═══════════════════════════════════════════════════════════════════════════
#  AS4 — Identity Hierarchy
# ═══════════════════════════════════════════════════════════════════════════

class TestIdentityLevel:
    """IdentityLevel enum."""

    def test_values(self):
        assert IdentityLevel.NONE == 0
        assert IdentityLevel.SOFTWARE == 1
        assert IdentityLevel.OS == 2
        assert IdentityLevel.HARDWARE == 3
        assert IdentityLevel.ATTESTED == 4

    def test_ordering(self):
        assert IdentityLevel.NONE < IdentityLevel.SOFTWARE
        assert IdentityLevel.SOFTWARE < IdentityLevel.OS
        assert IdentityLevel.OS < IdentityLevel.HARDWARE
        assert IdentityLevel.HARDWARE < IdentityLevel.ATTESTED

    def test_names(self):
        for level in IdentityLevel:
            assert level.name.upper() == level.name

class TestTrustBoostConstants:
    """Trust boost mapping sanity."""

    def test_all_levels_present(self):
        for level in IdentityLevel:
            assert level in _LEVEL_TRUST_BOOST

    def test_monotonically_increasing(self):
        boosts = [_LEVEL_TRUST_BOOST[IdentityLevel(i)] for i in range(5)]
        for i in range(1, len(boosts)):
            assert boosts[i] >= boosts[i - 1]

    def test_none_is_zero(self):
        assert _LEVEL_TRUST_BOOST[IdentityLevel.NONE] == 0.0

    def test_attested_max(self):
        assert _LEVEL_TRUST_BOOST[IdentityLevel.ATTESTED] == 0.30

class TestUpgradePaths:
    """Upgrade path constraints."""

    def test_none_can_reach_hardware(self):
        assert IdentityLevel.HARDWARE in _UPGRADE_PATHS[IdentityLevel.NONE]

    def test_none_cannot_reach_attested_directly(self):
        assert IdentityLevel.ATTESTED not in _UPGRADE_PATHS[IdentityLevel.NONE]

    def test_hardware_only_to_attested(self):
        assert _UPGRADE_PATHS[IdentityLevel.HARDWARE] == {IdentityLevel.ATTESTED}

    def test_attested_is_terminal(self):
        assert len(_UPGRADE_PATHS[IdentityLevel.ATTESTED]) == 0

class TestRegisterAgent:
    """register_agent() CRUD."""

    def test_register_new(self):
        ident = register_agent(TENANT, AGENT)
        assert isinstance(ident, AgentIdentity)
        assert ident.agent_id == AGENT
        assert ident.tenant_id == TENANT
        assert ident.level == IdentityLevel.NONE

    def test_register_with_level(self):
        ident = register_agent(TENANT, AGENT, level=IdentityLevel.HARDWARE, backend="tpm2")
        assert ident.level == IdentityLevel.HARDWARE
        assert ident.backend == "tpm2"

    def test_reregister_updates(self):
        register_agent(TENANT, AGENT, level=IdentityLevel.NONE)
        ident = register_agent(TENANT, AGENT, level=IdentityLevel.SOFTWARE, backend="sw")
        assert ident.level == IdentityLevel.SOFTWARE
        assert ident.backend == "sw"
        # History tracks both register and re-register
        assert len(ident.history) >= 2

    def test_register_creates_timestamps(self):
        ident = register_agent(TENANT, AGENT)
        assert ident.created_at
        assert ident.updated_at

    def test_invalid_agent_id_rejected(self):
        with pytest.raises(ValueError):
            register_agent(TENANT, "agent with spaces!!!")

    def test_invalid_tenant_id_rejected(self):
        with pytest.raises(ValueError):
            register_agent("tenant/../../etc", AGENT)

    def test_empty_agent_id_rejected(self):
        with pytest.raises(ValueError):
            register_agent(TENANT, "")

    def test_empty_tenant_id_rejected(self):
        with pytest.raises(ValueError):
            register_agent("", AGENT)

class TestGetIdentity:
    def test_found(self):
        register_agent(TENANT, AGENT)
        result = get_identity(TENANT, AGENT)
        assert result is not None
        assert result.agent_id == AGENT

    def test_not_found(self):
        result = get_identity(TENANT, "nonexistent")
        assert result is None

class TestListIdentities:
    def test_empty(self):
        assert list_identities(TENANT) == []

    def test_multiple(self):
        register_agent(TENANT, "agent-1")
        register_agent(TENANT, "agent-2")
        register_agent(TENANT, "agent-3")
        assert len(list_identities(TENANT)) == 3

    def test_tenant_isolation(self):
        register_agent("t1", AGENT)
        register_agent("t2", AGENT)
        assert len(list_identities("t1")) == 1
        assert len(list_identities("t2")) == 1

class TestDeleteIdentity:
    def test_delete_existing(self):
        register_agent(TENANT, AGENT)
        assert delete_identity(TENANT, AGENT) is True
        assert get_identity(TENANT, AGENT) is None

    def test_delete_nonexistent(self):
        assert delete_identity(TENANT, AGENT) is False

class TestUpgradeIdentity:
    def test_none_to_software(self):
        register_agent(TENANT, AGENT)
        ident = upgrade_identity(TENANT, AGENT, IdentityLevel.SOFTWARE, backend="sw")
        assert ident.level == IdentityLevel.SOFTWARE
        assert ident.backend == "sw"

    def test_none_to_hardware(self):
        register_agent(TENANT, AGENT)
        ident = upgrade_identity(TENANT, AGENT, IdentityLevel.HARDWARE, backend="tpm2")
        assert ident.level == IdentityLevel.HARDWARE

    def test_hardware_to_attested(self):
        register_agent(TENANT, AGENT, level=IdentityLevel.HARDWARE)
        ident = upgrade_identity(TENANT, AGENT, IdentityLevel.ATTESTED)
        assert ident.level == IdentityLevel.ATTESTED
        assert ident.attestation_time is not None

    def test_disallowed_none_to_attested(self):
        register_agent(TENANT, AGENT)
        with pytest.raises(ValueError, match="not allowed"):
            upgrade_identity(TENANT, AGENT, IdentityLevel.ATTESTED)

    def test_cannot_upgrade_to_same(self):
        register_agent(TENANT, AGENT, level=IdentityLevel.SOFTWARE)
        with pytest.raises(ValueError, match="target must be higher"):
            upgrade_identity(TENANT, AGENT, IdentityLevel.SOFTWARE)

    def test_cannot_upgrade_lower(self):
        register_agent(TENANT, AGENT, level=IdentityLevel.OS)
        with pytest.raises(ValueError, match="target must be higher"):
            upgrade_identity(TENANT, AGENT, IdentityLevel.SOFTWARE)

    def test_unregistered_agent(self):
        with pytest.raises(ValueError, match="not registered"):
            upgrade_identity(TENANT, "ghost", IdentityLevel.SOFTWARE)

    def test_history_recorded(self):
        register_agent(TENANT, AGENT)
        upgrade_identity(TENANT, AGENT, IdentityLevel.HARDWARE)
        ident = get_identity(TENANT, AGENT)
        assert any(h["action"] == "upgrade" for h in ident.history)

    def test_public_key_set_on_upgrade(self):
        register_agent(TENANT, AGENT)
        ident = upgrade_identity(TENANT, AGENT, IdentityLevel.HARDWARE, public_key_hex="abcdef01")
        assert ident.public_key_hex == "abcdef01"

class TestDowngradeIdentity:
    def test_attested_to_hardware(self):
        register_agent(TENANT, AGENT, level=IdentityLevel.HARDWARE)
        upgrade_identity(TENANT, AGENT, IdentityLevel.ATTESTED)
        ident = downgrade_identity(TENANT, AGENT, IdentityLevel.HARDWARE, reason="re-verify")
        assert ident.level == IdentityLevel.HARDWARE
        assert ident.attestation_time is None

    def test_hardware_to_none(self):
        register_agent(TENANT, AGENT, level=IdentityLevel.HARDWARE)
        ident = downgrade_identity(TENANT, AGENT, IdentityLevel.NONE, reason="compromised")
        assert ident.level == IdentityLevel.NONE

    def test_cannot_downgrade_same(self):
        register_agent(TENANT, AGENT, level=IdentityLevel.SOFTWARE)
        with pytest.raises(ValueError, match="target must be lower"):
            downgrade_identity(TENANT, AGENT, IdentityLevel.SOFTWARE)

    def test_cannot_downgrade_higher(self):
        register_agent(TENANT, AGENT, level=IdentityLevel.SOFTWARE)
        with pytest.raises(ValueError, match="target must be lower"):
            downgrade_identity(TENANT, AGENT, IdentityLevel.HARDWARE)

    def test_unregistered_agent(self):
        with pytest.raises(ValueError, match="not registered"):
            downgrade_identity(TENANT, "ghost", IdentityLevel.NONE)

    def test_history_recorded(self):
        register_agent(TENANT, AGENT, level=IdentityLevel.HARDWARE)
        downgrade_identity(TENANT, AGENT, IdentityLevel.NONE, reason="test")
        ident = get_identity(TENANT, AGENT)
        dg = [h for h in ident.history if h["action"] == "downgrade"]
        assert len(dg) == 1
        assert dg[0]["reason"] == "test"

class TestRecordVerification:
    def test_records_timestamp(self):
        register_agent(TENANT, AGENT)
        ident = record_verification(TENANT, AGENT)
        assert ident is not None
        assert ident.last_verified is not None

    def test_nonexistent_returns_none(self):
        assert record_verification(TENANT, "ghost") is None

class TestToDict:
    def test_contains_expected_keys(self):
        register_agent(TENANT, AGENT, level=IdentityLevel.SOFTWARE)
        ident = get_identity(TENANT, AGENT)
        d = ident.to_dict()
        expected_keys = {
            "agent_id",
            "tenant_id",
            "level",
            "level_name",
            "backend",
            "public_key_hex",
            "trust_boost",
            "attestation_time",
            "last_verified",
            "created_at",
            "updated_at",
        }
        assert expected_keys.issubset(d.keys())
        assert d["level"] == 1
        assert d["level_name"] == "software"

    def test_long_pubkey_truncated(self):
        register_agent(TENANT, AGENT, public_key_hex="a" * 100)
        d = get_identity(TENANT, AGENT).to_dict()
        assert d["public_key_hex"].endswith("...")
        assert len(d["public_key_hex"]) < 100

class TestTrustBoostProperty:
    @pytest.mark.parametrize(
        "level,expected",
        [
            (IdentityLevel.NONE, 0.0),
            (IdentityLevel.SOFTWARE, 0.05),
            (IdentityLevel.OS, 0.10),
            (IdentityLevel.HARDWARE, 0.20),
            (IdentityLevel.ATTESTED, 0.30),
        ],
    )
    def test_trust_boost_per_level(self, level, expected):
        register_agent(TENANT, AGENT, level=level)
        assert get_identity(TENANT, AGENT).trust_boost == expected

# ═══════════════════════════════════════════════════════════════════════════
#  AS5 — Trust Graph Boost / Feature Integration
# ═══════════════════════════════════════════════════════════════════════════

class TestGetTrustBoost:
    def test_registered_agent(self):
        register_agent(TENANT, AGENT, level=IdentityLevel.HARDWARE)
        assert get_trust_boost(TENANT, AGENT) == 0.20

    def test_unregistered_returns_zero(self):
        assert get_trust_boost(TENANT, "unknown") == 0.0

    def test_invalid_tenant_returns_zero(self):
        assert get_trust_boost("bad tenant!", AGENT) == 0.0

class TestComputeIdentityFeatures:
    def test_registered_hardware(self):
        register_agent(TENANT, AGENT, level=IdentityLevel.HARDWARE)
        feats = compute_identity_features(TENANT, AGENT)
        assert feats["identity_level"] == 3.0
        assert feats["identity_is_hardware"] == 1.0
        assert feats["identity_is_attested"] == 0.0
        assert feats["identity_trust_boost"] == 0.20

    def test_registered_attested(self):
        register_agent(TENANT, AGENT, level=IdentityLevel.HARDWARE)
        upgrade_identity(TENANT, AGENT, IdentityLevel.ATTESTED)
        feats = compute_identity_features(TENANT, AGENT)
        assert feats["identity_level"] == 4.0
        assert feats["identity_is_hardware"] == 1.0
        assert feats["identity_is_attested"] == 1.0
        assert feats["identity_trust_boost"] == 0.30

    def test_unregistered_returns_zeros(self):
        feats = compute_identity_features(TENANT, "ghost")
        assert all(v == 0.0 for v in feats.values())

    def test_invalid_ids_return_zeros(self):
        feats = compute_identity_features("bad tenant!", "bad agent!")
        assert all(v == 0.0 for v in feats.values())

    def test_feature_keys_stable(self):
        feats = compute_identity_features(TENANT, "nobody")
        assert set(feats.keys()) == {
            "identity_level",
            "identity_is_hardware",
            "identity_is_attested",
            "identity_trust_boost",
        }

class TestTrustFeaturesIntegration:
    """AS5 — identity features flow through compute_trust_features."""

    def test_with_agent_context(self):
        from ml.features.trust import compute_trust_features

        register_agent(TENANT, AGENT, level=IdentityLevel.HARDWARE)
        result = compute_trust_features(
            events=[],
            now=time.time(),
            tenant_id=TENANT,
            agent_id=AGENT,
        )
        assert result["identity_level"] == 3.0
        assert result["identity_is_hardware"] == 1.0
        assert result["identity_trust_boost"] == 0.20

    def test_without_agent_context(self):
        from ml.features.trust import compute_trust_features

        result = compute_trust_features(events=[], now=time.time())
        assert result["identity_level"] == 0.0
        assert result["identity_is_hardware"] == 0.0
        assert result["identity_is_attested"] == 0.0
        assert result["identity_trust_boost"] == 0.0

    def test_attested_agent_features(self):
        from ml.features.trust import compute_trust_features

        register_agent(TENANT, AGENT, level=IdentityLevel.HARDWARE)
        upgrade_identity(TENANT, AGENT, IdentityLevel.ATTESTED)
        result = compute_trust_features(
            events=[],
            now=time.time(),
            tenant_id=TENANT,
            agent_id=AGENT,
        )
        assert result["identity_is_attested"] == 1.0
        assert result["identity_trust_boost"] == 0.30

    def test_backward_compatible_no_args(self):
        """Existing callers that don't pass tenant_id/agent_id still work."""
        from ml.features.trust import compute_trust_features

        result = compute_trust_features(
            events=[{"timestamp_epoch": time.time(), "severity": "high"}],
            now=time.time(),
        )
        # Event-based features still computed
        assert "trust_critical_event_streak" in result
        # Identity defaults to zero
        assert result["identity_level"] == 0.0

# ═══════════════════════════════════════════════════════════════════════════
#  Security Regression — Input Validation & Edge Cases
# ═══════════════════════════════════════════════════════════════════════════

class TestSecurityRegression:
    """Injection-safe input handling, boundary conditions."""

    @pytest.mark.parametrize(
        "bad_id",
        [
            "'; DROP TABLE agents; --",
            "../../../etc/passwd",
            "agent\x00null",
            "<script>alert(1)</script>",
            "a" * 300,
            " ",
            "\t\n",
        ],
    )
    def test_bad_agent_ids_rejected(self, bad_id):
        with pytest.raises(ValueError):
            register_agent(TENANT, bad_id)

    @pytest.mark.parametrize(
        "bad_id",
        [
            "'; DROP TABLE tenants; --",
            "../../etc/shadow",
            "t\x00null",
            "<img src=x onerror=alert(1)>",
            "t" * 200,
        ],
    )
    def test_bad_tenant_ids_rejected(self, bad_id):
        with pytest.raises(ValueError):
            register_agent(bad_id, AGENT)

    def test_tenant_isolation_strict(self):
        """Agent in tenant A is invisible from tenant B."""
        register_agent("tenant-a", AGENT, level=IdentityLevel.HARDWARE)
        assert get_identity("tenant-b", AGENT) is None
        assert get_trust_boost("tenant-b", AGENT) == 0.0

    def test_upgrade_path_injection(self):
        """Cannot skip levels by passing raw int."""
        register_agent(TENANT, AGENT)
        with pytest.raises(ValueError, match="not allowed"):
            upgrade_identity(TENANT, AGENT, IdentityLevel.ATTESTED)

    def test_downgrade_does_not_overwrite_other_tenants(self):
        register_agent("t1", AGENT, level=IdentityLevel.HARDWARE)
        register_agent("t2", AGENT, level=IdentityLevel.ATTESTED)
        downgrade_identity("t1", AGENT, IdentityLevel.NONE)
        # t2 unaffected
        assert get_identity("t2", AGENT).level == IdentityLevel.ATTESTED

    def test_rapid_upgrade_downgrade_cycle(self):
        """Rapid level oscillation does not corrupt state."""
        register_agent(TENANT, AGENT)
        for _ in range(20):
            upgrade_identity(TENANT, AGENT, IdentityLevel.HARDWARE)
            downgrade_identity(TENANT, AGENT, IdentityLevel.NONE)
        ident = get_identity(TENANT, AGENT)
        assert ident.level == IdentityLevel.NONE
        assert len(ident.history) >= 40  # register + 20 ups + 20 downs

    def test_delete_then_reregister(self):
        register_agent(TENANT, AGENT, level=IdentityLevel.HARDWARE)
        delete_identity(TENANT, AGENT)
        ident = register_agent(TENANT, AGENT, level=IdentityLevel.SOFTWARE)
        assert ident.level == IdentityLevel.SOFTWARE
        # History starts fresh (new object)
        assert len(ident.history) == 1

    def test_feature_output_types(self):
        """All feature values must be float for ML pipeline compatibility."""
        register_agent(TENANT, AGENT, level=IdentityLevel.ATTESTED)
        feats = compute_identity_features(TENANT, AGENT)
        for k, v in feats.items():
            assert isinstance(v, float), f"{k} is {type(v)}, expected float"

    def test_trust_boost_bounded(self):
        """Trust boost must be between 0.0 and 1.0 for all levels."""
        for level in IdentityLevel:
            register_agent(TENANT, f"agent-{level.value}", level=level)
            boost = get_trust_boost(TENANT, f"agent-{level.value}")
            assert 0.0 <= boost <= 1.0
