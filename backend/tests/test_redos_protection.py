# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Tests for ReDoS protection and regex caching in functions.py."""

import pytest

from engine.evaluator.functions import _get_compiled_regex


def test_valid_regex_compiles():
    """Simple patterns should compile and cache successfully."""
    regex = _get_compiled_regex(r"^hello\s+world$")
    assert regex.match("hello   world")

def test_redos_nested_quantifiers_rejected():
    """Patterns with nested quantifiers should be rejected."""
    with pytest.raises(ValueError, match="ReDoS"):
        _get_compiled_regex(r"(a+)+")

    with pytest.raises(ValueError, match="ReDoS"):
        _get_compiled_regex(r"(a*)*")

    with pytest.raises(ValueError, match="ReDoS"):
        _get_compiled_regex(r"(x+y*)+")

def test_long_pattern_rejected():
    """Patterns exceeding 1000 characters should be rejected."""
    long_pattern = "a" * 1001
    with pytest.raises(ValueError, match="too long"):
        _get_compiled_regex(long_pattern)

def test_pattern_at_limit_allowed():
    """Exactly 1000 character pattern should be allowed."""
    pattern = "a" * 1000
    regex = _get_compiled_regex(pattern)
    assert regex.match("a" * 1000)

def test_safe_quantifiers_allowed():
    """Normal quantifiers (without nesting) should be fine."""
    regex = _get_compiled_regex(r"[a-z]+@[a-z]+\.[a-z]+")
    assert regex.match("user@example.com")

def test_cache_reuses_compiled():
    """Calling with same pattern should return cached result."""
    r1 = _get_compiled_regex(r"test_pattern_\d+")
    r2 = _get_compiled_regex(r"test_pattern_\d+")
    assert r1 is r2
