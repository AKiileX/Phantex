# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""Tests for the shared truncation utility."""

from engine.utils.truncate import truncate_dict


def test_small_dict_passes_through():
    """Dicts under max_size should be returned unchanged."""
    data = {"key": "value", "num": 42}
    assert truncate_dict(data, max_size=1024) == data

def test_large_strings_truncated():
    """Strings exceeding max_str_len should be cut with suffix."""
    data = {"long": "x" * 500, "short": "hello"}
    result = truncate_dict(data, max_size=100, max_str_len=50)
    assert result["short"] == "hello"
    assert len(result["long"]) < 500
    assert "truncated" in result["long"]

def test_nested_dict_strings_truncated():
    """Nested dict string values should be truncated at nested_str_len."""
    data = {"nested": {"a": "y" * 300, "b": "ok"}}
    result = truncate_dict(data, max_size=100, max_str_len=256, nested_str_len=50)
    assert len(result["nested"]["a"]) < 300
    assert result["nested"]["b"] == "ok"

def test_max_keys_respected():
    """When max_keys is set, only the first N keys should be kept."""
    data = {f"key{i}": f"val{i}" for i in range(20)}
    result = truncate_dict(data, max_size=10, max_keys=5)
    assert len(result) == 5

def test_non_string_values_preserved():
    """Numbers, booleans, and None values should pass through unchanged."""
    data = {"num": 42, "flag": True, "nothing": None, "long": "z" * 500}
    result = truncate_dict(data, max_size=100, max_str_len=10)
    assert result["num"] == 42
    assert result["flag"] is True
    assert result["nothing"] is None
