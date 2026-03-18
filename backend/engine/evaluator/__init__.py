# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""PRL evaluator — AST evaluation + built-in functions."""

from .evaluator import EvalError, Evaluator
from .functions import (
    BuiltinRegistry,
    FunctionContext,
    fn_contains,
    fn_count,
    fn_regex_match,
    fn_time_since,
    parse_duration,
)

__all__ = [
    "Evaluator",
    "EvalError",
    "BuiltinRegistry",
    "FunctionContext",
    "parse_duration",
    "fn_count",
    "fn_contains",
    "fn_regex_match",
    "fn_time_since",
]
