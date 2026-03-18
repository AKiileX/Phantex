# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for the PRL Parser.
"""

import pytest

from engine.parser import ast as ast_nodes
from engine.parser.parser import ParseError, parse_prl

class TestParserLiterals:
    def test_string_literal(self):
        rule = parse_prl('"hello"')
        assert isinstance(rule.condition, ast_nodes.StringLiteral)
        assert rule.condition.value == "hello"

    def test_number_literal_int(self):
        rule = parse_prl("42")
        assert isinstance(rule.condition, ast_nodes.NumberLiteral)
        assert rule.condition.value == 42

    def test_number_literal_float(self):
        rule = parse_prl("3.14")
        assert isinstance(rule.condition, ast_nodes.NumberLiteral)
        assert rule.condition.value == 3.14

    def test_bool_true(self):
        rule = parse_prl("true")
        assert isinstance(rule.condition, ast_nodes.BoolLiteral)
        assert rule.condition.value is True

    def test_bool_false(self):
        rule = parse_prl("false")
        assert isinstance(rule.condition, ast_nodes.BoolLiteral)
        assert rule.condition.value is False

    def test_list_literal(self):
        rule = parse_prl('["a", "b", "c"]')
        assert isinstance(rule.condition, ast_nodes.ListLiteral)
        assert len(rule.condition.elements) == 3

    def test_empty_list(self):
        rule = parse_prl("[]")
        assert isinstance(rule.condition, ast_nodes.ListLiteral)
        assert len(rule.condition.elements) == 0

class TestParserIdentifiers:
    def test_identifier(self):
        rule = parse_prl("severity")
        assert isinstance(rule.condition, ast_nodes.Identifier)
        assert rule.condition.name == "severity"

    def test_field_access(self):
        rule = parse_prl("event.type")
        c = rule.condition
        assert isinstance(c, ast_nodes.FieldAccess)
        assert c.object == "event"
        assert c.field_path == ["type"]

    def test_deep_field_access(self):
        rule = parse_prl("event.raw_data.tool_name")
        c = rule.condition
        assert isinstance(c, ast_nodes.FieldAccess)
        assert c.object == "event"
        assert c.field_path == ["raw_data", "tool_name"]

class TestParserComparisons:
    def test_eq(self):
        rule = parse_prl('event.type == "TOOL_CALL"')
        c = rule.condition
        assert isinstance(c, ast_nodes.Compare)
        assert c.op == "=="

    def test_neq(self):
        rule = parse_prl('event.type != "HEARTBEAT"')
        assert rule.condition.op == "!="

    def test_gt(self):
        rule = parse_prl("count > 100")
        assert rule.condition.op == ">"

    def test_lt(self):
        rule = parse_prl("count < 10")
        assert rule.condition.op == "<"

    def test_gte(self):
        rule = parse_prl("count >= 50")
        assert rule.condition.op == ">="

    def test_lte(self):
        rule = parse_prl("count <= 200")
        assert rule.condition.op == "<="

    def test_in_operator(self):
        rule = parse_prl('event.type IN ["TOOL_CALL", "TOOL_RESPONSE"]')
        c = rule.condition
        assert isinstance(c, ast_nodes.Compare)
        assert c.op == "IN"
        assert isinstance(c.right, ast_nodes.ListLiteral)

class TestParserLogicalOperators:
    def test_and(self):
        rule = parse_prl('event.type == "TOOL_CALL" AND severity == "high"')
        c = rule.condition
        assert isinstance(c, ast_nodes.BinaryOp)
        assert c.op == "AND"

    def test_or(self):
        rule = parse_prl('severity == "high" OR severity == "critical"')
        c = rule.condition
        assert isinstance(c, ast_nodes.BinaryOp)
        assert c.op == "OR"

    def test_not(self):
        rule = parse_prl('NOT event.type == "HEARTBEAT"')
        c = rule.condition
        assert isinstance(c, ast_nodes.UnaryOp)
        assert c.op == "NOT"

    def test_precedence_and_over_or(self):
        rule = parse_prl("a OR b AND c")
        c = rule.condition
        # Should parse as: a OR (b AND c)
        assert isinstance(c, ast_nodes.BinaryOp)
        assert c.op == "OR"
        assert isinstance(c.right, ast_nodes.BinaryOp)
        assert c.right.op == "AND"

    def test_precedence_not_over_and(self):
        rule = parse_prl("NOT a AND b")
        c = rule.condition
        # Should parse as: (NOT a) AND b
        assert isinstance(c, ast_nodes.BinaryOp)
        assert c.op == "AND"
        assert isinstance(c.left, ast_nodes.UnaryOp)
        assert c.left.op == "NOT"

    def test_parenthesized_expression(self):
        rule = parse_prl("(a OR b) AND c")
        c = rule.condition
        assert isinstance(c, ast_nodes.BinaryOp)
        assert c.op == "AND"
        assert isinstance(c.left, ast_nodes.BinaryOp)
        assert c.left.op == "OR"

class TestParserFunctionCalls:
    def test_count(self):
        rule = parse_prl('count("TOOL_CALL", "60s") > 100')
        c = rule.condition
        assert isinstance(c, ast_nodes.Compare)
        assert isinstance(c.left, ast_nodes.FunctionCall)
        assert c.left.name == "count"
        assert len(c.left.args) == 2

    def test_contains(self):
        rule = parse_prl('contains(event.raw_data.tool_input, "password")')
        c = rule.condition
        assert isinstance(c, ast_nodes.FunctionCall)
        assert c.name == "contains"
        assert len(c.args) == 2

    def test_regex_match(self):
        rule = parse_prl('regex_match(".*secret.*", event.raw_data.tool_input)')
        c = rule.condition
        assert isinstance(c, ast_nodes.FunctionCall)
        assert c.name == "regex_match"

    def test_time_since(self):
        rule = parse_prl('time_since("HEARTBEAT") > 300')
        c = rule.condition
        assert isinstance(c, ast_nodes.Compare)
        assert isinstance(c.left, ast_nodes.FunctionCall)
        assert c.left.name == "time_since"

    def test_unknown_function_error(self):
        with pytest.raises(ParseError, match="Unknown function"):
            parse_prl('evil_func("x")')

    def test_wrong_arg_count_error(self):
        with pytest.raises(ParseError, match="expects"):
            parse_prl('count("only_one_arg")')

class TestParserComplexRules:
    def test_full_detection_rule(self):
        src = (
            'event.type == "TOOL_CALL" AND event.raw_data.tool_name == "exec_shell" AND count("TOOL_CALL", "60s") > 100'
        )
        rule = parse_prl(src)
        c = rule.condition
        # Top: AND
        assert isinstance(c, ast_nodes.BinaryOp)
        assert c.op == "AND"
        # Left: AND
        assert isinstance(c.left, ast_nodes.BinaryOp)
        assert c.left.op == "AND"

    def test_multiline_with_comments(self):
        src = """
        # Detect rapid tool calls
        event.type == "TOOL_CALL"
        AND count("TOOL_CALL", "60s") > 50
        """
        rule = parse_prl(src)
        assert isinstance(rule.condition, ast_nodes.BinaryOp)

    def test_nested_field_access_in_function(self):
        src = 'contains(event.raw_data.arguments, "rm -rf")'
        rule = parse_prl(src)
        func = rule.condition
        assert isinstance(func, ast_nodes.FunctionCall)
        assert isinstance(func.args[0], ast_nodes.FieldAccess)

class TestParserErrors:
    def test_empty_input(self):
        with pytest.raises(ParseError, match="Unexpected token"):
            parse_prl("")

    def test_trailing_tokens(self):
        with pytest.raises(ParseError, match="Unexpected token after expression"):
            parse_prl('"hello" "world"')

    def test_unclosed_paren(self):
        with pytest.raises(ParseError, match="Expected RPAREN"):
            parse_prl("(a == b")

    def test_error_has_line_col(self):
        try:
            parse_prl("")
        except ParseError as e:
            assert e.line >= 0
            assert e.col >= 0

    def test_unexpected_token_in_primary(self):
        with pytest.raises(ParseError, match="Unexpected token"):
            parse_prl("== 5")
