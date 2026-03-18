# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Tests for the PRL Lexer.
"""

import pytest

from engine.parser.lexer import Lexer, LexerError, TokenType


def _types(source: str) -> list[TokenType]:
    """Helper: tokenize source and return list of token types (excluding EOF)."""
    tokens = list(Lexer(source).tokenize())
    return [t.type for t in tokens if t.type != TokenType.EOF]

def _values(source: str) -> list:
    """Helper: tokenize source and return list of token values (excluding EOF)."""
    tokens = list(Lexer(source).tokenize())
    return [t.value for t in tokens if t.type != TokenType.EOF]

class TestLexerBasics:
    def test_empty_source(self):
        tokens = list(Lexer("").tokenize())
        assert len(tokens) == 1
        assert tokens[0].type == TokenType.EOF

    def test_whitespace_only(self):
        tokens = list(Lexer("   \t\n  ").tokenize())
        assert len(tokens) == 1
        assert tokens[0].type == TokenType.EOF

    def test_comment_only(self):
        tokens = list(Lexer("# this is a comment").tokenize())
        assert len(tokens) == 1
        assert tokens[0].type == TokenType.EOF

    def test_comment_before_token(self):
        types = _types("# comment\nevent")
        assert types == [TokenType.IDENT]

class TestLexerStrings:
    def test_simple_string(self):
        vals = _values('"hello"')
        assert vals == ["hello"]

    def test_escape_sequences(self):
        vals = _values(r'"line\nbreak\ttab\\slash\"quote"')
        assert vals == ['line\nbreak\ttab\\slash"quote']

    def test_unterminated_string(self):
        with pytest.raises(LexerError, match="Unterminated string"):
            list(Lexer('"hello').tokenize())

class TestLexerNumbers:
    def test_integer(self):
        tokens = list(Lexer("42").tokenize())
        assert tokens[0].value == 42
        assert tokens[0].type == TokenType.NUMBER

    def test_float(self):
        tokens = list(Lexer("3.14").tokenize())
        assert tokens[0].value == 3.14

    def test_underscore_separator(self):
        tokens = list(Lexer("10_000").tokenize())
        assert tokens[0].value == 10000

class TestLexerKeywords:
    def test_and(self):
        assert _types("AND") == [TokenType.AND]
        assert _types("and") == [TokenType.AND]

    def test_or(self):
        assert _types("OR") == [TokenType.OR]
        assert _types("or") == [TokenType.OR]

    def test_not(self):
        assert _types("NOT") == [TokenType.NOT]
        assert _types("not") == [TokenType.NOT]

    def test_in(self):
        assert _types("IN") == [TokenType.IN]
        assert _types("in") == [TokenType.IN]

    def test_booleans(self):
        vals = _values("true false True False")
        assert vals == [True, False, True, False]

class TestLexerOperators:
    def test_comparison_operators(self):
        types = _types("== != > < >= <=")
        assert types == [
            TokenType.EQ,
            TokenType.NEQ,
            TokenType.GT,
            TokenType.LT,
            TokenType.GTE,
            TokenType.LTE,
        ]

    def test_delimiters(self):
        types = _types("( ) [ ] , .")
        assert types == [
            TokenType.LPAREN,
            TokenType.RPAREN,
            TokenType.LBRACKET,
            TokenType.RBRACKET,
            TokenType.COMMA,
            TokenType.DOT,
        ]

class TestLexerIdentifiers:
    def test_simple_ident(self):
        vals = _values("event")
        assert vals == ["event"]

    def test_underscore_ident(self):
        vals = _values("raw_data")
        assert vals == ["raw_data"]

    def test_ident_with_numbers(self):
        vals = _values("event2")
        assert vals == ["event2"]

class TestLexerErrors:
    def test_unexpected_character(self):
        with pytest.raises(LexerError, match="Unexpected character"):
            list(Lexer("@").tokenize())

    def test_error_has_line_col(self):
        try:
            list(Lexer("\n  @").tokenize())
        except LexerError as e:
            assert e.line == 2
            assert e.col == 3

class TestLexerFullExpressions:
    def test_full_rule(self):
        src = 'event.type == "TOOL_CALL" AND count("TOOL_CALL", "60s") > 100'
        types = _types(src)
        assert types == [
            TokenType.IDENT,
            TokenType.DOT,
            TokenType.IDENT,
            TokenType.EQ,
            TokenType.STRING,
            TokenType.AND,
            TokenType.IDENT,
            TokenType.LPAREN,
            TokenType.STRING,
            TokenType.COMMA,
            TokenType.STRING,
            TokenType.RPAREN,
            TokenType.GT,
            TokenType.NUMBER,
        ]
