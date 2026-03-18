# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
PRL Lexer — tokenizer for the Phantex Rule Language.

Converts PRL source text into a stream of typed tokens.
Handles:
- Keywords: AND, OR, NOT, IN, true, false
- Operators: ==, !=, >=, <=, >, <
- Delimiters: (, ), [, ], ,, .
- Strings: "..." (double-quoted, with escape sequences)
- Numbers: 123, 3.14, 10_000
- Identifiers: event, type, severity, count

Error reporting includes line and column numbers.

Security: The lexer operates on a fixed character set. No eval(), no
dynamic code loading, no arbitrary string interpretation.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from enum import Enum, auto

class TokenType(Enum):
    """All token types in PRL."""

    # Literals
    STRING = auto()
    NUMBER = auto()
    BOOL = auto()

    # Identifiers and keywords
    IDENT = auto()
    AND = auto()
    OR = auto()
    NOT = auto()
    IN = auto()

    # Comparison operators
    EQ = auto()  # ==
    NEQ = auto()  # !=
    GT = auto()  # >
    LT = auto()  # <
    GTE = auto()  # >=
    LTE = auto()  # <=

    # Delimiters
    LPAREN = auto()  # (
    RPAREN = auto()  # )
    LBRACKET = auto()  # [
    RBRACKET = auto()  # ]
    COMMA = auto()  # ,
    DOT = auto()  # .

    # Control
    EOF = auto()
    NEWLINE = auto()  # used internally, not emitted

@dataclass(slots=True)
class Token:
    """A single token with its source position."""

    type: TokenType
    value: str | float | int | bool
    line: int
    col: int

    def __repr__(self) -> str:
        return f"Token({self.type.name}, {self.value!r}, L{self.line}:{self.col})"

class LexerError(Exception):
    """Raised when the lexer encounters invalid input."""

    def __init__(self, message: str, line: int, col: int) -> None:
        self.line = line
        self.col = col
        super().__init__(f"Line {line}, col {col}: {message}")

# ── Keyword Map ──────────────────────────────────────────────────────────────

_KEYWORDS: dict[str, TokenType] = {
    "AND": TokenType.AND,
    "OR": TokenType.OR,
    "NOT": TokenType.NOT,
    "IN": TokenType.IN,
    "and": TokenType.AND,
    "or": TokenType.OR,
    "not": TokenType.NOT,
    "in": TokenType.IN,
    "true": TokenType.BOOL,
    "false": TokenType.BOOL,
    "True": TokenType.BOOL,
    "False": TokenType.BOOL,
}

# ── Lexer ─────────────────────────────────────────────────────────────────────

class Lexer:
    """
    Tokenize PRL source text.

    Usage:
        lexer = Lexer(source)
        tokens = list(lexer.tokenize())
    """

    def __init__(self, source: str) -> None:
        self.source = source
        self.pos = 0
        self.line = 1
        self.col = 1

    def _peek(self) -> str:
        if self.pos >= len(self.source):
            return ""
        return self.source[self.pos]

    def _advance(self) -> str:
        ch = self.source[self.pos]
        self.pos += 1
        if ch == "\n":
            self.line += 1
            self.col = 1
        else:
            self.col += 1
        return ch

    def _skip_whitespace_and_comments(self) -> None:
        while self.pos < len(self.source):
            ch = self._peek()
            if ch in (" ", "\t", "\r") or ch == "\n":
                self._advance()
            elif ch == "#":
                # Line comment: skip until end of line
                while self.pos < len(self.source) and self._peek() != "\n":
                    self._advance()
            else:
                break

    def _read_string(self) -> Token:
        """Read a double-quoted string with escape sequences."""
        start_line = self.line
        start_col = self.col
        self._advance()  # consume opening "

        result: list[str] = []
        while self.pos < len(self.source):
            ch = self._advance()
            if ch == '"':
                return Token(TokenType.STRING, "".join(result), start_line, start_col)
            elif ch == "\\":
                if self.pos >= len(self.source):
                    raise LexerError("Unterminated escape sequence", self.line, self.col)
                esc = self._advance()
                escape_map = {"n": "\n", "t": "\t", "\\": "\\", '"': '"', "r": "\r"}
                result.append(escape_map.get(esc, esc))
            else:
                result.append(ch)

        raise LexerError("Unterminated string", start_line, start_col)

    def _read_number(self) -> Token:
        """Read an integer or float. Supports underscores: 10_000."""
        start_line = self.line
        start_col = self.col
        start_pos = self.pos
        has_dot = False

        while self.pos < len(self.source):
            ch = self._peek()
            if ch.isdigit() or ch == "_":
                self._advance()
            elif ch == "." and not has_dot:
                has_dot = True
                self._advance()
            else:
                break

        raw = self.source[start_pos : self.pos].replace("_", "")
        try:
            value: float | int = float(raw) if has_dot else int(raw)
        except ValueError:
            raise LexerError(f"Invalid number: {raw}", start_line, start_col)

        return Token(TokenType.NUMBER, value, start_line, start_col)

    def _read_identifier(self) -> Token:
        """Read an identifier or keyword."""
        start_line = self.line
        start_col = self.col
        start_pos = self.pos

        while self.pos < len(self.source):
            ch = self._peek()
            if ch.isalnum() or ch == "_":
                self._advance()
            else:
                break

        word = self.source[start_pos : self.pos]

        # Check for keyword
        if word in _KEYWORDS:
            tt = _KEYWORDS[word]
            if tt == TokenType.BOOL:
                return Token(TokenType.BOOL, word.lower() == "true", start_line, start_col)
            return Token(tt, word.upper(), start_line, start_col)

        return Token(TokenType.IDENT, word, start_line, start_col)

    def tokenize(self) -> Iterator[Token]:
        """
        Yield all tokens from the source.
        Ends with a single EOF token.
        """
        while True:
            self._skip_whitespace_and_comments()

            if self.pos >= len(self.source):
                yield Token(TokenType.EOF, "", self.line, self.col)
                return

            ch = self._peek()
            line, col = self.line, self.col

            # Strings
            if ch == '"':
                yield self._read_string()
                continue

            # Numbers
            if ch.isdigit():
                yield self._read_number()
                continue

            # Identifiers / keywords
            if ch.isalpha() or ch == "_":
                yield self._read_identifier()
                continue

            # Two-character operators
            if self.pos + 1 < len(self.source):
                two = self.source[self.pos : self.pos + 2]
                if two == "==":
                    self._advance()
                    self._advance()
                    yield Token(TokenType.EQ, "==", line, col)
                    continue
                elif two == "!=":
                    self._advance()
                    self._advance()
                    yield Token(TokenType.NEQ, "!=", line, col)
                    continue
                elif two == ">=":
                    self._advance()
                    self._advance()
                    yield Token(TokenType.GTE, ">=", line, col)
                    continue
                elif two == "<=":
                    self._advance()
                    self._advance()
                    yield Token(TokenType.LTE, "<=", line, col)
                    continue

            # Single-character tokens
            if ch == ">":
                self._advance()
                yield Token(TokenType.GT, ">", line, col)
            elif ch == "<":
                self._advance()
                yield Token(TokenType.LT, "<", line, col)
            elif ch == "(":
                self._advance()
                yield Token(TokenType.LPAREN, "(", line, col)
            elif ch == ")":
                self._advance()
                yield Token(TokenType.RPAREN, ")", line, col)
            elif ch == "[":
                self._advance()
                yield Token(TokenType.LBRACKET, "[", line, col)
            elif ch == "]":
                self._advance()
                yield Token(TokenType.RBRACKET, "]", line, col)
            elif ch == ",":
                self._advance()
                yield Token(TokenType.COMMA, ",", line, col)
            elif ch == ".":
                self._advance()
                yield Token(TokenType.DOT, ".", line, col)
            else:
                raise LexerError(f"Unexpected character: {ch!r}", line, col)
