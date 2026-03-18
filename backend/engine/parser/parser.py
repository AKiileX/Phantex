# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
PRL Parser — converts token stream into an AST.

Implements a Pratt parser (top-down operator precedence) for the PRL grammar:

    rule        := expression
    expression  := or_expr
    or_expr     := and_expr ("OR" and_expr)*
    and_expr    := not_expr ("AND" not_expr)*
    not_expr    := "NOT" not_expr | comparison
    comparison  := primary (("==" | "!=" | ">" | "<" | ">=" | "<=" | "IN") primary)?
    primary     := function_call | field_access | literal | "(" expression ")" | list
    function_call := IDENT "(" args ")"
    field_access  := IDENT ("." IDENT)*
    literal     := STRING | NUMBER | BOOL
    list        := "[" (expression ("," expression)*)? "]"
    args        := (expression ("," expression)*)?

Operator precedence (low → high):
    OR  →  AND  →  NOT  →  comparisons  →  primary

Security: No eval(), no exec(). The parser only produces AST nodes from
the fixed set defined in ast.py. Invalid syntax produces a clear error
with line and column number.
"""

from __future__ import annotations

from . import ast as ast_nodes
from .lexer import Lexer, LexerError, Token, TokenType

class ParseError(Exception):
    """Raised when parsing encounters invalid PRL syntax."""

    def __init__(self, message: str, line: int, col: int) -> None:
        self.line = line
        self.col = col
        super().__init__(f"Line {line}, col {col}: {message}")

# ── Allowed Built-in Functions ────────────────────────────────────────────────

BUILTIN_FUNCTIONS: dict[str, tuple[int, int]] = {
    # name: (min_args, max_args)
    "count": (2, 2),  # count(event_type, window)
    "count_distinct": (3, 3),  # count_distinct(event_type, field_path, window)
    "contains": (2, 2),  # contains(field, pattern)
    "regex_match": (2, 2),  # regex_match(pattern, text)
    "time_since": (1, 1),  # time_since(event_type)
    "in_allowlist": (2, 2),  # in_allowlist(value, list_name)
    # ── Content-analysis functions (JB6) ──
    "ml_score": (2, 2),  # ml_score(classifier, content)
    "data_classification": (1, 1),  # data_classification(payload)
    "tool_authorized": (2, 2),  # tool_authorized(agent_id, tool)
    "mcp_trust_level": (1, 1),  # mcp_trust_level(server)
    "content_scan": (1, 1),  # content_scan(response)
    # ── Trust Graph Engine functions (K3) ──
    "trust_score": (2, 2),  # trust_score(entity_id, entity_type)
}

class Parser:
    """
    Parse PRL source text into an AST.

    Usage:
        parser = Parser(source)
        rule = parser.parse()  # returns ast.Rule
    """

    # Maximum nesting depth to prevent stack overflow on malicious input.
    MAX_DEPTH = 64

    def __init__(self, source: str) -> None:
        self.source = source
        self._tokens: list[Token] = []
        self._pos = 0
        self._depth = 0

    def parse(self) -> ast_nodes.Rule:
        """Parse the full PRL source into a Rule AST node."""
        try:
            lexer = Lexer(self.source)
            self._tokens = list(lexer.tokenize())
        except LexerError as e:
            raise ParseError(str(e), e.line, e.col) from e

        self._pos = 0
        condition = self._parse_expression()

        # Expect EOF
        tok = self._current()
        if tok.type != TokenType.EOF:
            raise ParseError(
                f"Unexpected token after expression: {tok.value!r}",
                tok.line,
                tok.col,
            )

        return ast_nodes.Rule(
            condition=condition,
            line=condition.line,
            col=condition.col,
        )

    # ── Token Navigation ──────────────────────────────────────────────────

    def _current(self) -> Token:
        if self._pos >= len(self._tokens):
            return Token(TokenType.EOF, "", 0, 0)
        return self._tokens[self._pos]

    def _peek(self) -> Token:
        return self._current()

    def _advance(self) -> Token:
        tok = self._current()
        self._pos += 1
        return tok

    def _expect(self, tt: TokenType) -> Token:
        tok = self._current()
        if tok.type != tt:
            raise ParseError(
                f"Expected {tt.name}, got {tok.type.name} ({tok.value!r})",
                tok.line,
                tok.col,
            )
        return self._advance()

    def _match(self, *types: TokenType) -> Token | None:
        tok = self._current()
        if tok.type in types:
            return self._advance()
        return None

    # ── Grammar Rules ─────────────────────────────────────────────────────

    def _parse_expression(self) -> ast_nodes.Node:
        """expression := or_expr"""
        self._depth += 1
        if self._depth > self.MAX_DEPTH:
            tok = self._peek()
            raise ParseError(
                f"Expression nesting too deep (max {self.MAX_DEPTH})",
                tok.line,
                tok.col,
            )
        try:
            return self._parse_or()
        finally:
            self._depth -= 1

    def _parse_or(self) -> ast_nodes.Node:
        """or_expr := and_expr ("OR" and_expr)*"""
        left = self._parse_and()

        while self._peek().type == TokenType.OR:
            op_tok = self._advance()
            right = self._parse_and()
            left = ast_nodes.BinaryOp(
                op="OR",
                left=left,
                right=right,
                line=op_tok.line,
                col=op_tok.col,
            )

        return left

    def _parse_and(self) -> ast_nodes.Node:
        """and_expr := not_expr ("AND" not_expr)*"""
        left = self._parse_not()

        while self._peek().type == TokenType.AND:
            op_tok = self._advance()
            right = self._parse_not()
            left = ast_nodes.BinaryOp(
                op="AND",
                left=left,
                right=right,
                line=op_tok.line,
                col=op_tok.col,
            )

        return left

    def _parse_not(self) -> ast_nodes.Node:
        """not_expr := "NOT" not_expr | comparison"""
        if self._peek().type == TokenType.NOT:
            self._depth += 1
            if self._depth > self.MAX_DEPTH:
                tok = self._peek()
                raise ParseError(
                    f"Expression nesting too deep (max {self.MAX_DEPTH})",
                    tok.line,
                    tok.col,
                )
            op_tok = self._advance()
            try:
                operand = self._parse_not()  # Recursive for chained NOT
            finally:
                self._depth -= 1
            return ast_nodes.UnaryOp(
                op="NOT",
                operand=operand,
                line=op_tok.line,
                col=op_tok.col,
            )
        return self._parse_comparison()

    def _parse_comparison(self) -> ast_nodes.Node:
        """comparison := primary (comp_op primary)?"""
        left = self._parse_primary()

        comp_ops = {
            TokenType.EQ,
            TokenType.NEQ,
            TokenType.GT,
            TokenType.LT,
            TokenType.GTE,
            TokenType.LTE,
            TokenType.IN,
        }

        if self._peek().type in comp_ops:
            op_tok = self._advance()
            right = self._parse_primary()
            op_str = str(op_tok.value)
            return ast_nodes.Compare(
                op=op_str,
                left=left,
                right=right,
                line=op_tok.line,
                col=op_tok.col,
            )

        return left

    def _parse_primary(self) -> ast_nodes.Node:
        """primary := function_call | field_access | literal | '(' expression ')' | list"""
        tok = self._peek()

        # Parenthesized expression
        if tok.type == TokenType.LPAREN:
            self._advance()  # consume (
            expr = self._parse_expression()
            self._expect(TokenType.RPAREN)
            return expr

        # List literal
        if tok.type == TokenType.LBRACKET:
            return self._parse_list()

        # String literal
        if tok.type == TokenType.STRING:
            self._advance()
            return ast_nodes.StringLiteral(value=tok.value, line=tok.line, col=tok.col)

        # Number literal
        if tok.type == TokenType.NUMBER:
            self._advance()
            return ast_nodes.NumberLiteral(value=tok.value, line=tok.line, col=tok.col)

        # Bool literal
        if tok.type == TokenType.BOOL:
            self._advance()
            return ast_nodes.BoolLiteral(value=tok.value, line=tok.line, col=tok.col)

        # Identifier: could be function call or field access
        if tok.type == TokenType.IDENT:
            return self._parse_ident_or_call()

        raise ParseError(
            f"Unexpected token: {tok.type.name} ({tok.value!r})",
            tok.line,
            tok.col,
        )

    def _parse_ident_or_call(self) -> ast_nodes.Node:
        """Parse identifier, field access (a.b.c), or function call (f(...))."""
        tok = self._advance()  # consume IDENT

        # Function call: ident(...)
        if self._peek().type == TokenType.LPAREN:
            return self._parse_function_call(tok)

        # Field access: ident.field.subfield...
        if self._peek().type == TokenType.DOT:
            return self._parse_field_access(tok)

        # Bare identifier
        return ast_nodes.Identifier(name=tok.value, line=tok.line, col=tok.col)

    def _parse_function_call(self, name_tok: Token) -> ast_nodes.FunctionCall:
        """Parse function_call := IDENT '(' args ')'"""
        func_name = name_tok.value

        # Validate function name against whitelist
        if func_name not in BUILTIN_FUNCTIONS:
            raise ParseError(
                f"Unknown function: {func_name!r}. Allowed: {', '.join(sorted(BUILTIN_FUNCTIONS.keys()))}",
                name_tok.line,
                name_tok.col,
            )

        self._expect(TokenType.LPAREN)
        args = self._parse_args()
        self._expect(TokenType.RPAREN)

        # Validate argument count
        min_args, max_args = BUILTIN_FUNCTIONS[func_name]
        if not (min_args <= len(args) <= max_args):
            raise ParseError(
                f"Function {func_name!r} expects {min_args}-{max_args} arguments, got {len(args)}",
                name_tok.line,
                name_tok.col,
            )

        return ast_nodes.FunctionCall(
            name=func_name,
            args=args,
            line=name_tok.line,
            col=name_tok.col,
        )

    def _parse_args(self) -> list[ast_nodes.Node]:
        """Parse comma-separated argument list (possibly empty)."""
        args: list[ast_nodes.Node] = []

        if self._peek().type == TokenType.RPAREN:
            return args  # Empty arg list

        args.append(self._parse_expression())
        while self._peek().type == TokenType.COMMA:
            self._advance()  # consume comma
            args.append(self._parse_expression())

        return args

    def _parse_field_access(self, base_tok: Token) -> ast_nodes.FieldAccess:
        """Parse field access: ident.field.subfield..."""
        fields: list[str] = []

        while self._peek().type == TokenType.DOT:
            self._advance()  # consume .
            field_tok = self._expect(TokenType.IDENT)
            fields.append(field_tok.value)

        return ast_nodes.FieldAccess(
            object=base_tok.value,
            field_path=fields,
            line=base_tok.line,
            col=base_tok.col,
        )

    def _parse_list(self) -> ast_nodes.ListLiteral:
        """Parse list literal: [expr, expr, ...]"""
        _MAX_LIST_ELEMENTS = 256
        tok = self._expect(TokenType.LBRACKET)
        elements: list[ast_nodes.Node] = []

        if self._peek().type != TokenType.RBRACKET:
            elements.append(self._parse_expression())
            while self._peek().type == TokenType.COMMA:
                self._advance()  # consume comma
                if len(elements) >= _MAX_LIST_ELEMENTS:
                    raise ParseError(
                        f"List literal too large (max {_MAX_LIST_ELEMENTS} elements)",
                        tok.line,
                        tok.col,
                    )
                elements.append(self._parse_expression())

        self._expect(TokenType.RBRACKET)
        return ast_nodes.ListLiteral(
            elements=elements,
            line=tok.line,
            col=tok.col,
        )

# ── Convenience Function ─────────────────────────────────────────────────────

def parse_prl(source: str) -> ast_nodes.Rule:
    """
    Parse a PRL rule string into an AST.

    Raises ParseError if the syntax is invalid.

    Example:
        rule = parse_prl('event.type == "TOOL_CALL" AND count("TOOL_CALL", "60s") > 100')
    """
    return Parser(source).parse()
