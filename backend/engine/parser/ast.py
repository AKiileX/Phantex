# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
PRL Abstract Syntax Tree node definitions.

PRL (Phantex Rule Language) is a safe DSL for defining detection rules.
No eval(), no exec(), no code injection possible — only a fixed set of
node types, operators, and built-in functions.

Every PRL rule is parsed into an AST of these nodes, then evaluated
against an event context by the evaluator.

Example PRL:
    event.type == "TOOL_CALL" AND count("TOOL_CALL", "60s") > 100

Parses to:
    BinaryOp(
        op="AND",
        left=Compare(op="==", left=FieldAccess("event", "type"), right=StringLiteral("TOOL_CALL")),
        right=Compare(op=">", left=FunctionCall("count", [StringLiteral("TOOL_CALL"), StringLiteral("60s")]),
                       right=NumberLiteral(100))
    )
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ── Base Node ─────────────────────────────────────────────────────────────────

@dataclass(slots=True)
class Node:
    """Base AST node. All nodes have a source position for error messages."""

    line: int = 0
    col: int = 0

# ── Literals ──────────────────────────────────────────────────────────────────

@dataclass(slots=True)
class StringLiteral(Node):
    """A quoted string value: "TOOL_CALL", "60s", ".*password.*" """

    value: str = ""

@dataclass(slots=True)
class NumberLiteral(Node):
    """An integer or float: 100, 3.14, 10_000_000"""

    value: float | int = 0

@dataclass(slots=True)
class BoolLiteral(Node):
    """A boolean: true, false"""

    value: bool = False

@dataclass(slots=True)
class ListLiteral(Node):
    """A list of values: ["a", "b", "c"] or [1, 2, 3]"""

    elements: list[Node] = field(default_factory=list)

# ── Identifiers / Field Access ────────────────────────────────────────────────

@dataclass(slots=True)
class Identifier(Node):
    """A bare name: severity, enabled"""

    name: str = ""

@dataclass(slots=True)
class FieldAccess(Node):
    """
    Dotted field access: event.type, event.raw_data.tool_name

    object: the base name (e.g., "event")
    field_path: list of field names (e.g., ["type"] or ["raw_data", "tool_name"])
    """

    object: str = ""
    field_path: list[str] = field(default_factory=list)

# ── Operators ─────────────────────────────────────────────────────────────────

@dataclass(slots=True)
class Compare(Node):
    """
    Comparison: ==, !=, >, <, >=, <=, IN

    left: expression
    right: expression
    op: one of "==", "!=", ">", "<", ">=", "<=", "IN"
    """

    op: str = ""
    left: Node = field(default_factory=Node)
    right: Node = field(default_factory=Node)

@dataclass(slots=True)
class BinaryOp(Node):
    """
    Logical binary: AND, OR

    left: boolean expression
    right: boolean expression
    op: "AND" or "OR"
    """

    op: str = ""
    left: Node = field(default_factory=Node)
    right: Node = field(default_factory=Node)

@dataclass(slots=True)
class UnaryOp(Node):
    """
    Unary: NOT

    operand: boolean expression
    op: "NOT"
    """

    op: str = ""
    operand: Node = field(default_factory=Node)

# ── Function Calls ────────────────────────────────────────────────────────────

@dataclass(slots=True)
class FunctionCall(Node):
    """
    Built-in function call: count("TOOL_CALL", "60s"), contains(event.tool_input, "password")

    name: function name (must be in the allowed function registry)
    args: list of argument expressions
    """

    name: str = ""
    args: list[Node] = field(default_factory=list)

# ── Rule Structure ────────────────────────────────────────────────────────────

@dataclass(slots=True)
class Rule(Node):
    """
    A complete PRL rule = condition expression.
    The rule fires when the condition evaluates to True.
    """

    condition: Node = field(default_factory=Node)

# ── Visitor Helpers ───────────────────────────────────────────────────────────

def walk(node: Node) -> list[Node]:
    """Walk all child nodes (depth-first). Useful for analysis/validation."""
    result: list[Node] = [node]

    if isinstance(node, Compare | BinaryOp):
        result.extend(walk(node.left))
        result.extend(walk(node.right))
    elif isinstance(node, UnaryOp):
        result.extend(walk(node.operand))
    elif isinstance(node, FunctionCall):
        for arg in node.args:
            result.extend(walk(arg))
    elif isinstance(node, ListLiteral):
        for elem in node.elements:
            result.extend(walk(elem))
    elif isinstance(node, Rule):
        result.extend(walk(node.condition))

    return result

def pretty_print(node: Node, indent: int = 0) -> str:
    """Pretty-print an AST for debugging."""
    pad = "  " * indent
    if isinstance(node, StringLiteral):
        return f'{pad}String("{node.value}")'
    elif isinstance(node, NumberLiteral):
        return f"{pad}Number({node.value})"
    elif isinstance(node, BoolLiteral):
        return f"{pad}Bool({node.value})"
    elif isinstance(node, Identifier):
        return f"{pad}Ident({node.name})"
    elif isinstance(node, FieldAccess):
        path = ".".join([node.object] + node.field_path)
        return f"{pad}Field({path})"
    elif isinstance(node, Compare):
        lines = [f"{pad}Compare({node.op})"]
        lines.append(pretty_print(node.left, indent + 1))
        lines.append(pretty_print(node.right, indent + 1))
        return "\n".join(lines)
    elif isinstance(node, BinaryOp):
        lines = [f"{pad}BinaryOp({node.op})"]
        lines.append(pretty_print(node.left, indent + 1))
        lines.append(pretty_print(node.right, indent + 1))
        return "\n".join(lines)
    elif isinstance(node, UnaryOp):
        lines = [f"{pad}UnaryOp({node.op})"]
        lines.append(pretty_print(node.operand, indent + 1))
        return "\n".join(lines)
    elif isinstance(node, FunctionCall):
        lines = [f"{pad}Call({node.name})"]
        for arg in node.args:
            lines.append(pretty_print(arg, indent + 1))
        return "\n".join(lines)
    elif isinstance(node, ListLiteral):
        lines = [f"{pad}List"]
        for elem in node.elements:
            lines.append(pretty_print(elem, indent + 1))
        return "\n".join(lines)
    elif isinstance(node, Rule):
        lines = [f"{pad}Rule"]
        lines.append(pretty_print(node.condition, indent + 1))
        return "\n".join(lines)
    else:
        return f"{pad}Node()"
