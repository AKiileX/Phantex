# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
PRL Evaluator — walks the AST and evaluates conditions against an event context.

The event context is a flat dictionary built from the database Event model:
{
    "event": {
        "type": "TOOL_CALL",
        "severity": "medium",
        "agent_id": "...",
        "raw_data": { "tool_name": "exec_shell", ... },
    },
    "rule": {
        "severity": "high",
        "attack_class": "command_injection",
    },
}

Field access like `event.raw_data.tool_name` is resolved by walking the
nested dictionaries.

Security: No eval(), no exec(). Only the fixed set of AST node types are
dispatched.  Unknown node types raise EvalError.
"""

from __future__ import annotations

from typing import Any

from engine.evaluator.functions import BuiltinRegistry, FunctionContext
from engine.parser import ast as ast_nodes

class EvalError(Exception):
    """Raised when evaluation encounters a runtime error."""

    def __init__(self, message: str, node: ast_nodes.Node | None = None) -> None:
        self.node = node
        loc = ""
        if node:
            loc = f" (line {node.line}, col {node.col})"
        super().__init__(f"{message}{loc}")

class Evaluator:
    """
    Evaluate a parsed PRL Rule against an event context.

    Usage:
        evaluator = Evaluator(functions=registry)
        result = evaluator.evaluate(rule, context)  # → bool
    """

    def __init__(self, functions: BuiltinRegistry | None = None) -> None:
        self._functions = functions or BuiltinRegistry()

    def evaluate(
        self,
        rule: ast_nodes.Rule,
        context: dict[str, Any],
        func_ctx: FunctionContext | None = None,
    ) -> bool:
        """Evaluate a Rule node against a context dict. Returns True if the rule fires."""
        result = self._eval_node(rule.condition, context, func_ctx)
        return bool(result)

    def _eval_node(
        self,
        node: ast_nodes.Node,
        ctx: dict[str, Any],
        func_ctx: FunctionContext | None,
    ) -> Any:
        """Dispatch evaluation based on node type."""
        dispatch = {
            ast_nodes.StringLiteral: self._eval_string,
            ast_nodes.NumberLiteral: self._eval_number,
            ast_nodes.BoolLiteral: self._eval_bool,
            ast_nodes.ListLiteral: self._eval_list,
            ast_nodes.Identifier: self._eval_identifier,
            ast_nodes.FieldAccess: self._eval_field_access,
            ast_nodes.Compare: self._eval_compare,
            ast_nodes.BinaryOp: self._eval_binary_op,
            ast_nodes.UnaryOp: self._eval_unary_op,
            ast_nodes.FunctionCall: self._eval_function_call,
        }

        handler = dispatch.get(type(node))
        if handler is None:
            raise EvalError(f"Unknown node type: {type(node).__name__}", node)

        return handler(node, ctx, func_ctx)

    # ── Literals ──────────────────────────────────────────────────────────

    def _eval_string(
        self,
        node: ast_nodes.StringLiteral,
        ctx: dict,
        func_ctx: FunctionContext | None,
    ) -> str:
        return node.value

    def _eval_number(
        self,
        node: ast_nodes.NumberLiteral,
        ctx: dict,
        func_ctx: FunctionContext | None,
    ) -> float | int:
        return node.value

    def _eval_bool(
        self,
        node: ast_nodes.BoolLiteral,
        ctx: dict,
        func_ctx: FunctionContext | None,
    ) -> bool:
        return node.value

    def _eval_list(
        self,
        node: ast_nodes.ListLiteral,
        ctx: dict,
        func_ctx: FunctionContext | None,
    ) -> list:
        return [self._eval_node(el, ctx, func_ctx) for el in node.elements]

    # ── Context Resolution ────────────────────────────────────────────────

    # Sentinel returned when a field path doesn't exist in the event.
    # Comparisons against _MISSING always return False, which means rules
    # silently skip events that lack the fields they inspect — the correct
    # behaviour for a multi-rule engine where most rules don't apply to
    # most event types.
    _MISSING = type("_MISSING", (), {"__repr__": lambda s: "<MISSING>", "__bool__": lambda s: False})()

    def _eval_identifier(
        self,
        node: ast_nodes.Identifier,
        ctx: dict,
        func_ctx: FunctionContext | None,
    ) -> Any:
        if node.name in ctx:
            return ctx[node.name]
        raise EvalError(f"Undefined variable: {node.name!r}", node)

    def _eval_field_access(
        self,
        node: ast_nodes.FieldAccess,
        ctx: dict,
        func_ctx: FunctionContext | None,
    ) -> Any:
        obj = ctx.get(node.object)
        if obj is None:
            # Top-level object missing → field is absent, not an error
            return self._MISSING

        current = obj
        for _i, field_name in enumerate(node.field_path):
            if isinstance(current, dict):
                if field_name in current:
                    current = current[field_name]
                else:
                    # Field path doesn't exist in this event → not an error
                    return self._MISSING
            else:
                # Trying to traverse into a non-dict value → field absent
                return self._MISSING

        return current

    # ── Operators ─────────────────────────────────────────────────────────

    def _eval_compare(
        self,
        node: ast_nodes.Compare,
        ctx: dict,
        func_ctx: FunctionContext | None,
    ) -> bool:
        left = self._eval_node(node.left, ctx, func_ctx)
        right = self._eval_node(node.right, ctx, func_ctx)

        # If either side is a missing field, the comparison is undefined → False
        if left is self._MISSING or right is self._MISSING:
            return False

        op = node.op
        if op == "==":
            return left == right
        elif op == "!=":
            return left != right
        elif op == ">":
            return left > right
        elif op == "<":
            return left < right
        elif op == ">=":
            return left >= right
        elif op == "<=":
            return left <= right
        elif op == "IN":
            if not isinstance(right, list | tuple | set):
                raise EvalError(
                    f"IN operator requires a list on the right side, got {type(right).__name__}",
                    node,
                )
            return left in right
        else:
            raise EvalError(f"Unknown comparison operator: {op!r}", node)

    def _eval_binary_op(
        self,
        node: ast_nodes.BinaryOp,
        ctx: dict,
        func_ctx: FunctionContext | None,
    ) -> bool:
        if node.op == "AND":
            # Short-circuit
            left_val = self._eval_node(node.left, ctx, func_ctx)
            if not left_val:
                return False
            return bool(self._eval_node(node.right, ctx, func_ctx))
        elif node.op == "OR":
            # Short-circuit
            left_val = self._eval_node(node.left, ctx, func_ctx)
            if left_val:
                return True
            return bool(self._eval_node(node.right, ctx, func_ctx))
        else:
            raise EvalError(f"Unknown binary operator: {node.op!r}", node)

    def _eval_unary_op(
        self,
        node: ast_nodes.UnaryOp,
        ctx: dict,
        func_ctx: FunctionContext | None,
    ) -> bool:
        if node.op == "NOT":
            val = self._eval_node(node.operand, ctx, func_ctx)
            return not val
        raise EvalError(f"Unknown unary operator: {node.op!r}", node)

    # ── Function Calls ────────────────────────────────────────────────────

    def _eval_function_call(
        self,
        node: ast_nodes.FunctionCall,
        ctx: dict,
        func_ctx: FunctionContext | None,
    ) -> Any:
        # Evaluate all arguments first
        args = [self._eval_node(arg, ctx, func_ctx) for arg in node.args]

        # If any argument resolved to _MISSING, the function cannot execute
        # meaningfully → return False (e.g. regex_match on a missing field)
        if any(a is self._MISSING for a in args):
            return False

        try:
            return self._functions.call(node.name, args, ctx, func_ctx)
        except Exception as e:
            raise EvalError(f"Function {node.name!r} failed: {e}", node) from e
