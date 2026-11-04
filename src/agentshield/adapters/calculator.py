"""Safe arithmetic tool: an AST whitelist, bounded magnitudes, no names or calls."""

from __future__ import annotations

import ast
import operator
from typing import Any, Callable

from ..constraints import CALCULATOR_CONSTRAINTS
from ..models import ExecutionError, Reason
from ..normalize import ArgSpec, truncate
from ..policy import ToolPolicy
from ..tools import CheckOutcome, Tool

_MAX_MAGNITUDE = 10**60
_MAX_NODES = 200
_MAX_DEPTH = 40
_MAX_EXPONENT = 100

_BIN = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod, ast.Pow: operator.pow,
}
def _pos(v: int | float) -> int | float:
    return +v


def _neg(v: int | float) -> int | float:
    return -v


_UNARY: dict[type[ast.unaryop], Callable[[int | float], int | float]] = {
    ast.UAdd: _pos,
    ast.USub: _neg,
}


def _parse(expr: str) -> ast.Expression:
    if len(expr) > 10_000:
        raise ExecutionError("INVALID_EXPRESSION", "expression too long")
    try:
        tree = ast.parse(expr.strip(), mode="eval")
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        raise ExecutionError("INVALID_EXPRESSION", "cannot parse expression") from None
    count = 0

    def walk(node: ast.AST, depth: int) -> None:
        nonlocal count
        count += 1
        if count > _MAX_NODES or depth > _MAX_DEPTH:
            raise ExecutionError("INVALID_EXPRESSION", "expression too complex")
        if isinstance(node, ast.Expression):
            walk(node.body, depth + 1)
        elif isinstance(node, ast.BinOp) and type(node.op) in _BIN:
            walk(node.left, depth + 1)
            walk(node.right, depth + 1)
        elif isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY:
            walk(node.operand, depth + 1)
        elif isinstance(node, ast.Constant) and type(node.value) in (int, float):
            return
        else:
            raise ExecutionError("INVALID_EXPRESSION", f"unsupported syntax: {type(node).__name__}")

    walk(tree, 0)
    return tree


def _bound(v: int | float) -> int | float:
    if type(v) not in (int, float):  # e.g. complex from (-8) ** 0.5
        raise ExecutionError("NUMERIC_RANGE", "result is not a real number")
    if isinstance(v, float) and v != v:  # NaN
        raise ExecutionError("NUMERIC_RANGE", "result is not a number")
    if abs(v) > _MAX_MAGNITUDE:
        raise ExecutionError("NUMERIC_RANGE", "magnitude too large")
    return v


def _eval(node: ast.AST) -> int | float:
    if isinstance(node, ast.Expression):
        return _eval(node.body)
    if isinstance(node, ast.Constant):
        val = node.value
        if isinstance(val, (int, float)) and not isinstance(val, bool):
            return _bound(val)
        raise ExecutionError("INVALID_EXPRESSION", f"unsupported constant: {type(val).__name__}")
    if isinstance(node, ast.UnaryOp):
        op = _UNARY.get(type(node.op))
        if op is None:
            raise ExecutionError("INVALID_EXPRESSION", f"unsupported unary operator: {type(node.op).__name__}")
        return _bound(op(_eval(node.operand)))
    if isinstance(node, ast.BinOp):
        left, right = _eval(node.left), _eval(node.right)
        if isinstance(node.op, ast.Pow) and abs(right) > _MAX_EXPONENT:
            raise ExecutionError("NUMERIC_RANGE", "exponent too large")
        try:
            return _bound(_BIN[type(node.op)](left, right))
        except ZeroDivisionError:
            raise ExecutionError("DIVISION_BY_ZERO") from None
        except OverflowError:
            raise ExecutionError("NUMERIC_RANGE", "overflow") from None
        except TypeError:  # e.g. complex result of negative ** fractional
            raise ExecutionError("NUMERIC_RANGE", "unsupported operands") from None
    raise ExecutionError("INVALID_EXPRESSION")  # pragma: no cover - guarded by _parse


def calculate(expression: str) -> int | float:
    return _eval(_parse(expression))


def _checker(args: dict[str, Any], tp: ToolPolicy) -> CheckOutcome:
    limit = int(tp.constraints.get("max_expression_length", 200))
    expr = args["expression"]
    if len(expr) > limit:
        return CheckOutcome(None, (Reason.ARG_TOO_LARGE,), (f"expression longer than {limit}",))
    try:
        _parse(expr)
    except ExecutionError as exc:
        return CheckOutcome(None, (Reason.SCHEMA_INVALID_VALUE,), (f"expression rejected: {exc.code}",))
    return CheckOutcome(None, (), ("expression syntax is within the whitelist",))


def calculator_tool() -> Tool:
    return Tool(
        name="calculator",
        args={"expression": ArgSpec("text", max_length=1000)},
        executor_factory=lambda _tp: (lambda expression: calculate(expression)),
        checker=_checker,
        constraint_schema=CALCULATOR_CONSTRAINTS,
        summarize=lambda a: {"expression": truncate(a["expression"], 100)},
    )
