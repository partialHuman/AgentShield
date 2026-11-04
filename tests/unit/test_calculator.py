import unittest

from agentshield.adapters.calculator import calculate
from agentshield.models import ExecutionError


class CalculatorTests(unittest.TestCase):
    def test_arithmetic(self):
        self.assertEqual(calculate("2 + 3 * 4"), 14)
        self.assertEqual(calculate("(2+3)*4"), 20)
        self.assertEqual(calculate("2 ** 10"), 1024)
        self.assertEqual(calculate("7 // 2"), 3)
        self.assertEqual(calculate("7 % 4"), 3)
        self.assertEqual(calculate("-3 + +2"), -1)
        self.assertAlmostEqual(calculate("10 / 4"), 2.5)
        self.assertEqual(calculate("  1.5 * 2 "), 3.0)

    def rejects(self, expr, code="INVALID_EXPRESSION"):
        with self.assertRaises(ExecutionError) as cm:
            calculate(expr)
        self.assertEqual(cm.exception.code, code, expr)

    def test_rejects_everything_but_arithmetic(self):
        for expr in [
            "__import__('os').system('id')", "open('/etc/passwd')", "().__class__", "a + 1", "1 if 1 else 2",
            "[1,2]", "{1:2}", "'a' * 3", "True + 1", "None", "1j", "lambda: 1", "(x := 1)", "1 < 2", "not 1",
            "1 and 2", "abs(-1)", "1;2", "import os", "", "   ", "1 +", "-" * 100 + "1", "1 @ 2", "~1", "1 << 2",
            "b'x'", "...", "f'{1}'", "\x00", "1\x002",
        ]:
            self.rejects(expr)

    def test_redundant_parentheses_are_harmless(self):
        self.assertEqual(calculate("(((((((((1)))))))))"), 1)

    def test_huge_inputs_fail_cleanly(self):
        self.rejects("1+" * 50_000 + "1")
        self.rejects("9" * 20_000)

    def test_magnitude_and_dos_bounds(self):
        self.rejects("9 ** 9 ** 9", "NUMERIC_RANGE")
        self.rejects("10 ** 101", "NUMERIC_RANGE")
        self.rejects("10 ** 100 * 10 ** 100", "NUMERIC_RANGE")
        self.rejects("1.5 ** 100000", "NUMERIC_RANGE")
        self.rejects("(-8) ** 0.5", "NUMERIC_RANGE")
        self.rejects("1e308 * 10", "NUMERIC_RANGE")
        self.rejects("1/0", "DIVISION_BY_ZERO")
        self.rejects("1//0", "DIVISION_BY_ZERO")
        self.rejects("1%0", "DIVISION_BY_ZERO")
        self.rejects("+".join(["1"] * 500), "INVALID_EXPRESSION")

    def test_numeric_boundary_and_floats(self):
        self.assertEqual(calculate("10 ** 60"), 10**60)
        self.rejects("10 ** 60 + 1", "NUMERIC_RANGE")
        self.assertEqual(calculate("0"), 0)
        self.assertEqual(calculate("0.0"), 0.0)
        self.assertEqual(calculate("1e10"), 1e10)
        self.assertEqual(calculate("1.25 + 2.75"), 4.0)
        self.assertEqual(calculate("+42"), 42)
        self.assertEqual(calculate("-42"), -42)
        self.assertEqual(calculate("-(-42)"), 42)
        self.assertEqual(calculate("+-+-42"), 42)

    def test_direct_ast_eval_invalid_types_rejected(self):
        import ast
        from agentshield.adapters.calculator import _eval
        for val in ["str", b"bytes", 1j, None, ..., True, False]:
            with self.assertRaises(ExecutionError) as cm:
                _eval(ast.Constant(value=val))
            self.assertEqual(cm.exception.code, "INVALID_EXPRESSION")

    def test_direct_ast_eval_unsupported_unary_op_rejected(self):
        import ast
        from agentshield.adapters.calculator import _eval
        with self.assertRaises(ExecutionError) as cm:
            _eval(ast.UnaryOp(op=ast.Invert(), operand=ast.Constant(value=1)))
        self.assertEqual(cm.exception.code, "INVALID_EXPRESSION")


if __name__ == "__main__":
    unittest.main()
