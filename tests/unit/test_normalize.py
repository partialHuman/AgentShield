import unittest

from agentshield.models import Reason
from agentshield.normalize import (
    ArgSpec, Limits, NormalizationError, action_hash, bound_summary, canonical_json, default_summary, normalize_args,
)

S = {"p": ArgSpec("path"), "n": ArgSpec("int", required=False), "t": ArgSpec("text", required=False)}


def code(fn, *a, **k):
    try:
        fn(*a, **k)
    except NormalizationError as e:
        return e.code
    return None


class NormalizeTests(unittest.TestCase):
    def test_ok_and_nfc(self):
        out = normalize_args(S, {"p": "cafe\u0301.txt"})
        self.assertEqual(out["p"], "caf\u00e9.txt")

    def test_text_is_not_modified(self):
        raw = "line1\r\nline2\tcafe\u0301"
        self.assertEqual(normalize_args(S, {"p": "a", "t": raw})["t"], raw)

    def test_missing_unexpected_and_types(self):
        self.assertEqual(code(normalize_args, S, {}), Reason.SCHEMA_MISSING_FIELD)
        self.assertEqual(code(normalize_args, S, {"p": "a", "zzz": 1}), Reason.SCHEMA_UNEXPECTED_FIELD)
        self.assertEqual(code(normalize_args, S, {"p": 5}), Reason.SCHEMA_INVALID_TYPE)
        self.assertEqual(code(normalize_args, S, {"p": "a", "n": "1"}), Reason.SCHEMA_INVALID_TYPE)

    def test_bool_is_not_int_and_str_subclass_rejected(self):
        self.assertEqual(code(normalize_args, S, {"p": "a", "n": True}), Reason.SCHEMA_INVALID_TYPE)

        class Evil(str):
            pass

        self.assertEqual(code(normalize_args, S, {"p": Evil("a")}), Reason.SCHEMA_INVALID_TYPE)

    def test_control_and_format_characters(self):
        for bad in ["a\x00b", "a\nb", "a\u202eb", "a\u200bb", "a\x7fb"]:
            self.assertIn(code(normalize_args, S, {"p": bad}), (Reason.ARG_INVALID_CHARACTERS,), repr(bad))
        self.assertEqual(code(normalize_args, S, {"p": "a", "t": "x\x00y"}), Reason.ARG_INVALID_CHARACTERS)

    def test_lone_surrogate_rejected(self):
        self.assertEqual(code(normalize_args, S, {"p": "a\ud800"}), Reason.ARG_INVALID_CHARACTERS)

    def test_size_bounds(self):
        self.assertEqual(code(normalize_args, S, {"p": "a" * 5000}), Reason.ARG_TOO_LARGE)
        self.assertEqual(code(normalize_args, {"t": ArgSpec("text")}, {"t": "x" * 2000}, limits=Limits(max_str=1000)), Reason.ARG_TOO_LARGE)
        self.assertEqual(code(normalize_args, {"j": ArgSpec("json")}, {"j": ["x" * 400] * 20}, limits=Limits(max_arg_bytes=1000)), Reason.ARG_TOO_LARGE)

    def test_empty_identifier_rejected(self):
        self.assertEqual(code(normalize_args, S, {"p": ""}), Reason.SCHEMA_INVALID_VALUE)

    def test_json_depth_and_items(self):
        nested: object = 1
        for _ in range(30):
            nested = [nested]
        self.assertEqual(code(normalize_args, {"j": ArgSpec("json")}, {"j": nested}), Reason.ARG_TOO_DEEP)
        self.assertEqual(code(normalize_args, {"j": ArgSpec("json")}, {"j": list(range(1000))}), Reason.ARG_TOO_LARGE)
        self.assertEqual(code(normalize_args, {"j": ArgSpec("json")}, {"j": {1: 2}}), Reason.SCHEMA_INVALID_TYPE)
        self.assertEqual(code(normalize_args, {"j": ArgSpec("json")}, {"j": float("nan")}), Reason.SCHEMA_INVALID_VALUE)
        self.assertEqual(code(normalize_args, {"j": ArgSpec("json")}, {"j": object()}), Reason.SCHEMA_INVALID_TYPE)

    def test_non_mapping_and_non_str_keys(self):
        self.assertEqual(code(normalize_args, S, ["p"]), Reason.MALFORMED_REQUEST)
        self.assertEqual(code(normalize_args, S, {1: "x"}), Reason.MALFORMED_REQUEST)

    def test_default_applied(self):
        s = {"a": ArgSpec("bool", required=False, default=False)}
        self.assertEqual(normalize_args(s, {}), {"a": False})

    def test_action_hash_is_canonical(self):
        a = action_hash("t", {"b": 1, "a": 2}, "x")
        b = action_hash("t", {"a": 2, "b": 1}, "x")
        self.assertEqual(a, b)
        self.assertNotEqual(a, action_hash("t", {"a": 2, "b": 1}, "y"))
        self.assertNotEqual(a, action_hash("u", {"a": 2, "b": 1}, "x"))
        self.assertEqual(canonical_json({"b": 1, "a": 2}), '{"a":2,"b":1}')

    def test_summaries_never_include_values(self):
        s = default_summary({"secret": "hunter2", "n": 5})
        self.assertNotIn("hunter2", str(s))
        big = bound_summary({"k": "x" * 1000})
        self.assertLess(len(big["k"]), 300)


if __name__ == "__main__":
    unittest.main()
