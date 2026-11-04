import json
import os
import unittest

import yaml

from agentshield.constraints import BUILTIN_SCHEMAS
from agentshield.schema import policy_schema, render

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")


class SchemaTests(unittest.TestCase):
    def test_checked_in_schema_is_current(self):
        with open(os.path.join(ROOT, "docs", "policy.schema.json"), encoding="utf-8") as fh:
            self.assertEqual(fh.read(), render(), "run: agentshield schema > docs/policy.schema.json")

    def test_every_builtin_constraint_is_described_and_required_ones_listed(self):
        schema = policy_schema()
        for name, constraints in BUILTIN_SCHEMAS.items():
            d = schema["$defs"][name]
            self.assertFalse(d["additionalProperties"])
            for key, spec in constraints.items():
                self.assertIn(key, d["properties"])
                self.assertEqual(key in d["required"], spec.required, (name, key))

    def test_example_policy_only_uses_keys_the_schema_knows(self):
        with open(os.path.join(ROOT, "examples", "policies", "default-deny.yaml"), encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        schema = policy_schema()
        self.assertTrue(set(doc) <= set(schema["properties"]))
        for name, rule in doc["tools"].items():
            if name in schema["$defs"]:
                self.assertTrue(set(rule) <= set(schema["$defs"][name]["properties"]), name)

    def test_schema_is_valid_json_with_draft_2020_12_id(self):
        s = json.loads(render())
        self.assertIn("2020-12", s["$schema"])


if __name__ == "__main__":
    unittest.main()
