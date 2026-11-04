import os
import re
import subprocess
import sys
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")


class QuickstartTests(unittest.TestCase):
    def test_quickstart_runs_and_prints_expected_lines(self):
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
        p = subprocess.run([sys.executable, os.path.join(ROOT, "examples", "quickstart.py")], capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        out = p.stdout.splitlines()
        self.assertEqual(out[0], "22")
        self.assertEqual(out[1], "hello")
        self.assertEqual(out[2], "Action denied by security policy.")
        self.assertEqual(out[3], "['PATH_TRAVERSAL']")
        self.assertTrue(out[4].startswith("waiting for approval: "))
        self.assertIn("bytes_written", out[5])

    def test_readme_embeds_the_quickstart_verbatim(self):
        with open(os.path.join(ROOT, "examples", "quickstart.py"), encoding="utf-8") as fh:
            code = fh.read().strip()
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as fh:
            readme = fh.read()
        blocks = re.findall(r"```python\n(.*?)```", readme, re.S)
        self.assertIn(code, [b.strip() for b in blocks], "README quickstart drifted from examples/quickstart.py")


if __name__ == "__main__":
    unittest.main()
