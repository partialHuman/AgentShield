import os
import subprocess
import sys
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")


def _can_symlink() -> bool:
    if os.name == "posix":
        return True
    import shutil
    import tempfile
    d = tempfile.mkdtemp()
    try:
        s, l = os.path.join(d, "s"), os.path.join(d, "l")
        with open(s, "w") as f:
            f.write("1")
        os.symlink(s, l)
        return True
    except OSError:
        return False
    finally:
        shutil.rmtree(d, ignore_errors=True)


@unittest.skipUnless(_can_symlink(), "environment does not support symlinks")
class DemoTests(unittest.TestCase):
    def test_scripted_attacker_demo_passes_offline(self):
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path), HTTPS_PROXY="http://127.0.0.1:9")
        p = subprocess.run([sys.executable, os.path.join(ROOT, "examples", "scripted_attacker.py")], capture_output=True,
                           text=True, env=env, timeout=120)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("RESULT: PASS", p.stdout)
        self.assertIn("secret in audit log: False", p.stdout)
        self.assertIn("denied: 11", p.stdout)


if __name__ == "__main__":
    unittest.main()
