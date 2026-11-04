import os
import unittest

from agentshield.adapters.filesystem import PathProblem, resolve_in_roots, split_path, windows_component_error
from agentshield.models import Reason

ROOTS = ["/srv/ws", "/srv/other"]


def code(fn, *a, **k):
    try:
        fn(*a, **k)
    except PathProblem as e:
        return e.code
    return None


class PathLogicTests(unittest.TestCase):
    def test_relative_uses_first_root(self):
        self.assertEqual(resolve_in_roots("a/b.txt", ROOTS, windows=False), ("/srv/ws", ["a", "b.txt"]))
        self.assertEqual(resolve_in_roots("./a//b/./c.txt", ROOTS, windows=False), ("/srv/ws", ["a", "b", "c.txt"]))

    def test_absolute_inside_any_root(self):
        self.assertEqual(resolve_in_roots("/srv/ws/a.txt", ROOTS, windows=False), ("/srv/ws", ["a.txt"]))
        self.assertEqual(resolve_in_roots("/srv/other/x/y.txt", ROOTS, windows=False), ("/srv/other", ["x", "y.txt"]))

    def test_traversal_always_rejected_even_if_it_would_stay_inside(self):
        for p in ["../x", "a/../b", "a/b/../../..", "/srv/ws/../ws/a.txt", "..", "a/.."]:
            self.assertEqual(code(resolve_in_roots, p, ROOTS, windows=False), Reason.PATH_TRAVERSAL, p)

    def test_outside_root(self):
        for p in ["/etc/passwd", "/srv/wsx/a.txt", "/srv", "/", "/srv/ws"]:
            self.assertIn(code(resolve_in_roots, p, ROOTS, windows=False), (Reason.PATH_OUTSIDE_ROOT, Reason.PATH_INVALID), p)
        self.assertEqual(code(resolve_in_roots, "/srv/wsx/a.txt", ROOTS, windows=False), Reason.PATH_OUTSIDE_ROOT)
        self.assertEqual(code(resolve_in_roots, "/srv/ws", ROOTS, windows=False), Reason.PATH_OUTSIDE_ROOT)

    def test_invalid_shapes(self):
        for p in ["", "dir/", ".", "./", "//", "a\x00b"]:
            self.assertEqual(code(split_path, p), Reason.PATH_INVALID, repr(p))
        self.assertEqual(code(split_path, "a" * 300), Reason.PATH_INVALID)

    def test_backslash_is_ordinary_on_posix_but_a_separator_on_windows(self):
        self.assertEqual(split_path("a\\b", windows=False), (False, ["a\\b"]))
        self.assertEqual(split_path("a\\b", windows=True), (False, ["a", "b"]))
        self.assertEqual(code(split_path, "..\\x", windows=True), Reason.PATH_TRAVERSAL)

    def test_windows_rules(self):
        for p in ["C:\\Windows\\x", "c:x", "\\\\server\\share\\x", "//server/share/x", "a/CON", "a/nul.txt", "a/COM1", "file.txt:stream", "a/b.", "a/b ", "a/PROGRA~1", "a/b?.txt"]:
            self.assertIsNotNone(code(split_path, p, windows=True), p)
        self.assertEqual(code(resolve_in_roots, "/abs/path.txt", ROOTS, windows=True), Reason.PATH_OUTSIDE_ROOT)
        self.assertIsNone(windows_component_error("notes.txt"))
        self.assertIsNone(windows_component_error("conf"))  # not reserved
        self.assertIsNotNone(windows_component_error("LPT9.log"))

    def test_probe_windows_detects_reparse_point_at_decision_time(self):
        import shutil
        import tempfile
        from agentshield.adapters.filesystem import probe_windows
        tmp = tempfile.mkdtemp()
        try:
            f = os.path.join(tmp, "real.txt")
            with open(f, "w") as fh:
                fh.write("real")
            self.assertIsNone(probe_windows(tmp, ["real.txt"]))
            try:
                os.symlink(f, os.path.join(tmp, "sym.txt"))
                self.assertEqual(probe_windows(tmp, ["sym.txt"]), Reason.PATH_SYMLINK)
            except OSError:
                pass  # symlink creation restricted
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
