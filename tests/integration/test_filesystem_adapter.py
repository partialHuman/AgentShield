import os
import stat
import threading
import unittest

from agentshield import ActionDenied, Policy, Reason, Shield, ToolExecutionError
from agentshield.adapters import file_read_tool, file_write_tool
from agentshield.adapters.filesystem import _read_factory, _write_factory
from tests.helpers import TmpDirTestCase

POSIX = os.name == "posix"
POLICY = """
version: 1
tools:
  filesystem.read: {risk: medium, decision: ALLOW, allowed_roots: [./workspace], max_bytes: 100}
  filesystem.write: {risk: high, decision: ALLOW, allowed_roots: [./workspace/output], max_bytes: 50}
"""


@unittest.skipUnless(POSIX, "POSIX no-follow semantics")
class FileAdapterTests(TmpDirTestCase):
    def setUp(self):
        super().setUp()
        self.outside = os.path.join(self.tmp, "outside")
        os.makedirs(self.outside)
        with open(os.path.join(self.outside, "secret.txt"), "w") as fh:
            fh.write("TOP-SECRET")
        self.sh = self.shield(POLICY)
        self.read = self.sh.wrap(file_read_tool())
        self.write = self.sh.wrap(file_write_tool())

    def denied(self, fn, **kw):
        with self.assertRaises(ActionDenied) as cm:
            fn(**kw)
        return cm.exception.result.reason_codes

    def exec_error(self, fn, **kw):
        with self.assertRaises(ToolExecutionError) as cm:
            fn(**kw)
        return cm.exception.error_code

    # ---- happy path
    def test_read_relative_and_absolute(self):
        self.assertEqual(self.read(path="hello.txt"), {"path": "hello.txt", "size": 5, "content": "hello"})
        self.assertEqual(self.read(path=os.path.join(self.ws, "hello.txt"))["content"], "hello")
        self.assertEqual(self.read(path="./hello.txt")["content"], "hello")
        self.assertEqual(self.denied(self.read, path="//hello.txt"), [Reason.PATH_OUTSIDE_ROOT])  # absolute, not in root

    def test_read_unicode_name_nfc(self):
        with open(os.path.join(self.ws, "caf\u00e9.txt"), "w", encoding="utf-8") as fh:
            fh.write("\u2603")
        self.assertEqual(self.read(path="cafe\u0301.txt")["content"], "\u2603")

    def test_write_create_and_overwrite_semantics(self):
        r = self.write(path="a.txt", content="one")
        self.assertEqual(r, {"path": "a.txt", "bytes_written": 3})
        with open(os.path.join(self.ws, "output", "a.txt")) as fh:
            self.assertEqual(fh.read(), "one")
        self.assertEqual(self.exec_error(self.write, path="a.txt", content="two"), "FILE_EXISTS")
        self.write(path="a.txt", content="two", overwrite=True)
        with open(os.path.join(self.ws, "output", "a.txt")) as fh:
            self.assertEqual(fh.read(), "two")
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.ws, "output", "a.txt")).st_mode), 0o600)

    def test_write_preserves_content_exactly(self):
        text = "line1\r\nline2\n\ttab caf\u00e9\u0301"
        self.write(path="exact.txt", content=text)
        with open(os.path.join(self.ws, "output", "exact.txt"), "rb") as fh:
            self.assertEqual(fh.read(), text.encode("utf-8"))

    # ---- lexical denials
    def test_lexical_denials(self):
        cases = {
            "../outside/secret.txt": Reason.PATH_TRAVERSAL,
            "a/../../outside/secret.txt": Reason.PATH_TRAVERSAL,
            os.path.join(self.outside, "secret.txt"): Reason.PATH_OUTSIDE_ROOT,
            "/etc/passwd": Reason.PATH_OUTSIDE_ROOT,
            self.ws + "x/hello.txt": Reason.PATH_OUTSIDE_ROOT,
            "": Reason.SCHEMA_INVALID_VALUE,
            "dir/": Reason.PATH_INVALID,
        }
        for path, code in cases.items():
            self.assertEqual(self.denied(self.read, path=path), [code], path)

    def test_write_cannot_escape_output_root_into_workspace(self):
        self.assertEqual(self.denied(self.write, path=os.path.join(self.ws, "hello.txt"), content="x"), [Reason.PATH_OUTSIDE_ROOT])
        self.assertEqual(self.denied(self.write, path="../hello.txt", content="x"), [Reason.PATH_TRAVERSAL])

    def test_content_limit_is_enforced_before_write(self):
        self.assertEqual(self.denied(self.write, path="big.txt", content="x" * 51), [Reason.CONTENT_TOO_LARGE])
        self.assertFalse(os.path.exists(os.path.join(self.ws, "output", "big.txt")))

    # ---- symlinks (decision-time detection)
    def test_symlinked_file_dir_and_dangling(self):
        os.symlink(os.path.join(self.outside, "secret.txt"), os.path.join(self.ws, "link.txt"))
        os.symlink(self.outside, os.path.join(self.ws, "dirlink"))
        os.symlink(os.path.join(self.outside, "nonexistent"), os.path.join(self.ws, "dangling"))
        os.symlink("hello.txt", os.path.join(self.ws, "inside-link.txt"))  # even in-root symlinks are refused
        for p in ["link.txt", "dirlink/secret.txt", "dangling", "inside-link.txt", "dirlink/x/y.txt"]:
            self.assertEqual(self.denied(self.read, path=p), [Reason.PATH_SYMLINK], p)
        os.symlink(self.outside, os.path.join(self.ws, "output", "wlink"))
        self.assertEqual(self.denied(self.write, path="wlink/pwned.txt", content="x"), [Reason.PATH_SYMLINK])
        self.assertFalse(os.path.exists(os.path.join(self.outside, "pwned.txt")))

    def test_symlink_as_allowed_root_itself_is_resolved_at_policy_load(self):
        real = os.path.join(self.tmp, "realroot")
        os.makedirs(real)
        with open(os.path.join(real, "f.txt"), "w") as fh:
            fh.write("ok")
        os.symlink(real, os.path.join(self.tmp, "rootlink"))
        sh = Shield(Policy.from_text("version: 1\ntools:\n  filesystem.read: {risk: low, decision: ALLOW, allowed_roots: [./rootlink]}\n", base_dir=self.tmp), agent_id="a")
        self.assertEqual(sh.wrap(file_read_tool())(path="f.txt")["content"], "ok")

    # ---- TOCTOU: the symlink appears AFTER the decision, before use ----
    def test_toctou_symlink_swapped_in_after_decision_is_still_blocked_at_use_time(self):
        read_exec = _read_factory(self.sh.policy.tool_policy("filesystem.read"))
        write_exec = _write_factory(self.sh.policy.tool_policy("filesystem.write"))
        # decision-time state: harmless real directory
        os.makedirs(os.path.join(self.ws, "sub"))
        with open(os.path.join(self.ws, "sub", "f.txt"), "w") as fh:
            fh.write("benign")
        self.assertEqual(self.sh.evaluate("filesystem.read", {"path": "sub/f.txt"}).decision.value, "ALLOW")
        # attacker swaps the directory for a symlink to the outside, between check and use
        os.rename(os.path.join(self.ws, "sub"), os.path.join(self.ws, "sub.old"))
        os.symlink(self.outside, os.path.join(self.ws, "sub"))
        os.symlink(os.path.join(self.outside, "secret.txt"), os.path.join(self.ws, "sub.old", "link"))
        from agentshield import ExecutionError

        with self.assertRaises(ExecutionError) as cm:
            read_exec(path="sub/secret.txt")
        self.assertEqual(cm.exception.code, Reason.PATH_SYMLINK)
        os.symlink(self.outside, os.path.join(self.ws, "output", "swap"))
        with self.assertRaises(ExecutionError) as cm2:
            write_exec(path="swap/pwned.txt", content="x")
        self.assertEqual(cm2.exception.code, Reason.PATH_SYMLINK)
        self.assertFalse(os.path.exists(os.path.join(self.outside, "pwned.txt")))

    def test_toctou_race_thread_hammering_symlink_swaps(self):
        """Swap a directory <-> symlink in a tight loop while reading; the secret must never be returned."""
        from agentshield import ExecutionError

        read_exec = _read_factory(self.sh.policy.tool_policy("filesystem.read"))
        real = os.path.join(self.ws, "d")
        os.makedirs(real)
        with open(os.path.join(real, "secret.txt"), "w") as fh:
            fh.write("benign")
        stop = threading.Event()

        def swapper():
            n = 0
            while not stop.is_set():
                n += 1
                tmp = os.path.join(self.ws, f"swap{n % 2}")
                try:
                    os.rename(real, real + ".bak")
                    os.symlink(self.outside, real)
                    os.unlink(real)
                    os.rename(real + ".bak", real)
                except OSError:
                    pass
                del tmp

        t = threading.Thread(target=swapper)
        t.start()
        leaked, blocked, ok = 0, 0, 0
        import time

        t0 = time.monotonic()
        try:
            for _ in range(30000):
                if time.monotonic() - t0 > 4:
                    break
                try:
                    out = read_exec(path="d/secret.txt")
                    if "TOP-SECRET" in out["content"]:
                        leaked += 1
                    else:
                        ok += 1
                except ExecutionError as exc:
                    blocked += exc.code == Reason.PATH_SYMLINK
        finally:
            stop.set()
            t.join()
        self.stats = (ok, blocked)
        self.assertEqual(leaked, 0)

    # ---- file-type and link hazards
    def test_hardlink_to_outside_file_is_refused(self):
        os.link(os.path.join(self.outside, "secret.txt"), os.path.join(self.ws, "hard.txt"))
        self.assertEqual(self.exec_error(self.read, path="hard.txt"), "HARDLINK_NOT_ALLOWED")
        os.link(os.path.join(self.outside, "secret.txt"), os.path.join(self.ws, "output", "hardw.txt"))
        self.assertEqual(self.exec_error(self.write, path="hardw.txt", content="x", overwrite=True), "HARDLINK_NOT_ALLOWED")
        with open(os.path.join(self.outside, "secret.txt")) as fh:
            self.assertEqual(fh.read(), "TOP-SECRET")

    def test_fifo_is_refused_without_blocking(self):
        os.mkfifo(os.path.join(self.ws, "pipe"))
        self.assertEqual(self.exec_error(self.read, path="pipe"), "NOT_REGULAR_FILE")

    def test_directory_target_and_missing(self):
        self.assertIn(self.exec_error(self.read, path="output"), ("NOT_REGULAR_FILE", "IO_ERROR"))
        self.assertEqual(self.exec_error(self.read, path="missing.txt"), "NOT_FOUND")
        self.assertEqual(self.exec_error(self.read, path="nodir/x.txt"), "NOT_FOUND")
        self.assertEqual(self.exec_error(self.write, path="nodir/x.txt", content="x"), "NOT_FOUND")

    def test_read_size_limit_and_encoding(self):
        with open(os.path.join(self.ws, "big.txt"), "w") as fh:
            fh.write("x" * 101)
        self.assertEqual(self.exec_error(self.read, path="big.txt"), "FILE_TOO_LARGE")
        with open(os.path.join(self.ws, "bin.dat"), "wb") as fh:
            fh.write(b"\xff\xfe\x00")
        self.assertEqual(self.exec_error(self.read, path="bin.dat"), "NOT_UTF8")

    def test_file_content_never_appears_in_audit_log(self):
        self.write(path="s.txt", content="PASSWORD=hunter2")
        self.read(path="output/s.txt")
        dump = str(self.sh.audit.events)
        self.assertNotIn("hunter2", dump)
        self.assertIn("content_sha256", dump)

    def test_target_in_audit_is_canonical_path(self):
        self.read(path="./hello.txt")
        self.assertEqual(self.sh.audit.events[0]["target"], os.path.join(self.ws, "hello.txt"))


if __name__ == "__main__":
    unittest.main()
