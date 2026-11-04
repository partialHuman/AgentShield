import json
import os
import unittest

from agentshield import AuditLog, AuditWriteError, verify_chain
from tests.helpers import FakeClock, TmpDirTestCase


class AuditTests(TmpDirTestCase):
    def make(self, n=5, **kw):
        path = os.path.join(self.tmp, "audit.jsonl")
        log = AuditLog(path, clock=FakeClock(), **kw)
        for i in range(n):
            log.record("decision", tool="t", i=i, decision="ALLOW")
        log.close()
        return path

    def lines(self, path):
        with open(path, "rb") as fh:
            return fh.read().splitlines(keepends=True)

    def write(self, path, lines):
        with open(path, "wb") as fh:
            fh.writelines(lines)

    def test_valid_chain(self):
        path = self.make(5)
        res = verify_chain(path)
        self.assertTrue(res.ok, res.error)
        self.assertEqual(res.events, 5)
        if os.name == "posix":
            self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o600")

    def test_chain_links_and_schema(self):
        path = self.make(3)
        evs = [json.loads(x) for x in self.lines(path)]
        self.assertEqual([e["seq"] for e in evs], [1, 2, 3])
        self.assertEqual(evs[0]["prev_hash"], "0" * 64)
        self.assertEqual(evs[1]["prev_hash"], evs[0]["hash"])
        self.assertTrue(all(e["schema"] == 1 and e["ts"].endswith("+00:00") for e in evs))

    def test_detects_edit(self):
        path = self.make(5)
        ls = self.lines(path)
        ev = json.loads(ls[2])
        ev["decision"] = "DENY"
        ls[2] = (json.dumps(ev, sort_keys=True, separators=(",", ":")) + "\n").encode()
        self.write(path, ls)
        res = verify_chain(path)
        self.assertFalse(res.ok)
        self.assertEqual(res.line, 3)

    def test_detects_edit_with_recomputed_hash_via_next_link(self):
        from agentshield.audit import _hash_event

        path = self.make(5)
        ls = self.lines(path)
        ev = json.loads(ls[1])
        ev["decision"] = "DENY"
        ev["hash"] = _hash_event(ev)
        ls[1] = (json.dumps(ev, sort_keys=True, separators=(",", ":")) + "\n").encode()
        self.write(path, ls)
        res = verify_chain(path)
        self.assertFalse(res.ok)
        self.assertEqual(res.line, 3)  # the successor no longer links

    def test_detects_deletion_insertion_and_reorder(self):
        path = self.make(5)
        ls = self.lines(path)
        for mutated in (ls[:2] + ls[3:], ls[:3] + [ls[1]] + ls[3:], [ls[1], ls[0]] + ls[2:]):
            self.write(path, mutated)
            self.assertFalse(verify_chain(path).ok)

    def test_detects_tail_truncation_via_head(self):
        path = self.make(5)
        self.write(path, self.lines(path)[:3])
        res = verify_chain(path)
        self.assertFalse(res.ok)
        self.assertIn("truncated", res.error)

    def test_detects_total_wipe_via_head(self):
        path = self.make(5)
        self.write(path, [])
        self.assertFalse(verify_chain(path).ok)

    def test_external_anchor(self):
        path = self.make(4)
        anchor = verify_chain(path).last_hash
        self.assertTrue(verify_chain(path, expect_hash=anchor).ok)
        self.assertFalse(verify_chain(path, expect_hash="0" * 64).ok)
        os.remove(path + ".head")  # attacker removes head and truncates; anchor still catches it
        self.write(path, self.lines(path)[:2])
        self.assertFalse(verify_chain(path, expect_hash=anchor).ok)

    def test_garbage_line(self):
        path = self.make(2)
        with open(path, "ab") as fh:
            fh.write(b"not json\n")
        self.assertFalse(verify_chain(path).ok)

    def test_reopen_continues_chain(self):
        path = self.make(3)
        log = AuditLog(path)
        log.record("decision", tool="t")
        log.close()
        res = verify_chain(path)
        self.assertTrue(res.ok, res.error)
        self.assertEqual(res.events, 4)

    def test_two_writers_same_file_keep_chain(self):
        path = os.path.join(self.tmp, "a.jsonl")
        a, b = AuditLog(path), AuditLog(path)
        for i in range(10):
            (a if i % 2 else b).record("decision", i=i)
        a.close(); b.close()
        res = verify_chain(path)
        self.assertTrue(res.ok, res.error)
        self.assertEqual(res.events, 10)

    def test_threads_keep_chain(self):
        import threading

        path = os.path.join(self.tmp, "t.jsonl")
        log = AuditLog(path)
        ts = [threading.Thread(target=lambda: [log.record("decision", n=n) for n in range(25)]) for _ in range(6)]
        [t.start() for t in ts]; [t.join() for t in ts]
        log.close()
        res = verify_chain(path)
        self.assertTrue(res.ok, res.error)
        self.assertEqual(res.events, 150)

    def test_write_failure_raises_audit_write_error(self):
        class Broken(AuditLog):
            def _append(self, event):
                raise OSError("disk full")

        with self.assertRaises(AuditWriteError):
            Broken().record("decision")

    def test_oversized_event_is_bounded(self):
        log = AuditLog()
        ev = log.record("decision", args_summary={"k": "x" * 50_000}, target="t")
        self.assertEqual(ev["args_summary"], {"_truncated": True})

    def test_refuses_to_append_to_unreadable_existing_log(self):
        path = os.path.join(self.tmp, "bad.jsonl")
        with open(path, "wb") as fh:
            fh.write(b"garbage without json\n")
        log = AuditLog(path)
        with self.assertRaises(AuditWriteError):
            log.record("decision")

    def test_memory_mode(self):
        log = AuditLog()
        log.record("decision", tool="x")
        self.assertEqual(len(log.events), 1)

    def test_tampering_event_seq_detected(self):
        path = self.make(3)
        ls = self.lines(path)
        ev = json.loads(ls[1])
        ev["seq"] = 99
        ls[1] = (json.dumps(ev, sort_keys=True, separators=(",", ":")) + "\n").encode()
        self.write(path, ls)
        res = verify_chain(path)
        self.assertFalse(res.ok)


if __name__ == "__main__":
    unittest.main()
