import os
import sqlite3
import unittest

from agentshield import ApprovalStore, ApprovalStoreError
from tests.helpers import FakeClock, TmpDirTestCase

H = dict(action_hash="a" * 64, policy_hash="b" * 64, agent_id="agent-1")


class ApprovalStoreTests(TmpDirTestCase):
    def setUp(self):
        super().setUp()
        self.clock = FakeClock()
        self.store = ApprovalStore(os.path.join(self.tmp, "ap"), clock=self.clock)

    def req(self, **over):
        kw = dict(**H, tool="filesystem.write", risk="high", summary={"target": "/x"}, ttl_seconds=300)
        kw.update(over)
        return self.store.request(**kw)

    def test_lifecycle_and_single_use(self):
        self.assertEqual(self.store.resolve(**H).state, "none")
        r = self.req()
        self.assertEqual(self.store.resolve(**H).state, "pending")
        self.assertFalse(self.store.consume(r.id), "pending approvals cannot be consumed")
        self.store.decide(r.id, True, approver="alice")
        res = self.store.resolve(**H)
        self.assertEqual((res.state, res.record.approver), ("approved", "alice"))
        self.assertTrue(self.store.consume(r.id))
        self.assertFalse(self.store.consume(r.id), "single use")
        self.assertEqual(self.store.resolve(**H).state, "none")

    def test_identical_requests_dedupe(self):
        a, b = self.req(), self.req()
        self.assertEqual(a.id, b.id)
        self.assertEqual(len(self.store.list("pending")), 1)

    def test_binding_to_action_policy_and_agent(self):
        r = self.req()
        self.store.decide(r.id, True)
        for k, v in (("action_hash", "c" * 64), ("policy_hash", "d" * 64), ("agent_id", "agent-2")):
            self.assertEqual(self.store.resolve(**{**H, k: v}).state, "none", k)

    def test_expiry(self):
        r = self.req(ttl_seconds=60)
        self.clock.advance(61)
        self.assertEqual(self.store.resolve(**H).state, "none")
        with self.assertRaises(ApprovalStoreError):
            self.store.decide(r.id, True)

    def test_approved_then_expired_cannot_be_consumed(self):
        r = self.req(ttl_seconds=60)
        self.store.decide(r.id, True)
        self.clock.advance(61)
        self.assertFalse(self.store.consume(r.id))
        self.assertEqual(self.store.resolve(**H).state, "none")

    def test_rejection(self):
        r = self.req()
        self.store.decide(r.id, False)
        self.assertEqual(self.store.resolve(**H).state, "rejected")
        self.assertFalse(self.store.consume(r.id))

    def test_cannot_decide_twice_or_unknown(self):
        r = self.req()
        self.store.decide(r.id, True)
        with self.assertRaises(ApprovalStoreError):
            self.store.decide(r.id, True)
        with self.assertRaises(ApprovalStoreError):
            self.store.decide("nope", True)

    def test_db_tampering_without_key_is_detected(self):
        r = self.req()
        con = sqlite3.connect(self.store.db_path)
        con.execute("UPDATE approvals SET status='approved', decided_at=1, mac='forged' WHERE id=?", (r.id,))
        con.commit()
        con.close()
        self.assertEqual(self.store.resolve(**H).state, "invalid")
        self.assertFalse(self.store.consume(r.id))

    def test_mac_is_bound_to_row_contents(self):
        r1 = self.req()
        r2 = self.req(action_hash="e" * 64)
        self.store.decide(r1.id, True)
        con = sqlite3.connect(self.store.db_path)
        mac = con.execute("SELECT mac FROM approvals WHERE id=?", (r1.id,)).fetchone()[0]
        con.execute("UPDATE approvals SET status='approved', decided_at=(SELECT decided_at FROM approvals WHERE id=?), mac=? WHERE id=?", (r1.id, mac, r2.id))
        con.commit()
        con.close()
        self.assertFalse(self.store.consume(r2.id), "an approval MAC cannot be transplanted to another action")

    def test_queue_cap(self):
        store = ApprovalStore(os.path.join(self.tmp, "ap2"), clock=self.clock, max_pending=2)
        for i in range(2):
            store.request(action_hash=str(i) * 64, policy_hash="b" * 64, agent_id="a", tool="t", risk=None, summary={}, ttl_seconds=60)
        with self.assertRaisesRegex(ApprovalStoreError, "full"):
            store.request(action_hash="9" * 64, policy_hash="b" * 64, agent_id="a", tool="t", risk=None, summary={}, ttl_seconds=60)

    @unittest.skipUnless(os.name == "posix", "POSIX file modes")
    def test_key_file_permissions(self):
        self.assertEqual(oct(os.stat(self.store.key_path).st_mode & 0o777), "0o600")
        os.chmod(self.store.key_path, 0o644)
        with self.assertRaises(ApprovalStoreError):
            ApprovalStore(os.path.join(self.tmp, "ap"))

    def test_corrupt_key_rejected(self):
        d = os.path.join(self.tmp, "ap3")
        os.makedirs(d)
        with open(os.path.join(d, "approval.key"), "wb") as fh:
            fh.write(b"short")
        os.chmod(os.path.join(d, "approval.key"), 0o600)
        with self.assertRaises(ApprovalStoreError):
            ApprovalStore(d)

    def test_key_is_persistent_across_instances(self):
        r = self.req()
        self.store.decide(r.id, True)
        again = ApprovalStore(os.path.join(self.tmp, "ap"), clock=self.clock)
        self.assertEqual(again.resolve(**H).state, "approved")

    def test_concurrent_consume_only_one_succeeds(self):
        import threading
        r = self.req()
        self.store.decide(r.id, True)
        results = []
        def attempt():
            results.append(self.store.consume(r.id))
        threads = [threading.Thread(target=attempt) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results.count(True), 1)
        self.assertEqual(results.count(False), 9)

    def test_modified_action_hash_or_policy_hash_denied(self):
        r = self.req()
        self.store.decide(r.id, True)
        # Modified action arguments
        self.assertEqual(self.store.resolve(action_hash="f" * 64, policy_hash=H["policy_hash"], agent_id=H["agent_id"]).state, "none")
        # Modified policy version
        self.assertEqual(self.store.resolve(action_hash=H["action_hash"], policy_hash="e" * 64, agent_id=H["agent_id"]).state, "none")


if __name__ == "__main__":
    unittest.main()
