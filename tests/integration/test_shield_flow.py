import asyncio
import gc
import inspect
import os
import threading
import unittest

from agentshield import (
    ActionDenied, ApprovalPending, ArgSpec, AuditLog, C, CheckOutcome, Decision, ExecutionError, PolicyError,
    Reason, Shield, Tool, ToolExecutionError, verify_chain,
)
from tests.helpers import BASE_POLICY, Counter, FakeClock, TmpDirTestCase

CUSTOM = """
version: 1
tools:
  demo.echo: {risk: low, decision: ALLOW}
  demo.send:
    risk: high
    decision: REQUIRE_APPROVAL
    arg_constraints: {channel: {enum: [ops, dev]}, text: {max_length: 20}}
  demo.limited: {risk: low, decision: ALLOW, max_calls: 2}
  demo.off: {enabled: false, risk: low, decision: ALLOW}
  demo.blocked: {risk: low, decision: DENY}
  demo.nums: {risk: low, decision: ALLOW, arg_constraints: {n: {min: 0, max: 10}}}
"""
ECHO = {"msg": ArgSpec("str", required=False, default="x")}


def tool(name, fn, args=None):
    return Tool.from_callable(fn, name, args or ECHO)


class DenyMeansNoExecutionTests(TmpDirTestCase):
    """The headline guarantee: DENY / REQUIRE_APPROVAL never reach the executor."""

    def test_every_non_allow_outcome_leaves_executor_untouched(self):
        sh = self.shield(CUSTOM, approvals=True)
        ctr = Counter()
        send = sh.wrap(tool("demo.send", ctr, {"channel": ArgSpec("str"), "text": ArgSpec("text")}))
        off = sh.wrap(tool("demo.off", ctr))
        blocked = sh.wrap(tool("demo.blocked", ctr))
        nums = sh.wrap(tool("demo.nums", ctr, {"n": ArgSpec("int")}))
        unlisted = sh.wrap(tool("demo.unlisted", ctr))
        attempts = [
            (send, dict(channel="ops", text="hi")),  # requires approval
            (send, dict(channel="evil", text="hi")),  # enum violation
            (send, dict(channel="ops", text="x" * 50)),  # length violation
            (send, dict(channel="ops")),  # missing field
            (send, dict(channel="ops", text="hi", extra=1)),  # unexpected field
            (off, {}), (blocked, {}), (unlisted, {}),
            (nums, dict(n=11)), (nums, dict(n=-1)), (nums, dict(n="5")), (nums, dict(n=True)),
        ]
        for fn, kw in attempts:
            with self.assertRaises((ActionDenied, ApprovalPending)):
                fn(**kw)
        self.assertEqual(ctr.count, 0)
        decisions = [e for e in sh.audit.events if e["type"] == "decision"]
        self.assertEqual(len(decisions), len(attempts))
        self.assertTrue(all(e["decision"] in ("DENY", "REQUIRE_APPROVAL") for e in decisions))
        self.assertEqual([e for e in sh.audit.events if e["type"] == "outcome"], [])

    def test_unknown_tool_name_is_denied_via_evaluate(self):
        sh = self.shield(CUSTOM)
        r = sh.evaluate("shell.exec", {"cmd": "id"})
        self.assertEqual((r.decision, r.reason_codes), (Decision.DENY, [Reason.UNKNOWN_TOOL]))
        for bad in (None, 5, ["x"], "x" * 500):
            self.assertEqual(sh.evaluate(bad, {}).decision, Decision.DENY)

    def test_policy_entry_without_wrapped_tool_is_not_callable(self):
        sh = self.shield(CUSTOM)  # nothing wrapped
        self.assertEqual(sh.evaluate("demo.echo", {}).reason_codes, [Reason.UNKNOWN_TOOL])

    def test_wrapped_tool_with_no_policy_rule_is_default_denied(self):
        sh = self.shield(CUSTOM)
        ctr = Counter()
        fn = sh.wrap(tool("demo.nopolicy", ctr))
        with self.assertRaises(ActionDenied) as cm:
            fn()
        self.assertEqual(cm.exception.result.reason_codes, [Reason.NO_POLICY_RULE])
        self.assertEqual(ctr.count, 0)

    def test_evaluator_crash_is_a_deny_not_an_allow(self):
        def bad_checker(args, tp):
            raise RuntimeError("boom")

        sh = self.shield(CUSTOM)
        ctr = Counter()
        fn = sh.wrap(Tool.from_callable(ctr, "demo.echo", ECHO, checker=bad_checker))
        with self.assertRaises(ActionDenied) as cm:
            fn()
        self.assertEqual(cm.exception.result.reason_codes, [Reason.EVALUATOR_ERROR])
        self.assertEqual(ctr.count, 0)
        self.assertEqual(sh.evaluate("demo.echo", {}).reason_codes, [Reason.EVALUATOR_ERROR])

    def test_positional_arguments_rejected(self):
        sh = self.shield(CUSTOM)
        fn = sh.wrap(tool("demo.echo", Counter()))
        with self.assertRaises(TypeError):
            fn("positional")


class CallByNameTests(TmpDirTestCase):
    def test_call_dispatches_by_name_and_audits_unknown_or_garbage_names(self):
        sh = self.shield(CUSTOM, approvals=True)
        ctr = Counter("yes")
        sh.wrap(tool("demo.echo", ctr))
        self.assertEqual(sh.call("demo.echo", {"msg": "a"}), "yes")
        garbage = ["shell.exec", "", None, 5, ["demo.echo"], {"n": 1}, b"demo.echo", "demo.echo\u200b", "x" * 1000, object()]
        for name in garbage:
            with self.assertRaises(ActionDenied) as cm:
                sh.call(name, {})
            self.assertEqual(cm.exception.result.reason_codes, [Reason.UNKNOWN_TOOL], repr(name)[:30])
        for args in (None, [], "x", 5, {1: 2}):
            with self.assertRaises(ActionDenied):
                sh.call("demo.echo", args)
        self.assertEqual(ctr.count, 1)
        self.assertEqual(len([e for e in sh.audit.events if e["type"] == "decision"]), 1 + len(garbage) + 5, "every attempt is audited")

    def test_acall(self):
        sh = self.shield(CUSTOM)
        sh.wrap(tool("demo.echo", Counter("z")))

        async def go():
            ok = await sh.acall("demo.echo", {})
            with self.assertRaises(ActionDenied):
                await sh.acall("nope", {})
            return ok

        self.assertEqual(asyncio.run(go()), "z")


class AllowPathTests(TmpDirTestCase):
    def test_allowed_call_executes_with_normalized_args_and_audits_both_events(self):
        sh = self.shield(CUSTOM)
        seen = []
        fn = sh.wrap(tool("demo.echo", lambda msg: seen.append(msg) or "done"))
        self.assertEqual(fn(msg="cafe\u0301"), "done")
        self.assertEqual(seen, ["caf\u00e9"])
        dec, out = sh.audit.events
        self.assertEqual((dec["type"], dec["decision"], dec["reason_codes"]), ("decision", "ALLOW", ["ALLOWED_BY_POLICY"]))
        self.assertEqual((out["type"], out["status"]), ("outcome", "ok"))
        self.assertEqual(out["decision_event_id"], dec["event_id"])
        self.assertEqual(out["request_id"], dec["request_id"])
        self.assertEqual(dec["agent_id"], "test-agent")
        self.assertEqual(dec["policy_hash"], sh.policy.hash)

    def test_decision_event_is_written_before_dispatch(self):
        sh = self.shield(CUSTOM)
        snapshots = []

        def executor(msg):
            snapshots.append([(e["type"], e["decision"] if e["type"] == "decision" else None) for e in sh.audit.events])
            return "ok"

        sh.wrap(tool("demo.echo", executor))(msg="a")
        self.assertEqual(snapshots, [[("decision", "ALLOW")]])

    def test_executor_error_is_wrapped_and_audited_without_message(self):
        sh = self.shield(CUSTOM)

        def boom(msg):
            raise ValueError("secret-token-123")

        fn = sh.wrap(tool("demo.echo", boom))
        with self.assertRaises(ToolExecutionError) as cm:
            fn()
        self.assertEqual(cm.exception.error_code, "EXECUTOR_EXCEPTION")
        self.assertNotIn("secret-token-123", str(cm.exception))
        out = sh.audit.events[-1]
        self.assertEqual((out["status"], out["error_code"]), ("error", "EXECUTOR_EXCEPTION"))
        self.assertNotIn("secret-token-123", str(sh.audit.events))
        self.assertIsInstance(cm.exception.__cause__, ValueError)

    def test_executor_execution_error_keeps_stable_code(self):
        sh = self.shield(CUSTOM)

        def fail(msg):
            raise ExecutionError("NOT_FOUND", "detail")

        with self.assertRaises(ToolExecutionError) as cm:
            sh.wrap(tool("demo.echo", fail))()
        self.assertEqual(cm.exception.error_code, "NOT_FOUND")

    def test_call_limit(self):
        sh = self.shield(CUSTOM)
        ctr = Counter()
        fn = sh.wrap(tool("demo.limited", ctr))
        fn(); fn()
        with self.assertRaises(ActionDenied) as cm:
            fn()
        self.assertEqual(cm.exception.result.reason_codes, [Reason.CALL_LIMIT_EXCEEDED])
        self.assertEqual(ctr.count, 2)

    def test_call_limit_is_exact_under_concurrency(self):
        sh = self.shield("version: 1\ntools:\n  demo.limited: {risk: low, decision: ALLOW, max_calls: 7}\n")
        ctr = Counter()
        fn = sh.wrap(tool("demo.limited", ctr))
        denied = []

        def worker():
            for _ in range(10):
                try:
                    fn()
                except ActionDenied:
                    denied.append(1)

        ts = [threading.Thread(target=worker) for _ in range(8)]
        [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(ctr.count, 7)
        self.assertEqual(len(denied), 80 - 7)

    def test_denial_message_is_generic_and_details_are_available_to_developers(self):
        sh = self.shield(CUSTOM)
        fn = sh.wrap(tool("demo.nums", Counter(), {"n": ArgSpec("int")}))
        with self.assertRaises(ActionDenied) as cm:
            fn(n=99)
        e = cm.exception
        self.assertEqual(str(e), "Action denied by security policy.")
        self.assertEqual(e.agent_message(), "Action denied by security policy.")
        self.assertNotIn("maximum", str(e) + e.agent_message() + e.code)
        self.assertEqual(e.result.reason_codes, [Reason.ARG_CONSTRAINT_VIOLATION])
        self.assertTrue(any("above maximum" in t for t in e.result.trace))

    def test_custom_checker_and_constraint_schema(self):
        pol = "version: 1\ntools:\n  demo.fetch: {risk: low, decision: ALLOW, hosts: [a.com, b.com]}\n"
        sh = self.shield(pol)

        def checker(args, tp):
            ok = args["host"] in tp.constraints["hosts"]
            return CheckOutcome(args["host"], () if ok else (Reason.HOST_NOT_ALLOWED,))

        t = Tool.from_callable(Counter(), "demo.fetch", {"host": ArgSpec("str")}, checker=checker,
                               constraint_schema={"hosts": C("str_list", nonempty=True)})
        fn = sh.wrap(t)
        fn(host="a.com")
        with self.assertRaises(ActionDenied):
            fn(host="evil.com")

    def test_custom_tool_unknown_constraint_fails_at_wrap_time(self):
        sh = self.shield("version: 1\ntools:\n  demo.fetch: {risk: low, decision: ALLOW, typo_key: 1}\n")
        with self.assertRaises(PolicyError):
            sh.wrap(Tool.from_callable(Counter(), "demo.fetch", ECHO))

    def test_double_wrap_rejected_and_bad_agent_id(self):
        sh = self.shield(CUSTOM)
        sh.wrap(tool("demo.echo", Counter()))
        with self.assertRaises(ValueError):
            sh.wrap(tool("demo.echo", Counter()))
        with self.assertRaises(ValueError):
            Shield(sh.policy, agent_id="bad id!")

    def test_metrics(self):
        sh = self.shield(CUSTOM)
        fn = sh.wrap(tool("demo.nums", Counter(), {"n": ArgSpec("int")}))
        fn(n=1)
        with self.assertRaises(ActionDenied):
            fn(n=50)
        m = sh.metrics()
        self.assertEqual(m["decisions"], {"ALLOW": 1, "DENY": 1})
        self.assertEqual(m["denials_by_reason"], {"ARG_CONSTRAINT_VIOLATION": 1})
        self.assertEqual(m["decision_latency_ms"]["count"], 2)


class ApprovalFlowTests(TmpDirTestCase):
    def setUp(self):
        super().setUp()
        self.clock = FakeClock()
        self.sh = self.shield(CUSTOM, approvals=True, clock=self.clock)
        self.ctr = Counter()
        self.send = self.sh.wrap(tool("demo.send", self.ctr, {"channel": ArgSpec("str"), "text": ArgSpec("text")}))
        self.store = self.sh._approvals

    def pending(self, **kw):
        with self.assertRaises(ApprovalPending) as cm:
            self.send(**(kw or dict(channel="ops", text="deploy")))
        return cm.exception

    def test_full_flow_single_use(self):
        p = self.pending()
        self.assertEqual(self.ctr.count, 0)
        self.assertEqual(self.pending().request_id, p.request_id, "re-submitting does not create duplicates")
        self.store.decide(p.request_id, True, approver="alice")
        self.assertEqual(self.send(channel="ops", text="deploy"), "ran")
        self.assertEqual(self.ctr.count, 1)
        self.pending()  # consumed: a new identical call needs a NEW approval
        self.assertEqual(self.ctr.count, 1)
        reasons = [e["reason_codes"][0] for e in self.sh.audit.events if e["type"] == "decision"]
        self.assertEqual(reasons, ["APPROVAL_REQUIRED", "APPROVAL_PENDING", "APPROVAL_CONSUMED", "APPROVAL_REQUIRED"])

    def test_changed_arguments_invalidate_approval(self):
        p = self.pending()
        self.store.decide(p.request_id, True)
        p2 = self.pending(channel="ops", text="deploy!")
        self.assertNotEqual(p2.request_id, p.request_id)
        self.assertEqual(self.ctr.count, 0)

    def test_approval_for_another_agent_or_policy_is_useless(self):
        p = self.pending()
        self.store.decide(p.request_id, True)
        other_agent = Shield(self.sh.policy, agent_id="someone-else", approvals=self.store)
        with self.assertRaises(ApprovalPending):
            other_agent.wrap(tool("demo.send", self.ctr, {"channel": ArgSpec("str"), "text": ArgSpec("text")}))(channel="ops", text="deploy")
        changed = self.policy(CUSTOM.replace("demo.echo: {risk: low", "demo.echo: {risk: medium"))
        other_policy = Shield(changed, agent_id="test-agent", approvals=self.store)
        with self.assertRaises(ApprovalPending):
            other_policy.wrap(tool("demo.send", self.ctr, {"channel": ArgSpec("str"), "text": ArgSpec("text")}))(channel="ops", text="deploy")
        self.assertEqual(self.ctr.count, 0)

    def test_expired_and_rejected(self):
        p = self.pending()
        self.clock.advance(301)
        with self.assertRaises(ApprovalPending) as cm:
            self.send(channel="ops", text="deploy")
        self.assertNotEqual(cm.exception.request_id, p.request_id)
        self.store.decide(cm.exception.request_id, False)
        with self.assertRaises(ActionDenied) as cm2:
            self.send(channel="ops", text="deploy")
        self.assertEqual(cm2.exception.result.reason_codes, [Reason.APPROVAL_REJECTED])
        self.assertEqual(self.ctr.count, 0)

    def test_approved_but_expired_before_use(self):
        p = self.pending()
        self.store.decide(p.request_id, True)
        self.clock.advance(301)
        with self.assertRaises(ApprovalPending):
            self.send(channel="ops", text="deploy")
        self.assertEqual(self.ctr.count, 0)

    def test_concurrent_resubmission_consumes_approval_exactly_once(self):
        p = self.pending()
        self.store.decide(p.request_id, True)
        results = []

        def worker():
            try:
                self.send(channel="ops", text="deploy")
                results.append("ran")
            except (ApprovalPending, ActionDenied):
                results.append("blocked")

        ts = [threading.Thread(target=worker) for _ in range(10)]
        [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(results.count("ran"), 1)
        self.assertEqual(self.ctr.count, 1)

    def test_no_store_configured_fails_closed(self):
        sh = self.shield(CUSTOM)
        ctr = Counter()
        fn = sh.wrap(tool("demo.send", ctr, {"channel": ArgSpec("str"), "text": ArgSpec("text")}))
        with self.assertRaises(ActionDenied) as cm:
            fn(channel="ops", text="x")
        self.assertEqual(cm.exception.result.reason_codes, [Reason.APPROVAL_UNAVAILABLE])

    def test_queue_full_fails_closed(self):
        from agentshield import ApprovalStore

        store = ApprovalStore(os.path.join(self.tmp, "small"), clock=self.clock, max_pending=1)
        sh = Shield(self.sh.policy, agent_id="a", approvals=store)
        fn = sh.wrap(tool("demo.send", Counter(), {"channel": ArgSpec("str"), "text": ArgSpec("text")}))
        with self.assertRaises(ApprovalPending):
            fn(channel="ops", text="1")
        with self.assertRaises(ActionDenied) as cm:
            fn(channel="ops", text="2")
        self.assertEqual(cm.exception.result.reason_codes, [Reason.APPROVAL_QUEUE_FULL])


class AuditFailureTests(TmpDirTestCase):
    class BrokenAudit(AuditLog):
        def _append(self, event):
            raise OSError("disk full")

    def test_allow_fails_closed_when_decision_event_cannot_be_written(self):
        sh = self.shield(CUSTOM, audit=self.BrokenAudit())
        ctr = Counter()
        fn = sh.wrap(tool("demo.echo", ctr))
        with self.assertRaises(ActionDenied) as cm:
            fn()
        self.assertEqual(cm.exception.result.reason_codes, [Reason.AUDIT_UNAVAILABLE])
        self.assertEqual(ctr.count, 0)
        self.assertEqual(sh.metrics()["counters"]["audit_failures"], 1)

    def test_explicit_low_risk_fallback_only(self):
        sh = self.shield(CUSTOM, audit=self.BrokenAudit(), allow_unaudited_low_risk=True)
        ctr = Counter()
        sh.wrap(tool("demo.echo", ctr))()  # low risk: allowed by explicit opt-in
        self.assertEqual(ctr.count, 1)
        sh2 = self.shield(CUSTOM.replace("demo.echo: {risk: low", "demo.echo: {risk: medium"), audit=self.BrokenAudit(), allow_unaudited_low_risk=True)
        ctr2 = Counter()
        with self.assertRaises(ActionDenied):
            sh2.wrap(tool("demo.echo", ctr2))()
        self.assertEqual(ctr2.count, 0)

    def test_deny_still_denies_when_audit_is_down(self):
        sh = self.shield(CUSTOM, audit=self.BrokenAudit())
        with self.assertRaises(ActionDenied):
            sh.wrap(tool("demo.blocked", Counter()))()

    def test_outcome_audit_failure_does_not_lose_result(self):
        class FailOutcome(AuditLog):
            def _append(self, event):
                if event["type"] == "outcome":
                    raise OSError("x")
                super()._append(event)

        sh = self.shield(CUSTOM, audit=FailOutcome())
        self.assertEqual(sh.wrap(tool("demo.echo", Counter("fine")))(), "fine")

    def test_file_audit_chain_verifies_after_mixed_activity(self):
        path = os.path.join(self.tmp, "audit.jsonl")
        sh = self.shield(CUSTOM, audit=AuditLog(path))
        fn = sh.wrap(tool("demo.nums", Counter(), {"n": ArgSpec("int")}))
        fn(n=1)
        for n in (50, -3):
            with self.assertRaises(ActionDenied):
                fn(n=n)
        sh.audit.close()
        res = verify_chain(path)
        self.assertTrue(res.ok, res.error)
        self.assertEqual(res.events, 4)


class EncapsulationTests(TmpDirTestCase):
    def test_public_api_exposes_no_executor_handle(self):
        sh = self.shield(CUSTOM)
        ctr = Counter()
        fn = sh.wrap(tool("demo.echo", ctr))
        self.assertFalse(hasattr(fn, "__wrapped__"))
        for obj in (fn, sh):
            for name in dir(obj):
                if name.startswith("_"):
                    continue
                try:
                    val = getattr(obj, name)
                except Exception:
                    continue
                self.assertIsNot(val, ctr, f"{type(obj).__name__}.{name} leaks the executor")
        self.assertEqual(ctr.count, 0)

    def test_wrapper_has_no_public_attributes_besides_metadata(self):
        sh = self.shield(CUSTOM)
        fn = sh.wrap(tool("demo.echo", Counter()))
        public = [n for n in vars(fn) if not n.startswith("_")]
        self.assertEqual(public, [])

    def test_tool_object_is_not_the_execution_path(self):
        sh = self.shield(CUSTOM)
        ctr = Counter()
        t = tool("demo.echo", ctr)
        sh.wrap(t)
        gc.collect()
        self.assertEqual(ctr.count, 0)  # wrapping never invokes the executor


class AsyncTests(TmpDirTestCase):
    def run_async(self, coro):
        return asyncio.run(coro)

    def test_async_executor_allowed_and_denied(self):
        sh = self.shield(CUSTOM)
        calls = []

        async def ex(n):
            await asyncio.sleep(0)
            calls.append(n)
            return n * 2

        fn = sh.wrap(Tool.from_callable(ex, "demo.nums", {"n": ArgSpec("int")}))
        self.assertTrue(inspect.iscoroutinefunction(fn))

        async def go():
            ok = await fn(n=4)
            with self.assertRaises(ActionDenied):
                await fn(n=40)
            return ok

        self.assertEqual(self.run_async(go()), 8)
        self.assertEqual(calls, [4])

    def test_wrap_async_runs_sync_executor_in_thread(self):
        sh = self.shield(CUSTOM)
        ctr = Counter("sync-result")
        fn = sh.wrap_async(tool("demo.echo", ctr))
        self.assertEqual(self.run_async(fn(msg="a")), "sync-result")
        self.assertEqual(ctr.count, 1)

    def test_async_denials_never_execute_and_approval_works(self):
        sh = self.shield(CUSTOM, approvals=True)
        ctr = Counter()
        fn = sh.wrap_async(tool("demo.send", ctr, {"channel": ArgSpec("str"), "text": ArgSpec("text")}))

        async def go():
            with self.assertRaises(ApprovalPending) as cm:
                await fn(channel="ops", text="x")
            sh._approvals.decide(cm.exception.request_id, True)
            self.assertEqual(await fn(channel="ops", text="x"), "ran")
            with self.assertRaises(ActionDenied):
                await fn(channel="nope", text="x")

        self.run_async(go())
        self.assertEqual(ctr.count, 1)

    def test_concurrent_async_calls(self):
        sh = self.shield(CUSTOM)
        ctr = Counter()
        fn = sh.wrap_async(tool("demo.nums", ctr, {"n": ArgSpec("int")}))

        async def go():
            res = await asyncio.gather(*[fn(n=i % 20) for i in range(60)], return_exceptions=True)
            return res

        res = self.run_async(go())
        denied = [r for r in res if isinstance(r, ActionDenied)]
        self.assertEqual(len(denied), sum(1 for i in range(60) if i % 20 > 10))
        self.assertEqual(ctr.count, 60 - len(denied))

    def test_cancellation_is_audited(self):
        sh = self.shield(CUSTOM)

        async def slow(msg):
            await asyncio.sleep(10)

        fn = sh.wrap(Tool.from_callable(slow, "demo.echo", ECHO))

        async def go():
            t = asyncio.create_task(fn())
            await asyncio.sleep(0.2)
            t.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await t

        self.run_async(go())
        self.assertEqual(sh.audit.events[-1]["status"], "cancelled")


if __name__ == "__main__":
    unittest.main()
