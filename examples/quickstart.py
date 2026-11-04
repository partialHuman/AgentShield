import os
import tempfile

from agentshield import ActionDenied, ApprovalPending, ApprovalStore, AuditLog, Policy, Shield
from agentshield.adapters import calculator_tool, file_read_tool, file_write_tool

# A throw-away workspace so the example is self-contained.
base = tempfile.mkdtemp()
os.makedirs(os.path.join(base, "workspace", "output"))
with open(os.path.join(base, "workspace", "hello.txt"), "w") as fh:
    fh.write("hello")

policy = Policy.from_text(
    """
version: 1
tools:
  calculator:       {risk: low,    decision: ALLOW}
  filesystem.read:  {risk: medium, decision: ALLOW, allowed_roots: [./workspace]}
  filesystem.write: {risk: high,   decision: REQUIRE_APPROVAL, allowed_roots: [./workspace/output]}
""",
    base_dir=base,
)

store = ApprovalStore(os.path.join(base, ".agentshield"))
shield = Shield(
    policy,
    agent_id="my-agent",
    audit=AuditLog(os.path.join(base, "audit.jsonl")),
    approvals=store,
)
calc = shield.wrap(calculator_tool())
read = shield.wrap(file_read_tool())
write = shield.wrap(file_write_tool())

print(calc(expression="2 + 2 * 10"))  # 22: allowed, executed
print(read(path="hello.txt")["content"])  # hello

try:
    read(path="../../etc/passwd")  # the model asked; the application decides
except ActionDenied as denied:
    print(denied.agent_message())  # generic text for the model
    print(denied.result.reason_codes)  # ['PATH_TRAVERSAL'] (developer-only detail)

try:
    write(path="report.txt", content="hi")  # high risk: needs a human
except ApprovalPending as pending:
    print("waiting for approval:", pending.request_id)
    store.decide(pending.request_id, True)  # normally: `agentshield approvals approve <id>`
    print(write(path="report.txt", content="hi"))  # identical call now runs, exactly once
