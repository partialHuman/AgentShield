"""Local, single-use, expiring approvals backed by SQLite.

Binding: an approval is valid only for the exact (action_hash, policy_hash,
agent_id) it was requested for. Approvals are single-use (atomic consume) and
expire. Approver identity in v0.1 is the local OS user plus possession of a
local secret key file (HMAC); that is a documented limitation, not a strong
authentication boundary against code running as the same user.
"""

from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import stat
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from .models import ApprovalStoreError

_SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY, action_hash TEXT NOT NULL, policy_hash TEXT NOT NULL, agent_id TEXT NOT NULL,
  tool TEXT NOT NULL, risk TEXT, summary TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL,
  status TEXT NOT NULL, decided_at REAL, approver TEXT, mac TEXT, consumed_at REAL
);
CREATE INDEX IF NOT EXISTS idx_approvals_key ON approvals (action_hash, policy_hash, agent_id);
"""


@dataclass(frozen=True)
class ApprovalRecord:
    id: str
    action_hash: str
    policy_hash: str
    agent_id: str
    tool: str
    risk: str | None
    summary: dict[str, Any]
    created_at: float
    expires_at: float
    status: str  # pending | approved | rejected | consumed
    decided_at: float | None
    approver: str | None

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


@dataclass(frozen=True)
class Resolution:
    """State of the approval for an action: none | pending | approved | rejected | invalid."""

    state: str
    record: ApprovalRecord | None = None


class ApprovalStore:
    def __init__(
        self,
        directory: str | os.PathLike[str],
        *,
        clock: Callable[[], float] = time.time,
        max_pending: int = 1000,
    ):
        self.directory = os.fspath(directory)
        self._clock = clock
        self._max_pending = max_pending
        os.makedirs(self.directory, mode=0o700, exist_ok=True)
        self.db_path = os.path.join(self.directory, "approvals.db")
        self.key_path = os.path.join(self.directory, "approval.key")
        self._key = self._load_or_create_key()
        with self._conn() as c:
            c.executescript(_SCHEMA)
        if os.name == "posix":
            os.chmod(self.db_path, 0o600)

    # ---- key handling ----
    def _load_or_create_key(self) -> bytes:
        if not os.path.exists(self.key_path):
            try:
                fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as fh:
                    fh.write(secrets.token_bytes(32))
            except FileExistsError:
                pass
        if os.name == "posix":
            mode = os.stat(self.key_path).st_mode
            if mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise ApprovalStoreError("approval.key must not be accessible by group/others (chmod 600)")
        with open(self.key_path, "rb") as fh:
            key = fh.read()
        if len(key) < 32:
            raise ApprovalStoreError("approval.key is too short or corrupt")
        return key

    def _mac(self, rid: str, action_hash: str, policy_hash: str, agent_id: str, decided_at: float) -> str:
        msg = f"{rid}|{action_hash}|{policy_hash}|{agent_id}|approved|{decided_at!r}".encode()
        return hmac.new(self._key, msg, hashlib.sha256).hexdigest()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    @staticmethod
    def _rec(row: sqlite3.Row) -> ApprovalRecord:
        return ApprovalRecord(
            row["id"], row["action_hash"], row["policy_hash"], row["agent_id"], row["tool"], row["risk"],
            json.loads(row["summary"]), row["created_at"], row["expires_at"], row["status"],
            row["decided_at"], row["approver"],
        )

    # ---- agent/shield side ----
    def resolve(self, action_hash: str, policy_hash: str, agent_id: str) -> Resolution:
        now = self._clock()
        with self._conn() as c:
            row = c.execute(
                "SELECT * FROM approvals WHERE action_hash=? AND policy_hash=? AND agent_id=? "
                "AND status IN ('pending','approved','rejected') AND expires_at>? "
                "ORDER BY created_at DESC LIMIT 1",
                (action_hash, policy_hash, agent_id, now),
            ).fetchone()
        if row is None:
            return Resolution("none")
        rec = self._rec(row)
        if rec.status == "approved":
            expected = self._mac(rec.id, rec.action_hash, rec.policy_hash, rec.agent_id, rec.decided_at or 0.0)
            if not hmac.compare_digest(expected, row["mac"] or ""):
                return Resolution("invalid", rec)
        return Resolution(rec.status, rec)

    def request(
        self,
        *,
        action_hash: str,
        policy_hash: str,
        agent_id: str,
        tool: str,
        risk: str | None,
        summary: dict[str, Any],
        ttl_seconds: int,
    ) -> ApprovalRecord:
        now = self._clock()
        with self._conn() as c:
            c.execute("BEGIN IMMEDIATE")
            try:
                existing = c.execute(
                    "SELECT * FROM approvals WHERE action_hash=? AND policy_hash=? AND agent_id=? "
                    "AND status='pending' AND expires_at>? LIMIT 1",
                    (action_hash, policy_hash, agent_id, now),
                ).fetchone()
                if existing is not None:
                    c.execute("COMMIT")
                    return self._rec(existing)
                (pending,) = c.execute(
                    "SELECT COUNT(*) FROM approvals WHERE status='pending' AND expires_at>?", (now,)
                ).fetchone()
                if pending >= self._max_pending:
                    raise ApprovalStoreError("approval queue is full")
                rid = uuid.uuid4().hex[:16]
                c.execute(
                    "INSERT INTO approvals (id, action_hash, policy_hash, agent_id, tool, risk, summary, "
                    "created_at, expires_at, status) VALUES (?,?,?,?,?,?,?,?,?, 'pending')",
                    (rid, action_hash, policy_hash, agent_id, tool, risk, json.dumps(summary, sort_keys=True),
                     now, now + ttl_seconds),
                )
                c.execute("COMMIT")
            except BaseException:
                c.execute("ROLLBACK")
                raise
            row = c.execute("SELECT * FROM approvals WHERE id=?", (rid,)).fetchone()
        return self._rec(row)

    def consume(self, record_id: str) -> bool:
        """Atomically mark an approved, unexpired, authentic approval as consumed."""
        now = self._clock()
        with self._conn() as c:
            c.execute("BEGIN IMMEDIATE")
            try:
                row = c.execute("SELECT * FROM approvals WHERE id=?", (record_id,)).fetchone()
                ok = False
                if row is not None and row["status"] == "approved" and row["expires_at"] > now:
                    expected = self._mac(
                        row["id"], row["action_hash"], row["policy_hash"], row["agent_id"], row["decided_at"] or 0.0
                    )
                    if hmac.compare_digest(expected, row["mac"] or ""):
                        c.execute("UPDATE approvals SET status='consumed', consumed_at=? WHERE id=?", (now, record_id))
                        ok = True
                c.execute("COMMIT")
            except BaseException:
                c.execute("ROLLBACK")
                raise
        return ok

    # ---- approver side (CLI) ----
    def get(self, record_id: str) -> ApprovalRecord | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM approvals WHERE id=?", (record_id,)).fetchone()
        return self._rec(row) if row else None

    def list(self, status: str | None = None) -> list[ApprovalRecord]:
        q, args = "SELECT * FROM approvals", ()
        if status:
            q, args = q + " WHERE status=?", (status,)
        with self._conn() as c:
            rows = c.execute(q + " ORDER BY created_at DESC LIMIT 500", args).fetchall()
        return [self._rec(r) for r in rows]

    def is_expired(self, rec: ApprovalRecord) -> bool:
        return rec.expires_at <= self._clock()

    def decide(self, record_id: str, approve: bool, approver: str | None = None) -> ApprovalRecord:
        """Approve or reject a pending, unexpired request. Raises ApprovalStoreError otherwise."""
        now = self._clock()
        who = approver or _os_user()
        with self._conn() as c:
            c.execute("BEGIN IMMEDIATE")
            try:
                row = c.execute("SELECT * FROM approvals WHERE id=?", (record_id,)).fetchone()
                if row is None:
                    raise ApprovalStoreError("no such approval request")
                if row["status"] != "pending":
                    raise ApprovalStoreError(f"request is already {row['status']}")
                if row["expires_at"] <= now:
                    raise ApprovalStoreError("request has expired")
                if approve:
                    mac = self._mac(row["id"], row["action_hash"], row["policy_hash"], row["agent_id"], now)
                    c.execute(
                        "UPDATE approvals SET status='approved', decided_at=?, approver=?, mac=? WHERE id=?",
                        (now, who, mac, record_id),
                    )
                else:
                    c.execute(
                        "UPDATE approvals SET status='rejected', decided_at=?, approver=? WHERE id=?",
                        (now, who, record_id),
                    )
                c.execute("COMMIT")
            except BaseException:
                c.execute("ROLLBACK")
                raise
        rec = self.get(record_id)
        assert rec is not None
        return rec


def _os_user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001
        return "unknown"
