"""Hash-chained JSONL audit log.

Each event embeds the previous event's hash, so edits, deletions, insertions and
reordering are detectable. A sidecar ``.head`` file records the latest
(seq, hash) so tail truncation is detectable too. This is tamper-*evident*, not
tamper-proof: an attacker who can rewrite the log and head file can forge both.
Anchor ``head`` hashes externally if that matters to you.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .models import AuditWriteError
from .normalize import canonical_json, sha256_hex

try:  # POSIX multi-process locking
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]

SCHEMA_VERSION = 1
GENESIS_HASH = "0" * 64
MAX_EVENT_BYTES = 16 * 1024


def _hash_event(event: dict[str, Any]) -> str:
    body = {k: v for k, v in event.items() if k != "hash"}
    return sha256_hex(canonical_json(body))


class AuditLog:
    """Append-only audit writer. ``path=None`` keeps events in memory (tests, dry runs)."""

    def __init__(
        self,
        path: str | os.PathLike[str] | None = None,
        *,
        fsync: bool = False,
        clock: Callable[[], float] = time.time,
    ):
        self.path = os.fspath(path) if path is not None else None
        self.head_path = f"{self.path}.head" if self.path else None
        self._fsync = fsync
        self._clock = clock
        self._lock = threading.Lock()
        self._seq = 0
        self._last = GENESIS_HASH
        self._known_size = -1
        self._fd: int | None = None
        self.events: list[dict[str, Any]] = []  # memory mode only
        if self.path:
            flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
            self._fd = os.open(self.path, flags, 0o600)

    # -- public --
    def record(self, event_type: str, **fields: Any) -> dict[str, Any]:
        """Append one event; raises AuditWriteError on any failure."""
        try:
            with self._lock:
                self._lock_file()
                try:
                    self._refresh_state()
                    event: dict[str, Any] = {
                        "schema": SCHEMA_VERSION,
                        "seq": self._seq + 1,
                        "event_id": uuid.uuid4().hex,
                        "ts": _dt.datetime.fromtimestamp(self._clock(), _dt.timezone.utc).isoformat(
                            timespec="milliseconds"
                        ),
                        "type": event_type,
                        **fields,
                        "prev_hash": self._last,
                    }
                    if len(canonical_json(event)) > MAX_EVENT_BYTES:
                        event["args_summary"] = {"_truncated": True}
                        event["target"] = None
                    event["hash"] = _hash_event(event)
                    self._append(event)
                    self._seq, self._last = event["seq"], event["hash"]
                    return event
                finally:
                    self._unlock_file()
        except AuditWriteError:
            raise
        except Exception as exc:  # noqa: BLE001 - any failure must surface as AuditWriteError
            raise AuditWriteError(f"audit write failed: {type(exc).__name__}") from None

    def close(self) -> None:
        with self._lock:
            if self._fd is not None:
                os.close(self._fd)
                self._fd = None

    def __enter__(self) -> AuditLog:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- internals (overridable in tests) --
    def _lock_file(self) -> None:
        if self._fd is not None and fcntl is not None:
            fcntl.flock(self._fd, fcntl.LOCK_EX)

    def _unlock_file(self) -> None:
        if self._fd is not None and fcntl is not None:
            fcntl.flock(self._fd, fcntl.LOCK_UN)

    def _refresh_state(self) -> None:
        if self._fd is None:
            return
        size = os.fstat(self._fd).st_size
        if size == self._known_size:
            return
        self._seq, self._last = 0, GENESIS_HASH
        if size:
            with open(self.path, "rb") as fh:  # type: ignore[arg-type]
                fh.seek(max(0, size - 65536))
                tail = fh.read().splitlines()
            for line in reversed(tail):
                try:
                    ev = json.loads(line)
                    self._seq, self._last = int(ev["seq"]), str(ev["hash"])
                    break
                except (ValueError, KeyError, TypeError):
                    continue
            else:
                raise AuditWriteError("existing audit log has no readable tail; refusing to append")
        self._known_size = size

    def _append(self, event: dict[str, Any]) -> None:
        line = (canonical_json(event) + "\n").encode("utf-8")
        if self._fd is None:
            self.events.append(event)
            return
        written = 0
        while written < len(line):
            written += os.write(self._fd, line[written:])
        if self._fsync:
            os.fsync(self._fd)
        self._known_size = os.fstat(self._fd).st_size
        head = json.dumps({"seq": event["seq"], "hash": event["hash"]})
        tmp = f"{self.head_path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(head)
        os.replace(tmp, self.head_path)  # type: ignore[arg-type]


@dataclass
class VerifyResult:
    ok: bool
    events: int
    error: str | None = None
    line: int | None = None
    last_hash: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "events": self.events, "error": self.error, "line": self.line, "last_hash": self.last_hash}


def verify_chain(
    path: str | os.PathLike[str],
    *,
    head_path: str | os.PathLike[str] | None = None,
    expect_hash: str | None = None,
) -> VerifyResult:
    """Verify chain integrity (+ head file, + optional externally anchored hash)."""
    p = os.fspath(path)
    hp = os.fspath(head_path) if head_path is not None else f"{p}.head"
    head: dict[str, Any] | None = None
    if os.path.exists(hp):
        try:
            with open(hp, encoding="utf-8") as fh:
                head = json.load(fh)
            if not isinstance(head, dict) or type(head.get("seq")) is not int:
                raise ValueError
        except (OSError, ValueError):
            return VerifyResult(False, 0, "head file unreadable")
    prev, seq, n = GENESIS_HASH, 0, 0
    hash_at_head: str | None = None
    try:
        with open(p, "rb") as fh:
            for lineno, raw in enumerate(fh, 1):
                try:
                    ev = json.loads(raw)
                except ValueError:
                    return VerifyResult(False, n, "line is not valid JSON", lineno)
                if not isinstance(ev, dict) or ev.get("schema") != SCHEMA_VERSION:
                    return VerifyResult(False, n, "unexpected event schema", lineno)
                if ev.get("seq") != seq + 1:
                    return VerifyResult(False, n, f"sequence gap or reorder (expected {seq + 1})", lineno)
                if ev.get("prev_hash") != prev:
                    return VerifyResult(False, n, "prev_hash does not match previous event", lineno)
                if ev.get("hash") != _hash_event(ev):
                    return VerifyResult(False, n, "event hash mismatch (event was modified)", lineno)
                prev, seq, n = ev["hash"], seq + 1, n + 1
                if head is not None and seq == head["seq"]:
                    hash_at_head = prev
    except OSError as exc:
        return VerifyResult(False, 0, f"cannot read log: {exc.strerror or exc}")
    if head is not None:
        if head["seq"] > seq:
            return VerifyResult(False, n, "log is shorter than its recorded head (truncated?)", None, prev)
        if head["seq"] > 0 and hash_at_head != head.get("hash"):
            return VerifyResult(False, n, "event at recorded head does not match (log was rewritten)", None, prev)
    if expect_hash is not None and expect_hash != prev:
        return VerifyResult(False, n, "last hash does not match the expected anchor", None, prev)
    return VerifyResult(True, n, None, None, prev if seq else None)
