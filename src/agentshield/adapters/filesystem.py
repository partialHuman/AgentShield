"""Filesystem tools confined to configured roots.

POSIX: every path component is opened with ``O_NOFOLLOW`` relative to the
previous directory file descriptor, starting from the (trusted, pre-resolved)
root. No symlink is ever followed beneath a root, and there is no
check-then-use gap on path strings. Hard-linked files are refused.

Windows: best effort. Reparse points (symlinks, junctions) are denied, and
alternate data streams, reserved device names and absolute/drive paths are
rejected, but a check-then-use window remains. See docs/threat-model.md.
"""

from __future__ import annotations

import errno
import hashlib
import os
import stat
from collections.abc import Callable, Sequence
from typing import Any

from ..constraints import FS_READ_CONSTRAINTS, FS_WRITE_CONSTRAINTS
from ..models import ExecutionError, Reason
from ..normalize import ArgSpec, truncate
from ..policy import ToolPolicy
from ..tools import CheckOutcome, Tool

_IS_POSIX = os.name == "posix"
_WIN_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
_WIN_BAD_CHARS = set('<>:"|?*')
_MAX_COMPONENT = 255


class PathProblem(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(detail or code)
        self.code = code


def windows_component_error(comp: str) -> str | None:
    """Return a reason if ``comp`` is unsafe as a Windows path component (pure; testable anywhere)."""
    if any(c in _WIN_BAD_CHARS for c in comp):
        return "forbidden character (drive letter, stream or wildcard)"
    if comp != comp.rstrip(" .") and comp not in (".", ".."):
        return "trailing dot or space"
    if comp.split(".")[0].lower().rstrip(" ") in _WIN_RESERVED:
        return "reserved device name"
    if "~" in comp and comp.split("~")[-1][:1].isdigit():
        return "possible 8.3 short name"
    return None


def split_path(path: str, *, windows: bool = False) -> tuple[bool, list[str]]:
    """Lexically split into (is_absolute, components). Rejects '..' outright."""
    if "\x00" in path or not path:
        raise PathProblem(Reason.PATH_INVALID, "empty or NUL path")
    if len(path) > 4096:
        raise PathProblem(Reason.PATH_INVALID, "path too long")
    if windows:
        if path.startswith(("\\\\", "//")) or (len(path) >= 2 and path[1] == ":"):
            raise PathProblem(Reason.PATH_OUTSIDE_ROOT, "UNC or drive paths are not accepted")
        norm = path.replace("\\", "/")
        absolute = norm.startswith("/")
    else:
        norm = path
        absolute = path.startswith("/")
    if norm.endswith("/"):
        raise PathProblem(Reason.PATH_INVALID, "path must name a file, not a directory")
    comps: list[str] = []
    for part in norm.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            raise PathProblem(Reason.PATH_TRAVERSAL, "'..' is not allowed")
        if len(part) > _MAX_COMPONENT:
            raise PathProblem(Reason.PATH_INVALID, "path component too long")
        if windows:
            bad = windows_component_error(part)
            if bad:
                raise PathProblem(Reason.PATH_INVALID, f"unsafe component: {bad}")
        comps.append(part)
    if not comps:
        raise PathProblem(Reason.PATH_INVALID, "path has no file name")
    return absolute, comps


def resolve_in_roots(path: str, roots: Sequence[str], *, windows: bool | None = None) -> tuple[str, list[str]]:
    """Map ``path`` to (root, components-below-root). Relative paths use the first root."""
    win = (os.name == "nt") if windows is None else windows
    absolute, comps = split_path(path, windows=win)
    if not absolute:
        return roots[0], comps
    if win:
        raise PathProblem(Reason.PATH_OUTSIDE_ROOT, "absolute paths are not accepted on Windows")
    for root in roots:
        root_parts = [p for p in root.split("/") if p]
        if comps[: len(root_parts)] == root_parts and len(comps) > len(root_parts):
            return root, comps[len(root_parts):]
    raise PathProblem(Reason.PATH_OUTSIDE_ROOT, "path is outside every allowed root")


# ------------------------------------------------------------------ POSIX no-follow walk
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


def _classify_open_error(name: str, dir_fd: int, exc: OSError) -> ExecutionError:
    if exc.errno in (errno.ELOOP, errno.ENOTDIR, errno.EMLINK):
        try:
            if stat.S_ISLNK(os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mode):
                return ExecutionError(Reason.PATH_SYMLINK, "symlink in path")
        except OSError:
            pass
        return ExecutionError("NOT_A_DIRECTORY")
    if exc.errno == errno.ENOENT:
        return ExecutionError("NOT_FOUND")
    if exc.errno == errno.EEXIST:
        return ExecutionError("FILE_EXISTS")
    if exc.errno in (errno.EACCES, errno.EPERM):
        return ExecutionError("PERMISSION_DENIED")
    return ExecutionError("IO_ERROR", errno.errorcode.get(exc.errno or 0, "?"))


def _open_dir_beneath(root: str, dirs: Sequence[str]) -> int:
    try:
        fd = os.open(root, os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC)
    except OSError as exc:
        raise ExecutionError("ROOT_UNAVAILABLE", errno.errorcode.get(exc.errno or 0, "?")) from None
    try:
        for name in dirs:
            try:
                nfd = os.open(name, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC, dir_fd=fd)
            except OSError as exc:
                raise _classify_open_error(name, fd, exc) from None
            os.close(fd)
            fd = nfd
        return fd
    except BaseException:
        os.close(fd)
        raise


def probe_posix(root: str, parts: Sequence[str]) -> str | None:
    """Decision-time check (advisory): return PATH_SYMLINK if the existing path contains a symlink."""
    try:
        fd = _open_dir_beneath(root, parts[:-1])
    except ExecutionError as exc:
        return exc.code if exc.code == Reason.PATH_SYMLINK else None
    try:
        st = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
        if stat.S_ISLNK(st.st_mode):
            return Reason.PATH_SYMLINK
    except OSError:
        pass
    finally:
        os.close(fd)
    return None


def _read_posix(root: str, parts: Sequence[str], max_bytes: int) -> bytes:
    dfd = _open_dir_beneath(root, parts[:-1])
    try:
        try:
            fd = os.open(parts[-1], os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_CLOEXEC, dir_fd=dfd)
        except OSError as exc:
            raise _classify_open_error(parts[-1], dfd, exc) from None
    finally:
        os.close(dfd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ExecutionError("NOT_REGULAR_FILE")
        if st.st_nlink > 1:
            raise ExecutionError("HARDLINK_NOT_ALLOWED")
        if st.st_size > max_bytes:
            raise ExecutionError("FILE_TOO_LARGE")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, max_bytes + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ExecutionError("FILE_TOO_LARGE")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _write_posix(root: str, parts: Sequence[str], data: bytes, overwrite: bool) -> int:
    dfd = _open_dir_beneath(root, parts[:-1])
    try:
        flags = os.O_WRONLY | os.O_CREAT | _O_NOFOLLOW | _O_NONBLOCK | _O_CLOEXEC
        if not overwrite:
            flags |= os.O_EXCL
        try:
            fd = os.open(parts[-1], flags, 0o600, dir_fd=dfd)
        except OSError as exc:
            raise _classify_open_error(parts[-1], dfd, exc) from None
    finally:
        os.close(dfd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ExecutionError("NOT_REGULAR_FILE")
        if st.st_nlink > 1:
            raise ExecutionError("HARDLINK_NOT_ALLOWED")
        if overwrite:
            os.ftruncate(fd, 0)
        view, written = memoryview(data), 0
        while written < len(data):
            written += os.write(fd, view[written:])
        return written
    finally:
        os.close(fd)


# ------------------------------------------------------------------ Windows best effort
def probe_windows(root: str, parts: Sequence[str]) -> str | None:
    """Decision-time check (advisory) on Windows: return PATH_SYMLINK if the path contains a reparse point or symlink."""
    cur = root
    for comp in parts:
        cur = os.path.join(cur, comp)
        try:
            st = os.lstat(cur)
        except OSError:
            continue
        if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & 0x400:
            return Reason.PATH_SYMLINK
    return None


def _win_walk(root: str, parts: Sequence[str]) -> str:  # pragma: no cover - exercised on Windows CI only
    cur = root
    for comp in parts:
        cur = os.path.join(cur, comp)
        try:
            st = os.lstat(cur)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & 0x400:
            raise ExecutionError(Reason.PATH_SYMLINK, "reparse point in path")
    return cur


# ------------------------------------------------------------------ tool plumbing
def _make_checker(kind: str) -> Callable[[dict[str, Any], ToolPolicy], CheckOutcome]:
    def check(args: dict[str, Any], tp: ToolPolicy) -> CheckOutcome:
        roots: Sequence[str] = tp.constraints["allowed_roots"]
        trace: list[str] = []
        try:
            root, parts = resolve_in_roots(args["path"], roots)
        except PathProblem as exc:
            return CheckOutcome(None, (exc.code,), (f"path rejected: {exc}",))
        target = root.rstrip("/") + "/" + "/".join(parts) if _IS_POSIX else os.path.join(root, *parts)
        trace.append(f"path resolves beneath allowed root {root}")
        codes: list[str] = []
        if _IS_POSIX:
            if probe_posix(root, parts):
                codes.append(Reason.PATH_SYMLINK)
                trace.append("symlink found in existing path")
        else:
            if probe_windows(root, parts):
                codes.append(Reason.PATH_SYMLINK)
                trace.append("reparse point found in existing path")
        if kind == "write":
            limit = int(tp.constraints["max_bytes"])
            if len(args["content"].encode("utf-8")) > limit:
                codes.append(Reason.CONTENT_TOO_LARGE)
                trace.append(f"content larger than {limit} bytes")
        return CheckOutcome(target, tuple(codes), tuple(trace))

    return check


def _read_factory(tp: ToolPolicy) -> Callable[..., Any]:
    roots: Sequence[str] = tp.constraints["allowed_roots"]
    max_bytes = int(tp.constraints["max_bytes"])

    def read(path: str) -> dict[str, Any]:
        try:
            root, parts = resolve_in_roots(path, roots)  # re-derived at use time; never trust the check
        except PathProblem as exc:
            raise ExecutionError(exc.code) from None
        if _IS_POSIX:
            raw = _read_posix(root, parts, max_bytes)
        else:  # pragma: no cover
            full = _win_walk(root, parts)
            try:
                st = os.stat(full)
                if not stat.S_ISREG(st.st_mode):
                    raise ExecutionError("NOT_REGULAR_FILE")
                if st.st_nlink > 1:
                    raise ExecutionError("HARDLINK_NOT_ALLOWED")
            except FileNotFoundError:
                raise ExecutionError("NOT_FOUND") from None
            except OSError as exc:
                if exc.errno in (errno.EACCES, errno.EPERM):
                    raise ExecutionError("PERMISSION_DENIED") from None
                raise ExecutionError("IO_ERROR", errno.errorcode.get(exc.errno or 0, "?")) from None
            with open(full, "rb") as fh:
                raw = fh.read(max_bytes + 1)
            if len(raw) > max_bytes:
                raise ExecutionError("FILE_TOO_LARGE")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise ExecutionError("NOT_UTF8") from None
        return {"path": "/".join(parts), "size": len(raw), "content": text}

    return read


def _write_factory(tp: ToolPolicy) -> Callable[..., Any]:
    roots: Sequence[str] = tp.constraints["allowed_roots"]
    max_bytes = int(tp.constraints["max_bytes"])

    def write(path: str, content: str, overwrite: bool = False) -> dict[str, Any]:
        try:
            root, parts = resolve_in_roots(path, roots)
        except PathProblem as exc:
            raise ExecutionError(exc.code) from None
        data = content.encode("utf-8")
        if len(data) > max_bytes:
            raise ExecutionError(Reason.CONTENT_TOO_LARGE)
        if _IS_POSIX:
            n = _write_posix(root, parts, data, overwrite)
        else:  # pragma: no cover
            full = _win_walk(root, parts)
            try:
                st = os.stat(full)
                if not stat.S_ISREG(st.st_mode):
                    raise ExecutionError("NOT_REGULAR_FILE")
                if st.st_nlink > 1:
                    raise ExecutionError("HARDLINK_NOT_ALLOWED")
            except FileNotFoundError:
                pass
            try:
                with open(full, "wb" if overwrite else "xb") as fh:
                    n = fh.write(data)
            except FileExistsError:
                raise ExecutionError("FILE_EXISTS") from None
            except FileNotFoundError:
                raise ExecutionError("NOT_FOUND") from None
            except PermissionError:
                raise ExecutionError("NOT_REGULAR_FILE") from None
        return {"path": "/".join(parts), "bytes_written": n}

    return write


def file_read_tool() -> Tool:
    return Tool(
        name="filesystem.read",
        args={"path": ArgSpec("path")},
        executor_factory=_read_factory,
        checker=_make_checker("read"),
        constraint_schema=FS_READ_CONSTRAINTS,
        summarize=lambda a: {"path": truncate(a["path"], 200)},
    )


def file_write_tool() -> Tool:
    return Tool(
        name="filesystem.write",
        args={"path": ArgSpec("path"), "content": ArgSpec("text"), "overwrite": ArgSpec("bool", required=False, default=False)},
        executor_factory=_write_factory,
        checker=_make_checker("write"),
        constraint_schema=FS_WRITE_CONSTRAINTS,
        # allowlist redaction: never log file content, only its size and digest
        summarize=lambda a: {
            "path": truncate(a["path"], 200),
            "overwrite": bool(a.get("overwrite", False)),
            "content_bytes": len(a["content"].encode("utf-8")),
            "content_sha256": hashlib.sha256(a["content"].encode("utf-8")).hexdigest(),
        },
    )
