"""Built-in protected-tool adapters."""

from ..tools import Tool
from .calculator import calculator_tool
from .filesystem import file_read_tool, file_write_tool
from .http_fetch import http_fetch_tool

__all__ = ["builtin_tools", "calculator_tool", "file_read_tool", "file_write_tool", "http_fetch_tool"]


def builtin_tools() -> dict[str, Tool]:
    """Fresh instances of every built-in tool, keyed by tool name."""
    tools = [calculator_tool(), file_read_tool(), file_write_tool(), http_fetch_tool()]
    return {t.name: t for t in tools}
