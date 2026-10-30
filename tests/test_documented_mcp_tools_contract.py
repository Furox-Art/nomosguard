"""The README's MCP tool list must match the tools the server ships.

A tool added or renamed in code has to show up in the component table, which
is what most readers see first. Both sides are parsed here, not restated, so
the test cannot agree with a stale copy of itself.
"""

from __future__ import annotations

import re
from pathlib import Path

from nomosguard.mcp_server import NomosGuardSession
from nomosguard.mcp_stdio import TOOLS

ROOT = Path(__file__).resolve().parents[1]


def _readme_component_line() -> str:
    for line in (ROOT / "README.md").read_text(encoding="utf-8").splitlines():
        if "`nomosguard.mcp_server`" in line:
            return line
    raise AssertionError("README has no nomosguard.mcp_server component row")


def test_readme_lists_exactly_the_registered_tools() -> None:
    line = _readme_component_line()
    assert "5 tools" in line
    documented = set(re.findall(r"`([a-z][a-z_]*)`", line.split("tools", 1)[1]))
    registered = {tool["name"] for tool in TOOLS}
    assert documented == registered


def test_every_registered_tool_resolves_to_a_session_method() -> None:
    missing = [
        tool["name"]
        for tool in TOOLS
        if not callable(getattr(NomosGuardSession, tool["name"], None))
    ]
    assert missing == []
