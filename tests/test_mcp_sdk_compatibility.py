"""Exercise real MCP SDK registration and dispatch, not only direct wrappers."""

import asyncio

import pytest
from mcp.server.fastmcp import FastMCP

from agentcontain import contain
from agentcontain.integrations.mcp import wrap_mcp_tool
from test_mcp_integration import _setup


@pytest.mark.parametrize("authorized", [True, False])
def test_sdk_dispatch_preserves_authority(authorized: bool) -> None:
    calls: list[str] = []

    def write_record(value: str) -> str:
        calls.append(value)
        return value

    _, admission, gateway, verifier = _setup(
        "sdk-allow" if authorized else "sdk-deny",
        "write_record" if authorized else "read_only",
    )
    server = FastMCP("warrantkit-compatibility")
    server.add_tool(
        wrap_mcp_tool(write_record, admission, gateway, warrant_verifier=verifier)
    )
    if authorized:
        asyncio.run(server.call_tool("write_record", {"value": "allowed"}))
        assert calls == ["allowed"]
        contain(admission)
    with pytest.raises(Exception):
        asyncio.run(server.call_tool("write_record", {"value": "denied"}))
    assert calls == (["allowed"] if authorized else [])
