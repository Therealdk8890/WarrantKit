"""Exercise SDK registration and dispatch across MCP major versions."""

import asyncio
from importlib import import_module, metadata

import pytest
from test_mcp_integration import _setup

from agentcontain import contain
from agentcontain.integrations.mcp import MCPWarrantError, wrap_mcp_tool


@pytest.mark.parametrize("authorized", [True, False])
def test_sdk_dispatch_preserves_authority(authorized: bool) -> None:
    pytest.importorskip("mcp")
    major = metadata.version("mcp").split(".")[0]
    calls: list[str] = []

    def write_record(value: str) -> str:
        calls.append(value)
        return value

    _, admission, gateway, verifier = _setup(
        "sdk-allow" if authorized else "sdk-deny",
        "write_record" if authorized else "read_only",
    )
    if major == "1":
        server = import_module("mcp.server.fastmcp").FastMCP("warrantkit")
    else:
        assert major == "2"
        server = import_module("mcp.server.mcpserver").MCPServer("warrantkit")

    server.add_tool(
        wrap_mcp_tool(write_record, admission, gateway, warrant_verifier=verifier)
    )
    if authorized:
        result = asyncio.run(server.call_tool("write_record", {"value": "allowed"}))
        if major == "2":
            assert not result.is_error
        assert calls == ["allowed"]
        contain(admission)

    for _ in range(2):
        if major == "1":
            error = import_module("mcp.server.fastmcp.exceptions").ToolError
            with pytest.raises(error):
                asyncio.run(server.call_tool("write_record", {"value": "denied"}))
        else:
            error = import_module("mcp.server.mcpserver.exceptions").UnexpectedToolError
            with pytest.raises(error) as denied:
                asyncio.run(server.call_tool("write_record", {"value": "denied"}))
            assert isinstance(denied.value.__cause__, MCPWarrantError)
        assert calls == (["allowed"] if authorized else [])
