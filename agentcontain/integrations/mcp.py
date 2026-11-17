"""Raw MCP server integration for WarrantKit.

Wrap synchronous Python tool handlers before registering them with an MCP
server. MCP is a transport/schema layer, not the security boundary; the
controller-owned AgentContainment ActionGateway remains the final enforcement
point.
"""
from __future__ import annotations

from functools import wraps
import inspect
from typing import Any

from ..engine import Admission
from ._execution import execute_authorized, snapshot_authority


class MCPWarrantError(RuntimeError):
    """Raised when an MCP tool call is not authorized by WarrantKit."""


def wrap_mcp_tool(
    function,
    admission: Admission,
    gateway=None,
    *,
    warrant_verifier,
    capability: str | None = None,
    risk: int = 0,
    resource: str = "mcp-tool",
    name_override: str | None = None,
):
    """Wrap a synchronous MCP server handler with WarrantKit enforcement.

    Register the returned callable with the MCP server in place of the
    original handler. The MCP SDK remains optional because this adapter wraps
    the Python callable at the actual side-effect boundary.

    The capability defaults to name_override or the handler function name.
    The wrapper acquires a controller-owned lease before verifying the signed
    Warrant and passes that exact lease to ActionGateway.
    """
    if gateway is None:
        raise ValueError(
            "gateway is required; construct AgentContainment ActionGateway "
            "from the controller that owns the admitted runtime"
        )
    if not callable(function):
        raise TypeError("function must be a synchronous callable")
    if inspect.iscoroutinefunction(function):
        raise TypeError(
            "async MCP handlers are not supported by this adapter yet; "
            "use a synchronous handler or wait for async-native lease support"
        )
    if not 0 <= risk <= 100:
        raise ValueError("risk must be between 0 and 100")

    operation = name_override or getattr(function, "__name__", "mcp_tool")
    required_capability = capability or operation
    expected_snapshot = snapshot_authority(admission)

    @wraps(function)
    def invoke_authorized(*args: Any, **kwargs: Any) -> Any:
        return execute_authorized(
            function=lambda: function(*args, **kwargs),
            admission=admission,
            gateway=gateway,
            warrant_verifier=warrant_verifier,
            expected_snapshot=expected_snapshot,
            required_capability=required_capability,
            operation=operation,
            resource=resource,
            risk=risk,
            action_prefix="mcp",
            metadata_framework="mcp",
            framework="MCP",
            error_type=MCPWarrantError,
        )

    return invoke_authorized
