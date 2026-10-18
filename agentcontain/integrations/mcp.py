"""Raw MCP server integration for WarrantKit.

Wrap synchronous Python tool handlers before registering them with an MCP
server. MCP is a transport/schema layer, not the security boundary; the
controller-owned AgentContainment ActionGateway remains the final enforcement
point.
"""
from __future__ import annotations

from copy import deepcopy
from functools import wraps
import inspect
from typing import Any
from uuid import uuid4

from ..engine import Admission
from ._authority import verify_current_authority


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
    expected_snapshot = (
        admission.identity,
        deepcopy(admission.policy),
        admission.warrant,
        deepcopy(admission.warrant_attestation),
    )

    @wraps(function)
    def invoke_authorized(*args: Any, **kwargs: Any) -> Any:
        execution_lease = gateway.acquire_lease()
        if execution_lease is None:
            raise MCPWarrantError(
                "runtime is not active; execution lease unavailable"
            )

        verify_current_authority(
            admission,
            gateway,
            warrant_verifier,
            expected_snapshot,
            error_type=MCPWarrantError,
            framework="MCP",
        )

        warrant = admission.warrant
        if warrant is None:
            raise MCPWarrantError("execution has no Warrant authority")
        if required_capability not in warrant.authority.capabilities:
            raise MCPWarrantError(
                f"Warrant does not grant capability '{required_capability}'"
            )

        from agent_containment.models import Action, DecisionType

        action = Action(
            agent_id=admission.identity.agent_id,
            action_id=f"mcp:{admission.identity.execution_id}:{uuid4()}",
            operation=operation,
            resource=resource,
            risk=risk,
            metadata={"framework": "mcp"},
        )
        result = gateway.execute_with_lease(
            action,
            execution_lease,
            lambda _action: function(*args, **kwargs),
        )
        if hasattr(result, "decision") and result.decision is not DecisionType.ALLOW:
            raise MCPWarrantError(
                f"AgentContainment denied '{operation}': {result.reason}"
            )
        return result

    return invoke_authorized
