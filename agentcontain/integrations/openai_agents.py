"""OpenAI Agents SDK integration for WarrantKit.

Wrap synchronous Python function tools so Warrant authority is checked before
the tool call and the actual side effect runs inside AgentContainment's
controller-owned ActionGateway lease. Async-native tool execution is not
claimed by this adapter.
"""
from __future__ import annotations

from functools import wraps
import inspect
from typing import Any

from ..engine import Admission
from ._execution import execute_authorized, snapshot_authority


class OpenAIAgentsWarrantError(RuntimeError):
    """Raised when an OpenAI Agents SDK tool call is not authorized."""


def wrap_openai_tool(
    function,
    admission: Admission,
    gateway=None,
    *,
    warrant_verifier,
    capability: str | None = None,
    risk: int = 0,
    resource: str = "openai-agents-tool",
    name_override: str | None = None,
    description_override: str | None = None,
):
    """Return an OpenAI Agents SDK FunctionTool protected by WarrantKit.

    Pass a synchronous Python function, an admitted execution, the
    AgentContainment ActionGateway owned by that execution's controller, and
    an Ed25519 verifier anchored to a deployment-configured public key.

    The tool's capability defaults to its exposed tool name. The original
    function is called only inside ActionGateway.execute, so the controller-
    owned execution lease covers the synchronous side effect.
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
            "async functions are not supported by this adapter yet; "
            "use a synchronous tool or wait for async-native lease support"
        )
    if not 0 <= risk <= 100:
        raise ValueError("risk must be between 0 and 100")

    try:
        from agents import function_tool
    except ImportError as exc:
        raise RuntimeError(
            "OpenAI Agents SDK is not installed; install WarrantKit with "
            'the "openai-agents" extra'
        ) from exc

    operation = name_override or getattr(function, "__name__", "openai_tool")
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
            action_prefix="openai-agents",
            metadata_framework="openai-agents-sdk",
            framework="OpenAI Agents",
            error_type=OpenAIAgentsWarrantError,
        )

    tool_options: dict[str, Any] = {"failure_error_function": None}
    if name_override is not None:
        tool_options["name_override"] = name_override
    if description_override is not None:
        tool_options["description_override"] = description_override
    return function_tool(invoke_authorized, **tool_options)
