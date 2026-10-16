"""OpenAI Agents SDK integration for WarrantKit.

Wrap synchronous Python function tools so Warrant authority is checked before
the tool call and the actual side effect runs inside AgentContainment's
controller-owned ActionGateway lease. Async-native tool execution is not
claimed by this adapter.
"""
from __future__ import annotations

from copy import deepcopy
from functools import wraps
import inspect
from typing import Any
from uuid import uuid4

from ..engine import Admission
from ._authority import verify_current_authority


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
    expected_snapshot = (
        admission.identity,
        deepcopy(admission.policy),
        admission.warrant,
        deepcopy(admission.warrant_attestation),
    )

    @wraps(function)
    def invoke_authorized(*args: Any, **kwargs: Any) -> Any:
        verify_current_authority(
            admission,
            gateway,
            warrant_verifier,
            expected_snapshot,
            error_type=OpenAIAgentsWarrantError,
            framework="OpenAI Agents",
        )

        warrant = admission.warrant
        if warrant is None:
            raise OpenAIAgentsWarrantError("execution has no Warrant authority")
        if required_capability not in warrant.authority.capabilities:
            raise OpenAIAgentsWarrantError(
                f"Warrant does not grant capability '{required_capability}'"
            )

        from agent_containment.models import Action, DecisionType

        action = Action(
            agent_id=admission.identity.agent_id,
            action_id=f"openai-agents:{admission.identity.execution_id}:{uuid4()}",
            operation=operation,
            resource=resource,
            risk=risk,
            metadata={"framework": "openai-agents-sdk"},
        )
        result = gateway.execute(
            action,
            lambda _action: function(*args, **kwargs),
        )
        if hasattr(result, "decision") and result.decision is not DecisionType.ALLOW:
            raise OpenAIAgentsWarrantError(
                f"AgentContainment denied '{operation}': {result.reason}"
            )
        return result

    tool_options: dict[str, Any] = {"failure_error_function": None}
    if name_override is not None:
        tool_options["name_override"] = name_override
    if description_override is not None:
        tool_options["description_override"] = description_override
    return function_tool(invoke_authorized, **tool_options)
