"""CrewAI tool integration for WarrantKit.

The adapter places Warrant verification and AgentContainment's ActionGateway
around an existing CrewAI tool. CrewAI remains outside the security boundary:
the controller-owned gateway is the final runtime enforcement point.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any
from uuid import uuid4

from ..engine import Admission
from ._authority import verify_current_authority


class CrewAIWarrantError(RuntimeError):
    """Raised when a CrewAI tool call is not authorized by WarrantKit."""


def _verify_current_authority(admission: Admission, gateway, warrant_verifier, expected_snapshot) -> None:
    verify_current_authority(
        admission,
        gateway,
        warrant_verifier,
        expected_snapshot,
        error_type=CrewAIWarrantError,
        framework="CrewAI",
    )


def wrap_crewai_tool(
    tool,
    admission: Admission,
    gateway=None,
    *,
    warrant_verifier,
    capability: str | None = None,
    risk: int = 0,
    resource: str = "crewai-tool",
):
    """Wrap an existing CrewAI tool with WarrantKit authority.

    The capability defaults to the CrewAI tool name. The wrapped tool is
    executed only through AgentContainment's synchronous ActionGateway lease.
    Async-native execution is deliberately not claimed by this integration.
    """
    if gateway is None:
        raise ValueError(
            "gateway is required; construct AgentContainment ActionGateway "
            "from the controller that owns the admitted runtime"
        )
    if not 0 <= risk <= 100:
        raise ValueError("risk must be between 0 and 100")

    try:
        from crewai.tools import BaseTool
    except ImportError as exc:
        raise RuntimeError(
            "CrewAI is not installed; install WarrantKit with the crewai extra"
        ) from exc

    if not isinstance(tool, BaseTool):
        raise TypeError("wrap_crewai_tool expects a CrewAI BaseTool instance")

    # Pin this wrapper to the authority accepted at construction time; a
    # different signed Warrant must not be replayed through mutable Admission.
    expected_snapshot = (
        admission.identity,
        deepcopy(admission.policy),
        admission.warrant,
        deepcopy(admission.warrant_attestation),
    )

    operation = str(tool.name)
    required_capability = capability or operation
    original_args_schema = getattr(tool, "args_schema", None)
    original_description = getattr(tool, "description", None)

    def invoke_authorized(**kwargs: Any) -> Any:
        _verify_current_authority(admission, gateway, warrant_verifier, expected_snapshot)
        warrant = admission.warrant
        assert warrant is not None
        if required_capability not in warrant.authority.capabilities:
            raise CrewAIWarrantError(
                f"Warrant does not grant capability '{required_capability}'"
            )

        from agent_containment.models import Action, DecisionType

        action = Action(
            agent_id=admission.identity.agent_id,
            action_id=f"crewai:{admission.identity.execution_id}:{uuid4()}",
            operation=operation,
            resource=resource,
            risk=risk,
            metadata={"framework": "crewai"},
        )
        result = gateway.execute(
            action,
            lambda _action: tool.run(**kwargs),
        )
        if hasattr(result, "decision") and result.decision is not DecisionType.ALLOW:
            raise CrewAIWarrantError(
                f"AgentContainment denied '{operation}': {result.reason}"
            )
        return result

    from pydantic import BaseModel

    class ProtectedCrewAITool(BaseTool):
        name: str = operation
        description: str = (
            original_description or f"WarrantKit-protected {operation}"
        )
        args_schema: type[BaseModel] | None = original_args_schema

        def _run(self, *args: Any, **kwargs: Any) -> Any:
            if args:
                raise CrewAIWarrantError("positional CrewAI tool arguments are not supported")
            return invoke_authorized(**kwargs)

    return ProtectedCrewAITool()
