"""CrewAI tool integration for WarrantKit.

The adapter places Warrant verification and AgentContainment's ActionGateway
around an existing CrewAI tool. CrewAI remains outside the security boundary:
the controller-owned gateway is the final runtime enforcement point.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from ..engine import Admission
from ..warrant import RevocationState, verify_warrant


class CrewAIWarrantError(RuntimeError):
    """Raised when a CrewAI tool call is not authorized by WarrantKit."""


def _current_runtime(admission: Admission, gateway):
    runtime = getattr(gateway, "containment", None)
    runtime = getattr(runtime, "runtime", None)
    if runtime is None:
        raise CrewAIWarrantError(
            "WarrantKit CrewAI integration requires an AgentContainment ActionGateway"
        )
    return runtime


def _verify_current_authority(admission: Admission, gateway, warrant_verifier, expected_snapshot) -> None:
    warrant = admission.warrant
    if warrant is None:
        raise CrewAIWarrantError("execution has no Warrant authority")
    if warrant_verifier is None:
        raise CrewAIWarrantError("a trusted Ed25519 Warrant verifier is required")
    if admission.warrant_attestation is None:
        raise CrewAIWarrantError("execution has no signed Warrant attestation; issue with warrant_signer")
    expected_identity, expected_policy, expected_warrant, expected_attestation = expected_snapshot
    if (
        admission.identity != expected_identity
        or admission.policy != expected_policy
        or admission.warrant != expected_warrant
        or admission.warrant_attestation != expected_attestation
    ):
        raise CrewAIWarrantError(
            "admission authority changed after the protected tool was wrapped"
        )
    try:
        signed_warrant = warrant_verifier.verify_warrant(admission.warrant_attestation)
    except (TypeError, ValueError) as exc:
        raise CrewAIWarrantError(f"Warrant signature verification failed: {exc}") from exc
    if signed_warrant != warrant:
        raise CrewAIWarrantError("signed Warrant payload does not match the active Warrant")
    snapshot = _current_runtime(admission, gateway).snapshot()
    try:
        verify_warrant(
            warrant,
            execution_id=admission.identity.execution_id,
            agent_id=admission.identity.agent_id,
            policy_id=admission.identity.policy_id,
            policy_digest=admission.identity.policy_digest,
            runtime_id=snapshot.runtime_id,
            epoch=snapshot.epoch,
            now=datetime.now(timezone.utc),
        )
    except ValueError as exc:
        raise CrewAIWarrantError(f"Warrant verification failed: {exc}") from exc
    if warrant.lifecycle.state is RevocationState.REVOKED:
        raise CrewAIWarrantError("Warrant is revoked")


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
