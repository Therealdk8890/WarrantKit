"""LangChain tool integration for WarrantKit.

The adapter places Warrant verification and AgentContainment's ActionGateway
around an existing LangChain tool. It does not make LangChain a security
boundary: the controller-owned gateway remains the final runtime enforcement
point.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..engine import Admission
from ..warrant import RevocationState, verify_warrant


class LangChainWarrantError(RuntimeError):
    """Raised when a LangChain tool call is not authorized by WarrantKit."""


def _current_runtime(admission: Admission, gateway):
    runtime = getattr(gateway, "containment", None)
    runtime = getattr(runtime, "runtime", None)
    if runtime is None:
        raise LangChainWarrantError(
            "WarrantKit LangChain integration requires an AgentContainment ActionGateway"
        )
    return runtime


def _verify_current_authority(admission: Admission, gateway) -> None:
    warrant = admission.warrant
    if warrant is None:
        raise LangChainWarrantError("execution has no Warrant authority")
    runtime = _current_runtime(admission, gateway)
    snapshot = runtime.snapshot()
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
    if warrant.lifecycle.state is RevocationState.REVOKED:
        raise LangChainWarrantError("Warrant is revoked")


def wrap_langchain_tool(
    tool,
    admission: Admission,
    gateway=None,
    *,
    capability: str | None = None,
    risk: int = 0,
    resource: str = "langchain-tool",
):
    """Wrap a LangChain tool with WarrantKit authority and runtime enforcement.

    The capability defaults to the LangChain tool name. The execution Warrant
    must therefore explicitly authorize the tool operation. The underlying
    LangChain tool is executed only inside AgentContainment's synchronous
    ActionGateway lease boundary.

    The wrapper deliberately uses the tool's synchronous invoke path. This
    keeps the runtime lease and the actual tool side effect in the same
    controller-owned execution boundary. Async-native tool execution is not
    claimed by this first integration.
    """
    if gateway is None:
        raise ValueError(
            "gateway is required; construct AgentContainment ActionGateway "
            "from the controller that owns the admitted runtime"
        )
    if not 0 <= risk <= 100:
        raise ValueError("risk must be between 0 and 100")

    try:
        from langchain_core.tools import StructuredTool
    except ImportError as exc:
        raise RuntimeError(
            "LangChain is not installed; install WarrantKit with the langchain extra"
        ) from exc

    operation = str(tool.name)
    required_capability = capability or operation

    def invoke_authorized(**kwargs: Any) -> Any:
        _verify_current_authority(admission, gateway)
        warrant = admission.warrant
        assert warrant is not None
        if required_capability not in warrant.authority.capabilities:
            raise LangChainWarrantError(
                f"Warrant does not grant capability '{required_capability}'"
            )

        from agent_containment.models import Action, DecisionType

        action = Action(
            agent_id=admission.identity.agent_id,
            action_id=f"langchain:{admission.identity.execution_id}:{operation}",
            operation=operation,
            resource=resource,
            risk=risk,
            metadata={"framework": "langchain"},
        )
        result = gateway.execute(
            action,
            lambda _action: tool.invoke(kwargs),
        )
        if hasattr(result, "decision") and result.decision is not DecisionType.ALLOW:
            raise LangChainWarrantError(
                f"AgentContainment denied '{operation}': {result.reason}"
            )
        return result

    args_schema = getattr(tool, "args_schema", None)
    if args_schema is None:
        args_schema = getattr(tool, "args", None)

    return StructuredTool.from_function(
        func=invoke_authorized,
        name=operation,
        description=getattr(tool, "description", None) or f"WarrantKit-protected {operation}",
        args_schema=args_schema,
        infer_schema=args_schema is None,
    )
