"""Native LangChain middleware for WarrantKit authority enforcement.

The middleware intercepts LangChain tool execution at the framework's
wrap_tool_call boundary. LangChain remains outside the security boundary:
the controller-owned AgentContainment ActionGateway is still the final
runtime enforcement point.
"""
from __future__ import annotations

from typing import Any
from uuid import uuid4

from ..engine import Admission
from .langchain import LangChainWarrantError, _verify_current_authority


class WarrantKitMiddleware:
    """Protect LangChain tool calls with a Warrant and ActionGateway.

    This class intentionally implements LangChain's middleware hook contract
    without importing LangChain at module import time. It can therefore remain
    an optional integration. The object is suitable for create_agent(...,
    middleware=[...]) when LangChain >= 1.0 is installed.

    The capability defaults to the tool name. A mapping can override that
    default for tools whose operation name differs from the Warrant capability.
    """

    def __init__(
        self,
        admission: Admission,
        gateway,
        *,
        capabilities: dict[str, str] | None = None,
        risk: int = 0,
        resource: str = "langchain-tool",
    ) -> None:
        if gateway is None:
            raise ValueError(
                "gateway is required; construct AgentContainment ActionGateway "
                "from the controller that owns the admitted runtime"
            )
        if not 0 <= risk <= 100:
            raise ValueError("risk must be between 0 and 100")
        self.admission = admission
        self.gateway = gateway
        self.capabilities = dict(capabilities or {})
        self.risk = risk
        self.resource = resource

    def wrap_tool_call(self, request: Any, handler: Any) -> Any:
        """Verify and enforce one LangChain tool call before its handler runs."""
        operation = str(request.tool.name)
        _verify_current_authority(self.admission, self.gateway)

        warrant = self.admission.warrant
        assert warrant is not None
        required_capability = self.capabilities.get(operation, operation)
        if required_capability not in warrant.authority.capabilities:
            raise LangChainWarrantError(
                f"Warrant does not grant capability '{required_capability}'"
            )

        from agent_containment.models import Action, DecisionType

        action = Action(
            agent_id=self.admission.identity.agent_id,
            action_id=f"langchain:{self.admission.identity.execution_id}:{uuid4()}",
            operation=operation,
            resource=self.resource,
            risk=self.risk,
            metadata={"framework": "langchain", "integration": "middleware"},
        )
        result = self.gateway.execute(
            action,
            lambda _action: handler(request),
        )
        if hasattr(result, "decision") and result.decision is not DecisionType.ALLOW:
            raise LangChainWarrantError(
                f"AgentContainment denied '{operation}': {result.reason}"
            )
        return result


def warrantkit_middleware(
    admission: Admission,
    gateway,
    *,
    capabilities: dict[str, str] | None = None,
    risk: int = 0,
    resource: str = "langchain-tool",
):
    """Return WarrantKit's native LangChain middleware object.

    The helper keeps application code concise while preserving the explicit
    admission and controller-owned gateway dependency.
    """
    try:
        from langchain.agents.middleware import AgentMiddleware
    except ImportError as exc:
        raise RuntimeError(
            "LangChain is not installed; install WarrantKit with the langchain extra"
        ) from exc

    protected = WarrantKitMiddleware(
        admission,
        gateway,
        capabilities=capabilities,
        risk=risk,
        resource=resource,
    )

    class _WarrantKitLangChainMiddleware(AgentMiddleware):
        name: str = "WarrantKit"

        def wrap_tool_call(self, request, handler):
            return protected.wrap_tool_call(request, handler)

    return _WarrantKitLangChainMiddleware()
