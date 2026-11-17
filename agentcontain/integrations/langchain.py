"""LangChain tool integration for WarrantKit.

The adapter places Warrant verification and AgentContainment's ActionGateway
around an existing LangChain tool. It does not make LangChain a security
boundary: the controller-owned gateway remains the final runtime enforcement
point.
"""
from __future__ import annotations

from typing import Any

from ..engine import Admission
from ._execution import execute_authorized, snapshot_authority
from ._authority import verify_current_authority


class LangChainWarrantError(RuntimeError):
    """Raised when a LangChain tool call is not authorized by WarrantKit."""


def _verify_current_authority(admission: Admission, gateway, warrant_verifier, expected_snapshot) -> None:
    """Compatibility hook still consumed by LangChain middleware."""
    verify_current_authority(
        admission, gateway, warrant_verifier, expected_snapshot,
        error_type=LangChainWarrantError, framework="LangChain",
    )


def wrap_langchain_tool(
    tool,
    admission: Admission,
    gateway=None,
    *,
    warrant_verifier,
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

    # Pin the exact accepted authority to this wrapper. A different but validly
    # signed Warrant for another execution must not be replayed by mutating the
    # public Admission object after the wrapper was created.
    expected_snapshot = snapshot_authority(admission)

    operation = str(tool.name)
    required_capability = capability or operation

    def invoke_authorized(**kwargs: Any) -> Any:
        return execute_authorized(
            function=lambda: tool.invoke(kwargs),
            admission=admission,
            gateway=gateway,
            warrant_verifier=warrant_verifier,
            expected_snapshot=expected_snapshot,
            required_capability=required_capability,
            operation=operation,
            resource=resource,
            risk=risk,
            action_prefix="langchain",
            metadata_framework="langchain",
            framework="LangChain",
            error_type=LangChainWarrantError,
        )

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
