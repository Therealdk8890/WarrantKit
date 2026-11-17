"""Framework-neutral guarded execution shared by synchronous tool adapters.

The same controller-owned lease is used for preflight and the guarded callback.
Authority and capability are verified again inside the callback, after gateway
policy evaluation. Framework adapters own their public APIs and tool schemas.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any, Callable, Type
from uuid import uuid4

from ..engine import Admission
from ._authority import verify_current_capability


def snapshot_authority(admission: Admission) -> tuple:
    """Pin the admitted authority; later mutation must fail closed."""
    return (
        admission.identity,
        deepcopy(admission.policy),
        admission.warrant,
        deepcopy(admission.warrant_attestation),
    )


def execute_authorized(
    *,
    function: Callable[[], Any],
    admission: Admission,
    gateway: Any,
    warrant_verifier: Any,
    expected_snapshot: tuple,
    required_capability: str,
    operation: str,
    resource: str,
    risk: int,
    action_prefix: str,
    metadata_framework: str,
    framework: str,
    error_type: Type[RuntimeError],
) -> Any:
    """Execute one synchronous tool invocation with a pinned, guarded lease."""
    from agent_containment.models import Action, DecisionType

    execution_lease = gateway.acquire_lease()
    if execution_lease is None:
        raise error_type("runtime is not active; execution lease unavailable")

    # Capability verification includes full signed-Warrant, policy and runtime
    # snapshot verification. Repeat it inside the callback to close the
    # preflight-to-execution authority gap.
    verify_current_capability(
        admission, gateway, warrant_verifier, expected_snapshot,
        required_capability, error_type=error_type, framework=framework,
    )

    action = Action(
        agent_id=admission.identity.agent_id,
        action_id=f"{action_prefix}:{admission.identity.execution_id}:{uuid4()}",
        operation=operation,
        resource=resource,
        risk=risk,
        metadata={"framework": metadata_framework},
    )

    def guarded_callback(_action: Any) -> Any:
        verify_current_capability(
            admission, gateway, warrant_verifier, expected_snapshot,
            required_capability, error_type=error_type, framework=framework,
        )
        return function()

    result = gateway.execute_with_lease(
        action, execution_lease, guarded_callback,
    )
    if hasattr(result, "decision") and result.decision is not DecisionType.ALLOW:
        raise error_type(
            f"AgentContainment denied '{operation}': {result.reason}"
        )
    return result
