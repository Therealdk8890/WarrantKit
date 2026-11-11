"""Public synchronous Warrant-to-ActionGateway execution boundary.

An accepted, signed Warrant is checked both before policy evaluation and
inside AgentContainment's controller-owned runtime lease callback.

This API models guarded local tool execution. The Python process containing
the agent must not itself be trusted as the security boundary, and external
side effects need independent downstream authorization/cancellation.
"""
from __future__ import annotations

from copy import deepcopy
import inspect
from typing import Callable, TypeVar

from agent_containment.models import Action, Decision
from .engine import Admission
from .integrations._authority import verify_current_authority


T = TypeVar("T")


class GuardedExecutionDenied(RuntimeError):
    """A protected side effect lacks current authority or gateway approval."""


class BoundGuardedExecution:
    """Bind an immutable admission snapshot to a controller-owned gateway.

    Construct this object when a protected operation is registered, not from
    mutable authority data supplied with an untrusted tool invocation.

    Only synchronous executor callbacks are supported. Warrant verification
    and the capability check are repeated within the runtime's guarded
    executor callback, after gateway policy evaluation. A Warrant is never
    converted to, or accepted as, an execution lease.
    """

    def __init__(self, admission: Admission, gateway, *, warrant_verifier):
        controller = getattr(admission.engine, "controller", None)
        if controller is None or getattr(gateway, "containment", None) is not controller:
            raise GuardedExecutionDenied(
                "gateway must be owned by the admitted runtime controller"
            )
        if warrant_verifier is None:
            raise GuardedExecutionDenied("trusted Warrant verifier is required")
        self._admission = admission
        self._gateway = gateway
        self._warrant_verifier = warrant_verifier
        self._expected_snapshot = (
            admission.identity,
            deepcopy(admission.policy),
            admission.warrant,
            deepcopy(admission.warrant_attestation),
        )

    def _verify(self, action: Action) -> None:
        verify_current_authority(
            self._admission,
            self._gateway,
            self._warrant_verifier,
            self._expected_snapshot,
            error_type=GuardedExecutionDenied,
            framework="guarded execution",
        )
        if action.agent_id != self._admission.identity.agent_id:
            raise GuardedExecutionDenied("action subject does not match admission")
        warrant = self._admission.warrant
        if warrant is None or action.operation not in warrant.authority.capabilities:
            raise GuardedExecutionDenied(
                f"Warrant does not grant capability '{action.operation}'"
            )

    def execute(self, action: Action, executor: Callable[[Action], T]) -> T:
        """Execute only when current signed authority and gateway lease agree.

        Raises GuardedExecutionDenied on failed authority or gateway checks.
        Exceptions raised by the executor itself propagate unchanged.
        """
        if not isinstance(action, Action):
            raise TypeError("action must be an AgentContainment Action")
        if not callable(executor):
            raise TypeError("executor must be callable")
        if inspect.iscoroutinefunction(executor):
            raise TypeError("async executors are unsupported by guarded execution")

        # Obtain the lease *before* verifying Warrant authority. Containment
        # and recovery must not let an old check reuse a newly minted lease.
        lease = self._gateway.acquire_lease()
        if lease is None:
            raise GuardedExecutionDenied("runtime execution lease unavailable")
        self._verify(action)

        sentinel = object()

        def guarded_callback(approved_action: Action):
            # This runs inside Runtime.execute_if_active's fence lock.
            # It closes the expiry/revocation race introduced by the gateway's
            # policy evaluation and preserves the exact lease used at entry.
            self._verify(approved_action)
            output = executor(approved_action)
            if inspect.isawaitable(output):
                if inspect.iscoroutine(output):
                    output.close()
                raise GuardedExecutionDenied(
                    "async/awaitable executor results are unsupported"
                )
            return (sentinel, output)

        result = self._gateway.execute_with_lease(action, lease, guarded_callback)
        if isinstance(result, tuple) and len(result) == 2 and result[0] is sentinel:
            return result[1]
        if isinstance(result, Decision):
            raise GuardedExecutionDenied(
                f"AgentContainment denied '{action.operation}': {result.reason}"
            )
        raise GuardedExecutionDenied(
            "gateway did not return an authenticated executor result"
        )
