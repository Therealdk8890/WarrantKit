"""Shared framework-neutral verification for WarrantKit tool adapters."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Type

from ..engine import Admission
from ..warrant import verify_warrant


def verify_current_authority(
    admission: Admission,
    gateway,
    warrant_verifier,
    expected_snapshot,
    *,
    error_type: Type[RuntimeError],
    framework: str,
) -> None:
    """Fail closed unless the wrapped tool has the exact accepted authority.

    Framework adapters must share this implementation so signature, identity,
    epoch, policy-capability ceiling, and runtime snapshot checks cannot drift.
    The runtime snapshot, not the platform's cached ExecutionIdentity, is the
    authority for whether the Warrant's epoch remains current.
    """
    def reject(message: str, cause: Exception | None = None) -> None:
        error = error_type(message)
        if cause is None:
            raise error
        raise error from cause

    warrant = admission.warrant
    if warrant is None:
        reject("execution has no Warrant authority")
    if warrant_verifier is None:
        reject("a trusted Ed25519 Warrant verifier is required")
    if admission.warrant_attestation is None:
        reject("execution has no signed Warrant attestation; issue with warrant_signer")

    try:
        admission.policy.validate()
    except (TypeError, ValueError) as exc:
        reject(f"accepted policy bundle verification failed: {exc}", exc)
    if (
        admission.policy.policy_id != admission.identity.policy_id
        or admission.policy.policy_digest != admission.identity.policy_digest
    ):
        reject("accepted policy identity does not match execution")

    expected_identity, expected_policy, expected_warrant, expected_attestation = expected_snapshot
    if (
        admission.identity != expected_identity
        or admission.policy != expected_policy
        or warrant != expected_warrant
        or admission.warrant_attestation != expected_attestation
    ):
        reject("admission authority changed after the protected tool was wrapped")

    try:
        signed_warrant = warrant_verifier.verify_warrant(admission.warrant_attestation)
    except (TypeError, ValueError) as exc:
        reject(f"Warrant signature verification failed: {exc}", exc)
    if signed_warrant != warrant:
        reject("signed Warrant payload does not match the active Warrant")

    runtime = getattr(gateway, "containment", None)
    runtime = getattr(runtime, "runtime", None)
    if runtime is None:
        reject(
            f"WarrantKit {framework} integration requires an AgentContainment ActionGateway"
        )

    # Take one atomic snapshot from the runtime owner immediately before the
    # protected action. Never use admission.identity.epoch as the freshness
    # source: it can remain stale if the controller crashes after fencing.
    snapshot = runtime.snapshot()
    if snapshot.runtime_id != warrant.runtime.runtime_id:
        reject("runtime snapshot runtime_id does not match Warrant")
    if snapshot.agent_id != warrant.subject.agent_id:
        reject("runtime snapshot agent_id does not match Warrant")
    state = getattr(snapshot.state, "value", snapshot.state)
    if state != "active" or snapshot.can_execute is not True:
        reject("runtime is not active; Warrant authority is denied")

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
    except (TypeError, ValueError) as exc:
        reject(f"Warrant verification failed: {exc}", exc)

    accepted_capabilities = set(admission.policy.policy.capabilities)
    if not set(warrant.authority.capabilities).issubset(accepted_capabilities):
        reject("Warrant capabilities exceed the accepted policy")
