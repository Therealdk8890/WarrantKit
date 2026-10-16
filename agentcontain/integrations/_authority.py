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
    """Fail closed unless the wrapped tool still has the exact accepted authority.

    Framework adapters must share this implementation so signature, identity,
    epoch, policy-capability ceiling, and runtime snapshot checks cannot drift.
    The caller supplies only its framework-specific exception type and label.
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
    snapshot = runtime.snapshot()
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
