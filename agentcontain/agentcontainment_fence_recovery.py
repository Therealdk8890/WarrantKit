"""Read actual AgentContainment durable fence and incident registries.

Controller-owned file paths and integrity are trust assumptions. These JSON
registries use fsync + atomic rename, not cryptographic authentication.
The caller MUST enforce exclusive controller ownership and file permissions.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from .downstream_commit_fence import DownstreamDenied
from .downstream_outbox import DurableTransitionOutbox
from .downstream_reconciliation import DurableFenceRecord, reconcile_missing_fence
from .downstream_transition_delivery import TransitionEnvelope


def reconcile_agentcontainment_registries(
    *, agent_id: str, fence_path: str | Path, incident_path: str | Path,
    outbox: DurableTransitionOutbox,
    sign_transition: Callable[[str, int, bool], TransitionEnvelope],
) -> TransitionEnvelope:
    """Reconstruct a missing downstream fence from two persisted registries.

    The fence registry is prepared before containment and survives missing
    incident records. An incident record, if present, must agree and must not
    indicate recovery. If absent, the durable fence is still authoritative
    containment intent, NOT evidence that external enforcers succeeded.

    This does not authenticate arbitrary on-disk JSON against tampering.
    """
    # Imported lazily: the pinned production AgentContainment submodule may
    # predate the newer durable fence/incident registry APIs.
    from agent_containment.incident_state import IncidentRegistry, IncidentState
    from agent_containment.runtime_fence import RuntimeFenceRegistry

    fence_file = Path(fence_path)
    incident_file = Path(incident_path)
    if not fence_file.is_file():
        raise DownstreamDenied("durable runtime fence registry is unavailable")
    fences = RuntimeFenceRegistry(fence_file)
    if not fences.persistence_available:
        raise DownstreamDenied("durable runtime fence registry is unavailable")
    fence = fences.get(agent_id)
    if (fence is None or fence.agent_id != agent_id
            or type(fence.containment_epoch) is not int
            or fence.containment_epoch < 1):
        raise DownstreamDenied("no valid durable containment fence")
    if incident_file.is_file():
        incidents = IncidentRegistry(incident_file)
        record = incidents.latest_for_agent(agent_id)
        if record is not None:
            if (record.state not in (IncidentState.CONTAINED, IncidentState.PROOF_DEGRADED)
                    or type(record.containment_epoch) is not int
                    or record.containment_epoch != fence.containment_epoch):
                raise DownstreamDenied("incident record conflicts with durable fence")
    authoritative = DurableFenceRecord(
        agent_id=agent_id, epoch=fence.containment_epoch,
        state="contained", can_execute=False,
        record_id=f"runtime-fence:{agent_id}:{fence.containment_epoch}",
    )
    return reconcile_missing_fence(
        agent_id=agent_id, outbox=outbox,
        read_authoritative_record=lambda _agent: authoritative,
        verify_authoritative_record=lambda candidate: candidate == authoritative,
        sign_transition=sign_transition,
    )


def reconcile_authenticated_agentcontainment_registries(
    *, agent_id: str, fence_path: str | Path, incident_path: str | Path,
    outbox: DurableTransitionOutbox,
    sign_transition: Callable[[str, int, bool], TransitionEnvelope],
    verify_registry_snapshot: Callable[[Path, Path], bool],
) -> TransitionEnvelope:
    """Require an external trust decision before using registry state.

    The verifier must independently authenticate BOTH file identities and
    contents against a trusted checkpoint or equivalent protected source.
    It must not simply parse these files and compare them to themselves.
    This is a reference boundary, not a built-in signature implementation.
    """
    if verify_registry_snapshot(Path(fence_path), Path(incident_path)) is not True:
        raise DownstreamDenied("controller registry snapshot not authenticated")
    return reconcile_agentcontainment_registries(
        agent_id=agent_id, fence_path=fence_path, incident_path=incident_path,
        outbox=outbox, sign_transition=sign_transition,
    )


def require_verified_against_agentcontainment_fence(
    *, agent_id: str, epoch: int, fence_path: str | Path,
    outbox: DurableTransitionOutbox,
) -> None:
    """Cross-check downstream receipt against actual persisted runtime fence.

    A missing or malformed controller-owned fence fails closed. This is an
    independent-file rollback check, not cryptographic registry attestation.
    """
    from agent_containment.runtime_fence import RuntimeFenceRegistry

    fence_file = Path(fence_path)
    if not fence_file.is_file():
        raise DownstreamDenied("durable runtime fence registry is unavailable")

    def read_epoch(requested_agent: str) -> int:
        registry = RuntimeFenceRegistry(fence_file)
        record = registry.get(requested_agent)
        if record is None or type(record.containment_epoch) is not int:
            raise DownstreamDenied("independent runtime fence is missing or invalid")
        return record.containment_epoch

    outbox.require_verified_against_authority(agent_id, epoch, read_epoch)
