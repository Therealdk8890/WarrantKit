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


def pinned_registry_snapshot_verifier(
    *, expected_fence_sha256: str, expected_incident_sha256: str | None,
) -> Callable[[Path, Path, bytes, bytes | None], bool]:
    """Compare captured bytes to digests supplied by a trusted external source.

    Digest strings MUST come from an independently protected checkpoint,
    never from the same mutable registry directory. This checks equality,
    not checkpoint authenticity or freshness.
    """
    import hashlib
    import hmac

    def valid_digest(value: object) -> bool:
        return (
            isinstance(value, str)
            and len(value) == 64
            and all(ch in "0123456789abcdef" for ch in value)
        )

    if not valid_digest(expected_fence_sha256):
        raise ValueError("invalid expected fence SHA-256 digest")
    if expected_incident_sha256 is not None and not valid_digest(expected_incident_sha256):
        raise ValueError("invalid expected incident SHA-256 digest")

    def verify(
        _fence_path: Path, _incident_path: Path,
        fence_bytes: bytes, incident_bytes: bytes | None,
    ) -> bool:
        if (incident_bytes is None) != (expected_incident_sha256 is None):
            return False
        if not hmac.compare_digest(
            hashlib.sha256(fence_bytes).hexdigest(), expected_fence_sha256
        ):
            return False
        return (
            incident_bytes is None
            or hmac.compare_digest(
                hashlib.sha256(incident_bytes).hexdigest(), expected_incident_sha256
            )
        )

    return verify


def reconcile_authenticated_agentcontainment_registries(
    *, agent_id: str, fence_path: str | Path, incident_path: str | Path,
    outbox: DurableTransitionOutbox,
    sign_transition: Callable[[str, int, bool], TransitionEnvelope],
    verify_registry_snapshot: Callable[[Path, Path, bytes, bytes | None], bool],
    minimum_trusted_epoch: int | None = None,
) -> TransitionEnvelope:
    """Authenticate captured bytes, then parse exactly those bytes.

    The verifier receives original file identities AND the exact bytes used
    for reconciliation. It must bind these to an independently protected
    checkpoint; merely returning True is not authentication.
    """
    import tempfile

    fence_file, incident_file = Path(fence_path), Path(incident_path)
    if not fence_file.is_file():
        raise DownstreamDenied("durable runtime fence registry is unavailable")
    fence_bytes = fence_file.read_bytes()
    incident_bytes = incident_file.read_bytes() if incident_file.is_file() else None
    if verify_registry_snapshot(
        fence_file, incident_file, fence_bytes, incident_bytes
    ) is not True:
        raise DownstreamDenied("controller registry snapshot not authenticated")

    if minimum_trusted_epoch is not None:
        if type(minimum_trusted_epoch) is not int or minimum_trusted_epoch < 1:
            raise DownstreamDenied("invalid trusted minimum containment epoch")
        # Read the captured snapshot, not the mutable original. The registry
        # parser below will validate its shape before any outbox enqueue.
        import json
        try:
            snapshot = json.loads(fence_bytes)
            records = snapshot["records"]
            if not isinstance(records, list):
                raise ValueError("invalid records")
            matching = [
                record["containment_epoch"] for record in records
                if isinstance(record, dict) and record.get("agent_id") == agent_id
            ]
            if len(matching) != 1 or type(matching[0]) is not int:
                raise ValueError("invalid agent epoch")
        except (ValueError, TypeError, KeyError, IndexError):
            raise DownstreamDenied("invalid captured controller fence epoch") from None
        if matching[0] < minimum_trusted_epoch:
            raise DownstreamDenied("controller fence epoch below trusted minimum")

    # The registry parsers only accept paths. Feed them private, immutable
    # captured copies rather than reopening the original mutable paths.
    with tempfile.TemporaryDirectory(prefix="warrantkit-fence-snapshot-") as directory:
        snapshot_dir = Path(directory)
        fence_snapshot = snapshot_dir / "fences.json"
        incident_snapshot = snapshot_dir / "incidents.json"
        fence_snapshot.write_bytes(fence_bytes)
        if incident_bytes is not None:
            incident_snapshot.write_bytes(incident_bytes)
        return reconcile_agentcontainment_registries(
            agent_id=agent_id, fence_path=fence_snapshot,
            incident_path=incident_snapshot, outbox=outbox,
            sign_transition=sign_transition,
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


# A checkpoint must be retrieved from an independently authenticated,
# rollback-resistant authority. This module intentionally does not implement
# a local-file checkpoint store: one would share the registry's rollback risk.
from dataclasses import dataclass


@dataclass(frozen=True)
class TrustedRegistryCheckpoint:
    """Externally authenticated, freshness-protected per-agent snapshot pin.

    The provider MUST authenticate agent identity, checkpoint provenance and
    freshness, and enforce monotonic progression across crashes/restores.
    This value is not a self-authenticating token.
    """
    agent_id: str
    epoch: int
    fence_sha256: str
    incident_sha256: str | None


def reconcile_with_trusted_checkpoint(
    *, agent_id: str, fence_path: str | Path, incident_path: str | Path,
    outbox: DurableTransitionOutbox,
    sign_transition: Callable[[str, int, bool], TransitionEnvelope],
    read_trusted_checkpoint: Callable[[str], TrustedRegistryCheckpoint],
) -> TransitionEnvelope:
    """Recover only from the exact snapshot pinned by external authority.

    The caller supplies a protected monotonic checkpoint service, not a
    checkpoint read from the mutable registry/outbox filesystem. A missing,
    stale, malformed, or mismatched checkpoint fails before enqueue. This
    adapter cannot establish that the provider is genuinely independent.
    """
    checkpoint = read_trusted_checkpoint(agent_id)
    if (not isinstance(checkpoint, TrustedRegistryCheckpoint)
            or checkpoint.agent_id != agent_id
            or type(checkpoint.epoch) is not int or checkpoint.epoch < 1):
        raise DownstreamDenied("invalid independent registry checkpoint")
    verifier = pinned_registry_snapshot_verifier(
        expected_fence_sha256=checkpoint.fence_sha256,
        expected_incident_sha256=checkpoint.incident_sha256,
    )
    def verify_exact_checkpoint(
        original_fence: Path, original_incident: Path,
        fence_bytes: bytes, incident_bytes: bytes | None,
    ) -> bool:
        import json
        if not verifier(original_fence, original_incident, fence_bytes, incident_bytes):
            return False
        try:
            snapshot = json.loads(fence_bytes)
            records = snapshot["records"]
            if not isinstance(records, list):
                return False
            matching = [record for record in records if isinstance(record, dict)
                        and record.get("agent_id") == agent_id]
            return (len(matching) == 1
                    and type(matching[0].get("containment_epoch")) is int
                    and matching[0]["containment_epoch"] == checkpoint.epoch)
        except (ValueError, TypeError, KeyError):
            return False

    return reconcile_authenticated_agentcontainment_registries(
        agent_id=agent_id, fence_path=fence_path, incident_path=incident_path,
        outbox=outbox, sign_transition=sign_transition,
        verify_registry_snapshot=verify_exact_checkpoint,
        minimum_trusted_epoch=checkpoint.epoch,
    )
