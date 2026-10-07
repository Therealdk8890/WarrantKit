"""Adapter boundary between AgentContain and AgentContainment."""

from __future__ import annotations

from dataclasses import dataclass, field
import threading
from datetime import datetime, timedelta, timezone
from typing import Protocol
from uuid import uuid4

from .evidence import EvidenceEnvelope, validate_runtime_pinned_binding
from .fleet import FleetRegistry
from .identity import ExecutionIdentity
from .policy import Policy
from .policy_distribution import PolicyBundle, PolicyRegistry
from .receipt import WarrantBoundReceipt
from .state import PlatformStateMachine
from .warrant import Warrant, RevocationState, verify_warrant


class ContainmentResult(Protocol):
    """Minimum result contract needed by the platform."""

    complete: bool


class ReceiptCapableResult(ContainmentResult, Protocol):
    """Containment result that can produce an authenticated receipt."""

    def to_receipt(
        self,
        secret: bytes,
        *,
        execution_id: str,
        policy_id: str,
    ): ...


class EnforcementEngine(Protocol):
    """Contract consumed by the platform adapter."""

    last_report: ReceiptCapableResult | None

    def contain(self) -> ContainmentResult: ...


class CredentialAuthority:
    """Runtime-scoped facade over the controller-owned credential leases.

    Credential issuance and modeled credential use are execution authority, so
    the platform must not expose the raw store while the runtime is contained
    or halted. Existing leases remain queryable for revocation/audit checks.
    """

    def __init__(self, controller) -> None:
        self._controller = controller

    @property
    def _store(self):
        store = getattr(self._controller, "credentials", None)
        if store is None:
            raise RuntimeError("runtime has no credential lease store")
        return store

    @property
    def _active(self) -> bool:
        state = getattr(getattr(self._controller, "runtime", None), "state", None)
        return getattr(state, "value", state) == "active"

    def issue(self, credential_id: str):
        if not self._active:
            raise RuntimeError("credential issuance requires an active runtime")
        return self._store.issue(credential_id)

    def valid(self, lease) -> bool:
        return self._store.valid(lease)

    def execute_if_valid(self, lease, executor):
        if not self._active:
            return None
        return self._store.execute_if_valid(lease, executor)

    def revoke(self, credential_id: str) -> None:
        self._store.revoke(credential_id)


def _synchronized(func):
    """Serialize lifecycle snapshots for one Admission without widening authority."""
    def wrapper(admission, *args, **kwargs):
        with admission._lock:
            return func(admission, *args, **kwargs)
    wrapper.__name__ = func.__name__
    wrapper.__doc__ = func.__doc__
    return wrapper


@dataclass
class Admission:
    """Authoritative platform admission result."""

    identity: ExecutionIdentity
    machine: PlatformStateMachine
    engine: EnforcementEngine
    policy: PolicyBundle
    warrant: Warrant | None = None
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False, compare=False)


class AgentContainmentRuntimeAdapter:
    """Platform adapter over the controller-owned AgentContainment service.

    The runtime service remains authoritative for containment, recovery
    authorization, durable incident state, and external enforcement. This
    adapter only exposes those operations to the platform lifecycle.
    """

    def __init__(self, agent_id: str, controller, service) -> None:
        self.agent_id = agent_id
        self.controller = controller
        self.service = service
        self.service.register(agent_id, containment=controller)
        self._credential_authority = CredentialAuthority(controller)

    @property
    def runtime_id(self) -> str:
        return self.controller.runtime.runtime_id

    @property
    def authority_revocation_evidence_record(self):
        """Return runtime-produced authority revocation evidence for the last containment."""
        report = self.controller.last_report
        export = getattr(report, "authority_revocation_evidence_record", None)
        if export is None:
            raise RuntimeError("runtime engine does not expose authority revocation evidence")
        return export(self.runtime_id)

    @property
    def credential_store(self):
        """Reference credential lease store owned by the runtime controller.

        Credential leases are revoked as part of authoritative containment.
        This exposes the existing AgentContainment reference-model boundary to
        WarrantKit without making WarrantKit the credential provider.
        """
        return self._credential_authority

    @property
    def last_report(self):
        return self.controller.last_report

    def contain(self):
        return self.service.contain(self.agent_id)

    def halt(self) -> None:
        self.controller.halt()

    def issue_recovery_authorization(self):
        return self.service.issue_recovery_authorization(self.agent_id)

    def recover(self, authorization) -> int:
        return self.service.recover(self.agent_id, authorization)

    def reconcile_containment(self):
        return self.service.reconcile_containment(self.agent_id)

    def recontain_enforcers(self):
        return self.controller.recontain_enforcers()


def admit(
    policy: Policy,
    *,
    agent_id: str,
    engine: EnforcementEngine,
    registry: PolicyRegistry | None = None,
    runtime_id: str | None = None,
    warrant_issuer: str = "warrantkit",
    warrant_ttl: timedelta = timedelta(hours=1),
) -> Admission:
    """Validate, issue, and admit one execution under a bounded Warrant.

    A runtime identifier is required for a Warrant. Provider-neutral test/fake
    engines may omit runtime identity and retain the legacy admission shape.
    """
    registry = registry or PolicyRegistry()
    bundle = registry.accept_policy(policy)
    if warrant_ttl <= timedelta(0):
        raise ValueError("warrant_ttl must be positive")
    identity = ExecutionIdentity.create(
        agent_id,
        bundle.policy_id,
        bundle.policy_digest,
        runtime_id=runtime_id,
    )
    warrant = None
    if identity.runtime_id is not None:
        issued_at = datetime.now(timezone.utc)
        warrant = Warrant.issue(
            warrant_id=str(uuid4()),
            issuer=warrant_issuer,
            agent_id=identity.agent_id,
            execution_id=identity.execution_id,
            policy=bundle,
            runtime_id=identity.runtime_id,
            epoch=identity.epoch,
            issued_at=issued_at,
            expires_at=issued_at + warrant_ttl,
            capabilities=tuple(bundle.policy.capabilities),
        )
        verify_warrant(
            warrant,
            execution_id=identity.execution_id,
            agent_id=identity.agent_id,
            policy_id=identity.policy_id,
            policy_digest=identity.policy_digest,
            runtime_id=identity.runtime_id,
            epoch=identity.epoch,
            now=issued_at,
        )
    machine = PlatformStateMachine(identity)
    machine.admit(
        details={"warrant_id": warrant.warrant_id} if warrant is not None else None
    )
    return Admission(
        identity=identity,
        machine=machine,
        engine=engine,
        policy=bundle,
        warrant=warrant,
    )

@_synchronized
def detect(admission: Admission, details: dict[str, str] | None = None):
    """Record an observed anomaly without changing runtime enforcement."""
    return admission.machine.detect(details)



def _revoke_warrant(admission: Admission) -> None:
    if admission.warrant is not None and admission.warrant.lifecycle.state == RevocationState.ACTIVE:
        admission.warrant = admission.warrant.revoke(
            revoked_at=datetime.now(timezone.utc)
        )


def _issue_current_warrant(admission: Admission) -> Warrant:
    if admission.identity.runtime_id is None:
        raise RuntimeError("runtime identity is required for Warrant authority")
    issued_at = datetime.now(timezone.utc)
    warrant = Warrant.issue(
        warrant_id=str(uuid4()),
        issuer="warrantkit",
        agent_id=admission.identity.agent_id,
        execution_id=admission.identity.execution_id,
        policy=admission.policy,
        runtime_id=admission.identity.runtime_id,
        epoch=admission.identity.epoch,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(hours=1),
        capabilities=tuple(admission.policy.policy.capabilities),
    )
    verify_warrant(
        warrant,
        execution_id=admission.identity.execution_id,
        agent_id=admission.identity.agent_id,
        policy_id=admission.identity.policy_id,
        policy_digest=admission.identity.policy_digest,
        runtime_id=admission.identity.runtime_id,
        epoch=admission.identity.epoch,
        now=issued_at,
    )
    admission.warrant = warrant
    return warrant

@_synchronized
def contain(admission: Admission) -> object:
    """Invoke authoritative runtime containment and record its platform state.

    AgentContainment's controller fences the runtime before applying and
    independently verifying configured enforcement providers. The platform
    therefore records one atomic containment transition rather than pretending
    it controls the provider-level fence boundary.
    """
    report = admission.engine.contain()
    if not getattr(report, "complete", True):
        raise RuntimeError(
            "enforcement engine reported containment failures: "
            + "; ".join(getattr(report, "failures", ()))
        )

    # AgentContainment advances its execution epoch when containment takes
    # effect. When the authoritative report exposes that epoch, require the
    # exact next platform epoch and adopt it before recording the lifecycle
    # event. This keeps receipts, events, and runtime proof in one namespace.
    report_epoch = getattr(report, "epoch", None)
    if report_epoch is not None:
        if isinstance(report_epoch, bool) or not isinstance(report_epoch, int):
            raise TypeError("runtime containment epoch must be an integer")
        expected_epoch = admission.identity.epoch + 1
        if report_epoch != expected_epoch:
            raise RuntimeError(
                f"runtime containment epoch {report_epoch} does not match "
                f"expected platform epoch {expected_epoch}"
            )
        # Keep epoch transition ownership inside the platform state machine.
        admission.machine.start_new_epoch(report_epoch)
        admission.identity = admission.machine.identity

    # The epoch transition makes old authority stale; explicit revocation keeps
    # the lifecycle state visible and fail-closed even to epoch-unaware callers.
    _revoke_warrant(admission)
    admission.machine.contain()
    return report


@_synchronized
def halt(admission: Admission):
    """Halt through runtime authority and revoke execution authority."""
    operation = getattr(admission.engine, "halt", None)
    if operation is None:
        raise RuntimeError("enforcement engine does not expose halt")
    operation()
    # A successful halt is an execution-authority boundary. Revoke the
    # current Warrant only after the authoritative runtime halt succeeds so a
    # failed provider operation does not create a platform/runtime mismatch.
    _revoke_warrant(admission)
    return admission.machine.halt()


@_synchronized
def verify(admission: Admission, *, runtime_binding: dict | None = None):
    """Verify authoritative runtime proof, optionally requiring second evidence.

    When a runtime binding is supplied, verification cannot complete unless
    authority revocation, external enforcement, and independent observation
    are all pinned to the current runtime epoch.
    """
    identity = admission.identity
    report = getattr(admission.engine, "last_report", None)
    report_epoch = getattr(report, "epoch", None) if report is not None else None
    stale_runtime_report = (
        report is not None
        and report_epoch is not None
        and report_epoch != identity.epoch
    )
    if stale_runtime_report:
        # A runtime proof is epoch-scoped. Never project a containment report
        # from a prior epoch into the current execution's verified envelope.
        report = None
    if report is None:
        raise RuntimeError("runtime verification report is unavailable")
    if not bool(getattr(report, "complete", False)):
        raise RuntimeError("runtime verification is incomplete")
    if not bool(getattr(report, "certified", False)):
        raise RuntimeError("runtime verification lacks independent external verification")
    if not bool(getattr(report, "durable", True)):
        raise RuntimeError("runtime verification evidence is not durable")
    if runtime_binding is not None:
        validate_runtime_pinned_binding(runtime_binding, {
            "agent_id": identity.agent_id,
            "epoch": identity.epoch,
            **({"runtime_id": identity.runtime_id} if identity.runtime_id is not None else {}),
        })
    return admission.machine.verify()


@_synchronized
def runtime_pinned_evidence(
    admission: Admission,
    *,
    authority_record: dict | None = None,
    observation,
) -> EvidenceEnvelope:
    """Bind real AgentContainment enforcement and observation to one epoch."""
    identity = admission.identity
    runtime_id = identity.runtime_id
    if not runtime_id:
        raise RuntimeError("runtime identity is required for pinned evidence")

    report = getattr(admission.engine, "last_report", None)
    export = getattr(report, "enforcement_evidence_record", None)
    if export is None:
        raise RuntimeError("runtime engine does not expose canonical enforcement evidence")
    enforcement = export(runtime_id)

    if not hasattr(observation, "verify_integrity") or not observation.verify_integrity():
        raise RuntimeError("independent runtime observation failed integrity verification")
    observation_payload = observation.payload()
    observation_digest = "sha256:" + observation.digest
    if observation_payload.get("runtime_id") != runtime_id:
        raise RuntimeError("runtime observation runtime_id does not match execution")
    if observation_payload.get("agent_id") != identity.agent_id:
        raise RuntimeError("runtime observation agent_id does not match execution")
    if observation_payload.get("epoch") != identity.epoch:
        raise RuntimeError("runtime observation epoch does not match execution")
    if observation_payload.get("state") not in {"contained", "halted"} or observation_payload.get("can_execute") is not False:
        raise RuntimeError("runtime observation does not prove a non-executable terminal state")

    if authority_record is None:
        authority_export = getattr(admission.engine, "authority_revocation_evidence_record", None)
        if authority_export is None:
            raise RuntimeError("runtime engine does not expose authority revocation evidence")
        authority_record = authority_export() if callable(authority_export) else authority_export
    authority = dict(authority_record)
    authority.setdefault("runtime_id", runtime_id)
    authority.setdefault("agent_id", identity.agent_id)
    authority.setdefault("epoch", identity.epoch)
    required_authority = {"runtime_id", "agent_id", "epoch", "revoked", "revoked_at", "digest", "record"}
    if set(authority) != required_authority:
        raise ValueError("authority record has an invalid pinned-evidence shape")

    binding = {
        "schema_version": "agentcontain.runtime-binding/v1",
        "runtime_id": runtime_id,
        "agent_id": identity.agent_id,
        "epoch": identity.epoch,
        "authority": authority,
        "enforcement": enforcement,
        "observation": {
            "digest": observation_digest,
            "record": observation_payload,
            # Preserve the independently observed canonical runtime state; do not
            # invent a second semantic label outside the digested record.
            "state": observation_payload["state"],
            "observed_at": observation_payload["observed_at"],
        },
    }
    return evidence_envelope(admission).with_runtime_pinned_evidence(binding)

@_synchronized
def issue_recovery_authorization(admission: Admission):
    """Request controller-owned recovery authorization for this execution."""
    operation = getattr(admission.engine, "issue_recovery_authorization", None)
    if operation is None:
        raise RuntimeError("enforcement engine does not expose recovery authorization")
    return operation()


@_synchronized
def recover(admission: Admission, authorization) -> int:
    """Recover through the controller-owned authority and record lifecycle state."""
    operation = getattr(admission.engine, "recover", None)
    if operation is None:
        raise RuntimeError("enforcement engine does not expose recovery")
    admission.machine.recover()
    try:
        epoch = operation(authorization)
    except Exception:
        # The runtime controller is fail-closed and remains contained on
        # failed recovery. Reflect that compensation in the platform event log.
        if admission.machine.state.value == "recovering":
            admission.machine.recovery_failed()
        raise
    admission.machine.recovered(epoch)
    admission.identity = admission.machine.identity
    # Recovery authorization is runtime-owned and distinct from Warrant
    # authority. Fresh execution authority is minted only after the new epoch
    # is authoritative. Preserve legacy provider-neutral adapters that do not
    # expose a runtime identity.
    if admission.identity.runtime_id is not None:
        _issue_current_warrant(admission)
    return epoch


@_synchronized
def recontain(admission: Admission):
    """Re-verify external enforcement after containment without granting authority."""
    if admission.machine.state.value != "contained":
        raise RuntimeError("recontainment requires an already-contained runtime")
    operation = getattr(admission.engine, "recontain_enforcers", None)
    if operation is None:
        raise RuntimeError("enforcement engine does not expose recontainment")
    failures = tuple(operation())
    if failures:
        raise RuntimeError("recontainment verification failed: " + "; ".join(failures))
    return admission.machine.recontain()


@_synchronized
def containment_receipt(admission: Admission, secret: bytes):
    """Create a signed/tamper-evident receipt bound to platform identity."""
    report = getattr(admission.engine, "last_report", None)
    if report is None:
        raise RuntimeError("containment has not been executed")
    report_epoch = getattr(report, "epoch", None)
    if report_epoch is not None and report_epoch != admission.identity.epoch:
        raise RuntimeError(
            "containment report epoch does not match current execution epoch"
        )
    runtime_receipt = report.to_receipt(
        secret,
        execution_id=admission.identity.execution_id,
        policy_id=admission.identity.policy_id,
    )
    if admission.warrant is None:
        return runtime_receipt
    if admission.identity.runtime_id is None:
        raise RuntimeError("runtime identity is required for Warrant-bound receipts")
    return WarrantBoundReceipt(
        runtime_receipt=runtime_receipt,
        warrant_id=admission.warrant.warrant_id,
        execution_id=admission.identity.execution_id,
        agent_id=admission.identity.agent_id,
        policy_id=admission.identity.policy_id,
        policy_digest=admission.identity.policy_digest,
        runtime_id=admission.identity.runtime_id,
        warrant_epoch=admission.warrant.runtime.epoch,
        epoch=admission.identity.epoch,
    )


@_synchronized
def evidence_envelope(admission: Admission, *, fleet: FleetRegistry | None = None) -> EvidenceEnvelope:
    """Build evidence from the accepted policy, runtime report, and event log.

    Policy identity is taken from the admission's validated PolicyBundle, not
    from caller-supplied evidence fields. Runtime enforcement fields are
    projected from the authoritative AgentContainment report when available;
    the adapter never manufactures host-proof claims.
    """
    identity = admission.identity
    if identity.policy_id != admission.policy.policy_id:
        raise RuntimeError("admission policy_id diverges from accepted policy")
    if identity.policy_digest != admission.policy.policy_digest:
        raise RuntimeError("admission policy_digest diverges from accepted policy")

    events = tuple(event.to_dict() for event in admission.machine.events.events)
    governance = None if fleet is None else fleet.governance_for_agent(identity.agent_id)

    report = getattr(admission.engine, "last_report", None)
    report_epoch = getattr(report, "epoch", None) if report is not None else None
    stale_runtime_report = (
        report is not None
        and report_epoch is not None
        and report_epoch != identity.epoch
    )
    if stale_runtime_report:
        # Runtime containment proof is scoped to the epoch in which it was
        # produced. Do not project historical proof into the current epoch.
        report = None
    if report is None:
        enforcement = {
            "complete": admission.machine.state.value in {
                "contained",
                "detected",
                "fenced",
                "halted",
                "verified",
                "recovering",
                "recovered",
            }
        }
        verification = {
            "status": "observed",
            "method": "agentcontain-platform-events",
        }
        if stale_runtime_report:
            verification["reason"] = "runtime-report-epoch-mismatch"
        proof = {}
    else:
        failures = tuple(getattr(report, "failures", ()))
        persistence_failures = tuple(getattr(report, "persistence_failures", ()))
        certified = bool(getattr(report, "certified", False))
        durable = bool(getattr(report, "durable", True))
        external_verified = bool(getattr(report, "external_verified", False))

        enforcement = {
            "complete": bool(getattr(report, "complete", False)),
            "external_verified": external_verified,
            "certified": certified,
            "durable": durable,
            "stages": list(getattr(report, "stages", ())),
            "failures": list(failures),
            "persistence_failures": list(persistence_failures),
            "enforcement_latency_seconds": getattr(
                report, "enforcement_latency_seconds", None
            ),
        }
        verification = {
            "status": (
                "verified"
                if certified and durable
                else "degraded"
                if failures or persistence_failures
                else "observed"
            ),
            "method": "agentcontainment-runtime-report",
            "scope": "runtime-enforcement",
        }
        proof = {
            "host_enforcement_verified": external_verified,
            "runtime_report": True,
        }

    return EvidenceEnvelope.from_execution(
        execution={
            "execution_id": identity.execution_id,
            "agent_id": identity.agent_id,
            "policy_id": admission.policy.policy_id,
            "policy_digest": admission.policy.policy_digest,
            "epoch": identity.epoch,
            **({"runtime_id": identity.runtime_id} if identity.runtime_id is not None else {}),
        },
        events=events,
        enforcement=enforcement,
        verification=verification,
        proof=proof,
        governance=governance,
        provenance={"producer": "agentcontain"},
    )


def build_agentcontainment_engine(
    agent_id: str,
    *,
    cgroup_path: str | None = None,
) -> EnforcementEngine:
    """Construct the pinned AgentContainment controller.

    If cgroup_path is supplied, use the real cgroup-v2 enforcement provider.
    The adapter never guesses or broadens the host trust boundary.
    """
    try:
        from agent_containment.containment import ContainmentController
        from agent_containment.cgroup_enforcer import CgroupV2Enforcer
        from agent_containment.control import ContainmentService
        from agent_containment.credentials import CredentialStore
        from agent_containment.runtime import Runtime
    except ImportError as exc:
        raise RuntimeError(
            "AgentContainment is not installed; initialize the pinned submodule "
            "and install its Python package before using the runtime adapter"
        ) from exc

    runtime = Runtime(agent_id)
    # Credential leases are part of the runtime authority boundary. They must
    # be attached to the same controller that performs containment so a fence
    # revokes previously issued credential authority atomically with the
    # containment transition.
    credentials = CredentialStore(runtime=runtime)
    if cgroup_path is None:
        controller = ContainmentController(runtime, credentials=credentials)
    else:
        enforcer = CgroupV2Enforcer({agent_id: cgroup_path})
        controller = ContainmentController(
            runtime,
            credentials=credentials,
            enforcers=[enforcer],
        )
    return AgentContainmentRuntimeAdapter(
        agent_id,
        controller,
        ContainmentService(),
    )
