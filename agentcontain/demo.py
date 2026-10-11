"""No-privilege demonstration of WarrantKit lifecycle and proof semantics."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any

from .engine import admit, evidence_envelope
from .evidence import EvidenceEnvelope, canonical_json
from .operator import OperatorIncidentView
from .policy import Policy

_DEMO_KEY = b"warrantkit-demo-key-v1"


@dataclass(frozen=True)
class DemoReport:
    complete: bool = True


class SimulatedEngine:
    """Demo-only engine. It does not enforce a kernel boundary."""

    def contain(self) -> DemoReport:
        return DemoReport()


def _issue_receipt(evidence: EvidenceEnvelope) -> dict[str, Any]:
    payload = {
        "schema_version": 1,
        "receipt_id": "demo-" + evidence.execution["execution_id"],
        "execution_id": evidence.execution["execution_id"],
        "agent_id": evidence.execution["agent_id"],
        "epoch": evidence.execution["epoch"],
        "containment": {
            "requested": True,
            "enforced": True,
            "independently_verified": False,
            "mode": "simulated",
        },
        "proof_status": "observed",
    }
    digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    signature = hmac.new(_DEMO_KEY, digest.encode("ascii"), hashlib.sha256).hexdigest()
    return {"payload": payload, "digest": digest, "signature": signature}


def _verify_receipt(receipt: dict[str, Any], evidence: EvidenceEnvelope) -> bool:
    payload = receipt["payload"]
    digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    signature = hmac.new(_DEMO_KEY, digest.encode("ascii"), hashlib.sha256).hexdigest()
    return (
        hmac.compare_digest(digest, receipt["digest"])
        and hmac.compare_digest(signature, receipt["signature"])
        and payload["execution_id"] == evidence.execution["execution_id"]
        and payload["agent_id"] == evidence.execution["agent_id"]
        and payload["epoch"] == evidence.execution["epoch"]
    )


def run_demo() -> int:
    admission = admit(
        Policy("demo", capabilities=("simulated-containment",)),
        agent_id="demo-agent",
        engine=SimulatedEngine(),
    )
    if not admission.engine.contain().complete:
        raise RuntimeError("simulated containment failed")

    admission.machine.contain()
    admission.machine.detect({"reason": "demo_policy_violation"})
    admission.machine.fence()
    admission.machine.halt()
    admission.machine.verify()

    base = evidence_envelope(admission)
    evidence = EvidenceEnvelope.from_execution(
        execution=base.execution,
        events=base.events,
        enforcement={"complete": True, "mode": "simulated", "external_enforcement": False},
        verification={"status": "observed", "method": "warrantkit-no-root-demo"},
        proof={"simulated": True, "host_enforcement_verified": False},
        provenance={"producer": "warrantkit-demo"},
    )
    receipt = _issue_receipt(evidence)
    evidence = evidence.with_receipt(receipt)
    evidence.validate()

    if not _verify_receipt(receipt, evidence):
        raise RuntimeError("demo receipt verification failed")

    view = OperatorIncidentView.from_evidence(evidence)
    incident = view.incident

    print("WarrantKit — reference incident experience")
    print("--------------------------------------------")
    print(f"Execution:     {admission.identity.execution_id}")
    print(f"Agent:         {view.agent['agent_id']}")
    print(f"Policy:        {view.policy['policy_id']}")
    print(f"Policy digest: {view.policy['policy_digest']}")
    print("Mode:          SIMULATED (no kernel enforcement)")
    print()
    print("Incident")
    print(f"  Trigger:     {incident.trigger or 'none'}")
    print(f"  Status:      {incident.status.value.upper()}")
    print(f"  Proof:       {incident.proof_status.upper()}")
    print()
    print("Lifecycle / evidence")
    for event in view.timeline:
        print(f"  {event.sequence}. {event.name}")
    print()
    print("Proof")
    print("  Evidence:    OBSERVED")
    print("  Verification: NOT CLAIMED (simulated)")
    print("  Receipt:     AUTHENTICATED")
    print(f"  Receipt ID:  {view.receipt_id}")
    print()
    print("Verified ≠ claim is true")
    print("This reference experience demonstrates the platform procedure,")
    print("operator projection, and receipt integrity.")
    print("It does not prove real host or kernel containment.")
    return 0


def run_stale_warrant_demo() -> int:
    """Demonstrate stale-Warrant rejection against the runtime epoch."""
    from .engine import build_agentcontainment_engine, contain
    from .warrant import Warrant, verify_warrant

    engine = build_agentcontainment_engine("first-proof")
    admission = admit(
        Policy("payments", capabilities=("payments_refund",)),
        agent_id="payments-agent",
        engine=engine,
        runtime_id=engine.runtime_id,
    )
    if admission.warrant is None:
        raise RuntimeError("the proof requires a runtime-bound Warrant")

    # Retain an active serialized copy, as an agent could before containment.
    retained = Warrant.from_dict(admission.warrant.to_dict())
    identity = admission.identity

    def verify_retained() -> None:
        # Read the epoch from runtime state; do not accept it from the caller.
        verify_warrant(
            retained,
            execution_id=identity.execution_id,
            agent_id=identity.agent_id,
            policy_id=identity.policy_id,
            policy_digest=identity.policy_digest,
            runtime_id=identity.runtime_id,
            epoch=admission.engine.controller.runtime.epoch,
        )

    initial_epoch = admission.engine.controller.runtime.epoch
    verify_retained()
    print("WarrantKit — stale-Warrant replay proof")
    print("---------------------------------------")
    print(f"Runtime epoch {initial_epoch}: retained Warrant ACCEPTED")

    contain(admission)
    current_epoch = admission.engine.controller.runtime.epoch
    if current_epoch == initial_epoch:
        raise RuntimeError(
            "containment did not advance the controller runtime epoch; "
            "this environment cannot demonstrate epoch fencing"
        )
    print(f"Containment advanced runtime epoch to {current_epoch}")

    try:
        verify_retained()
    except ValueError as exc:
        if "epoch" not in str(exc):
            raise
        print(f"Retained pre-containment Warrant: REJECTED ({exc})")
    else:
        raise RuntimeError("FAIL: stale Warrant was accepted")

    print()
    print("This proves verifier rejection against the controller's runtime epoch.")
    print("It does not prove kernel-level workload termination or isolate the")
    print("controller from the verifier; use the privileged Linux proof for that.")
    return 0
