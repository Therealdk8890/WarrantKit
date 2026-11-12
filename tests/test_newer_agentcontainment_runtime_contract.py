"""Cross-repository contract against AgentContainment's unlocked-callback runtime.

Run only in the dedicated CI job installing the explicitly pinned newer
AgentContainment source. This does NOT establish cancellation of an already
admitted side effect or guarantee that it cannot finish after a fence.
"""
from threading import Event, Thread

import pytest

from agentcontain import (
    BoundGuardedExecution,
    GuardedExecutionDenied,
    Policy,
    admit,
    build_agentcontainment_engine,
)
from agentcontain.attestation import Ed25519Signer, Ed25519Verifier
from agent_containment.gateway import ActionGateway
from agent_containment.models import Action
from agent_containment.policy import PolicyEngine


def test_containment_fences_new_admissions_while_prior_callback_is_blocked():
    engine = build_agentcontainment_engine("inflight-interop")
    signer = Ed25519Signer.generate("inflight-interop")
    admission = admit(
        Policy("inflight-interop-policy", capabilities=("write_record",)),
        agent_id="inflight-interop",
        engine=engine,
        runtime_id=engine.runtime_id,
        warrant_signer=signer,
    )
    gateway = ActionGateway(PolicyEngine(), engine.controller)
    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    bound = BoundGuardedExecution(admission, gateway, warrant_verifier=verifier)
    runtime = engine.controller.runtime
    action = Action("inflight-interop", "first", "write_record", "record", risk=1)
    original_epoch = runtime.epoch

    started = Event()
    release = Event()
    results = []
    errors = []
    blocked_new_admission = []

    def already_admitted(_action):
        started.set()
        if not release.wait(timeout=10):
            raise AssertionError("blocked executor was never released")
        return "completed-inflight"

    def run_admitted():
        try:
            results.append(bound.execute(action, already_admitted))
        except BaseException as exc:
            errors.append(exc)

    worker = Thread(target=run_admitted, daemon=True)
    worker.start()
    fence = None
    try:
        assert started.wait(timeout=5), "the guarded callback did not begin"
        assert runtime.inflight_executions == 1
        fence = Thread(target=runtime.halt, daemon=True)
        fence.start()
        fence.join(timeout=3)
        assert not fence.is_alive(), (
            "fencing waited behind an already-admitted application callback"
        )
        assert runtime.epoch == original_epoch + 1
        assert not runtime.can_execute

        with pytest.raises(GuardedExecutionDenied):
            bound.execute(
                Action("inflight-interop", "second", "write_record", "record", risk=1),
                lambda _action: blocked_new_admission.append("unexpected"),
            )
        assert blocked_new_admission == []
        # A previously admitted operation is still in flight. Only the external
        # enforcer/downstream auth can terminate or revoke such work.
        assert runtime.inflight_executions == 1
    finally:
        release.set()
        if fence is not None:
            fence.join(timeout=5)
        worker.join(timeout=5)

    assert not worker.is_alive()
    assert not errors, errors
    assert results == ["completed-inflight"]
    assert runtime.inflight_executions == 0
