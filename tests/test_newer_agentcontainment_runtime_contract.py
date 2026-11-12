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
    contain,
)
from agentcontain.attestation import Ed25519Signer, Ed25519Verifier
from agent_containment.gateway import ActionGateway
from agent_containment.enforcer import EnforcementResult, EnforcementStatus
from agent_containment.models import Action
from agent_containment.policy import PolicyEngine


@pytest.mark.integration
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


@pytest.mark.integration
def test_failed_external_enforcer_keeps_runtime_fenced_but_cannot_stop_inflight():
    """A failed external enforcer must never be reported as a successful kill.

    The already-admitted callback is explicitly released after containment
    fails. Its modeled side effect can complete; this is why downstream effect
    cancellation must not be inferred from the epoch fence alone.
    """
    engine = build_agentcontainment_engine("failed-enforcer-inflight")

    class FailingEnforcer:
        name = "deliberately-degraded-enforcer"

        def contain(self, agent_id):
            return EnforcementResult(
                self.name, EnforcementStatus.DEGRADED, "simulated kernel enforcement failure"
            )

        def verify_contained(self, agent_id):
            raise AssertionError("failed enforcement must not be verified as successful")

    engine.controller.enforcers.append(FailingEnforcer())
    signer = Ed25519Signer.generate("failed-enforcer-inflight")
    admission = admit(
        Policy("failed-enforcer-inflight", capabilities=("write_record",)),
        agent_id="failed-enforcer-inflight",
        engine=engine,
        runtime_id=engine.runtime_id,
        warrant_signer=signer,
    )
    gateway = ActionGateway(PolicyEngine(), engine.controller)
    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    bound = BoundGuardedExecution(admission, gateway, warrant_verifier=verifier)
    action = Action("failed-enforcer-inflight", "first", "write_record", "record", risk=1)
    runtime = engine.controller.runtime
    before_epoch = runtime.epoch

    entered = Event()
    release = Event()
    effects = []
    results = []
    errors = []

    def admitted_effect(_action):
        entered.set()
        assert release.wait(timeout=8), "test did not release the admitted callback"
        effects.append("already-admitted effect completed after failed enforcement")
        return "callback-completed"

    def guarded_worker():
        try:
            results.append(bound.execute(action, admitted_effect))
        except BaseException as exc:
            errors.append(exc)

    worker = Thread(target=guarded_worker, daemon=True)
    worker.start()
    try:
        assert entered.wait(timeout=5)
        assert runtime.inflight_executions == 1
        with pytest.raises(RuntimeError, match="enforcement engine reported containment failures"):
            contain(admission)
        report = engine.last_report
        assert report is not None
        assert not report.complete
        assert not report.certified
        assert report.external_verified is False
        assert any("deliberately-degraded-enforcer" in failure for failure in report.failures)
        assert runtime.epoch == before_epoch + 1
        assert not runtime.can_execute
        assert runtime.acquire_lease() is None
        assert effects == []
        assert runtime.inflight_executions == 1
        with pytest.raises(GuardedExecutionDenied):
            bound.execute(
                Action("failed-enforcer-inflight", "second", "write_record", "record"),
                lambda _action: effects.append("new effect bypassed fence"),
            )
        assert effects == []
    finally:
        release.set()
        worker.join(timeout=5)
    assert not worker.is_alive()
    assert not errors, errors
    assert results == ["callback-completed"]
    assert effects == ["already-admitted effect completed after failed enforcement"]
    assert runtime.inflight_executions == 0
