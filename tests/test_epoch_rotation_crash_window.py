from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest

from agentcontain.engine import admit, contain
from agentcontain.integrations._authority import verify_current_authority
from agentcontain.policy import Policy


class CrashAfterEpochAdvanceEngine:
    """Model a runtime fence committing before controller/report reconciliation."""

    last_report = None

    def __init__(self) -> None:
        self.runtime_epoch = 0
        self.controller = SimpleNamespace(runtime=self)
        self.state = SimpleNamespace(value="active")
        self.can_execute = True

    def snapshot(self):
        return SimpleNamespace(
            runtime_id="runtime-crash-window",
            agent_id="agent-crash-window",
            epoch=self.runtime_epoch,
            state=self.state,
            can_execute=self.can_execute,
        )

    def contain(self):
        # AgentContainment advances its runtime epoch before returning the
        # containment report. Simulate controller loss at that boundary.
        self.runtime_epoch += 1
        self.state = SimpleNamespace(value="contained")
        self.can_execute = False
        raise RuntimeError("simulated controller death before report delivery")


class RuntimeView:
    def __init__(self, engine, *, state="contained", can_execute=False):
        self.engine = engine
        self.state = state
        self.can_execute = can_execute

    def snapshot(self):
        return SimpleNamespace(
            runtime_id="runtime-crash-window",
            agent_id="agent-crash-window",
            epoch=self.engine.runtime_epoch,
            state=SimpleNamespace(value=self.state),
            can_execute=self.can_execute,
        )


class FakeWarrantVerifier:
    def verify_warrant(self, _attestation):
        return self.warrant


class FakeGateway:
    def __init__(self, runtime):
        self.containment = SimpleNamespace(runtime=runtime)


def _expected_snapshot(admission):
    return (
        admission.identity,
        deepcopy(admission.policy),
        admission.warrant,
        deepcopy(admission.warrant_attestation),
    )


def test_old_warrant_is_rejected_when_controller_crashes_after_runtime_fence():
    engine = CrashAfterEpochAdvanceEngine()
    admission = admit(
        Policy("production", capabilities=("read",)),
        agent_id="agent-crash-window",
        engine=engine,
        runtime_id="runtime-crash-window",
    )
    old_warrant = admission.warrant
    assert old_warrant is not None
    assert old_warrant.runtime.epoch == 0
    protected_snapshot = _expected_snapshot(admission)

    # The runtime commits epoch 1, then raises before report delivery. WarrantKit
    # must reconcile from the authoritative runtime snapshot, not the report.
    with pytest.raises(RuntimeError, match="controller death"):
        contain(admission)

    assert engine.runtime_epoch == 1
    assert admission.identity.epoch == 1
    assert admission.warrant is not None
    assert admission.warrant.lifecycle.state.value == "revoked"
    assert admission.warrant_attestation is None
    assert admission.machine.state.value == "contained"

    admission.warrant_attestation = {"test-only": "signed-warrant"}
    verifier = FakeWarrantVerifier()
    verifier.warrant = old_warrant
    runtime = RuntimeView(engine, state="contained", can_execute=False)

    with pytest.raises(RuntimeError, match="admission authority changed"):
        verify_current_authority(
            admission,
            FakeGateway(runtime),
            verifier,
            protected_snapshot,
            error_type=RuntimeError,
            framework="crash-window test",
        )


def test_old_warrant_is_rejected_after_runtime_recovers_into_new_epoch():
    engine = CrashAfterEpochAdvanceEngine()
    admission = admit(
        Policy("production", capabilities=("read",)),
        agent_id="agent-crash-window",
        engine=engine,
        runtime_id="runtime-crash-window",
    )
    old_warrant = admission.warrant
    assert old_warrant is not None
    engine.runtime_epoch = 1  # Recovery made epoch 1 active; old Warrant remains epoch 0.

    admission.warrant_attestation = {"test-only": "signed-warrant"}
    verifier = FakeWarrantVerifier()
    verifier.warrant = old_warrant
    runtime = RuntimeView(engine, state="active", can_execute=True)

    with pytest.raises(RuntimeError, match="epoch"):
        verify_current_authority(
            admission,
            FakeGateway(runtime),
            verifier,
            _expected_snapshot(admission),
            error_type=RuntimeError,
            framework="crash-window test",
        )
