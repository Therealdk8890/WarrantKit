from __future__ import annotations

import pytest

from agentcontain.engine import admit, contain
from agentcontain.policy import Policy
from agentcontain.warrant import verify_warrant


class CrashAfterEpochAdvanceEngine:
    """Model a controller interruption after the runtime fence advances."""

    last_report = None

    def __init__(self) -> None:
        self.runtime_epoch = 0

    def contain(self):
        # The runtime has committed the new epoch, but the platform never
        # receives a report and therefore cannot reconcile its local identity.
        self.runtime_epoch += 1
        raise RuntimeError("simulated controller death before report delivery")


@pytest.mark.xfail(
    strict=True,
    reason=(
        "verify_warrant trusts the caller-supplied epoch; it cannot detect that "
        "the caller's cached epoch is stale after a controller crash"
    ),
)
def test_old_warrant_is_rejected_after_epoch_advances_before_reconciliation():
    engine = CrashAfterEpochAdvanceEngine()
    admission = admit(
        Policy("production"),
        agent_id="agent-crash-window",
        engine=engine,
        runtime_id="runtime-crash-window",
    )
    old_warrant = admission.warrant
    assert old_warrant is not None
    assert old_warrant.runtime.epoch == 0

    # Fault injection: runtime fencing commits epoch 1, then controller
    # execution is interrupted before WarrantKit receives the containment
    # report and advances its local identity.
    with pytest.raises(RuntimeError, match="controller death"):
        contain(admission)

    assert engine.runtime_epoch == 1
    assert admission.identity.epoch == 0

    # Security invariant: a verifier must not accept the old Warrant merely
    # because the restarted caller still has cached epoch 0. This currently
    # fails because verify_warrant only compares the two supplied values.
    with pytest.raises(ValueError, match="epoch"):
        verify_warrant(
            old_warrant,
            execution_id=admission.identity.execution_id,
            agent_id=admission.identity.agent_id,
            policy_id=admission.identity.policy_id,
            policy_digest=admission.identity.policy_digest,
            runtime_id="runtime-crash-window",
            epoch=admission.identity.epoch,
        )
