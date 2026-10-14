from __future__ import annotations

import pytest

from agentcontain.engine import (
    admit,
    build_agentcontainment_engine,
    contain,
    detect,
    issue_recovery_authorization,
    recover,
)
from agentcontain.policy import Policy


def test_authorized_execution_violation_revokes_authority_before_recovery():
    policy = Policy(
        policy_id="prod-agent",
        capabilities=("read-data",),
    )
    engine = build_agentcontainment_engine("agent-authority-e2e")
    admission = admit(
        policy,
        agent_id="agent-authority-e2e",
        engine=engine,
    )

    credentials = engine.credential_store
    old_lease = credentials.issue("prod-api")
    executed: list[str] = []

    # The execution starts with explicitly granted authority.
    assert credentials.valid(old_lease)

    # The agent crosses the policy boundary. Detection is an observation;
    # containment is the authoritative security transition.
    detect(
        admission,
        {
            "capability": "network-egress",
            "target": "https://unapproved.example",
            "reason": "outside-policy-authority",
        },
    )
    assert admission.machine.state.value == "detected"

    report = contain(admission)

    assert report.complete
    assert admission.machine.state.value == "contained"
    assert not credentials.valid(old_lease)

    # Revoked authority cannot be reused, and containment cannot mint a
    # replacement lease.
    assert credentials.execute_if_valid(
        old_lease,
        lambda: executed.append("stale"),
    ) is None
    assert executed == []
    with pytest.raises(RuntimeError, match="active runtime"):
        credentials.issue("prod-api")

    # Recovery requires the controller-owned authorization path.
    authorization = issue_recovery_authorization(admission)
    recovered_epoch = recover(admission, authorization)

    assert admission.machine.state.value == "recovered"
    assert recovered_epoch > old_lease.epoch

    fresh_lease = credentials.issue("prod-api")
    assert credentials.valid(fresh_lease)
    assert fresh_lease.epoch == recovered_epoch
    assert not credentials.valid(old_lease)

    historical_events = [
        event.name
        for event in admission.machine.event_history[0].events
    ]
    assert historical_events == ["admission_verified", "anomaly_detected"]

    contained_epoch_events = [
        event.name
        for event in admission.machine.event_history[1].events
    ]
    assert contained_epoch_events == [
        "containment_verified",
        "recovery_requested",
    ]

    current_events = [event.name for event in admission.machine.events.events]
    assert current_events == ["runtime_recovery_complete"]
