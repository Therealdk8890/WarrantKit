import pytest

from agentcontain.identity import ExecutionIdentity


def test_execution_identity_is_stable_and_opaque():
    identity = ExecutionIdentity(
        execution_id="exec-1",
        agent_id="agent-1",
        policy_id="policy-1",
        policy_digest="digest-1",
        epoch=7,
    )
    assert identity.execution_id == "exec-1"
    assert identity.agent_id == "agent-1"
    assert identity.policy_id == "policy-1"
    assert identity.policy_digest == "digest-1"
    assert identity.epoch == 7



@pytest.mark.parametrize("epoch", [True, False, 1.0, "1", -1])
def test_execution_identity_rejects_invalid_epoch_types_and_values(epoch) -> None:
    with pytest.raises(ValueError, match="epoch"):
        ExecutionIdentity.create("agent-1", "policy-1", "digest-1", epoch=epoch)


@pytest.mark.parametrize("field", ["execution_id", "agent_id", "policy_id", "policy_digest"])
@pytest.mark.parametrize("value", [None, 7, "", "   ", [], {}])
def test_direct_execution_identity_rejects_invalid_required_strings(field, value) -> None:
    values = {
        "execution_id": "exec-1",
        "agent_id": "agent-1",
        "policy_id": "policy-1",
        "policy_digest": "digest-1",
        "epoch": 0,
        "runtime_id": None,
    }
    values[field] = value
    with pytest.raises(ValueError, match=field):
        ExecutionIdentity(**values)


@pytest.mark.parametrize("runtime_id", [7, "", "   ", [], {}])
def test_execution_identity_rejects_invalid_runtime_id(runtime_id) -> None:
    with pytest.raises(ValueError, match="runtime_id"):
        ExecutionIdentity.create("agent-1", "policy-1", "digest-1", runtime_id=runtime_id)
