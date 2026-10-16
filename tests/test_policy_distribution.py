from agentcontain.policy import Policy


def test_policy_identity_remains_available_to_execution_layer():
    policy = Policy(policy_id="policy-1", version=1)
    assert policy.policy_id == "policy-1"
    assert policy.version == 1
    assert isinstance(policy.digest, str)
    assert len(policy.digest) == 64


def test_policy_digest_is_deterministic_for_equivalent_policy_data():
    first = Policy(policy_id="policy-1", version=1, allowed_egress=("api.example", "db.example"))
    second = Policy(policy_id="policy-1", version=1, allowed_egress=("db.example", "api.example"))
    assert first.canonical() == second.canonical()
    assert first.digest == second.digest


def test_policy_snapshots_mutable_inputs_and_freezes_metadata():
    from copy import deepcopy
    import pytest

    metadata = {"owner": "security"}
    capabilities = ["read"]
    allowed_egress = ["api.example:443"]
    policy = Policy(
        policy_id="policy-1",
        capabilities=capabilities,
        allowed_egress=allowed_egress,
        metadata=metadata,
    )
    original_digest = policy.digest

    metadata["owner"] = "attacker"
    capabilities.append("admin")
    allowed_egress.append("evil.example:443")

    assert policy.metadata["owner"] == "security"
    assert policy.capabilities == ("read",)
    assert policy.allowed_egress == ("api.example:443",)
    assert policy.digest == original_digest
    with pytest.raises(TypeError):
        policy.metadata["owner"] = "attacker"
    assert deepcopy(policy) is policy


def test_policy_rejects_non_integer_versions():
    import pytest

    for version in (True, 1.5, "2"):
        with pytest.raises(TypeError, match="version must be an integer"):
            Policy(policy_id="policy-1", version=version)
