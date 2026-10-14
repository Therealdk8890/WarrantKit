import pytest

from agentcontain import Policy
from agentcontain.egress_binding import (
    DESTINATION_ALLOWLIST_CAPABILITY,
    EgressBinding,
    UnsupportedEgressBinding,
)
from agentcontain.engine import admit


class ProviderEngine:
    def __init__(self, capabilities=()):
        self.capabilities = frozenset(capabilities)
        self.calls = []
        self.last_report = None

    def bind_egress(self, **kwargs):
        self.calls.append(kwargs)
        return {"provider": "test-provider", "binding_installed": True}

    def contain(self):
        raise AssertionError("admission tests must not execute containment")


def test_non_empty_egress_without_runtime_identity_fails_admission():
    engine = ProviderEngine((DESTINATION_ALLOWLIST_CAPABILITY,))

    with pytest.raises(UnsupportedEgressBinding, match="requires a runtime_id"):
        admit(
            Policy("restricted", allowed_egress=("api.example.com:443",)),
            agent_id="agent-1",
            engine=engine,
        )

    assert engine.calls == []


def test_non_empty_egress_with_unsupported_provider_fails_admission():
    engine = ProviderEngine()

    with pytest.raises(UnsupportedEgressBinding, match=DESTINATION_ALLOWLIST_CAPABILITY):
        admit(
            Policy("restricted", allowed_egress=("api.example.com:443",)),
            agent_id="agent-1",
            engine=engine,
            runtime_id="runtime-1",
        )

    assert engine.calls == []


def test_capable_provider_binding_is_part_of_admission():
    engine = ProviderEngine((DESTINATION_ALLOWLIST_CAPABILITY,))
    policy = Policy("restricted", allowed_egress=("api.example.com:443",))

    admission = admit(
        policy,
        agent_id="agent-1",
        engine=engine,
        runtime_id="runtime-1",
    )

    assert isinstance(admission.egress_binding, EgressBinding)
    assert admission.egress_binding.policy_id == "restricted"
    assert admission.egress_binding.policy_digest == policy.digest
    assert admission.egress_binding.agent_id == "agent-1"
    assert admission.egress_binding.runtime_id == "runtime-1"
    assert admission.egress_binding.epoch == 0
    assert admission.egress_binding.allowed_egress == ("api.example.com:443",)
    assert admission.egress_binding.provider_evidence == {
        "provider": "test-provider",
        "binding_installed": True,
    }
    assert engine.calls == [{
        "policy_id": "restricted",
        "policy_digest": policy.digest,
        "agent_id": "agent-1",
        "runtime_id": "runtime-1",
        "epoch": 0,
        "allowed_egress": ("api.example.com:443",),
    }]
