from datetime import datetime, timedelta, timezone, tzinfo

import pytest

from agentcontain import ExternalAuthorizationDecision, Policy, import_authorization
from agentcontain.warrant import verify_warrant


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


class MissingOffsetTimezone(tzinfo):
    def utcoffset(self, dt):
        return None

    def dst(self, dt):
        return None



def _policy() -> Policy:
    return Policy("production", capabilities=("read",))


def _decision(policy: Policy) -> ExternalAuthorizationDecision:
    return ExternalAuthorizationDecision(
        decision_id="decision-1",
        issuer="external-idp",
        subject_agent_id="agent-1",
        subject_execution_id="exec-1",
        policy_id=policy.policy_id,
        policy_digest=policy.digest,
        capabilities=("read",),
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )


def test_external_authorization_becomes_local_epoch_bound_warrant() -> None:
    policy = _policy()
    warrant = _decision(policy).to_warrant(
        policy=policy, runtime_id="runtime-1", epoch=7, now=NOW
    )

    verify_warrant(
        warrant,
        execution_id="exec-1",
        agent_id="agent-1",
        policy_id=policy.policy_id,
        policy_digest=policy.digest,
        runtime_id="runtime-1",
        epoch=7,
        now=NOW + timedelta(minutes=1),
    )


@pytest.mark.parametrize("field", ["policy_id", "policy_digest"])
def test_external_authorization_cannot_widen_local_policy(field: str) -> None:
    policy = _policy()
    decision = _decision(policy)
    values = decision.__dict__.copy()
    values[field] = "different"
    mismatched = ExternalAuthorizationDecision(**values)
    with pytest.raises(ValueError, match=field):
        mismatched.to_warrant(policy=policy, runtime_id="runtime-1", epoch=0, now=NOW)


def test_external_authorization_cannot_supply_evidence_or_enforcement() -> None:
    policy = _policy()
    document = {
        "schema_version": "warrantkit.external-authorization/v1",
        "decision_id": "decision-1",
        "issuer": "external-idp",
        "subject_agent_id": "agent-1",
        "subject_execution_id": "exec-1",
        "policy_id": policy.policy_id,
        "policy_digest": policy.digest,
        "capabilities": ["read"],
        "constraints": {},
        "issued_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=5)).isoformat(),
        "decision": "allow",
    }
    warrant = import_authorization(
        document, policy=policy, runtime_id="runtime-1", epoch=2, now=NOW
    )
    assert "evidence" not in warrant.authority.__dict__
    assert not hasattr(warrant, "enforcement")


def test_deny_decision_fails_closed() -> None:
    policy = _policy()
    decision = _decision(policy)
    values = decision.__dict__.copy()
    values["decision"] = "deny"
    with pytest.raises(ValueError, match="allow"):
        ExternalAuthorizationDecision(**values)


def test_external_authorization_constraints_fail_closed_without_policy_contract() -> None:
    policy = _policy()
    decision = ExternalAuthorizationDecision(
        decision_id="decision-constraints",
        issuer="external-idp",
        subject_agent_id="agent-1",
        subject_execution_id="exec-constraints",
        policy_id=policy.policy_id,
        policy_digest=policy.digest,
        capabilities=("read",),
        constraints=(("resource", "production"),),
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )
    with pytest.raises(ValueError, match="constraint semantics"):
        decision.to_warrant(policy=policy, runtime_id="runtime-1", epoch=1, now=NOW)


def test_external_authorization_cannot_grant_capability_outside_policy() -> None:
    policy = Policy("production", capabilities=("read",))
    decision = ExternalAuthorizationDecision(
        decision_id="decision-2",
        issuer="external-idp",
        subject_agent_id="agent-1",
        subject_execution_id="exec-2",
        policy_id=policy.policy_id,
        policy_digest=policy.digest,
        capabilities=("read", "write"),
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )
    with pytest.raises(ValueError, match="write"):
        decision.to_warrant(policy=policy, runtime_id="runtime-1", epoch=1, now=NOW)


def test_external_authorization_cannot_extend_validity_window() -> None:
    policy = _policy()
    decision = _decision(policy)
    with pytest.raises(ValueError, match="extend external authorization"):
        decision.to_warrant(
            policy=policy,
            runtime_id="runtime-1",
            epoch=1,
            expires_at=NOW + timedelta(minutes=10),
            now=NOW,
        )


def test_external_authorization_cannot_backdate_warrant_before_issuance() -> None:
    policy = _policy()
    decision = _decision(policy)
    with pytest.raises(ValueError, match="precede external authorization"):
        decision.to_warrant(
            policy=policy,
            runtime_id="runtime-1",
            epoch=1,
            issued_at=NOW - timedelta(minutes=1),
            now=NOW,
        )


def test_direct_conversion_rejects_expired_external_authorization() -> None:
    policy = _policy()
    decision = _decision(policy)
    with pytest.raises(ValueError, match="external authorization is expired"):
        decision.to_warrant(
            policy=policy,
            runtime_id="runtime-1",
            epoch=1,
            now=NOW + timedelta(minutes=5),
        )


def test_direct_conversion_rejects_not_yet_valid_external_authorization() -> None:
    policy = _policy()
    decision = _decision(policy)
    with pytest.raises(ValueError, match="external authorization is not yet valid"):
        decision.to_warrant(
            policy=policy,
            runtime_id="runtime-1",
            epoch=1,
            now=NOW - timedelta(seconds=1),
        )


@pytest.mark.parametrize("field", ["issued_at", "expires_at"])
def test_external_authorization_rejects_timezone_without_utc_offset(field: str) -> None:
    policy = _policy()
    values = _decision(policy).__dict__.copy()
    values[field] = datetime(2026, 1, 1, tzinfo=MissingOffsetTimezone())

    with pytest.raises(ValueError, match=f"{field} must be timezone-aware"):
        ExternalAuthorizationDecision(**values)
