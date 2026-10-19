from datetime import datetime, timedelta, timezone

import pytest

from agentcontain import ExecutionIdentity, Policy
from agentcontain.warrant import EvidenceRequirements, RevocationState, Warrant, verify_warrant




from datetime import tzinfo


class _NoOffsetTimezone(tzinfo):
    def utcoffset(self, dt):
        return None

    def dst(self, dt):
        return None

    def tzname(self, dt):
        return "no-offset"


def _warrant(epoch: int = 0) -> Warrant:
    policy = Policy("production", capabilities=("read",))
    identity = ExecutionIdentity.create("agent-1", policy.policy_id, policy.digest, epoch=epoch, runtime_id="runtime-1")
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return Warrant.issue(
        warrant_id="w-1", issuer="controller", agent_id=identity.agent_id,
        execution_id=identity.execution_id, policy=policy, runtime_id="runtime-1",
        epoch=identity.epoch, issued_at=now, expires_at=now + timedelta(minutes=5),
        capabilities=("read",),
        evidence_requirements=EvidenceRequirements(
            enforcement=("kill",), observation=("exit",), verification=("receipt",)
        ),
    )


def _verify(warrant: Warrant, **overrides) -> None:
    values = {
        "execution_id": warrant.subject.execution_id,
        "agent_id": warrant.subject.agent_id,
        "policy_id": warrant.authority.policy_id,
        "policy_digest": warrant.authority.policy_digest,
        "runtime_id": warrant.runtime.runtime_id,
        "epoch": warrant.runtime.epoch,
        "now": datetime(2026, 1, 1, 0, 1, tzinfo=timezone.utc),
    }
    values.update(overrides)
    verify_warrant(warrant, **values)


def test_warrant_binds_identity_policy_and_epoch() -> None:
    _verify(_warrant())


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("execution_id", "other", "execution_id"),
        ("agent_id", "other", "agent_id"),
        ("policy_id", "other", "policy_id"),
        ("policy_digest", "other", "policy_digest"),
        ("runtime_id", "other-runtime", "runtime_id"),
        ("epoch", 1, "epoch"),
    ],
)
def test_warrant_rejects_binding_mismatch(field, value, match) -> None:
    warrant = _warrant()
    with pytest.raises(ValueError, match=match):
        _verify(warrant, **{field: value})


def test_stale_epoch_requires_fresh_warrant() -> None:
    old = _warrant(epoch=0)
    with pytest.raises(ValueError, match="epoch"):
        _verify(old, epoch=1)

    fresh = Warrant.issue(
        warrant_id="w-2", issuer="controller", agent_id=old.subject.agent_id,
        execution_id=old.subject.execution_id, policy=Policy("production", capabilities=("read",)),
        runtime_id="runtime-1", epoch=1,
        issued_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        expires_at=datetime(2026, 1, 1, 0, 5, tzinfo=timezone.utc),
    )
    _verify(fresh)


def test_revocation_and_expiry_fail_closed() -> None:
    revoked = _warrant().revoke(revoked_at=datetime(2026, 1, 1, 0, 2, tzinfo=timezone.utc))
    assert revoked.lifecycle.state == RevocationState.REVOKED
    with pytest.raises(ValueError, match="revoked"):
        _verify(revoked)

    with pytest.raises(ValueError, match="expired"):
        _verify(_warrant(), now=datetime(2026, 1, 1, 0, 6, tzinfo=timezone.utc))


def test_warrant_round_trip_keeps_evidence_out_of_authority() -> None:
    warrant = _warrant()
    restored = Warrant.from_dict(warrant.to_dict())
    assert restored == warrant
    assert "evidence" not in restored.to_dict()["authority"]


def test_allowed_egress_is_not_promoted_to_warrant_authority() -> None:
    policy = Policy(
        "production",
        allowed_egress=("api.example.com:443",),
        capabilities=("read",),
    )
    identity = ExecutionIdentity.create(
        "agent-1",
        policy.policy_id,
        policy.digest,
        runtime_id="runtime-1",
    )
    warrant = Warrant.issue(
        warrant_id="w-egress",
        issuer="controller",
        agent_id=identity.agent_id,
        execution_id=identity.execution_id,
        policy=policy,
        runtime_id=identity.runtime_id,
        epoch=identity.epoch,
        issued_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        expires_at=datetime(2026, 1, 1, 0, 5, tzinfo=timezone.utc),
        capabilities=("read",),
    )

    assert "allowed_egress" not in warrant.to_dict()["authority"]
    assert policy.allowed_egress == ("api.example.com:443",)


def test_warrant_issue_rejects_capabilities_not_granted_by_policy() -> None:
    policy = Policy("production", capabilities=("read",))
    identity = ExecutionIdentity.create(
        "agent-1", policy.policy_id, policy.digest, runtime_id="runtime-1"
    )
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="exceed accepted policy"):
        Warrant.issue(
            warrant_id="w-escalated", issuer="controller",
            agent_id=identity.agent_id, execution_id=identity.execution_id,
            policy=policy, runtime_id="runtime-1", epoch=0,
            issued_at=now, expires_at=now + timedelta(minutes=5),
            capabilities=("read", "write"),
        )


def test_warrant_issue_rejects_unsupported_constraints() -> None:
    policy = Policy("production", capabilities=("read",))
    identity = ExecutionIdentity.create(
        "agent-1", policy.policy_id, policy.digest, runtime_id="runtime-1"
    )
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="constraint semantics"):
        Warrant.issue(
            warrant_id="w-constrained", issuer="controller",
            agent_id=identity.agent_id, execution_id=identity.execution_id,
            policy=policy, runtime_id="runtime-1", epoch=0,
            issued_at=now, expires_at=now + timedelta(minutes=5),
            capabilities=("read",), constraints=(("resource", "production"),),
        )


def test_verifier_rejects_serialized_warrant_with_unsupported_constraints() -> None:
    document = _warrant().to_dict()
    document["authority"]["constraints"] = {"resource": "production"}
    constrained = Warrant.from_dict(document)
    with pytest.raises(ValueError, match="constraint semantics"):
        _verify(constrained)


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda doc: doc["authority"].pop("capabilities"), "authority has an invalid shape"),
        (lambda doc: doc["subject"].update(extra="ignored"), "subject has an invalid shape"),
        (lambda doc: doc["authority"].update(constraints={"resource": 7}), "string-to-string mapping"),
        (lambda doc: doc["authority"].update(capabilities="read"), "list of non-empty strings"),
        (lambda doc: doc["runtime"].update(epoch=True), "non-negative integer"),
        (lambda doc: doc["validity"].update(issued_at=123), "ISO-8601 string"),
        (lambda doc: doc["lifecycle"].update(state="revoked", revoked_at="2026-01-01T00:02:00"), "timezone-aware"),
        (lambda doc: doc["evidence_requirements"].pop("verification"), "evidence_requirements has an invalid shape"),
    ],
)
def test_from_dict_rejects_malformed_nested_schema(mutate, match) -> None:
    document = _warrant().to_dict()
    mutate(document)
    with pytest.raises((TypeError, ValueError), match=match):
        Warrant.from_dict(document)


def test_warrant_rejects_timezone_object_without_utc_offset() -> None:
    policy = Policy("production", capabilities=("read",))
    identity = ExecutionIdentity.create(
        "agent-1", policy.policy_id, policy.digest, epoch=0, runtime_id="runtime-1"
    )
    invalid_time = datetime(2026, 1, 1, tzinfo=_NoOffsetTimezone())
    with pytest.raises(ValueError, match="timezone-aware"):
        Warrant.issue(
            warrant_id="w-invalid-time", issuer="controller",
            agent_id=identity.agent_id, execution_id=identity.execution_id,
            policy=policy, runtime_id="runtime-1", epoch=0,
            issued_at=invalid_time,
            expires_at=datetime(2026, 1, 1, 0, 5, tzinfo=timezone.utc),
            capabilities=("read",),
        )


def test_warrant_rejects_invalid_revocation_timestamp() -> None:
    warrant = _warrant()
    with pytest.raises(ValueError, match="revoked_at must be timezone-aware"):
        warrant.revoke(revoked_at=datetime(2026, 1, 1, tzinfo=_NoOffsetTimezone()))


def test_verifier_rejects_timezone_object_without_utc_offset() -> None:
    with pytest.raises(ValueError, match="verification time must be timezone-aware"):
        _verify(_warrant(), now=datetime(2026, 1, 1, tzinfo=_NoOffsetTimezone()))
