from datetime import datetime, timedelta, timezone

import pytest

from agentcontain import Policy, import_authorization


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _document(policy):
    return {
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


@pytest.mark.parametrize("value", [None, 7, True, ["not-a-string"]])
def test_import_rejects_non_string_identity_fields(value):
    policy = Policy("production", capabilities=("read",))
    document = _document(policy)
    document["issuer"] = value
    with pytest.raises(ValueError, match="issuer must be a non-empty string"):
        import_authorization(document, policy=policy, runtime_id="runtime-1", epoch=0, now=NOW)


@pytest.mark.parametrize("value", ["read", 7, None, ["read", 3], [""]])
def test_import_rejects_malformed_capabilities(value):
    policy = Policy("production", capabilities=("read",))
    document = _document(policy)
    document["capabilities"] = value
    with pytest.raises(ValueError, match="capabilities must be a list"):
        import_authorization(document, policy=policy, runtime_id="runtime-1", epoch=0, now=NOW)


@pytest.mark.parametrize("value", [[], "resource=production", {"resource": 3}, {3: "production"}, None])
def test_import_rejects_malformed_constraints(value):
    policy = Policy("production", capabilities=("read",))
    document = _document(policy)
    document["constraints"] = value
    with pytest.raises(ValueError, match="constraints must be an object"):
        import_authorization(document, policy=policy, runtime_id="runtime-1", epoch=0, now=NOW)


@pytest.mark.parametrize("value", [None, 123, True, "not-a-timestamp"])
def test_import_rejects_malformed_timestamps(value):
    policy = Policy("production", capabilities=("read",))
    document = _document(policy)
    document["issued_at"] = value
    expected = "issued_at must be a non-empty string" if not isinstance(value, str) else "valid ISO-8601 strings"
    with pytest.raises(ValueError, match=expected):
        import_authorization(document, policy=policy, runtime_id="runtime-1", epoch=0, now=NOW)
