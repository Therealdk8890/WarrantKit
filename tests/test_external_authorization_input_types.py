from datetime import timedelta

import pytest

from agentcontain import Policy, import_authorization

from test_external_authorization import NOW, _policy


def test_import_rejects_capabilities_string():
    policy = _policy()
    document = {
        "schema_version": "warrantkit.external-authorization/v1",
        "decision_id": "decision-1",
        "issuer": "external-idp",
        "subject_agent_id": "agent-1",
        "subject_execution_id": "exec-1",
        "policy_id": policy.policy_id,
        "policy_digest": policy.digest,
        "capabilities": "read",
        "constraints": {},
        "issued_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=5)).isoformat(),
        "decision": "allow",
    }
    with pytest.raises(ValueError, match="capabilities must be a list"):
        import_authorization(document, policy=policy, runtime_id="runtime-1", epoch=0, now=NOW)
