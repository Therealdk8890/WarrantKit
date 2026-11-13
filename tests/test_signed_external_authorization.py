"""Adversarial tests for the opt-in signed external authorization profile."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json

import pytest

pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from agentcontain import Policy  # noqa: E402
from agentcontain.signed_external_authorization import (  # noqa: E402
    ExternalDecisionAuthenticationError,
    SQLiteDecisionReplayStore,
    SIGNATURE_DOMAIN,
    import_signed_authorization,
)

NOW = datetime(2026, 11, 13, tzinfo=timezone.utc)


def signed_request(tmp_path, *, document_override=None):
    policy = Policy("production", capabilities=("read",))
    document = {
        "schema_version": "warrantkit.external-authorization/v1",
        "decision_id": "decision-007",
        "issuer": "trusted-idp",
        "audience": "my-control-plane",
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
    if document_override:
        document.update(document_override)
    signer = Ed25519PrivateKey.generate()
    data = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = signer.sign(SIGNATURE_DOMAIN + data)
    key = signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    kwargs = dict(
        signature=signature, trusted_public_key=key, expected_issuer="trusted-idp",
        expected_audience="my-control-plane", expected_agent_id="agent-1",
        expected_execution_id="exec-1",
        replay_store=SQLiteDecisionReplayStore(tmp_path / "replay.sqlite3"),
        policy=policy, runtime_id="runtime-1", epoch=7, now=NOW,
    )
    return data, kwargs, signer


def test_verified_signature_and_scope_issue_local_epoch_bound_warrant(tmp_path):
    data, kwargs, _ = signed_request(tmp_path)
    warrant = import_signed_authorization(data, **kwargs)
    assert warrant.runtime.epoch == 7
    assert warrant.subject.agent_id == "agent-1"


@pytest.mark.parametrize("field,value", [
    ("issuer", "forged-idp"),
    ("audience", "other-control-plane"),
    ("subject_agent_id", "other-agent"),
    ("subject_execution_id", "other-execution"),
])
def test_signed_but_wrong_scope_cannot_issue_warrant(tmp_path, field, value):
    data, kwargs, _ = signed_request(tmp_path, document_override={field: value})
    with pytest.raises(ExternalDecisionAuthenticationError, match="mismatch"):
        import_signed_authorization(data, **kwargs)


def test_plain_unscoped_ed25519_signature_is_rejected(tmp_path):
    data, kwargs, signer = signed_request(tmp_path)
    with pytest.raises(ExternalDecisionAuthenticationError, match="signature invalid"):
        import_signed_authorization(
            data, **{**kwargs, "signature": signer.sign(data)}
        )


def test_tampering_signature_and_unknown_trust_key_fail_closed(tmp_path):
    data, kwargs, _ = signed_request(tmp_path)
    tampered = data.replace(b"decision-007", b"decision-008")
    with pytest.raises(ExternalDecisionAuthenticationError, match="signature invalid"):
        import_signed_authorization(tampered, **kwargs)
    different_signer = Ed25519PrivateKey.generate()
    untrusted = different_signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    with pytest.raises(ExternalDecisionAuthenticationError, match="signature invalid"):
        import_signed_authorization(data, **{**kwargs, "trusted_public_key": untrusted})


@pytest.mark.parametrize("replacement,argument", [
    (b"", "signature"),
    (b"invalid", "signature"),
    (None, "trusted_public_key"),
])
def test_missing_or_invalid_authentication_material_denied(tmp_path, replacement, argument):
    data, kwargs, _ = signed_request(tmp_path)
    with pytest.raises(ExternalDecisionAuthenticationError):
        import_signed_authorization(data, **{**kwargs, argument: replacement})


def test_exact_signed_bytes_must_parse_strictly_and_reject_duplicate_keys(tmp_path):
    data, kwargs, signer = signed_request(tmp_path)
    malformed = data[:-1] + b',"issuer":"trusted-idp"}'
    with pytest.raises(ExternalDecisionAuthenticationError, match="strict JSON"):
        import_signed_authorization(
            malformed, **{**kwargs, "signature": signer.sign(SIGNATURE_DOMAIN + malformed)}
        )


def test_overlong_decision_and_expired_decision_fail_closed(tmp_path):
    data, kwargs, _ = signed_request(
        tmp_path, document_override={
            "expires_at": (NOW + timedelta(hours=1)).isoformat()
        }
    )
    with pytest.raises(ExternalDecisionAuthenticationError, match="lifetime"):
        import_signed_authorization(data, **kwargs)

    expired, args, _ = signed_request(
        tmp_path, document_override={
            "issued_at": (NOW - timedelta(minutes=10)).isoformat(),
            "expires_at": (NOW - timedelta(minutes=5)).isoformat(),
        }
    )
    with pytest.raises(ValueError, match="expired"):
        import_signed_authorization(expired, **args)


def test_local_policy_mismatch_never_consumes_identity_or_issues_authority(tmp_path):
    data, kwargs, _ = signed_request(
        tmp_path, document_override={"policy_digest": "0" * 64}
    )
    with pytest.raises(ValueError, match="policy_digest"):
        import_signed_authorization(data, **kwargs)


def test_replay_fence_survives_new_store_instances(tmp_path):
    data, kwargs, _ = signed_request(tmp_path)
    import_signed_authorization(data, **kwargs)
    new_store = SQLiteDecisionReplayStore(tmp_path / "replay.sqlite3")
    with pytest.raises(ExternalDecisionAuthenticationError, match="replay"):
        import_signed_authorization(data, **{**kwargs, "replay_store": new_store})


def test_concurrent_replay_allows_exactly_one_admission(tmp_path):
    data, kwargs, _ = signed_request(tmp_path)
    def attempt(_):
        try:
            import_signed_authorization(data, **kwargs)
            return True
        except ExternalDecisionAuthenticationError as exc:
            assert "replay" in str(exc)
            return False
    with ThreadPoolExecutor(max_workers=5) as executor:
        assert sum(executor.map(attempt, range(5))) == 1


def test_no_in_memory_or_relative_replay_store_for_authentication():
    for path in (":memory:", "replay.sqlite3"):
        with pytest.raises(ValueError, match="absolute and persistent"):
            SQLiteDecisionReplayStore(path)
