"""Issue #207: an unauthenticated external document cannot become accepted authority.

``import_authorization`` is structural only. These tests pin the supported
integration flow: structural import yields an *unsigned* Warrant, and the adapter
verifier accepts only Warrant attestations signed by a trusted controller key.
Unknown-key, altered-payload, missing-authentication and replay cases for the
authenticated import path live in ``test_signed_external_authorization.py``.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("cryptography")

from agentcontain import Policy, import_authorization  # noqa: E402
from agentcontain.attestation import Ed25519Signer, Ed25519Verifier  # noqa: E402

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _document(policy: Policy, issuer: str = "trusted-idp") -> dict:
    return {
        "schema_version": "warrantkit.external-authorization/v1",
        "decision_id": "decision-207",
        "issuer": issuer,
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


def _policy() -> Policy:
    return Policy("production", capabilities=("read",))


def test_structural_import_accepts_any_issuer_text_so_it_is_not_authentication():
    # A forged issuer string passes the structural converter: that is exactly why
    # the result must never be treated as an authenticated provider decision.
    policy = _policy()
    warrant = import_authorization(
        _document(policy, issuer="definitely-not-the-real-idp"),
        policy=policy, runtime_id="runtime-1", epoch=1, now=NOW,
    )
    assert warrant.issuer == "definitely-not-the-real-idp"


def test_structural_import_yields_no_attestation_the_adapter_verifier_accepts():
    policy = _policy()
    warrant = import_authorization(
        _document(policy), policy=policy, runtime_id="runtime-1", epoch=1, now=NOW,
    )
    controller = Ed25519Signer.generate("controller-key")
    verifier = Ed25519Verifier({"controller-key": controller.public_key()})

    # The raw Warrant is not an attestation envelope.
    with pytest.raises((TypeError, ValueError, KeyError)):
        verifier.verify_warrant(warrant.to_dict())

    # An attacker who signs the imported Warrant with their own key is rejected.
    attacker = Ed25519Signer.generate("controller-key")
    forged = attacker.sign_warrant(warrant, issued_at=NOW)
    with pytest.raises(ValueError, match="invalid attestation signature"):
        verifier.verify_warrant(forged)

    # An unknown key id is rejected before any signature check.
    stranger = Ed25519Signer.generate("unknown-key")
    with pytest.raises(ValueError, match="unknown attestation key_id"):
        verifier.verify_warrant(stranger.sign_warrant(warrant, issued_at=NOW))

    # Only the trusted controller key produces an attestation the adapter accepts.
    accepted = verifier.verify_warrant(controller.sign_warrant(warrant, issued_at=NOW))
    assert accepted == warrant
