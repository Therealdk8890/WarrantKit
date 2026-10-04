"""Adversarial coverage for the portable runtime evidence verifier."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).parents[1] / "tools" / "verify_runtime_evidence.py"
SPEC = importlib.util.spec_from_file_location("verify_runtime_evidence", MODULE_PATH)
assert SPEC and SPEC.loader
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


def make_evidence() -> dict:
    execution = {
        "execution_id": "exec-1",
        "agent_id": "agent-1",
        "policy_id": "policy-1",
        "policy_digest": "sha256:policy-1",
        "runtime_id": "runtime-1",
        "epoch": 7,
    }
    authority = {
        "runtime_id": "runtime-1",
        "agent_id": "agent-1",
        "epoch": 7,
        "execution_id": "exec-1",
        "policy_id": "policy-1",
        "policy_digest": "sha256:policy-1",
        "revoked": True,
        "revoked_at": "2026-01-01T00:00:00Z",
    }
    enforcement = {
        "runtime_id": "runtime-1",
        "agent_id": "agent-1",
        "epoch": 7,
        "action": "KILL",
        "external_boundary": True,
        "occurred_at": "2026-01-01T00:00:01Z",
    }
    observation = {
        "runtime_id": "runtime-1",
        "agent_id": "agent-1",
        "epoch": 7,
        "state": "TERMINATED",
        "can_execute": False,
        "observed_at": "2026-01-01T00:00:02Z",
    }
    binding = {
        "schema_version": verifier.BINDING_SCHEMA,
        "runtime_id": "runtime-1",
        "agent_id": "agent-1",
        "epoch": 7,
        "authority": {"record": authority, "digest": verifier.digest_record(authority)},
        "enforcement": {"record": enforcement, "digest": verifier.digest_record(enforcement)},
        "observation": {"record": observation, "digest": verifier.digest_record(observation)},
    }
    return {
        "schema_version": verifier.SCHEMA_VERSION,
        "execution": execution,
        "events": [{"execution_id": "exec-1", "epoch": 7, "sequence": 1}],
        "enforcement": {},
        "verification": {"status": "verified"},
        "proof": {"runtime_binding": binding},
        "receipt": {},
        "governance": {},
        "provenance": {},
        "external_evidence": {},
    }


def test_valid_runtime_evidence_verifies() -> None:
    verifier.verify(make_evidence())


@pytest.mark.parametrize("field", ["execution_id", "policy_id", "policy_digest"])
def test_authority_must_match_execution_identity(field: str) -> None:
    document = make_evidence()
    document["proof"]["runtime_binding"]["authority"]["record"][field] = "different"
    document["proof"]["runtime_binding"]["authority"]["digest"] = verifier.digest_record(
        document["proof"]["runtime_binding"]["authority"]["record"]
    )

    with pytest.raises(ValueError, match=f"authority {field} does not match execution"):
        verifier.verify(document)


def test_runtime_identity_must_match_execution() -> None:
    document = make_evidence()
    document["proof"]["runtime_binding"]["runtime_id"] = "runtime-2"

    with pytest.raises(ValueError, match="runtime binding runtime_id does not match execution"):
        verifier.verify(document)


def test_epoch_must_match_execution() -> None:
    document = make_evidence()
    document["proof"]["runtime_binding"]["epoch"] = 8

    with pytest.raises(ValueError, match="runtime binding epoch does not match execution"):
        verifier.verify(document)
