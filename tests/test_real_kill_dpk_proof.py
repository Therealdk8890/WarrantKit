from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from agentcontain import incident_bundle
from tools.run_real_kill_dpk_proof import _build_dpk_document, _validate_execution_trace, _verify_cases
from tools.verify_real_kill_dpk_proof import verify_real_kill_dpk_proof


ROOT = Path(__file__).parents[1]
RUNTIME_FIXTURE = ROOT / "tests" / "fixtures" / "runtime_pinned_evidence.json"


def _valid_execution_trace() -> dict:
    execution_id = "exec-proof-test"
    runtime_id = "runtime-proof-test"
    return {
        "schema_version": "warrantkit.real-kill-execution-trace/v1",
        "execution_id": execution_id,
        "runtime_id": runtime_id,
        "epoch_before": 0,
        "epoch_after": 1,
        "events": [
            {"name": "warrant_validated", "execution_id": execution_id, "runtime_id": runtime_id, "warrant_id": "w-1", "epoch": 0},
            {"name": "gateway_action_executed", "execution_id": execution_id, "runtime_id": runtime_id, "epoch": 0, "action_id": "a-1", "executor_action_ids": ["a-1"], "gateway_result": {"status": "executed"}},
            {"name": "containment_completed", "execution_id": execution_id, "runtime_id": runtime_id, "epoch_before": 0, "epoch_after": 1, "complete": True, "external_verified": True},
            {"name": "stale_authority_rejected", "execution_id": execution_id, "runtime_id": runtime_id, "warrant_epoch": 0, "current_epoch": 1, "reason": "warrant epoch does not match current runtime epoch"},
            {"name": "stale_action_rejected", "execution_id": execution_id, "runtime_id": runtime_id, "current_epoch": 1, "executor_called": False, "reason": "agent runtime is not executable"},
            {"name": "runtime_terminal_state_observed", "execution_id": execution_id, "runtime_id": runtime_id, "epoch": 1, "runtime_state": "TERMINATED", "cgroup_populated": False, "workload_exit_code": -9, "workload_uid": 65534, "observation_source": "linux_cgroup_supervisor_and_child_wait"},
        ],
    }


def _signed_fixture(
    tmp_path: Path,
    monkeypatch,
    runtime_override: bytes | None = None,
) -> tuple[Path, Path, Path, str, str, bytes]:
    from dprovenancekit.attestation import SoftwareTraceAttestationKey, key_id_for_public_key_x963

    runtime_bytes = runtime_override if runtime_override is not None else RUNTIME_FIXTURE.read_bytes()
    runtime = json.loads(runtime_bytes)
    execution_id = runtime["execution"]["execution_id"]
    runtime_id = runtime["execution"]["runtime_id"]
    manifest_bytes = b'{"incident_id":"INC-fixture"}\n'
    runtime_path = tmp_path / "runtime-evidence.json"
    runtime_path.write_bytes(runtime_bytes)
    bundle = tmp_path / "incident-bundle"
    bundle.mkdir()
    (bundle / "manifest.json").write_bytes(manifest_bytes)
    (bundle / "runtime-evidence.json").write_bytes(runtime_bytes)

    key = SoftwareTraceAttestationKey()
    trusted_key_id = key_id_for_public_key_x963(key.public_key_x963_representation)
    monkeypatch.setenv("WARRANTKIT_DPK_TRUSTED_KEY_ID", trusted_key_id)
    key_b64 = base64.b64encode(key.raw_representation).decode("ascii")
    trace_data = {
        "execution_id": execution_id,
        "agent_id": runtime["execution"]["agent_id"],
        "runtime_id": runtime_id,
        "epoch_before": 0,
        "epoch_after": 1,
        "events": [
            {
                "name": "evidence_artifacts_bound",
                "observed_at_unix_microseconds": 1,
                "execution_id": execution_id,
                "runtime_id": runtime_id,
                "runtime_evidence_sha256": "sha256:" + hashlib.sha256(runtime_bytes).hexdigest(),
                "incident_bundle_manifest_sha256": "sha256:" + hashlib.sha256(manifest_bytes).hexdigest(),
            }
        ],
    }
    _, document, _ = _build_dpk_document(trace_data, key_b64)
    attestation_path = tmp_path / "dpk-attestation.json"
    attestation_path.write_bytes(document.json_bytes(pretty=True))
    trusted_public_key_b64 = base64.b64encode(b"t" * 32).decode("ascii")
    return attestation_path, runtime_path, bundle, trusted_key_id, trusted_public_key_b64, manifest_bytes


def test_trace_validation_requires_ordered_success_facts() -> None:
    trace = _valid_execution_trace()
    assert _validate_execution_trace(trace) == [event["name"] for event in trace["events"]]

    broken = _valid_execution_trace()
    broken["events"][2]["external_verified"] = False
    with pytest.raises(RuntimeError, match="completed external epoch transition"):
        _validate_execution_trace(broken)


@pytest.mark.parametrize(
    ("event_index", "field", "value"),
    [
        (1, "name", "containment_completed"),
        (2, "complete", False),
        (3, "current_epoch", 0),
        (4, "executor_called", True),
        (5, "cgroup_populated", True),
    ],
)
def test_trace_validation_rejects_missing_or_contradictory_facts(event_index, field, value) -> None:
    trace = _valid_execution_trace()
    trace["events"][event_index][field] = value
    with pytest.raises(RuntimeError):
        _validate_execution_trace(trace)


def test_dpk_cases_reject_wrong_key_and_tampering(monkeypatch) -> None:
    from dprovenancekit.attestation import SoftwareTraceAttestationKey, key_id_for_public_key_x963

    key = SoftwareTraceAttestationKey()
    trusted_key_id = key_id_for_public_key_x963(key.public_key_x963_representation)
    monkeypatch.setenv("WARRANTKIT_DPK_TRUSTED_KEY_ID", trusted_key_id)
    _, document, _ = _build_dpk_document(
        {"execution_id": "exec-test", "events": [{"name": "event", "observed_at_unix_microseconds": 1}]},
        base64.b64encode(key.raw_representation).decode("ascii"),
    )
    result = _verify_cases(document, trusted_key_id)
    assert result["valid_case"]["trust"] == "trustedKey"
    assert result["wrong_key_case"]["expected_rejection"] == "untrustedKey"
    assert result["tampered_trace_case"]["accepted"] is False


def test_bound_artifacts_verify_from_the_same_snapshotted_bytes(tmp_path, monkeypatch) -> None:
    attestation, runtime, bundle, key_id, public_key, manifest_bytes = _signed_fixture(tmp_path, monkeypatch)
    observed = {}

    def verify_bundle(snapshot, *, trusted_public_key_b64):
        observed["manifest"] = (snapshot / "manifest.json").read_bytes()
        observed["key"] = trusted_public_key_b64
        return {"status": "AUTHENTICATED", "authenticity": "trusted-anchor"}

    monkeypatch.setattr(incident_bundle, "verify_incident_bundle", verify_bundle)
    result = verify_real_kill_dpk_proof(
        attestation_path=attestation,
        runtime_evidence_path=runtime,
        incident_bundle_dir=bundle,
        trusted_key_id=key_id,
        trusted_incident_public_key_b64=public_key,
    )
    assert result["dpk_verification"] == "trustedKey"
    assert result["runtime_evidence_verification"] == "OBSERVED"
    assert observed["manifest"] == manifest_bytes
    assert observed["key"] == public_key


@pytest.mark.parametrize("artifact", ["runtime", "manifest"])
def test_bound_artifact_tampering_fails_closed(tmp_path, monkeypatch, artifact) -> None:
    attestation, runtime, bundle, key_id, public_key, _ = _signed_fixture(tmp_path, monkeypatch)
    target = runtime if artifact == "runtime" else bundle / "manifest.json"
    target.write_bytes(target.read_bytes() + b"tampered")
    monkeypatch.setattr(
        incident_bundle,
        "verify_incident_bundle",
        lambda *_args, **_kwargs: {"status": "AUTHENTICATED", "authenticity": "trusted-anchor"},
    )
    with pytest.raises(ValueError, match="do not match the DPK-signed digest"):
        verify_real_kill_dpk_proof(
            attestation_path=attestation,
            runtime_evidence_path=runtime,
            incident_bundle_dir=bundle,
            trusted_key_id=key_id,
            trusted_incident_public_key_b64=public_key,
        )


def test_bound_artifacts_reject_wrong_trusted_key(tmp_path, monkeypatch) -> None:
    attestation, runtime, bundle, _key_id, public_key, _ = _signed_fixture(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="did not verify with the trusted key"):
        verify_real_kill_dpk_proof(
            attestation_path=attestation,
            runtime_evidence_path=runtime,
            incident_bundle_dir=bundle,
            trusted_key_id="f" * 64,
            trusted_incident_public_key_b64=public_key,
        )


def test_bound_artifacts_reject_a_tampered_persisted_attestation(tmp_path, monkeypatch) -> None:
    attestation, runtime, bundle, key_id, public_key, _ = _signed_fixture(tmp_path, monkeypatch)
    wire = json.loads(attestation.read_text(encoding="utf-8"))
    wire["trace"]["contextID"] = wire["trace"]["contextID"] + "-tampered"
    attestation.write_text(json.dumps(wire), encoding="utf-8")
    with pytest.raises(ValueError, match="did not verify with the trusted key"):
        verify_real_kill_dpk_proof(
            attestation_path=attestation,
            runtime_evidence_path=runtime,
            incident_bundle_dir=bundle,
            trusted_key_id=key_id,
            trusted_incident_public_key_b64=public_key,
        )


def test_bound_artifacts_reject_malformed_runtime_evidence(tmp_path, monkeypatch) -> None:
    runtime_doc = json.loads(RUNTIME_FIXTURE.read_text(encoding="utf-8"))
    runtime_doc["verification"]["status"] = "verified"
    runtime_bytes = (json.dumps(runtime_doc, sort_keys=True) + "\n").encode()
    attestation, runtime, bundle, key_id, public_key, _ = _signed_fixture(
        tmp_path,
        monkeypatch,
        runtime_override=runtime_bytes,
    )
    monkeypatch.setattr(
        incident_bundle,
        "verify_incident_bundle",
        lambda *_args, **_kwargs: {"status": "AUTHENTICATED", "authenticity": "trusted-anchor"},
    )
    with pytest.raises(ValueError, match="runtime evidence verification failed"):
        verify_real_kill_dpk_proof(
            attestation_path=attestation,
            runtime_evidence_path=runtime,
            incident_bundle_dir=bundle,
            trusted_key_id=key_id,
            trusted_incident_public_key_b64=public_key,
        )


def test_bound_artifacts_reject_bundle_integrity_without_trust(tmp_path, monkeypatch) -> None:
    attestation, runtime, bundle, key_id, public_key, _ = _signed_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(
        incident_bundle,
        "verify_incident_bundle",
        lambda *_args, **_kwargs: {"status": "INTEGRITY_ONLY", "authenticity": "bundle-key-integrity-only"},
    )
    with pytest.raises(ValueError, match="did not authenticate"):
        verify_real_kill_dpk_proof(
            attestation_path=attestation,
            runtime_evidence_path=runtime,
            incident_bundle_dir=bundle,
            trusted_key_id=key_id,
            trusted_incident_public_key_b64=public_key,
        )


def test_bound_artifacts_reject_malformed_persisted_attestation(tmp_path, monkeypatch) -> None:
    attestation, runtime, bundle, key_id, public_key, _ = _signed_fixture(tmp_path, monkeypatch)
    attestation.write_bytes(b"{")
    with pytest.raises(ValueError, match="persisted DPK attestation is malformed"):
        verify_real_kill_dpk_proof(
            attestation_path=attestation,
            runtime_evidence_path=runtime,
            incident_bundle_dir=bundle,
            trusted_key_id=key_id,
            trusted_incident_public_key_b64=public_key,
        )


def test_bound_artifacts_reject_missing_bundle_manifest(tmp_path, monkeypatch) -> None:
    attestation, runtime, bundle, key_id, public_key, _ = _signed_fixture(tmp_path, monkeypatch)
    (bundle / "manifest.json").unlink()
    with pytest.raises(ValueError, match="incident bundle manifest is missing"):
        verify_real_kill_dpk_proof(
            attestation_path=attestation,
            runtime_evidence_path=runtime,
            incident_bundle_dir=bundle,
            trusted_key_id=key_id,
            trusted_incident_public_key_b64=public_key,
        )
