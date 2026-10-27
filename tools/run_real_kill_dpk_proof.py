#!/usr/bin/env python3
"""Run the Linux cgroup proof and sign its observed execution trace with DPK."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"REJECTED: set {name} in the DPK signing configuration")
    return value


def _required_dpk_signing_key() -> str:
    key_path_value = os.environ.get("WARRANTKIT_DPK_SIGNING_KEY_FILE")
    if not key_path_value:
        return _required_env("WARRANTKIT_DPK_SIGNING_KEY_B64")
    key_path = Path(key_path_value)
    if key_path.is_symlink() or not key_path.is_file():
        raise SystemExit("REJECTED: DPK signing-key file is missing or not a regular file")
    if stat.S_IMODE(key_path.stat().st_mode) & 0o077:
        raise SystemExit("REJECTED: DPK signing-key file must be owner-only")
    try:
        value = key_path.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as exc:
        raise SystemExit("REJECTED: DPK signing-key file could not be read") from exc
    if not value:
        raise SystemExit("REJECTED: DPK signing-key file is empty")
    return value


def _build_dpk_document(execution_trace: dict[str, Any], signing_key_b64: str):
    from dprovenancekit.attestation import (
        AttestableTrace,
        AttestableTraceEvent,
        SoftwareTraceAttestationKey,
        TraceAttestationDocument,
        attest,
    )

    execution_id = execution_trace["execution_id"]
    run_id = uuid.uuid5(uuid.NAMESPACE_URL, f"warrantkit-real-kill:{execution_id}")
    context_id = execution_id
    events = []
    for sequence, record in enumerate(execution_trace["events"]):
        event_id = uuid.uuid5(run_id, f"event:{sequence}:{record['name']}")
        payload_json = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        events.append(
            AttestableTraceEvent(
                id=event_id,
                run_id=run_id,
                context_id=context_id,
                engine_name="WarrantKitRealKillProof",
                schema_version=1,
                sequence=sequence,
                span_id=None,
                parent_span_id=None,
                type_identifier=record["name"],
                priority=100,
                payload_json=payload_json,
                timestamp_unix_microseconds=record["observed_at_unix_microseconds"],
            )
        )
    trace = AttestableTrace(run_id=run_id, context_id=context_id, events=tuple(events))
    raw_key = base64.b64decode(signing_key_b64, validate=True)
    key = SoftwareTraceAttestationKey.from_raw_representation(raw_key)
    expected_key_id = _required_env("WARRANTKIT_DPK_TRUSTED_KEY_ID")
    from dprovenancekit.attestation import key_id_for_public_key_x963

    actual_key_id = key_id_for_public_key_x963(key.public_key_x963_representation)
    if actual_key_id != expected_key_id:
        raise SystemExit(
            "REJECTED: DPK signer key ID does not match the configured trusted key ID"
        )
    document = TraceAttestationDocument(trace=trace, attestation=attest(trace, key))
    return trace, document, expected_key_id


def _verify_cases(document, trusted_key_id: str) -> dict[str, Any]:
    from dprovenancekit.attestation import TraceAttestationDocument

    trusted = document.verify(trusted_key_ids=[trusted_key_id])
    if not trusted.is_valid or trusted.trust.value != "trustedKey":
        raise RuntimeError(f"trusted-key verification failed: {trusted.failure}")

    wrong_key_id = "f" * 64 if trusted_key_id != "f" * 64 else "0" * 64
    wrong_key = document.verify(trusted_key_ids=[wrong_key_id])
    if wrong_key.is_valid or wrong_key.failure.value != "untrustedKey":
        raise RuntimeError("DPK verifier did not reject the incorrect trusted key ID")

    wire = document.to_wire()
    first_event = wire["trace"]["events"][0]
    payload = json.loads(first_event["payloadJSON"])
    payload["tamper_probe"] = True
    first_event["payloadJSON"] = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    tampered = TraceAttestationDocument.from_wire(wire)
    tamper_result = tampered.verify(trusted_key_ids=[trusted_key_id])
    if tamper_result.is_valid or tamper_result.failure is None:
        raise RuntimeError("DPK verifier accepted a modified signed trace")

    return {
        "valid_case": {
            "accepted": trusted.is_valid,
            "trust": trusted.trust.value,
            "key_id": trusted.key_id,
        },
        "wrong_key_case": {
            "accepted": wrong_key.is_valid,
            "expected_rejection": wrong_key.failure.value,
            "attempted_key_id": wrong_key_id,
        },
        "tampered_trace_case": {
            "accepted": tamper_result.is_valid,
            "expected_rejection": tamper_result.failure.value if tamper_result.failure else "invalid",
        },
    }


def _validate_execution_trace(execution_trace: dict[str, Any]) -> list[str]:
    if not isinstance(execution_trace, dict):
        raise RuntimeError("execution trace must be a JSON object")
    if execution_trace.get("schema_version") != "warrantkit.real-kill-execution-trace/v1":
        raise RuntimeError("unexpected WarrantKit execution trace schema")

    events = execution_trace.get("events")
    expected_order = [
        "warrant_validated",
        "gateway_action_executed",
        "containment_completed",
        "stale_authority_rejected",
        "stale_action_rejected",
        "runtime_terminal_state_observed",
    ]
    if not isinstance(events, list) or any(not isinstance(event, dict) for event in events):
        raise RuntimeError("execution trace events must be a list of objects")
    names = [event.get("name") for event in events]
    if names != expected_order:
        raise RuntimeError(f"execution trace event order is invalid: {names!r}")

    execution_id = execution_trace.get("execution_id")
    runtime_id = execution_trace.get("runtime_id")
    if not isinstance(execution_id, str) or not execution_id:
        raise RuntimeError("execution trace has no execution ID")
    if not isinstance(runtime_id, str) or not runtime_id:
        raise RuntimeError("execution trace has no runtime ID")

    epoch_before = execution_trace.get("epoch_before")
    epoch_after = execution_trace.get("epoch_after")
    if type(epoch_before) is not int or epoch_before < 0:
        raise RuntimeError("execution trace has an invalid pre-containment epoch")
    if type(epoch_after) is not int or epoch_after <= epoch_before:
        raise RuntimeError("execution trace does not show an epoch transition")

    for event in events:
        if event.get("execution_id") != execution_id or event.get("runtime_id") != runtime_id:
            raise RuntimeError("execution trace event identity does not match its execution")

    warrant = events[0]
    gateway = events[1]
    containment = events[2]
    stale_authority = events[3]
    stale_action = events[4]
    terminal = events[5]

    if (
        type(warrant.get("epoch")) is not int
        or warrant.get("epoch") != epoch_before
        or not isinstance(warrant.get("warrant_id"), str)
        or not warrant["warrant_id"]
    ):
        raise RuntimeError("Warrant validation event does not bind the pre-containment authority")
    action_id = gateway.get("action_id")
    if (
        type(gateway.get("epoch")) is not int
        or gateway.get("epoch") != epoch_before
        or not isinstance(action_id, str)
        or not action_id
        or gateway.get("executor_action_ids") != [action_id]
    ):
        raise RuntimeError("gateway event does not show exactly one executed action at the pre-containment epoch")
    if not isinstance(gateway.get("gateway_result"), dict) or gateway["gateway_result"].get("status") != "executed":
        raise RuntimeError("gateway event does not record a successful gateway result")

    if (
        type(containment.get("epoch_before")) is not int
        or type(containment.get("epoch_after")) is not int
        or containment.get("epoch_before") != epoch_before
        or containment.get("epoch_after") != epoch_after
        or containment.get("complete") is not True
        or containment.get("external_verified") is not True
    ):
        raise RuntimeError("containment event does not prove a completed external epoch transition")
    if (
        type(stale_authority.get("warrant_epoch")) is not int
        or type(stale_authority.get("current_epoch")) is not int
        or stale_authority.get("warrant_epoch") != epoch_before
        or stale_authority.get("current_epoch") != epoch_after
        or stale_authority.get("reason") != "warrant epoch does not match current runtime epoch"
    ):
        raise RuntimeError("stale-authority event does not prove pre-transition Warrant rejection")
    if (
        type(stale_action.get("current_epoch")) is not int
        or stale_action.get("current_epoch") != epoch_after
        or stale_action.get("executor_called") is not False
        or stale_action.get("reason") != "agent runtime is not executable"
    ):
        raise RuntimeError("post-containment gateway denial did not prevent executor invocation")
    if type(terminal.get("epoch")) is not int or terminal.get("epoch") != epoch_after or terminal.get("runtime_state") != "TERMINATED":
        raise RuntimeError("terminal observation does not match the post-containment runtime")
    if terminal.get("cgroup_populated") is not False:
        raise RuntimeError("terminal observation does not show an empty cgroup")
    exit_code = terminal.get("workload_exit_code")
    if type(exit_code) is not int or exit_code != -9:
        raise RuntimeError("terminal observation does not show SIGKILL termination")
    if type(terminal.get("workload_uid")) is not int or terminal["workload_uid"] == 0:
        raise RuntimeError("terminal observation does not identify an unprivileged workload")
    if terminal.get("observation_source") != "linux_cgroup_supervisor_and_child_wait":
        raise RuntimeError("terminal observation source is invalid")
    return names


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("real-kill-dpk-proof"))
    args = parser.parse_args()

    signing_key_b64 = _required_dpk_signing_key()
    trusted_key_id = _required_env("WARRANTKIT_DPK_TRUSTED_KEY_ID")
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    bundle_dir = output_dir / "incident-bundle"
    runtime_evidence = output_dir / "runtime-evidence.json"
    execution_trace_path = output_dir / "execution-trace.json"
    env = os.environ.copy()
    # The DPK signer belongs only to this controller process. The demo needs
    # the protected key-file path for its unprivileged-access probe, not the
    # private-key value itself.
    env.pop("WARRANTKIT_DPK_SIGNING_KEY_B64", None)
    env["WARRANTKIT_REAL_KILL_ARTIFACT"] = str(runtime_evidence)
    env["WARRANTKIT_EXECUTION_TRACE_ARTIFACT"] = str(execution_trace_path)
    env["WARRANTKIT_INCIDENT_BUNDLE_DIR"] = str(bundle_dir)

    runner = Path(__file__).with_name("run_real_kill_demo.py")
    result = subprocess.run([sys.executable, str(runner)], env=env, check=False)
    if result.returncode:
        return result.returncode

    incident_trusted_public_key = (
        os.environ.get("WARRANTKIT_TRUSTED_PUBLIC_KEY_B64")
        or os.environ.get("WARRANTKIT_CI_TRUSTED_PUBLIC_KEY_B64")
    )
    if not incident_trusted_public_key:
        raise SystemExit(
            "REJECTED: configure WARRANTKIT_TRUSTED_PUBLIC_KEY_B64 to authenticate the incident bundle"
        )
    incident_verify = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).with_name("verify_incident_bundle.py")),
            str(bundle_dir),
            "--trusted-public-key",
            incident_trusted_public_key,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    incident_verification = incident_verify.stdout.strip()
    if incident_verify.returncode or not incident_verification.startswith("AUTHENTICATED:"):
        raise RuntimeError(
            "incident bundle did not authenticate with the configured Ed25519 key: "
            + (incident_verify.stderr.strip() or incident_verification)
        )

    runtime_verify = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).with_name("verify_runtime_evidence.py")),
            str(runtime_evidence),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    runtime_verification = runtime_verify.stdout.strip()
    if runtime_verify.returncode or not runtime_verification:
        raise RuntimeError(
            "portable runtime evidence verification failed: "
            + (runtime_verify.stderr.strip() or runtime_verification)
        )

    try:
        execution_trace = json.loads(execution_trace_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"execution trace is unavailable or malformed: {exc}") from exc
    names = _validate_execution_trace(execution_trace)

    runtime_evidence_bytes = runtime_evidence.read_bytes()
    bundle_manifest_bytes = (bundle_dir / "manifest.json").read_bytes()
    execution_trace["events"].append({
        "name": "evidence_artifacts_bound",
        "observed_at_unix_microseconds": max(
            event["observed_at_unix_microseconds"] for event in execution_trace["events"]
        ) + 1,
        "execution_id": execution_trace["execution_id"],
        "runtime_id": execution_trace["runtime_id"],
        "runtime_evidence_sha256": "sha256:" + _sha256(runtime_evidence_bytes),
        "incident_bundle_manifest_sha256": "sha256:" + _sha256(bundle_manifest_bytes),
        "runtime_evidence_verification": runtime_verification,
        "incident_bundle_verification": incident_verification,
    })
    execution_trace_path.write_text(
        json.dumps(execution_trace, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    names = [event["name"] for event in execution_trace["events"]]

    trace, document, trusted_key_id = _build_dpk_document(execution_trace, signing_key_b64)
    attestation_path = output_dir / "dpk-attestation.json"
    attestation_path.write_bytes(document.json_bytes(pretty=True))
    (output_dir / "dpk-trace.json").write_text(
        json.dumps(trace.to_wire(), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    # Decode the saved bytes and use DProvenanceKit's verifier on the artifact
    # a reviewer receives, not only on the in-memory document.
    from dprovenancekit.attestation import TraceAttestationDocument

    try:
        attestation_bytes = attestation_path.read_bytes()
        exported_document = TraceAttestationDocument.decode_json(attestation_bytes)
    except Exception as exc:
        raise RuntimeError(f"persisted DPK attestation could not be read or decoded: {exc}") from exc
    cases = _verify_cases(exported_document, trusted_key_id)
    from verify_real_kill_dpk_proof import verify_real_kill_dpk_proof

    final_verification = verify_real_kill_dpk_proof(
        attestation_path=attestation_path,
        runtime_evidence_path=runtime_evidence,
        incident_bundle_dir=bundle_dir,
        trusted_key_id=trusted_key_id,
        trusted_incident_public_key_b64=incident_trusted_public_key,
    )
    report = {
        "schema_version": "warrantkit.dpk-real-kill-verification/v1",
        "run_id": str(trace.run_id),
        "context_id": trace.context_id,
        "execution_id": execution_trace["execution_id"],
        "agent_id": execution_trace["agent_id"],
        "runtime_id": execution_trace["runtime_id"],
        "epoch_before": execution_trace["epoch_before"],
        "epoch_after": execution_trace["epoch_after"],
        "event_count": len(trace.events),
        "event_names": names,
        "signer_key_id": trusted_key_id,
        "trusted_key_id_source": "WARRANTKIT_DPK_TRUSTED_KEY_ID runtime configuration; CI uses a per-run value",
        "incident_bundle_verification": final_verification["incident_bundle_verification"],
        "runtime_evidence_verification": final_verification["runtime_evidence_verification"],
        "attestation_sha256": final_verification["attestation_sha256"],
        "runtime_evidence_sha256": final_verification["runtime_evidence_sha256"],
        "incident_bundle_manifest_sha256": final_verification["incident_bundle_manifest_sha256"],
        "verification": cases,
        "claim_scope": {
            "runtime_enforcement": "observed by Linux cgroup supervisor and child wait",
            "trace_integrity": "verified by DProvenanceKit signature against trusted signer key ID",
            "model_reasoning_truth": "not established",
            "host_attestation": "not established",
        },
    }
    (output_dir / "verification-report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"DPK attestation: {attestation_path}")
    print(f"DPK trusted signer key ID: {trusted_key_id}")
    print("Verification: valid key accepted; wrong key and trace tampering rejected")
    print(f"Report: {output_dir / 'verification-report.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
