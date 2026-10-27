#!/usr/bin/env python3
"""Operator-facing Linux cgroup-v2 real-kill proof.

Requires the WarrantKit checkout, the AgentContainment submodule, Linux cgroup-v2,
root/delegated cgroup privileges, and the WarrantKit Python package installed.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

from agent_containment.gateway import ActionGateway
from agent_containment.models import Action
from agent_containment.policy import PolicyEngine
from agentcontain.engine import admit, build_agentcontainment_engine, contain
from agentcontain.evidence import EvidenceEnvelope, canonical_json
from agentcontain.policy import Policy
from agentcontain.warrant import Warrant, verify_warrant

from incident_bundle import write_incident_bundle


def _record_binding(record: dict) -> dict:
    return {
        "digest": "sha256:" + hashlib.sha256(
            canonical_json(record).encode("utf-8")
        ).hexdigest(),
        "record": record,
    }


def _sha256_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _workload_identity():
    """Return a dedicated unprivileged identity for the contained workload."""
    import pwd

    try:
        account = pwd.getpwnam("nobody")
    except KeyError as exc:
        raise RuntimeError("real-kill proof requires an unprivileged nobody account") from exc
    if account.pw_uid == 0 or account.pw_uid == os.geteuid():
        raise RuntimeError("workload identity must be distinct from the privileged controller")
    return account


def _assert_unprivileged_key_access_denied(path: Path, workload) -> None:
    """Probe file access as the workload identity without reading key bytes."""
    if not path.is_file():
        raise RuntimeError(f"incident signing key file is missing: {path}")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077 or path.stat().st_uid == workload.pw_uid:
        raise RuntimeError("incident signing key must be owner-only and unavailable to the workload identity")
    probe = (
        "import os,sys; "
        "fd=None; "
        "\ntry: fd=os.open(sys.argv[1], os.O_RDONLY)"
        "\nexcept PermissionError: raise SystemExit(0)"
        "\nexcept OSError: raise SystemExit(2)"
        "\nelse: os.close(fd); raise SystemExit(1)"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe, str(path)],
        env={"PATH": os.defpath, "HOME": "/nonexistent", "LANG": "C"},
        user=workload.pw_uid,
        group=workload.pw_gid,
        extra_groups=[],
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )
    if result.returncode != 0:
        raise RuntimeError("incident signing key is readable by the workload identity")


def _process_credentials(pid: int) -> tuple[int, int]:
    status_path = Path(f"/proc/{pid}/status")
    try:
        fields = {}
        for line in status_path.read_text(encoding="utf-8").splitlines():
            name, separator, value = line.partition(":")
            if separator and name in {"Uid", "Gid"}:
                fields[name] = int(value.split()[0])
        return fields["Uid"], fields["Gid"]
    except (OSError, KeyError, ValueError, IndexError) as exc:
        raise RuntimeError(f"cannot verify unprivileged workload credentials for pid {pid}") from exc


def main() -> int:
    if os.name != "posix" or os.geteuid() != 0:
        print("REJECTED: real-kill proof requires Linux/root privileges", file=sys.stderr)
        return 2
    if os.environ.get("AGENT_CONTAIN_RUN_REAL_CGROUP") != "1":
        print("REJECTED: set AGENT_CONTAIN_RUN_REAL_CGROUP=1", file=sys.stderr)
        return 2
    if not Path("/sys/fs/cgroup/cgroup.controllers").exists():
        print("REJECTED: cgroup-v2 is unavailable", file=sys.stderr)
        return 2

    from agent_containment.linux_supervisor import LinuxCgroupSupervisor

    workload = _workload_identity()
    for key_file_env in (
        "WARRANTKIT_INCIDENT_SIGNING_KEY_FILE",
        "WARRANTKIT_DPK_SIGNING_KEY_FILE",
    ):
        key_file = os.environ.get(key_file_env)
        if key_file:
            _assert_unprivileged_key_access_denied(Path(key_file), workload)

    supervisor = LinuxCgroupSupervisor("auto")
    agent_id = f"warrantkit-real-kill-{os.getpid()}"
    cgroup = supervisor.create_agent(agent_id)
    child = None
    proof_events: list[dict] = []

    try:
        print("[1/11] launching real workload")
        # The workload runs under a separate unprivileged UID/GID and receives
        # only a minimal environment. In particular, it cannot inherit the
        # controller's DPK signer key or incident-signing key path.
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(300)"],
            env={"PATH": os.defpath, "HOME": "/nonexistent", "LANG": "C"},
            user=workload.pw_uid,
            group=workload.pw_gid,
            extra_groups=[],
        )
        workload_uid, workload_gid = _process_credentials(child.pid)
        if workload_uid != workload.pw_uid or workload_gid != workload.pw_gid or workload_uid == 0:
            raise RuntimeError("workload did not start with the required unprivileged credentials")
        supervisor.attach_pid(cgroup, child.pid)
        if not supervisor.pid_in_cgroup(child.pid, cgroup):
            raise RuntimeError("workload was not attached to its cgroup")
        if not supervisor.is_populated(cgroup):
            raise RuntimeError("workload cgroup was not populated before containment")

        print("[2/11] admitting workload under Warrant")
        engine = build_agentcontainment_engine(agent_id, cgroup_path=str(cgroup))
        runtime_id = engine.runtime_id
        admission = admit(
            Policy("real-kill-proof", capabilities=("test-workload",)),
            agent_id=agent_id,
            engine=engine,
            runtime_id=runtime_id,
        )

        if admission.warrant is None:
            raise RuntimeError("real-kill proof requires a Warrant-bound admission")
        print(f"    warrant={admission.warrant.warrant_id}")
        print(f"    epoch={admission.identity.epoch}")
        pre_containment_warrant = admission.warrant.to_dict()

        print("[3/11] validating the Warrant and separately exercising the gateway")
        action = Action(
            agent_id=admission.identity.agent_id,
            action_id=f"{admission.identity.execution_id}:authorized-proof-action",
            operation="test-workload",
            resource="local-real-kill-proof",
            risk=1,
        )
        verify_warrant(
            admission.warrant,
            execution_id=admission.identity.execution_id,
            agent_id=admission.identity.agent_id,
            policy_id=admission.identity.policy_id,
            policy_digest=admission.identity.policy_digest,
            runtime_id=runtime_id,
            epoch=admission.identity.epoch,
        )
        proof_events.append({
            "name": "warrant_validated",
            "observed_at_unix_microseconds": time.time_ns() // 1_000,
            "execution_id": admission.identity.execution_id,
            "runtime_id": runtime_id,
            "warrant_id": admission.warrant.warrant_id,
            "epoch": admission.identity.epoch,
        })
        action_calls: list[str] = []
        gateway = ActionGateway(PolicyEngine(), admission.engine.controller)
        authorized_result = gateway.execute(
            action,
            lambda authorized_action: action_calls.append(
                authorized_action.action_id
            ) or {"status": "executed", "resource": action.resource},
        )
        if authorized_result != {"status": "executed", "resource": action.resource} or len(action_calls) != 1:
            raise AssertionError("valid Warrant did not permit exactly one intended gateway action")
        proof_events.append({
            "name": "gateway_action_executed",
            "observed_at_unix_microseconds": time.time_ns() // 1_000,
            "execution_id": admission.identity.execution_id,
            "agent_id": admission.identity.agent_id,
            "runtime_id": runtime_id,
            "epoch": admission.identity.epoch,
            "action_id": action.action_id,
            "operation": action.operation,
            "resource": action.resource,
            "gateway_result": authorized_result,
            "executor_action_ids": action_calls,
        })
        print(f"    authorized action executed: {authorized_result}")

        print("[4/11] invoking external runtime enforcement")
        report = contain(admission)
        if report.complete is not True:
            raise RuntimeError("containment report is incomplete")
        if report.external_verified is not True:
            raise RuntimeError("external cgroup containment was not verified")
        proof_events.append({
            "name": "containment_completed",
            "observed_at_unix_microseconds": time.time_ns() // 1_000,
            "execution_id": admission.identity.execution_id,
            "runtime_id": runtime_id,
            "epoch_before": pre_containment_warrant["runtime"]["epoch"],
            "epoch_after": admission.identity.epoch,
            "complete": report.complete,
            "external_verified": report.external_verified,
            "evidence_ref": getattr(report, "evidence_ref", None),
            "verification_id": getattr(report, "verification_id", None),
        })

        print("[5/11] proving pre-containment authority is stale")
        replayed_warrant = Warrant.from_dict(pre_containment_warrant)
        try:
            verify_warrant(replayed_warrant, execution_id=admission.identity.execution_id, agent_id=admission.identity.agent_id, policy_id=admission.identity.policy_id, policy_digest=admission.identity.policy_digest, runtime_id=runtime_id, epoch=admission.identity.epoch)
        except ValueError as exc:
            if "epoch" not in str(exc):
                raise
            print(f"    stale pre-containment Warrant rejected: {exc}")
            proof_events.append({
                "name": "stale_authority_rejected",
                "observed_at_unix_microseconds": time.time_ns() // 1_000,
                "execution_id": admission.identity.execution_id,
                "runtime_id": runtime_id,
                "warrant_epoch": replayed_warrant.runtime.epoch,
                "current_epoch": admission.identity.epoch,
                "reason": str(exc),
            })
        else:
            raise AssertionError("pre-containment Warrant remained valid after epoch transition")

        try:
            verify_warrant(admission.warrant, execution_id=admission.identity.execution_id, agent_id=admission.identity.agent_id, policy_id=admission.identity.policy_id, policy_digest=admission.identity.policy_digest, runtime_id=runtime_id, epoch=admission.identity.epoch)
        except ValueError as exc:
            if "revoked" not in str(exc):
                raise
            print(f"    revoked live Warrant rejected: {exc}")
        else:
            raise AssertionError("revoked Warrant remained executable")

        print("[6/11] proving the gateway rejects the stale action")
        post_containment_calls: list[dict] = []
        stale_action_result = gateway.execute(
            action,
            lambda attempted_action: post_containment_calls.append(
                {"action_id": attempted_action.action_id}
            ) or "executor-ran",
        )
        if post_containment_calls:
            raise AssertionError("gateway reached the action after containment")
        decision = getattr(getattr(stale_action_result, "decision", None), "value", None)
        reason = getattr(stale_action_result, "reason", None)
        if decision != "deny":
            raise AssertionError(f"gateway did not deny post-containment action: {stale_action_result!r}")
        proof_events.append({
            "name": "stale_action_rejected",
            "observed_at_unix_microseconds": time.time_ns() // 1_000,
            "execution_id": admission.identity.execution_id,
            "runtime_id": runtime_id,
            "current_epoch": admission.identity.epoch,
            "reason": reason,
            "executor_called": False,
        })
        print(f"    gateway rejected action before executor: {reason}")

        print("[7/11] independently checking terminal runtime state")
        child.wait(timeout=5)
        # Capture terminal-state facts from the OS-facing supervisor and child
        # process, rather than hard-coding the evidence fields below.
        cgroup_populated_after = supervisor.is_populated(cgroup)
        workload_exit_code = child.returncode
        terminal_state_independently_observed = (
            not cgroup_populated_after and workload_exit_code is not None
        )
        if not terminal_state_independently_observed:
            raise RuntimeError(
                "terminal state not established: cgroup is populated or workload is still running"
            )
        terminal_observed_at = time.time()
        print(f"    cgroup_populated={cgroup_populated_after}")
        print(f"    workload exited with code {workload_exit_code}")
        proof_events.append({
            "name": "runtime_terminal_state_observed",
            "observed_at_unix_microseconds": time.time_ns() // 1_000,
            "execution_id": admission.identity.execution_id,
            "runtime_id": runtime_id,
            "agent_id": admission.identity.agent_id,
            "epoch": admission.identity.epoch,
            "runtime_state": "TERMINATED",
            "cgroup_populated": cgroup_populated_after,
            "workload_exit_code": workload_exit_code,
            "observation_source": "linux_cgroup_supervisor_and_child_wait",
        })

        print("[8/11] exporting runtime-pinned evidence")
        authority_export = getattr(admission.engine, "authority_revocation_evidence_record", None)
        if authority_export is None:
            raise RuntimeError("runtime engine does not expose authority revocation evidence")
        authority = authority_export() if callable(authority_export) else authority_export
        # Bind the exported authority record to this exact execution authority.
        # The portable verifier must reject evidence transferred across a
        # different execution, policy, or policy digest.
        authority = dict(authority)
        authority.update(
            {
                "execution_id": admission.identity.execution_id,
                "policy_id": admission.identity.policy_id,
                "policy_digest": admission.identity.policy_digest,
            }
        )
        authority = _record_binding(authority)

        enforcement_export = getattr(report, "enforcement_evidence_record", None)
        if enforcement_export is None:
            raise RuntimeError("runtime report does not expose canonical enforcement evidence")
        enforcement = enforcement_export(runtime_id)

        observation_record = {
            "runtime_id": runtime_id,
            "agent_id": admission.identity.agent_id,
            "epoch": admission.identity.epoch,
            "state": "TERMINATED" if terminal_state_independently_observed else "UNKNOWN",
            "observed_at": terminal_observed_at,
            "can_execute": not terminal_state_independently_observed,
            "cgroup_populated": cgroup_populated_after,
            "workload_exit_code": workload_exit_code,
            "observation_source": "linux_cgroup_supervisor_and_child_wait",
        }
        binding = {
            "schema_version": "agentcontain.runtime-binding/v1",
            "runtime_id": runtime_id,
            "agent_id": admission.identity.agent_id,
            "epoch": admission.identity.epoch,
            "authority": authority,
            "enforcement": enforcement,
            "observation": _record_binding(observation_record),
        }
        envelope = EvidenceEnvelope.from_execution(
            execution={
                "execution_id": admission.identity.execution_id,
                "agent_id": admission.identity.agent_id,
                "policy_id": admission.identity.policy_id,
                "policy_digest": admission.identity.policy_digest,
                "epoch": admission.identity.epoch,
                "runtime_id": runtime_id,
            },
            events=(
                {
                    "execution_id": admission.identity.execution_id,
                    "sequence": 1,
                    "name": "containment_verified",
                    "epoch": admission.identity.epoch,
                },
                {
                    "execution_id": admission.identity.execution_id,
                    "sequence": 2,
                    "name": "stale_authority_rejected",
                    "epoch": admission.identity.epoch,
                    "details": {
                        "warrant_epoch": replayed_warrant.runtime.epoch,
                        "reason": "runtime_epoch_mismatch",
                    },
                },
            ),
            verification={"status": "observed"},
        ).with_runtime_pinned_evidence(binding)

        artifact = Path(
            os.environ.get(
                "WARRANTKIT_REAL_KILL_ARTIFACT",
                "real-kill-runtime-evidence.json",
            )
        )
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text(
            json.dumps(envelope.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"    artifact={artifact}")

        trace_artifact = Path(
            os.environ.get("WARRANTKIT_EXECUTION_TRACE_ARTIFACT", "real-kill-execution-trace.json")
        )
        trace_artifact.parent.mkdir(parents=True, exist_ok=True)
        trace_artifact.write_text(
            json.dumps(
                {
                    "schema_version": "warrantkit.real-kill-execution-trace/v1",
                    "execution_id": admission.identity.execution_id,
                    "agent_id": admission.identity.agent_id,
                    "runtime_id": runtime_id,
                    "policy_id": admission.identity.policy_id,
                    "policy_digest": admission.identity.policy_digest,
                    "epoch_before": replayed_warrant.runtime.epoch,
                    "epoch_after": admission.identity.epoch,
                    "workload_pid": child.pid,
                    "workload_uid": workload_uid,
                    "cgroup_path": str(cgroup),
                    "events": proof_events,
                },
                indent=2,
                sort_keys=True,
            ) + "\n",
            encoding="utf-8",
        )
        print(f"    execution_trace={trace_artifact}")

        print("[9/11] independently verifying exported artifact")
        verifier = Path(__file__).with_name("verify_runtime_evidence.py")
        result = subprocess.run(
            [sys.executable, str(verifier), str(artifact)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            print(result.stderr, file=sys.stderr)
            return 1
        print(f"    {result.stdout.strip()}")

        bundle_dir = os.environ.get("WARRANTKIT_INCIDENT_BUNDLE_DIR")
        if bundle_dir:
            print("[10/11] building signed incident bundle")
            incident_id = f"INC-{admission.identity.execution_id}"
            manifest = write_incident_bundle(
                Path(bundle_dir),
                incident_id=incident_id,
                authority=pre_containment_warrant,
                containment={
                    "schema_version": "warrantkit.containment-event/v1",
                    "incident_id": incident_id,
                    "runtime_id": runtime_id,
                    "execution_id": admission.identity.execution_id,
                    "agent_id": admission.identity.agent_id,
                    "epoch_before": replayed_warrant.runtime.epoch,
                    "epoch_after": admission.identity.epoch,
                    "state_after": "CONTAINED",
                    "operation": "external_containment",
                    "reason": "real-kill-proof containment",
                    "evidence_ref": getattr(report, "evidence_ref", None),
                    "verification_id": getattr(report, "verification_id", None),
                    "external_verified": report.external_verified,
                    "enforcement": enforcement,
                },
                runtime_evidence=envelope.to_dict(),
                external_proof={
                    "schema_version": "warrantkit.external-proof/v1",
                    "execution_id": admission.identity.execution_id,
                    "runtime_id": runtime_id,
                    "agent_id": admission.identity.agent_id,
                    "epoch": admission.identity.epoch,
                    "runtime_state": observation_record["state"],
                    "can_execute": observation_record["can_execute"],
                    "cgroup_populated": cgroup_populated_after,
                    "workload_exit_code": workload_exit_code,
                    "terminal_state_independently_observed": terminal_state_independently_observed,
                    "observed_at": terminal_observed_at,
                    "observation_source": "linux_cgroup_supervisor_and_child_wait",
                },
                provenance={
                    "schema_version": "warrantkit.incident-provenance/v1",
                    "producer": "tools/run_real_kill_demo.py",
                    "execution_id": admission.identity.execution_id,
                    "source_runtime_evidence": str(artifact),
                    "runtime_evidence_sha256": _sha256_file(artifact),
                    "runtime_verifier": str(verifier),
                    "runtime_verifier_result": result.stdout.strip(),
                },
            )
            print(f"    bundle={bundle_dir}")
            print(f"    incident={manifest['incident_id']}")
            print("    signature=Ed25519 verification receipt")
        else:
            print("[10/11] incident bundle not requested")
            print("    set WARRANTKIT_INCIDENT_BUNDLE_DIR to export one")

        print("[11/11] proof complete")
        print("What this proves: the tested Linux environment enforced the configured")
        print("cgroup-v2 kill/fence boundary, invalidated pre-containment authority,")
        print("and produced independently checked evidence.")
        print("What this does not prove: universal host isolation, formal verification,")
        print("or non-repudiable host attestation.")
        return 0
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        if cgroup.exists():
            try:
                supervisor.remove(cgroup)
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
