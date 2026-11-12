"""Real Linux proof for externally enforced in-flight WarrantKit side effects.

The protected callback is admitted before containment and waits for a child
process. The child is independently attached to a dedicated cgroup-v2 boundary.
A pre-fence filesystem effect is deliberately completed. A second effect is
gated until after containment and MUST never happen, because the kernel kills
the cgroup member. This does not model revocation of remote API requests.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

import pytest

from agentcontain import (
    BoundGuardedExecution,
    GuardedExecutionDenied,
    Policy,
    admit,
    build_agentcontainment_engine,
    contain,
)
from agentcontain.attestation import Ed25519Signer, Ed25519Verifier
from agent_containment.gateway import ActionGateway
from agent_containment.linux_supervisor import LinuxCgroupSupervisor
from agent_containment.models import Action
from agent_containment.policy import PolicyEngine

pytestmark = pytest.mark.integration

# The child cannot perform the first effect until the controller has attached
# its PID to the dedicated cgroup and opened the start gate. The second effect
# remains gated until AFTER the cgroup has been killed and checked empty.
_CHILD = """
import sys
import time
from pathlib import Path

start, already_committed, release, later_commit = map(Path, sys.argv[1:])
deadline = time.monotonic() + 15
while not start.is_file():
    if time.monotonic() > deadline:
        sys.exit(71)
    time.sleep(0.01)
already_committed.write_text("committed before containment", encoding="utf-8")
while not release.is_file():
    time.sleep(0.01)
later_commit.write_text("UNAUTHORIZED post-containment effect", encoding="utf-8")
"""


def _wait_for_marker(marker: Path, process: subprocess.Popen, timeout: float = 8) -> None:
    deadline = time.monotonic() + timeout
    while not marker.is_file() and time.monotonic() < deadline:
        if process.poll() is not None:
            pytest.fail(f"supervised worker exited before committing first effect: {process.returncode}")
        time.sleep(0.01)
    assert marker.is_file(), "supervised worker never reached the pre-fence effect"


def test_cgroup_kills_inflight_external_worker_but_cannot_undo_prior_effect():
    if os.environ.get("WARRANTKIT_RUN_INFLIGHT_REAL_KILL") != "1":
        pytest.skip("requires explicit privileged real-kill opt-in")
    if sys.platform != "linux" or os.geteuid() != 0:
        pytest.fail("in-flight real-kill proof requires Linux root/delegation")
    if not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
        pytest.fail("in-flight real-kill proof requires cgroup v2")

    supervisor = LinuxCgroupSupervisor("auto")
    agent_id = f"warrantkit-inflight-{os.getpid()}-{uuid4().hex[:8]}"
    cgroup = supervisor.create_agent(agent_id)
    child = None
    gateway_thread = None
    thread_result = []
    thread_error = []
    started = threading.Event()

    try:
        with TemporaryDirectory(prefix="warrantkit-inflight-") as directory:
            root = Path(directory)
            start_gate = root / "start"
            committed_before = root / "committed-before"
            release_gate = root / "release-after-fence"
            committed_after = root / "committed-after"

            engine = build_agentcontainment_engine(agent_id, cgroup_path=str(cgroup))
            signer = Ed25519Signer.generate("inflight-real-enforcer")
            admission = admit(
                Policy("inflight-real-enforcer", capabilities=("write_record",)),
                agent_id=agent_id,
                engine=engine,
                runtime_id=engine.runtime_id,
                warrant_signer=signer,
            )
            gateway = ActionGateway(PolicyEngine(), engine.controller)
            verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
            bound = BoundGuardedExecution(admission, gateway, warrant_verifier=verifier)
            action = Action(agent_id, "before-fence", "write_record", "test-record", risk=1)
            runtime = engine.controller.runtime
            before_epoch = runtime.epoch

            def admitted_executor(_action: Action) -> int:
                nonlocal child
                child = subprocess.Popen([
                    sys.executable, "-c", _CHILD,
                    str(start_gate), str(committed_before),
                    str(release_gate), str(committed_after),
                ])
                supervisor.attach_pid(cgroup, child.pid)
                assert supervisor.pid_in_cgroup(child.pid, cgroup)
                assert supervisor.is_populated(cgroup)
                start_gate.touch()
                started.set()
                # Waiting for the REAL worker must not hold the runtime fence
                # lock; containment independently kills this cgroup member.
                return child.wait(timeout=20)

            def call_guarded():
                try:
                    thread_result.append(bound.execute(action, admitted_executor))
                except BaseException as exc:
                    thread_error.append(exc)

            gateway_thread = threading.Thread(target=call_guarded, daemon=True)
            gateway_thread.start()

            try:
                assert started.wait(timeout=8), "guarded callback did not attach the child"
                assert child is not None
                _wait_for_marker(committed_before, child)
                assert child.poll() is None
                assert not committed_after.exists()
                assert runtime.inflight_executions == 1

                # Run the REAL WarrantKit containment lifecycle while its
                # already-admitted gateway callback is still blocked.
                requested = time.monotonic()
                report = contain(admission)
                elapsed = time.monotonic() - requested

                assert report.complete and report.external_verified
                assert report.certified
                assert "enforcer:cgroup-v2:verified" in report.stages
                assert report.enforcement_latency_seconds is not None
                assert report.enforcement_latency_seconds <= elapsed + 0.05
                assert runtime.epoch == before_epoch + 1
                assert not runtime.can_execute
                assert not supervisor.is_populated(cgroup)

                child.wait(timeout=5)
                assert child.returncode == -signal.SIGKILL
                gateway_thread.join(timeout=5)
                assert not gateway_thread.is_alive()
                assert not thread_error, thread_error
                # The controller callback can return a killed-worker result.
                # Such a result must NOT be interpreted as a successful write.
                assert thread_result == [-signal.SIGKILL]
                assert runtime.inflight_executions == 0

                # The already-committed effect persists; the delayed effect
                # is impossible after the kernel-enforced kill.
                assert committed_before.read_text(encoding="utf-8") == "committed before containment"
                release_gate.touch()
                time.sleep(0.05)
                assert not committed_after.exists()

                with pytest.raises(GuardedExecutionDenied):
                    bound.execute(
                        Action(agent_id, "after-fence", "write_record", "test-record", risk=1),
                        lambda _action: committed_after.write_text("UNAUTHORIZED"),
                    )
                assert not committed_after.exists()
            finally:
                if child is not None and child.poll() is None:
                    child.kill()
                    child.wait(timeout=5)
                if gateway_thread is not None:
                    gateway_thread.join(timeout=5)
    finally:
        if cgroup.exists():
            supervisor.remove(cgroup)
