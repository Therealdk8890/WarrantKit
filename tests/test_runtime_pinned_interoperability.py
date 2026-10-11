"""Cross-repo runtime-pinned evidence interoperability tests."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration


@pytest.fixture
def agent_containment_src():
    src = Path(__file__).parents[1] / "AgentContainment" / "src"
    if not src.exists():
        pytest.skip("AgentContainment submodule is unavailable")
    sys.path.insert(0, str(src))
    try:
        yield src
    finally:
        sys.path.remove(str(src))


@pytest.mark.skipif(
    not (
        sys.platform == "linux"
        and os.geteuid() == 0
        and os.environ.get("WARRANTKIT_RUN_RUNTIME_INTEROP") == "1"
        and os.path.exists("/sys/fs/cgroup/cgroup.controllers")
    ),
    reason="requires Linux cgroup-v2, root, and WARRANTKIT_RUN_RUNTIME_INTEROP=1",
)
def test_real_agentcontainment_evidence_round_trips_through_warrantkit(agent_containment_src):
    from agent_containment.cgroup_enforcer import CgroupV2Enforcer
    from agent_containment.containment import ContainmentController
    from agent_containment.control import ContainmentService
    from agent_containment.linux_supervisor import LinuxCgroupSupervisor
    from agent_containment.runtime import Runtime
    from agent_containment.runtime_observation import RuntimeObservationSource

    from agentcontain.engine import AgentContainmentRuntimeAdapter, admit, contain, runtime_pinned_evidence
    from agentcontain.policy import Policy

    supervisor = LinuxCgroupSupervisor("auto")
    agent_id = f"interop-agent-{os.getpid()}"
    cgroup = supervisor.create_agent(agent_id)
    workload = None
    try:
        runtime = Runtime(agent_id)
        enforcer = CgroupV2Enforcer({agent_id: cgroup})
        controller = ContainmentController(runtime, enforcers=[enforcer])
        adapter = AgentContainmentRuntimeAdapter(
            agent_id,
            controller,
            ContainmentService(),
        )

        workload = subprocess.Popen(
            [sys.executable, "-c", "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"]
        )
        supervisor.attach_pid(cgroup, workload.pid)
        assert supervisor.pid_in_cgroup(workload.pid, cgroup)
        assert supervisor.is_populated(cgroup)

        admission = admit(
            Policy("production"),
            agent_id=agent_id,
            runtime_id=runtime.runtime_id,
            engine=adapter,
        )
        report = contain(admission)
        workload.wait(timeout=5)

        assert report.epoch == admission.identity.epoch == 1
        assert report.external_verified is True
        assert report.certified is True
        assert workload.returncode is not None
        assert workload.returncode < 0
        assert not supervisor.is_populated(cgroup)

        observation = RuntimeObservationSource().observe(runtime)
        envelope = runtime_pinned_evidence(admission, observation=observation)

        # Runtime binding consistency is not producer authentication.
        assert envelope.verification["status"] == "observed"
        binding = envelope.proof["runtime_binding"]
        assert binding["runtime_id"] == runtime.runtime_id
        assert binding["agent_id"] == agent_id
        assert binding["epoch"] == 1
        assert binding["authority"]["record"]["revoked"] is True
        assert binding["enforcement"]["record"]["external_boundary"] is True
        assert binding["enforcement"]["record"]["action"] == "KILL"
        assert binding["observation"]["record"]["can_execute"] is False
        assert binding["observation"]["record"]["state"] == "contained"
    finally:
        if workload is not None and workload.poll() is None:
            workload.kill()
            workload.wait(timeout=5)
        if cgroup.exists():
            try:
                supervisor.remove(cgroup)
            except OSError:
                pass


@pytest.mark.skipif(
    not (
        sys.platform == "linux"
        and os.geteuid() == 0
        and os.environ.get("WARRANTKIT_RUN_RUNTIME_INTEROP") == "1"
        and os.path.exists("/sys/fs/cgroup/cgroup.controllers")
    ),
    reason="requires Linux cgroup-v2, root, and WARRANTKIT_RUN_RUNTIME_INTEROP=1",
)
def test_real_enforcement_evidence_recovery_lifecycle_is_epoch_fenced(agent_containment_src):
    """Prove containment, independent evidence, recovery, and fresh authority as one lifecycle."""
    from agent_containment.cgroup_enforcer import CgroupV2Enforcer
    from agent_containment.containment import ContainmentController
    from agent_containment.control import ContainmentService
    from agent_containment.credentials import CredentialStore
    from agent_containment.linux_supervisor import LinuxCgroupSupervisor
    from agent_containment.runtime import Runtime
    from agent_containment.runtime_observation import RuntimeObservationSource

    from agentcontain.engine import (
        AgentContainmentRuntimeAdapter,
        admit,
        contain,
        detect,
        issue_recovery_authorization,
        recover,
        runtime_pinned_evidence,
        verify,
    )
    from agentcontain.policy import Policy

    supervisor = LinuxCgroupSupervisor("auto")
    agent_id = f"lifecycle-agent-{os.getpid()}"
    cgroup = supervisor.create_agent(agent_id)
    workload = None
    try:
        runtime = Runtime(agent_id)
        enforcer = CgroupV2Enforcer({agent_id: cgroup})
        controller = ContainmentController(
            runtime,
            credentials=CredentialStore(runtime=runtime),
            enforcers=[enforcer],
        )
        adapter = AgentContainmentRuntimeAdapter(
            agent_id,
            controller,
            ContainmentService(),
        )

        lease = adapter.credential_store.issue("lifecycle-credential")
        assert adapter.credential_store.valid(lease)

        workload = subprocess.Popen(
            [sys.executable, "-c", "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"]
        )
        supervisor.attach_pid(cgroup, workload.pid)
        assert supervisor.pid_in_cgroup(workload.pid, cgroup)

        admission = admit(
            Policy("production"),
            agent_id=agent_id,
            runtime_id=runtime.runtime_id,
            engine=adapter,
        )
        detect(admission, {"reason": "policy_boundary_violation"})
        report = contain(admission)
        workload.wait(timeout=5)

        assert report.epoch == admission.identity.epoch == 1
        assert report.external_verified is True
        assert not adapter.credential_store.valid(lease)

        observation = RuntimeObservationSource().observe(runtime)
        binding = runtime_pinned_evidence(admission, observation=observation).proof["runtime_binding"]
        verify(admission, runtime_binding=binding)
        assert admission.machine.state.value == "verified"

        recovery_authorization = issue_recovery_authorization(admission)
        recovery_epoch = recover(admission, recovery_authorization)

        assert recovery_epoch == 2
        assert admission.identity.epoch == 2
        assert admission.identity.runtime_id == runtime.runtime_id
        assert admission.machine.state.value == "recovered"
        assert runtime.can_execute is True
        assert adapter.credential_store.valid(lease) is False

        fresh_lease = adapter.credential_store.issue("lifecycle-credential")
        assert fresh_lease.epoch == 2
        assert adapter.credential_store.valid(fresh_lease) is True

        with pytest.raises(RuntimeError, match="runtime verification report is unavailable"):
            verify(admission, runtime_binding=binding)
    finally:
        if workload is not None and workload.poll() is None:
            workload.kill()
            workload.wait(timeout=5)
        if cgroup.exists():
            try:
                supervisor.remove(cgroup)
            except OSError:
                pass
