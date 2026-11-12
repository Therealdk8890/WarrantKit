"""Cross-repository contract against AgentContainment's unlocked-callback runtime.

Run only in the dedicated CI job installing the explicitly pinned newer
AgentContainment source. This does NOT establish cancellation of an already
admitted side effect or guarantee that it cannot finish after a fence.
"""
from threading import Event, Thread

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
from agent_containment.enforcer import EnforcementResult, EnforcementStatus
from agent_containment.models import Action
from agent_containment.policy import PolicyEngine


@pytest.mark.integration
def test_containment_fences_new_admissions_while_prior_callback_is_blocked():
    engine = build_agentcontainment_engine("inflight-interop")
    signer = Ed25519Signer.generate("inflight-interop")
    admission = admit(
        Policy("inflight-interop-policy", capabilities=("write_record",)),
        agent_id="inflight-interop",
        engine=engine,
        runtime_id=engine.runtime_id,
        warrant_signer=signer,
    )
    gateway = ActionGateway(PolicyEngine(), engine.controller)
    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    bound = BoundGuardedExecution(admission, gateway, warrant_verifier=verifier)
    runtime = engine.controller.runtime
    action = Action("inflight-interop", "first", "write_record", "record", risk=1)
    original_epoch = runtime.epoch

    started = Event()
    release = Event()
    results = []
    errors = []
    blocked_new_admission = []

    def already_admitted(_action):
        started.set()
        if not release.wait(timeout=10):
            raise AssertionError("blocked executor was never released")
        return "completed-inflight"

    def run_admitted():
        try:
            results.append(bound.execute(action, already_admitted))
        except BaseException as exc:
            errors.append(exc)

    worker = Thread(target=run_admitted, daemon=True)
    worker.start()
    fence = None
    try:
        assert started.wait(timeout=5), "the guarded callback did not begin"
        assert runtime.inflight_executions == 1
        fence = Thread(target=runtime.halt, daemon=True)
        fence.start()
        fence.join(timeout=3)
        assert not fence.is_alive(), (
            "fencing waited behind an already-admitted application callback"
        )
        assert runtime.epoch == original_epoch + 1
        assert not runtime.can_execute

        with pytest.raises(GuardedExecutionDenied):
            bound.execute(
                Action("inflight-interop", "second", "write_record", "record", risk=1),
                lambda _action: blocked_new_admission.append("unexpected"),
            )
        assert blocked_new_admission == []
        # A previously admitted operation is still in flight. Only the external
        # enforcer/downstream auth can terminate or revoke such work.
        assert runtime.inflight_executions == 1
    finally:
        release.set()
        if fence is not None:
            fence.join(timeout=5)
        worker.join(timeout=5)

    assert not worker.is_alive()
    assert not errors, errors
    assert results == ["completed-inflight"]
    assert runtime.inflight_executions == 0


@pytest.mark.integration
def test_failed_external_enforcer_keeps_runtime_fenced_but_cannot_stop_inflight():
    """A failed external enforcer must never be reported as a successful kill.

    The already-admitted callback is explicitly released after containment
    fails. Its modeled side effect can complete; this is why downstream effect
    cancellation must not be inferred from the epoch fence alone.
    """
    engine = build_agentcontainment_engine("failed-enforcer-inflight")

    class FailingEnforcer:
        name = "deliberately-degraded-enforcer"

        def contain(self, agent_id):
            return EnforcementResult(
                self.name, EnforcementStatus.DEGRADED, "simulated kernel enforcement failure"
            )

        def verify_contained(self, agent_id):
            raise AssertionError("failed enforcement must not be verified as successful")

    engine.controller.enforcers.append(FailingEnforcer())
    signer = Ed25519Signer.generate("failed-enforcer-inflight")
    admission = admit(
        Policy("failed-enforcer-inflight", capabilities=("write_record",)),
        agent_id="failed-enforcer-inflight",
        engine=engine,
        runtime_id=engine.runtime_id,
        warrant_signer=signer,
    )
    gateway = ActionGateway(PolicyEngine(), engine.controller)
    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    bound = BoundGuardedExecution(admission, gateway, warrant_verifier=verifier)
    action = Action("failed-enforcer-inflight", "first", "write_record", "record", risk=1)
    runtime = engine.controller.runtime
    before_epoch = runtime.epoch

    entered = Event()
    release = Event()
    effects = []
    results = []
    errors = []

    def admitted_effect(_action):
        entered.set()
        assert release.wait(timeout=8), "test did not release the admitted callback"
        effects.append("already-admitted effect completed after failed enforcement")
        return "callback-completed"

    def guarded_worker():
        try:
            results.append(bound.execute(action, admitted_effect))
        except BaseException as exc:
            errors.append(exc)

    worker = Thread(target=guarded_worker, daemon=True)
    worker.start()
    try:
        assert entered.wait(timeout=5)
        assert runtime.inflight_executions == 1
        with pytest.raises(RuntimeError, match="enforcement engine reported containment failures"):
            contain(admission)
        report = engine.last_report
        assert report is not None
        assert not report.complete
        assert not report.certified
        assert report.external_verified is False
        assert any("deliberately-degraded-enforcer" in failure for failure in report.failures)
        assert runtime.epoch == before_epoch + 1
        assert not runtime.can_execute
        assert runtime.acquire_lease() is None
        assert effects == []
        assert runtime.inflight_executions == 1
        with pytest.raises(GuardedExecutionDenied):
            bound.execute(
                Action("failed-enforcer-inflight", "second", "write_record", "record"),
                lambda _action: effects.append("new effect bypassed fence"),
            )
        assert effects == []
    finally:
        release.set()
        worker.join(timeout=5)
    assert not worker.is_alive()
    assert not errors, errors
    assert results == ["callback-completed"]
    assert effects == ["already-admitted effect completed after failed enforcement"]
    assert runtime.inflight_executions == 0


@pytest.mark.integration
def test_downstream_commit_fence_rejects_previously_admitted_http_request():
    """An HTTP server must recheck trusted epoch at COMMIT, not at arrival.

    This deliberately uses an in-process trusted epoch oracle and localhost.
    It establishes the downstream authorization protocol's ordering, not
    network partition behavior, production identity, or credential custody.
    """
    import json
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.error import HTTPError
    from urllib.request import Request, urlopen

    engine = build_agentcontainment_engine("downstream-commit-fence")
    runtime = engine.controller.runtime
    original_epoch = runtime.epoch
    request_received = Event()
    permit_commit = Event()
    committed = []
    outcomes = []
    failures = []

    class DownstreamHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                request_received.set()
                if not permit_commit.wait(timeout=8):
                    raise TimeoutError("test never released the downstream commit")
                # This is the *trusted server-side* commit fence. It must be
                # atomic with the protected commit in a real downstream system.
                # Snapshot is atomic for this deterministic ordering test.
                # A real service must enforce its own transactional fence.
                snapshot = runtime.snapshot()
                allowed = (
                    snapshot.can_execute
                    and data["epoch"] == snapshot.epoch
                    and data["agent_id"] == snapshot.agent_id
                )
                if allowed:
                    committed.append(data["value"])
                self.send_response(200 if allowed else 409)
                self.end_headers()
                self.wfile.write(b"committed" if allowed else b"stale epoch")
            except BaseException as exc:
                failures.append(exc)
                try:
                    self.send_error(500)
                except OSError:
                    pass

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), DownstreamHandler)
    server_thread = Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    try:
        def client():
            request = Request(
                f"http://127.0.0.1:{server.server_port}/commit",
                data=json.dumps({
                    "agent_id": runtime.agent_id,
                    "epoch": original_epoch,
                    "value": "delayed-remote-commit",
                }).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urlopen(request, timeout=10) as response:
                    outcomes.append(response.status)
            except HTTPError as exc:
                outcomes.append(exc.code)
            except BaseException as exc:
                failures.append(exc)

        client_thread = Thread(target=client, daemon=True)
        client_thread.start()
        try:
            assert request_received.wait(timeout=5), "HTTP server did not accept request"
            assert committed == []
            # Request arrived while the old epoch was valid. Containment
            # commits before the server performs its authorization/commit.
            runtime.halt()
            assert runtime.epoch == original_epoch + 1
            assert not runtime.can_execute
        finally:
            permit_commit.set()
            client_thread.join(timeout=5)
        assert not client_thread.is_alive()
        assert not failures, failures
        assert outcomes == [409]
        assert committed == []
    finally:
        permit_commit.set()
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=5)
