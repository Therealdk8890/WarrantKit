import json

from agentcontain import cli


class FakeReport:
    complete = True
    certified = True
    durable = True
    external_verified = True
    failures = ()
    stages = ("runtime_fenced", "enforcer:cgroup:verified")
    enforcement_latency_seconds = 0.25

    def to_receipt(self, secret, *, execution_id, policy_id):
        return FakeReceipt(execution_id, policy_id, secret)


class FakeReceipt:
    def __init__(self, execution_id, policy_id, secret):
        self.payload = {"agent_id": execution_id, "policy_id": policy_id}
        self.signature = secret.hex()

    def to_dict(self):
        return {"payload": self.payload, "signature": self.signature}


class FakeEngine:
    def contain(self):
        self.last_report = FakeReport()
        return self.last_report


def test_cli_json_run_rejects_unsupported_egress(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "build_agentcontainment_engine", lambda agent_id, **kwargs: FakeEngine())

    assert cli.main([
        "run",
        "--policy", "production",
        "--agent-id", "agent-1",
        "--capability", "network",
        "--egress", "api.example",
        "--contain",
        "--json",
    ]) == 1

    captured = capsys.readouterr()
    assert "destination_allowlist.v1" in captured.err
    assert captured.out == ""


def test_cli_writes_portable_evidence_file(monkeypatch, tmp_path, capsys) -> None:
    monkeypatch.setattr(cli, "build_agentcontainment_engine", lambda agent_id, **kwargs: FakeEngine())
    output = tmp_path / "evidence.json"

    assert cli.main([
        "run",
        "--policy", "production",
        "--agent-id", "agent-1",
        "--contain",
        "--evidence-output", str(output),
    ]) == 0

    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["schema_version"] == "agentcontain.evidence/v2"
    assert document["execution"]["agent_id"] == "agent-1"
    assert document["execution"]["policy_id"] == "production"
    assert document["verification"]["status"] == "verified"
    assert document["verification"]["method"] == "agentcontainment-runtime-report"
    assert document["proof"]["host_enforcement_verified"] is True
    assert "Evidence:" in capsys.readouterr().out


def test_cli_returns_nonzero_when_engine_cannot_be_loaded(monkeypatch, capsys) -> None:
    def fail(_agent_id):
        raise RuntimeError("engine unavailable")

    monkeypatch.setattr(cli, "build_agentcontainment_engine", lambda agent_id, **kwargs: fail(agent_id))

    assert cli.main(["run", "--policy", "production"]) == 1
    assert "engine unavailable" in capsys.readouterr().err


def test_cli_reads_receipt_secret_from_environment(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "build_agentcontainment_engine", lambda agent_id, **kwargs: FakeEngine())
    monkeypatch.setenv("WARRANTKIT_RECEIPT_SECRET", "test-secret")
    captured = {}

    def fake_receipt(admission, secret):
        captured["secret"] = secret
        return None

    monkeypatch.setattr(cli, "containment_receipt", fake_receipt)

    assert cli.main(["run", "--policy", "production", "--agent-id", "agent-1", "--contain", "--json"]) == 0
    assert captured["secret"] == b"test-secret"
    json.loads(capsys.readouterr().out)


def test_cli_reads_receipt_secret_from_file(monkeypatch, tmp_path, capsys) -> None:
    monkeypatch.setattr(cli, "build_agentcontainment_engine", lambda agent_id, **kwargs: FakeEngine())
    secret = tmp_path / "receipt.secret"
    secret.write_text("test-secret\n", encoding="utf-8")
    captured = {}

    def fake_receipt(admission, value):
        captured["secret"] = value
        return None

    monkeypatch.setattr(cli, "containment_receipt", fake_receipt)

    assert cli.main(["run", "--policy", "production", "--agent-id", "agent-1", "--contain", "--receipt-secret-file", str(secret), "--json"]) == 0
    assert captured["secret"] == b"test-secret"
    json.loads(capsys.readouterr().out)


def test_cli_inspects_evidence_file(tmp_path, capsys) -> None:
    from agentcontain.evidence import EvidenceEnvelope

    envelope = EvidenceEnvelope.from_execution(
        execution={
            "execution_id": "exec-1",
            "agent_id": "agent-1",
            "policy_id": "payments",
            "policy_digest": "sha256:test",
            "epoch": 3,
        },
        events=(
            {
                "name": "admission_verified",
                "execution_id": "exec-1",
                "epoch": 3,
                "sequence": 1,
                "timestamp": "2026-09-27T00:00:00+00:00",
                "details": {},
            },
            {
                "name": "anomaly_detected",
                "execution_id": "exec-1",
                "epoch": 3,
                "sequence": 2,
                "timestamp": "2026-09-27T00:00:01+00:00",
                "details": {"reason": "unauthorized_action"},
            },
            {
                "name": "containment_verified",
                "execution_id": "exec-1",
                "epoch": 3,
                "sequence": 3,
                "timestamp": "2026-09-27T00:00:02+00:00",
                "details": {},
            },
        ),
        verification={"status": "verified", "method": "test"},
        proof={"checks": ["containment"]},
    )
    evidence = tmp_path / "evidence.json"
    evidence.write_text(envelope.to_json(), encoding="utf-8")

    assert cli.main(["inspect", "--evidence-file", str(evidence)]) == 0
    output = capsys.readouterr().out
    assert "Agent:        agent-1" in output
    assert "Policy:       payments" in output
    assert "Event:        anomaly_detected" in output
    assert "Status:       VERIFIED" in output
    assert "2. anomaly_detected" in output


def test_cli_inspect_json_is_machine_readable(tmp_path, capsys) -> None:
    from agentcontain.evidence import EvidenceEnvelope

    envelope = EvidenceEnvelope.from_execution(
        execution={
            "execution_id": "exec-2",
            "agent_id": "agent-2",
            "policy_id": "payments",
            "policy_digest": "sha256:test",
            "epoch": 1,
        },
        events=(
            {
                "name": "admission_verified",
                "execution_id": "exec-2",
                "epoch": 1,
                "sequence": 1,
                "timestamp": "2026-09-27T00:00:00+00:00",
                "details": {},
            },
        ),
        verification={"status": "verified"},
    )
    evidence = tmp_path / "evidence.json"
    evidence.write_text(envelope.to_json(), encoding="utf-8")

    assert cli.main(["inspect", "--evidence-file", str(evidence), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["agent"]["agent_id"] == "agent-2"
    assert payload["incident"]["execution_id"] == "exec-2"
    assert payload["timeline"][0]["name"] == "admission_verified"


def test_cli_primary_command_name() -> None:
    assert cli.build_parser().prog == "warrantkit"


def test_cli_demo_defaults_to_stale_warrant_replay(monkeypatch) -> None:
    from agentcontain import demo

    called = []
    monkeypatch.setattr(demo, "run_stale_warrant_demo", lambda: called.append("replay") or 0)
    monkeypatch.setattr(demo, "run_demo", lambda: called.append("lifecycle") or 0)

    assert cli.main(["demo"]) == 0
    assert called == ["replay"]


def test_cli_demo_lifecycle_is_explicit(monkeypatch) -> None:
    from agentcontain import demo

    called = []
    monkeypatch.setattr(demo, "run_stale_warrant_demo", lambda: called.append("replay") or 0)
    monkeypatch.setattr(demo, "run_demo", lambda: called.append("lifecycle") or 0)

    assert cli.main(["demo", "lifecycle"]) == 0
    assert called == ["lifecycle"]
