import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
VERIFIER = ROOT / "tools" / "verify_runtime_evidence.py"
FIXTURE = ROOT / "tests" / "fixtures" / "runtime_pinned_evidence.json"


def _run(document, tmp_path):
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(VERIFIER), str(path)],
        cwd=ROOT, capture_output=True, text=True,
    )


def _digest(record):
    canonical = json.dumps(
        record, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _fixture():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_standalone_verifier_accepts_valid_fixture(tmp_path):
    result = _run(_fixture(), tmp_path)
    assert result.returncode == 0
    assert result.stdout.strip() == "OBSERVED"


def test_standalone_verifier_requires_second_evidence_channel(tmp_path):
    document = _fixture()
    del document["proof"]["runtime_binding"]["observation"]
    result = _run(document, tmp_path)
    assert result.returncode == 1
    assert "runtime binding has an invalid shape" in result.stderr


def test_standalone_verifier_requires_observation_after_enforcement(tmp_path):
    document = _fixture()
    observation = document["proof"]["runtime_binding"]["observation"]
    observation["record"]["observed_at"] = "2026-09-30T12:00:01Z"
    observation["observed_at"] = "2026-09-30T12:00:01Z"
    observation["digest"] = _digest(observation["record"])
    result = _run(document, tmp_path)
    assert result.returncode == 1
    assert "observation predates enforcement" in result.stderr


def test_standalone_verifier_rejects_byte_level_mutation(tmp_path):
    document = _fixture()
    document["proof"]["runtime_binding"]["observation"]["record"]["can_execute"] = True
    result = _run(document, tmp_path)
    assert result.returncode == 1
    assert "digest does not match record" in result.stderr


def test_standalone_verifier_rejects_wrong_runtime_identity(tmp_path):
    document = _fixture()
    document["proof"]["runtime_binding"]["runtime_id"] = "runtime-forged"
    result = _run(document, tmp_path)
    assert result.returncode == 1
    assert "runtime binding runtime_id does not match execution" in result.stderr


def test_standalone_verifier_rejects_rewritten_but_rehashed_records(tmp_path):
    document = _fixture()
    binding = document["proof"]["runtime_binding"]
    for section in ("authority", "enforcement", "observation"):
        record = binding[section]["record"]
        record["runtime_id"] = "runtime-forged"
        binding[section]["digest"] = _digest(record)
    result = _run(document, tmp_path)
    assert result.returncode == 1
    assert "runtime_id does not match" in result.stderr


def test_standalone_verifier_rejects_stale_epoch(tmp_path):
    document = _fixture()
    document["proof"]["runtime_binding"]["epoch"] = 2
    result = _run(document, tmp_path)
    assert result.returncode == 1
    assert "runtime binding epoch does not match execution" in result.stderr
