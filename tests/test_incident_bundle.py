from pathlib import Path

import pytest

from tools.incident_bundle import verify_incident_bundle, write_incident_bundle


def test_incident_bundle_round_trip(tmp_path: Path) -> None:
    bundle = tmp_path / "incident"
    manifest = write_incident_bundle(
        bundle,
        incident_id="INC-test",
        authority={"warrant_id": "w-1", "runtime": {"epoch": 0}},
        containment={"epoch_before": 0, "epoch_after": 1, "external_verified": True},
        runtime_evidence={"execution": {"execution_id": "exec-1"}},
        external_proof={"cgroup_populated": False, "workload_exit_code": -9},
        provenance={"producer": "test"},
    )

    result = verify_incident_bundle(bundle)
    assert result["status"] == "VERIFIED"
    assert result["incident_id"] == "INC-test"
    assert manifest["incident_id"] == "INC-test"


def test_incident_bundle_fails_closed_on_tamper(tmp_path: Path) -> None:
    bundle = tmp_path / "incident"
    write_incident_bundle(
        bundle,
        incident_id="INC-tamper",
        authority={"warrant_id": "w-1"},
        containment={"epoch_after": 1},
        runtime_evidence={"status": "observed"},
        external_proof={"cgroup_populated": False},
        provenance={"producer": "test"},
    )

    (bundle / "external-proof.json").write_text(
        '{"cgroup_populated":true}\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="digest mismatch"):
        verify_incident_bundle(bundle)
