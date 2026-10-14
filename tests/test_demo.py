from agentcontain import cli


def test_cli_demo_is_no_root_and_rejects_stale_warrant(capsys) -> None:
    assert cli.main(["demo"]) == 0

    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 2
    assert lines[0].startswith("PASS:")
    assert "retained Warrant ACCEPTED at epoch 0" in lines[0]
    assert "containment advanced epoch to 1" in lines[0]
    assert "replay REJECTED" in lines[0]
    assert lines[1].startswith("SCOPE:")
    assert "in-process verifier/controller" in lines[1]
    assert "no kernel-kill proof or independent evidence claim" in lines[1]


def test_demo_lifecycle_has_distinct_detection_and_verification() -> None:
    from agentcontain.demo import SimulatedEngine
    from agentcontain.engine import admit
    from agentcontain.policy import Policy

    admission = admit(
        Policy("demo", capabilities=("simulated-containment",)),
        agent_id="demo-agent",
        engine=SimulatedEngine(),
    )
    admission.engine.contain()
    admission.machine.contain()
    admission.machine.detect({"reason": "demo_policy_violation"})
    admission.machine.fence()
    admission.machine.halt()
    admission.machine.verify()

    assert admission.machine.state.value == "verified"
    assert admission.machine.events.events[-1].name == "verification_completed"
    assert len(admission.machine.events.events) == 6
