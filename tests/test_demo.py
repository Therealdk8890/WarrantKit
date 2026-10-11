from agentcontain import cli


def test_cli_demo_is_no_root_and_rejects_stale_warrant(capsys) -> None:
    assert cli.main(["demo"]) == 0

    output = capsys.readouterr().out
    assert "stale-Warrant replay proof" in output
    assert "retained Warrant ACCEPTED" in output
    assert "Containment advanced runtime epoch" in output
    assert "Retained pre-containment Warrant: REJECTED" in output
    assert "does not prove kernel-level workload termination" in output
    assert "does not isolate the" in output


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
