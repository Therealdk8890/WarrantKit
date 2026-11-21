"""Keep the README kill-switch example runnable and its output honest."""
import runpy
from pathlib import Path

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "kill_switch_refund_agent" / "refund_agent.py"


def test_kill_switch_example_blocks_tool_call_after_containment(capsys):
    namespace = runpy.run_path(str(EXAMPLE))
    assert namespace["main"]() == [25]
    out = capsys.readouterr().out
    assert "before containment: refunded $25" in out
    assert "runtime epoch now 1" in out
    assert "after containment: DENIED" in out
    assert "refunds actually issued: [25]" in out


def test_example_readme_documents_the_real_output():
    readme = (EXAMPLE.parent / "README.md").read_text()
    for line in (
        "before containment: refunded $25",
        "contained: complete=True, runtime epoch now 1",
        "after containment: DENIED - runtime execution lease unavailable",
        "refunds actually issued: [25]",
    ):
        assert line in readme
