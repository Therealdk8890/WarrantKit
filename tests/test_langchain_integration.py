import pytest

from agentcontain import Policy, admit, build_agentcontainment_engine, contain
from agent_containment.gateway import ActionGateway
from agent_containment.policy import PolicyEngine


def test_langchain_tool_runs_only_with_matching_warrant_capability() -> None:
    pytest.importorskip("langchain_core")
    from langchain_core.tools import tool

    @tool
    def payments_refund(amount: int) -> str:
        """Issue a payment refund."""
        return f"refunded:{amount}"

    engine = build_agentcontainment_engine("agent-langchain")
    admission = admit(
        Policy("payments", capabilities=("payments_refund",)),
        agent_id="agent-langchain",
        engine=engine,
        runtime_id=engine.runtime_id,
    )
    gateway = ActionGateway(PolicyEngine(), engine.controller)
    protected = __import__(
        "agentcontain.integrations.langchain",
        fromlist=["wrap_langchain_tool"],
    ).wrap_langchain_tool(
        payments_refund,
        admission,
        gateway,
    )

    assert protected.invoke({"amount": 25}) == "refunded:25"


def test_langchain_tool_rejects_after_runtime_containment() -> None:
    pytest.importorskip("langchain_core")
    from langchain_core.tools import tool

    calls = []

    @tool
    def consequential_write(value: str) -> str:
        """Perform a consequential write."""
        calls.append(value)
        return "written"

    engine = build_agentcontainment_engine("agent-langchain-stale")
    admission = admit(
        Policy("writes", capabilities=("consequential_write",)),
        agent_id="agent-langchain-stale",
        engine=engine,
        runtime_id=engine.runtime_id,
    )
    gateway = ActionGateway(PolicyEngine(), engine.controller)
    protected = __import__(
        "agentcontain.integrations.langchain",
        fromlist=["wrap_langchain_tool", "LangChainWarrantError"],
    )
    wrapped = protected.wrap_langchain_tool(consequential_write, admission, gateway)

    contain(admission)

    with pytest.raises(protected.LangChainWarrantError):
        wrapped.invoke({"value": "must-not-run"})

    assert calls == []


def test_langchain_tool_rejects_missing_capability_before_side_effect() -> None:
    pytest.importorskip("langchain_core")
    from langchain_core.tools import tool

    calls = []

    @tool
    def production_write(value: str) -> str:
        """Write to production."""
        calls.append(value)
        return "written"

    engine = build_agentcontainment_engine("agent-langchain-capability")
    admission = admit(
        Policy("limited", capabilities=("read_only",)),
        agent_id="agent-langchain-capability",
        engine=engine,
        runtime_id=engine.runtime_id,
    )
    gateway = ActionGateway(PolicyEngine(), engine.controller)
    integration = __import__(
        "agentcontain.integrations.langchain",
        fromlist=["wrap_langchain_tool", "LangChainWarrantError"],
    )
    wrapped = integration.wrap_langchain_tool(production_write, admission, gateway)

    with pytest.raises(integration.LangChainWarrantError):
        wrapped.invoke({"value": "must-not-run"})

    assert calls == []
