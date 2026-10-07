import pytest

from agentcontain import Policy, admit, build_agentcontainment_engine, contain
from agent_containment.gateway import ActionGateway
from agent_containment.policy import PolicyEngine


def _integration():
    pytest.importorskip("crewai")
    from pydantic import BaseModel, Field
    from crewai.tools import BaseTool

    class PaymentInput(BaseModel):
        amount: int = Field(gt=0)

    class PaymentTool(BaseTool):
        name: str = "payments_refund"
        description: str = "Issue a payment refund."
        args_schema: type[BaseModel] = PaymentInput
        calls: list[int] = []

        def _run(self, amount: int) -> str:
            self.calls.append(amount)
            return f"refunded:{amount}"

    return PaymentTool


def test_crewai_tool_runs_with_matching_warrant_capability() -> None:
    PaymentTool = _integration()
    from agentcontain.integrations.crewai import wrap_crewai_tool

    engine = build_agentcontainment_engine("agent-crewai")
    admission = admit(
        Policy("payments", capabilities=("payments_refund",)),
        agent_id="agent-crewai",
        engine=engine,
        runtime_id=engine.runtime_id,
    )
    gateway = ActionGateway(PolicyEngine(), engine.controller)
    tool = PaymentTool()
    protected = wrap_crewai_tool(tool, admission, gateway)

    assert protected.run(amount=25) == "refunded:25"
    assert tool.calls == [25]


def test_crewai_tool_rejects_after_containment_before_side_effect() -> None:
    PaymentTool = _integration()
    from agentcontain.integrations.crewai import CrewAIWarrantError, wrap_crewai_tool

    engine = build_agentcontainment_engine("agent-crewai-stale")
    admission = admit(
        Policy("payments", capabilities=("payments_refund",)),
        agent_id="agent-crewai-stale",
        engine=engine,
        runtime_id=engine.runtime_id,
    )
    gateway = ActionGateway(PolicyEngine(), engine.controller)
    tool = PaymentTool()
    protected = wrap_crewai_tool(tool, admission, gateway)

    contain(admission)

    with pytest.raises(CrewAIWarrantError):
        protected.run(amount=25)

    assert tool.calls == []


def test_crewai_tool_rejects_missing_capability_before_side_effect() -> None:
    PaymentTool = _integration()
    from agentcontain.integrations.crewai import CrewAIWarrantError, wrap_crewai_tool

    engine = build_agentcontainment_engine("agent-crewai-capability")
    admission = admit(
        Policy("limited", capabilities=("read_only",)),
        agent_id="agent-crewai-capability",
        engine=engine,
        runtime_id=engine.runtime_id,
    )
    gateway = ActionGateway(PolicyEngine(), engine.controller)
    tool = PaymentTool()
    protected = wrap_crewai_tool(tool, admission, gateway)

    with pytest.raises(CrewAIWarrantError):
        protected.run(amount=25)

    assert tool.calls == []
