from agentcontain.attestation import Ed25519Signer, Ed25519Verifier
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
    signer = Ed25519Signer.generate("crewai-test")
    admission = admit(
        Policy("payments", capabilities=("payments_refund",)),
        agent_id="agent-crewai",
        engine=engine,
        runtime_id=engine.runtime_id,
        warrant_signer=signer,
    )
    gateway = ActionGateway(PolicyEngine(), engine.controller)
    tool = PaymentTool()
    protected = wrap_crewai_tool(tool, admission, gateway, warrant_verifier=Ed25519Verifier({signer.key_id: signer.public_key()}))

    assert protected.run(amount=25) == "refunded:25"
    assert tool.calls == [25]


def test_crewai_tool_rejects_after_containment_before_side_effect() -> None:
    PaymentTool = _integration()
    from agentcontain.integrations.crewai import CrewAIWarrantError, wrap_crewai_tool

    engine = build_agentcontainment_engine("agent-crewai-stale")
    signer = Ed25519Signer.generate("crewai-test")
    admission = admit(
        Policy("payments", capabilities=("payments_refund",)),
        agent_id="agent-crewai-stale",
        engine=engine,
        runtime_id=engine.runtime_id,
        warrant_signer=signer,
    )
    gateway = ActionGateway(PolicyEngine(), engine.controller)
    tool = PaymentTool()
    protected = wrap_crewai_tool(tool, admission, gateway, warrant_verifier=Ed25519Verifier({signer.key_id: signer.public_key()}))

    contain(admission)

    with pytest.raises(CrewAIWarrantError):
        protected.run(amount=25)

    assert tool.calls == []


def test_crewai_tool_rejects_missing_capability_before_side_effect() -> None:
    PaymentTool = _integration()
    from agentcontain.integrations.crewai import CrewAIWarrantError, wrap_crewai_tool

    engine = build_agentcontainment_engine("agent-crewai-capability")
    signer = Ed25519Signer.generate("crewai-test")
    admission = admit(
        Policy("limited", capabilities=("read_only",)),
        agent_id="agent-crewai-capability",
        engine=engine,
        runtime_id=engine.runtime_id,
        warrant_signer=signer,
    )
    gateway = ActionGateway(PolicyEngine(), engine.controller)
    tool = PaymentTool()
    protected = wrap_crewai_tool(tool, admission, gateway, warrant_verifier=Ed25519Verifier({signer.key_id: signer.public_key()}))

    with pytest.raises(CrewAIWarrantError):
        protected.run(amount=25)

    assert tool.calls == []

def test_crewai_tool_rejects_replay_of_another_valid_signed_warrant() -> None:
    """A different authentic Warrant must not replace this wrapper's authority."""
    PaymentTool = _integration()
    from datetime import datetime, timedelta, timezone

    from agentcontain import ExecutionIdentity
    from agentcontain.integrations.crewai import CrewAIWarrantError, wrap_crewai_tool
    from agentcontain.warrant import Warrant

    engine = build_agentcontainment_engine("agent-crewai-replay")
    signer = Ed25519Signer.generate("crewai-replay-test")
    policy = Policy("payments", capabilities=("payments_refund",))
    admission = admit(
        policy,
        agent_id="agent-crewai-replay",
        engine=engine,
        runtime_id=engine.runtime_id,
        warrant_signer=signer,
    )
    gateway = ActionGateway(PolicyEngine(), engine.controller)
    tool = PaymentTool()
    protected = wrap_crewai_tool(
        tool,
        admission,
        gateway,
        warrant_verifier=Ed25519Verifier({signer.key_id: signer.public_key()}),
    )

    now = datetime.now(timezone.utc)
    replay_identity = ExecutionIdentity.create(
        admission.identity.agent_id,
        admission.identity.policy_id,
        admission.identity.policy_digest,
        runtime_id=engine.runtime_id,
        epoch=admission.identity.epoch,
    )
    replay_warrant = Warrant.issue(
        warrant_id="other-valid-crewai-warrant",
        issuer="warrantkit",
        agent_id=replay_identity.agent_id,
        execution_id=replay_identity.execution_id,
        policy=admission.policy,
        runtime_id=engine.runtime_id,
        epoch=replay_identity.epoch,
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
        capabilities=("payments_refund",),
    )
    admission.identity = replay_identity
    admission.warrant = replay_warrant
    admission.warrant_attestation = signer.sign_warrant(replay_warrant).to_dict()

    with pytest.raises(CrewAIWarrantError, match="authority changed"):
        protected.run(amount=25)

    assert tool.calls == []


def test_crewai_tool_rejects_signed_warrant_that_exceeds_accepted_policy() -> None:
    """A valid signature must not let a Warrant exceed the accepted policy."""
    PaymentTool = _integration()

    from agentcontain.integrations.crewai import CrewAIWarrantError, wrap_crewai_tool
    from agentcontain.warrant import Warrant

    engine = build_agentcontainment_engine("agent-crewai-policy-escalation")
    signer = Ed25519Signer.generate("crewai-policy-escalation-test")
    admission = admit(
        Policy("payments", capabilities=("payments_refund",)),
        agent_id="agent-crewai-policy-escalation",
        engine=engine,
        runtime_id=engine.runtime_id,
        warrant_signer=signer,
    )

    # Simulate a correctly signed but overbroad serialized Warrant. The
    # supported issue() API must reject this input, so mutate the payload
    # before signing it to exercise the adapter's independent policy check.
    payload = admission.warrant.to_dict()
    payload["authority"]["capabilities"] = ["payments_refund", "admin"]
    overbroad_warrant = Warrant.from_dict(payload)
    admission.warrant = overbroad_warrant
    admission.warrant_attestation = signer.sign_warrant(overbroad_warrant).to_dict()

    gateway = ActionGateway(PolicyEngine(), engine.controller)
    tool = PaymentTool()
    protected = wrap_crewai_tool(
        tool,
        admission,
        gateway,
        warrant_verifier=Ed25519Verifier({signer.key_id: signer.public_key()}),
    )

    with pytest.raises(CrewAIWarrantError, match="Warrant capabilities exceed the accepted policy"):
        protected.run(amount=25)

    assert tool.calls == []
