from agentcontain.attestation import Ed25519Signer, Ed25519Verifier
from dataclasses import replace
import pytest

from agentcontain import Policy, admit, build_agentcontainment_engine, contain, recontain
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
    signer = Ed25519Signer.generate("langchain-test")
    admission = admit(
        Policy("payments", capabilities=("payments_refund",)),
        agent_id="agent-langchain",
        engine=engine,
        runtime_id=engine.runtime_id,
        warrant_signer=signer,
    )
    gateway = ActionGateway(PolicyEngine(), engine.controller)
    protected = __import__(
        "agentcontain.integrations.langchain",
        fromlist=["wrap_langchain_tool"],
    ).wrap_langchain_tool(
        payments_refund,
        admission,
        gateway,
        warrant_verifier=Ed25519Verifier({signer.key_id: signer.public_key()}),
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
    wrapped = protected.wrap_langchain_tool(consequential_write, admission, gateway, warrant_verifier=Ed25519Verifier({signer.key_id: signer.public_key()}))

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
    wrapped = integration.wrap_langchain_tool(production_write, admission, gateway, warrant_verifier=Ed25519Verifier({signer.key_id: signer.public_key()}))

    with pytest.raises(integration.LangChainWarrantError):
        wrapped.invoke({"value": "must-not-run"})

    assert calls == []


def test_recontainment_requires_prior_containment() -> None:
    from agentcontain import Policy, admit, build_agentcontainment_engine

    engine = build_agentcontainment_engine("agent-recontain-precondition")
    admission = admit(
        Policy("writes", capabilities=("write",)),
        agent_id="agent-recontain-precondition",
        engine=engine,
        runtime_id=engine.runtime_id,
    )

    with pytest.raises(RuntimeError, match="already-contained"):
        recontain(admission)

    assert admission.machine.state.value == "admitted"
    assert admission.identity.epoch == 0


def test_langchain_wrapper_rejects_replaced_admission_warrant() -> None:
    pytest.importorskip("langchain_core")
    from langchain_core.tools import tool
    from agentcontain.warrant import WarrantAuthority
    from agentcontain.integrations.langchain import LangChainWarrantError, wrap_langchain_tool

    calls = []

    @tool
    def protected_write(value: str) -> str:
        """Perform a protected write."""
        calls.append(value)
        return "written"

    engine = build_agentcontainment_engine("agent-langchain-replaced-warrant")
    admission = admit(
        Policy("limited", capabilities=("protected_write",)),
        agent_id="agent-langchain-replaced-warrant",
        engine=engine,
        runtime_id=engine.runtime_id,
    )
    gateway = ActionGateway(PolicyEngine(), engine.controller)
    wrapped = wrap_langchain_tool(protected_write, admission, gateway)

    assert admission.warrant is not None
    original = admission.warrant
    admission.warrant = replace(
        original,
        authority=WarrantAuthority(
            policy_id=original.authority.policy_id,
            policy_digest=original.authority.policy_digest,
            capabilities=("protected_write", "admin"),
            constraints=original.authority.constraints,
        ),
    )

    with pytest.raises(LangChainWarrantError, match="exceed the accepted policy"):
        wrapped.invoke({"value": "must-not-run"})
    assert calls == []
