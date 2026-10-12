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
    signer = Ed25519Signer.generate("langchain-test")
    admission = admit(
        Policy("writes", capabilities=("consequential_write",)),
        agent_id="agent-langchain-stale",
        engine=engine,
        runtime_id=engine.runtime_id,
        warrant_signer=signer,
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
    signer = Ed25519Signer.generate("langchain-test")
    admission = admit(
        Policy("limited", capabilities=("read_only",)),
        agent_id="agent-langchain-capability",
        engine=engine,
        runtime_id=engine.runtime_id,
        warrant_signer=signer,
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
    signer = Ed25519Signer.generate("langchain-test")
    admission = admit(
        Policy("writes", capabilities=("write",)),
        agent_id="agent-recontain-precondition",
        engine=engine,
        runtime_id=engine.runtime_id,
        warrant_signer=signer,
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
    signer = Ed25519Signer.generate("langchain-test")
    admission = admit(
        Policy("limited", capabilities=("protected_write",)),
        agent_id="agent-langchain-replaced-warrant",
        engine=engine,
        runtime_id=engine.runtime_id,
        warrant_signer=signer,
    )
    gateway = ActionGateway(PolicyEngine(), engine.controller)
    wrapped = wrap_langchain_tool(protected_write, admission, gateway, warrant_verifier=Ed25519Verifier({signer.key_id: signer.public_key()}))

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

    with pytest.raises(LangChainWarrantError, match="signed Warrant payload does not match"):
        wrapped.invoke({"value": "must-not-run"})
    assert calls == []


def test_langchain_tool_rejects_unsigned_warrant_before_side_effect() -> None:
    pytest.importorskip("langchain_core")
    from langchain_core.tools import tool
    from agentcontain.integrations.langchain import LangChainWarrantError, wrap_langchain_tool

    calls = []

    @tool
    def protected_write(value: str) -> str:
        calls.append(value)
        return "written"

    engine = build_agentcontainment_engine("agent-langchain-unsigned")
    admission = admit(
        Policy("limited", capabilities=("protected_write",)),
        agent_id="agent-langchain-unsigned",
        engine=engine,
        runtime_id=engine.runtime_id,
    )
    trusted_signer = Ed25519Signer.generate("trusted-but-not-used")
    verifier = Ed25519Verifier({trusted_signer.key_id: trusted_signer.public_key()})
    gateway = ActionGateway(PolicyEngine(), engine.controller)
    wrapped = wrap_langchain_tool(protected_write, admission, gateway, warrant_verifier=verifier)

    with pytest.raises(LangChainWarrantError, match="no signed Warrant attestation"):
        wrapped.invoke({"value": "must-not-run"})
    assert calls == []


def test_langchain_wrapper_rejects_replay_of_another_valid_signed_warrant():
    """A different authentic Warrant must not replace this wrapper's authority."""
    pytest.importorskip("langchain_core")
    from datetime import datetime, timedelta, timezone
    from langchain_core.tools import tool
    from agentcontain import ExecutionIdentity
    from agentcontain.warrant import Warrant
    from agentcontain.integrations.langchain import LangChainWarrantError, wrap_langchain_tool

    calls = []

    @tool
    def protected_write(value: str) -> str:
        calls.append(value)
        return "written"

    engine = build_agentcontainment_engine("agent-langchain-replay")
    signer = Ed25519Signer.generate("langchain-replay-test")
    policy = Policy("limited", capabilities=("protected_write",))
    admission = admit(
        policy,
        agent_id="agent-langchain-replay",
        engine=engine,
        runtime_id=engine.runtime_id,
        warrant_signer=signer,
    )
    gateway = ActionGateway(PolicyEngine(), engine.controller)
    wrapped = wrap_langchain_tool(
        protected_write,
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
        warrant_id="other-valid-warrant",
        issuer="warrantkit",
        agent_id=replay_identity.agent_id,
        execution_id=replay_identity.execution_id,
        policy=admission.policy,
        runtime_id=engine.runtime_id,
        epoch=replay_identity.epoch,
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
        capabilities=("protected_write",),
    )
    admission.identity = replay_identity
    admission.warrant = replay_warrant
    admission.warrant_attestation = signer.sign_warrant(replay_warrant).to_dict()

    with pytest.raises(LangChainWarrantError, match="authority changed"):
        wrapped.invoke({"value": "must-not-run"})
    assert calls == []
