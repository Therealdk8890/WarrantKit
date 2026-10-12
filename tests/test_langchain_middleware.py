from agentcontain.attestation import Ed25519Signer, Ed25519Verifier
import pytest

from agentcontain import Policy, admit, build_agentcontainment_engine, contain
from agentcontain.integrations.langchain_middleware import (
    LangChainWarrantError,
    WarrantKitMiddleware,
)
from agent_containment.gateway import ActionGateway
from agent_containment.policy import PolicyEngine


class _Tool:
    def __init__(self, name: str) -> None:
        self.name = name


class _Request:
    def __init__(self, tool_name: str) -> None:
        self.tool = _Tool(tool_name)


def _middleware(agent_id: str, capabilities: tuple[str, ...]):
    engine = build_agentcontainment_engine(agent_id)
    signer = Ed25519Signer.generate("middleware-test")
    admission = admit(
        Policy("payments", capabilities=capabilities),
        agent_id=agent_id,
        engine=engine,
        runtime_id=engine.runtime_id,
        warrant_signer=signer,
    )
    gateway = ActionGateway(PolicyEngine(), engine.controller)
    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    return WarrantKitMiddleware(admission, gateway, warrant_verifier=verifier), admission


def test_native_middleware_runs_handler_with_matching_capability() -> None:
    middleware, _ = _middleware("agent-langchain-middleware", ("payments_refund",))
    calls = []

    def handler(request):
        calls.append(request.tool.name)
        return "refunded"

    result = middleware.wrap_tool_call(
        _Request("payments_refund"),
        handler,
    )

    assert result == "refunded"
    assert calls == ["payments_refund"]


def test_native_middleware_rejects_missing_capability_before_handler() -> None:
    middleware, _ = _middleware("agent-langchain-middleware-capability", ("read_only",))
    calls = []

    def handler(request):
        calls.append(request.tool.name)
        return "must-not-run"

    with pytest.raises(LangChainWarrantError, match="does not grant capability"):
        middleware.wrap_tool_call(_Request("payments_write"), handler)

    assert calls == []


def test_native_middleware_rejects_after_containment_before_handler() -> None:
    middleware, admission = _middleware(
        "agent-langchain-middleware-contained",
        ("payments_refund",),
    )
    calls = []

    def handler(request):
        calls.append(request.tool.name)
        return "must-not-run"

    contain(admission)

    with pytest.raises(LangChainWarrantError, match="signed Warrant attestation"):
        middleware.wrap_tool_call(_Request("payments_refund"), handler)

    assert calls == []


def test_native_middleware_rejects_replay_of_another_valid_signed_warrant() -> None:
    """A different authentic Warrant must not replace middleware's pinned authority."""
    from datetime import datetime, timedelta, timezone

    from agentcontain import ExecutionIdentity
    from agentcontain.warrant import Warrant

    engine = build_agentcontainment_engine("agent-langchain-middleware-replay")
    signer = Ed25519Signer.generate("middleware-replay-test")
    policy = Policy("payments", capabilities=("payments_refund",))
    admission = admit(
        policy,
        agent_id="agent-langchain-middleware-replay",
        engine=engine,
        runtime_id=engine.runtime_id,
        warrant_signer=signer,
    )
    gateway = ActionGateway(PolicyEngine(), engine.controller)
    middleware = WarrantKitMiddleware(
        admission,
        gateway,
        warrant_verifier=Ed25519Verifier({signer.key_id: signer.public_key()}),
    )
    calls = []

    def handler(request):
        calls.append(request.tool.name)
        return "must-not-run"

    now = datetime.now(timezone.utc)
    replay_identity = ExecutionIdentity.create(
        admission.identity.agent_id,
        admission.identity.policy_id,
        admission.identity.policy_digest,
        runtime_id=engine.runtime_id,
        epoch=admission.identity.epoch,
    )
    replay_warrant = Warrant.issue(
        warrant_id="other-valid-middleware-warrant",
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

    with pytest.raises(LangChainWarrantError, match="authority changed"):
        middleware.wrap_tool_call(_Request("payments_refund"), handler)

    assert calls == []
