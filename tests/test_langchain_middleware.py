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

    with pytest.raises(LangChainWarrantError, match="runtime is not active|signed Warrant attestation"):
        middleware.wrap_tool_call(_Request("payments_refund"), handler)

    assert calls == []


def test_native_middleware_rejects_contain_recover_race_after_snapshot(monkeypatch) -> None:
    """A fresh post-recovery lease must not rescue a stale pre-recovery Warrant."""
    middleware, admission = _middleware(
        "agent-langchain-middleware-race",
        ("payments_refund",),
    )
    engine = admission.engine
    runtime = engine.controller.runtime
    service = engine.service
    original_snapshot = runtime.snapshot
    transitioned = False
    calls = []

    def snapshot_then_transition():
        nonlocal transitioned
        snapshot = original_snapshot()
        if not transitioned:
            transitioned = True
            service.contain(admission.identity.agent_id)
            authorization = service.issue_recovery_authorization(admission.identity.agent_id)
            service.recover(admission.identity.agent_id, authorization)
        return snapshot

    monkeypatch.setattr(runtime, "snapshot", snapshot_then_transition)

    def handler(request):
        calls.append(request.tool.name)
        return "must-not-run"

    with pytest.raises(LangChainWarrantError):
        middleware.wrap_tool_call(_Request("payments_refund"), handler)

    assert transitioned
    assert runtime.epoch == admission.identity.epoch + 2
    assert calls == []
