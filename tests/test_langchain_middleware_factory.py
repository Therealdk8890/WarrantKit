"""Smoke tests for WarrantKit's public LangChain middleware factory.

These tests exercise the actual object returned to application developers,
not only the framework-independent middleware implementation.
"""
from __future__ import annotations

import pytest

from agentcontain import Policy, admit, build_agentcontainment_engine, contain
from agentcontain.attestation import Ed25519Signer, Ed25519Verifier
from agentcontain.integrations.langchain_middleware import (
    LangChainWarrantError,
    warrantkit_middleware,
)
from agent_containment.gateway import ActionGateway
from agent_containment.policy import PolicyEngine


def _public_middleware(agent_id: str, capabilities: tuple[str, ...]):
    pytest.importorskip("langchain.agents.middleware")
    from langchain.agents.middleware import AgentMiddleware

    engine = build_agentcontainment_engine(agent_id)
    signer = Ed25519Signer.generate("langchain-public-middleware-test")
    admission = admit(
        Policy("middleware-public-api", capabilities=capabilities),
        agent_id=agent_id,
        engine=engine,
        runtime_id=engine.runtime_id,
        warrant_signer=signer,
    )
    gateway = ActionGateway(PolicyEngine(), engine.controller)
    middleware = warrantkit_middleware(
        admission,
        gateway,
        warrant_verifier=Ed25519Verifier({signer.key_id: signer.public_key()}),
    )
    assert isinstance(middleware, AgentMiddleware)
    return middleware, admission


class _Tool:
    def __init__(self, name: str) -> None:
        self.name = name


class _Request:
    def __init__(self, name: str) -> None:
        self.tool = _Tool(name)


def test_public_middleware_factory_returns_framework_middleware_and_allows_authorized_call():
    middleware, _ = _public_middleware(
        "agent-langchain-public-middleware-allow",
        ("payments_refund",),
    )
    calls: list[str] = []

    def handler(request):
        calls.append(request.tool.name)
        return "refunded"

    result = middleware.wrap_tool_call(_Request("payments_refund"), handler)

    assert result == "refunded"
    assert calls == ["payments_refund"]


def test_public_middleware_factory_denies_missing_capability_before_handler():
    middleware, _ = _public_middleware(
        "agent-langchain-public-middleware-deny",
        ("read_only",),
    )
    calls: list[str] = []

    def handler(request):
        calls.append(request.tool.name)
        return "must-not-run"

    with pytest.raises(LangChainWarrantError, match="does not grant capability"):
        middleware.wrap_tool_call(_Request("payments_write"), handler)

    assert calls == []


def test_public_middleware_factory_denies_stale_authority_before_handler():
    middleware, admission = _public_middleware(
        "agent-langchain-public-middleware-stale",
        ("payments_refund",),
    )
    calls: list[str] = []

    def handler(request):
        calls.append(request.tool.name)
        return "must-not-run"

    contain(admission)

    with pytest.raises(LangChainWarrantError):
        middleware.wrap_tool_call(_Request("payments_refund"), handler)

    assert calls == []
