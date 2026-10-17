import asyncio
import json
from types import SimpleNamespace

import pytest

from agentcontain import Policy, admit, build_agentcontainment_engine, contain
from agentcontain.attestation import Ed25519Signer, Ed25519Verifier
from agent_containment.gateway import ActionGateway
from agent_containment.policy import PolicyEngine


def _invoke(tool, arguments: dict) -> str:
    # FunctionTool's direct invocation API expects the context fields normally
    # supplied by the Agents SDK runner. These tests exercise the actual SDK
    # FunctionTool parser/invocation path without making a model/API request.
    context = SimpleNamespace(tool_name=tool.name, _function_tool_arguments=None)
    return asyncio.run(tool.on_invoke_tool(context, json.dumps(arguments)))


def _setup(agent_id: str, capability: str):
    engine = build_agentcontainment_engine(agent_id)
    signer = Ed25519Signer.generate("openai-agents-test")
    admission = admit(
        Policy("openai-test-policy", capabilities=(capability,)),
        agent_id=agent_id,
        engine=engine,
        runtime_id=engine.runtime_id,
        warrant_signer=signer,
    )
    gateway = ActionGateway(PolicyEngine(), engine.controller)
    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    return engine, admission, gateway, verifier


def test_openai_agents_tool_executes_authorized_side_effect() -> None:
    from agentcontain.integrations.openai_agents import wrap_openai_tool

    calls: list[int] = []

    def refund(amount: int) -> str:
        """Issue a test refund."""
        calls.append(amount)
        return f"refunded:{amount}"

    _, admission, gateway, verifier = _setup("openai-agents-allow", "refund")
    protected = wrap_openai_tool(
        refund, admission, gateway, warrant_verifier=verifier
    )

    assert _invoke(protected, {"amount": 25}) == "refunded:25"
    assert calls == [25]


def test_openai_agents_tool_blocks_side_effect_after_containment() -> None:
    from agentcontain.integrations.openai_agents import (
        OpenAIAgentsWarrantError,
        wrap_openai_tool,
    )

    calls: list[str] = []

    def write_record(value: str) -> str:
        """Write a test record."""
        calls.append(value)
        return "written"

    _, admission, gateway, verifier = _setup(
        "openai-agents-stale", "write_record"
    )
    protected = wrap_openai_tool(
        write_record, admission, gateway, warrant_verifier=verifier
    )
    contain(admission)

    with pytest.raises(OpenAIAgentsWarrantError):
        _invoke(protected, {"value": "must-not-run"})
    assert calls == []


def test_openai_agents_tool_rejects_missing_capability() -> None:
    from agentcontain.integrations.openai_agents import (
        OpenAIAgentsWarrantError,
        wrap_openai_tool,
    )

    calls: list[str] = []

    def delete_record(record_id: str) -> str:
        """Delete a test record."""
        calls.append(record_id)
        return "deleted"

    _, admission, gateway, verifier = _setup(
        "openai-agents-capability", "read_only"
    )
    protected = wrap_openai_tool(
        delete_record, admission, gateway, warrant_verifier=verifier
    )

    with pytest.raises(OpenAIAgentsWarrantError):
        _invoke(protected, {"record_id": "123"})
    assert calls == []


def test_openai_agents_adapter_rejects_async_function() -> None:
    from agentcontain.integrations.openai_agents import wrap_openai_tool

    async def async_write(value: str) -> str:
        return value

    _, admission, gateway, verifier = _setup(
        "openai-agents-async", "async_write"
    )
    with pytest.raises(TypeError, match="async functions are not supported"):
        wrap_openai_tool(
            async_write, admission, gateway, warrant_verifier=verifier
        )



def test_openai_agents_tool_rejects_execution_if_runtime_epoch_changes_after_warrant_check(monkeypatch) -> None:
    """A tool cannot reuse a fresh lease after its pre-check authority goes stale."""
    import agentcontain.integrations.openai_agents as integration
    from agentcontain import issue_recovery_authorization, recover

    calls: list[str] = []

    def protected_write(value: str) -> str:
        calls.append(value)
        return "written"

    engine, admission, gateway, verifier = _setup(
        "openai-agents-toctou", "protected_write"
    )
    protected = integration.wrap_openai_tool(
        protected_write, admission, gateway, warrant_verifier=verifier
    )
    original_check = integration.verify_current_authority

    monkeypatch.setattr(integration, "verify_current_authority", check_then_contain)
    with pytest.raises(integration.OpenAIAgentsWarrantError):
        _invoke(protected, {"value": "must-not-run"})
    assert calls == []
