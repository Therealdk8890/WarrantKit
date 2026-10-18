import pytest

from agentcontain import Policy, admit, build_agentcontainment_engine, contain


def _setup(agent_id: str, capability: str):
    from agentcontain.attestation import Ed25519Signer, Ed25519Verifier
    from agent_containment.gateway import ActionGateway
    from agent_containment.policy import PolicyEngine

    engine = build_agentcontainment_engine(agent_id)
    signer = Ed25519Signer.generate("mcp-test")
    admission = admit(
        Policy("mcp-test-policy", capabilities=(capability,)),
        agent_id=agent_id,
        engine=engine,
        runtime_id=engine.runtime_id,
        warrant_signer=signer,
    )
    gateway = ActionGateway(PolicyEngine(), engine.controller)
    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    return engine, admission, gateway, verifier


def test_mcp_handler_executes_authorized_side_effect():
    from agentcontain.integrations.mcp import wrap_mcp_tool

    calls = []

    def write_record(value: str) -> str:
        """Write a test record."""
        calls.append(value)
        return f"written:{value}"

    _, admission, gateway, verifier = _setup("mcp-allow", "write_record")
    protected = wrap_mcp_tool(write_record, admission, gateway, warrant_verifier=verifier)

    assert protected("safe") == "written:safe"
    assert calls == ["safe"]


def test_mcp_handler_blocks_side_effect_after_containment():
    from agentcontain.integrations.mcp import MCPWarrantError, wrap_mcp_tool

    calls = []

    def write_record(value: str) -> str:
        calls.append(value)
        return "written"

    _, admission, gateway, verifier = _setup("mcp-stale", "write_record")
    protected = wrap_mcp_tool(write_record, admission, gateway, warrant_verifier=verifier)
    contain(admission)

    with pytest.raises(MCPWarrantError):
        protected("must-not-run")
    assert calls == []


def test_mcp_handler_rejects_missing_capability_before_side_effect():
    from agentcontain.integrations.mcp import MCPWarrantError, wrap_mcp_tool

    calls = []

    def delete_record(record_id: str) -> str:
        calls.append(record_id)
        return "deleted"

    _, admission, gateway, verifier = _setup("mcp-capability", "read_only")
    protected = wrap_mcp_tool(delete_record, admission, gateway, warrant_verifier=verifier)

    with pytest.raises(MCPWarrantError, match="does not grant capability"):
        protected("123")
    assert calls == []


def test_mcp_adapter_rejects_async_handler():
    from agentcontain.integrations.mcp import wrap_mcp_tool

    async def async_write(value: str) -> str:
        return value

    _, admission, gateway, verifier = _setup("mcp-async", "async_write")
    with pytest.raises(TypeError, match="async MCP handlers are not supported"):
        wrap_mcp_tool(async_write, admission, gateway, warrant_verifier=verifier)


def test_mcp_handler_rejects_execution_if_epoch_changes_after_warrant_check(monkeypatch):
    import agentcontain.integrations.mcp as integration
    from agentcontain import issue_recovery_authorization, recover

    calls = []

    def write_record(value: str) -> str:
        calls.append(value)
        return "written"

    _, admission, gateway, verifier = _setup("mcp-toctou", "write_record")
    protected = integration.wrap_mcp_tool(
        write_record, admission, gateway, warrant_verifier=verifier
    )
    original_check = integration.verify_current_authority

    def check_then_contain(*args, **kwargs):
        original_check(*args, **kwargs)
        contain(admission)
        recover(admission, issue_recovery_authorization(admission))

    monkeypatch.setattr(integration, "verify_current_authority", check_then_contain)
    with pytest.raises(integration.MCPWarrantError):
        protected("must-not-run")
    assert calls == []
