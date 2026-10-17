"""Diagnostic reproducer for the pre-PR-196 lease TOCTOU window.

This test is intentionally run against the vulnerable baseline commit by CI.
It should PASS there by demonstrating the protected side effect executes after
containment and recovery happen between Warrant verification and gateway use.
The ordinary adapter regression test on the PR head asserts the opposite.
"""
import asyncio
import json
import os
from types import SimpleNamespace

import pytest

from agentcontain import (
    Policy,
    admit,
    build_agentcontainment_engine,
    contain,
    issue_recovery_authorization,
    recover,
)
from agentcontain.attestation import Ed25519Signer, Ed25519Verifier
from agent_containment.gateway import ActionGateway
from agent_containment.policy import PolicyEngine


def _invoke(tool, arguments: dict):
    context = SimpleNamespace(tool_name=tool.name, _function_tool_arguments=None)
    return asyncio.run(tool.on_invoke_tool(context, json.dumps(arguments)))


def _setup(agent_id: str, capability: str):
    engine = build_agentcontainment_engine(agent_id)
    signer = Ed25519Signer.generate("warrantkit-toctou-baseline-test")
    admission = admit(
        Policy("toctou-baseline-policy", capabilities=(capability,)),
        agent_id=agent_id,
        engine=engine,
        runtime_id=engine.runtime_id,
        warrant_signer=signer,
    )
    gateway = ActionGateway(PolicyEngine(), engine.controller)
    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    return admission, gateway, verifier


@pytest.mark.skipif(
    os.environ.get("WARRANTKIT_RUN_VULNERABLE_BASELINE_REPRO") != "1",
    reason="diagnostic must run only against the explicitly selected pre-fix baseline",
)
def test_pre_fix_wrapper_can_execute_after_epoch_changes_between_check_and_use(monkeypatch):
    import agentcontain.integrations.openai_agents as integration

    calls: list[str] = []

    def protected_write(value: str) -> str:
        calls.append(value)
        return "written"

    admission, gateway, verifier = _setup("toctou-baseline", "protected_write")
    protected = integration.wrap_openai_tool(
        protected_write, admission, gateway, warrant_verifier=verifier
    )
    original_check = integration.verify_current_authority

    def verify_then_rotate_epoch(*args, **kwargs):
        original_check(*args, **kwargs)
        # Deterministically create the check/use gap: verification succeeds,
        # then runtime containment and recovery advance the epoch before the
        # wrapper asks the gateway to execute.
        contain(admission)
        authorization = issue_recovery_authorization(admission)
        recover(admission, authorization)

    monkeypatch.setattr(
        integration, "verify_current_authority", verify_then_rotate_epoch
    )

    # On the pre-fix implementation this succeeds because execute() obtains a
    # fresh lease after recovery instead of consuming a lease pinned before
    # the Warrant check. If this assertion fails, the suspected baseline
    # exploit is not demonstrated and attribution must remain unconfirmed.
    assert _invoke(protected, {"value": "baseline-reproducer"}) == "written"
    assert calls == ["baseline-reproducer"]
