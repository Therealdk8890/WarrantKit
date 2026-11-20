#!/usr/bin/env python3
"""Kill switch for a tool-using agent, in about 60 lines.

A "refund agent" is allowed to issue refunds under a signed Warrant. Halfway
through, an operator contains the execution (for example after a prompt-injection
alert). The Warrant the agent still holds stops working immediately, and the
refund function is never called again.

No LLM, API key, network access, or root privileges are needed. Agent framework
adapters (LangChain, CrewAI, OpenAI Agents, MCP) wrap the same boundary shown here.

Scope: this runs the controller and verifier in one Python process. It shows the
authority lifecycle, not kernel-level process containment; see
docs/REAL_KILL_DEMO.md for the privileged Linux proof.
"""
from __future__ import annotations

from agent_containment.gateway import ActionGateway
from agent_containment.models import Action
from agent_containment.policy import PolicyEngine
from agentcontain import (
    BoundGuardedExecution,
    GuardedExecutionDenied,
    Policy,
    admit,
    build_agentcontainment_engine,
    contain,
)
from agentcontain.attestation import Ed25519Signer, Ed25519Verifier

AGENT_ID = "refund-agent"


def main() -> list[int]:
    refunds_issued: list[int] = []

    def issue_refund(amount: int) -> str:
        refunds_issued.append(amount)
        return f"refunded ${amount}"

    # 1. The operator admits the agent under a policy and signs a Warrant for it.
    engine = build_agentcontainment_engine(AGENT_ID)
    signer = Ed25519Signer.generate("operator-key")
    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    admission = admit(
        Policy("refunds", capabilities=("issue_refund",)),
        agent_id=AGENT_ID,
        engine=engine,
        runtime_id=engine.runtime_id,
        warrant_signer=signer,
    )
    gateway = ActionGateway(PolicyEngine(), engine.controller)
    boundary = BoundGuardedExecution(admission, gateway, warrant_verifier=verifier)

    def agent_tool_call(amount: int) -> str:
        action = Action(AGENT_ID, f"refund-{amount}", "issue_refund", "orders", risk=1)
        return boundary.execute(action, lambda _approved: issue_refund(amount))

    # 2. Before containment the agent's tool call is authorized and runs.
    print("before containment:", agent_tool_call(25))

    # 3. Something looks wrong. The operator contains the execution.
    report = contain(admission)
    print(f"contained: complete={report.complete}, runtime epoch now {admission.identity.epoch}")

    # 4. The agent still holds its old Warrant and tries again. It is refused,
    #    and the refund function is never reached.
    try:
        agent_tool_call(500)
    except GuardedExecutionDenied as exc:
        print("after containment: DENIED -", exc)
    else:
        raise AssertionError("tool call should have been denied after containment")

    print("refunds actually issued:", refunds_issued)
    if refunds_issued != [25]:
        raise AssertionError(f"unexpected side effects: {refunds_issued!r}")
    return refunds_issued


if __name__ == "__main__":
    main()
