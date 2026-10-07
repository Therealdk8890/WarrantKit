#!/usr/bin/env python3
"""Deterministic framework-to-enforcement authority boundary proof.

This demo uses a real LangChain tool but no LLM or network call. It proves that
an authorized side effect runs before external containment, then the same
retained authority is rejected after containment before the underlying side
effect can run.
"""
from __future__ import annotations

from agent_containment.gateway import ActionGateway
from agent_containment.policy import PolicyEngine
from agentcontain import Policy, admit, build_agentcontainment_engine, contain
from agentcontain.integrations.langchain import LangChainWarrantError, wrap_langchain_tool
from agentcontain.warrant import Warrant, verify_warrant


def main() -> int:
    from langchain_core.tools import tool

    calls: list[int] = []

    @tool
    def payments_refund(amount: int) -> str:
        """Issue a payment refund."""
        calls.append(amount)
        return f"refunded:{amount}"

    print("[1/5] admitting a tool-using execution under a Warrant")
    engine = build_agentcontainment_engine("authority-demo")
    admission = admit(
        Policy("payments", capabilities=("payments_refund",)),
        agent_id="authority-demo",
        engine=engine,
        runtime_id=engine.runtime_id,
    )
    gateway = ActionGateway(PolicyEngine(), engine.controller)
    protected = wrap_langchain_tool(payments_refund, admission, gateway)
    if admission.warrant is None:
        raise RuntimeError("authority demo requires a Warrant")
    pre_containment_warrant = admission.warrant.to_dict()

    print("[2/5] invoking the protected tool before containment")
    result = protected.invoke({"amount": 25})
    if result != "refunded:25" or calls != [25]:
        raise AssertionError(f"unexpected authorized result: {result!r}, calls={calls!r}")
    print(f"    side effect executed: {result}")

    print("[3/5] externally containing the execution")
    report = contain(admission)
    if not report.complete or not report.external_verified:
        raise AssertionError("containment did not complete with external verification")
    print(f"    runtime epoch advanced to {admission.identity.epoch}")

    print("[4/5] proving retained authority cannot be replayed")
    replayed = Warrant.from_dict(pre_containment_warrant)
    try:
        verify_warrant(
            replayed,
            execution_id=admission.identity.execution_id,
            agent_id=admission.identity.agent_id,
            policy_id=admission.identity.policy_id,
            policy_digest=admission.identity.policy_digest,
            runtime_id=engine.runtime_id,
            epoch=admission.identity.epoch,
        )
    except ValueError as exc:
        if "epoch" not in str(exc):
            raise
        print(f"    serialized pre-containment Warrant rejected: {exc}")
    else:
        raise AssertionError("serialized pre-containment Warrant remained valid")

    try:
        protected.invoke({"amount": 50})
    except LangChainWarrantError as exc:
        print(f"    protected tool rejected: {exc}")
    else:
        raise AssertionError("protected tool remained executable after containment")

    print("[5/5] proving the underlying side effect was never reached")
    if calls != [25]:
        raise AssertionError(f"post-containment side effect executed: calls={calls!r}")
    print(f"    side-effect calls={calls!r}")
    print("proof complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
