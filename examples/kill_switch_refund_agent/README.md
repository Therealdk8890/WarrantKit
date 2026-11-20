# Example: a kill switch for a refund agent

A tool-using "refund agent" is allowed to issue refunds under a signed Warrant.
Halfway through, an operator contains the execution. The Warrant the agent still
holds is refused at the next tool call, and the refund function is never reached.

No LLM, API key, network access, or root privileges are required.

```bash
python -m pip install "warrantkit[attestation]==0.2.0"
python refund_agent.py
```

Expected output:

```text
before containment: refunded $25
contained: complete=True, runtime epoch now 1
after containment: DENIED - runtime execution lease unavailable
refunds actually issued: [25]
```

## What to look at

- `admit(...)` issues a signed Warrant for one policy (`issue_refund` only).
- `BoundGuardedExecution.execute(...)` checks the Warrant, the current runtime
  epoch, and gateway policy before the tool runs, and again inside the
  controller-owned lease callback.
- `contain(admission)` advances the runtime epoch. Authority issued for the old
  epoch is fenced out.

To use the same boundary inside an agent framework, see the adapters for
LangChain, CrewAI, OpenAI Agents and MCP in the main [README](../../README.md).

## Scope

The controller and verifier run in one Python process here, so this shows the
authority lifecycle, not kernel-level process containment. It does not undo a
side effect that already happened, and it only protects actions routed through
the gateway. For the privileged Linux cgroup-v2 proof, see
[docs/REAL_KILL_DEMO.md](../../docs/REAL_KILL_DEMO.md).

This example runs in CI through `tests/test_example_kill_switch.py`.
