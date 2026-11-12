# WarrantKit

[![WarrantKit CI](https://github.com/Therealdk8890/WarrantKit/actions/workflows/ci.yml/badge.svg)](https://github.com/Therealdk8890/WarrantKit/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/warrantkit)](https://pypi.org/project/warrantkit/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://pypi.org/project/warrantkit/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

**A kill switch for AI agent tool calls: when you contain an agent, the permission it already holds stops working.**

WarrantKit gives each agent execution a signed Warrant tied to a policy, a runtime identity, and a runtime epoch. Containing the execution advances the epoch, so a Warrant the agent kept is rejected before its next tool call reaches your refund API, database, or other side effect. Adapters cover LangChain, CrewAI, the OpenAI Agents SDK, and synchronous raw MCP handlers.

## Try it in 60 seconds

No LLM, API key, network access, or root needed.

```bash
python -m pip install "warrantkit[attestation]"
warrantkit demo
```

Then watch a real tool call get blocked after containment ([source, about 60 lines](examples/kill_switch_refund_agent/refund_agent.py)):

```bash
curl -sSLO https://raw.githubusercontent.com/Therealdk8890/WarrantKit/main/examples/kill_switch_refund_agent/refund_agent.py
python refund_agent.py
```

```text
before containment: refunded $25
contained: complete=True, runtime epoch now 1
after containment: DENIED - runtime execution lease unavailable
refunds actually issued: [25]
```

## Why

- **Prompt filters are probabilistic.** WarrantKit makes a deterministic allow-or-deny decision at the tool boundary, outside the model.
- **Stopping an agent is not the same as revoking what it holds.** Authority issued before containment is fenced out by epoch, so a retained Warrant cannot be replayed.
- **You get evidence, not just logs.** Warrants and incident bundles are signed (Ed25519) so a separate verifier can check what was authorized.

## How it fits with what you already run

WarrantKit complements these tools; it does not replace them.

| Tool | What it answers | Where WarrantKit adds |
|---|---|---|
| IAM and secrets managers | Who may hold which credential | Ties an agent's authority to the current runtime state, so containment invalidates it |
| Policy engines (OPA, Cedar) | Is this request allowed by policy | Binds the decision to a signed, epoch-fenced Warrant checked at execution time |
| Guardrails and prompt filters | Is this input or output risky | A deterministic boundary that does not depend on the model behaving |
| Sandboxes and cgroups | Can this process be isolated or killed | Coordinates authority with enforcement via [AgentContainment](https://github.com/Therealdk8890/AgentContainment) |
| Tracing (LangSmith, Langfuse, OpenTelemetry) | What happened | Separately verifiable evidence of what was authorized and refused |

**Version: [`warrantkit 0.2.0`](https://github.com/Therealdk8890/WarrantKit/releases/tag/v0.2.0)** · [PyPI package](https://pypi.org/project/warrantkit/)

**Release focus:** Public guarded execution, final authority rechecks, and experimental authenticated external-decision import. See the [0.2.0 release record and procedure](docs/RELEASE_0.2.0.md).

## Install version 0.2.0

Install the versioned package with Python 3.11 or newer:

```bash
python -m pip install --upgrade warrantkit==0.2.0
warrantkit demo
```

The optional framework adapters are installed separately when needed:

```bash
python -m pip install "warrantkit[langchain]"
python -m pip install "warrantkit[crewai]"
python -m pip install "warrantkit[openai-agents]"
python -m pip install "warrantkit[mcp]"  # synchronous Python handlers on raw MCP servers
```

The portable `warrantkit demo` is a simulated lifecycle demonstration, not proof of kernel-level process containment. For the strongest containment claim, use the environment-gated Linux cgroup-v2 proof described below.

**New here?** Start with the [security overview](docs/SECURITY_OVERVIEW.md) for the incident/evidence story and deployment boundaries, then follow the [getting-started guide](docs/GETTING_STARTED.md) to run the deterministic framework-to-gateway proof.

**Authority that stops being valid when the runtime state that created it changes.**

WarrantKit binds execution authority to accepted policy, runtime identity, and runtime epoch. When containment advances the epoch, retained pre-containment authority is fenced out. WarrantKit coordinates the authority lifecycle; [AgentContainment](https://github.com/Therealdk8890/AgentContainment) provides external runtime enforcement.

## Open-source authority; NobodySystems enterprise operations

**WarrantKit is the independent Apache-2.0 authority engine.** Run its Warrant/epoch-fencing and controller-owned-gateway proofs without any proprietary service. [AgentContainment](https://github.com/Therealdk8890/AgentContainment) provides the external enforcement boundary; [DProvenanceKit](https://github.com/Therealdk8890/DProvenanceKit) provides separately verifiable trace evidence.

**NobodySystems** is the **proprietary operational/control-plane layer** coordinating these independent engines for teams. Its **private alpha** currently supports local operator workflows, bounded guarded tools, and separate evidence-bundle verification. Organization-wide policy lifecycle, cross-engine evidence correlation, fleet operations, enterprise identity/support guarantees, and hosted management are **planned capabilities, not a shipped production offer**.

Evaluate the OSS proof below first. For exact engine/platform responsibilities, test assertions, licensing, access, and current release limits, see [NobodySystems integration and commercial boundary](docs/NOBODYSYSTEMS.md). The existing separate `WarrantKit-Commercial` tenant-ingestion prototype is not evidence that NobodySystems Enterprise or Cloud is production-ready.

## Current implementation status

The current OSS implementation is a local authority-lifecycle and runtime-enforcement integration, not a hosted security platform.

| Capability | Current state | Important boundary |
|---|---|---|
| Warrant admission and runtime-epoch fencing | Implemented and CI-tested | A Warrant tied to an older runtime epoch is rejected; epoch fencing does not undo side effects already completed. |
| Controller-owned ActionGateway enforcement | Implemented and covered by the framework boundary proof | The adapter checks the Warrant before invoking the gateway; the gateway independently enforces its controller-owned execution lease. A serialized Warrant is not a gateway bearer credential. |
| Framework / tool adapters | LangChain and CrewAI adapters; OpenAI Agents SDK local function-tool adapter; raw MCP synchronous Python-handler wrapper | Hosted tools, remote MCP servers, async-native MCP execution, and alternate side-effect paths are not automatically protected. |
| Real process containment | Linux cgroup-v2 proof implemented and exercised in privileged CI | Requires Linux and suitable root/delegated cgroup privileges. It is not a universal host-isolation guarantee. |
| Evidence and incident bundles | Signed Warrants and full incident-bundle receipts use Ed25519; the short real-kill walkthrough's runtime receipt uses HMAC | Ed25519 authentication requires an independently provisioned trusted public key. HMAC is shared-secret authentication, not non-repudiable attestation. Neither mechanism proves every underlying claim true or establishes host integrity. |
| ClaimProofKit provenance integration | CI test uses ClaimProofKit's public APIs to create a claim report and provenance trace, then round-trips it through a signed WarrantKit incident bundle | The test validates provenance integrity and records the verifier verdict separately; claim truth and runtime enforcement are not established by provenance alone. |
| Hosted commercial control plane | Not part of this OSS repository's shipped boundary | The separate [WarrantKit Commercial](https://github.com/Therealdk8890/WarrantKit-Commercial) repository implements tenant-scoped bearer-token authentication and incident-bundle ingestion/verification. This is a minimal token-to-organization boundary, not full enterprise IAM/RBAC; production readiness still depends on secret management, token lifecycle controls, deployment hardening, and external validation. |

The main-branch CI suite includes unit/adapter tests, the framework authority-boundary proof, the privileged Linux cgroup-v2 workload proof, the AgentContainment eBPF hostile-agent proof (controller isolation, cgroup delegation, process containment, post-containment egress, and stale-lease fencing), clean-install/demo coverage, and a gateway benchmark smoke test. See [implementation status and proof scope](docs/INTEGRATIONS_AND_PROOFS.md#implementation-status) for the detailed test and environment boundaries.


## Start with the framework-to-gateway proof

This deterministic proof uses a real LangChain tool and AgentContainment's ActionGateway, without an LLM, network access, or real credentials. It shows an allowed tool side effect before containment, then proves the retained Warrant is rejected before a second side effect can occur.

```bash
git clone --recurse-submodules https://github.com/Therealdk8890/WarrantKit.git
cd WarrantKit
python -m pip install ".[langchain]"
python tools/run_authority_boundary_demo.py
```

**What this proves:** the adapter validates current Warrant authority, routes the call through ActionGateway, and blocks a retained pre-containment Warrant before the protected tool's second side effect.

**What it does not prove:** kernel-enforced process termination, universal host isolation, reversal of completed side effects, or that the Warrant is itself a gateway credential. The gateway separately enforces controller-owned execution leases.

## The proof ladder

Choose the demonstration that matches the claim you need to establish.

1. **Framework-to-gateway proof — best first run.** The command above exercises the adapter and gateway path and checks that the second side effect never occurs.
2. **Real host-enforcement proof — strongest containment evidence.** On Linux with cgroup-v2 and root or equivalent delegation, follow the [real-kill guide](docs/REAL_KILL_DEMO.md). It checks the workload and cgroup state, verifies stale authority, and exports evidence. This is the proof to use when claiming actual process containment.
3. **Portable lifecycle demo — quick orientation, not independent security evidence.** Install WarrantKit and run `warrantkit demo`. It illustrates authority invalidation after an epoch change, but the no-root verifier and controller share one Python process.

```bash
python -m pip install --upgrade warrantkit
warrantkit demo
```

Each proof has a narrower claim than a full production deployment. Preserve real-kill artifacts with the exact source revision and host details. The default demo signing key supports integrity checks only; authenticated incident evidence requires an operator-controlled Ed25519 key and a public key provisioned independently of the evidence bundle. See the [real-kill guide](docs/REAL_KILL_DEMO.md#trust-boundary-and-interpretation) and [trust-anchor operations](docs/INCIDENT_TRUST_ANCHOR_OPERATIONS.md).

## Public guarded-execution API (0.2.0)

Version 0.2.0 provides `BoundGuardedExecution` for trusted,
synchronous Python integrations that need one Warrant-aware execution
boundary without importing private framework-adapter functions. This API
was introduced after 0.1.6.

```python
from agentcontain import BoundGuardedExecution
from agent_containment.models import Action

bound = BoundGuardedExecution(admission, gateway, warrant_verifier=verifier)
result = bound.execute(
    Action(agent_id=admission.identity.agent_id, action_id="my-action",
           operation="write_record", resource="example"),
    lambda action: perform_authorized_write(action),
)
```

The binding captures the accepted admission and checks signed Warrant,
current runtime epoch, expiry, revocation, subject/policy, and the action's
**operation capability**, twice: before gateway policy and within the
controller-owned lease-guarded executor callback. Missing authority,
gateway denial, and runtime state changes fail closed.

The LangChain tool, LangChain middleware, CrewAI, OpenAI Agents, and MCP
synchronous wrappers also verify signed Warrant authority a second time inside
their lease-guarded executor callbacks, after gateway policy evaluation. This
closes preflight expiry/revocation check/use gaps for those wrapped paths.

This protects only actions actually routed through the trusted gateway.
The Python object is **not** a host isolation boundary; the agent must not
hold alternate credentials or an unrestricted route to protected downstream
side effects. The API is synchronous only and does not promise to interrupt
a side effect already in progress.

**AgentContainment compatibility boundary.** WarrantKit's current CI/proof
submodule is pinned to a runtime that invokes callbacks under the lifecycle lock.
A newer AgentContainment source revision uses atomic *admission*, then invokes
callbacks without holding that lock. It can fence new work promptly while an
already-admitted callback is in flight. WarrantKit's final in-callback Warrant
check is not an atomic external-side-effect commit in that design: a later
containment transition cannot retract a previously admitted callback or cancel
a downstream operation. Keep agent-owned credentials out of the agent process,
enforce revocation/cancellation at the downstream boundary, and do not claim
that no effects can complete after a fence. The dedicated newer-runtime CI job
covers new-admission rejection and in-flight behavior using an immutable source
revision. This compatibility check does not replace a separate production
enforcement or release-security review.

## Agent integration

The LangChain adapter protects a tool by admitting an execution under a policy, wrapping the tool with the admission and gateway, and then containing the execution when needed. This abbreviated example shows the shape; see the [complete runnable integration](docs/INTEGRATIONS_AND_PROOFS.md#langchain-integration) for imports, signer setup, and trusted-key configuration.

```python
admission = admit(policy, agent_id="payments-agent", engine=engine,
                  runtime_id=engine.runtime_id, warrant_signer=signer)
gateway = ActionGateway(PolicyEngine(), engine.controller)
protected_refund = wrap_langchain_tool(
    payments_refund, admission, gateway, warrant_verifier=verifier
)
agent = create_agent(model, tools=[protected_refund])
# When a security event requires stopping this execution:
contain(admission)
```

Use a deployment-managed signing key and independently provisioned Ed25519 public-key anchor in production. Do not place the private key or unrestricted downstream credentials in the agent process.

## Critical deployment boundary: credentials

> **If the agent holds its own unrestricted API key or other credential that can perform a protected side effect directly, the gateway is advisory.** Keep downstream credentials behind the trusted gateway/controller or ensure the downstream service independently enforces the same authorization. WarrantKit cannot block a path that bypasses its enforcement boundary.

## Why the Warrant and lease are separate

This is a deliberate two-check design in the current implementation, not an accidental claim that the objects are interchangeable:

- The framework adapter verifies the signed Warrant against current execution identity, policy binding, capabilities, and runtime epoch.
- The adapter then routes the action through AgentContainment's ActionGateway.
- ActionGateway's final runtime enforcement uses controller-owned execution leases; it does not consume the serialized Warrant as a bearer credential.

The checks protect different boundaries: the Warrant check rejects stale authority before the tool handler reaches the gateway, and the gateway lease check is the final side-effect enforcement point. Keeping lease issuance and validation under controller ownership prevents a caller-constructed lease from authorizing gateway effects. The framework proof tests the combined path and confirms that the second side effect is not reached.

**Roadmap status:** direct gateway consumption of a Warrant, or cryptographically deriving a gateway lease from a Warrant, is not implemented today. It should be treated as an architectural change requiring a clear threat-model benefit and regression proofs—not as a feature users can assume exists. See the [AgentContainment security contract](https://github.com/Therealdk8890/AgentContainment/blob/main/docs/SECURITY_CONTRACT.md).

## What WarrantKit means by authority and evidence

- **Warrant:** a typed authority contract bound to policy identity and digest, execution identity, runtime identity and epoch, validity, capabilities, and evidence requirements. The v1 schema retains a `constraints` field for compatibility, but non-empty constraints are unsupported: issuance rejects them and verification fails closed. Do not rely on constraints to limit action arguments or resources.
- **Evidence:** what a component observed or produced.
- **Verification:** whether specified checks succeeded.
- **Receipt:** a record of evidence and its stated authentication status.

**Evidence never grants authority. Verified does not mean an external claim is true.** Ed25519 signatures authenticate a payload relative to a separately trusted public key; they do not attest that every claim is true or that the host/kernel is uncompromised.

### Which cryptographic mechanism protects which artifact?

- **Signed Warrants:** Ed25519. Protected framework adapters verify the Warrant against a deployment-configured trusted public key before the protected tool handler runs. The private signing key must remain outside the agent process.
- **Full incident-bundle receipt:** Ed25519. The verifier reports `AUTHENTICATED` only when the signature validates against an independently provisioned operator public key. Verification with only the key embedded in the bundle is `INTEGRITY_ONLY` and does not authenticate the producer.
- **Short `tools/real_kill_demo.py` runtime receipt:** HMAC shared-secret authentication. It detects tampering and authenticates possession of the shared secret; it is not asymmetric signing or non-repudiable attestation.
- **Portable runtime evidence:** structural/integrity verification is a separate check from producer authentication. Do not treat a passing integrity check as proof of who produced the evidence.

See [Security Overview](docs/SECURITY_OVERVIEW.md#cryptographic-mechanisms-do-not-conflate-them), [real-kill trust boundaries](docs/REAL_KILL_DEMO.md#trust-boundary-and-interpretation), and [trust-anchor operations](docs/INCIDENT_TRUST_ANCHOR_OPERATIONS.md).

## Epoch fencing is not expiry

Epoch fencing invalidates every retained Warrant tied to an older runtime generation when the controller advances the epoch. This is a known fencing-token pattern, not a claim that epoch checks are unique to WarrantKit.

- **Epoch fencing:** coarse-grained invalidation of all authority tied to a prior runtime generation.
- **Per-Warrant revocation:** tracks individual credentials and requires revocation state to be available and checked.
- **Expiry:** bounds validity by time. It is a separate defense, not a substitute for epoch checks or revocation.

Advancing an epoch also invalidates legitimate Warrants from the prior generation; affected work must receive fresh authority under the new runtime state. See [Martin Kleppmann's explanation of fencing tokens](https://martin.kleppmann.com/2016/02/08/how-to-do-distributed-locking.html).

## How WarrantKit differs

These projects overlap in agent authorization. The distinctions below summarize their public documentation, not a claim that any project lacks features beyond this comparison.

| Approach | Publicly documented focus | WarrantKit's focus |
|---|---|---|
| [Tenuo](https://github.com/tenuo-ai/tenuo) | Signed, holder-bound, task-scoped capability warrants; constrained tool arguments; delegation that can only narrow authority; enforcement at the action boundary | Adds runtime-epoch invalidation tied to an external containment controller and a controller-owned gateway lease |
| [Liceat](https://liceat.com/) | Scoped, holder-bound and revocable warrants, including spend/rate limits; offline verification and point-of-action enforcement with audit records | Adds runtime-epoch invalidation tied to an external containment controller and a controller-owned gateway lease |
| OPA / Cedar | Policy evaluation and authorization decisions | Runtime-scoped authority lifecycle, epoch fencing, and recovery gating around protected actions |
| cgroup-v2 | Kernel-level process/resource containment | An authority contract tied to execution identity and runtime epoch |
| Short-lived credentials and revocation lists | Time-bounded validity and explicit per-credential revocation | One runtime epoch can invalidate all prior-generation authority without tracking every copy individually; revocation can also be immediate when checked at each enforcement point |

The contribution is the combination of authority bound to runtime state, stale-authority rejection, external containment, and verifiable incident evidence—not the invention of warrants, signatures, or fencing tokens.

## What WarrantKit is — and is not

WarrantKit complements rather than replaces IAM, policy engines, host isolation, cgroups, secret management, or independent provenance verification. It is not a sandbox, a universal host-isolation guarantee, a mechanism for reversing completed side effects, or a general destination-policy engine. The current egress path can use deny-all as a kill switch; it does not implement a general allowlist of approved destinations. See the [egress binding contract](docs/EGRESS_BINDING_CONTRACT.md).

## Further reading

- [Security overview for evaluators](docs/SECURITY_OVERVIEW.md)
- [Kubernetes deployment considerations and limitations](docs/KUBERNETES_DEPLOYMENT.md)
- [External proof package: reproduce, inspect, and verify WarrantKit evidence](docs/EXTERNAL_PROOF_PACKAGE.md)

- [Incident bundle API and trust model](docs/INCIDENT_BUNDLE_API.md)

- [Raw MCP server integration and limitations](docs/MCP_SERVER_INTEGRATION.md)
- [Design-partner program](docs/DESIGN_PARTNER_PROGRAM.md)
- [Design-partner validation guide](docs/DESIGN_PARTNER_VALIDATION.md)
- [Design-partner pilot](docs/DESIGN_PARTNER_PILOT.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Real-kill demo requirements and evidence interpretation](docs/REAL_KILL_DEMO.md)
- [Trust-anchor operations](docs/INCIDENT_TRUST_ANCHOR_OPERATIONS.md)
- [Implementation status: CI-tested versus planned](docs/INTEGRATIONS_AND_PROOFS.md#implementation-status)
- [Extended integrations, evidence, and proof documentation](docs/INTEGRATIONS_AND_PROOFS.md)

## License

Apache-2.0.

---

Copyright 2026 Daniel Paul Kissel
