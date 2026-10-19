# WarrantKit

[![WarrantKit CI](https://github.com/Therealdk8890/WarrantKit/actions/workflows/ci.yml/badge.svg)](https://github.com/Therealdk8890/WarrantKit/actions/workflows/ci.yml)

[![PyPI version](https://img.shields.io/pypi/v/warrantkit)](https://pypi.org/project/warrantkit/)

**Latest release: [`warrantkit 0.1.5`](https://github.com/Therealdk8890/WarrantKit/releases/tag/v0.1.5)** · [PyPI package](https://pypi.org/project/warrantkit/)

**Release focus:** External Proof Package and Evaluation Readiness.

## Install the published package

WarrantKit 0.1.5 is published on PyPI. It requires Python 3.11 or newer.

```bash
python -m pip install --upgrade warrantkit==0.1.5
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

**New here?** Follow the [getting-started guide](docs/GETTING_STARTED.md) to run the deterministic framework-to-gateway proof, choose your framework adapter, and understand the enforcement boundary.

**Authority that stops being valid when the runtime state that created it changes.**

WarrantKit binds execution authority to accepted policy, runtime identity, and runtime epoch. When containment advances the epoch, retained pre-containment authority is fenced out. WarrantKit coordinates the authority lifecycle; [AgentContainment](https://github.com/Therealdk8890/AgentContainment) provides external runtime enforcement.

## Current implementation status

The current OSS implementation is a local authority-lifecycle and runtime-enforcement integration, not a hosted security platform.

| Capability | Current state | Important boundary |
|---|---|---|
| Warrant admission and runtime-epoch fencing | Implemented and CI-tested | A Warrant tied to an older runtime epoch is rejected; epoch fencing does not undo side effects already completed. |
| Controller-owned ActionGateway enforcement | Implemented and covered by the framework boundary proof | The adapter checks the Warrant before invoking the gateway; the gateway independently enforces its controller-owned execution lease. A serialized Warrant is not a gateway bearer credential. |
| Framework / tool adapters | LangChain and CrewAI adapters; OpenAI Agents SDK local function-tool adapter; raw MCP synchronous Python-handler wrapper | Hosted tools, remote MCP servers, async-native MCP execution, and alternate side-effect paths are not automatically protected. |
| Real process containment | Linux cgroup-v2 proof implemented and exercised in privileged CI | Requires Linux and suitable root/delegated cgroup privileges. It is not a universal host-isolation guarantee. |
| Evidence and incident bundles | Bundle writer, standalone verifier, and optional Ed25519-authenticated Warrant/receipt artifacts | A trusted public key must be provisioned independently. Internal consistency or a valid signature does not prove the underlying claim is true. |
| ClaimProofKit provenance integration | CI test uses ClaimProofKit's public APIs to create a claim report and provenance trace, then round-trips it through a signed WarrantKit incident bundle | The test validates provenance integrity and records the verifier verdict separately; claim truth and runtime enforcement are not established by provenance alone. |
| Hosted commercial control plane | Not part of this OSS repository's shipped boundary | The separate WarrantKit Commercial API still lacks a completed authenticated-principal/tenant-authorization boundary; its incident-ingestion endpoint is intentionally disabled. |

The main-branch CI suite includes unit/adapter tests, the framework authority-boundary proof, the privileged Linux cgroup-v2 workload proof, clean-install/demo coverage, and a gateway benchmark smoke test. See [implementation status and proof scope](docs/INTEGRATIONS_AND_PROOFS.md#implementation-status) for the detailed test and environment boundaries.


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
