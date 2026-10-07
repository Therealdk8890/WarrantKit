# WarrantKit

[![WarrantKit CI](https://github.com/Therealdk8890/WarrantKit/actions/workflows/ci.yml/badge.svg)](https://github.com/Therealdk8890/WarrantKit/actions/workflows/ci.yml)

**Authority that expires when the runtime state that created it changes.**

> **Don't ask the agent to enforce its own boundaries. Enforce them from outside the agent trust boundary.**

The core invariant is simple: **authority must not survive the runtime state that created it.** A Warrant is bound to an execution and runtime epoch; when containment or recovery advances that epoch, a retained pre-containment Warrant becomes stale and cannot be replayed.

WarrantKit is the platform/control layer around the AgentContainment enforcement engine. The repository ships local authorization, admission, runtime containment coordination, epoch fencing, recovery gating, evidence envelopes, fleet-governance primitives, external evidence contracts, cryptographic attestation primitives, and offline verification receipts. Hosted multi-tenant operations and enterprise integrations are not shipped here.

The practical question is: **what is an autonomous agent allowed to do, what happens when it crosses that boundary, how is its authority revoked, and what evidence can be checked afterward?**

## 30-second demo

The no-root demo shows the shipped lifecycle without claiming kernel-level enforcement:

```bash
git clone --recurse-submodules https://github.com/Therealdk8890/WarrantKit.git
cd WarrantKit
python -m pip install ./AgentContainment
python -m pip install .
warrantkit demo
```

For actual host enforcement, use the environment-gated Linux proof below.

## See the authority boundary work

The fastest way to understand WarrantKit is to run the deterministic framework proof. It uses a real LangChain tool, but no LLM, network, or API key.

```bash
python -m pip install ./AgentContainment
python -m pip install ".[langchain]"
python tools/run_authority_boundary_demo.py
```

The sequence is deliberately concrete:

```text
Warrant + capability
        ↓
protected tool call → side effect succeeds
        ↓
external containment
        ↓
runtime epoch 0 → 1
        ↓
serialized old Warrant → REJECTED
retained framework tool → REJECTED
        ↓
second side effect → NEVER REACHED
```

Recorded CI output from the proof:

```text
[1/5] admitting a tool-using execution under a Warrant
[2/5] invoking the protected tool before containment
    side effect executed: refunded:25
[3/5] externally containing the execution
    runtime epoch advanced to 1
[4/5] proving retained authority cannot be replayed
    serialized pre-containment Warrant rejected: warrant epoch does not match current runtime epoch
    protected tool rejected: Warrant verification failed: warrant is revoked
[5/5] proving the underlying side effect was never reached
    side-effect calls=[25]
proof complete
```

**What this proves:** a framework tool can be placed behind WarrantKit authority and an external AgentContainment action boundary; after containment, retained authority is rejected before the underlying tool executes.

**What this does not prove:** kernel-level workload termination, universal host isolation, or that a serialized Warrant is itself a bearer credential accepted by the ActionGateway. The privileged Linux proof below covers the kernel enforcement boundary separately.

## End-to-end authority boundary proof

The fastest way to see the security boundary is the deterministic framework proof. It uses a real LangChain tool but no LLM, network, or API key:

```bash
python -m pip install ./AgentContainment
python -m pip install ".[langchain]"
python tools/run_authority_boundary_demo.py
```

The proof performs a real tool side effect while authority is valid, externally contains the execution, rejects a serialized pre-containment Warrant at the new epoch, rejects the retained framework tool, and verifies that the underlying side effect was never reached after containment.

This is the framework-level proof. The privileged Linux demo below separately proves actual cgroup-v2 workload termination.

## LangChain integration

WarrantKit can wrap an existing LangChain tool so the model-facing tool schema stays unchanged while execution crosses the Warrant and AgentContainment boundaries.

Install the optional integration:

```bash
python -m pip install "warrantkit[langchain]"
```

Then protect a tool by giving the execution Warrant an explicit capability matching the tool operation:

```python
from langchain.agents import create_agent
from langchain_core.tools import tool
from agent_containment.gateway import ActionGateway
from agent_containment.policy import PolicyEngine
from agentcontain import Policy, admit, build_agentcontainment_engine
from agentcontain.integrations.langchain import wrap_langchain_tool

@tool
def payments_refund(amount: int) -> str:
    """Issue a payment refund."""
    return f"refunded:{amount}"

engine = build_agentcontainment_engine("payments-agent")
admission = admit(
    Policy("payments", capabilities=("payments_refund",)),
    agent_id="payments-agent",
    engine=engine,
    runtime_id=engine.runtime_id,
)

gateway = ActionGateway(PolicyEngine(), engine.controller)
protected_refund = wrap_langchain_tool(
    payments_refund,
    admission,
    gateway,
)

agent = create_agent(model, tools=[protected_refund])
```

The wrapper verifies the current Warrant, requires the corresponding capability, and executes the underlying tool through AgentContainment's controller-owned ActionGateway. If containment advances the runtime epoch, the retained Warrant is rejected before the underlying tool is invoked.

The first integration deliberately uses LangChain's synchronous tool invocation path so the runtime lease and actual tool side effect remain inside the same controller-owned execution boundary. Async-native tool execution is not claimed by this integration yet.

For Ed25519 Warrant and receipt attestation, install the optional cryptographic dependency explicitly:

```bash
python -m pip install "warrantkit[attestation]"
```

The base package and 30-second no-root demo do not require the attestation dependency.



## CrewAI integration

WarrantKit can also wrap a CrewAI BaseTool without changing the agent-facing tool contract. CrewAI remains the framework layer; WarrantKit verifies authority and AgentContainment remains the controller-owned enforcement boundary.

Install the optional integration:

~~~bash
python -m pip install "warrantkit[crewai]"
~~~

Then wrap an existing CrewAI tool:

~~~python
from agent_containment.gateway import ActionGateway
from agent_containment.policy import PolicyEngine
from agentcontain import Policy, admit, build_agentcontainment_engine
from agentcontain.integrations.crewai import wrap_crewai_tool

engine = build_agentcontainment_engine("payments-agent")
admission = admit(
    Policy("payments", capabilities=("payments_refund",)),
    agent_id="payments-agent",
    engine=engine,
    runtime_id=engine.runtime_id,
)

gateway = ActionGateway(PolicyEngine(), engine.controller)
protected_refund = wrap_crewai_tool(
    payments_refund_tool,
    admission,
    gateway,
)

agent = Agent(..., tools=[protected_refund])
~~~

The adapter verifies the current Warrant and required capability before the tool reaches the AgentContainment ActionGateway. If containment advances the runtime epoch, a retained pre-containment authority is rejected before the underlying CrewAI tool runs. This first adapter deliberately covers the synchronous BaseTool.run() path; async-native execution is not claimed yet.

## What is a Warrant?

A **Warrant** is WarrantKit's portable authority contract for one execution. It binds execution identity, accepted policy identity and digest, runtime identity and epoch, validity/revocation state, capabilities, constraints, and required evidence.

Today the Warrant is a typed, transport-neutral authority object rather than the credential that the runtime ActionGateway consumes directly. WarrantKit verifies it against the exact execution, policy, runtime, epoch, and validity window at authority boundaries. AgentContainment's controller and ActionGateway remain the runtime enforcement boundary, using controller-owned execution leases that are invalidated by runtime state changes. Ed25519 signing/verification is shipped as an optional attestation layer; it does not make a signed Warrant authoritative by itself.

A Warrant answers:

> **Under exactly what authority was this execution admitted?**

It does not establish that an action was safe, that agent intent was correct, or that an external claim is true.

**Warrant = authority.**  
**Evidence = what was observed or produced.**  
**Verification = whether defined evidence checks succeeded.**  
**Receipt = an authenticated record of evidence.**

Evidence never grants authority, and a Warrant is never derived from evidence.

### Trust boundary: who checks the authority?

A Warrant is not useful merely because an agent possesses a serialized object. The enforcement point must check authority before an action reaches the protected side effect.

In the current implementation, the split is explicit:

- **WarrantKit** validates Warrant authority at admission and recovery boundaries against the exact execution, policy, runtime, epoch, and validity window.
- **AgentContainment's ActionGateway** is the runtime action enforcement point. It evaluates each action and executes it only through a controller-owned execution lease; containment invalidates that lease before a later side effect can run.
- **The Warrant is not currently a bearer credential accepted directly by ActionGateway.** A replayed serialized Warrant therefore cannot, by itself, invoke a tool, write a production database, or call a payments API. The gateway consumes runtime-owned execution authority.

That distinction matters. If a future integration makes serialized Warrants directly consumable by an action gateway, it must authenticate issuance as well as check epoch. The current core does not maintain a durable Warrant issuance registry, so an arbitrary unsigned serialized Warrant must not be treated as self-authenticating. The shipped Ed25519 attestation layer can authenticate a Warrant when a deployment establishes a trusted public-key anchor.

### Epoch fencing versus short-lived credentials

A short-lived credential gives a time-based upper bound on stale authority. Epoch fencing gives an event-based invalidation boundary.

For example, a Warrant with a 30-second TTL can remain usable for the rest of that 30-second window after containment unless the downstream system also maintains revocation state. An epoch-bound authority can become invalid immediately when containment advances the runtime epoch, without waiting for the TTL to expire.

Epochs therefore do not replace expiry. They solve a different problem: **immediate invalidation tied to a security event rather than to the clock.**

### Trust questions

- **Why not Macaroons/Biscuit?** Those are general-purpose capability/bearer-token designs. WarrantKit's distinctive contract is the binding of runtime authority to execution identity and runtime epoch; Ed25519 is available when cryptographic attestation of the object is required.
- **What does VERIFIED mean?** Only that the defined verification procedure and required evidence checks succeeded; it is not a truth oracle.

## Implementation status

**Implemented** means code is present; **CI-tested** means automated CI covers the behavior; **privileged integration-tested** means the proof requires the specified host environment.

| Capability | Current status | Boundary |
|---|---|---|
| External authorization and admission | **Implemented · CI-tested** | Policy and execution identity are enforced outside the agent runtime. |
| Runtime containment, kill, and fencing | **Implemented · lifecycle CI-tested** | Platform coordination is CI-tested; real kernel enforcement is the privileged Linux proof. |
| Epoch fencing / stale-authority invalidation | **Implemented · CI-tested** | Containment/recovery advance the runtime epoch and invalidate prior authority. |
| Fail-closed recovery | **Implemented · CI-tested** | Failed recovery remains contained; fresh authority follows an authoritative epoch transition. |
| Evidence envelopes and epoch scoping | **Implemented · CI-tested** | Runtime proof is bound to execution identity and epoch. |
| HMAC-authenticated receipts | **Implemented · CI-tested** | Shared-secret authentication and tamper detection; not non-repudiable attestation. |
| Ed25519 Warrant/receipt attestation | **Implemented · CI-tested** | Optional asymmetric authentication of Warrant/receipt artifacts; trust still depends on configured public-key anchors. |
| Linux cgroup-v2 workload containment | **Implemented · privileged integration-tested** | Requires Linux cgroup v2 and the required host privileges/delegation. |
| Adversarial containment/security regression tests | **Implemented · CI-tested** | Covers fail-closed and stale-authority/escape conditions in the tested environment. |
| Local fleet governance primitives | **Implemented · CI-tested** | Inventory, assignment, rollout/reconciliation, and status history are local foundations. |
| External evidence correlation | **Planned / partial** | Cross-source contracts and typed references exist; generalized correlation/reconciliation is not shipped. |
| Hosted multi-tenant control plane | **Planned** | Centralized orchestration, durable retention, and enterprise RBAC are commercial work. |
| Enterprise integrations | **Planned / integration-dependent** | IAM, SIEM/SOAR, deployment automation, and production integrations are not implied by the OSS foundation. |
| Non-repudiable host attestation | **Planned** | Ed25519 can authenticate an artifact; host-anchored attestation of the runtime itself remains future work. |

WarrantKit pins the security-critical AgentContainment engine as a submodule. Warden, DProvenanceKit, and ClaimProofKit remain independent evidence sources rather than hard runtime dependencies.

## Security lifecycle

**Policy → Admit → Contain → Detect → Fence → Halt → Verify → Recover → Receipt**

The security boundary is deliberately split:

- **WarrantKit** — authorization, lifecycle, revocation, recovery gating, governance, and evidence references.
- **AgentContainment** — security-critical runtime enforcement and kill/fencing.
- **Warden** — independent observation.
- **DProvenanceKit** — provenance/integrity evidence.
- **ClaimProofKit** — evidence/claim verification.

WarrantKit currently provides the contracts and identity binding needed to relate these sources. It does **not** yet ship a generalized correlator that reconciles every source automatically.

## Real workload proof

The privileged Linux proof uses a real child process and a real cgroup-v2 boundary. It demonstrates containment of the workload and the stale-authority check; it is not a demonstration that an arbitrary serialized Warrant is itself an action-gateway credential:

1. create a dedicated cgroup;
2. launch a real workload and attach it;
3. admit the workload under a Warrant;
4. invoke AgentContainment through WarrantKit;
5. prove that a serialized pre-containment Warrant is rejected after the runtime epoch changes;
6. independently verify the cgroup is empty and the workload exited;
7. export runtime-pinned evidence, including the stale-authority rejection;
8. verify that exported artifact with the standalone stdlib-only verifier.

Run:

```bash
sudo env AGENT_CONTAIN_RUN_REAL_CGROUP=1 WARRANTKIT_REAL_KILL_ARTIFACT=./real-kill-runtime-evidence.json \
"$(command -v python)" tools/run_real_kill_demo.py
```

The demo emits a portable evidence artifact and passes it through `tools/verify_runtime_evidence.py`. The fixture used by the verifier is a contract test; the real-kill path is the host-dependent proof. The lower-level pytest remains available for regression coverage.
### Captured CI proof

The following excerpt was captured from GitHub Actions run #336 on an Ubuntu 6.17 Azure runner with cgroup v2, using the real-kill demo above. It is recorded output, not a hand-written transcript:

```text
[4/8] proving pre-containment authority is stale
    stale pre-containment Warrant rejected: warrant epoch does not match current runtime epoch
    revoked live Warrant rejected: warrant is revoked
[5/8] independently checking terminal runtime state
    workload exited with code -9
[6/8] exporting runtime-pinned evidence
    artifact=real-kill-runtime-evidence.json
[7/8] independently verifying exported artifact
    VERIFIED
[8/8] proof complete
```

The same CI job ran the lower-level integration tests (`3 passed in 0.16s`), re-verified the exported artifact with `tools/verify_runtime_evidence.py` (`VERIFIED`), and uploaded the resulting `real-kill-runtime-evidence.json` artifact.
**What this proves:** the tested Linux environment can enforce the configured cgroup-v2 kill/fence boundary, invalidate the runtime-owned execution lease after the epoch changes, produce runtime-pinned evidence, and have that artifact checked by the standalone verifier. The serialized Warrant is also rejected by WarrantKit's Warrant verifier after its epoch becomes stale; that verifier result is an authority-contract check, not the action gateway itself.

**What this does not prove:** universal host isolation, arbitrary kernel/runtime security, reversal of already-completed side effects, formal verification, or non-repudiable host attestation.

## Evidence and verification

The portable evidence contract distinguishes:

| State | Meaning |
|---|---|
| **Observed** | An event or result was recorded. |
| **Verified** | The defined verification procedure and required evidence checks succeeded. |
| **Authenticated receipt** | Evidence was bound to a tamper-evident HMAC-authenticated receipt. |

**Verified ≠ claim is true.**

The standalone verifier uses only the Python standard library. It does not import WarrantKit or AgentContainment and does not consult control-plane state:

```bash
python tools/verify_runtime_evidence.py tests/fixtures/runtime_pinned_evidence.json
# VERIFIED
```

The verifier checks schema shape, identity, event ordering, runtime binding, exact record digests, revocation, external enforcement, terminal observation, and temporal ordering.

## Concurrency scope

The Warrant lifecycle has a bounded deterministic interleaving regression using `interleave-test`. Issue #81 is complete, including the existing containment/verification interleaving model.

This is evidence for the explored schedules and preemption bound, not a universal concurrency proof.

## Stale-authority attack

The important failure mode is not only whether the process can be killed. It is whether authority retained before containment can still be used afterward.

```text
Before containment
    Warrant(epoch=N) ──► authority is valid
             │
             ▼
        containment
             │
             └──► runtime epoch advances to N+1
                         │
                         ▼
After containment
    replay Warrant(epoch=N) ──► REJECTED
    fresh Warrant(epoch=N+1) ─► requires recovery policy
```

The old Warrant is not "revoked later" as the security boundary. Its runtime epoch is stale, so replay fails against the current execution state. The real-kill proof exercises this with a serialized Warrant snapshot, not an in-memory object.

## Kill path

The agent is not trusted to kill itself.

```
Detect violation
      ↓
Revoke authority
      ↓
Invoke external enforcement
      ↓
Kill / fence runtime
      ↓
Verify terminal state
      ↓
Produce evidence / receipt
```

WarrantKit coordinates the lifecycle. AgentContainment owns the runtime enforcement boundary. Independent evidence records what occurred.

## How WarrantKit differs

WarrantKit complements existing isolation and runtime-security mechanisms rather than replacing them.

| Technology | Primary boundary | WarrantKit's additional boundary |
|---|---|---|
| OPA / Cedar | Policy decision. | Runtime-scoped authority lifecycle, revocation, epoch fencing, recovery gating, and evidence binding. |
| cgroup-v2 | Process/resource containment. | A portable authority contract that identifies what execution is authorized to do and when that authority becomes stale. |
| Capability tokens | Bearer authority. | Warrant authority is explicitly bound to execution/runtime state; Ed25519 can authenticate the object when needed. |
| 30-second credentials + revocation list | Time-bounded authority plus explicit revocation state. | Epoch fencing gives immediate event-driven invalidation at a runtime-state transition instead of waiting for TTL expiry. |
| gVisor / Tetragon / seccomp | Isolation, observability, or syscall enforcement at other layers. | WarrantKit coordinates authority lifecycle above those mechanisms rather than replacing them. |

## Threat model and non-goals

The primary threat model is an autonomous agent treated as untrusted. Authorization, revocation, containment, and recovery remain outside the agent trust boundary.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the detailed model and [AgentContainment security contract](https://github.com/Therealdk8890/AgentContainment/blob/main/docs/SECURITY_CONTRACT.md) for host-side enforcement assumptions.

WarrantKit is **not**:

- a universal host-isolation guarantee;
- an agent-cooperative containment mechanism;
- a mechanism for reversing completed side effects;
- a generic secret manager;
- formal verification or host attestation;
- a generic SIEM or observability platform;
- an agent framework or LLM gateway;
- a replacement for DProvenanceKit or ClaimProofKit.

Passing tests demonstrates behavior in the tested environment and assumptions. It is not a universal security guarantee.

## Fleet governance

The open package includes local governance primitives for:

- Organization → Project → Runtime → Agent inventory;
- policy assignments with identity, version, digest, target, and state;
- deterministic rollout and reconciliation;
- fleet status;
- immutable status history.

These primitives describe desired state and fleet status. They do not constitute a hosted multi-tenant control plane, server-side RBAC system, or centralized enforcement authority.

## Architecture

```
                         WarrantKit
              authority / lifecycle / evidence
                         │
          ┌──────────────┼──────────────┐
          │              │              │
     Authorization   Governance     Evidence refs
          │              │              │
          ▼              ▼              ▼
   AgentContainment    Warden      DProvenanceKit
   runtime enforcement              ClaimProofKit
          │              │              │
          └──────────────┴──────────────┘
                         │
                 operator / audit view
```

WarrantKit coordinates authority and lifecycle state; AgentContainment remains the runtime enforcement boundary. Warden, DProvenanceKit, and ClaimProofKit produce evidence within their own boundaries.

## Security posture

This project is early-stage and actively developed toward a production 1.0 release.

Security-critical claims are backed by CI and privileged integration tests where host/kernel behavior is required. The project does not claim formal verification or universal host security.

## License

Apache-2.0.
