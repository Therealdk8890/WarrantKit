# WarrantKit

[![WarrantKit CI](https://github.com/Therealdk8890/WarrantKit/actions/workflows/ci.yml/badge.svg)](https://github.com/Therealdk8890/WarrantKit/actions/workflows/ci.yml)

**Runtime authorization, containment, and evidence platform for autonomous AI agents.**

> **Don't ask the agent to enforce its own boundaries. Enforce them from outside the agent trust boundary.**

The core invariant is simple: **authority must not survive the runtime state that created it.** A Warrant is bound to an execution and runtime epoch; when containment or recovery advances that epoch, a retained pre-containment Warrant becomes stale and cannot be replayed.

WarrantKit is the platform/control layer around the AgentContainment enforcement engine. The repository ships local authorization, admission, runtime containment coordination, epoch fencing, recovery gating, evidence envelopes, fleet-governance primitives, external evidence contracts, cryptographic attestation primitives, and offline verification receipts. Hosted multi-tenant operations and enterprise integrations are not shipped here.

The practical question is: **what is an autonomous agent allowed to do, what happens when it crosses that boundary, how is its authority revoked, and what evidence can be independently checked afterward?**

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

## What is a Warrant?

A **Warrant** is WarrantKit's portable authority contract for one execution. It binds execution identity, accepted policy identity and digest, runtime identity and epoch, validity/revocation state, capabilities, constraints, and required evidence.

Today the Warrant is a typed, transport-neutral authority object rather than a signed bearer token. It is verified against the exact execution, policy, runtime, epoch, and validity window; the AgentContainment controller remains the runtime enforcement boundary. Asymmetric Warrant attestation is a future trust-model extension.

A Warrant answers:

> **Under exactly what authority was this execution admitted?**

It does not establish that an action was safe, that agent intent was correct, or that an external claim is true.

**Warrant = authority.**  
**Evidence = what was observed or produced.**  
**Verification = whether defined evidence checks succeeded.**  
**Receipt = an authenticated record of evidence.**

Evidence never grants authority, and a Warrant is never derived from evidence.

### Trust questions

- **Why not Macaroons/Biscuit?** WarrantKit currently defines an application-level authority contract bound to execution identity and runtime epoch rather than choosing a general-purpose bearer-token language; signed/distributed authority is a future trust-model decision.
- **Is epoch just a fencing token?** It is used as a fencing token, but WarrantKit makes the epoch part of the authority validity contract: containment/recovery advances it so prior authority becomes stale.
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
| Linux cgroup-v2 workload containment | **Implemented · privileged integration-tested** | Requires Linux cgroup v2 and the required host privileges/delegation. |
| Adversarial containment/security regression tests | **Implemented · CI-tested** | Covers fail-closed and stale-authority/escape conditions in the tested environment. |
| Local fleet governance primitives | **Implemented · CI-tested** | Inventory, assignment, rollout/reconciliation, and status history are local foundations. |
| External evidence correlation | **Planned / partial** | Cross-source contracts and typed references exist; generalized correlation/reconciliation is not shipped. |
| Hosted multi-tenant control plane | **Planned** | Centralized orchestration, durable retention, and enterprise RBAC are commercial work. |
| Enterprise integrations | **Planned / integration-dependent** | IAM, SIEM/SOAR, deployment automation, and production integrations are not implied by the OSS foundation. |
| Non-repudiable host attestation | **Planned** | Current receipts are HMAC-authenticated; stronger host-anchored attestation is future work. |

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

The privileged Linux proof uses a real child process and a real cgroup-v2 boundary:

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
AGENT_CONTAIN_RUN_REAL_CGROUP=1 WARRANTKIT_REAL_KILL_ARTIFACT=./real-kill-runtime-evidence.json \
python tools/run_real_kill_demo.py
```

The demo emits a portable evidence artifact and passes it through `tools/verify_runtime_evidence.py`. The fixture used by the verifier is a contract test; the real-kill path is the host-dependent proof. The lower-level pytest remains available for regression coverage.

**What this proves:** the tested Linux environment can enforce the configured cgroup-v2 kill/fence boundary, reject replay of pre-containment authority after the epoch changes, produce runtime-pinned evidence, and have that artifact independently checked.

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
| Tetragon | Kernel-level runtime observability and policy enforcement. | Explicit execution authority bound to runtime epoch, with containment/recovery invalidating stale authority. |
| seccomp | Linux system-call filtering. | Agent-specific authority lifecycle, revocation, epoch fencing, recovery gating, and evidence semantics. |
| gVisor | Sandboxed application-kernel boundary. | Authority and evidence lifecycle above the isolation boundary. |

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
