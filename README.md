# WarrantKit

[![WarrantKit CI](https://github.com/Therealdk8890/WarrantKit/actions/workflows/ci.yml/badge.svg)](https://github.com/Therealdk8890/WarrantKit/actions/workflows/ci.yml)

**Authority that expires when the runtime state that created it changes.**

WarrantKit binds an execution's authority to accepted policy, runtime identity, and runtime epoch. When the controller advances that epoch during containment, retained pre-containment authority no longer matches current runtime state.

WarrantKit is the authority/lifecycle layer; [AgentContainment](https://github.com/Therealdk8890/AgentContainment) is the external runtime enforcement engine.

## Enforcement boundary, stated first

**A Warrant check and the runtime enforcement check are related, but they are not the same object.** WarrantKit's framework adapter verifies the Warrant against the controller's current runtime identity and epoch, then sends the action through AgentContainment's ActionGateway. The gateway's final runtime enforcement is based on controller-owned execution leases. The adapter's Warrant check must reject stale authority before it reaches the gateway; the gateway remains the final enforcement point for the side effect.

This is an explicit two-check design, not a claim that ActionGateway directly consumes a serialized Warrant as a bearer credential. The framework proof tests the complete adapter-to-gateway path by showing that a protected tool call succeeds before containment and that a retained pre-containment Warrant is rejected before the second tool side effect.

**The process that runs the agent must not hold credentials that let it perform protected side effects without the enforcement boundary.** Payment API keys, database credentials, cloud credentials, and equivalent secrets must be held by the trusted gateway/controller or by a downstream service that independently enforces the same authorization. If the agent can call the downstream API directly with its own unrestricted key, the gateway is advisory and WarrantKit cannot prevent that bypass.

WarrantKit's Warrant is a typed authority contract, not currently a bearer credential consumed directly by AgentContainment's ActionGateway. The gateway enforces controller-owned execution leases. A serialized or unsigned Warrant is not self-authenticating. Protected LangChain and CrewAI tool paths require the Warrant to be signed at issuance and verified against a deployment-configured Ed25519 public-key anchor. This authenticates the Warrant payload; it does not isolate the controller from the verifier or a compromised host. The verifier/controller in the no-root demo run in one Python process, so isolation remains a deployment requirement. See the [threat model](docs/THREAT_MODEL.md).

## Narrow proof: reject a stale Warrant

Install the package and run the stale-Warrant verifier proof:

```bash
python -m pip install --upgrade warrantkit
warrantkit demo
```

The proof retains a serialized copy of an active Warrant, reads the current epoch from the AgentContainment controller runtime, performs containment, and verifies that the retained pre-containment Warrant is rejected against the advanced epoch. It needs no root privileges, LLM, LangChain, source clone, or submodule checkout.

**What this proves:** the verifier rejects retained authority bound to the previous runtime epoch.

**What it does not prove:** that ActionGateway consumes the Warrant directly, that the issuer's signature is authenticated, or that the controller is isolated from the verifier or a compromised host. For the adapter-to-gateway side-effect proof, continue to the framework demonstration below. For kernel-enforced workload termination, use the separate [privileged Linux proof](docs/REAL_KILL_DEMO.md).

To see the simulated incident-lifecycle walkthrough instead, run `warrantkit demo lifecycle`. That walkthrough explicitly reports that host enforcement verification is not claimed.

## What epoch fencing adds

Epoch fencing is a form of **fencing token**, a known distributed-systems pattern: a resource checks a monotonically advancing generation so work from an earlier owner or runtime state is rejected. See [Martin Kleppmann's explanation of fencing tokens](https://martin.kleppmann.com/2016/02/08/how-to-do-distributed-locking.html).

A revocation list can also invalidate a credential immediately when every enforcement point checks it. The distinction is not “epoch is immediate, revocation is delayed.” Instead:

- **Per-Warrant revocation** tracks individual credentials and requires the relevant revocation state to be available and checked.
- **Epoch fencing** invalidates every retained Warrant from an older runtime generation by comparing against one controller-owned epoch, without tracking every copy individually.
- **Operational cost:** the invalidation is coarse-grained. Advancing the runtime epoch invalidates *all* Warrants bound to the prior epoch, including legitimate ones; affected executions need fresh authority issued for the new epoch.
- **Expiry** bounds validity by time; it is useful as a separate defense, not a substitute for either revocation or epoch checks.

In the framework proof, explicit revocation can cause the first rejection. The first proof above isolates the epoch mismatch by retaining an active serialized copy while the controller advances the runtime epoch.

## Second act: framework tool, then external containment

The deterministic framework proof is the stronger end-to-end example: it uses a real LangChain tool and AgentContainment's ActionGateway, but no LLM, network call, or API key. The adapter checks the Warrant against current runtime state, then calls the gateway, whose controller-owned lease is the final enforcement mechanism. The proof invokes the protected tool before containment, advances the runtime state, and shows that the retained Warrant is rejected before the second side effect can run. The Warrant and lease are distinct objects; this proves the adapter-to-gateway execution path, not that the gateway directly consumes the Warrant.

```bash
git clone --recurse-submodules https://github.com/Therealdk8890/WarrantKit.git
cd WarrantKit
python -m pip install ".[langchain]"
python tools/run_authority_boundary_demo.py
```

Expected proof properties:
- the first protected tool call executes;
- external containment advances the runtime epoch;
- the retained pre-containment Warrant is rejected;
- the second protected call does not reach the underlying side effect.

This does **not** prove universal host isolation, reversal of completed side effects, or that a serialized Warrant is itself an ActionGateway credential.

## What WarrantKit is — and is not

A **Warrant** binds one execution to accepted policy identity and digest, runtime identity and epoch, validity, capabilities, constraints, and evidence requirements.

- **Warrant = authority.**
- **Evidence = what was observed or produced.**
- **Verification = whether defined checks succeeded.**
- **Receipt = a record of evidence and its stated authentication status.**

Evidence never grants authority. **Verified does not mean an external claim is true.**

The current egress path is not a general destination-policy engine: a deny-all egress rule can act as a kill switch, but it does not implement an allowlist of approved destinations. See the [egress binding contract](docs/EGRESS_BINDING_CONTRACT.md).

WarrantKit is not a sandbox, a universal host-isolation guarantee, a secret manager, a mechanism for reversing completed side effects, or a replacement for IAM, policy engines, cgroups, or independent provenance verification. It complements those controls by binding execution authority to runtime state and fencing stale authority after a security event.

## How WarrantKit differs

| Approach | Primary guarantee | WarrantKit's distinct contribution |
|---|---|---|
| OPA / Cedar | Policy decision | Runtime-scoped authority lifecycle, epoch fencing, and recovery gating around protected actions |
| cgroup-v2 | Process/resource containment | An authority contract tied to execution identity and runtime epoch |
| Capability-token systems | Scoped or delegated authority | Runtime-generation fencing plus external containment; not a claim that capability warrants are unique to WarrantKit |
| Short-lived credentials + revocation list | Expiry and explicit per-credential revocation | One runtime epoch invalidates all older-generation authority without a per-copy revocation list; a revocation list can also invalidate immediately |
| Tenuo and Liceat | Warrant-based, task-scoped agent authorization and capability controls | WarrantKit's emphasis is runtime-epoch invalidation tied to an external containment controller and a controller-owned gateway lease ([Tenuo](https://github.com/tenuo-ai/tenuo), [Liceat](https://liceat.com/)) |

## Start here

- [Threat model](docs/THREAT_MODEL.md)
- [Real-kill demo requirements](docs/REAL_KILL_DEMO.md)
- [Implementation status: CI-tested versus planned](docs/INTEGRATIONS_AND_PROOFS.md#implementation-status)
- [Extended integrations, evidence, and proof documentation](docs/INTEGRATIONS_AND_PROOFS.md)
- [AgentContainment security contract](https://github.com/Therealdk8890/AgentContainment/blob/main/docs/SECURITY_CONTRACT.md)

## License

Apache-2.0.
