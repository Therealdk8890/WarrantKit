# WarrantKit

[![WarrantKit CI](https://github.com/Therealdk8890/WarrantKit/actions/workflows/ci.yml/badge.svg)](https://github.com/Therealdk8890/WarrantKit/actions/workflows/ci.yml)

**Authority that expires when the runtime state that created it changes.**

WarrantKit binds an execution's authority to accepted policy, runtime identity, and runtime epoch. When the controller advances that epoch during containment, retained pre-containment authority no longer matches current runtime state.

WarrantKit is the authority/lifecycle layer; [AgentContainment](https://github.com/Therealdk8890/AgentContainment) is the external runtime enforcement engine.

## First proof: replay a stale Warrant

Install the package and run the no-root demo:

```bash
python -m pip install --upgrade warrantkit
warrantkit demo
```

To inspect the verifier contract directly from a source checkout, run this end-to-end controller-backed proof. It uses the installed AgentContainment engine, not a caller-supplied epoch. No root privileges, LLM, LangChain, or submodule checkout are required.

```bash
git clone https://github.com/Therealdk8890/WarrantKit.git
cd WarrantKit
python -m pip install -e .
python - <<'PY'
from agentcontain import Policy, admit, build_agentcontainment_engine, contain
from agentcontain.warrant import Warrant, verify_warrant

engine = build_agentcontainment_engine("first-proof")
admission = admit(
    Policy("payments", capabilities=("payments_refund",)),
    agent_id="payments-agent",
    engine=engine,
    runtime_id=engine.runtime_id,
)
if admission.warrant is None:
    raise RuntimeError("the proof requires a runtime-bound Warrant")

# Keep a serialized copy the agent could have retained before containment.
retained = Warrant.from_dict(admission.warrant.to_dict())
identity = admission.identity
def verify_against_controller_epoch():
    verify_warrant(
        retained,
        execution_id=identity.execution_id,
        agent_id=identity.agent_id,
        policy_id=identity.policy_id,
        policy_digest=identity.policy_digest,
        runtime_id=identity.runtime_id,
        epoch=admission.engine.controller.runtime.epoch,
    )

verify_against_controller_epoch()
print(f"controller epoch {admission.engine.controller.runtime.epoch}: ACCEPTED")

contain(admission)
current_epoch = admission.engine.controller.runtime.epoch
print(f"controller epoch advanced to {current_epoch}")

try:
    verify_against_controller_epoch()
except ValueError as exc:
    if "epoch" not in str(exc):
        raise
    print(f"retained Warrant: REJECTED ({exc})")
else:
    raise SystemExit("FAIL: stale Warrant was accepted")
PY
```

The important input is `runtime.epoch`, read from the controller-owned runtime after containment. The caller does not choose the epoch used for verification.

This is a verifier-level and controller-backed proof, not a claim that the snippet itself kills a process. For kernel-enforced workload termination, use the separate [privileged Linux proof](docs/REAL_KILL_DEMO.md).

## Boundary, stated plainly

**The process that runs the agent must not hold credentials that let it perform protected side effects without the enforcement boundary.** Payment API keys, database credentials, cloud credentials, and equivalent secrets must be held by the trusted gateway/controller or by a downstream service that independently enforces the same authorization. If the agent can call the downstream API directly with its own unrestricted key, the gateway is advisory and WarrantKit cannot prevent that bypass.

WarrantKit's Warrant is a typed authority contract, not currently a bearer credential consumed directly by AgentContainment's ActionGateway. The gateway enforces controller-owned execution leases. A serialized or unsigned Warrant is not self-authenticating; Ed25519 attestation is available when a deployment configures a trusted public-key anchor.

## What epoch fencing adds

Epoch fencing is a form of **fencing token**, a known distributed-systems pattern: a resource checks a monotonically advancing generation so work from an earlier owner or runtime state is rejected. See [Martin Kleppmann's explanation of fencing tokens](https://martin.kleppmann.com/2016/02/08/how-to-do-distributed-locking.html).

A revocation list can also invalidate a credential immediately when every enforcement point checks it. The distinction is not “epoch is immediate, revocation is delayed.” Instead:

- **Per-Warrant revocation** tracks individual credentials and requires the relevant revocation state to be available and checked.
- **Epoch fencing** invalidates every retained Warrant from an older runtime generation by comparing against one controller-owned epoch, without tracking every copy individually.
- **Expiry** bounds validity by time; it is useful as a separate defense, not a substitute for either revocation or epoch checks.

In the framework proof, explicit revocation can cause the first rejection. The first proof above isolates the epoch mismatch by retaining an active serialized copy while the controller advances the runtime epoch.

## Second act: framework tool, then external containment

The deterministic framework proof uses a real LangChain tool but no LLM, network call, or API key. It invokes the protected tool before containment, advances the external runtime state, then proves that the retained authority is rejected before the second side effect can run.

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

WarrantKit is not a sandbox, a universal host-isolation guarantee, a secret manager, a mechanism for reversing completed side effects, or a replacement for IAM, policy engines, cgroups, or independent provenance verification. It complements those controls by binding execution authority to runtime state and fencing stale authority after a security event.

## How WarrantKit differs

| Approach | Primary guarantee | WarrantKit's distinct contribution |
|---|---|---|
| OPA / Cedar | Policy decision | Runtime-scoped authority lifecycle, epoch fencing, and recovery gating around protected actions |
| cgroup-v2 | Process/resource containment | An authority contract tied to execution identity and runtime epoch |
| Capability-token systems | Scoped or delegated authority | Runtime-generation fencing plus external containment; not a claim that capability warrants are unique to WarrantKit |
| Short-lived credentials + revocation list | Expiry and explicit per-credential revocation | One runtime epoch invalidates all older-generation authority without a per-copy revocation list; a revocation list can also invalidate immediately |
| Tenuo and Liceat | Warrant-based, task-scoped agent authorization and capability controls | WarrantKit focuses on runtime-epoch invalidation and external containment, rather than claiming ownership of the word “warrant” or general capability authorization ([Tenuo](https://github.com/tenuo-ai/tenuo), [Liceat](https://liceat.com/)) |

## Start here

- [Threat model](docs/THREAT_MODEL.md)
- [Real-kill demo requirements](docs/REAL_KILL_DEMO.md)
- [Extended integrations, evidence, implementation status, and proof documentation](docs/INTEGRATIONS_AND_PROOFS.md)
- [AgentContainment security contract](https://github.com/Therealdk8890/AgentContainment/blob/main/docs/SECURITY_CONTRACT.md)

## License

Apache-2.0.
