# WarrantKit Security Overview

**External enforcement and runtime-bound authority for autonomous agents.**

> **Security invariant:** authority must not survive the runtime state that created it.

WarrantKit coordinates policy-bound execution authority, runtime-epoch fencing, and evidence. The separate [AgentContainment](https://github.com/Therealdk8890/AgentContainment) engine performs runtime enforcement. This is an open-source security integration—not a hosted security platform, universal sandbox, or guarantee that every agent action is contained.

## The incident we are trying to prevent

An autonomous agent receives authority to perform a protected action. Its runtime is later contained, but the agent, a queued tool call, or a retained authorization object may still attempt to act.

A cooperative stop instruction is not an enforcement boundary. The operator needs an external mechanism to stop the workload and reject authority from the runtime generation that was just invalidated.

## What the system does

1. **Admit:** evaluate policy and bind a signed Warrant to execution identity, runtime identity, policy digest, capabilities, and current epoch.
2. **Execute:** the framework adapter verifies the Warrant before the protected tool handler, then routes the action through AgentContainment's controller-owned ActionGateway.
3. **Contain:** the external runtime controller performs the configured containment operation.
4. **Fence:** the runtime epoch advances; retained Warrants from the previous epoch are rejected.
5. **Verify:** the operator checks process/cgroup state and verifies exported evidence using the documented verifier and trust anchor.

The Warrant and gateway lease are separate checks in the current implementation. The adapter verifies the signed Warrant; ActionGateway independently enforces a controller-owned execution lease. A serialized Warrant is not a gateway bearer credential.

## Evidence card: independently inspectable proof

**Latest inspected privileged CI proof on this documentation branch (2026-10-31 UTC)**

- Source revision: [77d401d](https://github.com/Therealdk8890/WarrantKit/commit/77d401dfe62ea19a65c6deec5cebc81a5203a1ce)
- CI run: [WarrantKit CI #735](https://github.com/Therealdk8890/WarrantKit/actions/runs/41254034356)
- Host-containment job: [Linux cgroup-v2 workload proof](https://github.com/Therealdk8890/WarrantKit/actions/runs/41254034356/job/124693423680)
- Framework boundary job: [Framework authority-boundary proof](https://github.com/Therealdk8890/WarrantKit/actions/runs/41254034356/job/124693423679)
- All eight jobs in this run completed successfully, including hostile-agent, unit/adapter, CrewAI, TOCTOU, benchmark, clean-install, framework-boundary, and Linux cgroup-v2 proofs.
- Downloadable evidence: [real-kill-dpk-proof artifact](https://github.com/Therealdk8890/WarrantKit/actions/runs/41254034356/artifacts/13061693695) (13 files; GitHub retention expires 2027-01-29 unless retained or re-published).
- Host proof observed: authorized action executed; stale pre-containment Warrant rejected; gateway rejected the stale action before executor; cgroup_populated=False; workload exit code -9; runtime evidence verified as OBSERVED; DPK trusted-key verification succeeded and wrong-key/tamper checks rejected; incident bundle verified as AUTHENTICATED against the separately supplied CI trust anchor; signed cross-artifact bindings verified.

The CI signing key and trust anchor are isolated test material for this workflow run. The public trust value is visible in the workflow log; it is not a secret or a production operator identity. This run proves the tested CI environment and configured path only. It does not prove Kubernetes deployment, universal host isolation, formal verification, or production key custody. The artifact is attached to a PR-branch run and should not be presented as a permanent release artifact without re-running or retaining it through a controlled release process.

## Cryptographic mechanisms: do not conflate them

| Artifact / path | Mechanism | What it establishes | What it does not establish |
|---|---|---|---|
| Signed Warrant used by protected framework adapters | Ed25519 signature; verifier uses a deployment-configured trusted public key | The Warrant payload was signed by the private key corresponding to the trusted public key | It does not make the Warrant a gateway credential or prove the host is uncompromised |
| Full incident-bundle receipt | Ed25519 signature; authenticated verification requires an independently provisioned operator public key | The bundle signature verifies relative to the operator's trust decision; AUTHENTICATED is distinct from INTEGRITY_ONLY | It does not prove every statement in the bundle is true or that the signer observed events correctly |
| Short real_kill_demo.py runtime receipt | HMAC shared-secret authentication | A holder of the shared secret produced the receipt; tampering is detectable under the HMAC key | It is not asymmetric authentication or non-repudiable attestation |
| Portable runtime-evidence verifier | Structural and integrity checks over evidence invariants | The exported evidence satisfies the verifier's defined consistency checks | A verifier result alone does not establish producer identity or host integrity |

**Key custody is part of the trust model.** Keep private signing keys outside the agent process. Provision verifier public keys independently of the artifact being checked. A public key embedded in an uploaded bundle is not a trust anchor. See [trust-anchor operations](INCIDENT_TRUST_ANCHOR_OPERATIONS.md).

## Reproduce the proof

### Framework-to-gateway boundary

This deterministic proof runs without an LLM, network access, or production credentials:

    git clone --recurse-submodules https://github.com/Therealdk8890/WarrantKit.git
    cd WarrantKit
    python -m pip install ".[langchain]"
    python tools/run_authority_boundary_demo.py

It checks that a retained pre-containment Warrant is rejected before a second protected tool side effect.

### Linux host process containment

This proof requires Linux with cgroup v2 mounted and root or equivalent cgroup delegation:

    git clone --recurse-submodules https://github.com/Therealdk8890/WarrantKit.git
    cd WarrantKit
    python -m pip install -e ./AgentContainment
    python -m pip install -e '.[attestation]'

    sudo -E env \
      AGENT_CONTAIN_RUN_REAL_CGROUP=1 \
      WARRANTKIT_REAL_KILL_ARTIFACT=./incident-bundle/runtime-evidence.json \
      WARRANTKIT_INCIDENT_BUNDLE_DIR=./incident-bundle \
      python tools/run_real_kill_demo.py

    python tools/verify_runtime_evidence.py ./incident-bundle/runtime-evidence.json
    python tools/verify_incident_bundle.py ./incident-bundle

Without an independently provisioned trusted public key, default bundle verification is INTEGRITY_ONLY, not producer authentication. Follow the [real-kill guide](REAL_KILL_DEMO.md) and [trust-anchor operations](INCIDENT_TRUST_ANCHOR_OPERATIONS.md) before interpreting the result.

## Kubernetes deployment boundary

The host-enforcement proof is a Linux cgroup-v2 integration, not a Kubernetes operator or turnkey Helm deployment. Kubernetes does not remove the host prerequisites: the node must use Linux with cgroup v2, and the enforcement controller must have a deliberate, tested view of and authority over the workload's cgroup subtree.

See [Kubernetes deployment considerations](KUBERNETES_DEPLOYMENT.md) for the supported boundary, node/pod placement considerations, and what has not yet been validated.

## Important limitations

- The tested kernel containment path is Linux cgroup v2 and requires root or suitable delegated privileges. Native Windows and macOS are not host-enforcement targets for this proof.
- A framework adapter protects only calls routed through that adapter and ActionGateway. Direct credentials, alternate tool paths, hosted tools, remote MCP servers, and unwrapped side effects can bypass it.
- The current framework integrations are synchronous paths; do not assume async-native execution is covered.
- Epoch fencing invalidates all authority tied to the prior runtime generation; legitimate work may need fresh authority.
- Containment does not reverse side effects completed before the boundary was enforced.
- A valid Ed25519 signature authenticates a payload relative to a trusted key. It does not attest to host/kernel integrity or make the underlying claims true.
- This is not a certified sandbox, universal host-isolation guarantee, or production-readiness claim.

## What we want to validate with design partners

We are looking for a small number of teams already operating coding or autonomous agents in staging or production. The evaluation should use a representative, sanitized workload and establish:

- the agent's real authority and bypass paths;
- the current stop/containment mechanism and its failure modes;
- whether a compatible Linux cgroup-v2 deployment is feasible;
- whether the observed process/cgroup and stale-authority evidence satisfies the team's security reviewer;
- which integration or operational blocker prevents adoption;
- whether the problem is urgent enough to justify engineering time or budget.

We will not add enterprise features based on hypothetical demand. New roadmap work must be tied to a demonstrated blocker from a qualified workload owner.

Start with the [design-partner validation guide](DESIGN_PARTNER_VALIDATION.md) and [pilot outline](DESIGN_PARTNER_PILOT.md).

## Technical references

- [External proof package](EXTERNAL_PROOF_PACKAGE.md)
- [Real-kill demo and interpretation](REAL_KILL_DEMO.md)
- [Incident-bundle API and trust model](INCIDENT_BUNDLE_API.md)
- [Incident trust-anchor operations](INCIDENT_TRUST_ANCHOR_OPERATIONS.md)
- [Threat model](THREAT_MODEL.md)
- [Implementation status and proof scope](INTEGRATIONS_AND_PROOFS.md#implementation-status)
