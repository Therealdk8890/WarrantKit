# WarrantKit External Proof Package

This page is the starting point for an engineer evaluating WarrantKit. It separates the claims demonstrated by each proof, gives reproducible commands, and links to a recent public CI run with downloadable evidence.

## Start here

**Security invariant:** authority must not survive the runtime state that created it.

WarrantKit coordinates authority lifecycle and evidence. The separate AgentContainment engine performs the enforcement. A Warrant or signed receipt is not, by itself, a process-containment mechanism.

## Choose the proof that matches the claim

| Proof | What it demonstrates | What it does not demonstrate |
|---|---|---|
| [Framework-to-gateway proof](INTEGRATIONS_AND_PROOFS.md) | A retained pre-containment Warrant is rejected before a second protected tool side effect. | Kernel process termination, universal host isolation, or protection for paths that bypass the gateway. |
| [Linux cgroup-v2 real-kill proof](REAL_KILL_DEMO.md) | On the tested compatible Linux environment, the workload is contained, the cgroup is checked, stale authority is rejected, and evidence is exported and verified. | Universal host security, a compromised-kernel defense, reversal of completed side effects, or proof that every claim in the evidence is true. |
| [Portable lifecycle demo](../README.md#the-proof-ladder) | A quick orientation to lifecycle and epoch invalidation. | Real kernel process termination or independent host enforcement. |

If evaluating WarrantKit for the first time, start with the framework-to-gateway proof. Use the Linux real-kill proof when host-level process termination is the claim under review.

## Reproduce the framework-to-gateway proof

From a Linux, macOS, or other supported Python development environment with Git installed:

```bash
git clone --recurse-submodules https://github.com/Therealdk8890/WarrantKit.git
cd WarrantKit
python -m pip install ".[langchain]"
python tools/run_authority_boundary_demo.py
```

This deterministic proof does not require an LLM, network access at runtime, or real credentials. It checks a protected tool action before containment and rejection of a retained pre-containment Warrant before the next protected side effect.

## Reproduce the host-enforcement proof

This proof requires Linux with cgroup v2 mounted and root or equivalent cgroup delegation. It is not supported by native Windows; use a compatible Linux host or VM with the required kernel capabilities.

Follow the maintained [real-kill demo guide](REAL_KILL_DEMO.md). The short version is:

```bash
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
```

Without an independently provisioned trusted public key, the bundle's default verification is an integrity check, not producer authentication. For the trust model and operator-controlled key setup, follow [Incident Trust-Anchor Operations](INCIDENT_TRUST_ANCHOR_OPERATIONS.md).

## Latest inspected privileged CI evidence

The latest inspected privileged CI proof completed successfully on **2026-10-31 UTC** for source revision [`77d401d`](https://github.com/Therealdk8890/WarrantKit/commit/77d401dfe62ea19a65c6deec5cebc81a5203a1ce):

- [WarrantKit CI run #735](https://github.com/Therealdk8890/WarrantKit/actions/runs/41254034356)
- [Linux cgroup-v2 workload proof job](https://github.com/Therealdk8890/WarrantKit/actions/runs/41254034356/job/124693423680)
- [Framework authority-boundary proof job](https://github.com/Therealdk8890/WarrantKit/actions/runs/41254034356/job/124693423679)
- All eight jobs in that run completed successfully, including hostile-agent, unit/adapter, CrewAI, TOCTOU, benchmark, clean-install, framework-boundary, and Linux cgroup-v2 proofs.
- Downloadable evidence: [real-kill-dpk-proof artifact](https://github.com/Therealdk8890/WarrantKit/actions/runs/41254034356/artifacts/13061693695) (13 files; GitHub retention expires **2027-01-29** unless retained or re-published).

The host proof recorded an authorized action, rejection of a stale pre-containment Warrant, gateway rejection before the executor, an empty cgroup (`cgroup_populated=False`), and workload exit code `-9`. Runtime evidence verified as `OBSERVED`; DProvenanceKit trusted-key verification succeeded while wrong-key and tamper checks were rejected; the incident bundle verified as `AUTHENTICATED` against the separately supplied CI trust anchor; and signed cross-artifact bindings verified.

**Evidence scope:** this was a privileged CI run on a PR branch. It is inspectable evidence for the exact tested revision and CI environment, not a release-tag proof, permanent production trust anchor, production operator identity, Kubernetes validation, universal host-isolation guarantee, or proof of host integrity. The ephemeral CI public key is test material for that run only. Re-run and retain the proof through a controlled release process before presenting it as release-specific evidence.

## How to verify the CI artifact

1. Open the [CI run](https://github.com/Therealdk8890/WarrantKit/actions/runs/41254034356).
2. Download and extract `real-kill-dpk-proof` from the run's **Artifacts** section.
3. Obtain the **Trusted public key (base64 raw Ed25519)** generated for that exact run from its summary/log output. Do not reuse a key from another run.
4. From a WarrantKit checkout containing the verifier scripts, run:

   ```bash
   export WARRANTKIT_TRUSTED_PUBLIC_KEY_B64="<public key copied from that run's summary>"
   python tools/verify_runtime_evidence.py ./incident-bundle/runtime-evidence.json
   python tools/verify_incident_bundle.py ./incident-bundle \
     --trusted-public-key "$WARRANTKIT_TRUSTED_PUBLIC_KEY_B64"
   ```

   Adjust the extracted artifact paths to match the downloaded bundle layout.
5. Preserve the verifier output, exact source revision, CI run URL, and environment details together.

The expected authenticated result for the incident bundle is `AUTHENTICATED`. This means the bundle signature verifies against the public key supplied separately to the verifier. It does not prove that the CI runner or host was uncompromised, that the event's underlying claims are true, or that a production operator produced the evidence.

## Evaluation checklist

For an external review, capture:

- Exact WarrantKit commit and AgentContainment revision/package version.
- Operating system, kernel, cgroup-v2 availability, and privilege/delegation model.
- The threat scenario and protected side-effect boundary being tested.
- Observed workload exit and cgroup state, stale-Warrant rejection, and verifier output.
- The trusted public-key source and the distinction between `INTEGRITY_ONLY` and `AUTHENTICATED`.
- Any direct credential or alternate execution path that could bypass the gateway.
- Failures, limitations, latency, setup friction, and behavior that could not be validated.

Never provide production credentials or an unrestricted downstream API key to the agent. If the agent can perform a protected action directly outside the trusted gateway, WarrantKit cannot enforce that bypass path.

## Boundaries and further reading

- [Real-kill proof and limitations](REAL_KILL_DEMO.md)
- [Incident-bundle trust-anchor operations](INCIDENT_TRUST_ANCHOR_OPERATIONS.md)
- [Threat model](THREAT_MODEL.md)
- [Implementation status and proof scope](INTEGRATIONS_AND_PROOFS.md#implementation-status)
- [Design-partner validation](DESIGN_PARTNER_VALIDATION.md)
- [External evaluation record template](EXTERNAL_EVALUATION_RECORD.md) — record environment, proof outcomes, trust-anchor provenance, failures, and next steps consistently.

A successful demonstration is evidence for the tested revision and environment—not a claim of universal isolation, complete production readiness, or protection against a compromised host or kernel.
