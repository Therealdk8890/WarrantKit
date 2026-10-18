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

## Recent independently inspectable CI evidence

The following public GitHub Actions run completed successfully on **2026-10-18** for commit [`0fcf8d41ee9c`](https://github.com/Therealdk8890/WarrantKit/commit/0fcf8d41ee9c0a2c5e8247d7ce3b37e9fd0260cd):

- [Full CI run and job logs](https://github.com/Therealdk8890/WarrantKit/actions/runs/39083610578)
- [Linux cgroup-v2 workload proof job](https://github.com/Therealdk8890/WarrantKit/actions/runs/39083610578/job/117545604999)
- [Framework authority-boundary proof job](https://github.com/Therealdk8890/WarrantKit/actions/runs/39083610578/job/117545605024)

The run uploaded a `real-kill-incident-bundle` artifact. Download it from the run's **Artifacts** section. The run summary provides the ephemeral Ed25519 public key used separately by CI to verify that run's bundle. Use that key only for the artifact from the same run.

**Artifact retention:** this example artifact is scheduled to expire on **2027-01-16**. The run and instructions remain useful after the artifact expires, but a new successful CI run will be needed for a current downloadable bundle. CI's ephemeral key demonstrates verification relative to that run's key; it is not a production identity, permanent trust anchor, or host attestation.

## How to verify the CI artifact

1. Open the [CI run](https://github.com/Therealdk8890/WarrantKit/actions/runs/39083610578).
2. Download and extract `real-kill-incident-bundle`.
3. In the run summary, copy the **Trusted public key (base64 raw Ed25519)** generated for that exact run.
4. From the extracted directory's parent, run:

   ```bash
   export WARRANTKIT_TRUSTED_PUBLIC_KEY_B64="<public key copied from that run's summary>"
   python tools/verify_runtime_evidence.py ./incident-bundle/runtime-evidence.json
   python tools/verify_incident_bundle.py ./incident-bundle \
     --trusted-public-key "$WARRANTKIT_TRUSTED_PUBLIC_KEY_B64"
   ```

   Run the commands from a WarrantKit checkout containing the verifier scripts; adjust the extracted bundle path if needed.
5. Preserve the verifier output, the exact source commit, the CI run URL, and the environment details together.

The expected authenticated result for that CI artifact is `AUTHENTICATED`. This means the bundle signature verifies against the public key supplied separately to the verifier. It does not prove that the CI runner or host was uncompromised, that the event's underlying claims are true, or that a production operator produced the evidence.

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
