# Real-Kill Demo

WarrantKit has two operator-facing real-kill scripts. Use the evidence-producing proof below when you need a reproducible artifact; use the shorter demo only for a quick live walkthrough.

## Requirements

- Linux with cgroup-v2 mounted
- Root or equivalent cgroup delegation
- AgentContainment submodule initialized
- Python environment with WarrantKit and AgentContainment installed

From the repository root:

```bash
git submodule update --init --recursive
python -m pip install -e ./AgentContainment
python -m pip install -e .
``

## Full proof with portable evidence and incident bundle

This is the recommended proof path. It checks the actual workload and cgroup state, rejects pre-containment authority after the epoch transition, exports runtime-pinned evidence, runs the portable verifier, and can create an independently verifiable incident bundle.

```bash
sudo -E env \
  AGENT_CONTAIN_RUN_REAL_CGROUP=1 \
  WARRANTKIT_REAL_KILL_ARTIFACT=./incident-bundle/runtime-evidence.json \
  WARRANTKIT_INCIDENT_BUNDLE_DIR=./incident-bundle \
  python tools/run_real_kill_demo.py

python tools/verify_runtime_evidence.py ./incident-bundle/runtime-evidence.json
python tools/verify_incident_bundle.py ./incident-bundle
```

The script fails closed if the required Linux/root/cgroup-v2 prerequisites are absent, if the real workload is not attached to the expected cgroup, if containment is not externally verified, if the workload/cgroup remains active, if the pre-containment Warrant remains valid, or if exported evidence fails portable verification.

The runtime evidence artifact is portable and checked by `tools/verify_runtime_evidence.py`. The optional incident bundle additionally binds the authority, containment event, runtime evidence, and external proof, and has its own verification command. Preserve the bundle alongside the exact source revision and host/environment details for review.

## Short live walkthrough

For a quick interactive demonstration without the full portable evidence and incident-bundle workflow:

```bash
sudo -E python tools/real_kill_demo.py
```

This script prints `REAL KILL VERIFIED` after it confirms the child workload exited, the cgroup is empty, and the runtime receipt verifies. Its receipt uses the current HMAC profile.

## Trust boundary and interpretation

- WarrantKit issues authority and coordinates the lifecycle.
- AgentContainment performs runtime enforcement.
- Linux cgroup-v2 is the host-level process containment mechanism.
- The proof independently checks workload membership, terminal process state, and cgroup population.
- The portable evidence verifier checks evidence invariants and integrity; a producer-supplied status is not itself trusted proof.
- The incident-bundle verification receipt uses Ed25519, while the short demo's runtime receipt uses HMAC shared-secret authentication. Neither should be described as universal host attestation or as proof that every underlying claim is true.

A successful run is evidence for the tested Linux host, kernel, cgroup configuration, and software revision. It does not establish universal host security, protection from a compromised kernel/host, policy correctness, benign agent intent, or reversal of side effects that happened before containment. The short demo's HMAC receipt is shared-secret authentication, not non-repudiable attestation.
