# Real cgroup and DProvenanceKit proof

This proof joins one WarrantKit execution to a DProvenanceKit-signed event trace. It requires Linux, cgroup v2, root privileges, the initialized AgentContainment submodule, a DPK P-256 signing key and trusted key ID, and a WarrantKit Ed25519 signing key and trusted public key for the incident bundle. The contained child runs as the separate unprivileged `nobody` account; the controller fails closed if that account is unavailable or can read either signing-key file. DPK key material remains controller-only and is not passed to the child.

Install the dependencies from the repository root:

```bash
git submodule update --init --recursive
python -m pip install -e ./AgentContainment
python -m pip install -e '.[attestation]'
python -m pip install 'dprovenancekit[crypto]==0.7.1'
```

Provision either `WARRANTKIT_DPK_SIGNING_KEY_B64` or an owner-only `WARRANTKIT_DPK_SIGNING_KEY_FILE`, plus `WARRANTKIT_DPK_TRUSTED_KEY_ID` from the verifier's trusted-key configuration. Also set `WARRANTKIT_INCIDENT_SIGNING_KEY_FILE`, `WARRANTKIT_INCIDENT_SIGNING_KEY_ID`, and `WARRANTKIT_TRUSTED_PUBLIC_KEY_B64` for the WarrantKit incident bundle. Both private-key files must be unreadable by `nobody`; before launch, the proof checks this by attempting to open each file as that account without reading its contents. Obtain trust anchors independently for production verification. See the [incident trust-anchor operations guide](INCIDENT_TRUST_ANCHOR_OPERATIONS.md) for Ed25519 provisioning.

The Linux CI job creates disposable keys before the run and stores both private keys in a runner-temporary directory with owner-only access. It puts only the DPK key-file path and public trust configuration in the step environment, and publishes only public keys in the Actions run summary separately from the downloadable artifact. The keys are generated within the same workflow and authenticate only that CI run; they do not provide independently established operator identity or production trust.

Run the combined proof:

```bash
sudo -E env \
  AGENT_CONTAIN_RUN_REAL_CGROUP=1 \
  WARRANTKIT_DPK_SIGNING_KEY_B64="$WARRANTKIT_DPK_SIGNING_KEY_B64" \
  WARRANTKIT_DPK_TRUSTED_KEY_ID="$WARRANTKIT_DPK_TRUSTED_KEY_ID" \
  python tools/run_real_kill_dpk_proof.py --output-dir ./real-kill-dpk-proof
```

The command runs WarrantKit's real child-process cgroup proof, exports the WarrantKit runtime evidence and incident bundle, authenticates that bundle with its supplied Ed25519 trust anchor, converts the observed lifecycle events into DPK's `AttestableTrace`, signs the trace, and verifies the persisted attestation and its bound artifacts. Warrant validation and gateway authorization are separate checks: the proof validates the Warrant, then calls `ActionGateway`, whose pinned API enforces policy and runtime state but does not itself validate the Warrant. It requires all of these cases to hold:

1. WarrantKit validates a Warrant, and ActionGateway separately executes one policy-allowed action.
2. Containment advances the epoch; WarrantKit rejects the prior Warrant, and ActionGateway separately denies a later action.
3. Linux independently reports the workload exited and the cgroup empty.
4. The DPK signature passes with the trusted key ID, while a wrong key ID and modified trace fail.

The output directory contains `execution-trace.json`, `runtime-evidence.json`, the WarrantKit `incident-bundle/`, `dpk-trace.json`, `dpk-attestation.json`, and `verification-report.json`. The DPK report binds the WarrantKit execution ID, runtime ID, epochs, and runtime-evidence digest to the signed trace.

Verify the delivered files again:

```bash
python tools/verify_real_kill_dpk_proof.py \
  --attestation ./real-kill-dpk-proof/dpk-attestation.json \
  --runtime-evidence ./real-kill-dpk-proof/runtime-evidence.json \
  --incident-bundle ./real-kill-dpk-proof/incident-bundle \
  --trusted-key-id "$WARRANTKIT_DPK_TRUSTED_KEY_ID" \
  --trusted-public-key "$WARRANTKIT_TRUSTED_PUBLIC_KEY_B64"
```

The DPK signature establishes the integrity of the signed event trace relative to the configured signer key. The final verifier checks the exact persisted runtime-evidence and incident-manifest bytes against digests in that signed trace, then verifies those same byte snapshots. Runtime enforcement is observed separately by the WarrantKit/AgentContainment path and Linux cgroup/process checks; the signature does not independently attest the host or prove the truth of those observations. This deterministic child-process proof is not the previously described `gemma4:e2b` model run and does not establish model reasoning truth.
