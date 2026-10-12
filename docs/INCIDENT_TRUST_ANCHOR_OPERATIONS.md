# Incident-Bundle Trust-Anchor Operations

This guide covers production use of WarrantKit's Ed25519 incident-bundle signature. It complements the [real-kill proof](REAL_KILL_DEMO.md); it does not turn a signature into host attestation or prove that every claim in a bundle is true.

## Trust model

The verifier reports:

- `INTEGRITY_ONLY`: the bundle is internally consistent and its signature checks against a public key carried with the bundle. This does **not** authenticate the producer.
- `AUTHENTICATED`: the signature verifies against a public key supplied separately by the operator. This authenticates the signing key relative to that trust decision; it does not prove the host, runtime, or evidence claims are truthful.

The trusted public key must arrive through a channel independent of the incident bundle. Never promote a public key to trusted merely because it is embedded in the bundle or supplied by the same untrusted producer.

## Provision a deployment key

1. Generate an Ed25519 private key in a trusted operator environment. Do not generate or store the production key in an agent process, demo workspace, or ordinary CI job.
2. Keep the private key under operator control. Restrict file and account permissions; prefer a managed secret store or hardware-backed key custody where available. WarrantKit's current signing interface accepts a private-key file; it does not itself provide HSM/KMS integration.
3. Assign a unique, stable key ID for this key generation. The ID in the signed receipt must match the operator's key inventory.
4. Provision the private key to the trusted signing component using your deployment's secret-management mechanism. The agent must not be able to read the key or bypass the signing component.
5. Provision the corresponding public key separately to each authorized verifier. Record the key ID, public-key fingerprint, owner, purpose, activation date, and approved distribution channel in your operational inventory.
6. Test the deployment with a disposable incident bundle before relying on it operationally.

The repository's CI creates an ephemeral test key only to exercise the authenticated-verification path. **Do not reuse that key or treat CI output as a production trust anchor.**

## Sign and verify

The signing process reads the private key from `WARRANTKIT_INCIDENT_SIGNING_KEY_FILE` and the key ID from `WARRANTKIT_INCIDENT_SIGNING_KEY_ID`. Configure these only in the trusted operator-controlled environment that creates the bundle.

Obtain `warrantkit-public-key.pem` through your trusted provisioning process—not from the bundle under review. From the repository root, derive both the fingerprint to compare against your inventory and the base64 input expected by the verifier:

```bash
python tools/print_trust_anchor.py warrantkit-public-key.pem
```

The helper accepts a PEM-encoded Ed25519 public key only. It prints `fingerprint_sha256` as `SHA256:<hex>` over the raw public-key bytes, and `trusted_public_key_b64` for the verifier. You can set the verifier input directly from that trusted PEM file:

```bash
export WARRANTKIT_TRUSTED_PUBLIC_KEY_B64="$(python tools/print_trust_anchor.py warrantkit-public-key.pem | sed -n 's/^trusted_public_key_b64=//p')"
python tools/verify_incident_bundle.py ./incident-bundle \
  --trusted-public-key "$WARRANTKIT_TRUSTED_PUBLIC_KEY_B64"
```

Accept the bundle as authenticated only when the verifier reports `AUTHENTICATED` and the receipt key ID and independently computed public-key fingerprint match the operator's inventory. Treat `INTEGRITY_ONLY`, `REJECTED`, a key-ID mismatch, or an unknown key as a failed authentication decision. Preserve the complete verifier output with the review record. The fingerprint helper identifies a public key; it does not make an untrusted distribution channel trustworthy.

## Protect, rotate, and revoke keys

- **Least privilege:** only the trusted bundle-signing component should access the private key. Do not expose it to agent tools, prompts, logs, artifacts, or shell tracing.
- **Backups:** protect encrypted backups according to the same custody policy. Restrict access and audit retrieval.
- **Rotation:** create a new key pair and key ID; distribute and verify the new public key independently before switching signing. Update verifier configuration deliberately. Keep the old public key and its key ID in a protected historical trust inventory so prior bundles can still be checked against the key that signed them.
- **Current verifier limitation:** verification takes one trusted public key per invocation. For historical bundles, select the archived public key that matches the receipt's key ID; do not silently try arbitrary keys or fall back to the embedded key and label the result authenticated.
- **Suspected compromise:** stop signing with the affected key, mark it revoked in the operator inventory, distribute the revocation decision to reviewers, and investigate the affected time window. A valid signature from a compromised key is not sufficient evidence of a trustworthy producer.
- **Evidence retention:** preserve the bundle unchanged, verifier output, source commit or release, host/kernel and cgroup configuration, collection time, key ID, and the trusted public-key fingerprint. Hash and store the review package in a separately controlled evidence store where appropriate.

## What this does not guarantee

Ed25519 authenticates possession of a private key. It does not prove that the key holder observed the event correctly, that the kernel or host was uncompromised, that a policy was correct, or that downstream side effects were reversed. Independent host attestation and key-custody integration are separate deployment controls and are not implemented merely by supplying `--trusted-public-key`.
