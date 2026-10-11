# Evidence Trust Model

## Purpose

WarrantKit separates authority from evidence. This document defines what a verified receipt means, what it does not mean, and how trust changes when asymmetric signatures are used.

## Core semantics

- **Warrant** = authority granted for one execution.
- **Evidence** = an observation or result produced at a declared evidence boundary.
- **Verification** = the defined procedure successfully checked the supplied evidence and bindings.
- **Receipt** = a record that binds evidence to an execution and verification context.

**Verified does not mean the underlying claim is universally true.** Verification establishes only the documented invariants against the supplied artifact and trust anchors.

## Current profiles

### HMAC receipt profile

The runtime receipt path supports HMAC authentication using an operator/deployer-supplied shared secret.

This provides integrity/tamper detection when the secret is protected and authentication to holders of that secret. It does not provide non-repudiation, prove a unique signer created the receipt, or prevent a secret-holder from fabricating receipts.

HMAC must not be described as asymmetric attestation.

### Ed25519 attestation profile — implemented

The optional `warrantkit[attestation]` extra provides Ed25519 signing and verification for Warrant and receipt artifacts. The signed envelope includes a schema version, artifact type, algorithm, key ID, issuance time, canonical payload, and signature. Signature input is domain-separated and canonicalized.

The verifier checks the signature against the configured public key for the envelope's `key_id`. It rejects unknown key IDs, invalid signatures, unsupported schema/algorithm/artifact types, and payload or envelope tampering. Warrant signature verification authenticates the Warrant artifact; callers must still run the ordinary Warrant checks for execution, policy, runtime, epoch, validity, and lifecycle.

Example rotation behavior is supported by supplying a mapping of trusted key IDs to public keys to `Ed25519Verifier`:
- **Overlap:** include both old and new keys while both should be trusted.
- **Retirement:** remove the old key from the configured mapping; artifacts signed only by that key are then rejected as unknown.
- **Unknown key:** rejected by default.

This is verifier-configured key rotation, not a hosted key-management or revocation service. The library does not automatically manage key validity windows, persist trust policy, distribute keys, or determine when a key should be retired. Operators must distribute trust anchors through a channel independent of the artifact being verified.

## Trust anchors and limits

An asymmetric signature establishes authenticity relative to a configured public-key trust anchor. It does **not** by itself prove:
- that the host is uncompromised or the kernel is trustworthy;
- that the runtime provider enforced the action correctly;
- that an agent's intent was benign or a policy was correct; or
- that an external claim is true.

Host/TPM/measured-boot attestation is a separate future trust layer.

## Evidence boundary

For containment, the evidence chain is:

1. WarrantKit establishes authority and execution identity.
2. AgentContainment performs security-critical external enforcement.
3. The runtime produces enforcement evidence.
4. Independent observation can establish the workload's resulting state.
5. WarrantKit correlates facts by execution identity, runtime identity, and epoch.
6. The verifier checks the defined invariants and any required signature.
7. The receipt records the resulting verification state.

No evidence step grants, extends, or restores authority. A valid signature cannot turn incomplete, stale, conflicting, or missing evidence into verified enforcement.

## Conflicts

Conflicting evidence must remain explicitly conflicting or unverifiable rather than being promoted to verified. Examples include:
- enforcement reports epoch 18 while an external record is anchored to epoch 17;
- runtime identity differs between evidence sources; or
- a replacement record is internally valid but conflicts with an earlier external anchor.

Correlation and integrity checks do not independently establish that the underlying observations are truthful.

## Compatibility

- HMAC and Ed25519 are distinct trust profiles and must be identified accurately.
- HMAC must never be presented as non-repudiable.
- Unknown or retired Ed25519 key IDs fail closed under the verifier's configured trust-anchor mapping.
- A stronger signature does not upgrade weak or missing runtime evidence into verified enforcement.
- Key rotation changes the signing key, not the authority semantics.

## Non-goals

This trust model does not claim formal verification, universal host security, measured-boot attestation, policy correctness, agent-intent correctness, reversal of completed side effects, or universal truth of externally supplied claims.
