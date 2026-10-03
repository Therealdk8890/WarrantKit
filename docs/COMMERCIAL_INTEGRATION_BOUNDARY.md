# Commercial Integration Boundary

WarrantKit's commercial control plane is designed to consume the open-source
WarrantKit contracts rather than become a dependency of the security-critical
runtime.

## Public contract surface

The supported integration surface includes:

- `Policy` and `PolicyBundle` for policy identity and canonical digests.
- `ExecutionIdentity` for execution/runtime/epoch identity.
- `Warrant` and `verify_warrant` for runtime authority validation.
- `EvidenceEnvelope` for transport-neutral execution evidence.
- `ExternalEvidenceReference` and `ExternalEvidenceHandoff` for external evidence integration.
- `VerificationResult` and `compose_verification` for explicit verification state composition.
- Ed25519 `AttestationEnvelope`, `Ed25519Signer`, and `Ed25519Verifier` for authenticated artifact envelopes.
- Receipt types and verification contracts.
- Fleet/policy rollout primitives for local governance foundations.

These are public protocol/data contracts. Commercial implementations should not
depend on private module details or internal object layouts.

## Trust boundary

The commercial layer may administer, coordinate, index, retain, and display
these contracts at enterprise scale.

It must not:

- manufacture runtime authority from commercial database state;
- override epoch validation;
- resurrect revoked authority;
- turn evidence into authority;
- replace AgentContainment enforcement internals;
- treat a commercial availability signal as proof that runtime authority is valid.

The runtime must remain capable of enforcing its local security boundary when
the commercial control plane is unavailable.

## Dependency direction

```
Commercial WarrantKit
        |
        v
WarrantKit OSS contracts
        |
        v
AgentContainment
```

The reverse dependency is prohibited.

## Status semantics

Integrations must preserve the distinction between:

```
authenticated
correlated
anchored
verified
conflict
incomplete
```

A commercial summary may aggregate these states, but it must not replace them
with an ambiguous generic "trusted" or "secure" status.

## Versioning

The exported Python symbols in `agentcontain.__init__` are the intended
starting point for application-level consumption. Additive changes should be
preferred. Breaking semantic changes require an explicit schema/version
change.

This document describes the open integration boundary only. It does not
contain proprietary control-plane implementation.
