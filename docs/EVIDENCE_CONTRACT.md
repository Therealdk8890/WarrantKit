# Portable Runtime-Pinned Evidence Contract

## Purpose

This contract defines the smallest portable artifact that an independent
verifier can evaluate without WarrantKit control-plane state or the WarrantKit
verifier implementation.

A successful verification means the supplied artifact is internally consistent
and satisfies the published runtime-enforcement evidence invariants. It does
not prove an arbitrary external claim and does not provide non-repudiable host
attestation.

## Envelope

The serialized document is agentcontain.evidence/v2 and contains exactly:

- schema_version
- execution
- events
- enforcement
- verification
- proof
- receipt
- governance
- provenance
- external_evidence

The portable verifier requires verification.status=observed and
proof.runtime_binding. The artifact's producer-supplied status is not trusted
as a verification result; the independent verifier evaluates the required
invariants itself and reports its own result.

## Runtime binding

proof.runtime_binding has schema agentcontain.runtime-binding/v1 and contains
exactly:

- schema_version
- runtime_id
- agent_id
- epoch
- authority
- enforcement
- observation

The three evidence sections each contain record (the canonical producer record)
and digest (sha256: followed by SHA-256 of the record's canonical JSON).

Canonical JSON uses UTF-8 JSON, lexicographically sorted object keys, and no
insignificant whitespace.

## Runtime-pinned second evidence

The runtime binding deliberately contains two distinct evidence channels:

1. **enforcement** — the runtime enforcement result produced by the
   AgentContainment enforcement path.
2. **observation** — a separately produced runtime observation of the resulting
   terminal state.

Both records are pinned to the same runtime identity and epoch and each has its
own canonical digest. The portable verifier checks both records independently
and requires the observation to occur no earlier than enforcement.

This is a **second-evidence invariant**, not a cryptographic claim of producer
independence. The v2 artifact alone cannot prove that two records came from
organizationally or cryptographically independent operators. Establishing that
stronger property requires an external trust boundary such as independent key
custody, attestation, or external anchoring.

The distinction matters:

**Two pinned records ≠ independent attestation.**

The former is enforceable by this contract. The latter is a separate assurance
property.

## Required invariants

The portable verifier rejects the artifact unless:

1. Envelope schema is agentcontain.evidence/v2.
2. Execution identity is complete and has a positive integer epoch.
3. Every event belongs to the same execution and has contiguous sequence numbers.
4. Runtime binding identity (runtime_id, agent_id, epoch) matches execution.
5. Authority, enforcement, and observation records have matching SHA-256 digests.
6. Every bound record matches the runtime binding identity.
7. Authority evidence explicitly says revoked=true.
8. Enforcement action is KILL or FENCE.
9. Enforcement is explicitly outside the agent boundary.
10. Observation is terminal and explicitly says can_execute=false.
11. Authority revocation precedes enforcement, and enforcement precedes observation.

## What this proves

VERIFIED means the independent verifier established that the artifact satisfies
this contract.

It does not establish that the runtime existed outside the evidence, that the
producer was honest, that a key was held by a particular operator, that the
host kernel was uncompromised, or that an underlying policy/business claim was
true.

It also does not establish that the evidence predates an adversary's ability
to rewrite the producer's entire artifact. External anchoring, key custody, and
non-repudiable attestation are separate trust properties.

## Reference verifier

tools/verify_runtime_evidence.py uses only the Python standard library. It does
not import WarrantKit or AgentContainment and does not consult control-plane
state.

Usage:

    python tools/verify_runtime_evidence.py tests/fixtures/runtime_pinned_evidence.json

A valid artifact prints VERIFIED and exits 0. A contract violation prints
REJECTED and exits 1.
