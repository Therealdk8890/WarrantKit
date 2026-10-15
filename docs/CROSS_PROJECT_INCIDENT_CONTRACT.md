# Cross-Project Incident Contract (Proposal)

**Status:** proposal for review; not an implemented integration or stable public API.

This document defines the smallest useful handoff between Warden, WarrantKit/AgentContainment, and DProvenanceKit. The objective is one reviewable incident record without merging the projects or making one project's output implicitly trusted by another.

## Responsibilities

- **Warden:** emits observations about agent sessions and tool actions. An observation is not authorization and is not proof that an action succeeded.
- **WarrantKit:** records the authority decision and the runtime identity/epoch to which it applies. A Warrant must not remain valid after the runtime transition that invalidates it.
- **AgentContainment:** emits enforcement evidence for the runtime it actually controls, including whether the workload exited and the relevant cgroup became empty when Linux cgroup-v2 proof is enabled.
- **DProvenanceKit:** records the selected, instrumented incident path and binds references/digests to the exact exported artifacts. Its integrity result does not prove that a producer's claims are true.

## Proposed event envelope: `agent-incident-event/v1`

A producer may export a JSON event using this shape:

```json
{
  "schema_version": "agent-incident-event/v1",
  "incident_id": "opaque-stable-id",
  "event_id": "opaque-unique-id",
  "producer": "warden | warrantkit | agentcontainment | dprovenancekit",
  "event_type": "observation | authority_decision | runtime_transition | containment_result | provenance_record",
  "observed_at": "RFC3339 UTC timestamp",
  "runtime": {
    "runtime_id": "opaque-runtime-id",
    "epoch": 0
  },
  "artifact": {
    "media_type": "application/json",
    "sha256": "lowercase-hex-sha256",
    "uri": "optional local or exported artifact reference"
  },
  "claims": {},
  "assurance": {
    "status": "observed | integrity_verified | authenticated",
    "verifier": "optional verifier/version",
    "trust_anchor_id": "optional independently provisioned key identifier"
  }
}
```

The example is illustrative. Implementations must validate types, reject unknown security-critical enum values, and version incompatible changes. Producers may omit fields that do not apply; they must not invent runtime IDs, epochs, timestamps, verification results, or artifact digests.

## Security rules

1. **Observation never grants authority.** Warden events and DPK provenance records must not be accepted as a Warrant or as permission to invoke a tool.
2. **Bind to exact bytes.** Compute SHA-256 over the exact exported artifact bytes. Do not normalize/re-serialize JSON before checking a digest unless a separately versioned canonicalization scheme explicitly requires it.
3. **Keep evidence and claims separate.** A producer's `assurance.status` is descriptive metadata, not a trusted verdict. The verifier computes its own result.
4. **Authenticate independently.** A public key embedded in the same bundle is not an independent trust anchor. `authenticated` is only meaningful when the verifier supplies a trusted key through a separately controlled channel and verifies the signature.
5. **Preserve runtime binding.** Authority and containment evidence must refer to the same runtime identity and the correct epoch transition. A stale-epoch replay should fail verification or authorization as appropriate.
6. **Minimize sensitive data.** Do not copy full prompts, tool outputs, credentials, or customer payloads into a shared incident record by default. Prefer redacted metadata and artifact digests; keep raw artifacts local unless deliberately exported.
7. **Make partial evidence explicit.** Missing events, unsupported enforcement, absent host prerequisites, and unverified external anchors must remain visible. Never upgrade a simulated or in-process result into a kernel-enforced claim.

## DProvenanceKit handoff

The first integration should be deliberately narrow:

1. Export the WarrantKit incident bundle and preserve the exact source revision and host/environment details.
2. Verify the bundle using the WarrantKit verifier and a separately provisioned trust anchor. Record the verifier's actual result; do not copy the bundle's own claimed status as a verdict.
3. Pass a minimal, instrumented incident path into DProvenanceKit: authority issued, runtime transition/containment result, stale-authority replay outcome, and references/digests for the exported evidence.
4. Let DProvenanceKit record and, where supported/configured, attest that instrumented path. Keep the original WarrantKit bundle and the DPK output as separate artifacts.
5. Independently verify each artifact according to its own trust model. A valid DPK signature does not automatically authenticate the WarrantKit producer, and a valid WarrantKit signature does not prove every recorded claim is true.

The first demo should use synthetic test identities and a disposable local environment. It must include a clean case, a stale-Warrant replay rejection, a byte-mutated artifact that fails integrity verification, and a missing-trust-anchor case that does not report producer authentication.

## Acceptance criteria for implementation

- A clean checkout can run the demonstration from documented commands without credentials or a hosted service.
- The output names the exact artifacts, SHA-256 digests, source revisions, and verifier results.
- A stale authority is rejected after the relevant epoch transition.
- Mutating any bound artifact causes the relevant digest/signature verification to fail.
- Removing the external trust anchor cannot produce an authenticated result.
- Unsupported enforcement and incomplete evidence remain explicit.
- Tests prove that Warden observations and DPK records cannot issue or extend authority.
- The README describes this as a reference integration only after the end-to-end tests pass.

## Non-goals

This proposal does not add a shared runtime service, central database, live Evidentia client, production key-management service, universal host attestation, or guarantee that model reasoning is correct. It does not change any project's existing security semantics.
