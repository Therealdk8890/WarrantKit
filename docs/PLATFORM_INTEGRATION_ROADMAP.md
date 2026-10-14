# Platform Integration Roadmap

## Purpose

Restore the original WarrantKit platform objective: independently implemented components produce evidence with explicit provenance and trust boundaries, and WarrantKit binds those artifacts to an execution and runtime epoch. The platform is **not** one package, one source of truth, or a chain where one component's `verified` flag grants authority.

This document separates what exists today from the next integration proof. It is a plan, not a claim that every integration below is already implemented.

## Architecture contract

| Component | Responsibility | Must not be trusted to do |
|---|---|---|
| WarrantKit | Authority lifecycle, policy binding, execution identity, epoch checks, evidence-reference binding and eventual conflict reporting | Treat evidence as authority; infer truth from a producer-supplied status; claim that references alone prove artifact authenticity |
| AgentContainment | Controller-owned action leases, runtime fencing, external containment and enforcement observations | Let a caller-created lease or agent-owned credential bypass the controller boundary |
| DProvenanceKit | Record, query, diff and verify instrumented execution-path provenance; export trace artifacts | Prove that recorded reasoning was correct or that uninstrumented events did not happen |
| ClaimProofKit | Verify material claims against supplied evidence under its versioned verifier rules; export a report and provenance trace | Prove that supplied source material is true, complete, authentic, or applicable beyond the verification policy |
| Warden | Read-only observation and operator-facing timeline of agent activity, with clearly scoped guardrail behavior | Become an authority issuer or silently claim visibility into events it did not observe |
| interleave-test | Deterministically explore/replay concurrency schedules for modeled Python code | Prove all schedules or replace integration/host testing |
| cancelscope | Cooperative cancellation and cleanup for code that reaches checkpoints or registered unblock callbacks | Replace external process termination or guarantee cancellation of uncooperative code |
| hermetic-sandbox | Restrict execution environment and ambient resources | Replace runtime epoch fencing or host-level containment verification |
| pytest-flakedoctor | Diagnose nondeterministic test failures and optionally use interleave-test | Turn a flaky test's passing rerun into proof of correctness |

## What is already present

The current WarrantKit repository has a useful foundation:

- `ExternalEvidenceReference` provides a versioned, authority-neutral reference with source, reference ID, SHA-256 digest, relation and capture time.
- `EvidenceEnvelope` v2 can carry these references, and tests cover serialization round-trips and rejection of unknown sources, relations and malformed digests.
- A cross-repository fixture names Warden, AgentContainment, DProvenanceKit and ClaimProofKit.
- WarrantKit's README explicitly says generalized automatic correlation/reconciliation and conflict objects are **not yet shipped**.
- AgentContainment remains a direct runtime dependency and the side-effect enforcement boundary.
- ClaimProofKit Python can verify a document against supplied evidence and export a DProvenanceKit-compatible trace manifest. DProvenanceKit Python has its own recording/query/diff/gate APIs.
- interleave-test and pytest-flakedoctor already have a natural role in regression testing the security invariants; cancelscope is cooperative cancellation, not hard containment.

The existing fixture is a contract/serialization fixture. Its reference IDs and digests are illustrative; it does not demonstrate that the referenced artifacts were produced by the named systems, that artifact bytes were retrieved and hashed, or that cross-system conflicts are detected. A digest reference binds bytes only when the consumer has the bytes and recomputes the digest. A source label and a self-reported status are not an independent trust anchor.

## First end-to-end proof

Build a reproducible, offline-first proof that uses real package APIs for the parts under test, and labels synthetic inputs as synthetic. The first version should not require a model API key or privileged Linux host. Keep the existing real-cgroup proof as a separate, environment-gated proof of host enforcement.

### Happy path

1. Run the existing WarrantKit framework-to-gateway proof. Record the execution ID, runtime ID, policy digest and epoch.
2. Use ClaimProofKit to verify a small document against explicit evidence passages. Preserve the complete report bytes and its DProvenanceKit-compatible trace manifest.
3. Record the verification run through DProvenanceKit's public API where supported; compare or verify the exported trace using the documented public contract. Do not claim DPK storage/verification occurred if the proof only exported a compatible manifest.
4. Collect the Warden observation artifact through an explicit, documented export path. If no stable machine-readable export exists, mark Warden as an adapter gap rather than inventing an API.
5. Create `ExternalEvidenceReference` values from the **actual artifact bytes**, recomputing each SHA-256 digest locally. Bind references to the same execution identity and runtime epoch in a versioned integration manifest.
6. Have WarrantKit validate schema, digest, execution/epoch binding, producer identity where independently available, and required-artifact policy. The result must distinguish integrity, authenticity, provenance, semantic claim verification and runtime enforcement instead of collapsing them into one `verified` boolean.
7. Emit a final envelope/receipt containing the artifact references and verification results. It must not grant or extend authority; only the authority lifecycle and controller-owned enforcement path can do that.

### Required adversarial cases

- Mutate one artifact byte without updating its reference digest: reject as tampered.
- Mutate bytes and recompute the digest: integrity alone passes, but authentication must remain unestablished unless a separately trusted signature/key or trusted acquisition path exists.
- Supply a report with `safe_to_publish=true` but invalid/missing report content: reject based on recomputed verification or validated report contract, not the boolean alone.
- Mix execution IDs, runtime IDs, policy digests or epochs across artifacts: reject the binding.
- Supply a stale-epoch artifact after containment: retain it as historical evidence but do not treat it as current authority or proof of current runtime state.
- Omit a required source: return `incomplete`, not success by vacuous agreement.
- Present conflicting observations: preserve and surface the conflict; do not silently choose the favorable source.
- Attempt to use an evidence reference to authorize an action, release containment, or advance an epoch: reject.
- Exercise interleavings around cancellation, epoch advancement, receipt creation and evidence ingestion; replay any discovered schedules deterministically.
- Run flaky integration tests under pytest-flakedoctor as a diagnostic aid, not as a substitute for deterministic assertions.

## Integration milestones

### M0 — Contract audit (current)
Inventory public APIs, artifact formats, version constraints, trust assumptions, and current CI coverage. Keep a gap list distinguishing implemented, fixture-only, documented-only and unverified behavior.

### M1 — Artifact-bound evidence references
Add a helper that reads exact artifact bytes, computes the digest, and constructs references. Add a verifier that accepts bytes and a reference and rejects digest mismatch. Avoid network retrieval and implicit trust in the first version.

### M2 — ClaimProofKit + DProvenanceKit adapter
Use the published ClaimProofKit API to generate a real report and trace. Validate stable fields and pin the verifier/spec version. Validate the DPK bridge contract; explicitly label what was exported versus stored or independently verified.

### M3 — Runtime/observation binding
Bind AgentContainment runtime evidence and Warden observation artifacts to execution identity and epoch. Require an explicit adapter contract for every source; no placeholder artifact IDs in the proof's success path.

### M4 — Reconciliation and conflict model
Add a small, deterministic reconciliation function that reports `verified`, `incomplete`, `tampered`, `untrusted` or `conflict` per artifact/binding. Do not use majority vote: evidence independence and trust roots matter more than source count. Keep this separate from authorization decisions.

### M5 — Regression and release proof
Run ordinary unit tests everywhere; use interleave-test only for code compatible with its scheduler and Python floor; use pytest-flakedoctor to diagnose instability; keep privileged cgroup proof environment-gated. Publish a single command, pinned dependency versions, expected artifacts, exact claims proved, and explicit non-claims.

## Acceptance criteria

The platform integration is ready to demonstrate when:

- the happy-path command runs offline from a clean environment with pinned optional extras;
- each referenced artifact exists and its digest is recomputed from its exact bytes;
- tests prove rejection of tampering, mixed epochs, missing required evidence, untrusted claims and authority escalation;
- a conflicting source is surfaced rather than overwritten;
- all synthetic, observed, verified, authenticated and host-verified states are labeled precisely;
- no optional evidence package becomes a mandatory WarrantKit runtime dependency;
- the docs distinguish a compatible trace export from actual DProvenanceKit ingestion or independent verification;
- the existing stale-Warrant and AgentContainment enforcement proofs continue to pass.

## Dependency policy

Keep the WarrantKit core lean. Add optional extras for cross-project adapters only after their public APIs and supported versions are tested. Pin exact versions in the reproducible proof environment, not necessarily in every user's core install. Never make ClaimProofKit, DProvenanceKit, Warden, interleave-test, cancelscope, hermetic-sandbox or pytest-flakedoctor a prerequisite for WarrantKit's basic authority checks or AgentContainment's runtime enforcement.

## Immediate next implementation task

Implement M1 first: artifact-byte hashing/verification tests around `ExternalEvidenceReference`. This turns the existing reference schema from a shape-only contract into a tested integrity binding without overclaiming authenticity. Then build the real ClaimProofKit → trace export → WarrantKit reference path on top of that invariant.
