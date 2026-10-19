# Portable Warrant Contract

Status: proposed platform contract for the WarrantKit open foundation.

## Purpose

WarrantKit needs a portable object that binds **authority, execution, enforcement, and evidence** without making any runtime implementation the universal trust anchor.

A Warrant is that object.

A Warrant does not mean that an action is safe or that an agent's intent is correct. It establishes the machine-checkable authority under which a specific execution may proceed and identifies the evidence required to determine whether that authority was respected.

## Boundary

The WarrantKit control layer owns:

- policy identity and digest;
- execution identity;
- authority scope;
- runtime epoch;
- lifecycle state;
- evidence correlation;
- verification requirements.

A runtime enforcement provider owns the security-critical enforcement operation.

Independent evidence producers own facts within their declared evidence boundaries.

A Warrant must never allow an agent to grant, extend, or restore its own authority.

## Canonical model

A portable Warrant conceptually contains:

```text
Warrant
├── warrant_id
├── schema_version
├── issuer
├── subject
│   ├── agent_id
│   └── execution_id
├── authority
│   ├── policy_id
│   ├── policy_digest
│   ├── capabilities
│   └── constraints (reserved; non-empty values unsupported in v1)
├── runtime
│   ├── runtime_id
│   └── epoch
├── validity
│   ├── issued_at
│   └── expires_at
├── lifecycle
│   ├── state
│   └── revocation
└── evidence_requirements
    ├── enforcement
    ├── observation
    └── verification
```

The exact serialized schema is an implementation task; this document establishes the boundary before adding another representation.

## Required invariants

### 1. Identity binding

A Warrant is bound to an explicit execution identity. It cannot be transparently reused by another agent or execution.

### 2. Policy binding

The Warrant references both a policy identifier and its canonical digest. A policy name alone is insufficient.

### 3. Epoch binding

Authority is scoped to a runtime epoch. Containment or recovery can advance the epoch, invalidating stale authority.

### 4. External enforcement

A Warrant authorizes a control decision; it does not constitute evidence that enforcement occurred. Enforcement evidence must come from the runtime enforcement boundary.

### 5. Explicit revocation

Revocation is an observable lifecycle transition. A revoked Warrant cannot become valid merely because an agent continues presenting it.

### 6. Recovery requires fresh authority

Recovery after containment requires a new authorized transition. Stale authority from the prior epoch cannot authorize recovery.

### 7. Evidence does not become authority

Evidence may establish that a defined procedure succeeded. Evidence cannot grant, extend, or restore execution authority.

### 8. Conflict remains visible

If independent evidence sources disagree, WarrantKit records an evidence conflict rather than silently selecting one source as universally authoritative.

### 9. Verification semantics remain bounded

**Verified != claim is true.**

Verification means that the defined verification procedure and required evidence checks succeeded within their stated scope.

### 10. Portability

The Warrant contract must remain transport- and enforcement-provider-neutral. A Warrant should be consumable by different enforcement adapters without changing its authority semantics.

## Target execution path

The canonical developer-facing path should eventually be:

```text
Define policy
    ↓
Issue Warrant
    ↓
Admit execution
    ↓
Execute under bounded authority
    ↓
Detect violation or completion
    ↓
Revoke / contain when required
    ↓
Collect independent evidence
    ↓
Verify evidence against the Warrant
    ↓
Emit portable receipt
```

The important distinction is that the Warrant is the **authority contract**, while the receipt is the **evidence artifact**.

## Why this matters

This separation gives WarrantKit a layer that can sit above multiple runtime implementations.

The product is therefore not limited to one sandbox, one kernel mechanism, or one cloud. The same authority/evidence contract can coordinate:

- AgentContainment;
- container and Kubernetes enforcement;
- sandbox runtimes;
- future cloud-native enforcement providers;
- customer-specific security controls.

That is the interoperability boundary WarrantKit should defend as the platform matures.

## Non-goals

This contract does not:

- claim formal verification;
- claim host attestation;
- make an agent trustworthy;
- reverse completed side effects;
- replace IAM, sandboxing, or runtime security;
- define a hosted control plane;
- prescribe one cryptographic custody model.

Those are separate concerns and must not be smuggled into the core Warrant semantics.

## Next implementation step

Implement the smallest typed Warrant model and verifier that enforce the invariants above, then prove the existing Policy → Admit → Contain → Verify → Receipt flow can bind to it without weakening the current security boundary.

The first implementation should be deliberately small. No hosted service, UI, database, or new runtime dependency is required for this milestone.
