# WarrantKit Threat Model

Status: current platform threat model for the open foundation.

## Assets and trust boundaries

The security-critical assets are:

- execution authority;
- policy and execution identity;
- credential/capability authority;
- runtime containment state;
- recovery authority;
- evidence integrity and correlation.

The agent is **untrusted**. WarrantKit must not rely on the agent to enforce its own authorization, revoke its own authority, release its own containment, or preserve its own evidence.

The security-critical runtime enforcement boundary is delegated to AgentContainment. WarrantKit coordinates authorization and lifecycle state around that enforcement boundary; it is not a replacement for host/kernel enforcement.

## Primary threats

The model covers an autonomous or compromised agent attempting to:

1. execute outside its granted policy;
2. continue using authority after containment;
3. mint replacement authority while contained;
4. reuse authority from an earlier execution epoch;
5. cross the controller/workload boundary;
6. bypass application-level egress controls;
7. interfere with recovery or reuse stale recovery authority;
8. falsify, reorder, or silently remove evidence.

## Security responses

The intended security loop is:

**Authorize → Enforce → Detect → Revoke → Halt/Contain → Verify → Recover under fresh authority → Prove**

The key invariant is:

> **An autonomous agent cannot retain authority after it has violated the conditions under which that authority was granted.**

Authority is therefore scoped to execution identity and epoch. Containment advances the runtime epoch and invalidates stale authority. Recovery requires controller-owned authorization and establishes a fresh epoch.

## Constraint semantics are not implemented

WarrantKit v1 does not define an enforced schema for action-argument or resource constraints. The serialized Warrant model retains a string-to-string `constraints` field, but non-empty constraints are rejected by `Warrant.issue()` and by `verify_warrant()`. This is deliberate fail-closed behavior, not partial constraint enforcement. Integrations must not treat a signed Warrant containing a constraint such as `max_amount=100` as limiting the corresponding action argument. Capability authorization and argument/resource constraint enforcement are separate controls; constraint semantics require a versioned schema and enforcement before every protected side effect.


## Independent evidence

Warden, DProvenanceKit, ClaimProofKit, and AgentContainment have distinct evidence boundaries. They are not a hierarchy of truth or authority.

WarrantKit correlates their independently produced facts by execution identity, policy identity, epoch, and evidence integrity.

- agreement is corroboration;
- disagreement is an explicit evidence conflict;
- evidence does not itself authorize execution.

## Non-goals

WarrantKit does not currently claim:

- universal host or kernel isolation across all Linux configurations;
- reversal of side effects that already escaped the enforcement boundary;
- automatic revocation of arbitrary third-party cloud/API credentials;
- formal verification of the complete implementation;
- non-repudiable host attestation from the current HMAC receipts;
- a hosted multi-tenant control plane or centralized authority in the open repository.

## Controller isolation boundary

Controller isolation remains deployment-sensitive.

The repository contains tests for selected controller/agent IPC and host attack paths, and AgentContainment has privileged Linux proofs for controller survivability and delegated containment. Those tests establish evidence for the tested environment; they do not make the Python controller a kernel isolation boundary.

A deployment must still protect:

- the controller process and its host privileges;
- the Unix-domain control endpoint and peer-credential policy;
- the cgroup hierarchy and delegation;
- the host/kernel configuration used for enforcement;
- controller-owned evidence and recovery credentials.

An attacker with broader host privileges than the modeled threat can invalidate assumptions that the application-level controller depends on.

## Evidence limits

A passing test or authenticated receipt proves only the defined procedure and tested environment.

**Verified ≠ claim is true.**

The lower-level host-boundary assumptions and privileged proof scope are documented in AgentContainment's `docs/SECURITY_CONTRACT.md`.
