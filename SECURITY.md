# Security Policy

## Security boundary

WarrantKit is a runtime security platform for autonomous AI agents with two tightly coupled responsibilities: **enforcing the agent's authority boundary** and **producing independently derived evidence that establishes what happened**.

The enforcement model is explicit:

1. Establish the agent's identity, policy, execution identity, and authority scope.
2. Enforce that authority outside the agent trust boundary.
3. When an action violates policy or authority conditions, deny it and, when required, revoke the associated authority or credential/capability use.
4. Halt or contain the workload through the runtime enforcement layer.
5. Prevent stale authority from surviving an epoch transition or recovery boundary.
6. Require fresh authorization before recovery.
7. Correlate independent evidence to determine whether the security boundary actually held.

The core evidence architecture uses independently derived evidence from:

- **Warden** — observation at its defined boundary.
- **DProvenanceKit** — execution/reasoning provenance and integrity evidence.
- **ClaimProofKit** — verification of supplied claim/evidence pairs under its defined verifier.
- **AgentContainment** — runtime enforcement and host/provider verification evidence.

WarrantKit correlates these facts by execution identity, policy identity, epoch, and evidence integrity. It does not treat one subsystem as a universal authority over the facts. Agreement is corroboration; disagreement must remain distinguishable as an evidence conflict.

The agent is never trusted to enforce its own security boundary.

## Authority revocation and containment

Authority is treated as a lifecycle, not a static permission attached to an agent.

WarrantKit is designed to make policy violations operationally consequential:

- unauthorized actions can be denied;
- stale or violated execution authority can be invalidated;
- associated credential/secret or capability use can be revoked or rendered invalid;
- workloads can be halted or contained through the AgentContainment runtime;
- recovery is gated on the required verification and a fresh authority epoch.

The purpose is not merely to record that an agent violated policy. The security boundary must prevent the agent from continuing to operate with authority it no longer satisfies the conditions to hold.

The evidence architecture is separate from this enforcement boundary. It does not grant runtime authority and cannot be used to override a containment decision.

## What the project does not claim

A passing test, verified evidence envelope, or authenticated receipt is not by itself:

- a universal security guarantee;
- formal verification of the implementation or host;
- proof that an arbitrary external claim is true;
- non-repudiable host attestation.

Current receipts use HMAC authentication. This provides integrity and shared-secret authentication within the configured trust domain; it is not a non-repudiable attestation mechanism.

Privileged Linux integration tests exercise the tested kernel, cgroup, network, and privilege environment. Results from those tests should be interpreted within that environment.

## Runtime enforcement

The security-critical runtime enforcement engine is **AgentContainment**, pinned as a Git submodule. WarrantKit's authorization and lifecycle controls drive that enforcement boundary; the platform's evidence layer does not replace it.

External evidence integrations must not be used to:

- authorize execution;
- weaken policy;
- release containment;
- extend an authority epoch;
- restore revoked credentials or secrets;
- mark unverified runtime enforcement as verified.

Evidence integrations may add context or independently verifiable references, but they cannot override enforcement or resurrect authority that has been revoked.

## Supported environments

Host-level containment proof currently depends on Linux, cgroup v2, and the privileges/delegation required by the selected enforcement provider. Provider-specific behavior can depend on the host kernel, cgroup configuration, network stack, and deployment environment.

The no-root demonstration is intentionally simulated and must not be interpreted as kernel-level containment proof.

## Reporting a vulnerability

Please do not disclose suspected vulnerabilities in public issues, pull requests, or discussions.

Use GitHub's private vulnerability reporting feature from this repository's **Security** tab if it is available. If private reporting is not enabled, contact the repository maintainer through their GitHub profile to arrange a private report.

Include, where practical:

- affected commit, release, or component;
- a concise description of the security impact;
- reproduction steps or a minimal proof of concept;
- relevant logs or test output;
- any suggested mitigation.

Please avoid including credentials, private keys, personal data, or unrelated sensitive information in the report.

We will acknowledge reports as promptly as practical, investigate the reported behavior, and coordinate disclosure based on severity and affected users.

## Scope

Security reports are especially relevant to:

- authorization/admission boundaries;
- authority and credential/secret revocation;
- runtime containment and fencing;
- epoch and stale-authority invalidation;
- recovery and fail-closed behavior;
- evidence integrity and identity binding;
- privileged host enforcement integrations;
- cross-component evidence handling that could incorrectly turn evidence into runtime authority.

Issues that affect only documentation, test flakiness, or unsupported environments may be handled through the normal issue tracker unless they expose a security consequence.
