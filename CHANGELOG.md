# Changelog

All notable changes to WarrantKit are documented here.

The project is currently pre-1.0. Entries describe shipped repository changes; they do not imply a production security guarantee.

## Unreleased

### Security

- Made the external authorization trust contract explicit (#207).
  `import_authorization` and `ExternalAuthorizationDecision.to_warrant` now
  document that structural validation is not source authentication and point to
  the authenticated `import_signed_authorization` profile. New tests pin that a
  structurally imported Warrant is unsigned and that adapter verification accepts
  only Warrant attestations signed by a trusted controller key.

## 0.2.0 — 2026-11-15

### Added

- Public `BoundGuardedExecution` and `GuardedExecutionDenied` APIs for trusted,
  synchronous Warrant-aware execution through a controller-owned ActionGateway.
  The binding checks the accepted admission, current runtime state, signed Warrant
  and operation capability before policy evaluation and again inside the guarded
  executor callback. Asynchronous callbacks/results are rejected.
- Experimental Ed25519 raw-JSON external-decision import with domain-separated
  signatures, pinned issuer/audience/agent/execution identity and a controller-owned
  SQLite decision-replay store. The importer returns an unsigned local Warrant;
  local signing and runtime enforcement remain separate required boundaries.
- Regression coverage for final authority rechecks and signed external-decision
  authentication, malformed inputs, identity binding and replay rejection.

### Fixed

- LangChain tools and middleware, CrewAI, OpenAI Agents and synchronous MCP wrappers
  recheck Warrant authority inside their runtime-guarded executor callbacks after
  gateway policy evaluation, closing the wrapped preflight expiry/revocation gap.
- Repair LangChain test-tool descriptions and the admission-replacement error assertion;
  run the full LangChain adapter/middleware regression files in the real-framework CI job.

### Validation and scope

- CI proof tests use DProvenanceKit 0.10.0 for attestation and real-kill evidence
  interoperability. Core dependencies remain `agentcontainment>=0.1.3,<0.2` and the
  production AgentContainment submodule remains pinned to
  `9738c772aff900eb0ce5f1f9d93760d2f9e5de4f`.
- The signed external-decision profile remains experimental and opt-in. It is not
  OIDC/OAuth/JWT support, distributed replay protection, a protected anti-rollback
  anchor, or production-certified IAM. Operators provision trusted keys and protect
  the persistent replay database independently of the submitted decision.
- Guarded execution protects operations actually routed through the trusted gateway.
  It does not establish hostile-code isolation, cancel accepted remote requests,
  reverse completed effects or eliminate alternate credential paths.
- PR #248's newer-runtime in-flight/downstream enforcement references are excluded.
  No newer runtime promotion or distributed enforcement claim is made by this release.
- Release publication verifies the GitHub tag against the package version before
  building. See [the release procedure](docs/RELEASE_0.2.0.md) for proof and artifact gates.

## 0.1.6 — 2026-10-31

### Added

- Add a CrewAI adapter regression suite and deterministic framework authority-boundary proof.
- Expand the Linux cgroup-v2 integration workflow to generate and independently verify operator-facing real-kill evidence, authenticated incident bundles, DProvenanceKit attestations, and signed cross-artifact bindings.
- Add a hostile-agent eBPF containment proof covering controller isolation, delegated cgroup enforcement, post-containment egress, and stale execution-lease fencing.
- Add a TOCTOU regression reproducer against the pre-fix baseline.

### Changed

- Require AgentContainment 0.1.3 or later (within the 0.x compatibility line) for the updated runtime integration.
- Tighten package discovery and publish the project-facing `warrantkit` CLI while retaining the `agentcontain` compatibility alias.

- Clarify the enforcement-engine adapter contract, including the retained containment report used to create authenticated receipts.
- Add repository and issue links to package metadata.
- Restrict setuptools package discovery to the `agentcontain*` namespace.

## 0.1.0

Initial platform release line, including:

- local policy admission and execution identity;
- runtime containment adapter for AgentContainment;
- structured execution evidence and authenticated receipt integration;
- fleet governance primitives;
- operator and evidence-inspection tooling;
- no-root simulated demonstration path;
- privileged Linux integration proof for real cgroup-v2 containment.
