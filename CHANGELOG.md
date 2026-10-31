# Changelog

All notable changes to WarrantKit are documented here.

The project is currently pre-1.0. Entries describe shipped repository changes; they do not imply a production security guarantee.

## Unreleased

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
