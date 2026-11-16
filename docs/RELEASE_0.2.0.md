# WarrantKit 0.2.0 release record and procedure

Version: **0.2.0**. GitHub tag: `v0.2.0`. Python requirement: **3.11+**.
The source version and installation example identify the intended artifact; the
GitHub Release, successful publication workflow and PyPI artifact establish publication.

## Scope

- Public synchronous `BoundGuardedExecution`, including a final signed-authority and
  operation-capability recheck after gateway policy evaluation.
- The same final authority recheck across LangChain tools/middleware, CrewAI, OpenAI
  Agents and synchronous MCP wrappers.
- Experimental domain-separated Ed25519 external-decision authentication and a trusted
  local SQLite replay store; see [the profile](SIGNED_EXTERNAL_AUTHORIZATION_PROFILE.md).
- DProvenanceKit **0.10.0** attestation and real-kill evidence interoperability checks.

The AgentContainment requirement remains `>=0.1.3,<0.2`; the production submodule is
still `9738c772aff900eb0ce5f1f9d93760d2f9e5de4f`. PR #248 is excluded, including its
newer-runtime in-flight tests and experimental downstream/outbox/recovery references.
Publishing this version does not promote those runtime or distributed-enforcement claims.

The external-decision profile is an opt-in local reference, not OIDC/OAuth/JWT, arbitrary
identity-provider support or distributed replay/rollback protection. The returned Warrant
is unsigned until the trusted local signing path signs it. Guarded execution covers only
operations routed through the trusted gateway and cannot undo completed side effects,
cancel an accepted remote request or protect a bypass using unrestricted credentials.

## Validation before publication

Use the pinned AgentContainment checkout and DProvenanceKit 0.10.0:

```bash
git submodule update --init --recursive
python -m pip install -e ./AgentContainment
python -m pip install -e ".[test,langchain,mcp]"
python -m pip install "dprovenancekit[crypto]==0.10.0"
python -m pytest -q tests -m "not integration"
python tools/verify_runtime_evidence.py tests/fixtures/runtime_pinned_evidence.json
python tools/run_authority_boundary_demo.py
python tools/benchmark_gateway_overhead.py --calls 100 --warmup 5 --concurrency 1,2
python -m build
python -m twine check dist/*
```

The unit CI also installs the immutable `interleave-test` and ClaimProofKit test
dependencies listed in `.github/workflows/ci.yml`. CrewAI runs in a separate dependency
environment. Record optional skips instead of counting them as passing integrations.

Require all eight configured CI jobs, including the privileged Linux cgroup-v2
real-kill/evidence proof, AgentContainment eBPF hostile-agent proof, framework boundary,
CrewAI regression suite and pre-fix TOCTOU reproducer. Those privileged results must
come from a suitable Linux host; portable unit tests do not establish kernel enforcement.

Build the wheel from the sdist, validate both metadata files, then install the wheel
outside the checkout in a fresh environment. Confirm version 0.2.0, public guarded and
signed-import APIs, both CLI aliases, the no-root demo and installed adapter tests.

## Publication

1. Review the release diff, CI and DCO at the final candidate SHA; merge only that head.
2. Require the final main-commit CI to pass and confirm `v0.2.0` does not already exist.
3. Create `v0.2.0` and publish its GitHub Release from the validated main SHA.
4. Require the publish workflow's tag/version gate, build/metadata checks, installed-wheel
   adapter tests and Trusted Publishing upload to succeed.
5. Install exactly `warrantkit[langchain,openai-agents]==0.2.0` from PyPI in a fresh
   environment outside the checkout. Verify public APIs, both CLI aliases and the
   deterministic authority-boundary proof; confirm the published-package smoke job.
6. Record the immutable source SHA, release URL, publication run and observed proof
   results. Never move a published tag or reuse a failed/published package version.

Current evidence establishes behavior in the tested environments, not universal
hostile-code isolation or a production security certification.
