# WarrantKit and NobodySystems: evaluation and commercial boundary

## Independent components and buyer-visible separation

| Product | Role | Current evaluation target | Limitation |
|---|---|---|---|
| **WarrantKit** (this Apache-2.0 repository) | **Authority** | Signed, runtime/epoch-scoped Warrants; deny-before-side-effect through a framework adapter and controller-owned gateway | Cannot stop direct, unwrapped external side effects or prove kernel isolation by Warrant validation alone |
| [AgentContainment](https://github.com/Therealdk8890/AgentContainment) (Apache-2.0) | **Enforcement** | Controller-issued execution leases; privileged Linux cgroup-v2/eBPF host proofs | Host/kernel/environment dependent, not universal sandboxing |
| [DProvenanceKit](https://github.com/Therealdk8890/DProvenanceKit) (Apache-2.0) | **Evidence** | Instrumented trace capture, regression gates, signed artifacts and offline verification | Evidence integrity is not authorization and does not make assertions true |
| **NobodySystems** (proprietary, private alpha) | **Operations** | Bounded local-controller guarded workflows, operator interfaces, evidence-bundle verification using pinned keys | Not a delivered production fleet, hosted service, arbitrary hostile-agent sandbox, or contracted enterprise SLA |

NobodySystems is the **operational/control-plane layer for teams**. Its intended commercial scope includes organizational policy lifecycle/distribution, cross-engine and cross-run evidence correlation, fleet inventory/operations, enterprise access controls, deployment support and guarantees. These are **planned**, with specific implementation and external validation needed before they can be sold as production commitments. A separate `WarrantKit-Commercial` tenant-ingestion proof of concept is **not** the same thing as a released NobodySystems enterprise edition.

## Run the public WarrantKit authority proof

```bash
git clone --recurse-submodules https://github.com/Therealdk8890/WarrantKit.git
cd WarrantKit
python -m pip install ".[langchain]"
python tools/run_authority_boundary_demo.py
```

Use Python 3.11+. The deterministic demo uses a real LangChain tool without a live LLM or service credentials. Verify the first guarded side effect succeeds, then containment changes the runtime epoch; the retained Warrant must be rejected **before** the second protected side effect. Inspect the demo output and process exit status. See [getting started](GETTING_STARTED.md) and [integration/proof scope](INTEGRATIONS_AND_PROOFS.md).

**Separate host proof:** for a real Linux process-kill and cgroup-empty assertion, use the environment-gated [cgroup-v2 real-kill guide](REAL_KILL_DEMO.md) on an isolated host with suitable privileges. Do not describe the portable lifecycle or framework proof as kernel containment. Preserve exact Git commit, kernel/cgroup configuration, selected test IDs, receipt, verification verdict, and trusted public-key provenance.

## Security and purchasing checklist

1. **Threat model:** enumerate side-effect destinations and any direct credentials that bypass ActionGateway. An agent with an unrestricted downstream credential can evade WarrantKit's wrapped path.
2. **Authority:** distinguish Warrant signature, expiry, capability scope, epoch checks, per-Warrant revocation, and the gateway's separately controller-issued `ExecutionLease`. They are not interchangeable.
3. **Evidence:** verify producer signatures against an independently provisioned trust anchor. HMAC runtime receipts are shared-secret authentication, not asymmetric non-repudiation. Integrity/verification does not prove kernel or external claims.
4. **Environment:** demonstrate process termination and post-containment egress only on the configured Linux host; note failed or untested paths explicitly.
5. **Operations:** for a NobodySystems evaluation, request the pinned alpha revisions, supported fixed-workload threat model, verifier procedure, unresolved security gaps, explicit release gates and written pilot scope. Do not infer production readiness from the private alpha.

## Open-source and commercial rights

- WarrantKit's documented open-source engine is Apache-2.0 and remains independently runnable; no NobodySystems account or license is needed for its public local verification.
- NobodySystems is separately licensed private-alpha orchestration, not a relicense of OSS functionality. A management-plane outage must not cause previously invalidated authority to become valid or make local containment depend on SaaS connectivity.
- The source is access-controlled; a public GitHub link to its private repository would not be an open trial. [Request a controlled NobodySystems evaluation](mailto:danielpaulkissel@gmail.com?subject=NobodySystems%20private-alpha%20evaluation) and receive scope/access terms before review.

Review [security overview](SECURITY_OVERVIEW.md), [external proof package](EXTERNAL_PROOF_PACKAGE.md), [trust anchor procedures](INCIDENT_TRUST_ANCHOR_OPERATIONS.md), and [design-partner validation](DESIGN_PARTNER_VALIDATION.md).
