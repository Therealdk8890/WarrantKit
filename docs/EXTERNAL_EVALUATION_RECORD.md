# WarrantKit External Evaluation Record

Use one copy of this worksheet per evaluation run. It is a record of observations, not a certification. Complete it from the evaluator's own run and retain the source revision, logs, verifier output, and sanitized evidence artifacts alongside it.

Do not include secrets, production credentials, customer data, or sensitive incident artifacts. Mark a check **Not run** rather than inferring success from documentation or another machine's CI result.

## 1. Evaluation metadata

- Evaluator / organization:
- Evaluation date (UTC):
- Evaluation owner / role:
- WarrantKit repository and exact commit:
- AgentContainment repository and exact commit or package version:
- Evaluation environment (local, VM, CI, staging):
- OS and version:
- Kernel version (for Linux proof):
- Python version:
- cgroup version and mount status (for Linux proof):
- Privilege / cgroup delegation model:
- Relevant CI run or artifact URL:
- Evidence storage location (no secrets):

## 2. Scope and threat scenario

- Agent framework / integration:
- Agent task and tools under evaluation:
- Protected side effect being tested:
- Runtime event expected to invalidate authority:
- Threat scenario and attacker capabilities:
- Expected security outcome:
- Out-of-scope claims:
- Known alternate routes or direct credentials that bypass the gateway:

**Boundary check:** Can the agent reach the protected downstream operation without passing through the enforcement gateway?

- [ ] No known bypass path in this test scope
- [ ] A bypass path exists; describe it below
- [ ] Not assessed

Details:

## 3. Select the proof and record its result

Use the narrowest proof that tests the claim under review. Do not treat one proof as evidence for a different layer.

### A. Framework-to-gateway authority-boundary proof

Command, from the repository root:

```bash
python tools/run_authority_boundary_demo.py
```

- Result: **Not run / Pass / Fail / Inconclusive**
- Exact command and exit code:
- Observed allowed pre-containment side effect:
- Observed rejection of retained pre-containment Warrant:
- Evidence that the second protected side effect did not occur:
- Output/log location:
- Deviations or unexpected behavior:

**Pass criteria:** the proof demonstrates the intended first protected side effect and then rejects the retained pre-containment Warrant before the second protected side effect. A successful run does not establish kernel process termination, universal host isolation, or protection for paths that bypass the gateway.

### B. Linux cgroup-v2 host-enforcement proof

Use only on a compatible Linux environment with cgroup v2 and root or equivalent cgroup delegation. Follow [Real-Kill Demo](REAL_KILL_DEMO.md) for the maintained prerequisites and command sequence.

- Result: **Not run / Pass / Fail / Inconclusive**
- Exact command and exit code:
- WarrantKit commit:
- AgentContainment revision:
- OS / kernel:
- cgroup-v2 confirmed:
- Workload membership and identity checked:
- Workload terminal state observed:
- cgroup population observed empty:
- Stale pre-containment authority rejected:
- Runtime-evidence verifier output:
- Incident-bundle verifier output:
- Evidence bundle location / checksum:
- Output/log location:
- Deviations or unexpected behavior:

**Pass criteria:** the run verifies the real workload's expected cgroup membership and terminal state, confirms the cgroup is empty, rejects stale authority, and successfully verifies the exported evidence. If any required observation is missing, report **Fail** or **Inconclusive** with the reason; do not infer success from a printed summary alone.

Do not run this proof on native Windows or assume that a portable lifecycle demo is a substitute for kernel-level process containment.

## 4. Evidence authenticity and trust

- Bundle verification result: **Not run / INTEGRITY_ONLY / AUTHENTICATED / Fail**
- Verifier version / source commit:
- Was a trusted public key supplied independently of the bundle? **Yes / No**
- Public-key provenance (where obtained; do not record private keys):
- Was the key scoped to the exact artifact/run being verified? **Yes / No / N/A**
- Signature / integrity output:
- Evidence and verifier output preserved together? **Yes / No**

Interpretation:

- **INTEGRITY_ONLY** indicates internal consistency and integrity checks; it does not authenticate the producer.
- **AUTHENTICATED** means the signature verifies against the public key supplied to the verifier. It authenticates the producer only to the extent that the key's identity and custody are independently trusted.
- A CI run's ephemeral public key is scoped to that run's artifact. It is not a permanent production identity, independent host attestation, or proof that every underlying claim is true.
- Neither a signed receipt nor an evidence bundle proves universal host security or reverses side effects that occurred before containment.

## 5. Observations and failures

| Check | Status (Pass / Fail / Not run / Inconclusive) | Evidence reference | Notes |
|---|---|---|---|
| Setup prerequisites met | | | |
| Correct runtime / workload identity bound | | | |
| Protected action before containment behaved as expected | | | |
| Runtime state transition / containment event observed | | | |
| Stale authority rejected after transition | | | |
| Host process/cgroup terminal state verified (Linux proof only) | | | |
| Evidence verifier passed | | | |
| Trusted-key provenance assessed | | | |
| Gateway bypass paths assessed | | | |
| Cleanup completed safely | | | |

### Unexpected behavior / failure details

For each failure or inconclusive result, record the command, expected outcome, actual outcome, minimal sanitized logs, and whether it was reproducible. Do not silently rerun until a pass and omit the initial failure.

- Observation:
- Reproduction steps:
- Expected vs. actual:
- Sanitized evidence reference:
- Impact / severity:
- Follow-up owner:

## 6. Operational fit

- Integration effort and time:
- Required privileges / deployment changes:
- Runtime and framework compatibility:
- Latency or throughput measurements (include method and sample size):
- Reliability / cleanup behavior:
- Evidence retention and review requirements:
- Operator burden, failure recovery, and rollback:
- Missing controls or bypasses:
- Required changes before a pilot:

Do not report performance or reliability conclusions without recording the method, environment, and sample size. Separate measured results from estimates or impressions.

## 7. Evaluation conclusion

- Overall disposition: **Proceed to next evaluation / Proceed with conditions / Re-test required / Do not proceed / Insufficient evidence**
- Claims directly demonstrated:
- Claims not demonstrated:
- Open security questions:
- Required remediations:
- Owner and target date for each remediation:
- Next commitment (sanitized workload, technical review, pilot, introduction, budget discussion, or none):
- Evaluator's summary:

## 8. Reproducibility packet

Attach or link, using a location accessible to the evaluator's intended reviewers:

- [ ] Exact source revisions and dependency versions
- [ ] Environment details sufficient to reproduce the run
- [ ] Exact commands and exit codes
- [ ] Raw sanitized logs / stdout / stderr
- [ ] Runtime evidence and incident bundle, where applicable
- [ ] Verifier output
- [ ] Trusted public-key provenance (never private key material)
- [ ] Checksums for retained artifacts
- [ ] Failures and deviations, including unsuccessful attempts

## Claim boundary

This worksheet records results for the tested revision, configuration, and environment. A successful evaluation does not establish universal isolation, resistance to a compromised host or kernel, policy correctness, coverage of untested integrations or bypass routes, or reversal of completed side effects. WarrantKit coordinates authority lifecycle and evidence; AgentContainment performs runtime enforcement.
