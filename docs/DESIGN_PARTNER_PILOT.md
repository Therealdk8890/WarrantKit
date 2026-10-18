# WarrantKit Design-Partner Pilot

## Objective

Validate whether organizations operating autonomous agents will pay for runtime enforcement, incident containment, and independently verifiable execution evidence.

The pilot is intentionally narrow. It should prove customer value before expanding the product surface.

## Product and enforcement boundary

WarrantKit is the authority-lifecycle and evidence layer. AgentContainment is the separate runtime enforcement engine used for the security-critical gateway and host-containment paths. The pilot must test the actual boundary in the selected deployment, not treat a signed Warrant or evidence receipt as enforcement by itself.

The pilot must also document any route that can bypass the gateway. If an agent or tool can reach a protected service directly with unrestricted credentials, the gateway is advisory for that route. Keep real downstream credentials outside the agent process wherever practical.

## Pilot promise

For one consequential autonomous workflow, WarrantKit will coordinate the authority lifecycle and evidence, using the AgentContainment engine for the security-critical runtime enforcement path:

1. establish execution identity
2. define the authorized boundary
3. observe normal execution
4. exercise selected unauthorized/adversarial actions
5. deny or contain violations
6. invalidate stale execution authority
7. independently verify enforcement
8. preserve an evidence timeline
9. produce an authenticated receipt
10. recover the workload under fresh authority

The pilot does **not** promise regulatory compliance, universal host security, or that every possible agent escape path is prevented.

## Candidate workflows

Prioritize workflows with meaningful consequences if an agent crosses its boundary:

- production infrastructure changes
- deployment automation
- privileged repository operations
- access to sensitive APIs
- financial or transactional workflows
- cloud resource management
- autonomous security operations

Choose one workflow for the first pilot.

## Success criteria

### Security

- unauthorized actions are denied or contained according to the agreed policy
- containment occurs within a measured target
- stale execution/credential authority cannot be reused
- recovery requires fresh authority
- privileged enforcement behavior is independently verified where the environment supports it

### Evidence

- every tested execution has a stable execution identity
- lifecycle events are ordered and identity-bound
- detection and verification remain distinct
- evidence can be exported
- receipts can be verified offline
- evidence explicitly states what was and was not proven

### Operations

Measure:

- installation time
- integration effort
- operator actions per incident
- containment latency
- recovery time
- false-positive rate
- evidence review time

### Commercial

At the end of the pilot, determine:

- who owns the problem
- who would approve budget
- which workflow is valuable enough to protect
- which integrations are mandatory
- what deployment/support requirements exist
- what recurring operational value the platform provides
- what would block production purchase

Do not manufacture ROI. Establish the baseline and calculate value from customer-confirmed inputs.

## Proof selection and prerequisites

Select the smallest proof that answers the customer's question and state its limits before the session:

1. **Portable lifecycle demo** (`warrantkit demo`): orientation only; it is simulated and does not establish kernel process termination.
2. **Framework-to-gateway proof** (`python tools/run_authority_boundary_demo.py`): demonstrates a protected tool side effect before containment and rejection of a retained pre-containment Warrant before the next side effect. It does not prove host-level process termination or protect bypass routes.
3. **Linux cgroup-v2 real-kill proof**: use [the real-kill guide](REAL_KILL_DEMO.md) on a compatible Linux host with root or equivalent delegated cgroup privileges. Record the exact commit, host prerequisites, output, and artifacts.
4. **Raw MCP handler proof**: use [the MCP integration guide](MCP_SERVER_INTEGRATION.md) only for synchronous Python handlers registered through the wrapped function. It does not cover remote/hosted MCP tools or async-native handlers.

Never represent a simulated result as a host-enforcement result. Keep customer secrets and production credentials out of the test. A successful proof is evidence for the tested configuration, not a universal host-isolation guarantee.

## Pilot phases

### Phase 1 — Boundary definition

Document:

- agent
- owner
- runtime
- authorized capabilities
- sensitive resources
- credentials
- network destinations
- containment response
- recovery authority

### Phase 2 — Baseline

Run the workflow normally.

Capture:

- execution volume
- normal actions
- latency
- existing controls
- existing incident workflow
- current evidence available to operators

### Phase 3 — Adversarial exercise

Exercise a small agreed set of boundary violations.

Examples:

- unauthorized credential use
- unauthorized egress
- prohibited process/action
- stale execution authority
- post-containment execution attempt

### Phase 4 — Containment and proof

Demonstrate:

**Detect → Deny/Contain → Fence → Halt → Verify → Receipt**

Review the resulting evidence with the security/operator team.

### Phase 5 — Recovery

Demonstrate:

**Review → Release external enforcement → Verify release → Fresh authority → Resume**

Failure during recovery must leave the workload contained.

### Phase 6 — Production decision

Document:

- validated value
- remaining gaps
- required integrations
- deployment model
- support requirements
- proposed production scope
- commercial terms to explore

## Buyer interview questions

Use these before expanding the pilot:

1. Which autonomous workflows are currently too risky to run without additional controls?
2. What happens today when an agent violates policy?
3. Who owns that incident?
4. What evidence do they have afterward?
5. What evidence do auditors or security leadership ask for?
6. Which existing security product should WarrantKit integrate with rather than replace?
7. What deployment boundary is acceptable?
8. What latency or availability requirements exist?
9. What would make this a production requirement rather than an interesting security experiment?
10. What budget owns the problem?

## Evidence package

The pilot should produce a concise package containing:

- architecture diagram
- policy definition
- test scenarios
- execution identities
- incident timelines
- enforcement results
- verification results
- authenticated receipts
- measured latency
- integration/deployment findings
- open security limitations
- production recommendations

The customer should be able to inspect the evidence without trusting marketing claims.

## Commercial exit criteria

A successful technical pilot is not automatically a successful commercial pilot.

The strongest signal is a customer-confirmed production problem with:

- a named owner
- a defined deployment scope
- required integrations identified
- measurable operational value
- a production timeline
- willingness to discuss paid deployment/support

If those conditions are absent, treat the result as product research rather than a sales win.
