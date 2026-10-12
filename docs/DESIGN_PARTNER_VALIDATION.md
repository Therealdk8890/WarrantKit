# WarrantKit Design-Partner Validation

**Purpose:** validate whether WarrantKit solves a costly, current runtime-security problem for teams operating autonomous or coding agents. This is a discovery program, not a sales forecast and not a commitment to build requested features.

## Decision to answer

Do teams with real agent workloads need an independently enforced authority lifecycle that invalidates retained authority after runtime state changes—and will they invest engineering time, deployment access, or budget to adopt it?

The core hypothesis is specific: when an agent must be contained, the operator needs more than a model instruction, application callback, or sandbox boundary. They need an external enforcement path, stale-authority rejection, and evidence that distinguishes what was observed from what was verified.

## Target participants

Start with **5–10 interviews**. Prioritize people who own or operate agent execution in staging or production:

- Platform security and product security engineers responsible for agent runtimes.
- AI infrastructure / developer-platform leads running coding agents or tool-using agents.
- Security engineering or incident-response leads who would investigate an agent incident.
- Technical founders or engineering leaders at teams deploying agents with meaningful tool/API access.

Prefer participants with a workload already running or scheduled to launch within six months. Avoid counting general interest in AI safety as evidence of buyer demand. Seek a mix of technical evaluators and budget/process owners.

## Qualification

A conversation qualifies as a design-partner interview when the participant can describe a concrete workload, its trust boundaries, and its current failure/containment path.

Record these fields:

| Field | Capture |
|---|---|
| Workload | Agent framework, task, tools, environment, deployment stage |
| Blast radius | Data, credentials, APIs, code, or infrastructure the agent can affect |
| Current controls | Sandbox, IAM, short-lived credentials, gateway, policy engine, process controls |
| Failure path | What actually happens when the agent behaves unexpectedly |
| Evidence | Artifacts retained, verifier used, incident-review requirements |
| Adoption owner | Technical owner, security approver, procurement/budget owner |
| Deployment friction | Privilege, kernel/runtime constraints, latency, integration effort, operations |
| Urgency | Recent incident, near miss, audit requirement, launch blocker, or hypothetical concern |
| Next commitment | Technical review, proof run, test environment, introduction, budget discussion, or none |

Do not collect secrets, customer data, production credentials, or sensitive incident artifacts during discovery.

## Interview guide (30 minutes)

Ask about past and current behavior before presenting WarrantKit. Do not lead with the proposed solution.

### 1. Workload and stakes

1. What agent or coding-agent workload is actually running today? If none, what is scheduled and when?
2. Which tools, credentials, repositories, APIs, or infrastructure can it reach?
3. What is the worst credible failure mode, and what would that cost operationally?
4. Can the agent reach a protected downstream service without passing through the controls you described?

### 2. Current containment behavior

5. Tell me about the last time an agent had to be stopped, restricted, or rolled back. What triggered it?
6. What action stopped it: model instruction, task cancellation, process kill, credential revocation, network isolation, or another mechanism?
7. How did you establish that execution had actually stopped and could not continue using retained authority?
8. What can still happen after containment begins—queued work, retries, existing sessions, cached credentials, or in-flight API calls?
9. What evidence was available afterward, and what was missing or difficult to trust?

If no incident or near miss exists, ask them to walk through their actual runbook or tabletop exercise; record this as simulated rather than observed experience.

### 3. Requirements and alternatives

10. Which existing controls already solve this problem well? Where, specifically, do they fall short?
11. Would runtime-epoch fencing be useful in this environment? What legitimate work could it interrupt, and how would fresh authority be issued?
12. What evidence would your security reviewer require: logs, a signed receipt, an independently supplied trust anchor, host-level proof, or something else?
13. What is the minimum proof you would need before running this against a representative workload?
14. What deployment requirements are non-negotiable (OS, cgroup-v2, privileges/delegation, framework, latency, control-plane isolation)?

### 4. Adoption and commercial value

15. Who would own installation and ongoing operations? Who can approve it for production?
16. What would prevent adoption even if the proof worked—security review, privilege model, integration effort, performance, reliability, or competing priorities?
17. Is this an urgent project with a timeline, or a general concern? What initiative or budget would it compete with?
18. What concrete next step would you be willing to take: provide a sanitized workload, attend a technical review, run a proof, introduce the owner, or discuss a paid pilot?

Only after these questions, give a short explanation of WarrantKit's authority/epoch invariant and offer the narrowest relevant demo. Do not claim universal host isolation, reversal of completed side effects, or that a signed receipt proves every underlying claim.

## Demonstration path

Choose the lowest proof level that answers the participant's question:

1. **Portable proof:** `warrantkit demo` — stale authority is rejected after the runtime epoch changes; no host process-kill claim.
2. **Framework boundary proof:** `python tools/run_authority_boundary_demo.py` — protected framework tool call before containment, rejected call afterward before the second side effect.
3. **Linux host-enforcement proof:** follow [Real-Kill Demo](REAL_KILL_DEMO.md) on a compatible Linux cgroup-v2 host with root or equivalent delegation.

State prerequisites before the session. Do not present a simulated proof as a production workload. Record exact commit, environment, observed output, failures, and participant interpretation. Never request production credentials.

## Evidence and scoring

Score each dimension from **0–2** and record a quote or observed fact supporting every nonzero score.

| Dimension | 0 | 1 | 2 |
|---|---|---|---|
| Workload reality | Hypothetical | Planned within six months | Running in staging/production |
| Blast radius | Low/unclear | Meaningful but bounded | Sensitive tools, data, code, or infrastructure |
| Current control gap | No concrete gap | Friction or untested assumption | Demonstrated gap in stop/fence/evidence path |
| Urgency | No timeline | General roadmap concern | Incident, near miss, launch blocker, or mandated control |
| Technical fit | Incompatible / redundant | Potential fit with major unknowns | Clear fit and feasible representative proof |
| Adoption commitment | No next step | Follow-up discussion | Offers workload, test environment, owner introduction, or pilot path |
| Buying path | No owner or budget path | Owner identified, funding unclear | Buyer/process and plausible budget identified |

Maximum: 14. Use the score to compare evidence, not to automate a decision.

- **11–14:** strong candidate for a technical design-partner proof, provided workload reality and adoption commitment are both 2.
- **7–10:** continue discovery; identify the one assumption that needs validation.
- **0–6:** do not prioritize near-term implementation for this participant.

A high score cannot compensate for no real workload. Track technical champions separately from budget owners; one person may not fill both roles.

## Success criteria for the initial cohort

After 5–10 qualified interviews, summarize:

- Number with running workloads versus planned/hypothetical interest.
- Most common concrete containment failure and the existing control that failed to address it.
- Evidence/verification requirements that recur across organizations.
- Required deployment environment and the top adoption blockers.
- Number willing to run a representative proof, provide a sanitized test workload, introduce a buyer, or discuss a paid pilot.
- Commercial capabilities participants explicitly request and the operational problem each capability solves.
- Contradictory evidence: teams whose existing controls already meet the need or who reject the deployment model.

Do not treat page views, compliments, GitHub stars, or general concern about agent safety as product-market validation.

## Feedback-to-roadmap rubric

For each request, capture the problem and evidence before proposing a feature. Rate:

1. **Frequency:** independently raised by multiple qualified participants, or isolated?
2. **Severity:** blocks adoption / creates material risk, or merely improves convenience?
3. **Evidence:** observed in a real workload, supported by an existing runbook, or hypothetical?
4. **Boundary fit:** preserves the open-core split—open source defines semantics and verifiable enforcement contracts; commercial work organizes operations and enterprise workflow?
5. **Validation path:** can a small test, proof, or pilot establish value before building the feature?
6. **Cost and risk:** complexity, privilege expansion, new trust assumptions, maintenance, and scope creep.

Prefer improvements that remove a demonstrated adoption blocker and can be validated with a bounded proof. Defer broad platform features, generic dashboards, or enterprise controls without a named buyer and specific operational requirement. Do not change core architecture solely because one prospect asks.

## Outreach draft

> Hi — I’m validating a narrow security problem for teams operating coding agents or tool-using agents: when an agent needs to be stopped, how do you prove it has stopped and prevent retained authority from being reused?
>
> I’m building WarrantKit, which binds execution authority to runtime identity and epoch and works with an external containment engine. I’m not assuming it fits your environment; I’d value 25–30 minutes to understand your current controls, failure paths, evidence requirements, and deployment constraints.
>
> If there’s a concrete fit, I can follow up with the smallest relevant proof. No production access or sensitive data needed. Would you be open to a short conversation?

## After each interview

Within 24 hours, write a one-page record containing workload facts, current controls, exact problem evidence, key objections, scoring with rationale, next commitment, and one falsifiable takeaway. Separate direct quotes from interpretation. Update the roadmap only after comparing multiple interviews; explicitly note disconfirming evidence.

## Non-goals

This program does not presume product-market fit, guarantee a commercial buyer, or authorize building a hosted control plane, SSO/RBAC, compliance reporting, or other enterprise features without evidence. The objective is to learn whether the authority-boundary invariant solves a painful problem for a reachable buyer.
