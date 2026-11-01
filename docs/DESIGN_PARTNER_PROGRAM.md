# WarrantKit Design Partner Program

## Objective

Validate WarrantKit against teams that already operate autonomous or coding agents in staging or production.

The goal is not to collect generic feedback. The goal is to discover whether the external authority, hard-stop enforcement, epoch lifecycle, and independently verifiable evidence model solve a problem important enough to change deployment behavior or justify paid operational capabilities.

## 30-day validation target

The next milestone is one independent technical evaluation—not another feature release.

- **Days 1–5:** finalize the security overview, reproducible proof instructions, Kubernetes boundary statement, and evaluation record. Identify 10 named teams with an existing coding-agent or autonomous-agent workload.
- **Days 6–15:** conduct targeted outreach and seek 5–10 qualified discovery conversations. Ask about the team's actual workload and current containment path before presenting WarrantKit.
- **Days 16–23:** select the strongest qualified candidate and agree on a sanitized, bounded technical evaluation. Confirm Linux/cgroup-v2 and privilege prerequisites before scheduling the proof.
- **Days 24–30:** run the proof with the partner's representative workload, record failures and objections, and decide whether the problem and deployment model justify continued investment.

**Decision rule:** if no qualified team will commit a representative workload or technical evaluation within 30 days, do not respond by adding features. Reassess the target customer, urgency, deployment assumptions, and core problem statement.

Existing outreach should be recorded before sending duplicates. Track each organization, contact, role, date, response, workload qualification, next commitment, and reason for decline. A follow or connection is not a design-partner commitment.

## Feature-freeze rule

Until a partner evaluation produces evidence, keep the product surface stable. Do not implement SSO/OIDC, external audit anchoring, new tenant/permission layers, or additional control-plane endpoints merely because they are common enterprise requests. Capture the requirement, identify the buyer and deployment blocker, and seek confirmation from more than one qualified team before committing roadmap work. Fix correctness, security, reproducibility, and documentation defects in the existing proof path; those are not feature expansion.


## Product boundary and current proof options

WarrantKit coordinates authority lifecycle, policy-bound Warrants, gateway integration, and evidence. AgentContainment remains the separate runtime enforcement engine. Evidence and signatures support verification; they do not themselves grant authority, prove every underlying claim true, or establish host integrity.

Choose a proof based on the claim under evaluation:

- `warrantkit demo`: portable orientation; simulated lifecycle, not kernel process containment.
- `python tools/run_authority_boundary_demo.py`: framework-to-gateway boundary; tests rejection of retained stale authority before a subsequent protected side effect.
- [Linux cgroup-v2 real-kill proof](REAL_KILL_DEMO.md): host process-containment evidence, requiring Linux and suitable root/delegated cgroup privileges.
- [Raw MCP integration](MCP_SERVER_INTEGRATION.md): synchronous Python handlers only; not remote/hosted MCP tools or async-native execution.

For every proof, record the exact source revision, environment, observed result, and limitations. Do not claim a broader guarantee than the tested path supports.

## Target profile

Prioritize teams with one or more of:

- autonomous coding agents
- internal agent fleets
- agents that execute code or shell commands
- agents with access to production or sensitive staging resources
- security/platform teams responsible for agent guardrails
- AI infrastructure vendors that need a defensible containment story

Deprioritize teams that only experiment with chatbots or have no agent execution boundary to evaluate.

## What to validate

### Problem

- What can the agent actually execute?
- What resources, credentials, networks, or environments can it reach?
- What happens today when an agent violates policy?
- Does the current control depend on the agent voluntarily stopping?
- Where does the security team draw the enforcement boundary?

### Evidence

- What evidence is available after an incident?
- Which evidence sources are trusted independently?
- What would make a security reviewer accept a containment event as verified?
- What conflicts between runtime, observation, provenance, or audit records are difficult today?

### Deployment

- Which Linux/runtime/orchestration environments matter?
- Can the team run a privileged cgroup-v2 proof?
- What host or deployment constraints block evaluation?
- Which existing controls must WarrantKit complement rather than replace?

### Commercial value

- Which operational problems appear when managing more than one agent?
- Is fleet-wide authority governance needed?
- Is centralized evidence investigation valuable?
- Which compliance/audit workflows are painful?
- Which integrations are required for adoption?
- What would the team pay to avoid building or operating those capabilities internally?

## Interview structure

Keep the first conversation to roughly 30 minutes.

1. **Workload** — What autonomous agents are you running today?
2. **Authority** — What can those agents do that worries you?
3. **Enforcement** — What happens when one crosses a boundary?
4. **Failure** — What happens if the agent ignores a stop instruction?
5. **Evidence** — What can you prove afterward?
6. **Review** — What would a security reviewer challenge?
7. **Deployment** — What would make a real Linux evaluation difficult?
8. **Operations** — What becomes painful at fleet scale?
9. **Buying** — Which operational capability would justify budget?
10. **Pilot** — What is the smallest real workload that could validate the concept?

Do not lead the interview with WarrantKit's feature list. Start with the existing workflow and pain.

## Qualification

A strong design partner has:

- a real agent execution workload
- a named security/platform owner
- a concrete containment or authority problem
- willingness to run a technical evaluation
- a way to provide deployment feedback
- interest in evidence or operational governance

A weak candidate has only general interest in AI safety without an executable workload or owner.

## Pilot success signals

Track:

- number of teams that run the real privileged path
- time from clone to successful real-kill proof
- number of deployment blockers
- number of requested integrations
- number of incidents/workflows where independent evidence matters
- whether security reviewers accept the trust-boundary model
- whether customers request fleet/evidence/compliance operations
- whether a team would continue using WarrantKit after the evaluation
- whether a team would pay for a defined commercial capability

GitHub stars are secondary. Real execution and integration attempts are primary.

## Feedback-to-roadmap rubric

Classify feedback as:

**Core security primitive**
- authority
- identity
- epoch
- enforcement boundary
- evidence integrity
- verification

→ Candidate for open WarrantKit.

**Interoperability contract**
- Warrant schema
- evidence contract
- provider interface
- portable verification

→ Prefer open.

**Operational scale**
- fleet management
- centralized evidence operations
- policy governance
- incident workflows
- compliance automation

→ Candidate for commercial WarrantKit.

**Customer-specific integration**
- SIEM/SOC
- enterprise identity
- deployment systems
- ticketing

→ Evaluate as commercial integration unless an open interoperability contract materially benefits the ecosystem.

**One-off feature request**
→ Do not automatically add it. Validate whether multiple design partners have the same underlying problem.

## Outreach message

Subject: WarrantKit — external enforcement for autonomous agents

Hi [Name] — I'm building WarrantKit, an open security foundation for autonomous agents.

The narrow problem we're testing is simple: when an agent crosses a policy boundary, the agent itself shouldn't be trusted to stop. WarrantKit binds authority to an execution and epoch, delegates the hard stop to an external runtime enforcement layer, and produces independently checkable evidence afterward.

I'm looking for a small number of teams already running coding/autonomous agents in staging or production to try the real Linux enforcement path and give blunt feedback.

This isn't a sales demo or a request for a commitment. I'd like to understand how you're handling agent authority and containment today, run the smallest useful technical test, and learn what would make the approach genuinely valuable in your environment.

Would you be open to a 30-minute technical conversation?

— Daniel
