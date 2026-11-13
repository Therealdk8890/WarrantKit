# In-flight side effects and external enforcement

**Status:** security contract under review. This document describes the
currently tested behavior, not a claim of universal cancellation or a
production service-level objective.

## Trust boundaries

- **Admission fence:** AgentContainment validates the runtime's ACTIVE state,
  exact execution lease, and epoch while atomically admitting a callback. A
  subsequent containment transition advances the epoch and denies **new**
  admissions. An already-admitted callback is not retroactively un-admitted.
- **Warrant check:** WarrantKit verifies signed Warrant, capability, expiry,
  policy, revocation, and current runtime epoch before policy evaluation and
  again in the admitted callback. The newer AgentContainment runtime runs
  application callbacks **outside** its lifecycle lock. The final check is
  not an atomic commit with the downstream protected side effect.
- **External enforcement:** A configured, independently verified enforcer
  (for example, Linux cgroup-v2 cgroup.kill) can terminate an already
  running, correctly attached workload. The controller's runtime fence is
  not itself a process-kill or outbound-request cancellation primitive.
- **Downstream service:** Operations already accepted by an external
  service can complete even if the local process is subsequently killed.
  Only the downstream trust boundary can provide atomic authorization at
  commit, revocation, idempotent retries, or compensation. Local evidence
  must not imply that a remote side effect was undone.

## Observable outcome matrix

| Boundary and timing | Expected outcome | Evidence |
| --- | --- | --- |
| Attempt new callback after committed runtime fence | Denied by runtime lease and Warrant checks | tests/test_newer_agentcontainment_runtime_contract.py |
| Callback admitted before fence and blocked | Fence can commit without waiting; callback remains in-flight | tests/test_newer_agentcontainment_runtime_contract.py |
| Child in dedicated cgroup, pre-fence write already completed | Write remains; no rollback is claimed | tests/integration/test_inflight_cgroup_external_enforcement.py |
| Child in dedicated cgroup, second write gated until after containment | cgroup.kill terminates child; independently verified empty cgroup and SIGKILL; second write absent | tests/integration/test_inflight_cgroup_external_enforcement.py |
| External enforcer reports failure while callback is in-flight | Fence remains committed; report is not certified; old callback may continue and complete | tests/test_newer_agentcontainment_runtime_contract.py |
| HTTP request accepted before fencing, downstream epoch checked after fencing | A localhost server using a trusted in-process runtime snapshot rejects the pending commit with HTTP 409 | tests/test_newer_agentcontainment_runtime_contract.py |
| Remote request leaves the local host before containment | **Unproven.** May commit after containment, regardless of local process kill | Requires a separately authenticated remote-service test |

The localhost HTTP test demonstrates commit-time authorization ordering with a trusted in-process epoch oracle. It does not prove distributed revocation propagation, atomic server-side transactions, network partition behavior, or protection against an agent holding its own credentials. A real remote service must obtain trusted, fresh epoch state and enforce the authorization check in the same transaction as the protected effect.\n\nThe real-kill test runs only under an explicit privileged Linux opt-in and
checks the actual cgroup identity, kernel occupancy, child exit signal,
pre-fence effect, and absent pending effect. The test uses a local worker
process; it does not establish remote-service cancellation, network egress
policy correctness, or a bound on kill latency in production deployments.

## Interpreting containment results

1. A fenced runtime rejects newly admitted work even if an external enforcer
   later fails. A stale epoch is not made current by a failed enforcement
   stage.
2. A complete / certified report requires the configured external
   providers to return enforcement and independent verification. A failure
   must remain visible in the report and never be treated as a successful
   kill.
3. An already-admitted Python callback may return **after** the runtime is
   contained, including with the killed worker's nonzero return code. That
   return is not a new execution lease or proof that a downstream write
   succeeded.
4. Side effects committed before containment remain committed. Evidence
   should separate admission, fence, enforcement, verification,
   and the authoritative downstream outcome, when known.

## Requirements before a production compatibility claim

- Keep the older released/pinned runtime behavior and the newer-runtime
  behavior explicitly separated in tests and release documentation.
- Pin the exact newer AgentContainment source and validate it with both
  deterministic concurrency tests and real Linux process-enforcement tests.
- Verify failure-path handling: stale authority remains denied when the
  enforcer is unavailable, while any in-flight effect is treated as
  potentially completed until an authoritative downstream result exists.
- Specify the downstream authorization model before claiming that an
  already-admitted remote operation cannot commit after containment. Typical
  defenses are gateway-held credentials, per-operation epoch fencing at the
  server, idempotency keys, transaction-scoped authorization and explicit
  cancellation/compensation. None is automatically provided by a local
  process kill.
- Perform a separate review of controller crash/restart during fencing,
  durable incident reconciliation, and endpoint credential lifetime.

No API should claim that a local GuardedExecutionDenied, an epoch advance,
or external_verified alone reverses a side effect that already completed.


## Transactional downstream reference (experimental)

The module agentcontain/downstream_commit_fence.py implements a **single
SQLite database** reference for protecting a local committed effect. The
controller authenticates a monotonic epoch transition with a controller-held
HMAC key. A separately authenticated gateway signs the exact operation
(agent, epoch, operation ID and payload). The downstream database performs
both the epoch comparison and effect insertion under one BEGIN IMMEDIATE
transaction. Idempotent identical retries do not duplicate the effect;
conflicting retries fail closed.

This reference is not automatically wired to the WarrantKit gateway, its
production controller, a remote HTTP service, or an external identity
provider. The two signing helpers are co-located in the reference class for
test convenience; in a real deployment, private keys must be segregated
into controller/gateway processes and inaccessible to agents. The example
does not implement TLS/mTLS, trusted principal provisioning, durable key
rotation, distributed state replication, or cross-database atomicity.

**Critical operational constraint:** the downstream service must receive
the authenticated fence transition and durably commit it before claiming
that downstream writes are fenced. A local runtime epoch increment alone
does not synchronously update a remote service. An already-accepted remote
request can commit before the downstream fence transaction wins. If the
fence transaction wins first, the old-epoch request is rejected. A local
SQLite transaction provides a total order within one database only.

The reference demonstrates a concrete protocol and tests its behavior; it
is not a production-ready authenticated remote enforcement system.


## Authenticated downstream transition acknowledgment (experimental)

The transport-neutral module `agentcontain/downstream_transition_delivery.py`
adds a controller-authenticated transition envelope, a downstream endpoint
that commits the signed transition to the same SQLite authority table used
by protected effects, and a distinct downstream-authenticated receipt.
The controller-side verifier requires the receipt to match the exact agent,
epoch, active state, and request identifier. Missing, forged, stale, or
mismatched acknowledgments do not establish verified downstream enforcement.

The downstream endpoint issues its receipt **after** the database transition
returns successfully. An identical transition may be retried, with a new
request ID, if an acknowledgment is lost. An acknowledgment confirms only
the downstream database's committed transition, not the state of other
replicas or services.

The reference is intentionally not wired into the production controller's
`certified` reporting path. That integration requires an independently
authenticated channel, secret custody separated from the agent, a durable
outbox/retry policy, explicit error states, and evidence that each configured
downstream enforcement target has acknowledged the transition. The reference
uses symmetric test keys and no transport; it is **not** an HTTP security
service, a production key-management implementation, or distributed
consensus.


## Explicit combined local/downstream evidence (experimental)

The optional `contain_with_downstream_ack` coordinator calls the existing
WarrantKit containment lifecycle, then requires a valid, authenticated
downstream receipt for the fenced epoch. It does not mutate or overwrite
AgentContainment's local containment report. A failed or forged downstream
receipt raises `DownstreamContainmentUnverified`, preserving the local report
for incident review while explicitly refusing to claim remote verification.

A local containment report can be complete even when a remote service
never received the fence transition; the remote database may therefore
still accept a request under its previously active epoch. The coordinator
and its tests make this distinction observable. Production integration
requires durable retries, endpoint identity authentication, restart-safe
reconciliation, independent trust-key custody, and coverage of every
configured downstream enforcement target. A synchronous in-process
coordinator alone does not provide these guarantees.


## Restart-safe downstream transition outbox (experimental)

The `DurableTransitionOutbox` reference persists a controller-signed
transition envelope to a separate SQLite database before attempting delivery.
A restart reconstructs pending transitions from the database and retries them
in epoch order. Only a matching, authenticated downstream receipt is stored as
acknowledged; verification is repeated when querying persisted receipts.
The downstream transition endpoint accepts identical epoch transitions
idempotently, so losing the receipt after remote commit can be recovered by
retrying the same envelope. Missing acknowledgments remain pending.

**This does not yet solve the crash window between local runtime fencing and
outbox enqueue.** A controller that crashes after advancing its local epoch
but before recording the transition must reconstruct the missing transition
from durable, authoritative runtime incident state. No such reconciliation
is implemented by this outbox. It also does not automatically register as an
AgentContainment enforcer or amend its certification semantics.

The outbox SQLite file must itself have durable storage, exclusive controller
access, correct file permissions, backup/restore procedures, and the same
retention guarantees as the authority log. A compromised database, stolen
controller/gateway key, or stale trusted epoch source is outside this
reference's security guarantees. Multi-target delivery, retry scheduling,
operator alerts, endpoint identity, and authenticated transport are future
integration work.


## Reconstructing a missing fence after controller restart (experimental)

`downstream_reconciliation.py` provides a fail-closed recovery adapter
for the window in which local containment advanced the epoch but the
controller crashed before recording the downstream transition. A trusted
reader supplies a durable incident record with the agent, fenced epoch,
non-executable state, and record identifier. An independently supplied
authenticator must validate that record. Only then can a controller-held
signer reconstruct a pending downstream transition in the outbox.

**This is a protocol seam, not a verified AgentContainment incident-store
integration.** The caller must implement a reader and authenticator against
the actual durable, controller-owned incident log. The reference does not
establish which AgentContainment log format is authoritative, authenticate
that log itself, or prove it was flushed before the controller crash.
The reconstructed transition is pending until a matching downstream receipt
has been authenticated and durably persisted. Remote effects may still
commit before the downstream fence is delivered.

Repeated reconstruction of the same epoch must reuse the existing stored
envelope; generating a different request ID for the same epoch is rejected.
Production recovery must scan all unresolved incidents, retain their
authenticated ordering, and reconcile any missing intermediate epochs.


## Actual AgentContainment durable-registry adapter (newer runtime only)

`agentcontainment_fence_recovery.py` now reads the newer
AgentContainment `RuntimeFenceRegistry` and `IncidentRegistry` from
controller-owned persisted files, rather than relying only on an abstract
incident record. A durable runtime fence is prepared before containment;
it remains useful even if the incident record could not be written.
An existing incident must agree on the containment epoch and must not
already be recovered. The adapter reconstructs a **pending** downstream
transition and still requires an independently authenticated receipt.

The dedicated newer-runtime CI job exercises actual persisted registry
files, including missing incidents, conflicting recovery state, mismatched
epochs, and missing or malformed fences. The pinned production runtime
submodule remains unchanged.

The registries use atomic file replacement and file fsync, but **do not
cryptographically authenticate their JSON content**. This adapter assumes
controller-exclusive filesystem custody; it is not a defense against
tampering by a privileged host attacker. Directory fsync/power-loss
durability, incident ordering across multiple transitions, recovery of
already-cleared fences, and atomicity between upstream and downstream
stores are not proven. These limits must be resolved before claiming
production-grade distributed containment.
