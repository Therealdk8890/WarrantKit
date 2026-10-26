"""ARTEX-style tool-misuse regression tests.

These tests intentionally exercise the pinned AgentContainment gateway used by
WarrantKit. Tests asserting unsupported behavior are expected to expose gaps
until the implementation provides that behavior; do not turn them into xfails
or weaken their assertions merely to obtain a green run.
"""
from __future__ import annotations

from agent_containment import Action, ActionGateway, PolicyEngine
from agent_containment.containment import ContainmentController
from agent_containment.control import ContainmentService
from agent_containment.models import DecisionType
from agent_containment.runtime import ExecutionLease, Runtime, RuntimeState


def _harness(*, denied_operations: set[str] | None = None):
    runtime = Runtime("artex-agent", runtime_id="artex-runtime")
    controller = ContainmentController(runtime)
    service = ContainmentService()
    service.register("artex-agent", containment=controller)
    gateway = ActionGateway(
        PolicyEngine(denied_operations=denied_operations or set()),
        controller,
    )
    return runtime, controller, service, gateway


def _action(action_id: str, operation: str, resource: str = "tenant:A/recon"):
    return Action("artex-agent", action_id, operation, resource)


def test_baseline_in_scope_read_executes_and_records_side_effect():
    _runtime, _controller, _service, gateway = _harness()
    side_effects: list[str] = []

    result = gateway.execute(
        _action("baseline-read", "read"),
        lambda action: side_effects.append(action.action_id) or "read-result",
    )

    assert result == "read-result"
    assert side_effects == ["baseline-read"]


def test_spray_denials_do_not_halt_runtime_or_block_later_allowed_reads():
    """A denied attempt must not itself disable otherwise-authorized reads.

    Current PolicyEngine maps denied_operations to HALT, so this assertion
    deliberately reveals the current policy/gateway semantic mismatch.
    """
    runtime, _controller, _service, gateway = _harness(
        denied_operations={"credential_add", "privilege_modify", "write"}
    )
    side_effects: list[str] = []
    decisions = []

    for index in range(1_000):
        operation = "read" if index % 2 == 0 else (
            "credential_add" if index % 4 == 1 else "privilege_modify"
        )
        action = _action(f"spray-{index}", operation)
        result = gateway.execute(action, lambda candidate: side_effects.append(candidate.action_id))
        decisions.append(getattr(result, "decision", None))

    denied_ids = {
        f"spray-{index}" for index in range(1_000) if index % 2 == 1
    }
    assert not denied_ids.intersection(side_effects)
    assert runtime.state is RuntimeState.ACTIVE
    assert all(
        decisions[index] is DecisionType.ALLOW
        for index in range(0, 1_000, 2)
    )


def test_tenant_b_resource_is_denied_under_tenant_a_only_policy():
    """Expected to expose the absence of tenant-aware scope enforcement.

    ActionGateway's current Action/PolicyEngine contract has no tenant-scope
    primitive. This test must remain a failing security finding until scope is
    enforced by trusted policy, not inferred from a resource-name convention.
    """
    _runtime, _controller, _service, gateway = _harness()
    side_effects: list[str] = []

    result = gateway.execute(
        _action("cross-tenant", "read", "tenant:B/recon"),
        lambda action: side_effects.append(action.action_id),
    )

    assert getattr(result, "decision", None) is DecisionType.DENY
    assert side_effects == []


def test_containment_invalidates_old_and_forged_epoch_leases_without_side_effects():
    runtime, controller, _service, gateway = _harness()
    old_lease = gateway.acquire_lease()
    assert old_lease is not None
    assert old_lease.epoch == 0

    controller.contain()
    assert runtime.epoch == 1
    assert runtime.state is RuntimeState.CONTAINED
    assert runtime.can_execute is False

    forged_new_epoch_lease = ExecutionLease(
        agent_id="artex-agent",
        epoch=runtime.epoch,
    )
    side_effects: list[str] = []

    for action_id, lease in (
        ("old-lease-replay", old_lease),
        ("forged-epoch", forged_new_epoch_lease),
    ):
        result = gateway.execute_with_lease(
            _action(action_id, "read"),
            lease,
            lambda action: side_effects.append(action.action_id),
        )
        assert getattr(result, "decision", None) is DecisionType.DENY

    assert side_effects == []


def test_recovery_requires_current_capability_and_exact_next_epoch():
    runtime, _controller, service, _gateway = _harness()
    service.contain("artex-agent")
    assert runtime.epoch == 1
    assert runtime.state is RuntimeState.CONTAINED

    # No caller-created object is a valid recovery capability.
    try:
        runtime.recover(object(), expected_epoch=runtime.epoch)
    except PermissionError:
        pass
    else:
        raise AssertionError("recovery succeeded without controller authorization")
    assert runtime.epoch == 1

    stale_authorization = service.issue_recovery_authorization("artex-agent")
    try:
        service.recover("artex-agent", stale_authorization)
    except Exception:
        # The service may consume/rotate an authorization; the authoritative
        # recovery assertion below uses a freshly issued authorization.
        pass
    if runtime.state is RuntimeState.CONTAINED:
        authorization = service.issue_recovery_authorization("artex-agent")
        recovered_epoch = service.recover("artex-agent", authorization)
    else:
        recovered_epoch = runtime.epoch

    assert recovered_epoch == 2
    assert runtime.epoch == 2
    assert runtime.state is RuntimeState.ACTIVE
