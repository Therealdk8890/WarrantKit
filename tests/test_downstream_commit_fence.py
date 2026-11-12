"""Transactional downstream epoch fencing reference tests."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Event, Thread

import pytest

from agentcontain.downstream_commit_fence import DownstreamCommitFence, DownstreamDenied


@pytest.fixture
def store(tmp_path: Path) -> DownstreamCommitFence:
    fence = DownstreamCommitFence(tmp_path / "fence.db",
        controller_key=b"controller-trust-root-for-test-0001",
        gateway_key=b"gateway-trust-root-for-test-000002")
    _transition(fence, 0, True)
    return fence


def _transition(fence, epoch, active, agent_id="agent"):
    fence.transition(agent_id=agent_id, epoch=epoch, active=active,
                     signature=fence.sign_transition(agent_id=agent_id, epoch=epoch, active=active))


def _op(fence, operation_id="op", epoch=0, value="write", agent_id="agent"):
    return fence.sign_operation(agent_id=agent_id, epoch=epoch,
                                operation_id=operation_id, value=value)


def test_authorized_commit_idempotency_and_conflicting_replay(store):
    assert store.commit(_op(store))
    assert not store.commit(_op(store))
    assert store.effects("agent") == [("op", 0, "write")]
    with pytest.raises(DownstreamDenied, match="conflicting"):
        store.commit(_op(store, value="changed"))
    assert store.effects("agent") == [("op", 0, "write")]


def test_unauthenticated_commands_and_payload_tampering_denied(store):
    req = _op(store)
    with pytest.raises(DownstreamDenied, match="unauthenticated"):
        store.commit(replace(req, value="tampered"))
    with pytest.raises(DownstreamDenied, match="unauthenticated"):
        store.commit(replace(req, signature="0" * 64))
    with pytest.raises(DownstreamDenied, match="unauthenticated"):
        store.transition(agent_id="agent", epoch=1, active=False, signature=req.signature)
    assert store.effects("agent") == []


def test_fence_rejects_old_authority_and_requires_new_epoch(store):
    old = _op(store)
    _transition(store, 1, False)
    with pytest.raises(DownstreamDenied, match="fenced"):
        store.commit(old)
    with pytest.raises(DownstreamDenied, match="fenced"):
        store.commit(_op(store, epoch=1))
    with pytest.raises(DownstreamDenied, match="nonmonotonic"):
        _transition(store, 0, True)
    with pytest.raises(DownstreamDenied, match="nonmonotonic"):
        _transition(store, 3, True)
    _transition(store, 2, True)
    with pytest.raises(DownstreamDenied, match="fenced"):
        store.commit(old)
    assert store.commit(_op(store, epoch=2))
    assert store.effects("agent") == [("op", 2, "write")]


def test_unknown_agent_denied_and_distinct_agent_scopes(store):
    with pytest.raises(DownstreamDenied, match="fenced"):
        store.commit(_op(store, agent_id="other"))
    _transition(store, 0, True, agent_id="other")
    assert store.commit(_op(store, agent_id="other"))
    assert store.effects("agent") == []
    assert store.effects("other") == [("op", 0, "write")]


def test_request_accepted_before_fence_is_rejected_at_transactional_commit(store):
    accepted = Event()
    allow_commit = Event()
    errors = []
    request = _op(store, "pending")
    def delayed():
        accepted.set()
        assert allow_commit.wait(5)
        try:
            store.commit(request)
        except DownstreamDenied as exc:
            errors.append(str(exc))
    worker = Thread(target=delayed)
    worker.start()
    try:
        assert accepted.wait(5)
        _transition(store, 1, False)
    finally:
        allow_commit.set()
        worker.join(timeout=5)
    assert not worker.is_alive()
    assert errors == ["fenced or stale epoch"]
    assert store.effects("agent") == []


def test_concurrent_commit_and_fence_are_serialized(store):
    # The database write and authority check are protected by the same
    # SQLite write transaction, so every outcome has a legal total order.
    for i in range(12):
        epoch = 2 * i
        request = _op(store, f"parallel-{i}", epoch=epoch)
        with ThreadPoolExecutor(max_workers=2) as pool:
            future_commit = pool.submit(store.commit, request)
            future_fence = pool.submit(_transition, store, epoch + 1, False)
            try:
                committed = future_commit.result(timeout=5)
            except DownstreamDenied:
                committed = False
            future_fence.result(timeout=5)
        rows = store.effects("agent")
        assert any(row[0] == request.operation_id for row in rows) == committed
        if i < 11:
            _transition(store, epoch + 2, True)
    assert len(store.effects("agent")) <= 12


def test_secret_requirements_and_epoch_validation(tmp_path):
    with pytest.raises(ValueError, match="at least 32"):
        DownstreamCommitFence(tmp_path / "weak.db", controller_key=b"weak",
                              gateway_key=b"x" * 32)
    with pytest.raises(ValueError, match="distinct"):
        DownstreamCommitFence(tmp_path / "same.db", controller_key=b"x" * 32,
                              gateway_key=b"x" * 32)
    fence = DownstreamCommitFence(tmp_path / "fresh.db",
                                 controller_key=b"a" * 32, gateway_key=b"b" * 32)
    with pytest.raises(DownstreamDenied, match="first transition"):
        _transition(fence, 1, True)
