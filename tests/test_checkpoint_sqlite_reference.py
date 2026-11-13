"""Transactional checkpoint reference contract tests."""
import sqlite3
import pytest

from agentcontain.agentcontainment_fence_recovery import TrustedRegistryCheckpoint
from agentcontain.checkpoint_sqlite_reference import SQLiteCheckpointAuthority
from agentcontain.downstream_commit_fence import DownstreamDenied


def checkpoint(epoch, digest="a"):
    return TrustedRegistryCheckpoint("agent", epoch, digest * 64, None)


def test_reference_checkpoint_persists_restart_and_replays(tmp_path):
    path = tmp_path / "checkpoint.db"
    first = SQLiteCheckpointAuthority(path)
    assert first.read("agent") is None
    assert first.advance(checkpoint(0))
    second = SQLiteCheckpointAuthority(path)
    assert second.read("agent") == checkpoint(0)
    assert not second.advance(checkpoint(0))
    assert second.advance(checkpoint(1, "b"))
    assert SQLiteCheckpointAuthority(path).read("agent") == checkpoint(1, "b")


def test_reference_checkpoint_rejects_rollback_gap_and_conflict(tmp_path):
    authority = SQLiteCheckpointAuthority(tmp_path / "checkpoint.db")
    assert authority.advance(checkpoint(0))
    for invalid in (checkpoint(0, "b"), checkpoint(2, "b")):
        with pytest.raises((DownstreamDenied, ValueError)):
            authority.advance(invalid)
    assert authority.advance(checkpoint(1, "b"))
    with pytest.raises(DownstreamDenied):
        authority.advance(checkpoint(0))
    assert authority.read("agent") == checkpoint(1, "b")


def test_reference_checkpoint_invalid_prior_row_fails_closed(tmp_path):
    path = tmp_path / "checkpoint.db"
    authority = SQLiteCheckpointAuthority(path)
    assert authority.advance(checkpoint(0))
    with sqlite3.connect(path) as db:
        db.execute("UPDATE checkpoints SET fence_sha256='corrupt' WHERE agent_id='agent'")
    with pytest.raises(DownstreamDenied):
        authority.advance(checkpoint(1, "b"))
    assert authority.read("agent").epoch == 0


def test_concurrent_writers_only_one_conflicting_epoch_wins(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    path = tmp_path / "concurrent-checkpoint.db"
    SQLiteCheckpointAuthority(path).advance(checkpoint(0))
    barrier = Barrier(2)

    def compete(digest):
        barrier.wait(timeout=10)
        try:
            return SQLiteCheckpointAuthority(path).advance(checkpoint(1, digest))
        except DownstreamDenied:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(compete, "b")
        b = pool.submit(compete, "c")
        results = [a.result(timeout=20), b.result(timeout=20)]
    assert sorted(results) == [False, True]
    stored = SQLiteCheckpointAuthority(path).read("agent")
    assert stored in (checkpoint(1, "b"), checkpoint(1, "c"))


def test_concurrent_identical_replay_is_idempotent(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    path = tmp_path / "replay-checkpoint.db"
    SQLiteCheckpointAuthority(path).advance(checkpoint(0))
    barrier = Barrier(2)

    def replay():
        barrier.wait(timeout=10)
        return SQLiteCheckpointAuthority(path).advance(checkpoint(1, "b"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: replay(), range(2)))
    assert sorted(results) == [False, True]
    assert SQLiteCheckpointAuthority(path).read("agent") == checkpoint(1, "b")


def test_sqlite_transaction_rollback_preserves_checkpoint_on_failed_write(tmp_path):
    path = tmp_path / "rollback-checkpoint.db"
    authority = SQLiteCheckpointAuthority(path)
    assert authority.advance(checkpoint(0))
    with sqlite3.connect(path) as db:
        db.execute("""CREATE TRIGGER reject_epoch_one BEFORE UPDATE ON checkpoints
            WHEN NEW.epoch = 1 BEGIN SELECT RAISE(ABORT, 'simulated write failure'); END""")
    with pytest.raises(sqlite3.DatabaseError, match="simulated write failure"):
        authority.advance(checkpoint(1, "b"))
    assert SQLiteCheckpointAuthority(path).read("agent") == checkpoint(0)
    with sqlite3.connect(path) as db:
        db.execute("DROP TRIGGER reject_epoch_one")
    assert SQLiteCheckpointAuthority(path).advance(checkpoint(1, "b"))
