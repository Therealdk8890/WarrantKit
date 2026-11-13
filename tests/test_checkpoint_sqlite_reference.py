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
