"""Transactional checkpoint CAS reference backend.

Deploy ONLY on storage administered independently of the agent/controller.
SQLite transaction atomicity does not provide independent identity,
anti-rollback storage, remote authentication, or durable replication.
"""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import sqlite3

from .agentcontainment_fence_recovery import (
    MonotonicCheckpointStore, TrustedRegistryCheckpoint,
)
from .downstream_commit_fence import DownstreamDenied


class SQLiteCheckpointAuthority:
    """Reference single-database transactional CAS, not a trust anchor."""

    def __init__(self, db_path: str | Path):
        self._path = str(db_path)
        with self._db() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS checkpoints (
                agent_id TEXT PRIMARY KEY,
                epoch INTEGER NOT NULL,
                fence_sha256 TEXT NOT NULL,
                incident_sha256 TEXT
            )""")

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self._path, timeout=10, isolation_level=None)
        try:
            db.execute("PRAGMA busy_timeout=10000")
            yield db
        finally:
            db.close()

    def read(self, agent_id: str) -> TrustedRegistryCheckpoint | None:
        if not isinstance(agent_id, str) or not agent_id:
            raise DownstreamDenied("invalid checkpoint agent identity")
        with self._db() as db:
            row = db.execute(
                "SELECT epoch, fence_sha256, incident_sha256 FROM checkpoints WHERE agent_id=?",
                (agent_id,),
            ).fetchone()
        return None if row is None else TrustedRegistryCheckpoint(agent_id, *row)

    def advance(self, proposed: TrustedRegistryCheckpoint) -> bool:
        """Atomic epoch CAS; returns False only for identical replay."""
        if not isinstance(proposed, TrustedRegistryCheckpoint):
            raise DownstreamDenied("invalid checkpoint proposal")
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute(
                    "SELECT epoch, fence_sha256, incident_sha256 FROM checkpoints WHERE agent_id=?",
                    (proposed.agent_id,),
                ).fetchone()
                previous = None if row is None else TrustedRegistryCheckpoint(proposed.agent_id, *row)
                changed = MonotonicCheckpointStore.validate_advance(previous, proposed)
                if changed:
                    db.execute(
                        "INSERT INTO checkpoints(agent_id, epoch, fence_sha256, incident_sha256) "
                        "VALUES (?,?,?,?) ON CONFLICT(agent_id) DO UPDATE SET "
                        "epoch=excluded.epoch, fence_sha256=excluded.fence_sha256, "
                        "incident_sha256=excluded.incident_sha256",
                        (proposed.agent_id, proposed.epoch, proposed.fence_sha256,
                         proposed.incident_sha256),
                    )
                db.commit()
                return changed
            except BaseException:
                db.rollback()
                raise
