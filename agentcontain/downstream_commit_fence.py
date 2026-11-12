"""Reference downstream commit fence: authenticated commands and SQLite atomicity.

This is a *single database* reference boundary, not a distributed revocation
protocol. Trusted controller and gateway credentials must be held separately
from the agent. Commit authority is decided inside the same BEGIN IMMEDIATE
transaction as the protected ledger write. Do not use a read-only snapshot
from a different process as a substitute for this transaction.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import sqlite3
from pathlib import Path


class DownstreamDenied(PermissionError):
    """A request is unauthenticated, stale, conflicting, or fenced."""


def _canonical(data: dict[str, object]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _mac(key: bytes, domain: str, data: dict[str, object]) -> str:
    return hmac.new(key, domain.encode("ascii") + b"\x00" + _canonical(data), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class CommitRequest:
    agent_id: str
    epoch: int
    operation_id: str
    value: str
    signature: str


class DownstreamCommitFence:
    """Trusted server-side transactional epoch fence for local SQLite effects.

    The controller key signs monotonic epoch transitions. The separate gateway
    key signs each requested operation. Neither key may be available to the
    untrusted agent. Both keys are required to be high-entropy secrets; this
    class does not distribute keys or authenticate an HTTP/TLS peer.
    """

    def __init__(self, db_path: str | Path, *, controller_key: bytes, gateway_key: bytes):
        if not isinstance(controller_key, bytes) or len(controller_key) < 32:
            raise ValueError("controller_key must contain at least 32 secret bytes")
        if not isinstance(gateway_key, bytes) or len(gateway_key) < 32:
            raise ValueError("gateway_key must contain at least 32 secret bytes")
        if hmac.compare_digest(controller_key, gateway_key):
            raise ValueError("controller and gateway keys must be distinct")
        self._db_path = str(db_path)
        self._controller_key = controller_key
        self._gateway_key = gateway_key
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS authority (
                agent_id TEXT PRIMARY KEY,
                epoch INTEGER NOT NULL CHECK(epoch >= 0),
                active INTEGER NOT NULL CHECK(active IN (0, 1))
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS effects (
                agent_id TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                epoch INTEGER NOT NULL,
                value TEXT NOT NULL,
                PRIMARY KEY(agent_id, operation_id)
            )""")

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self._db_path, timeout=10, isolation_level=None)
        db.execute("PRAGMA busy_timeout = 10000")
        return db

    def sign_transition(self, *, agent_id: str, epoch: int, active: bool) -> str:
        """Controller-side helper; call only where the controller key is trusted."""
        return _mac(self._controller_key, "warrantkit.downstream.transition.v1",
                    {"agent_id": agent_id, "epoch": epoch, "active": active})

    def sign_operation(self, *, agent_id: str, epoch: int, operation_id: str, value: str) -> CommitRequest:
        """Gateway-side helper; never expose this signer to the agent."""
        data = {"agent_id": agent_id, "epoch": epoch, "operation_id": operation_id, "value": value}
        return CommitRequest(**data, signature=_mac(
            self._gateway_key, "warrantkit.downstream.operation.v1", data))

    def transition(self, *, agent_id: str, epoch: int, active: bool, signature: str) -> None:
        if not agent_id or type(epoch) is not int or epoch < 0 or type(active) is not bool:
            raise DownstreamDenied("invalid transition")
        expected = self.sign_transition(agent_id=agent_id, epoch=epoch, active=active)
        if not isinstance(signature, str) or not hmac.compare_digest(expected, signature):
            raise DownstreamDenied("unauthenticated transition")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                old = db.execute("SELECT epoch, active FROM authority WHERE agent_id=?", (agent_id,)).fetchone()
                if old is None:
                    if epoch != 0 or not active:
                        raise DownstreamDenied("first transition must initialize active epoch zero")
                    db.execute("INSERT INTO authority VALUES (?, ?, ?)", (agent_id, epoch, 1))
                elif epoch == old[0] and int(active) == old[1]:
                    pass  # Idempotent replay of the identical transition.
                elif epoch != old[0] + 1:
                    raise DownstreamDenied("nonmonotonic epoch transition")
                else:
                    db.execute("UPDATE authority SET epoch=?, active=? WHERE agent_id=?",
                               (epoch, int(active), agent_id))
                db.commit()
            except BaseException:
                db.rollback()
                raise

    def commit(self, request: CommitRequest) -> bool:
        """Commit a protected local effect atomically with the epoch check.

        Returns False for an identical operation replay; mismatched replays
        are denied. No effect is committed if the epoch has been fenced.
        """
        if not isinstance(request, CommitRequest):
            raise DownstreamDenied("invalid request")
        if (not request.agent_id or not request.operation_id
                or type(request.epoch) is not int or request.epoch < 0
                or not isinstance(request.value, str)):
            raise DownstreamDenied("invalid operation")
        data = {"agent_id": request.agent_id, "epoch": request.epoch,
                "operation_id": request.operation_id, "value": request.value}
        expected = _mac(self._gateway_key, "warrantkit.downstream.operation.v1", data)
        if not isinstance(request.signature, str) or not hmac.compare_digest(expected, request.signature):
            raise DownstreamDenied("unauthenticated operation")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                state = db.execute("SELECT epoch, active FROM authority WHERE agent_id=?",
                                   (request.agent_id,)).fetchone()
                if state != (request.epoch, 1):
                    raise DownstreamDenied("fenced or stale epoch")
                old = db.execute("SELECT epoch, value FROM effects WHERE agent_id=? AND operation_id=?",
                                 (request.agent_id, request.operation_id)).fetchone()
                if old is not None:
                    if old != (request.epoch, request.value):
                        raise DownstreamDenied("conflicting operation replay")
                    db.commit()
                    return False
                db.execute("INSERT INTO effects VALUES (?, ?, ?, ?)",
                           (request.agent_id, request.operation_id, request.epoch, request.value))
                db.commit()
                return True
            except BaseException:
                db.rollback()
                raise

    def effects(self, agent_id: str) -> list[tuple[str, int, str]]:
        with self._connect() as db:
            return list(db.execute(
                "SELECT operation_id, epoch, value FROM effects WHERE agent_id=? ORDER BY operation_id",
                (agent_id,)))
