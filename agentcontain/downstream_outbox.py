"""Durable, restart-safe downstream transition delivery reference.

A transition is enqueued with an authenticated controller signature, then
retried until an independently authenticated receipt is persisted. The caller
must durably enqueue before claiming remote enforcement. This is not a
distributed transaction with the local AgentContainment runtime.
"""
from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
import sqlite3
from contextlib import contextmanager
from typing import Callable

from .downstream_commit_fence import DownstreamDenied
from .downstream_transition_delivery import (
    TransitionEnvelope, TransitionReceipt, TransitionReceiptVerifier,
)


class PendingDownstreamFence(RuntimeError):
    """Transition has no durably verified downstream acknowledgment."""


class DurableTransitionOutbox:
    """SQLite outbox with per-agent ordering and crash-safe receipt storage.

    Callers MUST supply a trusted verifier after restart. Never put controller
    signing keys or receipt verification keys in this database.
    """

    def __init__(self, db_path: str | Path, *, verifier: TransitionReceiptVerifier):
        self._path = str(db_path)
        self._verifier = verifier
        with self._db() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS transitions (
                request_id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                epoch INTEGER NOT NULL CHECK(epoch >= 0),
                active INTEGER NOT NULL CHECK(active IN (0,1)),
                envelope_json TEXT NOT NULL,
                receipt_json TEXT,
                UNIQUE(agent_id, epoch)
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS transition_order ON transitions(agent_id, epoch)")

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self._path, timeout=10, isolation_level=None)
        try:
            db.execute("PRAGMA busy_timeout=10000")
            yield db
        finally:
            db.close()

    @staticmethod
    def _parse_envelope(raw: str) -> TransitionEnvelope:
        return TransitionEnvelope(**json.loads(raw))

    @staticmethod
    def _parse_receipt(raw: str) -> TransitionReceipt:
        return TransitionReceipt(**json.loads(raw))

    def enqueue(self, envelope: TransitionEnvelope) -> None:
        if (not isinstance(envelope, TransitionEnvelope) or not envelope.agent_id
                or type(envelope.epoch) is not int or envelope.epoch < 0
                or type(envelope.active) is not bool or not envelope.request_id
                or not isinstance(envelope.controller_signature, str)):
            raise DownstreamDenied("invalid outbox transition")
        raw = json.dumps(asdict(envelope), sort_keys=True)
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                old = db.execute(
                    "SELECT envelope_json FROM transitions WHERE agent_id=? AND epoch=?",
                    (envelope.agent_id, envelope.epoch),
                ).fetchone()
                if old:
                    if old[0] != raw:
                        raise DownstreamDenied("conflicting transition for epoch")
                else:
                    db.execute(
                        "INSERT INTO transitions(request_id, agent_id, epoch, active, envelope_json)"
                        " VALUES (?,?,?,?,?)",
                        (envelope.request_id, envelope.agent_id, envelope.epoch,
                         int(envelope.active), raw),
                    )
                db.commit()
            except BaseException:
                db.rollback()
                raise

    def pending(self, agent_id: str) -> list[TransitionEnvelope]:
        with self._db() as db:
            rows = db.execute(
                "SELECT envelope_json FROM transitions WHERE agent_id=? AND receipt_json IS NULL"
                " ORDER BY epoch ASC", (agent_id,),
            ).fetchall()
        return [self._parse_envelope(row[0]) for row in rows]

    def verified(self, agent_id: str, epoch: int) -> bool:
        with self._db() as db:
            row = db.execute(
                "SELECT receipt_json FROM transitions WHERE agent_id=? AND epoch=?",
                (agent_id, epoch),
            ).fetchone()
        return row is not None and row[0] is not None

    def deliver_pending(
        self, agent_id: str, send: Callable[[TransitionEnvelope], TransitionReceipt],
    ) -> int:
        """Send in epoch order; stop on first unverified acknowledgment.

        A timeout, malformed receipt, or transport exception leaves the item
        pending. If the remote transaction committed before an ACK was lost,
        a retry must be idempotently accepted by the downstream endpoint.
        """
        delivered = 0
        for envelope in self.pending(agent_id):
            receipt = send(envelope)
            self._verifier.verify(envelope, receipt)
            raw = json.dumps(asdict(receipt), sort_keys=True)
            with self._db() as db:
                db.execute("BEGIN IMMEDIATE")
                try:
                    row = db.execute(
                        "SELECT envelope_json, receipt_json FROM transitions WHERE request_id=?",
                        (envelope.request_id,),
                    ).fetchone()
                    if row is None or self._parse_envelope(row[0]) != envelope:
                        raise DownstreamDenied("outbox transition changed during delivery")
                    if row[1] is None:
                        db.execute(
                            "UPDATE transitions SET receipt_json=? WHERE request_id=?",
                            (raw, envelope.request_id),
                        )
                        delivered += 1
                    elif self._parse_receipt(row[1]) != receipt:
                        raise DownstreamDenied("conflicting acknowledged transition")
                    db.commit()
                except BaseException:
                    db.rollback()
                    raise
        return delivered

    def require_verified(self, agent_id: str, epoch: int) -> None:
        if not self.verified(agent_id, epoch):
            raise PendingDownstreamFence(
                f"downstream fence for agent={agent_id!r} epoch={epoch} is not verified"
            )
