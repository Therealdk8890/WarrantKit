"""Transport-neutral, authenticated downstream transition receipts.

Experimental: production callers must provide an authenticated transport,
separate secret custody and durable delivery/retry.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import secrets
from typing import Callable

from .downstream_commit_fence import DownstreamCommitFence, DownstreamDenied


def _mac(key: bytes, fields: dict[str, object]) -> str:
    payload = json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hmac.new(key, b"warrantkit.downstream.receipt.v1\x00" + payload, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class TransitionEnvelope:
    agent_id: str
    epoch: int
    active: bool
    request_id: str
    controller_signature: str


@dataclass(frozen=True)
class TransitionReceipt:
    agent_id: str
    epoch: int
    active: bool
    request_id: str
    status: str
    signature: str


class TransitionReceiptVerifier:
    def __init__(self, receipt_key: bytes):
        if not isinstance(receipt_key, bytes) or len(receipt_key) < 32:
            raise ValueError("receipt_key must contain at least 32 secret bytes")
        self._key = receipt_key

    def verify(self, expected: TransitionEnvelope, receipt: TransitionReceipt) -> None:
        if not isinstance(receipt, TransitionReceipt):
            raise DownstreamDenied("invalid downstream receipt")
        fields = {"agent_id": expected.agent_id, "epoch": expected.epoch,
                  "active": expected.active, "request_id": expected.request_id,
                  "status": "committed"}
        if (receipt.agent_id != expected.agent_id or type(receipt.epoch) is not int
                or receipt.epoch != expected.epoch or receipt.active is not expected.active
                or receipt.request_id != expected.request_id or receipt.status != "committed"):
            raise DownstreamDenied("downstream receipt does not match transition")
        if not isinstance(receipt.signature, str) or not hmac.compare_digest(
            _mac(self._key, fields), receipt.signature
        ):
            raise DownstreamDenied("downstream receipt authentication failed")


class DownstreamTransitionEndpoint:
    def __init__(self, fence: DownstreamCommitFence, *, receipt_key: bytes):
        if not isinstance(receipt_key, bytes) or len(receipt_key) < 32:
            raise ValueError("receipt_key must contain at least 32 secret bytes")
        self._fence = fence
        self._receipt_key = receipt_key

    def apply(self, envelope: TransitionEnvelope) -> TransitionReceipt:
        if (not isinstance(envelope, TransitionEnvelope) or not envelope.agent_id
                or type(envelope.epoch) is not int or type(envelope.active) is not bool
                or not isinstance(envelope.request_id, str) or not envelope.request_id
                or len(envelope.request_id) > 128):
            raise DownstreamDenied("invalid transition envelope")
        self._fence.transition(agent_id=envelope.agent_id, epoch=envelope.epoch,
                               active=envelope.active, signature=envelope.controller_signature)
        fields = {"agent_id": envelope.agent_id, "epoch": envelope.epoch,
                  "active": envelope.active, "request_id": envelope.request_id,
                  "status": "committed"}
        return TransitionReceipt(**fields, signature=_mac(self._receipt_key, fields))


class VerifiedTransitionDelivery:
    def __init__(self, send: Callable[[TransitionEnvelope], TransitionReceipt],
                 verifier: TransitionReceiptVerifier):
        self._send = send
        self._verifier = verifier

    def deliver(self, envelope: TransitionEnvelope) -> TransitionReceipt:
        receipt = self._send(envelope)
        self._verifier.verify(envelope, receipt)
        return receipt


def new_transition_envelope(fence: DownstreamCommitFence, *,
                            agent_id: str, epoch: int, active: bool) -> TransitionEnvelope:
    return TransitionEnvelope(agent_id=agent_id, epoch=epoch, active=active,
                              request_id=secrets.token_hex(16),
                              controller_signature=fence.sign_transition(
                                  agent_id=agent_id, epoch=epoch, active=active))
