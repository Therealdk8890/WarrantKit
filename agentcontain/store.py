"""Durable, transport-neutral evidence storage primitives."""

from __future__ import annotations

from typing import Protocol

from .evidence import EvidenceEnvelope


class EvidenceStore(Protocol):
    """Persistence boundary that never becomes runtime authority."""

    def put(self, envelope: EvidenceEnvelope) -> EvidenceEnvelope: ...

    def get(self, receipt_id: str) -> EvidenceEnvelope | None: ...

    def exists(self, receipt_id: str) -> bool: ...


class InMemoryEvidenceStore:
    """Reference durable-store semantics for tests and local integrations."""

    def __init__(self) -> None:
        self._items: dict[str, EvidenceEnvelope] = {}
        self._anonymous: list[EvidenceEnvelope] = []

    def put(self, envelope: EvidenceEnvelope) -> EvidenceEnvelope:
        if not isinstance(envelope, EvidenceEnvelope):
            raise TypeError("envelope must be an EvidenceEnvelope")
        snapshot = _snapshot(envelope)
        receipt_id = snapshot.receipt_id
        if receipt_id is None:
            self._anonymous.append(snapshot)
            return _snapshot(snapshot)
        existing = self._items.get(receipt_id)
        if existing is None:
            self._items[receipt_id] = snapshot
            return _snapshot(snapshot)
        if existing.to_json() != snapshot.to_json():
            raise ValueError(f"evidence receipt_id collision: {receipt_id}")
        return _snapshot(existing)

    def get(self, receipt_id: str) -> EvidenceEnvelope | None:
        envelope = self._items.get(receipt_id)
        return _snapshot(envelope) if envelope is not None else None

    def exists(self, receipt_id: str) -> bool:
        return receipt_id in self._items

    def all(self) -> tuple[EvidenceEnvelope, ...]:
        return tuple(_snapshot(item) for item in self._items.values()) + tuple(
            _snapshot(item) for item in self._anonymous
        )


def _snapshot(envelope: EvidenceEnvelope) -> EvidenceEnvelope:
    """Round-trip through canonical JSON to detach mutable nested mappings."""
    return EvidenceEnvelope.from_json(envelope.to_json())
