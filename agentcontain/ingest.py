"""Transport-neutral ingestion boundary for AgentContain evidence."""

from __future__ import annotations

from typing import Protocol

from .evidence import EvidenceEnvelope
from .store import InMemoryEvidenceStore


class EvidenceSink(Protocol):
    """Minimal downstream boundary for accepted evidence."""

    def submit(self, envelope: EvidenceEnvelope) -> EvidenceEnvelope:
        """Accept evidence and return a detached accepted snapshot."""


class InMemoryEvidenceSink:
    """Reference sink for local use and tests.

    Storage semantics are delegated to the reference evidence store so the
    sink and store cannot drift on validation, idempotency, or collision
    handling. The sink intentionally exposes only its ingestion-facing API.
    """

    def __init__(self) -> None:
        self._store = InMemoryEvidenceStore()

    def submit(self, envelope: EvidenceEnvelope) -> EvidenceEnvelope:
        return self._store.put(envelope)

    def get(self, receipt_id: str) -> EvidenceEnvelope | None:
        return self._store.get(receipt_id)

    def all(self) -> tuple[EvidenceEnvelope, ...]:
        return self._store.all()
