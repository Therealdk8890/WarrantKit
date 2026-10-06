"""Explicit AgentContain platform lifecycle state machine."""

from __future__ import annotations

from enum import StrEnum

from .events import Event, EventLog
from .identity import ExecutionIdentity


class LifecycleState(StrEnum):
    NEW = "new"
    ADMITTED = "admitted"
    CONTAINED = "contained"
    DETECTED = "detected"
    FENCED = "fenced"
    HALTED = "halted"
    VERIFIED = "verified"
    RECOVERING = "recovering"
    RECOVERED = "recovered"


_TRANSITIONS: dict[LifecycleState, frozenset[LifecycleState]] = {
    LifecycleState.NEW: frozenset({LifecycleState.ADMITTED}),
    LifecycleState.ADMITTED: frozenset({LifecycleState.CONTAINED, LifecycleState.DETECTED, LifecycleState.FENCED, LifecycleState.HALTED}),
    LifecycleState.CONTAINED: frozenset({LifecycleState.DETECTED, LifecycleState.FENCED, LifecycleState.HALTED, LifecycleState.VERIFIED, LifecycleState.RECOVERING}),
    LifecycleState.DETECTED: frozenset({LifecycleState.CONTAINED, LifecycleState.FENCED, LifecycleState.HALTED}),
    LifecycleState.FENCED: frozenset({LifecycleState.HALTED, LifecycleState.VERIFIED}),
    LifecycleState.HALTED: frozenset({LifecycleState.VERIFIED, LifecycleState.RECOVERING}),
    LifecycleState.VERIFIED: frozenset({LifecycleState.RECOVERING}),
    LifecycleState.RECOVERING: frozenset({LifecycleState.RECOVERED, LifecycleState.CONTAINED}),
    LifecycleState.RECOVERED: frozenset({LifecycleState.CONTAINED, LifecycleState.RECOVERING}),
}


class PlatformStateMachine:
    """State machine with monotonically sequenced evidence events."""

    def __init__(self, identity: ExecutionIdentity) -> None:
        self.identity = identity
        self.state = LifecycleState.NEW
        self.events = EventLog()
        self.event_history: list[EventLog] = []
        self._sequence = 0

    def transition(self, target: LifecycleState, *, event_name: str, details: dict[str, str] | None = None) -> Event:
        if target not in _TRANSITIONS[self.state]:
            raise ValueError(f"invalid lifecycle transition: {self.state} -> {target}")
        self._sequence += 1
        event = Event.create(
            event_name,
            self.identity.execution_id,
            self.identity.epoch,
            self._sequence,
            details=details,
        )
        self.events.append(event)
        self.state = target
        return event

    def admit(self, details: dict[str, str] | None = None) -> Event:
        return self.transition(
            LifecycleState.ADMITTED,
            event_name="admission_verified",
            details=details,
        )

    def contain(self) -> Event:
        return self.transition(LifecycleState.CONTAINED, event_name="containment_verified")

    def detect(self, details: dict[str, str] | None = None) -> Event:
        return self.transition(LifecycleState.DETECTED, event_name="anomaly_detected", details=details)

    def fence(self) -> Event:
        return self.transition(LifecycleState.FENCED, event_name="fence_requested")

    def halt(self) -> Event:
        return self.transition(LifecycleState.HALTED, event_name="halt_requested")

    def verify(self) -> Event:
        return self.transition(LifecycleState.VERIFIED, event_name="verification_completed")

    def recover(self) -> Event:
        return self.transition(LifecycleState.RECOVERING, event_name="recovery_requested")

    def start_new_epoch(self, runtime_epoch: int) -> None:
        """Archive the current epoch and adopt the runtime-authoritative next epoch."""
        if isinstance(runtime_epoch, bool) or not isinstance(runtime_epoch, int):
            raise TypeError("runtime epoch must be an integer")
        expected_epoch = self.identity.epoch + 1
        if runtime_epoch != expected_epoch:
            raise RuntimeError(
                f"runtime epoch {runtime_epoch} does not match "
                f"expected platform epoch {expected_epoch}"
            )
        self.event_history.append(self.events)
        self.identity = self.identity.advance_epoch()
        self.events = EventLog()
        self._sequence = 0

    def recovered(self, runtime_epoch: int) -> Event:
        """Record recovery only when the runtime-authoritative epoch advances exactly once."""
        self.start_new_epoch(runtime_epoch)
        return self.transition(
            LifecycleState.RECOVERED,
            event_name="runtime_recovery_complete",
        )

    def recontain(self) -> Event:
        """Record a fresh enforcement verification for an already-contained runtime."""
        if self.state is not LifecycleState.CONTAINED:
            raise ValueError("recontainment requires an already-contained runtime")
        self._sequence += 1
        event = Event.create(
            "recontainment_verified",
            self.identity.execution_id,
            self.identity.epoch,
            self._sequence,
        )
        self.events.append(event)
        return event
