"""Execution identity and epoch authority."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4


@dataclass(frozen=True)
class ExecutionIdentity:
    """Stable identity for one admitted execution."""

    execution_id: str
    agent_id: str
    policy_id: str
    policy_digest: str
    epoch: int = 0
    runtime_id: str | None = None

    def __post_init__(self) -> None:
        for name in ("execution_id", "agent_id", "policy_id", "policy_digest"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        if self.runtime_id is not None and (
            not isinstance(self.runtime_id, str) or not self.runtime_id.strip()
        ):
            raise ValueError("runtime_id must be None or a non-empty string")
        if type(self.epoch) is not int or self.epoch < 0:
            raise ValueError("epoch must be a non-negative integer")

    @classmethod
    def create(cls, agent_id: str, policy_id: str, policy_digest: str, *, epoch: int = 0, runtime_id: str | None = None) -> "ExecutionIdentity":
        return cls(
            execution_id=str(uuid4()),
            agent_id=agent_id,
            policy_id=policy_id,
            policy_digest=policy_digest,
            epoch=epoch,
            runtime_id=runtime_id,
        )

    def advance_epoch(self) -> "ExecutionIdentity":
        return ExecutionIdentity(
            execution_id=self.execution_id,
            agent_id=self.agent_id,
            policy_id=self.policy_id,
            policy_digest=self.policy_digest,
            epoch=self.epoch + 1,
            runtime_id=self.runtime_id,
        )
