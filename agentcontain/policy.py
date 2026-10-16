"""Deterministic platform policy model.

allowed_egress is part of policy identity and distribution, but remains
declarative until an enforcement provider explicitly consumes it. It must not
be treated as runtime enforcement merely because it is present in a Policy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from collections.abc import Mapping
from types import MappingProxyType


@dataclass(frozen=True)
class Policy:
    """Versioned policy describing the authority granted to an execution.

    allowed_egress is a declarative policy field. Its presence in the
    canonical policy and digest does not itself configure or prove host-level
    egress enforcement.
    """

    policy_id: str
    version: int = 1
    allowed_egress: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.policy_id, str) or not self.policy_id.strip():
            raise ValueError("policy_id must not be empty")
        if isinstance(self.version, bool) or not isinstance(self.version, int):
            raise TypeError("version must be an integer")
        if self.version < 1:
            raise ValueError("version must be >= 1")

        for name in ("allowed_egress", "capabilities"):
            values = getattr(self, name)
            if not isinstance(values, (tuple, list)):
                raise TypeError(f"{name} must be a sequence of strings")
            normalized = tuple(values)
            if any(not isinstance(value, str) or not value.strip() for value in normalized):
                raise ValueError(f"{name} entries must be non-empty strings")
            object.__setattr__(self, name, normalized)

        if not isinstance(self.metadata, Mapping):
            raise TypeError("metadata must be a mapping of strings to strings")
        metadata = dict(self.metadata)
        if any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in metadata.items()
        ):
            raise TypeError("metadata keys and values must be strings")
        object.__setattr__(self, "metadata", MappingProxyType(metadata))

    def __deepcopy__(self, memo):
        """Reuse this deeply immutable policy in wrapper authority snapshots."""
        memo[id(self)] = self
        return self

    def canonical(self) -> str:
        payload = {
            "capabilities": sorted(self.capabilities),
            "allowed_egress": sorted(self.allowed_egress),
            "metadata": dict(sorted(self.metadata.items())),
            "policy_id": self.policy_id,
            "version": self.version,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.canonical().encode("utf-8")).hexdigest()
