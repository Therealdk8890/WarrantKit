"""Explicit composition of independent WarrantKit verification dimensions.

This module intentionally does not infer truth or authority. It records which
checks succeeded, which are missing, and whether independently sourced evidence
conflicts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class VerificationStatus(StrEnum):
    VERIFIED = "verified"
    INCOMPLETE = "incomplete"
    CONFLICT = "conflict"
    UNAUTHENTICATED = "unauthenticated"


_CHECK_FIELDS = (
    "authority_valid",
    "runtime_valid",
    "authenticated",
    "correlated",
    "anchored",
    "verifier_executed",
)


@dataclass(frozen=True)
class VerificationResult:
    """Machine-readable verification composition result."""

    authority_valid: bool
    runtime_valid: bool
    authenticated: bool
    correlated: bool
    anchored: bool
    verifier_executed: bool
    conflicts: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()
    status: VerificationStatus = field(init=False)

    def __post_init__(self) -> None:
        # Do not allow truthy non-booleans (for example, "false" or 1) to
        # satisfy a security verification dimension.
        for name in _CHECK_FIELDS:
            if type(getattr(self, name)) is not bool:
                raise TypeError(f"{name} must be a bool")

        for name in ("conflicts", "missing"):
            values = getattr(self, name)
            if not isinstance(values, (tuple, list)):
                raise TypeError(f"{name} must be a tuple or list of strings")
            if any(not isinstance(item, str) or not item.strip() for item in values):
                raise ValueError(f"{name} must contain only non-empty strings")
            object.__setattr__(self, name, tuple(values))

        conflicts = self.conflicts
        missing = self.missing

        if conflicts:
            status = VerificationStatus.CONFLICT
        elif not self.authenticated:
            status = VerificationStatus.UNAUTHENTICATED
        elif missing or not all(
            (
                self.authority_valid,
                self.runtime_valid,
                self.correlated,
                self.anchored,
                self.verifier_executed,
            )
        ):
            status = VerificationStatus.INCOMPLETE
        else:
            status = VerificationStatus.VERIFIED

        object.__setattr__(self, "status", status)

    @property
    def is_verified(self) -> bool:
        """Return whether the defined verification procedure established all requirements."""
        return self.status == VerificationStatus.VERIFIED

    @property
    def is_authorized(self) -> bool:
        """Verification never creates authorization authority."""
        return False

    @property
    def claim_is_true(self) -> bool:
        """Verification is not a truth oracle."""
        return False

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "authority_valid": self.authority_valid,
            "runtime_valid": self.runtime_valid,
            "authenticated": self.authenticated,
            "correlated": self.correlated,
            "anchored": self.anchored,
            "verifier_executed": self.verifier_executed,
            "conflicts": list(self.conflicts),
            "missing": list(self.missing),
        }


def compose_verification(
    *,
    authority_valid: bool,
    runtime_valid: bool,
    authenticated: bool,
    correlated: bool,
    anchored: bool,
    verifier_executed: bool,
    conflicts: tuple[str, ...] = (),
    missing: tuple[str, ...] = (),
) -> VerificationResult:
    """Compose independent checks without upgrading any source's authority.

    A result is verified only when authentication, authority, runtime identity,
    correlation, anchoring, and the defined verifier procedure all succeeded.
    Independent conflicts dominate the result. Missing evidence never gets
    silently treated as a successful check.
    """

    return VerificationResult(
        authority_valid=authority_valid,
        runtime_valid=runtime_valid,
        authenticated=authenticated,
        correlated=correlated,
        anchored=anchored,
        verifier_executed=verifier_executed,
        conflicts=conflicts,
        missing=missing,
    )
