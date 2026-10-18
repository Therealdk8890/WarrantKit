"""Transport-neutral boundary for authorization supplied by an external identity system.

External authorization is an input to WarrantKit admission, not a replacement for
WarrantKit's policy, identity, epoch, or runtime enforcement authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping

from .policy import Policy
from .warrant import EvidenceRequirements, Warrant


SCHEMA_VERSION = "warrantkit.external-authorization/v1"


@dataclass(frozen=True)
class ExternalAuthorizationDecision:
    """A narrow authorization decision imported from an external control plane.

    The decision carries authorization context only. It cannot supply evidence,
    mutate the local policy, select the runtime epoch, or perform enforcement.
    """

    decision_id: str
    issuer: str
    subject_agent_id: str
    subject_execution_id: str
    policy_id: str
    policy_digest: str
    capabilities: tuple[str, ...] = ()
    constraints: tuple[tuple[str, str], ...] = ()
    issued_at: datetime | None = None
    expires_at: datetime | None = None
    decision: str = "allow"
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name, value in (
            ("decision_id", self.decision_id),
            ("issuer", self.issuer),
            ("subject_agent_id", self.subject_agent_id),
            ("subject_execution_id", self.subject_execution_id),
            ("policy_id", self.policy_id),
            ("policy_digest", self.policy_digest),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must not be empty")
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported authorization schema: {self.schema_version}")
        if self.decision != "allow":
            raise ValueError("only allow decisions can be imported as Warrant authority")
        if self.issued_at is not None and self.issued_at.tzinfo is None:
            raise ValueError("issued_at must be timezone-aware")
        if self.expires_at is not None and self.expires_at.tzinfo is None:
            raise ValueError("expires_at must be timezone-aware")
        if self.issued_at is not None and self.expires_at is not None:
            if self.expires_at <= self.issued_at:
                raise ValueError("expires_at must be after issued_at")

    def to_warrant(
        self,
        *,
        policy: Policy,
        runtime_id: str,
        epoch: int,
        issued_at: datetime | None = None,
        expires_at: datetime | None = None,
        evidence_requirements: EvidenceRequirements | None = None,
    ) -> Warrant:
        """Convert external authorization into local, epoch-bound Warrant authority.

        The locally accepted policy remains authoritative. A mismatched external
        policy identity or digest fails closed instead of widening local authority.
        """
        if self.policy_id != policy.policy_id:
            raise ValueError("external authorization policy_id does not match accepted policy")
        if self.policy_digest != policy.digest:
            raise ValueError("external authorization policy_digest does not match accepted policy")
        if self.constraints:
            raise ValueError(
                "external authorization constraints are unsupported until accepted policy defines constraint semantics"
            )
        accepted_capabilities = set(policy.capabilities)
        requested_capabilities = set(self.capabilities)
        if not requested_capabilities.issubset(accepted_capabilities):
            unexpected = sorted(requested_capabilities - accepted_capabilities)
            raise ValueError(
                "external authorization requests capabilities outside accepted policy: "
                + ", ".join(unexpected)
            )
        now = issued_at or self.issued_at or datetime.now(timezone.utc)
        expiry = expires_at or self.expires_at
        if expiry is None:
            raise ValueError("an authorization expiry is required")
        if now.tzinfo is None or expiry.tzinfo is None:
            raise ValueError("warrant validity timestamps must be timezone-aware")
        if self.issued_at is not None and now < self.issued_at:
            raise ValueError("warrant issued_at cannot precede external authorization")
        if self.expires_at is not None and expiry > self.expires_at:
            raise ValueError("warrant expires_at cannot extend external authorization")
        if expiry <= now:
            raise ValueError("warrant expires_at must be after issued_at")
        return Warrant.issue(
            warrant_id=f"external:{self.decision_id}",
            issuer=self.issuer,
            agent_id=self.subject_agent_id,
            execution_id=self.subject_execution_id,
            policy=policy,
            runtime_id=runtime_id,
            epoch=epoch,
            issued_at=now,
            expires_at=expiry,
            capabilities=self.capabilities,
            constraints=self.constraints,
            evidence_requirements=evidence_requirements,
        )


def import_authorization(
    document: Mapping[str, object],
    *,
    policy: Policy,
    runtime_id: str,
    epoch: int,
    now: datetime | None = None,
) -> Warrant:
    """Import a minimal external decision without importing external evidence."""
    required = {
        "schema_version", "decision_id", "issuer", "subject_agent_id",
        "subject_execution_id", "policy_id", "policy_digest", "capabilities",
        "constraints", "issued_at", "expires_at", "decision",
    }
    if set(document) != required:
        raise ValueError("external authorization has an invalid shape")

    string_fields = (
        "schema_version",
        "decision_id",
        "issuer",
        "subject_agent_id",
        "subject_execution_id",
        "policy_id",
        "policy_digest",
        "issued_at",
        "expires_at",
        "decision",
    )
    for field_name in string_fields:
        value = document[field_name]
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"external authorization {field_name} must be a non-empty string")

    raw_capabilities = document["capabilities"]
    if not isinstance(raw_capabilities, list) or any(
        not isinstance(capability, str) or not capability.strip()
        for capability in raw_capabilities
    ):
        raise ValueError("external authorization capabilities must be a list of non-empty strings")

    raw_constraints = document["constraints"]
    if not isinstance(raw_constraints, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in raw_constraints.items()
    ):
        raise ValueError("external authorization constraints must be an object of string keys and values")

    try:
        issued_at = datetime.fromisoformat(document["issued_at"])
        expires_at = datetime.fromisoformat(document["expires_at"])
    except ValueError as exc:
        raise ValueError("external authorization timestamps must be valid ISO-8601 strings") from exc

    decision = ExternalAuthorizationDecision(
        decision_id=document["decision_id"],
        issuer=document["issuer"],
        subject_agent_id=document["subject_agent_id"],
        subject_execution_id=document["subject_execution_id"],
        policy_id=document["policy_id"],
        policy_digest=document["policy_digest"],
        capabilities=tuple(raw_capabilities),
        constraints=tuple(raw_constraints.items()),
        issued_at=issued_at,
        expires_at=expires_at,
        decision=document["decision"],
        schema_version=document["schema_version"],
    )
    warrant = decision.to_warrant(
        policy=policy,
        runtime_id=runtime_id,
        epoch=epoch,
    )
    if now is not None:
        if now.tzinfo is None:
            raise ValueError("verification time must be timezone-aware")
        if now < warrant.validity.issued_at or now >= warrant.validity.expires_at:
            raise ValueError("external authorization is outside its validity window")
    return warrant
