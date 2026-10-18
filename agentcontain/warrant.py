"""Typed, transport-neutral Warrant authority contract.

A Warrant is an authorization object, not enforcement evidence. Verification
binds it to the execution identity and current runtime epoch; evidence is
validated separately by the existing evidence layer.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Mapping


SCHEMA_VERSION = "warrantkit.warrant/v1"


class RevocationState(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"


@dataclass(frozen=True)
class WarrantSubject:
    agent_id: str
    execution_id: str


@dataclass(frozen=True)
class WarrantAuthority:
    policy_id: str
    policy_digest: str
    capabilities: tuple[str, ...] = ()
    constraints: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class WarrantRuntime:
    runtime_id: str
    epoch: int


@dataclass(frozen=True)
class WarrantValidity:
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class WarrantLifecycle:
    state: RevocationState = RevocationState.ACTIVE
    revoked_at: datetime | None = None


@dataclass(frozen=True)
class EvidenceRequirements:
    enforcement: tuple[str, ...] = ()
    observation: tuple[str, ...] = ()
    verification: tuple[str, ...] = ()


@dataclass(frozen=True)
class Warrant:
    """Machine-checkable authority for one execution in one runtime epoch."""

    warrant_id: str
    issuer: str
    subject: WarrantSubject
    authority: WarrantAuthority
    runtime: WarrantRuntime
    validity: WarrantValidity
    lifecycle: WarrantLifecycle = WarrantLifecycle()
    evidence_requirements: EvidenceRequirements = EvidenceRequirements()
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name, value in (
            ("warrant_id", self.warrant_id),
            ("issuer", self.issuer),
            ("agent_id", self.subject.agent_id),
            ("execution_id", self.subject.execution_id),
            ("policy_id", self.authority.policy_id),
            ("policy_digest", self.authority.policy_digest),
            ("runtime_id", self.runtime.runtime_id),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must not be empty")
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported warrant schema: {self.schema_version}")
        if isinstance(self.runtime.epoch, bool) or not isinstance(self.runtime.epoch, int) or self.runtime.epoch < 0:
            raise ValueError("runtime epoch must be a non-negative integer")
        if self.validity.issued_at.tzinfo is None or self.validity.expires_at.tzinfo is None:
            raise ValueError("warrant validity timestamps must be timezone-aware")
        if self.validity.expires_at <= self.validity.issued_at:
            raise ValueError("warrant expires_at must be after issued_at")
        if self.lifecycle.state == RevocationState.REVOKED and self.lifecycle.revoked_at is None:
            raise ValueError("revoked warrant requires revoked_at")
        if self.lifecycle.state == RevocationState.ACTIVE and self.lifecycle.revoked_at is not None:
            raise ValueError("active warrant cannot have revoked_at")

    @classmethod
    def issue(
        cls,
        *,
        warrant_id: str,
        issuer: str,
        agent_id: str,
        execution_id: str,
        policy: "PolicyLike",
        runtime_id: str,
        epoch: int,
        issued_at: datetime,
        expires_at: datetime,
        capabilities: tuple[str, ...] = (),
        constraints: tuple[tuple[str, str], ...] = (),
        evidence_requirements: EvidenceRequirements | None = None,
    ) -> "Warrant":
        """Issue authority from an accepted policy; never from evidence."""
        # PolicyBundle is the accepted-policy representation used by the
        # platform; raw Policy remains supported for transport-neutral callers.
        policy_digest = getattr(policy, "policy_digest", None)
        if policy_digest is None:
            policy_digest = policy.digest
        accepted_policy = getattr(policy, "policy", policy)
        policy_capabilities = set(getattr(accepted_policy, "capabilities", ()))
        requested_capabilities = tuple(capabilities)
        if set(requested_capabilities) - policy_capabilities:
            raise ValueError("warrant capabilities exceed accepted policy")
        requested_constraints = tuple(constraints)
        if requested_constraints:
            raise ValueError(
                "warrant constraints are unsupported until accepted policy defines constraint semantics"
            )
        return cls(
            warrant_id=warrant_id,
            issuer=issuer,
            subject=WarrantSubject(agent_id, execution_id),
            authority=WarrantAuthority(
                policy_id=policy.policy_id,
                policy_digest=policy_digest,
                capabilities=requested_capabilities,
                constraints=requested_constraints,
            ),
            runtime=WarrantRuntime(runtime_id, epoch),
            validity=WarrantValidity(issued_at, expires_at),
            evidence_requirements=evidence_requirements or EvidenceRequirements(),
        )

    def revoke(self, *, revoked_at: datetime) -> "Warrant":
        """Return a revoked copy; revocation cannot be undone by the agent."""
        return Warrant(
            warrant_id=self.warrant_id,
            issuer=self.issuer,
            subject=self.subject,
            authority=self.authority,
            runtime=self.runtime,
            validity=self.validity,
            lifecycle=WarrantLifecycle(RevocationState.REVOKED, revoked_at),
            evidence_requirements=self.evidence_requirements,
            schema_version=self.schema_version,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "warrant_id": self.warrant_id,
            "issuer": self.issuer,
            "subject": {
                "agent_id": self.subject.agent_id,
                "execution_id": self.subject.execution_id,
            },
            "authority": {
                "policy_id": self.authority.policy_id,
                "policy_digest": self.authority.policy_digest,
                "capabilities": list(self.authority.capabilities),
                "constraints": {k: v for k, v in self.authority.constraints},
            },
            "runtime": {
                "runtime_id": self.runtime.runtime_id,
                "epoch": self.runtime.epoch,
            },
            "validity": {
                "issued_at": self.validity.issued_at.astimezone(timezone.utc).isoformat(),
                "expires_at": self.validity.expires_at.astimezone(timezone.utc).isoformat(),
            },
            "lifecycle": {
                "state": self.lifecycle.state.value,
                "revoked_at": (
                    self.lifecycle.revoked_at.astimezone(timezone.utc).isoformat()
                    if self.lifecycle.revoked_at else None
                ),
            },
            "evidence_requirements": {
                "enforcement": list(self.evidence_requirements.enforcement),
                "observation": list(self.evidence_requirements.observation),
                "verification": list(self.evidence_requirements.verification),
            },
        }

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "Warrant":
        if not isinstance(document, Mapping):
            raise TypeError("warrant must be a mapping")
        expected = {
            "schema_version", "warrant_id", "issuer", "subject", "authority",
            "runtime", "validity", "lifecycle", "evidence_requirements",
        }
        if set(document) != expected:
            raise ValueError("warrant has an invalid shape")
        subject = document["subject"]
        authority = document["authority"]
        runtime = document["runtime"]
        validity = document["validity"]
        lifecycle = document["lifecycle"]
        requirements = document["evidence_requirements"]
        if not all(isinstance(x, Mapping) for x in (subject, authority, runtime, validity, lifecycle, requirements)):
            raise TypeError("warrant nested fields must be mappings")
        constraints = authority.get("constraints", {})
        if not isinstance(constraints, Mapping):
            raise TypeError("warrant constraints must be a mapping")
        return cls(
            warrant_id=document["warrant_id"],
            issuer=document["issuer"],
            subject=WarrantSubject(subject["agent_id"], subject["execution_id"]),
            authority=WarrantAuthority(
                authority["policy_id"],
                authority["policy_digest"],
                tuple(authority.get("capabilities", ())),
                tuple(sorted((str(k), str(v)) for k, v in constraints.items())),
            ),
            runtime=WarrantRuntime(runtime["runtime_id"], runtime["epoch"]),
            validity=WarrantValidity(
                datetime.fromisoformat(validity["issued_at"]),
                datetime.fromisoformat(validity["expires_at"]),
            ),
            lifecycle=WarrantLifecycle(
                RevocationState(lifecycle["state"]),
                datetime.fromisoformat(lifecycle["revoked_at"]) if lifecycle.get("revoked_at") else None,
            ),
            evidence_requirements=EvidenceRequirements(
                tuple(requirements.get("enforcement", ())),
                tuple(requirements.get("observation", ())),
                tuple(requirements.get("verification", ())),
            ),
            schema_version=document["schema_version"],
        )


class PolicyLike:
    policy_id: str
    digest: str


def verify_warrant(
    warrant: Warrant,
    *,
    execution_id: str,
    agent_id: str,
    policy_id: str,
    policy_digest: str,
    runtime_id: str,
    epoch: int,
    now: datetime | None = None,
) -> None:
    """Fail closed unless the Warrant authorizes this exact execution epoch.

    This verifier consumes authority inputs only. Evidence cannot make an
    otherwise-invalid Warrant valid.
    """
    if not isinstance(warrant, Warrant):
        raise TypeError("warrant must be a Warrant")
    if warrant.authority.constraints:
        raise ValueError(
            "warrant constraints are unsupported until accepted policy defines constraint semantics"
        )
    if warrant.lifecycle.state != RevocationState.ACTIVE:
        raise ValueError("warrant is revoked")
    if warrant.subject.execution_id != execution_id:
        raise ValueError("warrant execution_id does not match")
    if warrant.subject.agent_id != agent_id:
        raise ValueError("warrant agent_id does not match")
    if warrant.authority.policy_id != policy_id:
        raise ValueError("warrant policy_id does not match")
    if warrant.authority.policy_digest != policy_digest:
        raise ValueError("warrant policy_digest does not match")
    if warrant.runtime.runtime_id != runtime_id:
        raise ValueError("warrant runtime_id does not match")
    if warrant.runtime.epoch != epoch:
        raise ValueError("warrant epoch does not match current runtime epoch")
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("verification time must be timezone-aware")
    if current < warrant.validity.issued_at:
        raise ValueError("warrant is not yet valid")
    if current >= warrant.validity.expires_at:
        raise ValueError("warrant has expired")
