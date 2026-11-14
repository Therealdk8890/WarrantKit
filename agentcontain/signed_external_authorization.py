"""Opt-in Ed25519-signed external decision import, with durable replay protection.

This is a *specific raw-JSON provider profile*, not an OIDC/OAuth verifier.
The trusted public key, issuer and audience MUST be provisioned out of band.
The existing import_authorization() remains a structural converter only.
"""
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any

from .external_authorization import import_authorization
from .policy import Policy
from .warrant import Warrant


# Domain-separated signature to prevent cross-protocol Ed25519 replay.
SIGNATURE_DOMAIN = b"WARRANTKIT-SIGNED-EXTERNAL-AUTHORIZATION-V1\x00"


class ExternalDecisionAuthenticationError(ValueError):
    """External decision cannot be promoted to local authority."""


class SQLiteDecisionReplayStore:
    """Controller-owned durable, never-reuse decision-ID registry.

    Place this DB in a protected, persistent directory. This reference store
    does not provide distributed consistency across separate databases/hosts.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if not self.path.is_absolute():
            raise ValueError("replay database path must be absolute and persistent")
        with closing(self._connect()) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS consumed_decisions ("
                "issuer TEXT NOT NULL, audience TEXT NOT NULL, decision_id TEXT NOT NULL, "
                "PRIMARY KEY (issuer, audience, decision_id))"
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self.path), timeout=10, isolation_level=None)

    def claim(self, issuer: str, audience: str, decision_id: str) -> bool:
        """Atomically consume the identity; False means already observed."""
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    "INSERT INTO consumed_decisions VALUES (?, ?, ?)",
                    (issuer, audience, decision_id),
                )
            except sqlite3.IntegrityError:
                connection.execute("ROLLBACK")
                return False
            connection.execute("COMMIT")
            return True


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ExternalDecisionAuthenticationError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ExternalDecisionAuthenticationError("non-JSON numeric constant")


def import_signed_authorization(
    signed_document: bytes,
    *,
    signature: bytes,
    trusted_public_key: bytes,
    expected_issuer: str,
    expected_audience: str,
    expected_agent_id: str,
    expected_execution_id: str,
    replay_store: SQLiteDecisionReplayStore,
    policy: Policy,
    runtime_id: str,
    epoch: int,
    now: datetime | None = None,
) -> Warrant:
    """Verify exact signed JSON bytes before issuing an epoch-bound Warrant.

    The payload has the v1 import_authorization fields plus a signed "audience"
    string. It is signed directly with Ed25519 (not a JSON serialization
    reconstructed by the verifier). This is NOT a JWT/JWS protocol.

    The replay store is authoritative for one deployment. Callers MUST supply
    their own trusted, independently provisioned issuer key and persistent
    controller-owned replay DB; do not accept them from the untrusted payload.
    """
    verification_time = now if now is not None else datetime.now(timezone.utc)
    if verification_time.tzinfo is None or verification_time.utcoffset() is None:
        raise ExternalDecisionAuthenticationError("verification time must be timezone-aware")
    if any(type(value) is not str or not value.strip() for value in (
        expected_issuer, expected_audience, expected_agent_id, expected_execution_id
    )):
        raise ExternalDecisionAuthenticationError("expected identity and audience are required")
    if not isinstance(replay_store, SQLiteDecisionReplayStore):
        raise ExternalDecisionAuthenticationError("controller-owned replay store required")
    if type(signed_document) is not bytes or not 0 < len(signed_document) <= 65536:
        raise ExternalDecisionAuthenticationError("signed decision must be bounded JSON bytes")
    if type(signature) is not bytes or len(signature) != 64:
        raise ExternalDecisionAuthenticationError("64-byte Ed25519 signature required")
    if type(trusted_public_key) is not bytes or len(trusted_public_key) != 32:
        raise ExternalDecisionAuthenticationError("independently trusted Ed25519 key required")

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise ExternalDecisionAuthenticationError(
            "cryptography required for signed external authorization"
        ) from exc

    try:
        Ed25519PublicKey.from_public_bytes(trusted_public_key).verify(signature, SIGNATURE_DOMAIN + signed_document)
    except (InvalidSignature, ValueError) as exc:
        raise ExternalDecisionAuthenticationError("external decision signature invalid") from exc

    try:
        document = json.loads(
            signed_document.decode("utf-8"),
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, ValueError, TypeError) as exc:
        raise ExternalDecisionAuthenticationError("signed decision is not valid strict JSON") from exc
    if not isinstance(document, dict):
        raise ExternalDecisionAuthenticationError("signed decision must be a JSON object")
    if document.get("audience") != expected_audience:
        raise ExternalDecisionAuthenticationError("external decision audience mismatch")
    for key, expected in (
        ("issuer", expected_issuer),
        ("subject_agent_id", expected_agent_id),
        ("subject_execution_id", expected_execution_id),
    ):
        if document.get(key) != expected:
            raise ExternalDecisionAuthenticationError(f"external decision {key} mismatch")

    # Strip exactly the signed provider-profile extension before applying the
    # existing strict structural, policy, epoch and validity checks.
    raw = {key: value for key, value in document.items() if key != "audience"}
    warrant = import_authorization(
        raw, policy=policy, runtime_id=runtime_id, epoch=epoch, now=verification_time
    )
    issued_at = datetime.fromisoformat(raw["issued_at"])
    expires_at = datetime.fromisoformat(raw["expires_at"])
    if expires_at - issued_at > timedelta(minutes=15):
        raise ExternalDecisionAuthenticationError("external decision lifetime exceeds 15 minutes")

    try:
        claimed = replay_store.claim(expected_issuer, expected_audience, raw["decision_id"])
    except sqlite3.Error as exc:
        raise ExternalDecisionAuthenticationError("replay store unavailable") from exc
    if not claimed:
        raise ExternalDecisionAuthenticationError("external decision replay")
    return warrant
