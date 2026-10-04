#!/usr/bin/env python3
"""Independent verifier for the portable runtime-pinned evidence contract."""
from __future__ import annotations
import hashlib, json, sys
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

SCHEMA_VERSION = "agentcontain.evidence/v2"
BINDING_SCHEMA = "agentcontain.runtime-binding/v1"
VALID_STATUSES = {"observed", "verified", "degraded", "tampered", "incomplete"}
REQUIRED_ENVELOPE_KEYS = {"schema_version","execution","events","enforcement","verification","proof","receipt","governance","provenance","external_evidence"}
REQUIRED_BINDING_KEYS = {"schema_version","runtime_id","agent_id","epoch","authority","enforcement","observation"}

def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

def fail(message: str) -> None:
    raise ValueError(message)

def digest_record(record: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(record).encode("utf-8")).hexdigest()

def parse_time(label: str, value: Any) -> float:
    if isinstance(value, bool): fail(f"{label} timestamp is invalid")
    if isinstance(value, (int, float)): return float(value)
    if isinstance(value, str):
        try: return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError as exc: raise ValueError(f"{label} timestamp is not ISO-8601") from exc
    fail(f"{label} timestamp is required")

def verify(document: Mapping[str, Any]) -> None:
    if set(document) != REQUIRED_ENVELOPE_KEYS: fail("evidence envelope has an invalid shape")
    if document["schema_version"] != SCHEMA_VERSION: fail("unsupported evidence schema")
    execution = document["execution"]
    if not isinstance(execution, Mapping): fail("execution must be a mapping")
    required_execution = {"execution_id","agent_id","policy_id","policy_digest","epoch"}
    if not required_execution <= set(execution): fail("execution identity is incomplete")
    if not isinstance(execution["epoch"], int) or isinstance(execution["epoch"], bool) or execution["epoch"] < 1:
        fail("execution epoch must be a positive integer")
    events = document["events"]
    if not isinstance(events, list) or not events: fail("verified evidence requires events")
    for expected_sequence, event in enumerate(events, 1):
        if not isinstance(event, Mapping): fail("event must be a mapping")
        if event.get("execution_id") != execution["execution_id"]: fail("event execution_id does not match execution")
        if event.get("epoch", execution["epoch"]) != execution["epoch"]: fail("event epoch does not match execution")
        if event.get("sequence") != expected_sequence: fail("event sequence must be contiguous starting at 1")
    verification = document["verification"]
    if not isinstance(verification, Mapping): fail("verification must be a mapping")
    if verification.get("status") not in VALID_STATUSES: fail("invalid verification status")
    if verification.get("status") != "verified": fail("portable verifier requires status=verified")
    proof = document["proof"]
    if not isinstance(proof, Mapping) or not isinstance(proof.get("runtime_binding"), Mapping):
        fail("runtime-pinned evidence binding is required")
    binding = proof["runtime_binding"]
    if set(binding) != REQUIRED_BINDING_KEYS: fail("runtime binding has an invalid shape")
    if binding["schema_version"] != BINDING_SCHEMA: fail("unsupported runtime binding schema")
    if binding["runtime_id"] != execution.get("runtime_id"): fail("runtime binding runtime_id does not match execution")
    if binding["agent_id"] != execution["agent_id"]: fail("runtime binding agent_id does not match execution")
    if binding["epoch"] != execution["epoch"]: fail("runtime binding epoch does not match execution")
    if not isinstance(binding["runtime_id"], str) or not binding["runtime_id"].strip(): fail("runtime binding runtime_id must not be empty")

    for label in ("authority","enforcement","observation"):
        item = binding[label]
        if not isinstance(item, Mapping): fail(f"runtime binding {label} must be a mapping")
        record = item.get("record")
        if not isinstance(record, Mapping): fail(f"runtime binding {label} record is required")
        if item.get("digest") != digest_record(record): fail(f"runtime binding {label} digest does not match record")
        if record.get("runtime_id") != binding["runtime_id"]: fail(f"runtime binding {label} runtime_id does not match")
        if record.get("agent_id") != binding["agent_id"]: fail(f"runtime binding {label} agent_id does not match")
        if record.get("epoch") != binding["epoch"]: fail(f"runtime binding {label} epoch does not match")

    authority, enforcement, observation = (binding[x]["record"] for x in ("authority","enforcement","observation"))
    # Bind runtime evidence to the exact authority presented for this execution.
    # Shared runtime/agent/epoch identity alone is insufficient: evidence must
    # not be transferable across distinct execution authorities.
    for field in ("execution_id", "policy_id", "policy_digest"):
        if authority.get(field) != execution.get(field):
            fail(f"runtime binding authority {field} does not match execution")
    if authority.get("revoked") is not True: fail("runtime binding requires explicit authority revocation evidence")
    if enforcement.get("action") not in {"KILL","FENCE"}: fail("runtime binding enforcement action must be KILL or FENCE")
    if enforcement.get("external_boundary") is not True: fail("runtime binding enforcement must be external to the agent")
    if observation.get("state") not in {"TERMINATED","FENCED","contained","halted"}: fail("runtime binding observation state is not terminal")
    if observation.get("can_execute") is not False: fail("runtime binding observation does not prove non-executability")

    for label, item, record, fields in (
        ("authority",binding["authority"],authority,("revoked","revoked_at")),
        ("enforcement",binding["enforcement"],enforcement,("action","external_boundary","occurred_at")),
        ("observation",binding["observation"],observation,("state","observed_at")),
    ):
        for field in fields:
            if field in item and item[field] != record.get(field): fail(f"runtime binding {label} {field} does not match record")

    revoked_at = parse_time("authority revoked_at", authority.get("revoked_at"))
    occurred_at = parse_time("enforcement occurred_at", enforcement.get("occurred_at"))
    observed_at = parse_time("observation observed_at", observation.get("observed_at"))
    if occurred_at < revoked_at: fail("runtime binding enforcement predates authority revocation")
    if observed_at < occurred_at: fail("runtime binding observation predates enforcement")

def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} EVIDENCE.json", file=sys.stderr); return 2
    try:
        document = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
        if not isinstance(document, Mapping): raise ValueError("evidence document must be a JSON object")
        verify(document)
    except Exception as exc:
        print(f"REJECTED: {exc}", file=sys.stderr); return 1
    print("VERIFIED"); return 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
