"""Small operator-facing WarrantKit CLI."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .engine import (
    admit,
    build_agentcontainment_engine,
    containment_receipt,
    contain,
    evidence_envelope,
)
from .policy import Policy


def _policy_from_args(args: argparse.Namespace) -> Policy:
    return Policy(policy_id=args.policy, capabilities=tuple(args.capability), allowed_egress=tuple(args.egress))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="warrantkit", description="WarrantKit runtime authorization, enforcement, and proof platform for autonomous AI agents.")
    sub = parser.add_subparsers(dest="command", required=True)
    inspect = sub.add_parser("inspect", help="inspect an evidence envelope as an operator incident")
    inspect.add_argument("--evidence-file", required=True, help="JSON evidence envelope produced by WarrantKit")
    inspect.add_argument("--json", action="store_true", help="emit the complete operator view as JSON")
    demo = sub.add_parser("demo", help="run the stale-Warrant replay proof (or the simulated lifecycle demo)")
    demo.add_argument("mode", nargs="?", choices=("replay", "lifecycle"), default="replay", help="replay a stale Warrant (default) or show the simulated lifecycle")
    run = sub.add_parser("run", help="admit an execution and optionally contain it")
    run.add_argument("--policy", required=True, help="policy identifier")
    run.add_argument("--agent-id", default="agent", help="agent identity")
    run.add_argument("--capability", action="append", default=[], help="declared capability")
    run.add_argument("--egress", action="append", default=[], help="allowed egress target")
    run.add_argument("--cgroup-path", help="existing Linux cgroup-v2 path for this workload")
    run.add_argument("--receipt-secret-file", help="read the HMAC receipt secret from a file instead of exposing it in argv")
    run.add_argument("--receipt-secret-env", default="WARRANTKIT_RECEIPT_SECRET", help="environment variable containing the HMAC receipt secret")
    run.add_argument("--evidence-output", help="write the complete evidence envelope to this JSON file")
    run.add_argument("--contain", action="store_true", help="invoke external containment immediately after admission")
    run.add_argument("--json", action="store_true", help="emit machine-readable execution state")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "inspect":
        try:
            from .evidence import EvidenceEnvelope
            from .operator import OperatorIncidentView
            envelope = EvidenceEnvelope.from_json(Path(args.evidence_file).read_text(encoding="utf-8"))
            view = OperatorIncidentView.from_evidence(envelope)
            if args.json:
                print(json.dumps(view.to_dict(), sort_keys=True, indent=2))
            else:
                incident = view.incident
                print(f"Incident {incident.incident_id}")
                print(f"  Agent:        {view.agent.get('agent_id', 'unknown')}")
                print(f"  Policy:       {view.policy.get('policy_id', 'unknown')}")
                print(f"  Event:        {incident.trigger or 'none'}")
                print(f"  Status:       {incident.status.value.upper()}")
                print(f"  Proof:        {incident.proof_status}")
                if view.receipt_id:
                    print(f"  Receipt:      {view.receipt_id}")
                print("  Timeline:")
                for event in view.timeline:
                    print(f"    {event.sequence}. {event.name}")
            return 0
        except Exception as exc:
            print(f"warrantkit: {exc}", file=sys.stderr)
            return 1
    if args.command == "demo":
        from .demo import run_demo, run_stale_warrant_demo
        if args.mode == "lifecycle":
            return run_demo()
        return run_stale_warrant_demo()
    if args.command == "run":
        policy = _policy_from_args(args)
        try:
            engine = build_agentcontainment_engine(args.agent_id, cgroup_path=args.cgroup_path)
            admission = admit(policy, agent_id=args.agent_id, engine=engine)
            report = contain(admission) if args.contain else None

            receipt_secret = None
            if args.receipt_secret_file:
                receipt_secret = Path(args.receipt_secret_file).read_text(encoding="utf-8").rstrip("\r\n").encode("utf-8")
            elif args.receipt_secret_env:
                configured_secret = os.environ.get(args.receipt_secret_env)
                if configured_secret:
                    receipt_secret = configured_secret.encode("utf-8")
                elif args.receipt_secret_env == "WARRANTKIT_RECEIPT_SECRET":
                    legacy_secret = os.environ.get("AGENTCONTAIN_RECEIPT_SECRET")
                    if legacy_secret:
                        receipt_secret = legacy_secret.encode("utf-8")

            receipt = (
                containment_receipt(admission, receipt_secret)
                if receipt_secret is not None and report is not None
                else None
            )
            envelope = evidence_envelope(admission)
            if receipt is not None:
                envelope = envelope.with_receipt(receipt.to_dict())

            payload = {
                "execution_id": admission.identity.execution_id,
                "agent_id": admission.identity.agent_id,
                "policy_id": admission.identity.policy_id,
                "policy_digest": admission.identity.policy_digest,
                "epoch": admission.identity.epoch,
                "state": admission.machine.state.value,
                "events": [event.to_dict() for event in admission.machine.events.events],
            }
            if report is not None:
                payload["containment"] = {
                    "complete": report.complete,
                    "certified": getattr(report, "certified", False),
                    "durable": getattr(report, "durable", False),
                    "external_verified": getattr(report, "external_verified", False),
                    "enforcement_latency_seconds": getattr(report, "enforcement_latency_seconds", None),
                    "failures": list(getattr(report, "failures", ())),
                }
                if receipt is not None:
                    payload["receipt"] = receipt.to_dict()

            if args.evidence_output:
                Path(args.evidence_output).write_text(
                    envelope.to_json() + "\n",
                    encoding="utf-8",
                )

            if args.json:
                print(json.dumps(payload, sort_keys=True, indent=2))
            else:
                print(f"WarrantKit execution {payload['execution_id']}")
                print(f"  Agent:  {payload['agent_id']}")
                print(f"  Policy: {payload['policy_id']}")
                print(f"  Epoch:  {payload['epoch']}")
                print(f"  State:  {payload['state'].upper()}")
                for event in admission.machine.events.events:
                    print(f"  Event:  {event.name}")
                if report is not None:
                    status = "VERIFIED" if report.certified and report.durable else "DEGRADED"
                    print(f"  Containment: {status}")
                if args.evidence_output:
                    print(f"  Evidence: {args.evidence_output}")
            return 0
        except Exception as exc:
            print(f"warrantkit: {exc}", file=sys.stderr)
            return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
