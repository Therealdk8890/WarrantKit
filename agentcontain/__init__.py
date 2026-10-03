"""WarrantKit platform primitives.

The platform layer defines policy, execution identity, lifecycle state, structured
events, and transport-neutral evidence around the AgentContainment engine.
"""

from .engine import (
    Admission,
    admit,
    build_agentcontainment_engine,
    containment_receipt,
    detect,
    evidence_envelope,
    halt,
    issue_recovery_authorization,
    recover,
    recontain,
    verify,
)
from .events import Event, EventLog
from .evidence import EvidenceEnvelope, canonical_json
from .external_authorization import ExternalAuthorizationDecision, import_authorization
from .external_evidence import ExternalEvidenceReference, digest_artifact
from .external_handoff import CorrelationState, ExternalEvidenceHandoff, HandoffCorrelation, correlate_handoff
from .verification_result import VerificationResult, VerificationStatus, compose_verification
from .attestation import AttestationEnvelope, Ed25519Signer, Ed25519Verifier
from .fleet import Agent, FleetRegistry, FleetScope, Organization, Project, Runtime
from .fleet_status import FleetPolicyStatus, fleet_policy_status
from .fleet_status_history import FleetPolicyStatusHistory, FleetPolicyStatusSnapshot
from .identity import ExecutionIdentity
from .incident import IncidentStatus, IncidentSummary
from .operator import EvidenceTimelineEvent, OperatorIncidentView
from .policy import Policy
from .policy_assignment import AssignmentState, PolicyAssignment, PolicyAssignmentRegistry
from .policy_reconciliation import (
    RolloutReconciliation,
    TargetReconciliation,
    TargetReconciliationState,
    reconcile_rollout,
)
from .policy_rollout import Rollout, RolloutState
from .policy_distribution import PolicyBundle, PolicyRegistry
from .receipt import WarrantBoundReceipt
from .state import LifecycleState, PlatformStateMachine
from .warrant import (
    EvidenceRequirements,
    RevocationState,
    Warrant,
    WarrantAuthority,
    WarrantLifecycle,
    WarrantRuntime,
    WarrantSubject,
    WarrantValidity,
    verify_warrant,
)
from .store import EvidenceStore, InMemoryEvidenceStore

__all__ = [
    "Admission",
    "Event",
    "EventLog",
    "EvidenceStore",
    "InMemoryEvidenceStore",
    "EvidenceEnvelope",
    "ExternalAuthorizationDecision",
    "import_authorization",
    "ExternalEvidenceReference",
    "digest_artifact",
    "CorrelationState",
    "ExternalEvidenceHandoff",
    "HandoffCorrelation",
    "correlate_handoff",
    "VerificationResult",
    "VerificationStatus",
    "compose_verification",
    "AttestationEnvelope",
    "Ed25519Signer",
    "Ed25519Verifier",
    "Agent",
    "FleetRegistry",
    "FleetScope",
    "Organization",
    "Project",
    "Runtime",
    "FleetPolicyStatus",
    "fleet_policy_status",
    "FleetPolicyStatusHistory",
    "FleetPolicyStatusSnapshot",
    "ExecutionIdentity",
    "IncidentStatus",
    "IncidentSummary",
    "EvidenceTimelineEvent",
    "OperatorIncidentView",
    "LifecycleState",
    "PlatformStateMachine",
    "Policy",
    "AssignmentState",
    "PolicyAssignment",
    "PolicyAssignmentRegistry",
    "TargetReconciliationState",
    "TargetReconciliation",
    "RolloutReconciliation",
    "reconcile_rollout",
    "Rollout",
    "RolloutState",
    "PolicyBundle",
    "PolicyRegistry",
    "WarrantBoundReceipt",
    "admit",
    "build_agentcontainment_engine",
    "canonical_json",
    "containment_receipt",
    "detect",
    "evidence_envelope",
    "halt",
    "issue_recovery_authorization",
    "recover",
    "recontain",
    "verify",
    "EvidenceRequirements",
    "RevocationState",
    "Warrant",
    "WarrantAuthority",
    "WarrantLifecycle",
    "WarrantRuntime",
    "WarrantSubject",
    "WarrantValidity",
    "verify_warrant",
]
