"""Data contracts for the evidence-driven agent and its three pipelines."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from diagnostic_intelligence.models.classification import Category
from diagnostic_intelligence.models.evidence import EvidenceType
from diagnostic_intelligence.remediation.approval import ApprovalRecord, ApprovalRequest
from diagnostic_intelligence.remediation.catalogue import VerificationResult
from diagnostic_intelligence.remediation.policy import PolicyDecision, ProposedOperation


class ReasoningMode(StrEnum):
    AI = "ai"          # language model reasons over evidence; output is validated and grounded
    RULES = "rules"    # explicit, labelled deterministic mode (offline/testing); never a silent fallback


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class NextStep(StrEnum):
    COLLECT_MORE = "collect_more"
    PROPOSE_ACTION = "propose_action"
    CONCLUDE = "conclude"
    ASK_USER = "ask_user"


class Observation(BaseModel):
    """A fact the reasoner claims to read from a specific evidence record. Checked by code."""

    model_config = ConfigDict(extra="ignore")

    evidence_id: str = Field(min_length=1, max_length=128)
    field: str = Field(min_length=1, max_length=128)
    value: Any = None


class Hypothesis(BaseModel):
    model_config = ConfigDict(extra="ignore")

    cause_id: str = Field(pattern=r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$", max_length=96)
    title: str = Field(min_length=1, max_length=160)
    explanation: str = Field(min_length=1, max_length=1500)
    observations: list[Observation] = Field(min_length=1, max_length=12)
    confidence: Confidence


class TriageResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    primary_category: Category
    secondary_categories: list[Category] = Field(default_factory=list)
    evidence_types: list[EvidenceType]
    needs_clarification: bool = False
    clarification_question: str | None = None
    explanation: str
    source: ReasoningMode
    model: str | None = None
    rejected_items: list[str] = Field(default_factory=list)


class ReasoningDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str
    hypotheses: list[Hypothesis]
    alternatives_ruled_out: list[str] = Field(default_factory=list)
    uncertainty: str
    next_step: NextStep
    evidence_requests: list[EvidenceType] = Field(default_factory=list)
    evidence_request_reason: str | None = None
    action: ProposedOperation | None = None
    question: str | None = None
    source: ReasoningMode
    model: str | None = None
    rejected_claims: list[str] = Field(default_factory=list)
    llm_calls: int = 0


class SessionStatus(StrEnum):
    NEEDS_CLARIFICATION = "needs_clarification"
    DIAGNOSED = "diagnosed"
    CAUSE_UNDETERMINED = "cause_undetermined"
    AWAITING_APPROVAL = "awaiting_approval"
    RESOLVED = "resolved"
    PARTIALLY_RESOLVED = "partially_resolved"
    NOT_RESOLVED = "not_resolved"
    ACTION_REFUSED = "action_refused"
    APPROVAL_DENIED = "approval_denied"
    REASONING_UNAVAILABLE = "reasoning_unavailable"
    ERROR = "error"


class ExecutionSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command_succeeded: bool
    message: str
    started_at: datetime
    finished_at: datetime


class ActionAttempt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attempt_number: int
    proposal: ProposedOperation
    decision: PolicyDecision
    approval: ApprovalRecord | None = None
    execution: ExecutionSummary | None = None
    verification: VerificationResult | None = None
    outcome: str


class RefusedProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    proposal: ProposedOperation
    decision: PolicyDecision


class TimelineEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    stage: str
    message: str
    data: dict[str, Any] = Field(default_factory=dict)


class RuleCrossCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    description: str = "Deterministic correlation rules run independently over the same evidence, for comparison only."
    findings: list[dict[str, Any]]
    agrees_with_reasoner: bool | None


class SessionReport(BaseModel):
    """Everything the UI, CLI and audit need. JSON-serializable."""

    model_config = ConfigDict(extra="forbid")

    session_id: str
    pipeline: dict[str, Any]
    reasoning_mode: ReasoningMode
    reasoning_model: str | None
    complaint: str
    primary_category: Category | None
    secondary_categories: list[Category]
    status: SessionStatus
    headline: str
    diagnosis: list[Hypothesis]
    diagnosis_confirmed: bool | None
    alternatives_ruled_out: list[str]
    uncertainty: str
    evidence_summary: list[str]
    evidence_count: int
    actions: list[ActionAttempt]
    refused_proposals: list[RefusedProposal]
    recommendation: dict[str, Any] | None
    pending_approval: ApprovalRequest | None
    rule_cross_check: RuleCrossCheck | None
    timeline: list[TimelineEvent]
    warnings: list[str]
    clarification_question: str | None
