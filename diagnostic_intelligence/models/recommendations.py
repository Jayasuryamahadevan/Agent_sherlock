"""Structured root-cause findings and user/API recommendations."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from diagnostic_intelligence.models.classification import Category
from diagnostic_intelligence.models.diagnostic_plan import EvidenceRequest


class DiagnosticStatus(StrEnum):
    CLASSIFIED = "classified"
    COLLECTING_EVIDENCE = "collecting_evidence"
    ANALYSIS_COMPLETE = "analysis_complete"
    NEEDS_CLARIFICATION = "needs_clarification"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


class RemediationCandidate(BaseModel):
    """A policy-engine input; never an instruction to execute an operation."""

    model_config = ConfigDict(extra="forbid")

    action_candidate_id: str
    related_cause_id: str
    action_type: str
    purpose: str
    expected_effect: str
    risk_hint: str
    supporting_evidence_ids: list[str]
    preconditions: list[str]
    verification_criteria: list[str]


class RootCauseCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cause_id: str
    title: str
    explanation: str
    supporting_evidence_ids: list[str]
    contradicting_evidence_ids: list[str]
    confidence_score: float = Field(ge=0, le=1)
    confidence_rationale: str
    missing_evidence: list[str]
    suggested_next_step: str
    remediation_candidate: RemediationCandidate | None = None


class DiagnosticResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str | None
    primary_category: Category
    secondary_categories: list[Category]
    problem_summary: str
    status: DiagnosticStatus
    evidence_summary: list[str]
    evidence_requests: list[EvidenceRequest]
    ranked_root_causes: list[RootCauseCandidate]
    overall_uncertainty: str
    recommended_next_step: str
    remediation_candidate: RemediationCandidate | None = None
    user_facing_explanation: str
    warnings: list[str]
    ai_summary: str | None = None
    ai_model: str | None = None
