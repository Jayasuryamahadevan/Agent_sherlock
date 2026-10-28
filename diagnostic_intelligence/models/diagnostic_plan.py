"""Collector-independent, non-executable evidence collection plans."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from diagnostic_intelligence.models.classification import Category
from diagnostic_intelligence.models.evidence import EvidenceType


class Priority(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class EvidenceRequest(BaseModel):
    """A request that a collector maps to an approved local evidence source."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{1,127}$")
    evidence_type: EvidenceType
    purpose: str = Field(min_length=1, max_length=500)
    priority: Priority
    required: bool
    parameters: dict[str, Any] = Field(default_factory=dict)
    time_window: str | None = None
    expected_output_fields: list[str] = Field(default_factory=list)
    privacy_notes: str


class DiagnosticPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str | None
    category: Category
    evidence_requests: list[EvidenceRequest]
    reasoning_summary: str
