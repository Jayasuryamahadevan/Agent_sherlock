"""Validated complaint understanding and category identifiers."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Category(StrEnum):
    STORAGE = "storage"
    NETWORK = "network"
    SYSTEM_PERFORMANCE = "system_performance"
    WINDOWS_HEALTH = "windows_health"
    APPLICATION_COMPATIBILITY = "application_compatibility"
    DRIVER = "driver"
    UNKNOWN = "unknown"


class ProblemUnderstanding(BaseModel):
    """Deterministic interpretation of a complaint, not a root-cause finding."""

    model_config = ConfigDict(extra="forbid")

    original_complaint: str = Field(min_length=1, max_length=4000)
    primary_category: Category
    secondary_categories: list[Category] = Field(default_factory=list)
    symptoms: list[str] = Field(default_factory=list)
    affected_component: str | None = None
    time_pattern: str | None = None
    recent_changes: str | None = None
    severity_or_impact: str | None = None
    missing_information: list[str] = Field(default_factory=list)
    clarification_questions: list[str] = Field(default_factory=list)
    needs_clarification: bool = False
    classification_confidence: float = Field(ge=0, le=1)
    classification_explanation: str

    @classmethod
    def category_ids(cls) -> set[str]:
        return {category.value for category in Category}
