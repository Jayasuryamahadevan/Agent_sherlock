"""Input contracts received from the API/frontend layer."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class DiagnosticRequest(BaseModel):
    """A complaint and optional context for one diagnostic session."""

    model_config = ConfigDict(extra="forbid")

    session_id: str | None = Field(default=None, min_length=1, max_length=128)
    complaint: str = Field(min_length=1, max_length=4000)
    context: dict[str, Any] = Field(default_factory=dict)

    @field_validator("complaint")
    @classmethod
    def complaint_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("complaint must not be blank")
        return value.strip()

    @field_validator("context")
    @classmethod
    def context_must_be_bounded(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(value) > 50:
            raise ValueError("context may contain at most 50 fields")
        return value
