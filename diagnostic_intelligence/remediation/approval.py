"""Approval requests and providers for the whitelist-and-approval pipeline."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

APPROVAL_VALIDITY = timedelta(minutes=15)


class ApprovalRequest(BaseModel):
    """Everything a person needs to decide; shown verbatim in the UI/CLI."""

    model_config = ConfigDict(extra="forbid")

    decision_id: str
    session_id: str
    action_id: str
    title: str
    parameters: dict[str, Any]
    risk: str
    reversible: bool
    requires_admin: bool
    consequences: str
    justification: str
    supporting_evidence: list[str]
    created_at: datetime
    expires_at: datetime


class ApprovalResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision_id: str = Field(min_length=1, max_length=64)
    approved: bool
    approver: str = Field(default="local-user", min_length=1, max_length=64)
    note: str = Field(default="", max_length=500)


class ApprovalRecord(BaseModel):
    """Created only by the pipeline after validating a response against the pending request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    decision_id: str
    approved: bool
    approver: str
    note: str
    decided_at: datetime


class ApprovalProvider(Protocol):
    def request(self, request: ApprovalRequest) -> ApprovalResponse | None:
        """Return a response now, or None to pause the session until one arrives."""


class DeferredApprovalProvider:
    """Used by the API: the session pauses in 'awaiting_approval' and resumes via an endpoint."""

    def request(self, request: ApprovalRequest) -> ApprovalResponse | None:
        return None


class ScriptedApprovalProvider:
    """Test/demo provider that answers every request the same way."""

    def __init__(self, approve: bool, approver: str = "scripted-test") -> None:
        self.approve = approve
        self.approver = approver
        self.requests: list[ApprovalRequest] = []

    def request(self, request: ApprovalRequest) -> ApprovalResponse | None:
        self.requests.append(request)
        return ApprovalResponse(decision_id=request.decision_id, approved=self.approve, approver=self.approver)


class ConsoleApprovalProvider:
    """Interactive CLI approval. Anything other than an explicit 'yes' is a denial."""

    def request(self, request: ApprovalRequest) -> ApprovalResponse | None:
        print("\n=== APPROVAL REQUIRED ===")
        print(f"Action:        {request.title} ({request.action_id})")
        print(f"Parameters:    {request.parameters or '(none)'}")
        print(f"Risk:          {request.risk}   Reversible: {request.reversible}   Needs admin: {request.requires_admin}")
        print(f"Consequences:  {request.consequences}")
        print(f"Why:           {request.justification}")
        for line in request.supporting_evidence:
            print(f"  evidence:    {line}")
        try:
            answer = input("Type 'yes' to approve, anything else to deny: ").strip().casefold()
        except EOFError:
            answer = ""
        return ApprovalResponse(decision_id=request.decision_id, approved=answer == "yes", approver="console-user")


def new_expiry(now: datetime | None = None) -> tuple[datetime, datetime]:
    created = now or datetime.now(timezone.utc)
    return created, created + APPROVAL_VALIDITY
