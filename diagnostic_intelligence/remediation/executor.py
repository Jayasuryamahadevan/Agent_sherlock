"""The only code path that performs operations. It enforces policy, not the language model."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from diagnostic_intelligence.engines.diagnostic_decision import DiagnosticDecisionEngine
from diagnostic_intelligence.models.evidence import EvidenceRecord, EvidenceType
from diagnostic_intelligence.remediation.approval import ApprovalRecord
from diagnostic_intelligence.remediation.backends import ActionBackend
from diagnostic_intelligence.remediation.catalogue import CATALOGUE, ActionKind
from diagnostic_intelligence.remediation.policy import PolicyAuthority, PolicyDecision, Verdict


class PolicyViolation(Exception):
    """Raised when something tries to execute without a valid authorization."""


class EvidenceCollector(Protocol):
    def collect_types(self, session_id: str, requests: list) -> list[EvidenceRecord]: ...


class ExecutionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision_id: str
    action_id: str
    command_succeeded: bool
    message: str
    started_at: datetime
    finished_at: datetime
    evidence: list[EvidenceRecord] = Field(default_factory=list)


class Executor:
    def __init__(self, authority: PolicyAuthority, backend: ActionBackend, collector: EvidenceCollector) -> None:
        self._authority = authority
        self.backend = backend
        self.collector = collector
        self._used_decisions: set[str] = set()
        self._planner = DiagnosticDecisionEngine()

    def execute(
        self,
        decision: PolicyDecision,
        approval: ApprovalRecord | None = None,
        *,
        evidence_id_prefix: str = "ev",
    ) -> ExecutionResult:
        if not self._authority.verify(decision):
            raise PolicyViolation("Decision signature is invalid; it was not issued by the policy engine or was modified.")
        if decision.decision_id in self._used_decisions:
            raise PolicyViolation("This decision has already been used; each authorization is single-use.")
        if decision.verdict == Verdict.DENY:
            raise PolicyViolation(f"Policy denied '{decision.action_id}': {'; '.join(decision.reasons)}")
        if decision.verdict == Verdict.REQUIRE_APPROVAL:
            if approval is None:
                raise PolicyViolation("This action requires explicit approval and none was provided.")
            if approval.decision_id != decision.decision_id:
                raise PolicyViolation("The approval does not belong to this decision.")
            if not approval.approved:
                raise PolicyViolation("Approval was denied; the action will not be executed.")
        spec = CATALOGUE.get(decision.action_id)
        if spec is None:
            raise PolicyViolation(f"'{decision.action_id}' is not catalogued.")
        params = spec.params_model.model_validate(decision.parameters)
        self._used_decisions.add(decision.decision_id)

        started = datetime.now(timezone.utc)
        if spec.kind == ActionKind.DIAGNOSTIC:
            requests = [
                self._planner.build_request(
                    EvidenceType(evidence_type),
                    f"{evidence_id_prefix}.{EvidenceType(evidence_type).value.replace('.', '_')}",
                )
                for evidence_type in dict.fromkeys(params.evidence_types)
            ]
            records = self.collector.collect_types(decision.session_id, requests)
            usable = sum(1 for r in records if r.status.value in ("available", "partial"))
            return ExecutionResult(
                decision_id=decision.decision_id,
                action_id=decision.action_id,
                command_succeeded=True,
                message=f"collected {len(records)} record(s), {usable} usable",
                started_at=started,
                finished_at=datetime.now(timezone.utc),
                evidence=records,
            )
        if spec.requires_admin and not self.backend.is_elevated():
            raise PolicyViolation("Administrator privileges are required at execution time and are not available.")
        succeeded, message = self.backend.run(decision.action_id, params)
        return ExecutionResult(
            decision_id=decision.decision_id,
            action_id=decision.action_id,
            command_succeeded=succeeded,
            message=message,
            started_at=started,
            finished_at=datetime.now(timezone.utc),
        )
