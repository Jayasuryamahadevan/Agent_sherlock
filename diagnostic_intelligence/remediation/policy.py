"""Deterministic authorization for every operation the agent wants to perform.

The language model proposes; this module decides. Decisions are signed with a per-process
secret shared only with the Executor, so the executor refuses anything that did not come from
this engine. An edited, replayed or fabricated decision fails verification.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from diagnostic_intelligence.evidence_view import EvidenceView
from diagnostic_intelligence.remediation.catalogue import CATALOGUE, ActionKind, RiskLevel


class Verdict(StrEnum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


class ChangeMode(StrEnum):
    NEVER = "never"                  # Pipeline 1: system changes are recommended, never executed
    AUTOMATIC = "automatic"          # Pipeline 2: eligible changes execute without approval
    WITH_APPROVAL = "with_approval"  # Pipeline 3: whitelisted changes execute only after approval


class ProposedOperation(BaseModel):
    """What the reasoner asks for. Untrusted input."""

    model_config = ConfigDict(extra="forbid")

    action_id: str = Field(min_length=1, max_length=64)
    parameters: dict[str, Any] = Field(default_factory=dict)
    addresses_cause_id: str | None = Field(default=None, max_length=128)
    rationale: str = Field(default="", max_length=1000)


class PolicyDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    decision_id: str
    session_id: str
    pipeline_id: str
    action_id: str
    parameters: dict[str, Any]
    verdict: Verdict
    reasons: list[str]
    kind: ActionKind | None
    risk: RiskLevel | None
    requires_admin: bool
    addresses_cause_id: str | None
    issued_at: datetime
    signature: str

    def signing_payload(self) -> bytes:
        return _canonical(
            {
                "decision_id": self.decision_id,
                "session_id": self.session_id,
                "pipeline_id": self.pipeline_id,
                "action_id": self.action_id,
                "parameters": self.parameters,
                "verdict": self.verdict.value,
            }
        )


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def operation_key(action_id: str, parameters: dict[str, Any]) -> str:
    return f"{action_id}:{_canonical(parameters).decode()}"


class PolicyAuthority:
    """Holds the signing secret. Create one per process and share it with the Executor only."""

    def __init__(self, secret: bytes | None = None) -> None:
        self._secret = secret or os.urandom(32)

    def sign(self, payload: bytes) -> str:
        return hmac.new(self._secret, payload, hashlib.sha256).hexdigest()

    def verify(self, decision: PolicyDecision) -> bool:
        return hmac.compare_digest(self.sign(decision.signing_payload()), decision.signature)


@dataclass(frozen=True)
class WhitelistEntry:
    """Pipeline 3 whitelist entry: the action plus extra parameter constraints."""

    action_id: str
    constraint: Callable[[BaseModel], str | None] = lambda params: None
    note: str = ""


def _services_subset(params: BaseModel) -> str | None:
    allowed = {"Spooler", "WSearch", "BITS"}
    name = getattr(params, "service_name", None)
    return None if name in allowed else f"Service '{name}' is not on the approval whitelist (allowed: {sorted(allowed)})."


def _temp_min_age(params: BaseModel) -> str | None:
    days = getattr(params, "max_age_days", 0)
    return None if days >= 3 else "Whitelist requires max_age_days >= 3 so recently created temporary files are kept."


DEFAULT_APPROVAL_WHITELIST: dict[str, WhitelistEntry] = {
    entry.action_id: entry
    for entry in (
        WhitelistEntry("flush_dns_cache"),
        WhitelistEntry("renew_dhcp_lease"),
        WhitelistEntry("restart_network_adapter"),
        WhitelistEntry("restart_service", _services_subset, "Only Spooler, WSearch and BITS."),
        WhitelistEntry("clear_temp_files", _temp_min_age, "Only files at least 3 days old."),
        WhitelistEntry("terminate_process", note="Protected processes are always refused by the catalogue."),
    )
}


@dataclass(frozen=True)
class PipelinePolicy:
    pipeline_id: str
    name: str
    summary: str
    change_mode: ChangeMode
    max_auto_risk: RiskLevel | None = None
    whitelist: dict[str, WhitelistEntry] | None = None
    max_change_attempts: int = 0
    max_diagnostic_rounds: int = 3

    def describe(self) -> dict[str, Any]:
        return {
            "pipeline_id": self.pipeline_id,
            "name": self.name,
            "summary": self.summary,
            "system_changes": self.change_mode.value,
            "max_automatic_risk": self.max_auto_risk.value if self.max_auto_risk else None,
            "whitelist": (
                [{"action_id": e.action_id, "note": e.note} for e in self.whitelist.values()]
                if self.whitelist is not None else None
            ),
            "max_change_attempts": self.max_change_attempts,
            "max_diagnostic_rounds": self.max_diagnostic_rounds,
        }


AUTOMATIC_EXECUTION_POLICY = PipelinePolicy(
    pipeline_id="automatic_execution",
    name="Automatic execution",
    summary=(
        "Runs read-only diagnostic operations automatically (evidence collection, probes, "
        "confirmation re-measurements). System changes are never executed; they are reported as recommendations."
    ),
    change_mode=ChangeMode.NEVER,
    max_change_attempts=0,
)

AUTO_RESOLUTION_POLICY = PipelinePolicy(
    pipeline_id="auto_resolution",
    name="Automatic execution and resolution",
    summary=(
        "Diagnoses, then automatically executes eligible low/medium-risk corrective actions, "
        "verifies each with fresh evidence, and stops after a bounded number of attempts."
    ),
    change_mode=ChangeMode.AUTOMATIC,
    max_auto_risk=RiskLevel.MEDIUM,
    max_change_attempts=2,
)

WHITELIST_APPROVAL_POLICY = PipelinePolicy(
    pipeline_id="whitelist_approval",
    name="Whitelist and approval before action",
    summary=(
        "Diagnoses, then checks each proposed change against a parameter-constrained whitelist. "
        "Allowed changes run only after explicit user approval; everything else is refused."
    ),
    change_mode=ChangeMode.WITH_APPROVAL,
    whitelist=DEFAULT_APPROVAL_WHITELIST,
    max_change_attempts=2,
)

POLICIES: dict[str, PipelinePolicy] = {
    policy.pipeline_id: policy
    for policy in (AUTOMATIC_EXECUTION_POLICY, AUTO_RESOLUTION_POLICY, WHITELIST_APPROVAL_POLICY)
}


@dataclass
class PolicyContext:
    session_id: str
    evidence: EvidenceView
    grounded_cause_ids: set[str]
    attempted_operations: set[str] = field(default_factory=set)
    change_attempts: int = 0


class PolicyEngine:
    def __init__(
        self,
        policy: PipelinePolicy,
        authority: PolicyAuthority,
        *,
        is_elevated: Callable[[], bool],
    ) -> None:
        self.policy = policy
        self.authority = authority
        self.is_elevated = is_elevated

    def evaluate(self, proposal: ProposedOperation, context: PolicyContext) -> PolicyDecision:
        spec = CATALOGUE.get(proposal.action_id)
        if spec is None:
            return self._decide(
                context, proposal, {}, Verdict.DENY,
                [f"'{proposal.action_id}' is not a catalogued operation; it cannot be executed by any pipeline."],
                None,
            )
        try:
            params = spec.params_model.model_validate(proposal.parameters)
        except ValidationError as error:
            first = error.errors(include_url=False)[0]
            location = ".".join(str(part) for part in first["loc"]) or "parameters"
            return self._decide(
                context, proposal, proposal.parameters, Verdict.DENY,
                [f"Invalid parameters for '{spec.action_id}': {location}: {first['msg']}."], spec,
            )
        normalized = params.model_dump(mode="json")

        if spec.kind == ActionKind.DIAGNOSTIC:
            return self._decide(
                context, proposal, normalized, Verdict.ALLOW,
                ["Read-only diagnostic operation; allowed automatically in every pipeline."], spec,
            )

        reasons: list[str] = []
        blocking = False
        if self.policy.change_mode == ChangeMode.NEVER:
            blocking = True
            reasons.append("This pipeline never executes system changes; the action is reported as a recommendation.")
        if self.policy.whitelist is not None:
            entry = self.policy.whitelist.get(spec.action_id)
            if entry is None:
                blocking = True
                reasons.append(f"'{spec.action_id}' is not on this pipeline's whitelist.")
            else:
                constraint_reason = entry.constraint(params)
                if constraint_reason:
                    blocking = True
                    reasons.append(constraint_reason)
        if not proposal.addresses_cause_id or proposal.addresses_cause_id not in context.grounded_cause_ids:
            blocking = True
            reasons.append("The action is not linked to a hypothesis that is supported by verified evidence.")
        precondition_reason = spec.precondition(params, context.evidence)
        if precondition_reason:
            blocking = True
            reasons.append(precondition_reason)
        if operation_key(spec.action_id, normalized) in context.attempted_operations:
            blocking = True
            reasons.append("This exact action was already attempted in this session; repeating it is not allowed.")
        if self.policy.change_mode != ChangeMode.NEVER and context.change_attempts >= self.policy.max_change_attempts:
            blocking = True
            reasons.append(f"The limit of {self.policy.max_change_attempts} corrective attempt(s) has been reached.")
        if spec.requires_admin and not self.is_elevated():
            blocking = True
            reasons.append("The action requires administrator privileges and the agent is not running elevated.")
        if self.policy.change_mode == ChangeMode.AUTOMATIC:
            if not spec.auto_remediation_eligible or (
                self.policy.max_auto_risk is not None and spec.risk.rank > self.policy.max_auto_risk.rank
            ):
                blocking = True
                reasons.append(
                    f"'{spec.action_id}' is {spec.risk.value} risk and not eligible for automatic execution; "
                    "it needs a human decision (use the whitelist-and-approval pipeline)."
                )

        if blocking:
            return self._decide(context, proposal, normalized, Verdict.DENY, reasons, spec)
        if self.policy.change_mode == ChangeMode.WITH_APPROVAL:
            return self._decide(
                context, proposal, normalized, Verdict.REQUIRE_APPROVAL,
                ["Whitelisted and justified by evidence; explicit user approval is required before execution."], spec,
            )
        return self._decide(
            context, proposal, normalized, Verdict.ALLOW,
            [f"Eligible for automatic remediation ({spec.risk.value} risk, preconditions met)."], spec,
        )

    def _decide(self, context, proposal, parameters, verdict, reasons, spec) -> PolicyDecision:
        unsigned = dict(
            decision_id=f"dec-{uuid4().hex[:12]}",
            session_id=context.session_id,
            pipeline_id=self.policy.pipeline_id,
            action_id=proposal.action_id,
            parameters=parameters,
            verdict=verdict,
            reasons=reasons,
            kind=spec.kind if spec else None,
            risk=spec.risk if spec else None,
            requires_admin=spec.requires_admin if spec else False,
            addresses_cause_id=proposal.addresses_cause_id,
            issued_at=datetime.now(timezone.utc),
        )
        draft = PolicyDecision(**unsigned, signature="")
        return PolicyDecision(**unsigned, signature=self.authority.sign(draft.signing_payload()))
