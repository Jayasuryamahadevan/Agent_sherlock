"""The three execution pipelines required by the project.

All three share one investigation engine (triage -> evidence planning -> collection -> reasoning
-> follow-up collection). They differ in what happens when the reasoner proposes a change:

* ``AutomaticExecutionPipeline`` (Pipeline 1): automatically executes only read-only diagnostic
  operations, including a confirmation re-measurement; system changes become recommendations.
* ``AutoResolutionPipeline`` (Pipeline 2): automatically executes eligible corrective actions,
  verifies each with fresh evidence, lets the reasoner revise, and stops at a hard attempt limit.
* ``WhitelistApprovalPipeline`` (Pipeline 3): every change must pass a parameter-constrained
  whitelist and then explicit user approval; denial or absence of approval prevents execution.

The authorization difference is enforced by ``PolicyEngine`` + ``Executor``, not by prompts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from diagnostic_intelligence.agent.audit import AuditLog
from diagnostic_intelligence.agent.models import (
    ActionAttempt,
    ExecutionSummary,
    NextStep,
    ReasoningDecision,
    RefusedProposal,
    RuleCrossCheck,
    SessionReport,
    SessionStatus,
    TimelineEvent,
    TriageResult,
)
from diagnostic_intelligence.agent.reasoning import Reasoner, ReasoningContext, ReasoningUnavailable, RuleReasoner
from diagnostic_intelligence.engines.diagnostic_orchestrator import DiagnosticOrchestrator
from diagnostic_intelligence.evidence_view import EvidenceView
from diagnostic_intelligence.models.classification import Category
from diagnostic_intelligence.models.evidence import EvidenceRecord, EvidenceType
from diagnostic_intelligence.remediation.approval import (
    ApprovalProvider,
    ApprovalRecord,
    ApprovalRequest,
    ApprovalResponse,
    DeferredApprovalProvider,
    new_expiry,
)
from diagnostic_intelligence.remediation.backends import ActionBackend
from diagnostic_intelligence.remediation.catalogue import CATALOGUE, VerificationVerdict
from diagnostic_intelligence.remediation.executor import EvidenceCollector, Executor, PolicyViolation
from diagnostic_intelligence.remediation.policy import (
    AUTO_RESOLUTION_POLICY,
    AUTOMATIC_EXECUTION_POLICY,
    WHITELIST_APPROVAL_POLICY,
    PipelinePolicy,
    PolicyAuthority,
    PolicyContext,
    PolicyDecision,
    PolicyEngine,
    ProposedOperation,
    Verdict,
    operation_key,
)

MAX_POLICY_REFUSALS = 2


@dataclass
class PendingApproval:
    request: ApprovalRequest
    decision: PolicyDecision
    proposal: ProposedOperation


@dataclass
class AgentSession:
    session_id: str
    complaint: str
    pipeline_id: str
    triage: TriageResult | None = None
    evidence: list[EvidenceRecord] = field(default_factory=list)
    decisions: list[ReasoningDecision] = field(default_factory=list)
    attempts: list[ActionAttempt] = field(default_factory=list)
    refused: list[RefusedProposal] = field(default_factory=list)
    recommendation: dict[str, Any] | None = None
    pending: PendingApproval | None = None
    status: SessionStatus = SessionStatus.ERROR
    timeline: list[TimelineEvent] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    attempted_operations: set[str] = field(default_factory=set)
    collection_counter: int = 0
    diagnosis_confirmed: bool | None = None
    clarification_question: str | None = None

    @property
    def executed_attempts(self) -> list[ActionAttempt]:
        return [attempt for attempt in self.attempts if attempt.execution is not None]

    @property
    def latest_decision(self) -> ReasoningDecision | None:
        return self.decisions[-1] if self.decisions else None


class BasePipeline:
    """Shared investigation engine. Subclasses implement ``_act`` (their execution logic)."""

    policy: PipelinePolicy

    def __init__(
        self,
        *,
        reasoner: Reasoner,
        collector: EvidenceCollector,
        backend: ActionBackend,
        approval_provider: ApprovalProvider | None = None,
        audit: AuditLog | None = None,
        authority: PolicyAuthority | None = None,
    ) -> None:
        self.reasoner = reasoner
        self.authority = authority or PolicyAuthority()
        self.policy_engine = PolicyEngine(self.policy, self.authority, is_elevated=backend.is_elevated)
        self.executor = Executor(self.authority, backend, collector)
        self.approval_provider = approval_provider or DeferredApprovalProvider()
        self.audit = audit or AuditLog(None)
        self._rules = RuleReasoner()

    # ------------------------------------------------------------------ entry
    def start(self, complaint: str, session_id: str | None = None) -> AgentSession:
        complaint = complaint.strip()
        if not complaint:
            raise ValueError("complaint must not be blank")
        session = AgentSession(session_id=session_id or f"s-{uuid4().hex[:12]}", complaint=complaint[:4000],
                               pipeline_id=self.policy.pipeline_id)
        self._event(session, "start", f"{self.policy.name} started ({self.reasoner.mode.value} reasoning).",
                    {"model": self.reasoner.model_name})
        try:
            triage = self.reasoner.triage(session.complaint)
        except ReasoningUnavailable as problem:
            return self._reasoning_unavailable(session, problem)
        session.triage = triage
        for item in triage.rejected_items:
            session.warnings.append(f"Triage: {item}")
        self._event(session, "triage", triage.explanation, {
            "category": triage.primary_category.value,
            "secondary": [c.value for c in triage.secondary_categories],
            "evidence_types": [t.value for t in triage.evidence_types],
            "source": triage.source.value,
        })
        if triage.needs_clarification and (triage.primary_category == Category.UNKNOWN or not triage.evidence_types):
            session.status = SessionStatus.NEEDS_CLARIFICATION
            session.clarification_question = triage.clarification_question or "What exactly is happening, and when?"
            return self._finalize(session)
        self._collect(session, triage.evidence_types, "initial evidence selected during triage")
        decision = self._investigate(session)
        try:
            self._act(session, decision)
        except Exception as error:  # never leave a session half-reported
            session.status = SessionStatus.ERROR
            session.warnings.append(f"Pipeline error: {type(error).__name__}: {error}")
            self._event(session, "error", f"{type(error).__name__}: {error}")
        return self._finalize(session)

    def resume(self, session: AgentSession, response: ApprovalResponse) -> AgentSession:
        raise ValueError(f"The {self.policy.name} pipeline does not use approvals.")

    # ------------------------------------------------------- shared machinery
    def _event(self, session: AgentSession, stage: str, message: str, data: dict[str, Any] | None = None) -> None:
        session.timeline.append(TimelineEvent(stage=stage, message=message, data=data or {}))
        self.audit.write(session.session_id, self.policy.pipeline_id, stage, message, data)

    def _collect(self, session: AgentSession, evidence_types, reason: str) -> list[EvidenceRecord]:
        types = list(dict.fromkeys(EvidenceType(t) for t in evidence_types))
        if not types:
            return []
        session.collection_counter += 1
        proposal = ProposedOperation(action_id="collect_evidence",
                                     parameters={"evidence_types": [t.value for t in types]}, rationale=reason)
        decision = self._evaluate(session, proposal)
        if decision.verdict != Verdict.ALLOW:
            self._event(session, "policy", f"Evidence collection refused: {'; '.join(decision.reasons)}")
            return []
        result = self.executor.execute(decision, evidence_id_prefix=f"c{session.collection_counter}")
        session.evidence.extend(result.evidence)
        self._event(session, "collect", f"{reason}: {result.message}", {
            "records": [{"evidence_id": r.evidence_id, "type": r.evidence_type.value, "status": r.status.value}
                        for r in result.evidence],
        })
        return result.evidence

    def _context(self, session: AgentSession, round_index: int) -> ReasoningContext:
        triage = session.triage
        return ReasoningContext(
            session_id=session.session_id,
            complaint=session.complaint,
            primary_category=triage.primary_category if triage else Category.UNKNOWN,
            secondary_categories=list(triage.secondary_categories) if triage else [],
            evidence=EvidenceView(session.evidence),
            pipeline_summary=self.policy.summary,
            round_index=round_index,
            max_rounds=self.policy.max_diagnostic_rounds,
            attempts=[
                {
                    "attempt": a.attempt_number,
                    "action_id": a.proposal.action_id,
                    "parameters": a.decision.parameters,
                    "approved": a.approval.approved if a.approval else None,
                    "executed": a.execution is not None,
                    "command_succeeded": a.execution.command_succeeded if a.execution else None,
                    "verification": a.verification.verdict.value if a.verification else None,
                    "verification_details": a.verification.details if a.verification else [],
                }
                for a in session.attempts
            ],
            attempted_operation_keys=set(session.attempted_operations),
            refused=[{"action_id": r.proposal.action_id, "parameters": r.proposal.parameters,
                      "reasons": r.decision.reasons} for r in session.refused],
        )

    def _assess(self, session: AgentSession, round_index: int) -> ReasoningDecision | None:
        try:
            decision = self.reasoner.assess(self._context(session, round_index))
        except ReasoningUnavailable as problem:
            self._reasoning_unavailable(session, problem)
            return None
        session.decisions.append(decision)
        for claim in decision.rejected_claims:
            session.warnings.append(f"Rejected reasoning claim: {claim}")
        self._event(session, "reason", decision.summary, {
            "source": decision.source.value,
            "hypotheses": [{"cause_id": h.cause_id, "confidence": h.confidence.value} for h in decision.hypotheses],
            "next_step": decision.next_step.value,
            "requested_evidence": [t.value for t in decision.evidence_requests],
            "proposed_action": decision.action.model_dump() if decision.action else None,
            "rejected_claims": len(decision.rejected_claims),
        })
        return decision

    def _investigate(self, session: AgentSession) -> ReasoningDecision | None:
        """Reason, collect requested follow-up evidence, reason again; bounded by policy."""
        rounds = 0
        while True:
            decision = self._assess(session, rounds)
            if decision is None:
                return None
            if decision.next_step == NextStep.COLLECT_MORE and decision.evidence_requests:
                if rounds >= self.policy.max_diagnostic_rounds:
                    self._event(session, "limit", "Diagnostic round limit reached; continuing with the evidence collected so far.")
                    return decision
                rounds += 1
                self._collect(session, decision.evidence_requests,
                              decision.evidence_request_reason or "follow-up evidence requested by the reasoner")
                continue
            return decision

    def _grounded_cause_ids(self, session: AgentSession) -> set[str]:
        latest = session.latest_decision
        return {h.cause_id for h in latest.hypotheses} if latest else set()

    def _evaluate(self, session: AgentSession, proposal: ProposedOperation) -> PolicyDecision:
        context = PolicyContext(
            session_id=session.session_id,
            evidence=EvidenceView(session.evidence),
            grounded_cause_ids=self._grounded_cause_ids(session),
            attempted_operations=set(session.attempted_operations),
            change_attempts=len(session.executed_attempts),
        )
        decision = self.policy_engine.evaluate(proposal, context)
        if proposal.action_id != "collect_evidence":
            self._event(session, "policy", f"{decision.verdict.value}: {decision.action_id}", {
                "decision_id": decision.decision_id, "parameters": decision.parameters, "reasons": decision.reasons,
            })
        return decision

    def _refuse(self, session: AgentSession, proposal: ProposedOperation, decision: PolicyDecision) -> None:
        session.refused.append(RefusedProposal(proposal=proposal, decision=decision))

    def _execute_and_verify(
        self,
        session: AgentSession,
        proposal: ProposedOperation,
        decision: PolicyDecision,
        approval: ApprovalRecord | None = None,
    ) -> ActionAttempt:
        number = len(session.attempts) + 1
        spec = CATALOGUE[decision.action_id]
        before = EvidenceView(list(session.evidence))
        try:
            result = self.executor.execute(decision, approval)
        except PolicyViolation as violation:
            attempt = ActionAttempt(attempt_number=number, proposal=proposal, decision=decision, approval=approval,
                                    outcome=f"Blocked by the executor: {violation}")
            session.attempts.append(attempt)
            self._event(session, "execute", attempt.outcome)
            return attempt
        session.attempted_operations.add(operation_key(decision.action_id, decision.parameters))
        execution = ExecutionSummary(command_succeeded=result.command_succeeded, message=result.message,
                                     started_at=result.started_at, finished_at=result.finished_at)
        self._event(session, "execute", f"{spec.title}: {result.message}",
                    {"decision_id": decision.decision_id, "command_succeeded": result.command_succeeded})
        self._collect(session, spec.verification_evidence, f"post-action verification for {decision.action_id}")
        params = spec.params_model.model_validate(decision.parameters)
        verification = spec.verify(params, before, EvidenceView(session.evidence))
        if not result.command_succeeded:
            outcome = f"The command reported failure ({result.message}). Fresh evidence verdict: {verification.verdict.value}."
        else:
            outcome = f"Command completed; fresh evidence verdict: {verification.verdict.value}."
        attempt = ActionAttempt(attempt_number=number, proposal=proposal, decision=decision, approval=approval,
                                execution=execution, verification=verification, outcome=outcome)
        session.attempts.append(attempt)
        self._event(session, "verify", outcome, {"details": verification.details})
        return attempt

    def _status_from_attempts(self, session: AgentSession) -> SessionStatus:
        executed = [a for a in session.executed_attempts if a.verification]
        if executed and executed[-1].verification.verdict == VerificationVerdict.RESOLVED:
            return SessionStatus.RESOLVED
        if any(a.verification.verdict in (VerificationVerdict.IMPROVED, VerificationVerdict.RESOLVED) for a in executed):
            return SessionStatus.PARTIALLY_RESOLVED
        return SessionStatus.NOT_RESOLVED

    def _finish_without_action(self, session: AgentSession, decision: ReasoningDecision) -> None:
        if session.executed_attempts:
            session.status = self._status_from_attempts(session)
        elif decision.next_step == NextStep.ASK_USER and decision.question:
            session.status = SessionStatus.NEEDS_CLARIFICATION
            session.clarification_question = decision.question
        elif session.refused and decision.hypotheses:
            session.status = SessionStatus.ACTION_REFUSED
        elif decision.hypotheses:
            session.status = SessionStatus.DIAGNOSED
        else:
            session.status = SessionStatus.CAUSE_UNDETERMINED

    def _reasoning_unavailable(self, session: AgentSession, problem: Exception) -> AgentSession:
        session.status = SessionStatus.REASONING_UNAVAILABLE
        message = (f"AI reasoning is unavailable: {problem} No diagnosis was produced and no action was taken. "
                   "Fix the model connection, or explicitly re-run in rules mode.")
        session.warnings.append(message)
        self._event(session, "reason", message)
        return session

    def _act(self, session: AgentSession, decision: ReasoningDecision | None) -> None:  # pragma: no cover
        raise NotImplementedError

    # ------------------------------------------------------------- reporting
    def _finalize(self, session: AgentSession) -> AgentSession:
        self._event(session, "finish", f"Session finished with status '{session.status.value}'.",
                    {"attempts": len(session.executed_attempts), "evidence_records": len(session.evidence)})
        return session

    def report(self, session: AgentSession) -> SessionReport:
        latest = session.latest_decision
        hypotheses = latest.hypotheses if latest else []
        cross_check = None
        if self.reasoner.mode.value == "ai" and session.triage and session.evidence:
            findings = self._rules.findings(self._context(session, 0))
            rule_ids = [c.cause_id for c in findings]
            agrees = (hypotheses[0].cause_id in rule_ids) if hypotheses and rule_ids else (
                None if hypotheses or rule_ids else True)
            cross_check = RuleCrossCheck(
                findings=[{"cause_id": c.cause_id, "title": c.title, "score": round(c.confidence_score, 2)} for c in findings],
                agrees_with_reasoner=agrees,
            )
        triage = session.triage
        return SessionReport(
            session_id=session.session_id,
            pipeline=self.policy.describe(),
            reasoning_mode=self.reasoner.mode,
            reasoning_model=self.reasoner.model_name,
            complaint=session.complaint,
            primary_category=triage.primary_category if triage else None,
            secondary_categories=list(triage.secondary_categories) if triage else [],
            status=session.status,
            headline=self._headline(session),
            diagnosis=hypotheses,
            diagnosis_confirmed=session.diagnosis_confirmed,
            alternatives_ruled_out=latest.alternatives_ruled_out if latest else [],
            uncertainty=latest.uncertainty if latest else "No reasoning was completed.",
            evidence_summary=[f"{r.evidence_id} | {DiagnosticOrchestrator._evidence_summary(r)}" for r in session.evidence],
            evidence_count=len(session.evidence),
            actions=session.attempts,
            refused_proposals=session.refused,
            recommendation=session.recommendation,
            pending_approval=session.pending.request if session.pending else None,
            rule_cross_check=cross_check,
            timeline=session.timeline,
            warnings=list(dict.fromkeys(session.warnings)),
            clarification_question=session.clarification_question,
        )

    def _headline(self, session: AgentSession) -> str:
        latest = session.latest_decision
        top = latest.hypotheses[0] if latest and latest.hypotheses else None
        cause = f"'{top.title}' ({top.confidence.value} confidence)" if top else "no evidence-supported cause"
        last = session.executed_attempts[-1] if session.executed_attempts else None
        action = CATALOGUE[last.decision.action_id].title.lower() if last else None
        status = session.status
        if status == SessionStatus.RESOLVED:
            return f"Resolved. After '{action}', fresh evidence shows the fault is gone."
        if status == SessionStatus.PARTIALLY_RESOLVED:
            return f"Partly improved after '{action}', but the problem is not fully resolved. A person should review it."
        if status == SessionStatus.NOT_RESOLVED:
            return f"Not resolved. {len(session.executed_attempts)} corrective action(s) ran, and fresh evidence still shows the fault. Human help is needed."
        if status == SessionStatus.DIAGNOSED:
            suffix = " Confirmed by a second measurement." if session.diagnosis_confirmed else (
                " A second measurement did not reproduce it, so it may be intermittent." if session.diagnosis_confirmed is False else "")
            return f"Probable cause: {cause}.{suffix}"
        if status == SessionStatus.CAUSE_UNDETERMINED:
            return "Cause undetermined. The collected evidence does not support a specific cause."
        if status == SessionStatus.AWAITING_APPROVAL:
            return f"Probable cause: {cause}. A corrective action is waiting for your approval."
        if status == SessionStatus.APPROVAL_DENIED:
            return "Approval was declined, so nothing was changed."
        if status == SessionStatus.ACTION_REFUSED:
            return f"Probable cause: {cause}. The proposed action was refused by policy, so nothing was changed."
        if status == SessionStatus.NEEDS_CLARIFICATION:
            return "More detail is needed before investigating."
        if status == SessionStatus.REASONING_UNAVAILABLE:
            return "AI reasoning is unavailable, so no diagnosis was made and nothing was changed."
        return "The session ended with an internal error; nothing further was changed."


class AutomaticExecutionPipeline(BasePipeline):
    """Pipeline 1: automatic read-only operations; changes are only recommended."""

    policy = AUTOMATIC_EXECUTION_POLICY

    def _act(self, session: AgentSession, decision: ReasoningDecision | None) -> None:
        if decision is None:
            return
        if decision.hypotheses:
            top = decision.hypotheses[0]
            view = EvidenceView(session.evidence)
            cited = [view.get(o.evidence_id).evidence_type for o in top.observations if view.get(o.evidence_id)]
            self._collect(session, cited, f"confirmation re-measurement for '{top.cause_id}'")
            second = self._investigate(session)
            if second is None:
                return
            session.diagnosis_confirmed = top.cause_id in {h.cause_id for h in second.hypotheses}
            self._event(session, "confirm", "Diagnosis confirmed by fresh measurement." if session.diagnosis_confirmed
                        else "Fresh measurement did not reproduce the earlier finding.")
            decision = second
        if decision.next_step == NextStep.PROPOSE_ACTION and decision.action is not None:
            policy_decision = self._evaluate(session, decision.action)
            other_reasons = [r for r in policy_decision.reasons if "never executes system changes" not in r]
            spec = CATALOGUE.get(decision.action.action_id)
            session.recommendation = {
                "action_id": decision.action.action_id,
                "title": spec.title if spec else decision.action.action_id,
                "parameters": policy_decision.parameters,
                "rationale": decision.action.rationale,
                "executed": False,
                "why_not_executed": "Pipeline 1 only executes read-only diagnostic operations.",
                "evidence_supports_action": not other_reasons,
                "policy_notes": other_reasons,
                "risk": spec.risk.value if spec else None,
            }
        self._finish_without_action(session, decision)


class AutoResolutionPipeline(BasePipeline):
    """Pipeline 2: automatic, bounded remediation with verification after every action."""

    policy = AUTO_RESOLUTION_POLICY

    def _act(self, session: AgentSession, decision: ReasoningDecision | None) -> None:
        while decision is not None:
            if decision.next_step != NextStep.PROPOSE_ACTION or decision.action is None:
                self._finish_without_action(session, decision)
                return
            policy_decision = self._evaluate(session, decision.action)
            if policy_decision.verdict != Verdict.ALLOW:
                self._refuse(session, decision.action, policy_decision)
                if len(session.refused) < MAX_POLICY_REFUSALS:
                    decision = self._investigate(session)
                    continue
                session.status = self._status_from_attempts(session) if session.executed_attempts else SessionStatus.ACTION_REFUSED
                self._event(session, "stop", "Stopping: the proposed action is not eligible for automatic execution; human intervention is required.")
                return
            attempt = self._execute_and_verify(session, decision.action, policy_decision)
            if attempt.verification and attempt.verification.verdict == VerificationVerdict.RESOLVED:
                session.status = SessionStatus.RESOLVED
                return
            if attempt.execution is None:
                session.status = SessionStatus.ACTION_REFUSED if not session.executed_attempts else self._status_from_attempts(session)
                return
            if len(session.executed_attempts) >= self.policy.max_change_attempts:
                session.status = self._status_from_attempts(session)
                self._event(session, "stop", f"Stopping after {self.policy.max_change_attempts} corrective attempts; human intervention is required.")
                return
            decision = self._investigate(session)


class WhitelistApprovalPipeline(BasePipeline):
    """Pipeline 3: whitelist + explicit approval before any system change."""

    policy = WHITELIST_APPROVAL_POLICY

    def _act(self, session: AgentSession, decision: ReasoningDecision | None) -> None:
        while decision is not None:
            if decision.next_step != NextStep.PROPOSE_ACTION or decision.action is None:
                self._finish_without_action(session, decision)
                return
            policy_decision = self._evaluate(session, decision.action)
            if policy_decision.verdict == Verdict.DENY:
                self._refuse(session, decision.action, policy_decision)
                if len(session.refused) < MAX_POLICY_REFUSALS:
                    decision = self._investigate(session)
                    continue
                session.status = self._status_from_attempts(session) if session.executed_attempts else SessionStatus.ACTION_REFUSED
                return
            request = self._approval_request(session, decision, policy_decision)
            session.pending = PendingApproval(request=request, decision=policy_decision, proposal=decision.action)
            self._event(session, "approval", f"Approval requested for {policy_decision.action_id}.",
                        {"decision_id": policy_decision.decision_id})
            response = self.approval_provider.request(request)
            if response is None:
                session.status = SessionStatus.AWAITING_APPROVAL
                return
            decision = self._apply_response(session, response)

    def resume(self, session: AgentSession, response: ApprovalResponse) -> AgentSession:
        if session.pending is None:
            raise ValueError("No approval is pending for this session.")
        if response.decision_id != session.pending.decision.decision_id:
            raise ValueError("The approval does not match the pending decision.")
        try:
            decision = self._apply_response(session, response)
            if decision is not None:
                self._act(session, decision)
        except Exception as error:
            session.status = SessionStatus.ERROR
            session.warnings.append(f"Pipeline error: {type(error).__name__}: {error}")
        return self._finalize(session)

    def _apply_response(self, session: AgentSession, response: ApprovalResponse) -> ReasoningDecision | None:
        pending = session.pending
        if pending is None or response.decision_id != pending.decision.decision_id:
            raise ValueError("The approval does not match the pending decision.")
        session.pending = None
        now = datetime.now(timezone.utc)
        if now > pending.request.expires_at:
            session.status = SessionStatus.ACTION_REFUSED
            session.warnings.append("The approval arrived after the request expired; the evidence may be stale, so nothing was executed. Run the diagnosis again.")
            self._event(session, "approval", "Approval expired; not executed.")
            return None
        record = ApprovalRecord(decision_id=response.decision_id, approved=response.approved,
                                approver=response.approver, note=response.note, decided_at=now)
        self._event(session, "approval", f"{'Approved' if record.approved else 'Denied'} by {record.approver}.",
                    {"decision_id": record.decision_id})
        if not record.approved:
            session.attempts.append(ActionAttempt(
                attempt_number=len(session.attempts) + 1, proposal=pending.proposal, decision=pending.decision,
                approval=record, outcome="Approval denied; the action was not executed."))
            session.status = SessionStatus.APPROVAL_DENIED
            return None
        attempt = self._execute_and_verify(session, pending.proposal, pending.decision, record)
        if attempt.verification and attempt.verification.verdict == VerificationVerdict.RESOLVED:
            session.status = SessionStatus.RESOLVED
            return None
        if attempt.execution is None:
            session.status = SessionStatus.ACTION_REFUSED
            return None
        if len(session.executed_attempts) >= self.policy.max_change_attempts:
            session.status = self._status_from_attempts(session)
            return None
        return self._investigate(session)

    def _approval_request(self, session: AgentSession, decision: ReasoningDecision, policy_decision: PolicyDecision) -> ApprovalRequest:
        spec = CATALOGUE[policy_decision.action_id]
        top = next((h for h in decision.hypotheses if h.cause_id == policy_decision.addresses_cause_id), None)
        created, expires = new_expiry()
        return ApprovalRequest(
            decision_id=policy_decision.decision_id,
            session_id=session.session_id,
            action_id=spec.action_id,
            title=spec.title,
            parameters=policy_decision.parameters,
            risk=spec.risk.value,
            reversible=spec.reversible,
            requires_admin=spec.requires_admin,
            consequences=spec.consequences,
            justification=(f"{top.title}: " if top else "") + (decision.action.rationale or decision.summary),
            supporting_evidence=[f"{o.evidence_id}: {o.field} = {o.value}" for o in (top.observations if top else [])],
            created_at=created,
            expires_at=expires,
        )


PIPELINES: dict[str, type[BasePipeline]] = {
    AutomaticExecutionPipeline.policy.pipeline_id: AutomaticExecutionPipeline,
    AutoResolutionPipeline.policy.pipeline_id: AutoResolutionPipeline,
    WhitelistApprovalPipeline.policy.pipeline_id: WhitelistApprovalPipeline,
}


def build_pipeline(pipeline_id: str, **kwargs) -> BasePipeline:
    try:
        cls = PIPELINES[pipeline_id]
    except KeyError as error:
        raise ValueError(f"Unknown pipeline '{pipeline_id}'. Choose one of {sorted(PIPELINES)}.") from error
    return cls(**kwargs)
