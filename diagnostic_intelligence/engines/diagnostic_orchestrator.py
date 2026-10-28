"""Legacy single-pass, rule-based diagnostic flow (served at /api/diagnostics).

The evidence-driven agent with AI reasoning and the three execution pipelines lives in
``diagnostic_intelligence.agent``.
"""

from collections.abc import Iterable
from datetime import datetime, timezone
from uuid import uuid4

from pydantic import ValidationError

from diagnostic_intelligence.engines.diagnostic_decision import DiagnosticDecisionEngine
from diagnostic_intelligence.engines.problem_understanding import ProblemUnderstandingEngine
from diagnostic_intelligence.engines.root_cause_correlation import RootCauseCorrelationEngine
from diagnostic_intelligence.models.classification import Category
from diagnostic_intelligence.models.diagnostic_plan import DiagnosticPlan
from diagnostic_intelligence.models.evidence import EvidenceRecord
from diagnostic_intelligence.models.recommendations import (
    DiagnosticResult,
    DiagnosticStatus,
)
from diagnostic_intelligence.models.requests import DiagnosticRequest


class DiagnosticOrchestrator:
    """Coordinate understanding, evidence planning, correlation, and explanation."""

    def __init__(
        self,
        ai_agent: object | None = None,
        *,
        evidence_collector: object | None = None,
    ) -> None:
        self.ai_agent = ai_agent
        self.evidence_collector = evidence_collector
        self.understanding_engine = ProblemUnderstandingEngine(self.ai_agent)
        self.decision_engine = DiagnosticDecisionEngine(self.ai_agent)
        self.correlation_engine = RootCauseCorrelationEngine(self.ai_agent)

    def run(
        self,
        request: DiagnosticRequest | dict,
        evidence: Iterable[EvidenceRecord | dict] = (),
        now: datetime | None = None,
        *,
        use_ai: bool = False,
        ai_agent: object | None = None,
    ) -> DiagnosticResult:
        if not isinstance(request, DiagnosticRequest):
            request = DiagnosticRequest.model_validate(request)
        understanding = self.understanding_engine.understand(request.complaint)
        valid_evidence: list[EvidenceRecord] = []
        warnings: list[str] = []
        for index, record in enumerate(evidence):
            try:
                validated = record if isinstance(record, EvidenceRecord) else EvidenceRecord.model_validate(record)
            except ValidationError as error:
                warnings.append(
                    f"Evidence item {index + 1} was malformed and ignored: "
                    f"{self._validation_summary(error)}"
                )
                continue
            valid_evidence.append(validated)
        evidence_sessions = {item.session_id for item in valid_evidence}
        session_id = request.session_id or (
            next(iter(evidence_sessions)) if len(evidence_sessions) == 1 else str(uuid4())
        )

        plan = self.decision_engine.create_plan(understanding, valid_evidence, session_id)
        if understanding.needs_clarification and understanding.primary_category == Category.UNKNOWN:
            return self._result(
                session_id, understanding, plan, DiagnosticStatus.NEEDS_CLARIFICATION,
                [], warnings, [], valid_evidence,
                "Please answer the clarification question before collecting diagnostic evidence.",
            )
        if self.evidence_collector is not None:
            try:
                collected_records = self.evidence_collector.collect_for_plan(plan)
            except Exception as error:
                warnings.append(f"Evidence collection failed: {type(error).__name__}.")
                collected_records = []
            for index, record in enumerate(collected_records):
                try:
                    validated = (
                        record
                        if isinstance(record, EvidenceRecord)
                        else EvidenceRecord.model_validate(record)
                    )
                except ValidationError as error:
                    warnings.append(
                        f"Collected evidence item {index + 1} was malformed and ignored: "
                        f"{self._validation_summary(error)}"
                    )
                    continue
                valid_evidence.append(validated)

        aligned_evidence = [
            record for record in valid_evidence if record.session_id == session_id
        ]
        candidates, correlation_warnings, missing = self.correlation_engine.analyze(
            understanding, plan, valid_evidence, now=now
        )
        warnings.extend(correlation_warnings)
        if candidates:
            status = DiagnosticStatus.ANALYSIS_COMPLETE
            next_step = candidates[0].suggested_next_step
            explanation = (
                f"The strongest evidence-supported candidate is '{candidates[0].title}'. "
                "This is a heuristic assessment, not proof of causation or confirmation that the issue is resolved."
            )
        elif not aligned_evidence:
            status = DiagnosticStatus.COLLECTING_EVIDENCE
            next_step = "Collect the required evidence in the diagnostic plan and submit the results for analysis."
            explanation = "The complaint is classified, but no collected evidence supports a root-cause finding yet."
        else:
            status = DiagnosticStatus.INCONCLUSIVE
            next_step = (
                "Collect the requested missing evidence and rerun the analysis."
                if missing else "Collect a targeted follow-up measurement during the reported issue."
            )
            explanation = "The available evidence does not support a root-cause candidate with the current rules."
        result = self._result(
            session_id, understanding, plan, status, candidates, warnings, missing,
            aligned_evidence, next_step, explanation,
        )
        if use_ai:
            agent = ai_agent or self.ai_agent
            if agent is None or not hasattr(agent, "generate_diagnostic_summary"):
                result.warnings.append(
                    "An AI summary was requested but no AI agent is configured; the result is rule-based only."
                )
            else:
                try:
                    summary = agent.generate_diagnostic_summary(
                        complaint=understanding.original_complaint,
                        category=result.primary_category.value,
                        evidence_summary=result.evidence_summary,
                        root_causes=[cause.title for cause in result.ranked_root_causes],
                    )
                except Exception:
                    summary = None
                if summary:
                    result.ai_summary = summary
                    result.ai_model = getattr(agent, "model", "ollama")
                else:
                    result.warnings.append(
                        "Optional Ollama summary could not be generated; deterministic analysis remains authoritative."
                    )
        return result

    @staticmethod
    def _result(
        session_id: str,
        understanding,
        plan: DiagnosticPlan,
        status: DiagnosticStatus,
        candidates,
        warnings: list[str],
        missing: list[str],
        evidence: list[EvidenceRecord],
        next_step: str,
        explanation: str | None = None,
    ) -> DiagnosticResult:
        evidence_summary = [
            DiagnosticOrchestrator._evidence_summary(item)
            for item in evidence
        ]
        if missing:
            warnings = [*warnings, *missing]
        remediation = candidates[0].remediation_candidate if candidates else None
        if understanding.primary_category == Category.UNKNOWN:
            next_step = understanding.clarification_questions[0]
            explanation = "The complaint does not yet identify a supported diagnostic category."
        return DiagnosticResult(
            session_id=session_id,
            primary_category=understanding.primary_category,
            secondary_categories=understanding.secondary_categories,
            problem_summary=understanding.original_complaint,
            status=status,
            evidence_summary=evidence_summary,
            evidence_requests=plan.evidence_requests,
            ranked_root_causes=candidates,
            overall_uncertainty=(
                "Cause confidence scores are heuristic evidence-strength scores, not measured probabilities. "
                "A cause finding does not establish resolution."
            ),
            recommended_next_step=next_step,
            remediation_candidate=remediation,
            user_facing_explanation=explanation or understanding.classification_explanation,
            warnings=warnings,
        )

    @staticmethod
    def _validation_summary(error: ValidationError) -> str:
        first = error.errors(include_url=False)[0]
        location = ".".join(str(part) for part in first["loc"])
        return f"invalid field '{location}' ({first['type']})"

    @staticmethod
    def _evidence_summary(record: EvidenceRecord) -> str:
        safe_fields = (
            "utilization_percent", "used_percent", "available_percent",
            "free_percent", "free_gb", "success", "reachable", "started",
            "error_category", "status", "problem_code", "recurring_error_count",
            "average_latency_ms",
        )
        facts = [
            f"{key}={record.data[key]}"
            for key in safe_fields
            if isinstance(record.data.get(key), (str, int, float, bool))
        ]
        samples = record.data.get("samples")
        if not facts and isinstance(samples, list) and samples:
            latest = samples[-1]
            if isinstance(latest, dict) and isinstance(latest.get("utilization_percent"), (int, float)):
                facts.append(f"utilization_percent={latest['utilization_percent']}")
        processes = record.data.get("processes")
        if isinstance(processes, list):
            summaries = []
            for process in processes[:3]:
                if not isinstance(process, dict) or not isinstance(process.get("name"), str):
                    continue
                process_facts = [process["name"][:128]]
                cpu_percent = process.get("cpu_percent")
                memory_bytes = process.get("memory_bytes")
                if isinstance(cpu_percent, (int, float)) and not isinstance(cpu_percent, bool):
                    process_facts.append(f"cpu_percent={cpu_percent:.1f}")
                if isinstance(memory_bytes, int) and not isinstance(memory_bytes, bool):
                    process_facts.append(f"memory_bytes={memory_bytes}")
                summaries.append(" ".join(process_facts))
            if summaries:
                facts.append(f"top_processes={'; '.join(summaries)}")
        incidents = record.data.get("incidents")
        if isinstance(incidents, list):
            facts.append(f"incident_count={len(incidents)}")
        suffix = f" ({', '.join(facts)})" if facts else ""
        return f"{record.evidence_type.value}: {record.status.value}{suffix}"
