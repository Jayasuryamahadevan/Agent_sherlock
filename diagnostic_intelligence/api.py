"""Local HTTP API.

* ``/api/agent/*``: the evidence-driven agent and its three execution pipelines.
* ``/api/diagnostics``: the original single-pass, rule-based analysis (kept for compatibility).
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from collections.abc import Callable
from typing import Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from diagnostic_intelligence.agent.llm import AgyClient, LLMClient
from diagnostic_intelligence.agent.models import ReasoningMode, SessionReport
from diagnostic_intelligence.agent.pipelines import PIPELINES, AgentSession, BasePipeline
from diagnostic_intelligence.agent.reasoning import AIReasoner, RuleReasoner
from diagnostic_intelligence.agent.runtime import RuntimeConfig, make_pipeline
from diagnostic_intelligence.ai.ollama_agent import OllamaAgent
from diagnostic_intelligence.collectors.windows import WindowsEvidenceCollector
from diagnostic_intelligence.engines.diagnostic_orchestrator import DiagnosticOrchestrator
from diagnostic_intelligence.models.recommendations import DiagnosticResult
from diagnostic_intelligence.models.requests import DiagnosticRequest
from diagnostic_intelligence.remediation.approval import ApprovalResponse
from diagnostic_intelligence.remediation.backends import WindowsActionBackend
from diagnostic_intelligence.simulation.host import SCENARIOS, build_scenario

MAX_SESSIONS = 200


class DiagnosticRunRequest(DiagnosticRequest):
    """Legacy request with optional local Ollama summary generation."""

    model_config = ConfigDict(extra="forbid")

    use_ai: bool = False


class AgentRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    complaint: str = Field(min_length=1, max_length=4000)
    pipeline: Literal["automatic_execution", "auto_resolution", "whitelist_approval"]
    reasoning: ReasoningMode | None = None
    scenario: str | None = Field(default=None, max_length=64)


class ApprovalBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision_id: str = Field(min_length=1, max_length=64)
    approved: bool
    note: str = Field(default="", max_length=500)


def create_app(
    collector_factory: Callable[[], object] = WindowsEvidenceCollector,
    *,
    agent_config: RuntimeConfig | None = None,
    llm_factory: Callable[[], LLMClient] | None = None,
) -> FastAPI:
    config = agent_config or RuntimeConfig.from_env()
    make_llm = llm_factory or (lambda: AgyClient())
    app = FastAPI(
        title="Windows Diagnostic Agent API",
        version="0.2.0",
        description="Local-only API: evidence collection, AI reasoning, and three controlled execution pipelines.",
    )
    app.state.sessions = {}
    app.state.agent_sessions: OrderedDict[str, tuple[BasePipeline, AgentSession]] = OrderedDict()
    lock = threading.Lock()

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "windows-diagnostic-intelligence"}

    # ------------------------------------------------------------------ agent
    @app.get("/api/agent/config")
    def agent_config_view() -> dict:
        llm = make_llm()
        ai_ok, ai_detail = llm.health() if hasattr(llm, "health") else (True, "Custom model client configured.")
        if config.backend == "windows":
            backend = WindowsActionBackend(config.allow_system_changes)
            elevated, changes = backend.is_elevated(), backend.allow_changes
        else:
            elevated, changes = True, True
        return {
            "backend": config.backend,
            "default_reasoning": config.reasoning.value,
            "ai": {"available": ai_ok, "detail": ai_detail, "model": getattr(llm, "model", None)},
            "elevated": elevated,
            "system_changes_enabled": changes,
            "pipelines": [cls.policy.describe() for cls in PIPELINES.values()],
            "scenarios": (
                [{"name": name, "description": build_scenario(name).description,
                  "sample_complaint": build_scenario(name).sample_complaint} for name in SCENARIOS]
                if config.backend == "simulated" else []
            ),
        }

    @app.post("/api/agent/sessions", response_model=SessionReport)
    def start_session(body: AgentRunRequest) -> SessionReport:
        if not body.complaint.strip():
            raise HTTPException(status_code=422, detail="complaint must not be blank")
        if body.scenario and config.backend != "simulated":
            raise HTTPException(status_code=400, detail="Scenarios are only available with the simulated backend.")
        if body.scenario and body.scenario not in SCENARIOS:
            raise HTTPException(status_code=400, detail=f"Unknown scenario. Choose one of {sorted(SCENARIOS)}.")
        mode = body.reasoning or config.reasoning
        reasoner = RuleReasoner() if mode == ReasoningMode.RULES else AIReasoner(make_llm())
        run_config = RuntimeConfig(**{**config.__dict__, "scenario": body.scenario or config.scenario})
        pipeline, _ = make_pipeline(body.pipeline, run_config, reasoner=reasoner)
        session = pipeline.start(body.complaint)
        with lock:
            app.state.agent_sessions[session.session_id] = (pipeline, session)
            while len(app.state.agent_sessions) > MAX_SESSIONS:
                app.state.agent_sessions.popitem(last=False)
        return pipeline.report(session)

    @app.get("/api/agent/sessions/{session_id}", response_model=SessionReport)
    def get_session(session_id: str) -> SessionReport:
        entry = app.state.agent_sessions.get(session_id)
        if entry is None:
            raise HTTPException(status_code=404, detail="Session not found (sessions are kept in memory only).")
        pipeline, session = entry
        return pipeline.report(session)

    @app.post("/api/agent/sessions/{session_id}/approval", response_model=SessionReport)
    def approve(session_id: str, body: ApprovalBody) -> SessionReport:
        entry = app.state.agent_sessions.get(session_id)
        if entry is None:
            raise HTTPException(status_code=404, detail="Session not found.")
        pipeline, session = entry
        try:
            pipeline.resume(session, ApprovalResponse(decision_id=body.decision_id, approved=body.approved,
                                                      approver="local-user", note=body.note))
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        return pipeline.report(session)

    # ----------------------------------------------------------------- legacy
    @app.post("/api/diagnostics", response_model=DiagnosticResult)
    def run_diagnostic(payload: DiagnosticRunRequest) -> DiagnosticResult:
        summary_agent = OllamaAgent(timeout=90) if payload.use_ai else None
        orchestrator = DiagnosticOrchestrator(ai_agent=None, evidence_collector=collector_factory())
        result = orchestrator.run(payload, use_ai=payload.use_ai, ai_agent=summary_agent)
        if result.session_id is None:
            raise HTTPException(status_code=500, detail="Diagnostic session could not be created.")
        app.state.sessions[result.session_id] = result
        return result

    @app.get("/api/diagnostics/{session_id}", response_model=DiagnosticResult)
    def get_diagnostic(session_id: str) -> DiagnosticResult:
        result = app.state.sessions.get(session_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Diagnostic session was not found.")
        return result

    return app


app = create_app()
