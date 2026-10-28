"""Wire collectors, backends, reasoners and pipelines from configuration."""

from __future__ import annotations

import os
import platform
from dataclasses import dataclass

from diagnostic_intelligence.agent.audit import AuditLog
from diagnostic_intelligence.agent.llm import AgyClient, LLMClient
from diagnostic_intelligence.agent.models import ReasoningMode
from diagnostic_intelligence.agent.pipelines import BasePipeline, build_pipeline
from diagnostic_intelligence.agent.reasoning import AIReasoner, Reasoner, RuleReasoner
from diagnostic_intelligence.collectors.windows import WindowsEvidenceCollector
from diagnostic_intelligence.remediation.approval import ApprovalProvider
from diagnostic_intelligence.remediation.backends import WindowsActionBackend
from diagnostic_intelligence.simulation.host import (
    SimulatedActionBackend,
    SimulatedEvidenceCollector,
    SimulatedHost,
    build_scenario,
)


@dataclass
class RuntimeConfig:
    backend: str = "windows"              # "windows" or "simulated"
    scenario: str = "dns_cache_stale"     # simulated backend only
    reasoning: ReasoningMode = ReasoningMode.AI
    allow_system_changes: bool | None = None
    audit_dir: str | None = None

    @classmethod
    def from_env(cls) -> "RuntimeConfig":
        default_backend = "windows" if platform.system() == "Windows" else "simulated"
        return cls(
            backend=os.environ.get("DIAG_BACKEND", default_backend).strip().lower(),
            scenario=os.environ.get("DIAG_SCENARIO", "dns_cache_stale").strip(),
            reasoning=ReasoningMode(os.environ.get("DIAG_REASONING", "ai").strip().lower()),
            allow_system_changes=None,
            audit_dir=os.environ.get("DIAG_AUDIT_DIR", "audit_logs"),
        )


def make_reasoner(mode: ReasoningMode, llm: LLMClient | None = None) -> Reasoner:
    if mode == ReasoningMode.RULES:
        return RuleReasoner()
    return AIReasoner(llm or AgyClient())


def make_pipeline(
    pipeline_id: str,
    config: RuntimeConfig,
    *,
    reasoner: Reasoner | None = None,
    approval_provider: ApprovalProvider | None = None,
    host: SimulatedHost | None = None,
) -> tuple[BasePipeline, SimulatedHost | None]:
    if config.backend == "simulated":
        host = host or build_scenario(config.scenario)
        collector, backend = SimulatedEvidenceCollector(host), SimulatedActionBackend(host)
    elif config.backend == "windows":
        collector, backend = WindowsEvidenceCollector(), WindowsActionBackend(config.allow_system_changes)
    else:
        raise ValueError("backend must be 'windows' or 'simulated'")
    pipeline = build_pipeline(
        pipeline_id,
        reasoner=reasoner or make_reasoner(config.reasoning),
        collector=collector,
        backend=backend,
        approval_provider=approval_provider,
        audit=AuditLog(config.audit_dir),
    )
    return pipeline, host
