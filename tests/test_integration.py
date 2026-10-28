from datetime import datetime, timezone

from diagnostic_intelligence import DiagnosticOrchestrator


class FakeOllamaAgent:
    def __init__(self, summary: str = "AI summary") -> None:
        self.summary = summary

    def generate_diagnostic_summary(self, *, complaint: str, category: str, evidence_summary: list[str], root_causes: list[str]) -> str:
        return self.summary


def test_end_to_end_classification_planning_analysis_and_result() -> None:
    result = DiagnosticOrchestrator().run(
        {"session_id": "demo-001", "complaint": "My laptop is slow."},
        [
            {
                "session_id": "demo-001",
                "evidence_id": "cpu.sample",
                "evidence_type": "performance.cpu",
                "collected_at": datetime.now(timezone.utc).isoformat(),
                "status": "available",
                "data": {"utilization_percent": 96},
                "source": "synthetic_test_fixture",
            }
        ],
    )
    payload = result.model_dump(mode="json")
    assert payload["status"] == "analysis_complete"
    assert payload["primary_category"] == "system_performance"
    assert payload["ranked_root_causes"][0]["cause_id"] == "performance.cpu_saturation"
    assert payload["evidence_summary"] == ["performance.cpu: available (utilization_percent=96)"]
    assert "resolved" not in payload["status"]


def test_orchestrator_survives_malformed_evidence_and_reports_warning() -> None:
    result = DiagnosticOrchestrator().run(
        {"session_id": "demo-001", "complaint": "My laptop is slow."},
        [{"evidence_type": "performance.cpu", "data": {"utilization_percent": 99}}],
    )
    assert result.status.value == "collecting_evidence"
    assert any("malformed" in warning for warning in result.warnings)


def test_unknown_complaint_requires_clarification() -> None:
    result = DiagnosticOrchestrator().run({"complaint": "Help me with my computer"})
    assert result.status.value == "needs_clarification"
    assert result.primary_category.value == "unknown"


def test_foreign_session_evidence_is_reported_and_not_scored() -> None:
    result = DiagnosticOrchestrator().run(
        {"session_id": "demo-001", "complaint": "My laptop is slow."},
        [{
            "session_id": "another-session",
            "evidence_id": "cpu.sample",
            "evidence_type": "performance.cpu",
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "status": "available",
            "data": {"utilization_percent": 99},
        }],
    )
    assert result.status.value == "collecting_evidence"
    assert any("different session" in warning for warning in result.warnings)


def test_orchestrator_can_enrich_result_with_ollama_summary() -> None:
    result = DiagnosticOrchestrator().run(
        {"session_id": "demo-001", "complaint": "My laptop is slow."},
        [{
            "session_id": "demo-001",
            "evidence_id": "cpu.sample",
            "evidence_type": "performance.cpu",
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "status": "available",
            "data": {"utilization_percent": 96},
            "source": "synthetic_test_fixture",
        }],
        use_ai=True,
        ai_agent=FakeOllamaAgent("AI summary enabled"),
    )
    assert result.ai_summary == "AI summary enabled"
    assert result.ai_model is not None
