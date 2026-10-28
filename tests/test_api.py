from datetime import datetime, timezone

from fastapi.testclient import TestClient

from diagnostic_intelligence import api
from diagnostic_intelligence.api import create_app
from diagnostic_intelligence.models.evidence import EvidenceRecord


class StubCollector:
    def collect_for_plan(self, plan):
        return [
            EvidenceRecord(
                session_id=plan.session_id,
                evidence_id="performance.cpu",
                evidence_type="performance.cpu",
                collected_at=datetime.now(timezone.utc),
                status="available",
                data={"utilization_percent": 96},
                source="api_test_fixture",
            )
        ]


def test_health_endpoint_reports_service_ready() -> None:
    client = TestClient(create_app(collector_factory=StubCollector))

    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_diagnostic_endpoint_runs_and_retrieves_session() -> None:
    client = TestClient(create_app(collector_factory=StubCollector))

    response = client.post(
        "/api/diagnostics",
        json={
            "session_id": "api-test-001",
            "complaint": "My laptop is slow.",
            "use_ai": False,
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "analysis_complete"
    assert result["ranked_root_causes"][0]["cause_id"] == "performance.cpu_saturation"
    assert client.get("/api/diagnostics/api-test-001").json() == result


def test_diagnostic_endpoint_rejects_blank_complaint() -> None:
    client = TestClient(create_app(collector_factory=StubCollector))

    response = client.post("/api/diagnostics", json={"complaint": "  "})

    assert response.status_code == 422


def test_get_diagnostic_returns_not_found_for_unknown_session() -> None:
    client = TestClient(create_app(collector_factory=StubCollector))

    response = client.get("/api/diagnostics/no-such-session")

    assert response.status_code == 404


def test_api_uses_long_timeout_for_optional_summary_only(monkeypatch) -> None:
    class FakeSummaryAgent:
        model = "test-model"
        timeouts = []

        def __init__(self, timeout):
            self.timeouts.append(timeout)

        def generate_diagnostic_summary(self, **kwargs):
            return "Summary based on supplied evidence."

    monkeypatch.setattr(api, "OllamaAgent", FakeSummaryAgent)
    client = TestClient(create_app(collector_factory=StubCollector))

    response = client.post(
        "/api/diagnostics",
        json={
            "session_id": "api-ai-test",
            "complaint": "My laptop is slow.",
            "use_ai": True,
        },
    )

    assert response.status_code == 200
    assert response.json()["ai_summary"] == "Summary based on supplied evidence."
    assert response.json()["ai_model"] == "test-model"
    assert FakeSummaryAgent.timeouts == [90]


def test_api_does_not_label_missing_summary_as_ollama_output(monkeypatch) -> None:
    class UnavailableSummaryAgent:
        model = "test-model"

        def __init__(self, timeout):
            self.timeout = timeout

        def generate_diagnostic_summary(self, **kwargs):
            return None

    monkeypatch.setattr(api, "OllamaAgent", UnavailableSummaryAgent)
    client = TestClient(create_app(collector_factory=StubCollector))

    response = client.post(
        "/api/diagnostics",
        json={
            "session_id": "api-no-summary-test",
            "complaint": "My laptop is slow.",
            "use_ai": True,
        },
    )

    assert response.status_code == 200
    assert response.json()["ai_summary"] is None
    assert response.json()["ai_model"] is None
    assert any("Optional Ollama summary could not be generated" in warning for warning in response.json()["warnings"])