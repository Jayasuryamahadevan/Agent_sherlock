import pytest

from diagnostic_intelligence.engines.diagnostic_decision import DiagnosticDecisionEngine
from diagnostic_intelligence.engines.problem_understanding import ProblemUnderstandingEngine
from diagnostic_intelligence.models.classification import Category
from tests.helpers import evidence


@pytest.mark.parametrize(
    ("complaint", "expected_category"),
    [
        ("My drive is full and storage is low.", Category.STORAGE),
        ("The Wi-Fi internet is not working.", Category.NETWORK),
        ("My laptop is slow.", Category.SYSTEM_PERFORMANCE),
        ("Windows has a system error and hangs.", Category.WINDOWS_HEALTH),
        ("Oracle SQL Developer app won't start.", Category.APPLICATION_COMPATIBILITY),
        ("My device driver is failing.", Category.DRIVER),
    ],
)
def test_plan_selects_documented_evidence(complaint: str, expected_category: Category) -> None:
    understanding = ProblemUnderstandingEngine().understand(complaint)
    plan = DiagnosticDecisionEngine().create_plan(understanding, session_id="test-session")
    assert plan.category == expected_category
    assert plan.evidence_requests
    assert all(request.evidence_id.startswith("evidence.") for request in plan.evidence_requests)
    assert all(not request.parameters for request in plan.evidence_requests)


def test_planner_does_not_request_already_available_evidence() -> None:
    understanding = ProblemUnderstandingEngine().understand("My laptop is slow.")
    plan = DiagnosticDecisionEngine().create_plan(
        understanding,
        [evidence("performance.cpu", {"utilization_percent": 22})],
        "test-session",
    )
    assert all(request.evidence_type.value != "performance.cpu" for request in plan.evidence_requests)
