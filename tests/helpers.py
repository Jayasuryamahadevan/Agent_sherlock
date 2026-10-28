from datetime import datetime, timezone
from typing import Any

from diagnostic_intelligence.models.evidence import EvidenceRecord


def evidence(
    evidence_type: str,
    data: dict[str, Any],
    evidence_id: str = "test.evidence",
    session_id: str = "test-session",
    collected_at: datetime | None = None,
    status: str = "available",
) -> EvidenceRecord:
    return EvidenceRecord(
        session_id=session_id,
        evidence_id=evidence_id,
        evidence_type=evidence_type,
        collected_at=collected_at or datetime.now(timezone.utc),
        status=status,
        data=data,
        source="synthetic_test_fixture",
    )
