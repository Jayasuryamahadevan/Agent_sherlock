"""Read-only helpers over collected evidence, shared by policy, verification and reasoning."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from diagnostic_intelligence.models.evidence import EvidenceRecord, EvidenceStatus, EvidenceType

_USABLE = (EvidenceStatus.AVAILABLE, EvidenceStatus.PARTIAL)
_MISSING = object()


class EvidenceView:
    """Indexed, immutable view of a session's evidence records (in collection order)."""

    def __init__(self, records: Iterable[EvidenceRecord]) -> None:
        self.records: list[EvidenceRecord] = list(records)
        self._by_id = {record.evidence_id: record for record in self.records}

    def get(self, evidence_id: str) -> EvidenceRecord | None:
        return self._by_id.get(evidence_id)

    def usable(self) -> list[EvidenceRecord]:
        return [record for record in self.records if record.status in _USABLE]

    def latest(self, evidence_type: EvidenceType) -> EvidenceRecord | None:
        """Most recently collected usable record of a type, or None."""
        for record in reversed(self.records):
            if record.evidence_type == evidence_type and record.status in _USABLE:
                return record
        return None

    def latest_data(self, evidence_type: EvidenceType) -> dict[str, Any] | None:
        record = self.latest(evidence_type)
        return record.data if record else None

    def types_attempted(self) -> set[EvidenceType]:
        return {record.evidence_type for record in self.records}


def resolve_field(data: Any, path: str) -> Any:
    """Resolve 'a.b.0.c' or 'a.b[0].c' inside JSON-like data; returns _MISSING sentinel when absent."""
    normalized = path.replace("[", ".").replace("]", "")
    current = data
    for part in [segment for segment in normalized.split(".") if segment]:
        if isinstance(current, dict):
            if part not in current:
                return _MISSING
            current = current[part]
        elif isinstance(current, list):
            if not part.isdigit() or int(part) >= len(current):
                return _MISSING
            current = current[int(part)]
        else:
            return _MISSING
    return current


def is_missing(value: Any) -> bool:
    return value is _MISSING


def values_match(claimed: Any, actual: Any) -> bool:
    """Tolerant equality used to check that a model quoted evidence correctly."""
    if isinstance(actual, bool) or isinstance(claimed, bool):
        if isinstance(claimed, str):
            return claimed.strip().casefold() == str(actual).casefold()
        return claimed is actual
    if isinstance(actual, (int, float)):
        try:
            claimed_number = float(str(claimed).rstrip("%").strip()) if isinstance(claimed, str) else float(claimed)
        except (TypeError, ValueError):
            return False
        tolerance = max(0.5, abs(float(actual)) * 0.02)
        return abs(claimed_number - float(actual)) <= tolerance
    if isinstance(actual, str):
        return isinstance(claimed, str) and claimed.strip().casefold() == actual.strip().casefold()
    if actual is None:
        return claimed is None or (isinstance(claimed, str) and claimed.strip().casefold() in {"null", "none"})
    return claimed == actual
