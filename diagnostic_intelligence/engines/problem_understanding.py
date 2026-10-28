"""Rule-based complaint classification, without external model dependencies."""

import re

from diagnostic_intelligence.models.classification import Category, ProblemUnderstanding


_CATEGORY_TERMS: dict[Category, tuple[str, ...]] = {
    Category.STORAGE: (
        "disk space", "storage", "drive full", "low space", "disk is full",
        "hard drive", "ssd", "disk utilization",
    ),
    Category.NETWORK: (
        "internet", "wifi", "wi-fi", "network", "dns", "gateway",
        "cannot connect", "connection drops", "no connection", "website", "web page",
        "pages won't load", "won't load", "browser", "online",
    ),
    Category.SYSTEM_PERFORMANCE: (
        "slow", "sluggish", "high cpu", "cpu usage", "memory usage",
        "ram", "freezes under load", "performance",
    ),
    Category.WINDOWS_HEALTH: (
        "hang", "hanging", "crash", "blue screen", "system error",
        "windows error", "unexpected restart", "unstable", "printer", "printing",
        "print spooler", "service stopped", "service is not running",
    ),
    Category.APPLICATION_COMPATIBILITY: (
        "application", "app won't start", "app does not start", "startup failure",
        "runtime", "dependency", "sql developer", "java",
    ),
    Category.DRIVER: (
        "driver", "device manager", "device unavailable", "device not working",
        "adapter stopped", "driver update",
    ),
}

_SEVERITY_TERMS = ("extremely", "severe", "cannot use", "completely", "critical")
_RECENT_CHANGE_TERMS = ("after update", "after installing", "recently installed", "recent change")
_TIME_MARKERS = ("after ", "when ", "while ", "since ", "for about ", "for approximately ")
_COMPONENT_PATTERN = re.compile(
    r"\b(C:[\\/]|[A-Z]:\\|wi-?fi|ethernet|network adapter|cpu|memory|ram|"
    r"disk|drive|sql developer|java|printer|graphics card)\b",
    re.IGNORECASE,
)


class ProblemUnderstandingEngine:
    """Deterministic keyword classifier.

    Used for triage in rules mode and by the legacy orchestrator. In AI mode the agent
    triages with the language model instead; there is no hidden AI-to-rules fallback.
    """

    def __init__(self, ai_agent: object | None = None) -> None:
        # Kept for backward compatibility; the classifier never calls an AI model.
        self.ai_agent = ai_agent

    def understand(self, complaint: str) -> ProblemUnderstanding:
        normalized = complaint.strip()
        if not normalized:
            raise ValueError("complaint must not be blank")
        if len(normalized) > 4000:
            raise ValueError("complaint must not exceed 4000 characters")

        text = normalized.casefold()
        scores = {
            category: sum(1 for term in terms if term in text)
            for category, terms in _CATEGORY_TERMS.items()
        }
        ranked = sorted(
            ((score, category) for category, score in scores.items() if score),
            reverse=True,
        )
        if not ranked:
            return ProblemUnderstanding(
                original_complaint=normalized,
                primary_category=Category.UNKNOWN,
                symptoms=[normalized],
                missing_information=["What Windows symptom or component is affected?"],
                clarification_questions=[
                    "What is happening on your Windows computer, and when does it happen?"
                ],
                needs_clarification=True,
                classification_confidence=0.0,
                classification_explanation=(
                    "No supported category-specific symptom was identified; classification is unknown."
                ),
            )

        best_score, primary = ranked[0]
        secondary = [
            category
            for score, category in ranked[1:]
            if score >= 1
        ]
        confidence = min(0.95, 0.55 + (best_score - 1) * 0.12)
        if secondary:
            confidence = max(0.45, confidence - 0.08 * len(secondary))
        ambiguous = sum(score == best_score for score, _ in ranked) > 1
        component_match = _COMPONENT_PATTERN.search(normalized)
        time_pattern = next(
            (
                normalized[normalized.casefold().find(marker):].strip(" .")
                for marker in _TIME_MARKERS
                if marker in text
            ),
            None,
        )
        recent_changes = (
            "A recent update or installation is mentioned."
            if any(marker in text for marker in _RECENT_CHANGE_TERMS)
            else None
        )
        missing = self._missing_information(primary)
        return ProblemUnderstanding(
            original_complaint=normalized,
            primary_category=primary,
            secondary_categories=secondary,
            symptoms=[normalized],
            affected_component=component_match.group(0) if component_match else None,
            time_pattern=time_pattern,
            recent_changes=recent_changes,
            severity_or_impact=(
                "High impact language is reported."
                if any(term in text for term in _SEVERITY_TERMS)
                else None
            ),
            missing_information=missing,
            clarification_questions=(
                ["Which symptom is the main issue, and what changed most recently?"]
                if ambiguous
                else []
            ),
            needs_clarification=ambiguous,
            classification_confidence=confidence,
            classification_explanation=(
                f"Matched {best_score} category-specific phrase(s) for '{primary.value}'."
                + (
                    " Other categories also matched; treat this as a possible multi-category issue."
                    if secondary
                    else ""
                )
            ),
        )

    @staticmethod
    def _missing_information(category: Category) -> list[str]:
        return {
            Category.STORAGE: ["Which drive is affected and when did the issue begin?"],
            Category.NETWORK: ["Does the issue affect all network destinations or only specific ones?"],
            Category.SYSTEM_PERFORMANCE: ["When does the slowdown occur and for how long?"],
            Category.WINDOWS_HEALTH: ["When did the hang/error occur and how often?"],
            Category.APPLICATION_COMPATIBILITY: ["Which application version and exact startup error are involved?"],
            Category.DRIVER: ["Which device is affected and did anything change recently?"],
        }.get(category, [])
