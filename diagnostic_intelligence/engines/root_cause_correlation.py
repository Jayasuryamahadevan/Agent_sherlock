"""Evidence-based correlation rules and heuristic confidence scoring."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from diagnostic_intelligence.models.classification import Category, ProblemUnderstanding
from diagnostic_intelligence.models.diagnostic_plan import DiagnosticPlan
from diagnostic_intelligence.models.evidence import (
    EvidenceRecord,
    EvidenceStatus,
    EvidenceType,
    evidence_is_stale,
)
from diagnostic_intelligence.models.recommendations import (
    RemediationCandidate,
    RootCauseCandidate,
)


Predicate = Callable[[dict[str, Any]], bool]


@dataclass(frozen=True)
class CauseRule:
    cause_id: str
    category: Category
    title: str
    explanation: str
    evidence_type: EvidenceType
    supports: Predicate
    contradicts: Predicate
    next_step: str
    action_type: str | None = None


def _number(data: dict[str, Any], key: str) -> float | None:
    value = data.get(key)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    samples = data.get("samples")
    if isinstance(samples, list):
        for sample in reversed(samples):
            if isinstance(sample, dict):
                value = sample.get(key)
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    return float(value)
    return None


def _capacity_values(data: dict[str, Any]) -> list[tuple[float | None, float | None]]:
    values: list[tuple[float | None, float | None]] = []
    volumes = data.get("volumes")
    if isinstance(volumes, list):
        for volume in volumes:
            if not isinstance(volume, dict):
                continue
            free_bytes = _number(volume, "free_bytes")
            total_bytes = _number(volume, "total_bytes")
            free_percent = _number(volume, "free_percent")
            if free_percent is None and free_bytes is not None and total_bytes:
                free_percent = free_bytes / total_bytes * 100
            free_gb = _number(volume, "free_gb")
            if free_gb is None and free_bytes is not None:
                free_gb = free_bytes / (1024 ** 3)
            values.append((free_percent, free_gb))
    if data.get("free_percent") is not None or data.get("free_gb") is not None:
        values.append((_number(data, "free_percent"), _number(data, "free_gb")))
    return values


def _has_runtime_error(data: dict[str, Any]) -> bool:
    categories = [data.get("error_category")]
    errors = data.get("errors")
    if isinstance(errors, list):
        categories.extend(
            error.get("error_category") for error in errors if isinstance(error, dict)
        )
    return any(
        isinstance(category, str)
        and category.casefold() in {"missing_runtime", "incompatible_runtime", "missing_dependency"}
        for category in categories
    )


def _has_reliability_failure(data: dict[str, Any]) -> bool:
    incidents = data.get("incidents")
    if not isinstance(incidents, list):
        return False
    return any(
        isinstance(incident, dict)
        and isinstance(incident.get("type"), str)
        and incident["type"].casefold() in {"application error", "application hang"}
        for incident in incidents
    )


def _eq(value: Any, expected: Any) -> bool:
    return isinstance(value, str) and value.casefold() == expected


def _adapter_statuses(data: dict[str, Any]) -> list[str]:
    adapters = data.get("adapters")
    if not isinstance(adapters, list):
        return []
    # Loopback/pseudo interfaces are always "up" on Windows and say nothing about connectivity.
    return [
        adapter["status"].casefold()
        for adapter in adapters
        if isinstance(adapter, dict)
        and isinstance(adapter.get("status"), str)
        and not any(token in str(adapter.get("name", "")).casefold() for token in ("loopback", "pseudo-interface"))
    ]


_LOOPBACK_NAMES = ("loopback", "lo", "pseudo-interface")


def _routable_ipv4(address: Any) -> bool:
    if not isinstance(address, str) or ":" in address:
        return False
    return not (address.startswith("169.254.") or address.startswith("127."))


def _has_no_valid_address(data: dict[str, Any]) -> bool:
    """An up, non-loopback adapter exists but none has a routable IPv4 address (e.g. APIPA)."""
    adapters = data.get("adapters")
    if not isinstance(adapters, list):
        return False
    candidates = [
        adapter for adapter in adapters
        if isinstance(adapter, dict)
        and _eq(adapter.get("status"), "up")
        and isinstance(adapter.get("name"), str)
        and not any(token in adapter["name"].casefold() for token in _LOOPBACK_NAMES)
    ]
    if not candidates:
        return False
    return not any(
        _routable_ipv4(address)
        for adapter in candidates
        for address in adapter.get("addresses", []) or []
    )


def _stopped_auto_services(data: dict[str, Any]) -> list[str]:
    services = data.get("services")
    if not isinstance(services, list):
        return []
    return [
        service["name"]
        for service in services
        if isinstance(service, dict)
        and isinstance(service.get("name"), str)
        and _eq(service.get("start_mode"), "auto")
        and isinstance(service.get("state"), str)
        and service["state"].casefold() != "running"
    ]


RULES: tuple[CauseRule, ...] = (
    CauseRule(
        "storage.low_free_space", Category.STORAGE, "Insufficient free disk space",
        "Collected volume capacity shows critically low free space; this supports a storage capacity issue but does not identify which files caused it.",
        EvidenceType.STORAGE_CAPACITY,
        lambda d: any(
            free_percent is not None and free_percent <= 10
            or free_gb is not None and free_gb <= 2
            for free_percent, free_gb in _capacity_values(d)
        ),
        lambda d: any(
            free_percent is not None and free_percent >= 25
            or free_gb is not None and free_gb >= 10
            for free_percent, free_gb in _capacity_values(d)
        ),
        "Review per-volume capacity and identify large storage consumers using a privacy-safe collector.",
        "review_storage_cleanup",
    ),
    CauseRule(
        "storage.disk_saturation", Category.STORAGE, "High disk activity",
        "Collected disk activity is at or above the high-utilization threshold.",
        EvidenceType.DISK_ACTIVITY,
        lambda d: (_number(d, "utilization_percent") or 0) >= 90,
        lambda d: (_number(d, "utilization_percent") is not None and _number(d, "utilization_percent") <= 50),
        "Repeat aggregate disk measurements during the reported slowdown.",
    ),
    CauseRule(
        "storage.recurring_errors", Category.STORAGE, "Recurring storage-related system errors",
        "Repeated System event metadata from storage providers supports further storage investigation, but does not establish disk failure.",
        EvidenceType.STORAGE_ERRORS,
        lambda d: (_number(d, "recurring_error_count") or 0) >= 3,
        lambda d: _number(d, "recurring_error_count") == 0,
        "Compare storage event timestamps with the reported symptoms and fresh disk activity before drawing a stronger conclusion.",
    ),
    CauseRule(
        "network.dns_failure", Category.NETWORK, "DNS resolution failure",
        "A DNS resolution test explicitly failed; this supports a name-resolution issue, not a general internet diagnosis.",
        EvidenceType.DNS_RESOLUTION,
        lambda d: d.get("success") is False,
        lambda d: d.get("success") is True,
        "Compare DNS resolution with gateway and permitted endpoint connectivity.",
        "review_dns_configuration",
    ),
    CauseRule(
        "network.gateway_unreachable", Category.NETWORK, "Default gateway unreachable",
        "The collected gateway reachability test reports the default gateway as unreachable.",
        EvidenceType.GATEWAY_REACHABILITY,
        lambda d: isinstance(d.get("gateway"), str) and bool(d["gateway"]) and d.get("reachable") is False,
        lambda d: isinstance(d.get("gateway"), str) and bool(d["gateway"]) and d.get("reachable") is True,
        "Check adapter status and IP configuration before considering any network change.",
    ),
    CauseRule(
        "network.permitted_endpoint_unreachable", Category.NETWORK,
        "Permitted network endpoint unreachable",
        "A connectivity test to a configured permitted endpoint failed. This indicates a connectivity problem but does not identify its cause.",
        EvidenceType.NETWORK_CONNECTIVITY,
        lambda d: d.get("reachable") is False,
        lambda d: d.get("reachable") is True,
        "Compare the endpoint result with gateway reachability and DNS evidence.",
    ),
    CauseRule(
        "network.adapter_unavailable", Category.NETWORK, "Network adapter unavailable",
        "All reported network adapters are explicitly down; this indicates network access may be unavailable but does not identify the underlying cause.",
        EvidenceType.ADAPTER_STATUS,
        lambda d: bool(_adapter_statuses(d)) and all(
            status == "down" for status in _adapter_statuses(d)
        ),
        lambda d: any(
            status in {"up", "connected", "ok"}
            for status in _adapter_statuses(d)
        ),
        "Identify the relevant adapter and check its device status and recent driver events.",
    ),
    CauseRule(
        "performance.cpu_saturation", Category.SYSTEM_PERFORMANCE, "High CPU utilization",
        "CPU measurements show sustained high utilization; a process-level cause is not identified unless process evidence is available.",
        EvidenceType.CPU_METRICS,
        lambda d: (_number(d, "utilization_percent") or 0) >= 85,
        lambda d: (_number(d, "utilization_percent") is not None and _number(d, "utilization_percent") <= 50),
        "Collect a bounded process summary during the same high-utilization interval.",
    ),
    CauseRule(
        "performance.memory_pressure", Category.SYSTEM_PERFORMANCE, "Memory pressure",
        "Collected memory metrics show low available memory or high utilization.",
        EvidenceType.MEMORY_METRICS,
        lambda d: (_number(d, "available_percent") is not None and _number(d, "available_percent") <= 10)
        or (_number(d, "used_percent") is not None and _number(d, "used_percent") >= 90),
        lambda d: (_number(d, "available_percent") is not None and _number(d, "available_percent") >= 30)
        or (_number(d, "used_percent") is not None and _number(d, "used_percent") <= 60),
        "Collect a process summary to determine whether any process coincides with memory pressure.",
    ),
    CauseRule(
        "performance.disk_bottleneck", Category.SYSTEM_PERFORMANCE, "High disk utilization",
        "Collected disk activity is at or above 90% utilization during the reported issue.",
        EvidenceType.DISK_ACTIVITY,
        lambda d: (_number(d, "utilization_percent") or 0) >= 90,
        lambda d: (_number(d, "utilization_percent") is not None and _number(d, "utilization_percent") <= 50),
        "Correlate disk utilization and latency with process-level evidence during the slowdown.",
    ),
    CauseRule(
        "windows_health.recurring_errors", Category.WINDOWS_HEALTH, "Recurring Windows system errors",
        "Relevant recurring error events were collected; timing correlation is supportive evidence, not proof of causation.",
        EvidenceType.SYSTEM_EVENTS,
        lambda d: (_number(d, "recurring_error_count") or 0) >= 3,
        lambda d: _number(d, "recurring_error_count") == 0,
        "Compare event timestamps with the user's reported hang times and reliability summary.",
    ),
    CauseRule(
        "windows_health.reliability_failure", Category.WINDOWS_HEALTH,
        "Application failure or hang recorded",
        "Windows reliability metadata contains an application error or hang record; this is evidence of an incident, not proof that it caused the reported symptom.",
        EvidenceType.RELIABILITY_SUMMARY,
        _has_reliability_failure,
        lambda d: isinstance(d.get("incidents"), list) and not _has_reliability_failure(d),
        "Compare the incident timestamp with the reported symptom and collect application-specific evidence before drawing a stronger conclusion.",
    ),
    CauseRule(
        "application.runtime_incompatibility", Category.APPLICATION_COMPATIBILITY,
        "Application runtime or dependency incompatibility",
        "The application log explicitly identifies a missing or incompatible runtime/dependency.",
        EvidenceType.APPLICATION_LOGS,
        _has_runtime_error,
        lambda d: _eq(d.get("error_category"), "runtime_ok"),
        "Compare the application's documented runtime requirements with collected runtime versions.",
    ),
    CauseRule(
        "application.startup_failure", Category.APPLICATION_COMPATIBILITY,
        "Application startup failure",
        "The application startup collector explicitly reports that the application did not start.",
        EvidenceType.APPLICATION_STARTUP,
        lambda d: d.get("started") is False,
        lambda d: d.get("started") is True,
        "Collect the application-specific startup error and relevant logs before proposing a change.",
    ),
    CauseRule(
        "driver.device_error", Category.DRIVER, "Device or driver error",
        "Windows device evidence reports a problem code for the relevant device; the precise cause is not established.",
        EvidenceType.DEVICE_STATUS,
        lambda d: any(
            bool(device.get("problem_code"))
            for device in d.get("devices", [])
            if isinstance(device, dict)
        ) if isinstance(d.get("devices"), list) else bool(d.get("problem_code")),
        lambda d: _eq(d.get("status"), "ok"),
        "Identify the exact device and correlate its status with driver details and recent events.",
    ),
    CauseRule(
        "driver.recurring_device_errors", Category.DRIVER, "Recurring device or driver errors",
        "Collected driver events report repeated errors associated with a device.",
        EvidenceType.DRIVER_EVENTS,
        lambda d: (_number(d, "recurring_error_count") or 0) >= 3,
        lambda d: _number(d, "recurring_error_count") == 0,
        "Compare the affected device's provider and version with its recent error and update history.",
    ),
    CauseRule(
        "network.no_valid_address", Category.NETWORK, "No valid IP address on the active adapter",
        "An active adapter has no routable IPv4 address (for example a 169.254.x.x self-assigned address), which usually means the DHCP lease was not obtained.",
        EvidenceType.NETWORK_CONFIGURATION,
        _has_no_valid_address,
        lambda d: isinstance(d.get("default_gateway"), str) and bool(d["default_gateway"]) and not _has_no_valid_address(d),
        "Renew the DHCP lease and re-check address assignment and gateway reachability.",
    ),
    CauseRule(
        "performance.disk_latency", Category.SYSTEM_PERFORMANCE, "High disk I/O latency",
        "Average disk I/O latency over the sample window is high, which can make applications slow to open.",
        EvidenceType.DISK_ACTIVITY,
        lambda d: (_number(d, "average_latency_ms") or 0) >= 50,
        lambda d: _number(d, "average_latency_ms") is not None and _number(d, "average_latency_ms") <= 10,
        "Correlate latency with free space and the process summary during the slowdown.",
    ),
    CauseRule(
        "windows_health.service_stopped", Category.WINDOWS_HEALTH, "Automatic Windows service not running",
        "A service configured to start automatically is not running, according to WMI/CIM service status.",
        EvidenceType.SERVICE_STATUS,
        lambda d: bool(_stopped_auto_services(d)),
        lambda d: isinstance(d.get("services"), list) and not _stopped_auto_services(d),
        "Check the service's recent errors and consider a controlled restart of that specific service.",
    ),
)

_ACTION_DETAILS = {
    "review_storage_cleanup": (
        "Review storage cleanup options", "Review identified large storage consumers.",
        "No files are deleted by this recommendation; user review and policy approval are required.",
    ),
    "review_dns_configuration": (
        "Review DNS configuration", "Review the configured DNS resolver and retest resolution.",
        "No network settings are changed by this recommendation; approval may be required.",
    ),
}


class RootCauseCorrelationEngine:
    """Correlate validated structured evidence; scores are heuristic, not probabilities."""

    def __init__(self, ai_agent: object | None = None) -> None:
        # Kept for backward compatibility; correlation rules never call an AI model.
        # In AI mode the agent runs these rules as a labelled deterministic cross-check.
        self.ai_agent = ai_agent

    def analyze(
        self,
        understanding: ProblemUnderstanding,
        plan: DiagnosticPlan,
        evidence: list[EvidenceRecord],
        now: datetime | None = None,
        max_age_hours: int = 24,
    ) -> tuple[list[RootCauseCandidate], list[str], list[str]]:
        now = now or datetime.now(timezone.utc)
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("now must include a timezone")
        categories = {understanding.primary_category, *understanding.secondary_categories}
        usable = [
            item for item in evidence
            if item.session_id == plan.session_id
            and item.status in (EvidenceStatus.AVAILABLE, EvidenceStatus.PARTIAL)
            and not evidence_is_stale(item, now, max_age_hours)
        ]
        stale = [
            item for item in evidence
            if item.session_id == plan.session_id
            and item.status in (EvidenceStatus.AVAILABLE, EvidenceStatus.PARTIAL)
            and evidence_is_stale(item, now, max_age_hours)
        ]
        warnings = [
            f"Evidence '{item.evidence_id}' is stale and was excluded from correlation."
            for item in stale
        ]
        warnings.extend(
            f"Evidence '{item.evidence_id}' has status '{item.status.value}' and was not used for cause scoring."
            for item in evidence
            if item.status in (EvidenceStatus.UNAVAILABLE, EvidenceStatus.ERROR)
        )
        warnings.extend(
            f"Evidence '{item.evidence_id}' belongs to a different session and was ignored."
            for item in evidence if item.session_id != plan.session_id
        )
        candidates: list[RootCauseCandidate] = []
        for rule in RULES:
            if rule.category not in categories:
                continue
            matching = [item for item in usable if item.evidence_type == rule.evidence_type]
            supporters = [item for item in matching if self._safe_test(rule.supports, item.data)]
            contradictors = [item for item in matching if self._safe_test(rule.contradicts, item.data)]
            if not supporters:
                continue
            support_ids = [item.evidence_id for item in supporters]
            contradict_ids = [item.evidence_id for item in contradictors]
            explanation = rule.explanation
            process_context = self._process_context(rule, usable)
            if process_context:
                explanation = f"{explanation} {process_context}"
            score = min(0.92, 0.68 + 0.08 * (len(support_ids) - 1))
            if contradict_ids:
                score = max(0.25, score - 0.25)
            remediation = self._remediation(rule, support_ids)
            candidates.append(
                RootCauseCandidate(
                    cause_id=rule.cause_id,
                    title=rule.title,
                    explanation=explanation,
                    supporting_evidence_ids=support_ids,
                    contradicting_evidence_ids=contradict_ids,
                    confidence_score=score,
                    confidence_rationale=(
                        f"Heuristic evidence-strength score {score:.2f}, based on "
                        f"{len(support_ids)} supporting and {len(contradict_ids)} contradicting "
                        "record(s); this is not a calibrated probability."
                    ),
                    missing_evidence=self._missing_for(rule, plan, usable),
                    suggested_next_step=rule.next_step,
                    remediation_candidate=remediation,
                )
            )
        candidates.sort(key=lambda item: (-item.confidence_score, item.cause_id))
        planned_types = {request.evidence_type for request in plan.evidence_requests}
        usable_types = {item.evidence_type for item in usable}
        missing = [
            f"Evidence '{request.evidence_id}' is not available."
            for request in plan.evidence_requests
            if request.required and request.evidence_type not in usable_types
        ]
        if stale:
            missing.extend(f"Fresh {item.evidence_type.value} evidence is needed." for item in stale)
        missing = list(dict.fromkeys(missing))
        if not usable and not missing and planned_types:
            missing = ["No usable evidence was returned for this diagnostic plan."]
        return candidates, warnings, missing

    @staticmethod
    def _safe_test(predicate: Predicate, data: dict[str, Any]) -> bool:
        try:
            return predicate(data)
        except (TypeError, ValueError, AttributeError):
            return False

    @staticmethod
    def _process_context(rule: CauseRule, usable: list[EvidenceRecord]) -> str | None:
        if rule.cause_id not in {
            "performance.cpu_saturation",
            "performance.memory_pressure",
        }:
            return None
        process_records = [
            item for item in usable if item.evidence_type == EvidenceType.PROCESS_SUMMARY
        ]
        processes = [
            process
            for record in process_records
            for process in record.data.get("processes", [])
            if isinstance(process, dict) and isinstance(process.get("name"), str)
        ]
        if not processes:
            return None
        if rule.cause_id == "performance.cpu_saturation":
            key = "cpu_percent"
            label = "highest sampled CPU consumer"
        else:
            key = "memory_bytes"
            label = "largest sampled memory consumer"
        measured = [
            process for process in processes
            if isinstance(process.get(key), (int, float))
            and not isinstance(process.get(key), bool)
        ]
        if not measured:
            return None
        top_process = max(measured, key=lambda process: process[key])
        value = top_process[key]
        formatted_value = f"{value:.1f}%" if key == "cpu_percent" else f"{int(value)} bytes"
        return (
            f"The {label} was '{top_process['name'][:128]}' at {formatted_value}; "
            "this short sample is contextual evidence, not proof of causation."
        )

    @staticmethod
    def _missing_for(
        rule: CauseRule,
        plan: DiagnosticPlan,
        usable: list[EvidenceRecord],
    ) -> list[str]:
        used = {item.evidence_type for item in usable}
        return [
            f"{request.evidence_type.value} is needed for additional context."
            for request in plan.evidence_requests
            if request.evidence_type != rule.evidence_type
            and request.evidence_type not in used
            and request.evidence_type in {
                EvidenceType.PROCESS_SUMMARY,
                EvidenceType.GATEWAY_REACHABILITY,
                EvidenceType.NETWORK_CONNECTIVITY,
                EvidenceType.RUNTIME_VERSIONS,
                EvidenceType.RELIABILITY_SUMMARY,
                EvidenceType.DRIVER_DETAILS,
            }
        ]

    @staticmethod
    def _remediation(rule: CauseRule, evidence_ids: list[str]) -> RemediationCandidate | None:
        if not rule.action_type:
            return None
        title, effect, risk = _ACTION_DETAILS[rule.action_type]
        return RemediationCandidate(
            action_candidate_id=f"candidate.{rule.action_type}",
            related_cause_id=rule.cause_id,
            action_type=rule.action_type,
            purpose=title,
            expected_effect=effect,
            risk_hint=risk,
            supporting_evidence_ids=evidence_ids,
            preconditions=["Reconfirm the finding with current evidence.", "Member 3 policy engine must independently authorize any action."],
            verification_criteria=["Collect fresh evidence and confirm the reported symptom improves."],
        )
