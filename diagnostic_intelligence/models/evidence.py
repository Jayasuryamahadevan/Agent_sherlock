"""Evidence types exchanged with the Windows Evidence Collection Engine."""

import json
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from diagnostic_intelligence.models.classification import Category


class EvidenceStatus(StrEnum):
    AVAILABLE = "available"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


class EvidenceType(StrEnum):
    STORAGE_CAPACITY = "storage.capacity"
    DISK_ACTIVITY = "storage.disk_activity"
    STORAGE_ERRORS = "storage.errors"
    NETWORK_CONFIGURATION = "network.configuration"
    DNS_RESOLUTION = "network.dns_resolution"
    GATEWAY_REACHABILITY = "network.gateway_reachability"
    NETWORK_CONNECTIVITY = "network.connectivity"
    ADAPTER_STATUS = "network.adapter_status"
    CPU_METRICS = "performance.cpu"
    MEMORY_METRICS = "performance.memory"
    PROCESS_SUMMARY = "performance.process_summary"
    SYSTEM_EVENTS = "windows.system_events"
    RELIABILITY_SUMMARY = "windows.reliability"
    SERVICE_STATUS = "windows.service_status"
    APPLICATION_LOGS = "application.logs"
    RUNTIME_VERSIONS = "application.runtime_versions"
    APPLICATION_STARTUP = "application.startup"
    DEVICE_STATUS = "driver.device_status"
    DRIVER_DETAILS = "driver.details"
    DRIVER_EVENTS = "driver.events"
    UPDATE_HISTORY = "system.update_history"


class EvidenceRecord(BaseModel):
    """One collector response; data must be factual collector output."""

    model_config = ConfigDict(extra="forbid")

    session_id: str = Field(min_length=1, max_length=128)
    evidence_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{1,127}$")
    evidence_type: EvidenceType
    collected_at: datetime
    status: EvidenceStatus
    data: dict[str, Any] = Field(default_factory=dict)
    source: str | None = Field(default=None, max_length=256)
    error: str | None = Field(default=None, max_length=1000)

    @field_validator("collected_at")
    @classmethod
    def timestamp_must_have_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("collected_at must include a timezone")
        return value.astimezone(timezone.utc)

    @field_validator("data")
    @classmethod
    def data_must_be_bounded_json(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(value) > 200:
            raise ValueError("evidence data may contain at most 200 top-level fields")
        try:
            serialized = json.dumps(value, ensure_ascii=True, allow_nan=False)
        except (TypeError, ValueError) as error:
            raise ValueError("evidence data must contain JSON-compatible finite values") from error
        if len(serialized.encode("utf-8")) > 100_000:
            raise ValueError("evidence data must not exceed 100 KB")
        return value

    @model_validator(mode="after")
    def errors_require_error_status(self) -> "EvidenceRecord":
        if self.error and self.status != EvidenceStatus.ERROR:
            raise ValueError("error details require status='error'")
        numeric_fields = {
            EvidenceType.STORAGE_CAPACITY: ("free_percent", "free_gb"),
            EvidenceType.DISK_ACTIVITY: ("utilization_percent", "average_latency_ms"),
            EvidenceType.CPU_METRICS: ("utilization_percent",),
            EvidenceType.MEMORY_METRICS: ("available_percent", "used_percent"),
            EvidenceType.SYSTEM_EVENTS: ("recurring_error_count",),
            EvidenceType.DRIVER_EVENTS: ("recurring_error_count",),
        }
        for field_name in numeric_fields.get(self.evidence_type, ()):
            value = self.data.get(field_name)
            if value is not None and (
                not isinstance(value, (int, float)) or isinstance(value, bool)
            ):
                raise ValueError(f"{field_name} must be numeric")
        if self.evidence_type == EvidenceType.STORAGE_CAPACITY:
            volumes = self.data.get("volumes")
            if volumes is not None and (
                not isinstance(volumes, list)
                or any(not isinstance(volume, dict) for volume in volumes)
            ):
                raise ValueError("volumes must be a list of objects")
            if isinstance(volumes, list):
                for volume in volumes:
                    for field_name in ("total_bytes", "free_bytes", "free_percent", "free_gb"):
                        value = volume.get(field_name)
                        if value is not None and (
                            not isinstance(value, (int, float)) or isinstance(value, bool)
                        ):
                            raise ValueError(f"volumes[].{field_name} must be numeric")
        boolean_fields = {
            EvidenceType.DNS_RESOLUTION: ("success",),
            EvidenceType.GATEWAY_REACHABILITY: ("reachable",),
            EvidenceType.NETWORK_CONNECTIVITY: ("reachable",),
            EvidenceType.APPLICATION_STARTUP: ("started",),
        }
        for field_name in boolean_fields.get(self.evidence_type, ()):
            value = self.data.get(field_name)
            if value is not None and not isinstance(value, bool):
                raise ValueError(f"{field_name} must be boolean")
        if self.evidence_type == EvidenceType.APPLICATION_LOGS:
            error_category = self.data.get("error_category")
            if error_category is not None and not isinstance(error_category, str):
                raise ValueError("error_category must be a string")
        if self.evidence_type == EvidenceType.ADAPTER_STATUS:
            adapters = self.data.get("adapters")
            if adapters is not None and (
                not isinstance(adapters, list)
                or any(not isinstance(item, dict) for item in adapters)
            ):
                raise ValueError("adapters must be a list of objects")
        if self.evidence_type == EvidenceType.SERVICE_STATUS:
            services = self.data.get("services")
            if services is not None and (
                not isinstance(services, list)
                or any(not isinstance(item, dict) for item in services)
            ):
                raise ValueError("services must be a list of objects")
        if self.evidence_type == EvidenceType.DEVICE_STATUS:
            devices = self.data.get("devices")
            if devices is not None and (
                not isinstance(devices, list)
                or any(not isinstance(item, dict) for item in devices)
            ):
                raise ValueError("devices must be a list of objects")
        return self


EVIDENCE_BY_CATEGORY: dict[Category, tuple[EvidenceType, ...]] = {
    Category.STORAGE: (
        EvidenceType.STORAGE_CAPACITY,
        EvidenceType.DISK_ACTIVITY,
        EvidenceType.STORAGE_ERRORS,
    ),
    Category.NETWORK: (
        EvidenceType.NETWORK_CONFIGURATION,
        EvidenceType.DNS_RESOLUTION,
        EvidenceType.GATEWAY_REACHABILITY,
        EvidenceType.NETWORK_CONNECTIVITY,
        EvidenceType.ADAPTER_STATUS,
    ),
    Category.SYSTEM_PERFORMANCE: (
        EvidenceType.CPU_METRICS,
        EvidenceType.MEMORY_METRICS,
        EvidenceType.DISK_ACTIVITY,
        EvidenceType.PROCESS_SUMMARY,
    ),
    Category.WINDOWS_HEALTH: (
        EvidenceType.SYSTEM_EVENTS,
        EvidenceType.RELIABILITY_SUMMARY,
        EvidenceType.SERVICE_STATUS,
    ),
    Category.APPLICATION_COMPATIBILITY: (
        EvidenceType.APPLICATION_STARTUP,
        EvidenceType.APPLICATION_LOGS,
        EvidenceType.RUNTIME_VERSIONS,
    ),
    Category.DRIVER: (
        EvidenceType.DEVICE_STATUS,
        EvidenceType.DRIVER_DETAILS,
        EvidenceType.DRIVER_EVENTS,
        EvidenceType.UPDATE_HISTORY,
    ),
}


def evidence_is_stale(record: EvidenceRecord, now: datetime, max_age_hours: int = 24) -> bool:
    """Return whether an evidence timestamp is older than its freshness window."""
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must include a timezone")
    age = now.astimezone(timezone.utc) - record.collected_at
    return age.total_seconds() > max_age_hours * 3600
