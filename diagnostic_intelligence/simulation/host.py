"""A mutable, deterministic model of a Windows machine.

The simulated collector returns evidence in exactly the same shape as WindowsEvidenceCollector,
and the simulated backend changes the host state the way the real action would. This lets the
pipelines be tested end-to-end: a fix that works produces different fresh evidence than a fix
that does not, so verification is genuinely exercised.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel

from diagnostic_intelligence.models.diagnostic_plan import DiagnosticPlan
from diagnostic_intelligence.models.evidence import EvidenceRecord, EvidenceStatus, EvidenceType

GB = 1024 ** 3


@dataclass
class SimulatedHost:
    scenario: str
    description: str
    sample_complaint: str
    cpu_percent: float = 18.0
    memory_total: int = 16 * GB
    memory_used_percent: float = 48.0
    processes: list[dict[str, Any]] = field(default_factory=lambda: [
        {"name": "msedge.exe", "cpu_percent": 4.0, "memory_bytes": int(1.1 * GB)},
        {"name": "Teams.exe", "cpu_percent": 2.0, "memory_bytes": int(0.7 * GB)},
        {"name": "explorer.exe", "cpu_percent": 0.5, "memory_bytes": int(0.2 * GB)},
    ])
    volume_total: int = 256 * GB
    volume_free: int = 120 * GB
    temp_reclaimable: int = 2 * GB
    disk_latency_ms: float = 4.0
    adapter_name: str = "Wi-Fi"
    adapter_up: bool = True
    address: str = "192.168.1.23"
    gateway: str = "192.168.1.1"
    gateway_ok: bool = True
    stale_dns_cache: bool = False
    upstream_down: bool = False
    dns_hostname_configured: bool = True
    services: dict[str, dict[str, str]] = field(default_factory=lambda: {
        "Spooler": {"state": "Running", "start_mode": "Auto"},
        "WSearch": {"state": "Running", "start_mode": "Auto"},
        "BITS": {"state": "Stopped", "start_mode": "Manual"},
        "wuauserv": {"state": "Running", "start_mode": "Manual"},
        "Audiosrv": {"state": "Running", "start_mode": "Auto"},
    })
    system_error_count: int = 0
    elevated: bool = True
    failing_actions: set[str] = field(default_factory=set)
    actions_applied: list[str] = field(default_factory=list)

    # --- derived network state -------------------------------------------------
    @property
    def has_valid_address(self) -> bool:
        return self.adapter_up and not self.address.startswith("169.254.")

    @property
    def gateway_reachable(self) -> bool:
        return self.has_valid_address and self.gateway_ok

    @property
    def dns_ok(self) -> bool:
        return self.gateway_reachable and not self.stale_dns_cache and not self.upstream_down

    @property
    def endpoint_ok(self) -> bool:
        return self.dns_ok and not self.upstream_down

    # --- evidence producers ----------------------------------------------------
    def evidence_data(self, evidence_type: EvidenceType) -> tuple[dict[str, Any], EvidenceStatus] | None:
        adapters = [
            {"name": self.adapter_name, "status": "up" if self.adapter_up else "down",
             "addresses": [self.address] if self.adapter_up else []},
            {"name": "Loopback Pseudo-Interface 1", "status": "up", "addresses": ["127.0.0.1"]},
        ]
        producers: dict[EvidenceType, Callable[[], tuple[dict[str, Any], EvidenceStatus]]] = {
            EvidenceType.CPU_METRICS: lambda: (
                {"utilization_percent": self.cpu_percent,
                 "samples": [{"timestamp": _now().isoformat(), "utilization_percent": self.cpu_percent}]},
                EvidenceStatus.AVAILABLE),
            EvidenceType.MEMORY_METRICS: lambda: (
                {"total_bytes": self.memory_total,
                 "available_bytes": int(self.memory_total * (100 - self.memory_used_percent) / 100),
                 "used_percent": self.memory_used_percent},
                EvidenceStatus.AVAILABLE),
            EvidenceType.PROCESS_SUMMARY: lambda: (
                {"processes": sorted(self.processes, key=lambda p: (-p["cpu_percent"], -p["memory_bytes"]))[:5],
                 "unavailable_process_count": 0},
                EvidenceStatus.AVAILABLE),
            EvidenceType.STORAGE_CAPACITY: lambda: (
                {"volumes": [{"total_bytes": self.volume_total, "free_bytes": self.volume_free,
                              "free_percent": self.volume_free / self.volume_total * 100,
                              "free_gb": self.volume_free / GB}],
                 "unavailable_volume_count": 0},
                EvidenceStatus.AVAILABLE),
            EvidenceType.DISK_ACTIVITY: lambda: (
                {"observation_window_seconds": 0.5, "read_bytes_per_second": 2_000_000.0,
                 "write_bytes_per_second": 1_000_000.0, "read_ops_per_second": 40.0,
                 "write_ops_per_second": 20.0, "average_latency_ms": self.disk_latency_ms},
                EvidenceStatus.AVAILABLE),
            EvidenceType.STORAGE_ERRORS: lambda: ({"events": [], "recurring_error_count": 0, "truncated": False}, EvidenceStatus.AVAILABLE),
            EvidenceType.SYSTEM_EVENTS: lambda: (
                {"events": [], "recurring_error_count": self.system_error_count, "truncated": False},
                EvidenceStatus.AVAILABLE),
            EvidenceType.RELIABILITY_SUMMARY: lambda: ({"incidents": [], "skipped_record_count": 0, "truncated": False}, EvidenceStatus.AVAILABLE),
            EvidenceType.SERVICE_STATUS: lambda: (
                {"services": [{"name": n, "state": s["state"], "start_mode": s["start_mode"], "exit_code": 0}
                              for n, s in self.services.items()],
                 "queried": list(self.services)},
                EvidenceStatus.AVAILABLE),
            EvidenceType.NETWORK_CONFIGURATION: lambda: (
                {"adapters": adapters, "default_gateway": self.gateway if self.has_valid_address else None},
                EvidenceStatus.AVAILABLE),
            EvidenceType.ADAPTER_STATUS: lambda: ({"adapters": adapters, "unavailable_adapter_count": 0}, EvidenceStatus.AVAILABLE),
            EvidenceType.GATEWAY_REACHABILITY: lambda: (
                {"gateway": self.gateway if self.has_valid_address else None,
                 "reachable": self.gateway_reachable,
                 "latency_ms": 3 if self.gateway_reachable else None,
                 "error_category": None if self.gateway_reachable else ("no_default_gateway" if not self.has_valid_address else "TimedOut")},
                EvidenceStatus.AVAILABLE),
            EvidenceType.DNS_RESOLUTION: lambda: (
                ({"hostname": "www.microsoft.com", "success": self.dns_ok,
                  "resolved_addresses": ["23.45.67.89"] if self.dns_ok else [],
                  "error_category": None if self.dns_ok else "name_resolution_failed"},
                 EvidenceStatus.AVAILABLE)
                if self.dns_hostname_configured else
                ({"success": False, "resolved_addresses": [], "error_category": "no_permitted_hostname_configured"},
                 EvidenceStatus.UNAVAILABLE)),
            EvidenceType.NETWORK_CONNECTIVITY: lambda: (
                {"endpoint_id": "msft-https", "reachable": self.endpoint_ok,
                 "latency_ms": 21.0 if self.endpoint_ok else None,
                 "error_category": None if self.endpoint_ok else ("timeout" if self.dns_ok else "name_resolution_failed")},
                EvidenceStatus.AVAILABLE),
            EvidenceType.DEVICE_STATUS: lambda: ({"devices": [], "problem_device_count": 0, "status": "ok"}, EvidenceStatus.AVAILABLE),
        }
        producer = producers.get(evidence_type)
        return producer() if producer else None

    # --- action effects --------------------------------------------------------
    def apply(self, action_id: str, params: BaseModel) -> tuple[bool, str]:
        if action_id in self.failing_actions:
            return False, "exit code 1: simulated command failure"
        self.actions_applied.append(action_id)
        if action_id == "flush_dns_cache":
            self.stale_dns_cache = False
            return True, "exit code 0: Successfully flushed the DNS Resolver Cache."
        if action_id == "renew_dhcp_lease":
            if self.adapter_up:
                self.address = "192.168.1.23"
                self.gateway_ok = True
            return True, "exit code 0"
        if action_id == "restart_network_adapter":
            self.adapter_up = True
            return True, "exit code 0"
        if action_id == "restart_service":
            name = params.service_name
            if name in self.services:
                self.services[name]["state"] = "Running"
            if name == "WSearch":
                for process in self.processes:
                    if process["name"].casefold() == "searchindexer.exe":
                        process["cpu_percent"] = 1.5
                self.cpu_percent = 21.0
            return True, "exit code 0"
        if action_id == "clear_temp_files":
            freed = self.temp_reclaimable
            self.volume_free += freed
            self.temp_reclaimable = 0
            return True, f"deleted files, freed {freed / 1024 ** 2:.1f} MB"
        if action_id == "terminate_process":
            target = params.process_name.casefold()
            victim = next((p for p in self.processes if p["name"].casefold() == target), None)
            if victim is None:
                return False, "No running process with that name was found."
            self.processes.remove(victim)
            share = victim["memory_bytes"] / self.memory_total * 100
            self.memory_used_percent = max(20.0, self.memory_used_percent - share)
            self.cpu_percent = max(5.0, self.cpu_percent - victim["cpu_percent"] / 2)
            return True, "terminated 1 instance(s); 0 still running"
        return False, f"No simulated implementation for '{action_id}'."


def _now() -> datetime:
    return datetime.now(timezone.utc)


class SimulatedEvidenceCollector:
    source = "simulated_windows_host"

    def __init__(self, host: SimulatedHost) -> None:
        self.host = host
        self.collected_types: list[EvidenceType] = []

    def collect_types(self, session_id: str, requests: list) -> list[EvidenceRecord]:
        records = []
        for request in requests:
            self.collected_types.append(request.evidence_type)
            produced = self.host.evidence_data(request.evidence_type)
            if produced is None:
                records.append(EvidenceRecord(
                    session_id=session_id, evidence_id=request.evidence_id, evidence_type=request.evidence_type,
                    collected_at=_now(), status=EvidenceStatus.UNAVAILABLE,
                    data={"reason": "No collector is registered for this evidence type."}, source=self.source))
                continue
            data, status = produced
            data = copy.deepcopy(data)  # evidence must be a snapshot, never a live reference to host state
            records.append(EvidenceRecord(
                session_id=session_id, evidence_id=request.evidence_id, evidence_type=request.evidence_type,
                collected_at=_now(), status=status, data=data, source=self.source))
        return records

    def collect_for_plan(self, plan: DiagnosticPlan) -> list[EvidenceRecord]:
        return self.collect_types(plan.session_id or "simulated", plan.evidence_requests)


class SimulatedActionBackend:
    name = "simulated"

    def __init__(self, host: SimulatedHost) -> None:
        self.host = host

    def is_elevated(self) -> bool:
        return self.host.elevated

    def run(self, action_id: str, params: BaseModel) -> tuple[bool, str]:
        return self.host.apply(action_id, params)


def _healthy(**kw) -> SimulatedHost:
    return SimulatedHost(**kw)


def _dns_cache_stale() -> SimulatedHost:
    return SimulatedHost("dns_cache_stale", "Websites fail to resolve; a stale DNS cache is the cause (flush fixes it).",
                         "Websites won't load but my Wi-Fi says connected. DNS errors in the browser.",
                         stale_dns_cache=True)


def _dhcp_lease_lost() -> SimulatedHost:
    return SimulatedHost("dhcp_lease_lost", "Adapter has a 169.254.x.x address; flushing DNS will not help, renewing the lease will.",
                         "No internet at all since this morning, Wi-Fi shows limited connectivity.",
                         address="169.254.77.12", gateway_ok=False)


def _isp_outage() -> SimulatedHost:
    return SimulatedHost("isp_outage", "Local network is fine but upstream is down; no local action can fix it.",
                         "Internet is not working, pages time out.", upstream_down=True)


def _adapter_down() -> SimulatedHost:
    return SimulatedHost("adapter_down", "The Wi-Fi adapter is down; restarting it fixes the problem (needs admin).",
                         "My network adapter stopped working and I have no connection.", adapter_up=False)


def _search_indexer_runaway() -> SimulatedHost:
    host = SimulatedHost("search_indexer_runaway", "Windows Search indexer is stuck at high CPU; restarting WSearch fixes it.",
                         "My laptop is very slow and the fan is loud, CPU usage seems high.", cpu_percent=96.0)
    host.processes.append({"name": "SearchIndexer.exe", "cpu_percent": 82.0, "memory_bytes": int(0.4 * GB)})
    return host


def _memory_hog() -> SimulatedHost:
    host = SimulatedHost("memory_hog", "One application uses most of the RAM; closing it is a high-risk action (unsaved work).",
                         "Everything is slow and freezes, memory usage is very high.", memory_used_percent=94.0, cpu_percent=55.0)
    host.processes.append({"name": "chrome.exe", "cpu_percent": 30.0, "memory_bytes": int(9.5 * GB)})
    return host


def _low_disk_temp() -> SimulatedHost:
    return SimulatedHost("low_disk_temp", "System drive nearly full, mostly reclaimable temporary files.",
                         "My C drive is almost full and I get low disk space warnings.",
                         volume_free=int(7 * GB), temp_reclaimable=int(40 * GB))


def _low_disk_no_temp() -> SimulatedHost:
    return SimulatedHost("low_disk_no_temp", "System drive nearly full, but temp cleanup frees very little.",
                         "My C drive is almost full and I get low disk space warnings.",
                         volume_free=int(7 * GB), temp_reclaimable=int(0.3 * GB))


def _spooler_stopped() -> SimulatedHost:
    host = SimulatedHost("spooler_stopped", "The Print Spooler service (automatic start) has stopped; restarting it fixes printing.",
                         "Printing stopped working, documents never reach the printer service.", system_error_count=4)
    host.services["Spooler"]["state"] = "Stopped"
    return host


def _healthy_host() -> SimulatedHost:
    return SimulatedHost("healthy", "Nothing is wrong; the agent should report the cause as undetermined.",
                         "My laptop feels slow sometimes.")


SCENARIOS: dict[str, Callable[[], SimulatedHost]] = {
    "dns_cache_stale": _dns_cache_stale,
    "dhcp_lease_lost": _dhcp_lease_lost,
    "isp_outage": _isp_outage,
    "adapter_down": _adapter_down,
    "search_indexer_runaway": _search_indexer_runaway,
    "memory_hog": _memory_hog,
    "low_disk_temp": _low_disk_temp,
    "low_disk_no_temp": _low_disk_no_temp,
    "spooler_stopped": _spooler_stopped,
    "healthy": _healthy_host,
}


def build_scenario(name: str) -> SimulatedHost:
    try:
        return SCENARIOS[name]()
    except KeyError as error:
        raise ValueError(f"Unknown scenario '{name}'. Known: {sorted(SCENARIOS)}") from error
