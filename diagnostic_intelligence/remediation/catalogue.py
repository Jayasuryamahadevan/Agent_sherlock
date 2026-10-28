"""The complete set of operations the agent can ever perform.

Every operation is a typed entry here. A language model can only *name* an entry and supply
parameters; parameters are validated by a Pydantic model, preconditions are checked against
collected evidence, and success is judged by a deterministic verification function using
freshly collected evidence. Anything not in this catalogue (for example deleting a driver)
cannot be executed by any pipeline.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from diagnostic_intelligence.engines.root_cause_correlation import _has_no_valid_address
from diagnostic_intelligence.evidence_view import EvidenceView
from diagnostic_intelligence.models.classification import Category
from diagnostic_intelligence.models.evidence import EvidenceType


class ActionKind(StrEnum):
    DIAGNOSTIC = "diagnostic"          # read-only: collects evidence, changes nothing
    SYSTEM_CHANGE = "system_change"    # changes system state


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2}[self.value]


class VerificationVerdict(StrEnum):
    RESOLVED = "resolved"
    IMPROVED = "improved"
    UNCHANGED = "unchanged"
    WORSENED = "worsened"
    INCONCLUSIVE = "inconclusive"


class VerificationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: VerificationVerdict
    details: list[str]


# ---------------------------------------------------------------------------
# Parameter schemas (strict; unknown fields rejected)
# ---------------------------------------------------------------------------

MANAGED_SERVICES = ("Spooler", "WSearch", "BITS", "wuauserv", "Audiosrv")
ServiceName = Literal["Spooler", "WSearch", "BITS", "wuauserv", "Audiosrv"]

# Process names that must never be terminated by the agent, whatever the evidence says.
PROTECTED_PROCESSES = frozenset(
    name.casefold()
    for name in (
        "System", "Idle", "Registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
        "services.exe", "lsass.exe", "lsaiso.exe", "svchost.exe", "dwm.exe", "explorer.exe",
        "fontdrvhost.exe", "MsMpEng.exe", "NisSrv.exe", "SecurityHealthService.exe",
        "spoolsv.exe", "SearchIndexer.exe", "conhost.exe", "sihost.exe", "ctfmon.exe",
        "python.exe", "pythonw.exe", "py.exe", "powershell.exe", "pwsh.exe", "uvicorn.exe",
        "Memory Compression", "audiodg.exe", "WmiPrvSE.exe",
    )
)

# Processes that belong to a managed service (restart the service instead of killing it).
SERVICE_PROCESSES = {"wsearch": "searchindexer.exe", "spooler": "spoolsv.exe"}


class NoParams(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CollectEvidenceParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_types: list[EvidenceType] = Field(min_length=1, max_length=8)


class AdapterParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    adapter_name: str = Field(pattern=r"^[A-Za-z0-9 ._()#-]{1,64}$")


class ServiceParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    service_name: ServiceName


class TempCleanupParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_age_days: int = Field(default=7, ge=1, le=90)


class ProcessParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    process_name: str = Field(pattern=r"(?i)^[A-Za-z0-9 ._()+-]{1,64}\.exe$")


# ---------------------------------------------------------------------------
# Evidence-derived signals
# ---------------------------------------------------------------------------

LOW_SPACE_PERCENT = 15.0
LOW_SPACE_GB = 10.0


def _system_volume(view: EvidenceView) -> dict[str, Any] | None:
    data = view.latest_data(EvidenceType.STORAGE_CAPACITY)
    if not data:
        return None
    volumes = data.get("volumes")
    if isinstance(volumes, list) and volumes and isinstance(volumes[0], dict):
        return volumes[0]
    return None


def _is_low_space(volume: dict[str, Any]) -> bool:
    free_percent = volume.get("free_percent")
    free_gb = volume.get("free_gb")
    return (isinstance(free_percent, (int, float)) and free_percent < LOW_SPACE_PERCENT) or (
        isinstance(free_gb, (int, float)) and free_gb < LOW_SPACE_GB
    )


def network_signals(view: EvidenceView) -> dict[str, bool | None]:
    """True = healthy, False = failing, None = not measured."""
    config = view.latest_data(EvidenceType.NETWORK_CONFIGURATION)
    gateway = view.latest_data(EvidenceType.GATEWAY_REACHABILITY)
    dns = view.latest_data(EvidenceType.DNS_RESOLUTION)
    connectivity = view.latest_data(EvidenceType.NETWORK_CONNECTIVITY)
    adapters = view.latest_data(EvidenceType.ADAPTER_STATUS)
    adapter_ok = None
    if adapters and isinstance(adapters.get("adapters"), list):
        statuses = [a.get("status") for a in adapters["adapters"] if isinstance(a, dict)
                    and "loopback" not in str(a.get("name", "")).casefold()]
        adapter_ok = any(status == "up" for status in statuses) if statuses else None
    return {
        "adapter_up": adapter_ok,
        "valid_address": (not _has_no_valid_address(config)) if config and isinstance(config.get("adapters"), list) else None,
        "gateway_reachable": gateway.get("reachable") if gateway and isinstance(gateway.get("reachable"), bool) else None,
        "dns_resolves": dns.get("success") if dns and isinstance(dns.get("success"), bool) else None,
        "endpoint_reachable": connectivity.get("reachable") if connectivity and isinstance(connectivity.get("reachable"), bool) else None,
    }


def _process(view: EvidenceView, name: str) -> dict[str, Any] | None:
    data = view.latest_data(EvidenceType.PROCESS_SUMMARY)
    if not data or not isinstance(data.get("processes"), list):
        return None
    for process in data["processes"]:
        if isinstance(process, dict) and str(process.get("name", "")).casefold() == name.casefold():
            return process
    return None


def _total_memory(view: EvidenceView) -> int | None:
    data = view.latest_data(EvidenceType.MEMORY_METRICS)
    total = data.get("total_bytes") if data else None
    return total if isinstance(total, int) and total > 0 else None


def _number(data: dict[str, Any] | None, key: str) -> float | None:
    value = data.get(key) if data else None
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


# ---------------------------------------------------------------------------
# Preconditions: return None when satisfied, otherwise a human-readable reason
# ---------------------------------------------------------------------------

def _pre_none(params: BaseModel, view: EvidenceView) -> str | None:
    return None


def _pre_flush_dns(params: BaseModel, view: EvidenceView) -> str | None:
    signals = network_signals(view)
    if signals["dns_resolves"] is None:
        return "No DNS resolution test result is available, so a DNS cache flush is not justified by evidence."
    if signals["dns_resolves"]:
        return "The latest DNS test succeeded; flushing the DNS cache is not justified."
    return None


def _pre_renew_dhcp(params: BaseModel, view: EvidenceView) -> str | None:
    signals = network_signals(view)
    if signals["valid_address"] is False or signals["gateway_reachable"] is False:
        return None
    return "Evidence does not show a missing IP address or an unreachable gateway, so renewing the DHCP lease is not justified."


def _pre_restart_adapter(params: AdapterParams, view: EvidenceView) -> str | None:
    names = set()
    for evidence_type in (EvidenceType.ADAPTER_STATUS, EvidenceType.NETWORK_CONFIGURATION):
        data = view.latest_data(evidence_type)
        if data and isinstance(data.get("adapters"), list):
            names |= {str(a.get("name")) for a in data["adapters"] if isinstance(a, dict)}
    match = next((name for name in names if name.casefold() == params.adapter_name.casefold()), None)
    if match is None:
        return f"Adapter '{params.adapter_name}' was not observed in collected evidence."
    if "loopback" in match.casefold():
        return "Loopback interfaces cannot be restarted."
    signals = network_signals(view)
    if signals["adapter_up"] is False or signals["valid_address"] is False or signals["gateway_reachable"] is False:
        return None
    return "Evidence does not show an adapter, addressing or gateway fault that justifies restarting an adapter."


def _pre_restart_service(params: ServiceParams, view: EvidenceView) -> str | None:
    data = view.latest_data(EvidenceType.SERVICE_STATUS)
    if not data or not isinstance(data.get("services"), list):
        return "Service status (WMI/CIM) has not been collected; restart is not justified without it."
    service = next((s for s in data["services"] if isinstance(s, dict)
                    and str(s.get("name", "")).casefold() == params.service_name.casefold()), None)
    if service is None:
        return f"Service '{params.service_name}' was not found in collected service status."
    if str(service.get("state", "")).casefold() != "running":
        return None
    process_name = SERVICE_PROCESSES.get(params.service_name.casefold())
    process = _process(view, process_name) if process_name else None
    cpu = _number(process, "cpu_percent")
    if cpu is not None and cpu >= 50:
        return None
    return f"Service '{params.service_name}' is running and no evidence shows it misbehaving; restart is not justified."


def _pre_clear_temp(params: TempCleanupParams, view: EvidenceView) -> str | None:
    volume = _system_volume(view)
    if volume is None:
        return "Storage capacity has not been collected; cleanup is not justified without it."
    if not _is_low_space(volume):
        return "The system volume is not low on free space; temporary-file cleanup is not justified."
    return None


def _pre_terminate_process(params: ProcessParams, view: EvidenceView) -> str | None:
    if params.process_name.casefold() in PROTECTED_PROCESSES:
        return f"'{params.process_name}' is a protected system or agent process and can never be terminated."
    process = _process(view, params.process_name)
    if process is None:
        return f"'{params.process_name}' was not observed in the collected process summary."
    cpu = _number(process, "cpu_percent") or 0.0
    memory = _number(process, "memory_bytes") or 0.0
    total = _total_memory(view)
    heavy_memory = memory >= (0.2 * total if total else 2 * 1024 ** 3)
    if cpu >= 50 or heavy_memory:
        return None
    return f"'{params.process_name}' is not consuming enough CPU or memory to justify terminating it."


# ---------------------------------------------------------------------------
# Verification: compare evidence collected before and after the action
# ---------------------------------------------------------------------------

def _verify_network(params: BaseModel, before: EvidenceView, after: EvidenceView) -> VerificationResult:
    old, new = network_signals(before), network_signals(after)
    details = [f"{name}: {old[name]} -> {new[name]}" for name in new if old[name] is not None or new[name] is not None]
    failing_before = [k for k, v in old.items() if v is False]
    failing_after = [k for k, v in new.items() if v is False]
    if not any(v is not None for v in new.values()):
        return VerificationResult(verdict=VerificationVerdict.INCONCLUSIVE, details=["No network evidence after the action."])
    # Only signals measured both before and after can show a regression.
    regressed = [k for k in new if old[k] is True and new[k] is False]
    fixed = [k for k in failing_before if new.get(k) is True]
    if regressed:
        return VerificationResult(verdict=VerificationVerdict.WORSENED, details=details + [f"regressed: {regressed}"])
    if not failing_after and (fixed or not failing_before):
        return VerificationResult(verdict=VerificationVerdict.RESOLVED, details=details)
    if fixed:
        return VerificationResult(verdict=VerificationVerdict.IMPROVED, details=details + [f"still failing: {failing_after}"])
    return VerificationResult(verdict=VerificationVerdict.UNCHANGED, details=details + [f"still failing: {failing_after}"])


def _verify_adapter(params: AdapterParams, before: EvidenceView, after: EvidenceView) -> VerificationResult:
    return _verify_network(params, before, after)


def _verify_service(params: ServiceParams, before: EvidenceView, after: EvidenceView) -> VerificationResult:
    def state(view: EvidenceView) -> str | None:
        data = view.latest_data(EvidenceType.SERVICE_STATUS) or {}
        for service in data.get("services", []) or []:
            if isinstance(service, dict) and str(service.get("name", "")).casefold() == params.service_name.casefold():
                return str(service.get("state"))
        return None

    old_state, new_state = state(before), state(after)
    details = [f"{params.service_name} state: {old_state} -> {new_state}"]
    if new_state is None:
        return VerificationResult(verdict=VerificationVerdict.INCONCLUSIVE, details=details + ["Service status was not re-collected."])
    if new_state.casefold() != "running":
        return VerificationResult(verdict=VerificationVerdict.UNCHANGED if old_state == new_state else VerificationVerdict.WORSENED, details=details)
    process_name = SERVICE_PROCESSES.get(params.service_name.casefold())
    old_cpu = _number(_process(before, process_name), "cpu_percent") if process_name else None
    new_cpu = _number(_process(after, process_name), "cpu_percent") if process_name else None
    system_cpu = _number(after.latest_data(EvidenceType.CPU_METRICS), "utilization_percent")
    if old_cpu is not None and old_cpu >= 50:
        details.append(f"{process_name} CPU: {old_cpu} -> {new_cpu}; system CPU now {system_cpu}")
        if (new_cpu is None or new_cpu < 25) and (system_cpu is None or system_cpu < 85):
            return VerificationResult(verdict=VerificationVerdict.RESOLVED, details=details)
        if new_cpu is not None and new_cpu < old_cpu:
            return VerificationResult(verdict=VerificationVerdict.IMPROVED, details=details)
        return VerificationResult(verdict=VerificationVerdict.UNCHANGED, details=details)
    if old_state is not None and old_state.casefold() != "running":
        return VerificationResult(verdict=VerificationVerdict.RESOLVED, details=details)
    return VerificationResult(verdict=VerificationVerdict.INCONCLUSIVE, details=details)


def _verify_clear_temp(params: TempCleanupParams, before: EvidenceView, after: EvidenceView) -> VerificationResult:
    old, new = _system_volume(before), _system_volume(after)
    if not old or not new:
        return VerificationResult(verdict=VerificationVerdict.INCONCLUSIVE, details=["Storage capacity was not re-collected."])
    freed = (new.get("free_bytes") or 0) - (old.get("free_bytes") or 0)
    details = [
        f"free space: {old.get('free_percent', 0):.1f}% -> {new.get('free_percent', 0):.1f}%",
        f"freed approximately {freed / 1024 ** 3:.2f} GB",
    ]
    if not _is_low_space(new):
        return VerificationResult(verdict=VerificationVerdict.RESOLVED, details=details)
    if freed >= 1024 ** 3:
        return VerificationResult(verdict=VerificationVerdict.IMPROVED, details=details + ["Volume is still below the low-space threshold."])
    if freed < 0:
        return VerificationResult(verdict=VerificationVerdict.WORSENED, details=details)
    return VerificationResult(verdict=VerificationVerdict.UNCHANGED, details=details)


def _verify_terminate(params: ProcessParams, before: EvidenceView, after: EvidenceView) -> VerificationResult:
    process_after = _process(after, params.process_name)
    cpu_before = _number(before.latest_data(EvidenceType.CPU_METRICS), "utilization_percent")
    cpu_after = _number(after.latest_data(EvidenceType.CPU_METRICS), "utilization_percent")
    mem_before = _number(before.latest_data(EvidenceType.MEMORY_METRICS), "used_percent")
    mem_after = _number(after.latest_data(EvidenceType.MEMORY_METRICS), "used_percent")
    details = [
        f"{params.process_name} still present: {process_after is not None}",
        f"system CPU: {cpu_before} -> {cpu_after}",
        f"memory used: {mem_before} -> {mem_after}",
    ]
    system_ok = (cpu_after is None or cpu_after < 85) and (mem_after is None or mem_after < 90)
    if process_after is None and system_ok and (cpu_after is not None or mem_after is not None):
        return VerificationResult(verdict=VerificationVerdict.RESOLVED, details=details)
    improved = (cpu_before and cpu_after is not None and cpu_after < cpu_before - 10) or (
        mem_before and mem_after is not None and mem_after < mem_before - 5
    )
    if improved:
        return VerificationResult(verdict=VerificationVerdict.IMPROVED, details=details)
    if cpu_after is None and mem_after is None:
        return VerificationResult(verdict=VerificationVerdict.INCONCLUSIVE, details=details)
    return VerificationResult(verdict=VerificationVerdict.UNCHANGED, details=details)


def _verify_none(params: BaseModel, before: EvidenceView, after: EvidenceView) -> VerificationResult:
    return VerificationResult(verdict=VerificationVerdict.INCONCLUSIVE, details=["Read-only operation; nothing to verify."])


_NETWORK_VERIFY = (
    EvidenceType.NETWORK_CONFIGURATION,
    EvidenceType.ADAPTER_STATUS,
    EvidenceType.GATEWAY_REACHABILITY,
    EvidenceType.DNS_RESOLUTION,
    EvidenceType.NETWORK_CONNECTIVITY,
)


@dataclass(frozen=True)
class ActionSpec:
    action_id: str
    title: str
    description: str
    kind: ActionKind
    risk: RiskLevel
    requires_admin: bool
    reversible: bool
    consequences: str
    params_model: type[BaseModel]
    categories: tuple[Category, ...]
    addresses_causes: tuple[str, ...]
    precondition: Callable[[Any, EvidenceView], str | None]
    verification_evidence: tuple[EvidenceType, ...]
    verify: Callable[[Any, EvidenceView, EvidenceView], VerificationResult]
    auto_remediation_eligible: bool = True
    extra: dict[str, Any] = field(default_factory=dict)

    def params_schema(self) -> dict[str, Any]:
        return self.params_model.model_json_schema()


CATALOGUE: dict[str, ActionSpec] = {
    spec.action_id: spec
    for spec in (
        ActionSpec(
            action_id="collect_evidence",
            title="Collect additional diagnostic evidence",
            description="Run read-only, predefined evidence collectors (WMI/CIM, psutil, event log metadata, permitted probes).",
            kind=ActionKind.DIAGNOSTIC,
            risk=RiskLevel.LOW,
            requires_admin=False,
            reversible=True,
            consequences="Reads system information only. No settings are changed.",
            params_model=CollectEvidenceParams,
            categories=tuple(Category),
            addresses_causes=(),
            precondition=_pre_none,
            verification_evidence=(),
            verify=_verify_none,
        ),
        ActionSpec(
            action_id="flush_dns_cache",
            title="Flush the DNS resolver cache",
            description="Clear cached DNS answers (ipconfig /flushdns) so names are looked up again.",
            kind=ActionKind.SYSTEM_CHANGE,
            risk=RiskLevel.LOW,
            requires_admin=False,
            reversible=True,
            consequences="Cached name lookups are discarded; the next lookups may be slightly slower. No connection is interrupted.",
            params_model=NoParams,
            categories=(Category.NETWORK,),
            addresses_causes=("network.dns_failure",),
            precondition=_pre_flush_dns,
            verification_evidence=_NETWORK_VERIFY,
            verify=_verify_network,
        ),
        ActionSpec(
            action_id="renew_dhcp_lease",
            title="Renew the DHCP lease",
            description="Ask the DHCP server for a fresh IP configuration (ipconfig /renew).",
            kind=ActionKind.SYSTEM_CHANGE,
            risk=RiskLevel.MEDIUM,
            requires_admin=True,
            reversible=True,
            consequences="Network connections may drop for a few seconds while the address is renewed.",
            params_model=NoParams,
            categories=(Category.NETWORK,),
            addresses_causes=("network.no_valid_address", "network.gateway_unreachable"),
            precondition=_pre_renew_dhcp,
            verification_evidence=_NETWORK_VERIFY,
            verify=_verify_network,
        ),
        ActionSpec(
            action_id="restart_network_adapter",
            title="Restart a network adapter",
            description="Disable and re-enable one observed network adapter (Restart-NetAdapter).",
            kind=ActionKind.SYSTEM_CHANGE,
            risk=RiskLevel.MEDIUM,
            requires_admin=True,
            reversible=True,
            consequences="All connections on that adapter drop for several seconds; VPN sessions may need to reconnect.",
            params_model=AdapterParams,
            categories=(Category.NETWORK, Category.DRIVER),
            addresses_causes=("network.adapter_unavailable", "network.no_valid_address", "network.gateway_unreachable"),
            precondition=_pre_restart_adapter,
            verification_evidence=_NETWORK_VERIFY,
            verify=_verify_adapter,
        ),
        ActionSpec(
            action_id="restart_service",
            title="Restart a managed Windows service",
            description="Restart one service from a fixed list (Spooler, WSearch, BITS, wuauserv, Audiosrv).",
            kind=ActionKind.SYSTEM_CHANGE,
            risk=RiskLevel.MEDIUM,
            requires_admin=True,
            reversible=True,
            consequences="The service is unavailable for a few seconds (for example, print jobs or search indexing pause).",
            params_model=ServiceParams,
            categories=(Category.WINDOWS_HEALTH, Category.SYSTEM_PERFORMANCE),
            addresses_causes=("windows_health.service_stopped", "performance.cpu_saturation"),
            precondition=_pre_restart_service,
            verification_evidence=(EvidenceType.SERVICE_STATUS, EvidenceType.CPU_METRICS, EvidenceType.PROCESS_SUMMARY),
            verify=_verify_service,
        ),
        ActionSpec(
            action_id="clear_temp_files",
            title="Delete old temporary files",
            description="Delete files older than N days from the current user's TEMP folder only. Locked files are skipped.",
            kind=ActionKind.SYSTEM_CHANGE,
            risk=RiskLevel.MEDIUM,
            requires_admin=False,
            reversible=False,
            consequences="Deleted temporary files cannot be recovered. Files in use are skipped; no other folder is touched.",
            params_model=TempCleanupParams,
            categories=(Category.STORAGE, Category.SYSTEM_PERFORMANCE),
            addresses_causes=("storage.low_free_space",),
            precondition=_pre_clear_temp,
            verification_evidence=(EvidenceType.STORAGE_CAPACITY,),
            verify=_verify_clear_temp,
        ),
        ActionSpec(
            action_id="terminate_process",
            title="Close a resource-heavy application",
            description="Terminate all instances of one observed, non-protected process by name.",
            kind=ActionKind.SYSTEM_CHANGE,
            risk=RiskLevel.HIGH,
            requires_admin=False,
            reversible=False,
            consequences="Unsaved work in that application will be lost. The application can be reopened afterwards.",
            params_model=ProcessParams,
            categories=(Category.SYSTEM_PERFORMANCE,),
            addresses_causes=("performance.cpu_saturation", "performance.memory_pressure"),
            precondition=_pre_terminate_process,
            verification_evidence=(EvidenceType.CPU_METRICS, EvidenceType.MEMORY_METRICS, EvidenceType.PROCESS_SUMMARY),
            verify=_verify_terminate,
            auto_remediation_eligible=False,
        ),
    )
}


def describe_catalogue_for_model() -> list[dict[str, Any]]:
    """Compact description of operations, given to the language model as data."""
    described = []
    for spec in CATALOGUE.values():
        if spec.kind == ActionKind.DIAGNOSTIC:
            continue
        schema = spec.params_schema()
        described.append(
            {
                "action_id": spec.action_id,
                "what_it_does": spec.description,
                "parameters": schema.get("properties", {}),
                "risk": spec.risk.value,
                "addresses_causes": list(spec.addresses_causes),
            }
        )
    return described
