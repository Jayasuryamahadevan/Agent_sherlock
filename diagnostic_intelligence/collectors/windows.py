"""Collect a limited set of privacy-bounded local Windows resource metrics."""

from __future__ import annotations

import json
import ipaddress
import os
import platform
import socket
import subprocess
import time
from collections import Counter
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Callable

import psutil

from diagnostic_intelligence.models.evidence import (
    EvidenceRecord,
    EvidenceStatus,
    EvidenceType,
)
from diagnostic_intelligence.models.diagnostic_plan import DiagnosticPlan


_EVENT_LOG_QUERY = (
    "$events = @(Get-WinEvent -FilterHashtable "
    "@{ LogName = 'System'; StartTime = (Get-Date).AddHours(-24); Level = @(1, 2, 3) } "
    "-MaxEvents 100 -ErrorAction Stop); "
    "$events | Select-Object "
    "@{Name='timestamp';Expression={$_.TimeCreated.ToUniversalTime().ToString('o')}}, "
    "@{Name='provider';Expression={$_.ProviderName}}, "
    "@{Name='event_id';Expression={$_.Id}}, "
    "@{Name='level';Expression={$_.LevelDisplayName}} | ConvertTo-Json -Compress -Depth 3"
)
_STORAGE_EVENT_LOG_QUERY = (
    "$providers = @('Disk', 'Ntfs', 'UASPStor', 'storahci', 'stornvme', 'stexstor', "
    "'partmgr', 'nvstor', 'iaStorV', 'iaStorAVC', 'iaStorAC', 'Volsnap', "
    "'Microsoft-Windows-StorPort', 'Microsoft-Windows-StorageSpaces-Driver', "
    "'Microsoft-Windows-Kernel-Disk', 'Windows Disk Diagnostic'); "
    "$events = foreach ($provider in $providers) { "
    "try { Get-WinEvent -FilterHashtable "
    "@{ LogName = 'System'; StartTime = (Get-Date).AddHours(-24); Level = @(1, 2, 3); ProviderName = $provider } "
    "-MaxEvents 100 -ErrorAction Stop } catch { "
    "if ($_.FullyQualifiedErrorId -notmatch '^NoMatchingEventsFound|^NoMatchingProvidersFound|^LogsAndProvidersDontOverlap') { throw } } }; "
    "$events = @($events | Sort-Object TimeCreated -Descending | Select-Object -First 100); "
    "$events | Select-Object "
    "@{Name='timestamp';Expression={$_.TimeCreated.ToUniversalTime().ToString('o')}}, "
    "@{Name='provider';Expression={$_.ProviderName}}, "
    "@{Name='event_id';Expression={$_.Id}}, "
    "@{Name='level';Expression={$_.LevelDisplayName}} | ConvertTo-Json -Compress -Depth 3"
)
_STORAGE_EVENT_PROVIDERS = {
    "disk",
    "ntfs",
    "microsoft-windows-ntfs",
    "storahci",
    "stornvme",
    "partmgr",
    "volsnap",
    "microsoft-windows-storport",
}
_DEFAULT_ROUTE_QUERY = (
    "$route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop "
    "| Sort-Object RouteMetric | Select-Object -First 1; "
    "if ($null -ne $route) { $route.NextHop }"
)
_GATEWAY_REACHABILITY_QUERY = (
    "$route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop "
    "| Sort-Object RouteMetric | Select-Object -First 1; "
    "if ($null -eq $route) { "
    "[pscustomobject]@{ gateway = $null; reachable = $false; latency_ms = $null; error_category = 'no_default_gateway' } "
    "| ConvertTo-Json -Compress } else { "
    "$gateway = $route.NextHop; "
    "try { $ping = [System.Net.NetworkInformation.Ping]::new(); "
    "$reply = $ping.Send($gateway, 1500); $reachable = $reply.Status -eq 'Success'; "
    "$latency = if ($reachable) { [int]$reply.RoundtripTime } else { $null }; "
    "$category = if ($reachable) { $null } else { $reply.Status.ToString() }; "
    "[pscustomobject]@{ gateway = $gateway; reachable = $reachable; latency_ms = $latency; error_category = $category } "
    "| ConvertTo-Json -Compress } catch { "
    "[pscustomobject]@{ gateway = $gateway; reachable = $false; latency_ms = $null; error_category = 'probe_failed' } "
    "| ConvertTo-Json -Compress } }"
)
_RELIABILITY_SUMMARY_QUERY = (
    "$cutoff = (Get-Date).AddDays(-7); "
    "$records = @(Get-CimInstance -ClassName Win32_ReliabilityRecords -OperationTimeoutSec 8 -ErrorAction Stop "
    "| Where-Object { $_.TimeGenerated -and $_.TimeGenerated -ge $cutoff } "
    "| Sort-Object TimeGenerated -Descending | Select-Object -First 51); "
    "$truncated = $records.Count -gt 50; "
    "$records | Select-Object -First 50 "
    "@{Name='timestamp';Expression={$_.TimeGenerated.ToUniversalTime().ToString('o')}}, "
    "@{Name='type';Expression={$_.SourceName}}, "
    "@{Name='application';Expression={$_.ProductName}}, "
    "@{Name='event_id';Expression={$_.EventIdentifier}}, "
    "@{Name='truncated';Expression={$truncated}} | ConvertTo-Json -Compress -Depth 3"
)

# Services whose state the agent may query. Must stay in sync with the remediation catalogue.
MANAGED_SERVICES: tuple[str, ...] = ("Spooler", "WSearch", "BITS", "wuauserv", "Audiosrv", "Dnscache", "Dhcp")
_SERVICE_STATUS_QUERY = (
    "$names = @($env:DIAG_SERVICE_NAMES -split ','); "
    "@(Get-CimInstance -ClassName Win32_Service -OperationTimeoutSec 8 -ErrorAction Stop "
    "| Where-Object { $names -contains $_.Name } "
    "| Select-Object @{Name='name';Expression={$_.Name}}, @{Name='state';Expression={$_.State}}, "
    "@{Name='start_mode';Expression={$_.StartMode}}, @{Name='exit_code';Expression={[int]$_.ExitCode}}) "
    "| ConvertTo-Json -Compress -Depth 3"
)
_DEVICE_STATUS_QUERY = (
    "@(Get-CimInstance -ClassName Win32_PnPEntity -OperationTimeoutSec 10 -ErrorAction Stop "
    "| Where-Object { $_.ConfigManagerErrorCode -ne 0 } | Select-Object -First 25 "
    "@{Name='device_id';Expression={$_.PNPDeviceID}}, @{Name='name';Expression={$_.Name}}, "
    "@{Name='device_class';Expression={$_.PNPClass}}, @{Name='status';Expression={$_.Status}}, "
    "@{Name='problem_code';Expression={[int]$_.ConfigManagerErrorCode}}) | ConvertTo-Json -Compress -Depth 3"
)


class WindowsEvidenceCollector:
    """Collect bounded resource and Windows event metadata from the host."""

    source = "windows_resource_collector"

    def __init__(
        self,
        cpu_sample_seconds: float = 0.25,
        disk_sample_seconds: float = 0.5,
        process_sample_seconds: float = 0.25,
        max_processes: int = 5,
    ) -> None:
        if isinstance(cpu_sample_seconds, bool) or not 0.05 <= cpu_sample_seconds <= 5:
            raise ValueError("cpu_sample_seconds must be between 0.05 and 5 seconds")
        if isinstance(disk_sample_seconds, bool) or not 0.1 <= disk_sample_seconds <= 5:
            raise ValueError("disk_sample_seconds must be between 0.1 and 5 seconds")
        if isinstance(process_sample_seconds, bool) or not 0.05 <= process_sample_seconds <= 5:
            raise ValueError("process_sample_seconds must be between 0.05 and 5 seconds")
        if isinstance(max_processes, bool) or not 1 <= max_processes <= 20:
            raise ValueError("max_processes must be between 1 and 20")
        self.cpu_sample_seconds = cpu_sample_seconds
        self.disk_sample_seconds = disk_sample_seconds
        self.process_sample_seconds = process_sample_seconds
        self.max_processes = max_processes

    def collect(
        self,
        session_id: str,
        *,
        storage_paths: Sequence[str] | None = None,
    ) -> list[EvidenceRecord]:
        """Return CPU, memory, disk activity, and configured-volume capacity evidence."""
        paths = tuple(storage_paths or (os.path.abspath(os.sep),))
        return [
            self._capture(
                session_id,
                "performance.cpu",
                EvidenceType.CPU_METRICS,
                self._cpu_data,
            ),
            self._capture(
                session_id,
                "performance.memory",
                EvidenceType.MEMORY_METRICS,
                self._memory_data,
            ),
            self._capture(
                session_id,
                "storage.capacity",
                EvidenceType.STORAGE_CAPACITY,
                lambda: self._storage_data(paths),
            ),
            self._capture(
                session_id,
                "storage.disk_activity",
                EvidenceType.DISK_ACTIVITY,
                self._disk_activity_data,
            ),
            self._capture(
                session_id,
                "performance.process_summary",
                EvidenceType.PROCESS_SUMMARY,
                self._process_summary_data,
            ),
        ]

    def collect_for_plan(self, plan: DiagnosticPlan) -> list[EvidenceRecord]:
        """Collect supported requests and mark unimplemented types unavailable."""
        if plan.session_id is None:
            raise ValueError("the diagnostic plan must include a session_id")

        handlers = {
            EvidenceType.CPU_METRICS: self._cpu_data,
            EvidenceType.MEMORY_METRICS: self._memory_data,
            EvidenceType.STORAGE_CAPACITY: lambda: self._storage_data(
                (os.path.abspath(os.sep),)
            ),
            EvidenceType.DISK_ACTIVITY: self._disk_activity_data,
            EvidenceType.PROCESS_SUMMARY: self._process_summary_data,
            EvidenceType.STORAGE_ERRORS: self._storage_errors_data,
            EvidenceType.SYSTEM_EVENTS: self._system_events_data,
            EvidenceType.RELIABILITY_SUMMARY: self._reliability_summary_data,
            EvidenceType.NETWORK_CONFIGURATION: self._network_configuration_data,
            EvidenceType.ADAPTER_STATUS: self._adapter_status_data,
            EvidenceType.DNS_RESOLUTION: self._dns_resolution_data,
            EvidenceType.GATEWAY_REACHABILITY: self._gateway_reachability_data,
            EvidenceType.NETWORK_CONNECTIVITY: self._network_connectivity_data,
            EvidenceType.SERVICE_STATUS: self._service_status_data,
            EvidenceType.DEVICE_STATUS: self._device_status_data,
        }
        records = []
        for evidence_request in plan.evidence_requests:
            handler = handlers.get(evidence_request.evidence_type)
            if handler is None:
                records.append(
                    EvidenceRecord(
                        session_id=plan.session_id,
                        evidence_id=evidence_request.evidence_id,
                        evidence_type=evidence_request.evidence_type,
                        collected_at=datetime.now(timezone.utc),
                        status=EvidenceStatus.UNAVAILABLE,
                        data={"reason": "No collector is registered for this evidence type."},
                        source=self.source,
                    )
                )
                continue
            records.append(
                self._capture(
                    plan.session_id,
                    evidence_request.evidence_id,
                    evidence_request.evidence_type,
                    handler,
                )
            )
        return records

    def _cpu_data(self) -> tuple[dict, EvidenceStatus]:
        collected_at = datetime.now(timezone.utc)
        utilization = psutil.cpu_percent(interval=self.cpu_sample_seconds)
        return (
            {
                "utilization_percent": utilization,
                "samples": [
                    {
                        "timestamp": collected_at.isoformat(),
                        "utilization_percent": utilization,
                    }
                ],
            },
            EvidenceStatus.AVAILABLE,
        )

    @staticmethod
    def _memory_data() -> tuple[dict, EvidenceStatus]:
        memory = psutil.virtual_memory()
        return (
            {
                "total_bytes": memory.total,
                "available_bytes": memory.available,
                "used_percent": memory.percent,
            },
            EvidenceStatus.AVAILABLE,
        )

    def _disk_activity_data(self) -> tuple[dict, EvidenceStatus]:
        before = psutil.disk_io_counters(perdisk=False)
        if before is None:
            raise OSError("Aggregate disk I/O counters are unavailable")

        started = time.monotonic()
        time.sleep(self.disk_sample_seconds)
        after = psutil.disk_io_counters(perdisk=False)
        elapsed = time.monotonic() - started
        if after is None:
            raise OSError("Aggregate disk I/O counters are unavailable")
        if elapsed <= 0:
            raise OSError("Disk I/O observation window was not measurable")

        counter_names = ("read_count", "write_count", "read_bytes", "write_bytes")
        deltas = {}
        for name in counter_names:
            first = getattr(before, name, None)
            last = getattr(after, name, None)
            if not isinstance(first, int) or not isinstance(last, int) or last < first:
                raise OSError("Disk I/O counters were incomplete or reset during sampling")
            deltas[name] = last - first

        operations = deltas["read_count"] + deltas["write_count"]
        read_time_before = getattr(before, "read_time", None)
        read_time_after = getattr(after, "read_time", None)
        write_time_before = getattr(before, "write_time", None)
        write_time_after = getattr(after, "write_time", None)
        latency_values = (
            read_time_before,
            read_time_after,
            write_time_before,
            write_time_after,
        )
        average_latency = None
        if operations and all(isinstance(value, int) for value in latency_values):
            read_time_delta = read_time_after - read_time_before
            write_time_delta = write_time_after - write_time_before
            if read_time_delta < 0 or write_time_delta < 0:
                raise OSError("Disk I/O timing counters reset during sampling")
            average_latency = (read_time_delta + write_time_delta) / operations

        return (
            {
                "observation_window_seconds": elapsed,
                "read_bytes_per_second": deltas["read_bytes"] / elapsed,
                "write_bytes_per_second": deltas["write_bytes"] / elapsed,
                "read_ops_per_second": deltas["read_count"] / elapsed,
                "write_ops_per_second": deltas["write_count"] / elapsed,
                "average_latency_ms": average_latency,
            },
            EvidenceStatus.AVAILABLE,
        )

    def _process_summary_data(self) -> tuple[dict, EvidenceStatus]:
        sampled_processes = []
        unavailable_count = 0
        for process in psutil.process_iter(attrs=["name"]):
            try:
                name = process.info.get("name")
                if not isinstance(name, str) or not name:
                    unavailable_count += 1
                    continue
                process.cpu_percent(interval=None)
                memory_bytes = process.memory_info().rss
                sampled_processes.append((process, name, memory_bytes))
            except psutil.Error:
                unavailable_count += 1

        if not sampled_processes:
            return (
                {"processes": [], "unavailable_process_count": unavailable_count},
                EvidenceStatus.UNAVAILABLE,
            )

        time.sleep(self.process_sample_seconds)
        process_summaries = []
        for process, name, memory_bytes in sampled_processes:
            try:
                cpu_percent = process.cpu_percent(interval=None)
            except psutil.Error:
                unavailable_count += 1
                continue
            process_summaries.append(
                {
                    "name": name,
                    "cpu_percent": cpu_percent,
                    "memory_bytes": memory_bytes,
                }
            )

        if not process_summaries:
            return (
                {"processes": [], "unavailable_process_count": unavailable_count},
                EvidenceStatus.UNAVAILABLE,
            )

        max_cpu = max(item["cpu_percent"] for item in process_summaries)
        max_memory = max(item["memory_bytes"] for item in process_summaries)
        process_summaries.sort(
            key=lambda item: (
                (item["cpu_percent"] / max_cpu if max_cpu else 0)
                + (item["memory_bytes"] / max_memory if max_memory else 0)
            ),
            reverse=True,
        )
        return (
            {
                "processes": process_summaries[: self.max_processes],
                "unavailable_process_count": unavailable_count,
            },
            EvidenceStatus.PARTIAL if unavailable_count else EvidenceStatus.AVAILABLE,
        )

    def _system_events_data(self) -> tuple[dict, EvidenceStatus]:
        return self._windows_event_data(storage_only=False)

    @staticmethod
    def _reliability_summary_data() -> tuple[dict, EvidenceStatus]:
        if platform.system() != "Windows":
            return (
                {"incidents": [], "reason": "Windows reliability records are only available on Windows."},
                EvidenceStatus.UNAVAILABLE,
            )
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _RELIABILITY_SUMMARY_QUERY],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if result.returncode != 0:
            raise OSError("The Windows reliability query failed")
        try:
            parsed = json.loads(result.stdout.strip()) if result.stdout.strip() else []
        except json.JSONDecodeError as error:
            raise ValueError("The reliability query returned invalid JSON") from error
        raw_incidents = [parsed] if isinstance(parsed, dict) else parsed
        if not isinstance(raw_incidents, list):
            raise ValueError("The reliability query returned an invalid shape")

        incidents = []
        skipped_count = 0
        for incident in raw_incidents:
            if not isinstance(incident, dict):
                skipped_count += 1
                continue
            timestamp = incident.get("timestamp")
            incident_type = incident.get("type")
            application = incident.get("application")
            if not all(isinstance(value, str) and value for value in (timestamp, incident_type, application)):
                skipped_count += 1
                continue
            event_id = incident.get("event_id")
            incidents.append(
                {
                    "timestamp": timestamp,
                    "type": incident_type[:128],
                    "application": application[:128],
                    "event_id": event_id if isinstance(event_id, int) else None,
                }
            )
        truncated = any(
            incident.get("truncated") is True
            for incident in raw_incidents
            if isinstance(incident, dict)
        )
        data = {
            "incidents": incidents,
            "skipped_record_count": skipped_count,
            "truncated": truncated,
        }
        return data, EvidenceStatus.PARTIAL if truncated or skipped_count else EvidenceStatus.AVAILABLE

    def _storage_errors_data(self) -> tuple[dict, EvidenceStatus]:
        return self._windows_event_data(storage_only=True)

    @staticmethod
    def _adapter_records() -> tuple[list[dict], int]:
        addresses = psutil.net_if_addrs()
        interface_stats = psutil.net_if_stats()
        unavailable_count = 0
        adapters = []
        for name in sorted(set(addresses) | set(interface_stats)):
            stat = interface_stats.get(name)
            if stat is None:
                unavailable_count += 1
            interface_addresses = []
            for address in addresses.get(name, []):
                if address.family not in (socket.AF_INET, socket.AF_INET6):
                    continue
                value = address.address.split("%", 1)[0]
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    continue
                interface_addresses.append(value)
            adapters.append(
                {
                    "name": name[:128],
                    "status": "up" if stat and stat.isup else "down" if stat else "unknown",
                    "addresses": interface_addresses,
                }
            )
        return adapters, unavailable_count

    @classmethod
    def _network_configuration_data(cls) -> tuple[dict, EvidenceStatus]:
        adapters, unavailable_count = cls._adapter_records()
        if not adapters:
            raise OSError("No network adapters could be queried")
        gateway = None
        if platform.system() == "Windows":
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _DEFAULT_ROUTE_QUERY],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode != 0:
                raise OSError("The default route query failed")
            gateway = result.stdout.strip() or None
            if gateway:
                try:
                    ipaddress.ip_address(gateway)
                except ValueError as error:
                    raise ValueError("The default route returned an invalid gateway address") from error
        else:
            unavailable_count += 1
        return (
            {"adapters": adapters, "default_gateway": gateway},
            EvidenceStatus.PARTIAL if unavailable_count else EvidenceStatus.AVAILABLE,
        )

    @classmethod
    def _adapter_status_data(cls) -> tuple[dict, EvidenceStatus]:
        adapters, unavailable_count = cls._adapter_records()
        if not adapters:
            raise OSError("No network adapters could be queried")
        return (
            {"adapters": adapters, "unavailable_adapter_count": unavailable_count},
            EvidenceStatus.PARTIAL if unavailable_count else EvidenceStatus.AVAILABLE,
        )

    @staticmethod
    def _valid_dns_hostname(hostname: str) -> bool:
        if not hostname or len(hostname) > 253 or hostname.endswith("."):
            return False
        try:
            ipaddress.ip_address(hostname)
            return False
        except ValueError:
            pass
        labels = hostname.split(".")
        return all(
            1 <= len(label) <= 63
            and label[0].isalnum()
            and label[-1].isalnum()
            and all(character.isascii() and (character.isalnum() or character == "-") for character in label)
            for label in labels
        )

    @classmethod
    def _dns_resolution_data(cls) -> tuple[dict, EvidenceStatus]:
        hostname = os.environ.get("WINDOWS_DIAGNOSTIC_DNS_HOSTNAME", "").strip()
        if not hostname:
            return (
                {
                    "success": False,
                    "resolved_addresses": [],
                    "error_category": "no_permitted_hostname_configured",
                },
                EvidenceStatus.UNAVAILABLE,
            )
        if not cls._valid_dns_hostname(hostname):
            return (
                {
                    "hostname": hostname[:253],
                    "success": False,
                    "resolved_addresses": [],
                    "error_category": "invalid_configured_hostname",
                },
                EvidenceStatus.UNAVAILABLE,
            )
        try:
            results = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        except socket.gaierror:
            return (
                {
                    "hostname": hostname,
                    "success": False,
                    "resolved_addresses": [],
                    "error_category": "name_resolution_failed",
                },
                EvidenceStatus.AVAILABLE,
            )

        addresses = sorted({item[4][0] for item in results if item and len(item) > 4})
        if not addresses:
            return (
                {
                    "hostname": hostname,
                    "success": False,
                    "resolved_addresses": [],
                    "error_category": "no_addresses_returned",
                },
                EvidenceStatus.AVAILABLE,
            )
        truncated = len(addresses) > 20
        return (
            {
                "hostname": hostname,
                "success": True,
                "resolved_addresses": addresses[:20],
                "error_category": None,
                "truncated": truncated,
            },
            EvidenceStatus.PARTIAL if truncated else EvidenceStatus.AVAILABLE,
        )

    @staticmethod
    def _gateway_reachability_data() -> tuple[dict, EvidenceStatus]:
        if platform.system() != "Windows":
            return (
                {"gateway": None, "reachable": False, "latency_ms": None, "error_category": "windows_only_probe"},
                EvidenceStatus.UNAVAILABLE,
            )
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _GATEWAY_REACHABILITY_QUERY],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode != 0:
            raise OSError("The default gateway reachability probe failed")
        try:
            payload = json.loads(result.stdout.strip())
        except json.JSONDecodeError as error:
            raise ValueError("The default gateway probe returned invalid JSON") from error
        if not isinstance(payload, dict) or not isinstance(payload.get("reachable"), bool):
            raise ValueError("The default gateway probe returned an invalid shape")
        gateway = payload.get("gateway")
        if gateway is not None:
            if not isinstance(gateway, str):
                raise ValueError("The default gateway probe returned an invalid address")
            try:
                ipaddress.ip_address(gateway)
            except ValueError as error:
                raise ValueError("The default gateway probe returned an invalid address") from error
        latency_ms = payload.get("latency_ms")
        if latency_ms is not None and (
            not isinstance(latency_ms, (int, float)) or isinstance(latency_ms, bool)
        ):
            raise ValueError("The default gateway probe returned invalid latency")
        error_category = payload.get("error_category")
        if error_category is not None and not isinstance(error_category, str):
            raise ValueError("The default gateway probe returned an invalid error category")
        return (
            {
                "gateway": gateway,
                "reachable": payload["reachable"],
                "latency_ms": latency_ms,
                "error_category": error_category,
            },
            EvidenceStatus.AVAILABLE,
        )

    @classmethod
    def _network_connectivity_data(cls) -> tuple[dict, EvidenceStatus]:
        endpoint_id = os.environ.get("WINDOWS_DIAGNOSTIC_CONNECTIVITY_ENDPOINT_ID", "").strip()
        hostname = os.environ.get("WINDOWS_DIAGNOSTIC_CONNECTIVITY_HOST", "").strip()
        raw_port = os.environ.get("WINDOWS_DIAGNOSTIC_CONNECTIVITY_PORT", "").strip()
        unavailable = {
            "endpoint_id": endpoint_id or None,
            "reachable": False,
            "latency_ms": None,
            "error_category": "no_permitted_endpoint_configured",
        }
        if not endpoint_id or len(endpoint_id) > 64 or not endpoint_id[0].isalpha() or not all(
            character.isascii() and (character.isalnum() or character in "_.-")
            for character in endpoint_id
        ):
            return unavailable, EvidenceStatus.UNAVAILABLE
        if not hostname or len(hostname) > 253:
            return unavailable, EvidenceStatus.UNAVAILABLE
        try:
            ipaddress.ip_address(hostname)
            valid_host = True
        except ValueError:
            valid_host = cls._valid_dns_hostname(hostname)
        if not valid_host:
            return (
                {**unavailable, "error_category": "invalid_configured_endpoint"},
                EvidenceStatus.UNAVAILABLE,
            )
        try:
            port = int(raw_port)
        except ValueError:
            return (
                {**unavailable, "error_category": "invalid_configured_endpoint"},
                EvidenceStatus.UNAVAILABLE,
            )
        if not 1 <= port <= 65535:
            return (
                {**unavailable, "error_category": "invalid_configured_endpoint"},
                EvidenceStatus.UNAVAILABLE,
            )

        started = time.monotonic()
        try:
            connection = socket.create_connection((hostname, port), timeout=3)
            connection.close()
        except socket.gaierror:
            return (
                {"endpoint_id": endpoint_id, "reachable": False, "latency_ms": None, "error_category": "name_resolution_failed"},
                EvidenceStatus.AVAILABLE,
            )
        except TimeoutError:
            return (
                {"endpoint_id": endpoint_id, "reachable": False, "latency_ms": None, "error_category": "timeout"},
                EvidenceStatus.AVAILABLE,
            )
        except OSError:
            return (
                {"endpoint_id": endpoint_id, "reachable": False, "latency_ms": None, "error_category": "connection_failed"},
                EvidenceStatus.AVAILABLE,
            )
        return (
            {
                "endpoint_id": endpoint_id,
                "reachable": True,
                "latency_ms": round((time.monotonic() - started) * 1000, 2),
                "error_category": None,
            },
            EvidenceStatus.AVAILABLE,
        )

    @staticmethod
    def _run_cim_json(query: str, *, timeout: int, env_extra: dict[str, str] | None = None) -> list:
        """Run a fixed WMI/CIM PowerShell query and return a JSON list (no user input in the script)."""
        env = {**os.environ, **(env_extra or {})}
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", query],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
        if result.returncode != 0:
            raise OSError("The WMI/CIM query failed")
        output = result.stdout.strip()
        try:
            parsed = json.loads(output) if output else []
        except json.JSONDecodeError as error:
            raise ValueError("The WMI/CIM query returned invalid JSON") from error
        parsed = [parsed] if isinstance(parsed, dict) else parsed
        if not isinstance(parsed, list):
            raise ValueError("The WMI/CIM query returned an invalid shape")
        return parsed

    @classmethod
    def _service_status_data(cls) -> tuple[dict, EvidenceStatus]:
        if platform.system() != "Windows":
            return (
                {"services": [], "reason": "Windows service status is only available on Windows."},
                EvidenceStatus.UNAVAILABLE,
            )
        raw = cls._run_cim_json(
            _SERVICE_STATUS_QUERY,
            timeout=15,
            env_extra={"DIAG_SERVICE_NAMES": ",".join(MANAGED_SERVICES)},
        )
        allowed = {name.casefold(): name for name in MANAGED_SERVICES}
        services = []
        for item in raw:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                continue
            canonical = allowed.get(item["name"].casefold())
            if canonical is None:
                continue
            services.append(
                {
                    "name": canonical,
                    "state": str(item.get("state") or "Unknown")[:32],
                    "start_mode": str(item.get("start_mode") or "Unknown")[:32],
                    "exit_code": item.get("exit_code") if isinstance(item.get("exit_code"), int) else None,
                }
            )
        return {"services": services, "queried": list(MANAGED_SERVICES)}, EvidenceStatus.AVAILABLE

    @classmethod
    def _device_status_data(cls) -> tuple[dict, EvidenceStatus]:
        if platform.system() != "Windows":
            return (
                {"devices": [], "reason": "Plug and Play device status is only available on Windows."},
                EvidenceStatus.UNAVAILABLE,
            )
        raw = cls._run_cim_json(_DEVICE_STATUS_QUERY, timeout=20)
        devices = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            problem_code = item.get("problem_code")
            if not isinstance(problem_code, int) or problem_code == 0:
                continue
            devices.append(
                {
                    "device_id": str(item.get("device_id") or "")[:200],
                    "name": str(item.get("name") or "Unknown device")[:128],
                    "device_class": str(item.get("device_class") or "")[:64],
                    "status": str(item.get("status") or "")[:32],
                    "problem_code": problem_code,
                }
            )
        return (
            {"devices": devices, "problem_device_count": len(devices), "status": "ok" if not devices else "problem"},
            EvidenceStatus.PARTIAL if len(raw) >= 25 else EvidenceStatus.AVAILABLE,
        )

    def collect_types(self, session_id: str, requests: list) -> list[EvidenceRecord]:
        """Collect an explicit list of EvidenceRequest objects (used by the agent)."""
        plan = DiagnosticPlan(
            session_id=session_id,
            category="unknown",
            evidence_requests=requests,
            reasoning_summary="Agent-selected evidence collection.",
        )
        return self.collect_for_plan(plan)

    @staticmethod
    def _windows_event_data(*, storage_only: bool) -> tuple[dict, EvidenceStatus]:
        if platform.system() != "Windows":
            return (
                {"events": [], "reason": "Windows event logs are only available on Windows."},
                EvidenceStatus.UNAVAILABLE,
            )

        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                _STORAGE_EVENT_LOG_QUERY if storage_only else _EVENT_LOG_QUERY,
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if result.returncode != 0:
            raise OSError("The System event log query failed")

        output = result.stdout.strip()
        try:
            parsed = json.loads(output) if output else []
        except json.JSONDecodeError as error:
            raise ValueError("The System event log query returned invalid JSON") from error
        raw_events = [parsed] if isinstance(parsed, dict) else parsed
        if not isinstance(raw_events, list):
            raise ValueError("The System event log query returned an invalid shape")

        events = []
        for event in raw_events:
            if not isinstance(event, dict):
                continue
            provider = event.get("provider")
            if not isinstance(provider, str):
                continue
            if storage_only and provider.casefold() not in _STORAGE_EVENT_PROVIDERS:
                continue
            event_id = event.get("event_id")
            timestamp = event.get("timestamp")
            level = event.get("level")
            if not isinstance(event_id, int) or not isinstance(timestamp, str) or not isinstance(level, str):
                continue
            events.append(
                {
                    "timestamp": timestamp,
                    "provider": provider[:128],
                    "event_id": event_id,
                    "level": level[:32],
                }
            )

        error_counts = Counter(
            (event["provider"].casefold(), event["event_id"])
            for event in events
            if event["level"].casefold() in {"critical", "error"}
        )
        recurring_error_count = sum(count for count in error_counts.values() if count >= 2)
        truncated = len(raw_events) >= 100
        data = {
            "events": events,
            "recurring_error_count": recurring_error_count,
            "truncated": truncated,
        }
        return data, EvidenceStatus.PARTIAL if truncated else EvidenceStatus.AVAILABLE

    @staticmethod
    def _storage_data(paths: Sequence[str]) -> tuple[dict, EvidenceStatus]:
        volumes = []
        failures = 0
        for path in paths:
            try:
                usage = psutil.disk_usage(path)
            except OSError:
                failures += 1
                continue
            volumes.append(
                {
                    "total_bytes": usage.total,
                    "free_bytes": usage.free,
                    "free_percent": usage.free / usage.total * 100 if usage.total else 0,
                    "free_gb": usage.free / (1024 ** 3),
                }
            )
        if not volumes:
            raise OSError("No configured storage volume could be queried")
        return (
            {"volumes": volumes, "unavailable_volume_count": failures},
            EvidenceStatus.PARTIAL if failures else EvidenceStatus.AVAILABLE,
        )

    @classmethod
    def _capture(
        cls,
        session_id: str,
        evidence_id: str,
        evidence_type: EvidenceType,
        collect_data: Callable[[], tuple[dict, EvidenceStatus]],
    ) -> EvidenceRecord:
        try:
            data, status = collect_data()
            return EvidenceRecord(
                session_id=session_id,
                evidence_id=evidence_id,
                evidence_type=evidence_type,
                collected_at=datetime.now(timezone.utc),
                status=status,
                data=data,
                source=cls.source,
            )
        except Exception as error:
            return EvidenceRecord(
                session_id=session_id,
                evidence_id=evidence_id,
                evidence_type=evidence_type,
                collected_at=datetime.now(timezone.utc),
                status=EvidenceStatus.ERROR,
                data={},
                source=cls.source,
                error=f"Collection failed ({type(error).__name__}).",
            )