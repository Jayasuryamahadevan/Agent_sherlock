import json
from types import SimpleNamespace

import pytest

from diagnostic_intelligence import DiagnosticOrchestrator, WindowsEvidenceCollector
from diagnostic_intelligence.collectors import windows
from diagnostic_intelligence.models.classification import Category
from diagnostic_intelligence.models.diagnostic_plan import DiagnosticPlan, EvidenceRequest, Priority
from diagnostic_intelligence.models.evidence import EvidenceType


def patch_system_metrics(monkeypatch) -> None:
    class FakeProcess:
        info = {"name": "test-process.exe"}

        def __init__(self):
            self.cpu_samples = iter([0.0, 1.0])

        def cpu_percent(self, interval=None):
            return next(self.cpu_samples)

        def memory_info(self):
            return SimpleNamespace(rss=1_000)

    monkeypatch.setattr(windows.psutil, "cpu_percent", lambda interval: 94.0)
    monkeypatch.setattr(
        windows.psutil,
        "virtual_memory",
        lambda: SimpleNamespace(total=16_000, available=4_000, percent=75.0),
    )
    monkeypatch.setattr(
        windows.psutil,
        "disk_usage",
        lambda path: SimpleNamespace(total=1_000, free=250),
    )
    disk_samples = iter(
        [
            SimpleNamespace(
                read_count=100,
                write_count=200,
                read_bytes=1_000,
                write_bytes=2_000,
                read_time=200,
                write_time=100,
            ),
            SimpleNamespace(
                read_count=120,
                write_count=210,
                read_bytes=11_000,
                write_bytes=7_000,
                read_time=240,
                write_time=120,
            ),
        ]
    )
    monkeypatch.setattr(
        windows.psutil,
        "disk_io_counters",
        lambda perdisk=False: next(disk_samples),
    )
    monkeypatch.setattr(windows.time, "sleep", lambda seconds: None)
    monotonic_values = iter([10.0, 12.0])
    monkeypatch.setattr(windows.time, "monotonic", lambda: next(monotonic_values))
    monkeypatch.setattr(windows.psutil, "process_iter", lambda attrs: [FakeProcess()])


def test_collector_returns_valid_aggregate_evidence(monkeypatch) -> None:
    patch_system_metrics(monkeypatch)

    records = WindowsEvidenceCollector().collect("collector-test", storage_paths=["C:\\"])

    assert [record.evidence_type.value for record in records] == [
        "performance.cpu",
        "performance.memory",
        "storage.capacity",
        "storage.disk_activity",
        "performance.process_summary",
    ]
    assert all(record.status.value == "available" for record in records)
    assert records[0].data["utilization_percent"] == 94.0
    assert records[1].data["available_bytes"] == 4_000
    assert records[2].data["volumes"][0]["free_percent"] == 25.0
    assert "C:" not in str(records[2].model_dump(mode="json"))
    assert records[3].evidence_type.value == "storage.disk_activity"
    assert records[3].data["read_bytes_per_second"] == 5_000
    assert records[3].data["write_bytes_per_second"] == 2_500
    assert records[3].data["average_latency_ms"] == 2
    assert records[4].data["processes"] == [
        {"name": "test-process.exe", "cpu_percent": 1.0, "memory_bytes": 1_000}
    ]


def test_collector_marks_individual_collection_failure(monkeypatch) -> None:
    patch_system_metrics(monkeypatch)
    monkeypatch.setattr(windows.psutil, "virtual_memory", lambda: (_ for _ in ()).throw(OSError()))

    records = WindowsEvidenceCollector().collect("collector-test", storage_paths=["C:\\"])

    assert records[0].status.value == "available"
    assert records[1].status.value == "error"
    assert records[1].error == "Collection failed (OSError)."
    assert records[2].status.value == "available"


def test_process_summary_returns_top_resource_users_without_identifiers(monkeypatch) -> None:
    class FakeProcess:
        def __init__(self, name, cpu_percent, memory_bytes):
            self.info = {"name": name}
            self.pid = 12345
            self._cpu_percent = iter([0.0, cpu_percent])
            self._memory_bytes = memory_bytes

        def cpu_percent(self, interval=None):
            return next(self._cpu_percent)

        def memory_info(self):
            return SimpleNamespace(rss=self._memory_bytes)

    monkeypatch.setattr(
        windows.psutil,
        "process_iter",
        lambda attrs: [
            FakeProcess("worker.exe", 60.0, 100),
            FakeProcess("browser.exe", 5.0, 900),
            FakeProcess("idle.exe", 0.0, 10),
        ],
    )

    record = WindowsEvidenceCollector(max_processes=2)._capture(
        "collector-test",
        "performance.process_summary",
        EvidenceType.PROCESS_SUMMARY,
        WindowsEvidenceCollector(max_processes=2)._process_summary_data,
    )

    assert record.status.value == "available"
    assert {item["name"] for item in record.data["processes"]} == {
        "worker.exe",
        "browser.exe",
    }
    assert all(set(item) == {"name", "cpu_percent", "memory_bytes"} for item in record.data["processes"])
    assert "pid" not in str(record.model_dump(mode="json"))


def test_process_summary_marks_process_access_failures_partial(monkeypatch) -> None:
    class FakeProcess:
        info = {"name": "restricted.exe"}

        def cpu_percent(self, interval=None):
            raise windows.psutil.AccessDenied(pid=456)

        def memory_info(self):
            return SimpleNamespace(rss=10)

    monkeypatch.setattr(windows.psutil, "process_iter", lambda attrs: [FakeProcess()])

    data, status = WindowsEvidenceCollector()._process_summary_data()

    assert status.value == "unavailable"
    assert data["processes"] == []
    assert data["unavailable_process_count"] == 1


def test_event_log_collection_returns_only_bounded_metadata(monkeypatch) -> None:
    raw_events = [
        {
            "timestamp": "2026-10-21T12:00:00Z",
            "provider": "Disk",
            "event_id": 7,
            "level": "Error",
            "message": "Private event message",
        },
        {
            "timestamp": "2026-10-21T12:01:00Z",
            "provider": "Microsoft-Windows-Kernel-Power",
            "event_id": 41,
            "level": "Warning",
            "message": "Another private event message",
        },
    ]
    monkeypatch.setattr(windows.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        windows.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=json.dumps(raw_events),
            stderr="",
        ),
    )

    data, status = WindowsEvidenceCollector._windows_event_data(storage_only=True)

    assert status.value == "available"
    assert data["events"] == [
        {
            "timestamp": "2026-10-21T12:00:00Z",
            "provider": "Disk",
            "event_id": 7,
            "level": "Error",
        }
    ]
    assert "message" not in str(data)


def test_system_event_collection_counts_repeated_errors(monkeypatch) -> None:
    raw_events = [
        {"timestamp": "2026-10-21T12:00:00Z", "provider": "Example", "event_id": 7, "level": "Error"},
        {"timestamp": "2026-10-21T12:01:00Z", "provider": "Example", "event_id": 7, "level": "Error"},
        {"timestamp": "2026-10-21T12:02:00Z", "provider": "Example", "event_id": 8, "level": "Error"},
        {"timestamp": "2026-10-21T12:03:00Z", "provider": "Example", "event_id": 9, "level": "Warning"},
    ]
    monkeypatch.setattr(windows.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        windows.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=json.dumps(raw_events),
            stderr="",
        ),
    )

    data, status = WindowsEvidenceCollector._windows_event_data(storage_only=False)

    assert status.value == "available"
    assert len(data["events"]) == 4
    assert data["recurring_error_count"] == 2


def test_event_collection_is_unavailable_off_windows(monkeypatch) -> None:
    monkeypatch.setattr(windows.platform, "system", lambda: "Linux")

    data, status = WindowsEvidenceCollector._windows_event_data(storage_only=False)

    assert status.value == "unavailable"
    assert data["events"] == []
    assert "only available on Windows" in data["reason"]


def test_reliability_summary_returns_only_incident_metadata(monkeypatch) -> None:
    incident = {
        "timestamp": "2026-10-21T12:00:00Z",
        "type": "Application Error",
        "application": "example.exe",
        "event_id": 1000,
        "message": "Private failure details",
        "truncated": False,
    }
    monkeypatch.setattr(windows.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        windows.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=json.dumps([incident]),
            stderr="",
        ),
    )

    data, status = WindowsEvidenceCollector._reliability_summary_data()

    assert status.value == "available"
    assert data["incidents"] == [
        {
            "timestamp": "2026-10-21T12:00:00Z",
            "type": "Application Error",
            "application": "example.exe",
            "event_id": 1000,
        }
    ]
    assert "message" not in str(data)


def test_reliability_summary_marks_truncated_records_partial(monkeypatch) -> None:
    incident = {
        "timestamp": "2026-10-21T12:00:00Z",
        "type": "Application Hang",
        "application": "example.exe",
        "event_id": 1002,
        "truncated": True,
    }
    monkeypatch.setattr(windows.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        windows.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=json.dumps(incident),
            stderr="",
        ),
    )

    data, status = WindowsEvidenceCollector._reliability_summary_data()

    assert status.value == "partial"
    assert data["truncated"] is True


def test_reliability_summary_is_unavailable_off_windows(monkeypatch) -> None:
    monkeypatch.setattr(windows.platform, "system", lambda: "Linux")

    data, status = WindowsEvidenceCollector._reliability_summary_data()

    assert status.value == "unavailable"
    assert data["incidents"] == []


def test_network_configuration_returns_ip_addresses_and_default_gateway(monkeypatch) -> None:
    monkeypatch.setattr(windows.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        windows.psutil,
        "net_if_addrs",
        lambda: {
            "Ethernet": [
                SimpleNamespace(family=windows.socket.AF_INET, address="192.0.2.10"),
                SimpleNamespace(family=windows.socket.AF_INET6, address="fe80::1%12"),
                SimpleNamespace(family=999, address="00-11-22-33-44-55"),
            ]
        },
    )
    monkeypatch.setattr(
        windows.psutil,
        "net_if_stats",
        lambda: {"Ethernet": SimpleNamespace(isup=True)},
    )
    monkeypatch.setattr(
        windows.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="192.0.2.1\n", stderr=""),
    )

    data, status = WindowsEvidenceCollector._network_configuration_data()

    assert status.value == "available"
    assert data["default_gateway"] == "192.0.2.1"
    assert data["adapters"] == [
        {"name": "Ethernet", "status": "up", "addresses": ["192.0.2.10", "fe80::1"]}
    ]
    assert "00-11-22-33-44-55" not in str(data)


def test_gateway_reachability_reports_fixed_gateway_probe(monkeypatch) -> None:
    monkeypatch.setattr(windows.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        windows.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=json.dumps({
                "gateway": "192.0.2.1",
                "reachable": True,
                "latency_ms": 2,
                "error_category": None,
            }),
            stderr="",
        ),
    )

    data, status = WindowsEvidenceCollector._gateway_reachability_data()

    assert status.value == "available"
    assert data == {
        "gateway": "192.0.2.1",
        "reachable": True,
        "latency_ms": 2,
        "error_category": None,
    }


def test_gateway_reachability_reports_missing_route_without_probe(monkeypatch) -> None:
    monkeypatch.setattr(windows.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        windows.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=json.dumps({
                "gateway": None,
                "reachable": False,
                "latency_ms": None,
                "error_category": "no_default_gateway",
            }),
            stderr="",
        ),
    )

    data, status = WindowsEvidenceCollector._gateway_reachability_data()

    assert status.value == "available"
    assert data["reachable"] is False
    assert data["error_category"] == "no_default_gateway"


def test_adapter_status_marks_missing_stats_partial(monkeypatch) -> None:
    monkeypatch.setattr(
        windows.psutil,
        "net_if_addrs",
        lambda: {"Unreported adapter": []},
    )
    monkeypatch.setattr(windows.psutil, "net_if_stats", lambda: {})

    data, status = WindowsEvidenceCollector._adapter_status_data()

    assert status.value == "partial"
    assert data["adapters"] == [
        {"name": "Unreported adapter", "status": "unknown", "addresses": []}
    ]
    assert data["unavailable_adapter_count"] == 1


def test_dns_collection_is_unavailable_without_configured_hostname(monkeypatch) -> None:
    monkeypatch.delenv("WINDOWS_DIAGNOSTIC_DNS_HOSTNAME", raising=False)
    monkeypatch.setattr(
        windows.socket,
        "getaddrinfo",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("must not resolve an unconfigured host")),
    )

    data, status = WindowsEvidenceCollector._dns_resolution_data()

    assert status.value == "unavailable"
    assert data["error_category"] == "no_permitted_hostname_configured"


def test_dns_collection_resolves_only_configured_hostname(monkeypatch) -> None:
    monkeypatch.setenv("WINDOWS_DIAGNOSTIC_DNS_HOSTNAME", "diagnostic.example")
    monkeypatch.setattr(
        windows.socket,
        "getaddrinfo",
        lambda hostname, port, type: [
            (windows.socket.AF_INET, type, 6, "", ("192.0.2.10", port)),
            (windows.socket.AF_INET6, type, 6, "", ("2001:db8::10", port, 0, 0)),
        ],
    )

    data, status = WindowsEvidenceCollector._dns_resolution_data()

    assert status.value == "available"
    assert data["hostname"] == "diagnostic.example"
    assert data["success"] is True
    assert data["resolved_addresses"] == ["192.0.2.10", "2001:db8::10"]


def test_dns_collection_rejects_invalid_host_without_lookup(monkeypatch) -> None:
    monkeypatch.setenv("WINDOWS_DIAGNOSTIC_DNS_HOSTNAME", "example.com;bad")
    monkeypatch.setattr(
        windows.socket,
        "getaddrinfo",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("invalid host must not be resolved")),
    )

    data, status = WindowsEvidenceCollector._dns_resolution_data()

    assert status.value == "unavailable"
    assert data["error_category"] == "invalid_configured_hostname"


def test_connectivity_probe_is_unavailable_without_permitted_endpoint(monkeypatch) -> None:
    monkeypatch.delenv("WINDOWS_DIAGNOSTIC_CONNECTIVITY_ENDPOINT_ID", raising=False)
    monkeypatch.delenv("WINDOWS_DIAGNOSTIC_CONNECTIVITY_HOST", raising=False)
    monkeypatch.delenv("WINDOWS_DIAGNOSTIC_CONNECTIVITY_PORT", raising=False)
    monkeypatch.setattr(
        windows.socket,
        "create_connection",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("must not connect without configuration")),
    )

    data, status = WindowsEvidenceCollector._network_connectivity_data()

    assert status.value == "unavailable"
    assert data["error_category"] == "no_permitted_endpoint_configured"


def test_connectivity_probe_uses_only_configured_target(monkeypatch) -> None:
    class FakeConnection:
        closed = False

        def close(self):
            self.closed = True

    connection = FakeConnection()
    calls = []
    monkeypatch.setenv("WINDOWS_DIAGNOSTIC_CONNECTIVITY_ENDPOINT_ID", "corp-health")
    monkeypatch.setenv("WINDOWS_DIAGNOSTIC_CONNECTIVITY_HOST", "health.example")
    monkeypatch.setenv("WINDOWS_DIAGNOSTIC_CONNECTIVITY_PORT", "443")
    monkeypatch.setattr(
        windows.socket,
        "create_connection",
        lambda address, timeout: calls.append((address, timeout)) or connection,
    )
    monotonic_values = iter([1.0, 1.025])
    monkeypatch.setattr(windows.time, "monotonic", lambda: next(monotonic_values))

    data, status = WindowsEvidenceCollector._network_connectivity_data()

    assert status.value == "available"
    assert calls == [(('health.example', 443), 3)]
    assert connection.closed is True
    assert data == {
        "endpoint_id": "corp-health",
        "reachable": True,
        "latency_ms": 25.0,
        "error_category": None,
    }


def test_connectivity_probe_reports_timeout_without_exception_text(monkeypatch) -> None:
    monkeypatch.setenv("WINDOWS_DIAGNOSTIC_CONNECTIVITY_ENDPOINT_ID", "corp-health")
    monkeypatch.setenv("WINDOWS_DIAGNOSTIC_CONNECTIVITY_HOST", "health.example")
    monkeypatch.setenv("WINDOWS_DIAGNOSTIC_CONNECTIVITY_PORT", "443")
    monkeypatch.setattr(
        windows.socket,
        "create_connection",
        lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError("private detail")),
    )

    data, status = WindowsEvidenceCollector._network_connectivity_data()

    assert status.value == "available"
    assert data["reachable"] is False
    assert data["error_category"] == "timeout"
    assert "private detail" not in str(data)


def test_collector_marks_unavailable_volume_as_partial(monkeypatch) -> None:
    patch_system_metrics(monkeypatch)
    monkeypatch.setattr(
        windows.psutil,
        "disk_usage",
        lambda path: (_ for _ in ()).throw(OSError()) if path == "D:\\" else SimpleNamespace(total=1000, free=250),
    )

    storage = WindowsEvidenceCollector().collect(
        "collector-test", storage_paths=["C:\\", "D:\\"]
    )[2]

    assert storage.status.value == "partial"
    assert storage.data["unavailable_volume_count"] == 1
    assert len(storage.data["volumes"]) == 1


def test_collector_evidence_flows_into_diagnostic_orchestrator(monkeypatch) -> None:
    patch_system_metrics(monkeypatch)

    result = DiagnosticOrchestrator(ai_agent=object()).run(
        {"session_id": "collector-test", "complaint": "My laptop is slow."},
        WindowsEvidenceCollector().collect("collector-test", storage_paths=["C:\\"]),
        use_ai=False,
    )

    assert result.status.value == "analysis_complete"
    assert result.ranked_root_causes[0].cause_id == "performance.cpu_saturation"


def test_orchestrator_can_collect_from_its_generated_plan(monkeypatch) -> None:
    patch_system_metrics(monkeypatch)
    collector = WindowsEvidenceCollector()
    orchestrator = DiagnosticOrchestrator(
        ai_agent=object(), evidence_collector=collector
    )

    result = orchestrator.run(
        {"session_id": "collector-test", "complaint": "My laptop is slow."},
        use_ai=False,
    )

    assert result.status.value == "analysis_complete"
    assert result.ranked_root_causes[0].cause_id == "performance.cpu_saturation"
    assert any(item.startswith("performance.cpu: available") for item in result.evidence_summary)
    assert any(item.startswith("performance.memory: available") for item in result.evidence_summary)
    assert any("storage.disk_activity: available" in item for item in result.evidence_summary)
    process_summary = next(
        item for item in result.evidence_summary
        if item.startswith("performance.process_summary: available")
    )
    assert "test-process.exe" in process_summary
    cpu_cause = next(
        cause for cause in result.ranked_root_causes
        if cause.cause_id == "performance.cpu_saturation"
    )
    assert "test-process.exe" in cpu_cause.explanation
    assert "not proof of causation" in cpu_cause.explanation


def test_process_memory_context_is_added_to_memory_pressure_finding(monkeypatch) -> None:
    patch_system_metrics(monkeypatch)
    monkeypatch.setattr(
        windows.psutil,
        "virtual_memory",
        lambda: SimpleNamespace(total=16_000, available=800, percent=95.0),
    )
    result = DiagnosticOrchestrator(
        ai_agent=object(), evidence_collector=WindowsEvidenceCollector()
    ).run(
        {"session_id": "collector-test", "complaint": "My laptop is slow."},
        use_ai=False,
    )

    memory_cause = next(
        cause for cause in result.ranked_root_causes
        if cause.cause_id == "performance.memory_pressure"
    )
    assert "largest sampled memory consumer was 'test-process.exe'" in memory_cause.explanation
    assert "not proof of causation" in memory_cause.explanation


def test_orchestrator_requests_clarification_before_collecting() -> None:
    class UnexpectedCollector:
        def collect_for_plan(self, plan):
            raise AssertionError("collector should not run for an unclear complaint")

    result = DiagnosticOrchestrator(
        ai_agent=object(), evidence_collector=UnexpectedCollector()
    ).run({"session_id": "collector-test", "complaint": "Help me with my computer"}, use_ai=False)

    assert result.status.value == "needs_clarification"


def test_collector_dispatches_supported_plan_types_and_marks_unsupported(monkeypatch) -> None:
    patch_system_metrics(monkeypatch)
    plan = DiagnosticPlan(
        session_id="collector-test",
        category=Category.SYSTEM_PERFORMANCE,
        evidence_requests=[
            EvidenceRequest(
                evidence_id="evidence.performance.cpu",
                evidence_type=EvidenceType.CPU_METRICS,
                purpose="Measure CPU utilization.",
                priority=Priority.HIGH,
                required=True,
                privacy_notes="Aggregate metrics only.",
            ),
            EvidenceRequest(
                evidence_id="evidence.driver.details",
                evidence_type=EvidenceType.DRIVER_DETAILS,
                purpose="Check driver metadata.",
                priority=Priority.MEDIUM,
                required=False,
                privacy_notes="Omit command lines and paths.",
            ),
        ],
        reasoning_summary="Test plan.",
    )

    records = WindowsEvidenceCollector().collect_for_plan(plan)

    assert [record.evidence_id for record in records] == [
        "evidence.performance.cpu",
        "evidence.driver.details",
    ]
    assert records[0].status.value == "available"
    assert records[1].status.value == "unavailable"
    assert records[1].data["reason"] == "No collector is registered for this evidence type."


def test_collector_dispatches_reliability_summary_request(monkeypatch) -> None:
    monkeypatch.setattr(windows.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        windows.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=json.dumps({
                "timestamp": "2026-10-21T12:00:00Z",
                "type": "Application Hang",
                "application": "example.exe",
                "event_id": 1002,
                "truncated": False,
            }),
            stderr="",
        ),
    )
    plan = DiagnosticPlan(
        session_id="reliability-test",
        category=Category.WINDOWS_HEALTH,
        evidence_requests=[
            EvidenceRequest(
                evidence_id="evidence.windows.reliability",
                evidence_type=EvidenceType.RELIABILITY_SUMMARY,
                purpose="Summarize recent reliability incidents.",
                priority=Priority.HIGH,
                required=True,
                privacy_notes="Exclude raw messages.",
            )
        ],
        reasoning_summary="Reliability collector test.",
    )

    records = WindowsEvidenceCollector().collect_for_plan(plan)

    assert len(records) == 1
    assert records[0].status.value == "available"
    assert records[0].data["incidents"][0]["type"] == "Application Hang"


def test_collector_dispatches_storage_and_system_event_requests(monkeypatch) -> None:
    events = [
        {"timestamp": "2026-10-21T12:00:00Z", "provider": "Disk", "event_id": 7, "level": "Error"},
        {"timestamp": "2026-10-21T12:01:00Z", "provider": "Example", "event_id": 8, "level": "Warning"},
    ]
    monkeypatch.setattr(windows.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        windows.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=json.dumps(events),
            stderr="",
        ),
    )
    plan = DiagnosticPlan(
        session_id="event-test",
        category=Category.STORAGE,
        evidence_requests=[
            EvidenceRequest(
                evidence_id="evidence.storage.errors",
                evidence_type=EvidenceType.STORAGE_ERRORS,
                purpose="Check storage error metadata.",
                priority=Priority.HIGH,
                required=True,
                privacy_notes="Do not collect raw event messages.",
            ),
            EvidenceRequest(
                evidence_id="evidence.windows.system_events",
                evidence_type=EvidenceType.SYSTEM_EVENTS,
                purpose="Summarize recent system events.",
                priority=Priority.MEDIUM,
                required=False,
                privacy_notes="Do not collect raw event messages.",
            ),
        ],
        reasoning_summary="Event collection test.",
    )

    records = WindowsEvidenceCollector().collect_for_plan(plan)

    assert [record.status.value for record in records] == ["available", "available"]
    assert [event["provider"] for event in records[0].data["events"]] == ["Disk"]
    assert [event["provider"] for event in records[1].data["events"]] == ["Disk", "Example"]


def test_collector_dispatches_network_configuration_and_adapter_requests(monkeypatch) -> None:
    monkeypatch.setattr(windows.platform, "system", lambda: "Windows")
    monkeypatch.setenv("WINDOWS_DIAGNOSTIC_DNS_HOSTNAME", "diagnostic.example")
    monkeypatch.setenv("WINDOWS_DIAGNOSTIC_CONNECTIVITY_ENDPOINT_ID", "corp-health")
    monkeypatch.setenv("WINDOWS_DIAGNOSTIC_CONNECTIVITY_HOST", "health.example")
    monkeypatch.setenv("WINDOWS_DIAGNOSTIC_CONNECTIVITY_PORT", "443")
    monkeypatch.setattr(windows.psutil, "net_if_addrs", lambda: {"Ethernet": []})
    monkeypatch.setattr(
        windows.psutil,
        "net_if_stats",
        lambda: {"Ethernet": SimpleNamespace(isup=True)},
    )
    command_outputs = iter([
        "192.0.2.1",
        json.dumps({
            "gateway": "192.0.2.1",
            "reachable": True,
            "latency_ms": 2,
            "error_category": None,
        }),
    ])
    monkeypatch.setattr(
        windows.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=next(command_outputs), stderr=""),
    )
    monkeypatch.setattr(
        windows.socket,
        "getaddrinfo",
        lambda hostname, port, type: [(windows.socket.AF_INET, type, 6, "", ("192.0.2.10", port))],
    )
    monkeypatch.setattr(
        windows.socket,
        "create_connection",
        lambda address, timeout: SimpleNamespace(close=lambda: None),
    )
    monotonic_values = iter([1.0, 1.01])
    monkeypatch.setattr(windows.time, "monotonic", lambda: next(monotonic_values))
    plan = DiagnosticPlan(
        session_id="network-test",
        category=Category.NETWORK,
        evidence_requests=[
            EvidenceRequest(
                evidence_id="evidence.network.configuration",
                evidence_type=EvidenceType.NETWORK_CONFIGURATION,
                purpose="Review IP configuration.",
                priority=Priority.HIGH,
                required=True,
                privacy_notes="IP addresses are sensitive.",
            ),
            EvidenceRequest(
                evidence_id="evidence.network.adapter_status",
                evidence_type=EvidenceType.ADAPTER_STATUS,
                purpose="Review adapter state.",
                priority=Priority.MEDIUM,
                required=False,
                privacy_notes="Only relevant adapter state.",
            ),
            EvidenceRequest(
                evidence_id="evidence.network.gateway_reachability",
                evidence_type=EvidenceType.GATEWAY_REACHABILITY,
                purpose="Check the default gateway.",
                priority=Priority.MEDIUM,
                required=False,
                privacy_notes="Only the configured gateway.",
            ),
            EvidenceRequest(
                evidence_id="evidence.network.dns_resolution",
                evidence_type=EvidenceType.DNS_RESOLUTION,
                purpose="Resolve the configured permitted hostname.",
                priority=Priority.MEDIUM,
                required=False,
                privacy_notes="Only resolve the configured hostname.",
            ),
            EvidenceRequest(
                evidence_id="evidence.network.connectivity",
                evidence_type=EvidenceType.NETWORK_CONNECTIVITY,
                purpose="Connect to the configured permitted endpoint.",
                priority=Priority.MEDIUM,
                required=False,
                privacy_notes="Only connect to the configured endpoint.",
            ),
        ],
        reasoning_summary="Network collector test.",
    )

    records = WindowsEvidenceCollector().collect_for_plan(plan)

    assert [record.status.value for record in records] == ["available", "available", "available", "available", "available"]
    assert records[0].data["default_gateway"] == "192.0.2.1"
    assert records[1].data["adapters"][0]["status"] == "up"
    assert records[2].data["reachable"] is True
    assert records[3].data["hostname"] == "diagnostic.example"
    assert records[4].data["endpoint_id"] == "corp-health"
    assert records[4].data["reachable"] is True


def test_collector_requires_session_id_in_plan() -> None:
    plan = DiagnosticPlan(
        session_id=None,
        category=Category.SYSTEM_PERFORMANCE,
        evidence_requests=[],
        reasoning_summary="Test plan.",
    )

    with pytest.raises(ValueError, match="must include a session_id"):
        WindowsEvidenceCollector().collect_for_plan(plan)


@pytest.mark.parametrize("interval", [0, -1, 5.1, True])
def test_collector_rejects_unbounded_cpu_sample_interval(interval) -> None:
    with pytest.raises(ValueError, match="between 0.05 and 5"):
        WindowsEvidenceCollector(cpu_sample_seconds=interval)


@pytest.mark.parametrize("interval", [0, -1, 5.1, True])
def test_collector_rejects_unbounded_disk_sample_interval(interval) -> None:
    with pytest.raises(ValueError, match="between 0.1 and 5"):
        WindowsEvidenceCollector(disk_sample_seconds=interval)


@pytest.mark.parametrize("interval", [0, -1, 5.1, True])
def test_collector_rejects_unbounded_process_sample_interval(interval) -> None:
    with pytest.raises(ValueError, match="between 0.05 and 5"):
        WindowsEvidenceCollector(process_sample_seconds=interval)


@pytest.mark.parametrize("count", [0, -1, 21, True])
def test_collector_rejects_unbounded_process_count(count) -> None:
    with pytest.raises(ValueError, match="between 1 and 20"):
        WindowsEvidenceCollector(max_processes=count)