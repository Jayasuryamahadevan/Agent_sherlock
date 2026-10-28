import json
import os
import subprocess
from types import SimpleNamespace

import pytest

from diagnostic_intelligence.collectors import windows
from diagnostic_intelligence.collectors.windows import MANAGED_SERVICES, WindowsEvidenceCollector
from diagnostic_intelligence.remediation import backends
from diagnostic_intelligence.remediation.backends import WindowsActionBackend
from diagnostic_intelligence.remediation.catalogue import MANAGED_SERVICES as CATALOGUE_SERVICES, ProcessParams, ServiceParams, TempCleanupParams


def fake_powershell(monkeypatch, payload, captured=None, returncode=0):
    def fake_run(argv, **kwargs):
        if captured is not None:
            captured.update(argv=argv, env=kwargs.get("env", {}))
        return SimpleNamespace(returncode=returncode, stdout=json.dumps(payload), stderr="")
    monkeypatch.setattr(windows.subprocess, "run", fake_run)
    monkeypatch.setattr(windows.platform, "system", lambda: "Windows")


def test_service_status_filters_to_managed_services_only(monkeypatch):
    captured = {}
    fake_powershell(monkeypatch, [
        {"name": "Spooler", "state": "Stopped", "start_mode": "Auto", "exit_code": 1},
        {"name": "SomeOtherService", "state": "Running", "start_mode": "Auto", "exit_code": 0},
    ], captured)
    data, status = WindowsEvidenceCollector._service_status_data()
    assert [s["name"] for s in data["services"]] == ["Spooler"]
    assert status.value == "available"
    assert captured["env"]["DIAG_SERVICE_NAMES"] == ",".join(MANAGED_SERVICES)
    assert "Spooler" not in captured["argv"][-1]  # names travel via environment, not script text


def test_service_status_unavailable_off_windows(monkeypatch):
    monkeypatch.setattr(windows.platform, "system", lambda: "Linux")
    _, status = WindowsEvidenceCollector._service_status_data()
    assert status.value == "unavailable"


def test_device_status_reports_only_devices_with_problem_codes(monkeypatch):
    fake_powershell(monkeypatch, [
        {"device_id": "PCI\\VEN_1", "name": "Wi-Fi adapter", "device_class": "Net", "status": "Error", "problem_code": 43},
        {"device_id": "PCI\\VEN_2", "name": "Fine device", "device_class": "Net", "status": "OK", "problem_code": 0},
    ])
    data, _ = WindowsEvidenceCollector._device_status_data()
    assert [d["problem_code"] for d in data["devices"]] == [43]
    assert data["status"] == "problem"


def test_cim_failure_becomes_error_evidence_not_exception(monkeypatch):
    fake_powershell(monkeypatch, [], returncode=1)
    record = WindowsEvidenceCollector()._capture("s", "e.svc", windows.EvidenceType.SERVICE_STATUS,
                                                 WindowsEvidenceCollector._service_status_data)
    assert record.status.value == "error"


def test_service_lists_stay_in_sync_between_collector_and_catalogue():
    assert set(CATALOGUE_SERVICES) <= set(MANAGED_SERVICES)


# ---------------------------------------------------------------- real backend
def test_changes_are_disabled_by_default(monkeypatch):
    monkeypatch.delenv("DIAG_ALLOW_SYSTEM_CHANGES", raising=False)
    ok, message = WindowsActionBackend().run("flush_dns_cache", SimpleNamespace())
    assert ok is False and "disabled" in message


def test_service_name_is_passed_via_environment_not_script(monkeypatch):
    captured = {}
    monkeypatch.setattr(backends.platform, "system", lambda: "Windows")
    monkeypatch.setattr(backends.subprocess, "run", lambda argv, **kw: (captured.update(argv=argv, env=kw["env"]) or
                                                                         SimpleNamespace(returncode=0, stdout="", stderr="")))
    ok, _ = WindowsActionBackend(allow_changes=True).run("restart_service", ServiceParams(service_name="Spooler"))
    assert ok
    assert "Spooler" not in captured["argv"][-1] and captured["env"]["DIAG_SERVICE_NAME"] == "Spooler"


def test_service_params_reject_injection_and_unlisted_services():
    for bad in ("Spooler; calc", "RemoteRegistry", "spooler", ""):
        with pytest.raises(Exception):
            ServiceParams(service_name=bad)


def test_process_params_require_exe_names_without_paths():
    ProcessParams(process_name="chrome.exe")
    for bad in ("..\\..\\x.exe", "chrome", "a;b.exe", "C:\\Windows\\x.exe"):
        with pytest.raises(Exception):
            ProcessParams(process_name=bad)


def test_clear_temp_only_removes_old_files_inside_temp(tmp_path, monkeypatch):
    temp = tmp_path / "Temp"
    temp.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("keep")
    old, new = temp / "old.tmp", temp / "new.tmp"
    old.write_text("x" * 100)
    new.write_text("y")
    ten_days_ago = os.path.getmtime(old) - 10 * 86400
    os.utime(old, (ten_days_ago, ten_days_ago))
    link = temp / "link"
    try:
        link.symlink_to(tmp_path)
    except OSError:
        pass
    monkeypatch.setattr(backends.tempfile, "gettempdir", lambda: str(temp))
    ok, message = WindowsActionBackend(allow_changes=True).run("clear_temp_files", TempCleanupParams(max_age_days=7))
    assert ok and "deleted 1 file" in message
    assert not old.exists() and new.exists() and outside.exists()


def test_terminate_refuses_protected_and_own_process(monkeypatch):
    backend = WindowsActionBackend(allow_changes=True)
    monkeypatch.setattr(backends.platform, "system", lambda: "Windows")
    ok, message = backend.run("terminate_process", SimpleNamespace(process_name="lsass.exe"))
    assert ok is False and "protected" in message.lower()
