"""Concrete implementations of catalogued system changes.

Each action maps to a fixed implementation. Parameters were already validated by the action's
Pydantic model and re-checked by policy; they are passed to PowerShell through environment
variables (never interpolated into script text) so they cannot inject commands.
"""

from __future__ import annotations

import os
import platform
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Protocol

import psutil
from pydantic import BaseModel

from diagnostic_intelligence.remediation.catalogue import PROTECTED_PROCESSES


class ActionBackend(Protocol):
    name: str

    def is_elevated(self) -> bool: ...

    def run(self, action_id: str, params: BaseModel) -> tuple[bool, str]:
        """Return (command_succeeded, short_message). Success here is NOT problem resolution."""


def windows_is_elevated() -> bool:
    if platform.system() != "Windows":
        return hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


class WindowsActionBackend:
    """Executes catalogued actions on the local Windows machine.

    System changes are disabled unless ``allow_changes`` is True (CLI ``--allow-changes`` or
    environment ``DIAG_ALLOW_SYSTEM_CHANGES=1``). When disabled, actions report failure honestly.
    """

    name = "windows"

    def __init__(self, allow_changes: bool | None = None, timeout_seconds: int = 60) -> None:
        if allow_changes is None:
            allow_changes = os.environ.get("DIAG_ALLOW_SYSTEM_CHANGES", "").strip() == "1"
        self.allow_changes = allow_changes
        self.timeout_seconds = timeout_seconds

    def is_elevated(self) -> bool:
        return windows_is_elevated()

    def run(self, action_id: str, params: BaseModel) -> tuple[bool, str]:
        if not self.allow_changes:
            return False, "System changes are disabled in this configuration (set DIAG_ALLOW_SYSTEM_CHANGES=1 or use --allow-changes)."
        if platform.system() != "Windows" and action_id != "clear_temp_files":
            return False, "This action is only implemented for Windows."
        handler = {
            "flush_dns_cache": self._flush_dns,
            "renew_dhcp_lease": self._renew_dhcp,
            "restart_network_adapter": self._restart_adapter,
            "restart_service": self._restart_service,
            "clear_temp_files": self._clear_temp,
            "terminate_process": self._terminate_process,
        }.get(action_id)
        if handler is None:
            return False, f"No implementation exists for '{action_id}'."
        try:
            return handler(params)
        except subprocess.TimeoutExpired:
            return False, "The operation timed out."
        except Exception as error:  # report, never crash the pipeline
            return False, f"The operation failed ({type(error).__name__})."

    def _process(self, argv: list[str], env_extra: dict[str, str] | None = None) -> tuple[bool, str]:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=self.timeout_seconds,
            check=False,
            env={**os.environ, **(env_extra or {})},
        )
        output = (result.stdout or result.stderr or "").strip().splitlines()
        tail = output[-1][:300] if output else ""
        return result.returncode == 0, f"exit code {result.returncode}" + (f": {tail}" if tail else "")

    def _powershell(self, script: str, env_extra: dict[str, str]) -> tuple[bool, str]:
        return self._process(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], env_extra)

    def _flush_dns(self, params: BaseModel) -> tuple[bool, str]:
        return self._process(["ipconfig", "/flushdns"])

    def _renew_dhcp(self, params: BaseModel) -> tuple[bool, str]:
        return self._process(["ipconfig", "/renew"])

    def _restart_adapter(self, params: BaseModel) -> tuple[bool, str]:
        return self._powershell(
            "Restart-NetAdapter -Name $env:DIAG_ADAPTER_NAME -Confirm:$false -ErrorAction Stop",
            {"DIAG_ADAPTER_NAME": params.adapter_name},
        )

    def _restart_service(self, params: BaseModel) -> tuple[bool, str]:
        return self._powershell(
            "Restart-Service -Name $env:DIAG_SERVICE_NAME -Force -ErrorAction Stop",
            {"DIAG_SERVICE_NAME": params.service_name},
        )

    def _clear_temp(self, params: BaseModel) -> tuple[bool, str]:
        root = Path(tempfile.gettempdir()).resolve()
        cutoff = time.time() - params.max_age_days * 86400
        deleted = skipped = 0
        freed = 0
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            current = Path(dirpath)
            dirnames[:] = [
                d for d in dirnames
                if not (current / d).is_symlink() and not getattr(os.path, "isjunction", lambda p: False)(current / d)
            ]
            for filename in filenames:
                path = current / filename
                try:
                    if path.is_symlink() or not path.resolve().is_relative_to(root):
                        skipped += 1
                        continue
                    stat = path.lstat()
                    if stat.st_mtime >= cutoff:
                        continue
                    path.unlink()
                    deleted += 1
                    freed += stat.st_size
                except OSError:
                    skipped += 1
                if deleted >= 200_000:
                    break
        return True, f"deleted {deleted} file(s), freed {freed / 1024 ** 2:.1f} MB, skipped {skipped} in-use/protected file(s)"

    def _terminate_process(self, params: BaseModel) -> tuple[bool, str]:
        target = params.process_name.casefold()
        if target in PROTECTED_PROCESSES:
            return False, "Refused: protected process."
        own = {os.getpid(), os.getppid()}
        victims = [
            proc for proc in psutil.process_iter(["name"])
            if str(proc.info.get("name") or "").casefold() == target and proc.pid not in own
        ]
        if not victims:
            return False, "No running process with that name was found."
        for proc in victims:
            try:
                proc.terminate()
            except psutil.Error:
                pass
        gone, alive = psutil.wait_procs(victims, timeout=5)
        return not alive, f"terminated {len(gone)} instance(s); {len(alive)} still running"
