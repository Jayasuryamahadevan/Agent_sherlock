"""Read Windows metrics and ask Claude Code (through Ollama) for an analysis."""
import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

MODEL = "nemotron-3-nano:30b-cloud"
COLLECT = r'''
$ErrorActionPreference = 'Stop'
$result = [ordered]@{}
try { $os = Get-CimInstance Win32_OperatingSystem; $result.memory = @{ total_mb = [math]::Round($os.TotalVisibleMemorySize / 1024); free_mb = [math]::Round($os.FreePhysicalMemory / 1024) } } catch { $result.memory = @{ unavailable = 'Could not read memory' } }
try { $result.cpu = @(Get-CimInstance Win32_Processor | ForEach-Object { @{ load_percent = $_.LoadPercentage } }) } catch { $result.cpu = @{ unavailable = 'Could not read CPU' } }
try { $result.disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { @{ drive = $_.DeviceID; size_gb = [math]::Round($_.Size / 1GB, 1); free_gb = [math]::Round($_.FreeSpace / 1GB, 1) } }) } catch { $result.disks = @{ unavailable = 'Could not read disks' } }
try { $result.system_events = @(Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 20 -ErrorAction Stop | ForEach-Object { @{ time = $_.TimeCreated.ToString('o'); provider = $_.ProviderName; id = $_.Id; level = $_.LevelDisplayName } }) } catch { $result.system_events = @{ unavailable = 'No events found or event log unavailable' } }
$result | ConvertTo-Json -Depth 5 -Compress
'''


def main():
    parser = argparse.ArgumentParser(description="Read-only Windows diagnostic analysis")
    parser.add_argument("complaint", help="Describe the problem; this text is sent to Ollama Cloud")
    parser.add_argument("--model", default=os.environ.get("DIAG_MODEL", MODEL))
    args = parser.parse_args()
    if not args.complaint.strip():
        parser.error("complaint must not be empty")
    if platform.system() != "Windows":
        sys.exit("This collector requires Windows. Run it on the Windows PC you want to diagnose.")
    claude = shutil.which("claude") or shutil.which("claude.cmd")
    if not claude:
        sys.exit("Claude Code was not found. Install it and restart the terminal.")
    try:
        result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", COLLECT], capture_output=True, text=True, timeout=30, check=True)
        evidence = json.loads(result.stdout.lstrip('\ufeff'))
    except (subprocess.SubprocessError, OSError, ValueError) as exc:
        sys.exit(f"Could not collect Windows evidence: {exc}")
    prompt = json.dumps({"complaint": args.complaint[:4000], "evidence": evidence}, ensure_ascii=True)
    env = os.environ.copy()
    env["ANTHROPIC_BASE_URL"] = "http://127.0.0.1:11434"
    env["ANTHROPIC_AUTH_TOKEN"] = "ollama"
    env.pop("ANTHROPIC_API_KEY", None)
    system = (Path(__file__).with_name("system_prompt.txt")).read_text(encoding="utf-8")
    try:
        completed = subprocess.run([claude, "--print", "--tools", "", "--strict-mcp-config", "--setting-sources", "", "--no-session-persistence", "--model", args.model, "--system-prompt", system], input=prompt, text=True, env=env, timeout=180)
    except (subprocess.TimeoutExpired, OSError) as exc:
        sys.exit(f"Claude Code could not complete the request: {exc}")
    if completed.returncode:
        sys.exit(f"Analysis failed (Claude Code exit code {completed.returncode}). Check Ollama is running, signed in, and the cloud model is available.")


if __name__ == "__main__":
    main()
