"""Append-only JSONL audit log. Stores decisions and outcomes, not raw evidence contents."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditLog:
    def __init__(self, directory: str | Path | None) -> None:
        self.directory = Path(directory) if directory else None
        self._lock = threading.Lock()
        if self.directory:
            self.directory.mkdir(parents=True, exist_ok=True)

    def write(self, session_id: str, pipeline_id: str, stage: str, message: str, data: dict[str, Any] | None = None) -> None:
        if self.directory is None:
            return
        now = datetime.now(timezone.utc)
        line = json.dumps(
            {"at": now.isoformat(), "session_id": session_id, "pipeline": pipeline_id,
             "stage": stage, "message": message, "data": data or {}},
            ensure_ascii=True, default=str,
        )
        path = self.directory / f"agent-{now:%Y%m%d}.jsonl"
        with self._lock, path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
