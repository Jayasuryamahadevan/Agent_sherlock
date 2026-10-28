"""Minimal Ollama client for the optional AI summary on the legacy /api/diagnostics endpoint.

AI diagnosis, planning and action selection live in ``diagnostic_intelligence.agent``.
"""

from __future__ import annotations

import json
from urllib import error, request


class OllamaAgent:
    """Thin HTTP client for a local Ollama instance."""

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "llama3.2",
        timeout: int = 20,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def _call_model(self, prompt: str) -> str | None:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.1},
        }
        endpoint = f"{self.base_url}/api/generate"
        data = json.dumps(payload).encode("utf-8")
        req = request.Request(endpoint, data=data, headers={"Content-Type": "application/json"})
        try:
            with request.urlopen(req, timeout=self.timeout) as response:
                body = response.read().decode("utf-8")
        except (error.URLError, TimeoutError, OSError, ValueError):
            return None

        try:
            result = json.loads(body)
        except (TypeError, json.JSONDecodeError):
            return None

        response_text = result.get("response")
        if isinstance(response_text, str):
            return response_text.strip()
        return None

    def generate_diagnostic_summary(
        self,
        *,
        complaint: str,
        category: str,
        evidence_summary: list[str],
        root_causes: list[str],
    ) -> str | None:
        """Generate a concise, safety-constrained summary from a local Ollama model."""
        prompt = (
            "You are a safety-constrained diagnostic assistant. Use only the structured evidence below "
            "and do not claim a fix or resolution. Summarize the likely issue in 2 to 3 sentences. "
            "Keep it factual and explain uncertainty carefully.\n\n"
            f"Complaint: {complaint}\n"
            f"Category: {category}\n"
            f"Evidence: {json.dumps(evidence_summary, ensure_ascii=True)}\n"
            f"Root causes: {json.dumps(root_causes, ensure_ascii=True)}"
        )
        response = self._call_model(prompt)
        return response or None
