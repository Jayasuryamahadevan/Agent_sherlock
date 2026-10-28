"""Deterministic stand-ins for a language model, used to test the AI reasoning path."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from diagnostic_intelligence.agent.llm import LLMUnavailable


def parse_user(user: str) -> dict[str, Any]:
    payload, _ = json.JSONDecoder().raw_decode(user)
    return payload


def is_triage(system: str) -> bool:
    return "triage step" in system


class ScriptedLLM:
    """Returns queued responses in order. Items may be dicts, raw strings, exceptions or callables."""

    model = "scripted-test-model"

    def __init__(self, responses: list[Any]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str]] = []

    def complete_json(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        if not self.responses:
            raise LLMUnavailable("script exhausted")
        item = self.responses.pop(0)
        if callable(item):
            item = item(system, user)
        if isinstance(item, Exception):
            raise item
        return item if isinstance(item, str) else json.dumps(item)


class UnreachableLLM:
    model = "unreachable-model"

    def __init__(self) -> None:
        self.calls = 0

    def complete_json(self, system: str, user: str) -> str:
        self.calls += 1
        raise LLMUnavailable("Could not reach Ollama at http://127.0.0.1:11434 (URLError).")


def _find(evidence: list[dict], evidence_type: str) -> dict | None:
    for record in reversed(evidence):
        if record["evidence_type"] == evidence_type and record["status"] in ("available", "partial"):
            return record
    return None


class EvidenceDrivenLLM:
    """Behaves like a competent model: its conclusions depend only on the evidence it is shown."""

    model = "evidence-driven-fake"

    def __init__(self, triage_category: str | None = None) -> None:
        self.triage_category = triage_category
        self.calls = 0

    def complete_json(self, system: str, user: str) -> str:
        self.calls += 1
        payload = parse_user(user)
        if is_triage(system):
            return json.dumps(self._triage(payload["COMPLAINT"]))
        return json.dumps(self._assess(payload))

    def _triage(self, complaint: str) -> dict:
        text = complaint.casefold()
        if self.triage_category:
            category = self.triage_category
        elif any(w in text for w in ("internet", "wi-fi", "network", "dns", "website")):
            category = "network"
        elif any(w in text for w in ("drive", "disk", "space")):
            category = "storage"
        elif any(w in text for w in ("print",)):
            category = "windows_health"
        elif any(w in text for w in ("slow", "cpu", "memory", "freez")):
            category = "system_performance"
        else:
            return {"primary_category": "unknown", "secondary_categories": [], "evidence_types": [],
                    "needs_clarification": True, "clarification_question": "What happens, and when?",
                    "explanation": "No recognizable symptom."}
        types = {
            "network": ["network.configuration", "network.gateway_reachability", "network.dns_resolution", "network.adapter_status"],
            "storage": ["storage.capacity", "storage.disk_activity"],
            "system_performance": ["performance.cpu", "performance.memory", "performance.process_summary"],
            "windows_health": ["windows.service_status", "windows.system_events"],
        }[category]
        return {"primary_category": category, "secondary_categories": [], "evidence_types": types,
                "needs_clarification": False, "clarification_question": None,
                "explanation": f"The complaint describes a {category} symptom."}

    def _assess(self, p: dict) -> dict:
        evidence = p["EVIDENCE"]
        attempts = p["PREVIOUS_ATTEMPTS"]
        tried = {(a["action_id"], json.dumps(a["parameters"], sort_keys=True)) for a in attempts}
        if attempts and attempts[-1].get("verification") == "resolved":
            return self._out("Verification shows the fault is gone.", [], "conclude")

        def obs(record, field, value):
            return {"evidence_id": record["evidence_id"], "field": field, "value": value}

        def propose(hyp, action_id, params, why):
            if (action_id, json.dumps(params, sort_keys=True)) in tried:
                return self._out(hyp["title"] + " persists; no further safe action.", [hyp], "conclude")
            return self._out(hyp["title"], [hyp], "propose_action",
                             action={"action_id": action_id, "parameters": params,
                                     "addresses_cause_id": hyp["cause_id"], "rationale": why})

        config = _find(evidence, "network.configuration")
        dns = _find(evidence, "network.dns_resolution")
        gateway = _find(evidence, "network.gateway_reachability")
        adapters = _find(evidence, "network.adapter_status")
        if adapters:
            for i, a in enumerate(adapters["data"]["adapters"]):
                if a["status"] == "down" and "loopback" not in a["name"].casefold():
                    hyp = {"cause_id": "network.adapter_unavailable", "title": "Adapter down",
                           "explanation": "The adapter is down.", "confidence": "high",
                           "observations": [obs(adapters, f"adapters.{i}.status", "down")]}
                    return propose(hyp, "restart_network_adapter", {"adapter_name": a["name"]}, "Bring the adapter back.")
        if config:
            first = config["data"]["adapters"][0]
            if first["addresses"] and first["addresses"][0].startswith("169.254."):
                hyp = {"cause_id": "network.no_valid_address", "title": "Self-assigned IP address",
                       "explanation": "DHCP lease missing.", "confidence": "high",
                       "observations": [obs(config, "adapters.0.addresses.0", first["addresses"][0])]}
                return propose(hyp, "renew_dhcp_lease", {}, "Obtain a valid lease.")
        if dns and dns["data"].get("success") is False:
            hyp = {"cause_id": "network.dns_failure", "title": "DNS resolution failure",
                   "explanation": "Name lookups fail while the gateway responds.", "confidence": "medium",
                   "observations": [obs(dns, "success", False)] + ([obs(gateway, "reachable", True)] if gateway else [])}
            return propose(hyp, "flush_dns_cache", {}, "Clear a possibly stale cache first.")
        cpu = _find(evidence, "performance.cpu")
        procs = _find(evidence, "performance.process_summary")
        services = _find(evidence, "windows.service_status")
        if cpu and cpu["data"]["utilization_percent"] >= 85 and procs:
            top_i, top = max(enumerate(procs["data"]["processes"]), key=lambda x: x[1]["cpu_percent"])
            hyp = {"cause_id": "performance.cpu_saturation", "title": f"{top['name']} saturates the CPU",
                   "explanation": "One process dominates CPU.", "confidence": "high",
                   "observations": [obs(cpu, "utilization_percent", cpu["data"]["utilization_percent"]),
                                    obs(procs, f"processes.{top_i}.name", top["name"])]}
            if top["name"].casefold() == "searchindexer.exe":
                if not services:
                    return self._out("Check the Windows Search service.", [hyp], "collect_more",
                                     requests=["windows.service_status"])
                return propose(hyp, "restart_service", {"service_name": "WSearch"}, "Restart the stuck indexer.")
            return propose(hyp, "terminate_process", {"process_name": top["name"]}, "Close the runaway app.")
        memory = _find(evidence, "performance.memory")
        if memory and memory["data"]["used_percent"] >= 90 and procs:
            top_i, top = max(enumerate(procs["data"]["processes"]), key=lambda x: x[1]["memory_bytes"])
            hyp = {"cause_id": "performance.memory_pressure", "title": f"{top['name']} exhausts memory",
                   "explanation": "Memory nearly full; one process holds most of it.", "confidence": "high",
                   "observations": [obs(memory, "used_percent", memory["data"]["used_percent"]),
                                    obs(procs, f"processes.{top_i}.memory_bytes", top["memory_bytes"])]}
            return propose(hyp, "terminate_process", {"process_name": top["name"]}, "Close the memory-heavy app.")
        storage = _find(evidence, "storage.capacity")
        if storage and storage["data"]["volumes"][0]["free_percent"] < 10:
            hyp = {"cause_id": "storage.low_free_space", "title": "System drive almost full",
                   "explanation": "Very little free space.", "confidence": "high",
                   "observations": [obs(storage, "volumes.0.free_percent", storage["data"]["volumes"][0]["free_percent"])]}
            return propose(hyp, "clear_temp_files", {"max_age_days": 7}, "Remove old temp files.")
        return self._out("Nothing in the evidence explains the complaint.", [], "conclude")

    @staticmethod
    def _out(summary, hypotheses, next_step, action=None, requests=None):
        return {"summary": summary, "hypotheses": hypotheses, "alternatives_ruled_out": [],
                "uncertainty": "Based only on the collected evidence.", "next_step": next_step,
                "evidence_requests": requests or [], "evidence_request_reason": "follow-up" if requests else None,
                "action": action, "question": None}


def assess_response(**overrides) -> Callable[[str, str], dict]:
    """Build a one-off assess response that cites real evidence ids from the prompt."""

    def build(system: str, user: str) -> dict:
        payload = parse_user(user)
        base = {"summary": "s", "hypotheses": [], "alternatives_ruled_out": [], "uncertainty": "u",
                "next_step": "conclude", "evidence_requests": [], "evidence_request_reason": None,
                "action": None, "question": None}
        for key, value in overrides.items():
            base[key] = value(payload) if callable(value) else value
        return base

    return build
