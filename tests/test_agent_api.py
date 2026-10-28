from fastapi.testclient import TestClient

from diagnostic_intelligence.agent.runtime import RuntimeConfig
from diagnostic_intelligence.api import create_app
from tests.fakes import EvidenceDrivenLLM, UnreachableLLM


def client(llm=EvidenceDrivenLLM, scenario="dns_cache_stale", reasoning="ai"):
    from diagnostic_intelligence.agent.models import ReasoningMode
    config = RuntimeConfig(backend="simulated", scenario=scenario, reasoning=ReasoningMode(reasoning), audit_dir=None)
    return TestClient(create_app(agent_config=config, llm_factory=llm))


def test_config_lists_three_pipelines_and_scenarios():
    body = client().get("/api/agent/config").json()
    assert {p["pipeline_id"] for p in body["pipelines"]} == {"automatic_execution", "auto_resolution", "whitelist_approval"}
    assert body["backend"] == "simulated" and len(body["scenarios"]) >= 8


def test_p3_session_pauses_then_approval_endpoint_executes():
    c = client()
    started = c.post("/api/agent/sessions", json={"complaint": "Websites won't load", "pipeline": "whitelist_approval"}).json()
    assert started["status"] == "awaiting_approval"
    assert started["actions"] == []
    pending = started["pending_approval"]
    assert pending["action_id"] == "flush_dns_cache"

    wrong = c.post(f"/api/agent/sessions/{started['session_id']}/approval", json={"decision_id": "dec-nope", "approved": True})
    assert wrong.status_code == 409

    done = c.post(f"/api/agent/sessions/{started['session_id']}/approval",
                  json={"decision_id": pending["decision_id"], "approved": True}).json()
    assert done["status"] == "resolved"
    assert done["actions"][0]["approval"]["approved"] is True
    assert c.get(f"/api/agent/sessions/{started['session_id']}").json()["status"] == "resolved"


def test_p3_denial_via_api_changes_nothing():
    c = client()
    started = c.post("/api/agent/sessions", json={"complaint": "Websites won't load", "pipeline": "whitelist_approval"}).json()
    done = c.post(f"/api/agent/sessions/{started['session_id']}/approval",
                  json={"decision_id": started["pending_approval"]["decision_id"], "approved": False}).json()
    assert done["status"] == "approval_denied"
    assert done["actions"][0]["execution"] is None


def test_p1_and_p2_via_api():
    c = client()
    p1 = c.post("/api/agent/sessions", json={"complaint": "Websites won't load", "pipeline": "automatic_execution"}).json()
    assert p1["status"] == "diagnosed" and p1["actions"] == [] and p1["recommendation"]["executed"] is False
    p2 = c.post("/api/agent/sessions", json={"complaint": "Websites won't load", "pipeline": "auto_resolution"}).json()
    assert p2["status"] == "resolved"


def test_approval_on_non_approval_pipeline_is_rejected():
    c = client()
    s = c.post("/api/agent/sessions", json={"complaint": "Websites won't load", "pipeline": "auto_resolution"}).json()
    r = c.post(f"/api/agent/sessions/{s['session_id']}/approval", json={"decision_id": "dec-x", "approved": True})
    assert r.status_code == 409


def test_ai_unavailable_is_reported_not_hidden():
    c = client(llm=UnreachableLLM)
    body = c.post("/api/agent/sessions", json={"complaint": "Websites won't load", "pipeline": "auto_resolution"}).json()
    assert body["status"] == "reasoning_unavailable" and body["actions"] == []
    assert body["reasoning_mode"] == "ai"


def test_rules_mode_is_explicit_and_labelled():
    c = client(llm=UnreachableLLM)
    body = c.post("/api/agent/sessions", json={"complaint": "Websites won't load", "pipeline": "auto_resolution",
                                               "reasoning": "rules"}).json()
    assert body["reasoning_mode"] == "rules" and body["status"] == "resolved"


def test_scenario_selection_and_validation():
    c = client()
    ok = c.post("/api/agent/sessions", json={"complaint": "No internet", "pipeline": "auto_resolution",
                                             "scenario": "adapter_down"}).json()
    assert ok["diagnosis"][0]["cause_id"] == "network.adapter_unavailable"
    assert c.post("/api/agent/sessions", json={"complaint": "x", "pipeline": "auto_resolution", "scenario": "nope"}).status_code == 400
    assert c.post("/api/agent/sessions", json={"complaint": "x", "pipeline": "bogus"}).status_code == 422
    assert c.post("/api/agent/sessions", json={"complaint": "  ", "pipeline": "auto_resolution"}).status_code == 422
    assert c.get("/api/agent/sessions/unknown").status_code == 404
