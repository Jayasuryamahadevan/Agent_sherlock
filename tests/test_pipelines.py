"""Each pipeline tested independently against controlled scenarios (AI path via a deterministic fake model)."""

import pytest

from diagnostic_intelligence.agent.models import SessionStatus
from diagnostic_intelligence.remediation.approval import ApprovalResponse
from tests.agent_helpers import run

P1, P2, P3 = "automatic_execution", "auto_resolution", "whitelist_approval"


# ---------------------------------------------------------------- Pipeline 1
@pytest.mark.parametrize("scenario", ["dns_cache_stale", "dhcp_lease_lost", "search_indexer_runaway",
                                      "memory_hog", "low_disk_temp", "adapter_down"])
def test_p1_never_changes_the_system(scenario):
    _, _, report, host = run(P1, scenario)
    assert host.actions_applied == []
    assert report.actions == []
    assert report.status == SessionStatus.DIAGNOSED
    assert report.recommendation is not None and report.recommendation["executed"] is False


def test_p1_runs_diagnostics_automatically_and_confirms_with_fresh_measurement():
    _, session, report, _ = run(P1, "dns_cache_stale")
    collect_events = [e for e in report.timeline if e.stage == "collect"]
    assert len(collect_events) >= 2  # initial collection + confirmation re-measurement
    assert report.diagnosis_confirmed is True
    assert report.diagnosis[0].cause_id == "network.dns_failure"
    assert report.recommendation["action_id"] == "flush_dns_cache"
    assert report.recommendation["evidence_supports_action"] is True


def test_p1_follows_up_with_evidence_the_model_requests():
    _, _, report, _ = run(P1, "search_indexer_runaway")
    collected = [r["type"] for e in report.timeline if e.stage == "collect" for r in e.data["records"]]
    assert "windows.service_status" in collected  # not in the initial plan; requested by the reasoner
    assert report.recommendation["action_id"] == "restart_service"


def test_p1_reports_undetermined_when_evidence_shows_nothing():
    _, _, report, _ = run(P1, "healthy")
    assert report.status == SessionStatus.CAUSE_UNDETERMINED
    assert report.diagnosis == []


# ---------------------------------------------------------------- Pipeline 2
def test_p2_resolves_and_verifies_with_fresh_evidence():
    _, _, report, host = run(P2, "dns_cache_stale")
    assert report.status == SessionStatus.RESOLVED
    assert host.actions_applied == ["flush_dns_cache"]
    attempt = report.actions[0]
    assert attempt.verification.verdict.value == "resolved"
    verify_records = [r for e in report.timeline if e.stage == "collect" and "verification" in e.message for r in e.data["records"]]
    assert any(r["type"] == "network.dns_resolution" for r in verify_records)


def test_different_evidence_produces_different_diagnosis_and_action():
    complaint = "My internet is not working."
    _, _, dns_report, dns_host = run(P2, "dns_cache_stale", complaint=complaint)
    _, _, dhcp_report, dhcp_host = run(P2, "dhcp_lease_lost", complaint=complaint)
    _, _, adapter_report, adapter_host = run(P2, "adapter_down", complaint=complaint)
    assert dns_report.diagnosis[0].cause_id == "network.dns_failure"
    assert dhcp_report.diagnosis[0].cause_id == "network.no_valid_address"
    assert adapter_report.diagnosis[0].cause_id == "network.adapter_unavailable"
    assert dns_host.actions_applied == ["flush_dns_cache"]
    assert dhcp_host.actions_applied == ["renew_dhcp_lease"]
    assert adapter_host.actions_applied == ["restart_network_adapter"]
    assert {r.status for r in (dns_report, dhcp_report, adapter_report)} == {SessionStatus.RESOLVED}


def test_p2_does_not_claim_success_when_the_fix_does_not_work():
    _, _, report, host = run(P2, "isp_outage")
    assert host.actions_applied == ["flush_dns_cache"]
    assert report.status == SessionStatus.NOT_RESOLVED
    assert report.actions[0].execution.command_succeeded is True
    assert report.actions[0].verification.verdict.value == "unchanged"


def test_rules_target_the_upstream_fault_before_the_symptom():
    _, _, report, host = run(P2, "dhcp_lease_lost", rules=True)
    assert host.actions_applied == ["renew_dhcp_lease"]  # not flush_dns_cache first
    assert report.diagnosis[0].cause_id == "network.no_valid_address"
    assert report.status == SessionStatus.RESOLVED


def test_p2_revises_after_a_wrong_first_fix_using_fresh_evidence():
    from tests.fakes import ScriptedLLM, assess_response
    triage = {"primary_category": "network", "secondary_categories": [],
              "evidence_types": ["network.dns_resolution", "network.configuration"],
              "needs_clarification": False, "clarification_question": None, "explanation": "network"}

    def hyp(cause, ev_type, field, value):
        def build(p):
            rec = [r for r in p["EVIDENCE"] if r["evidence_type"] == ev_type][-1]
            return [{"cause_id": cause, "title": cause, "explanation": "x", "confidence": "medium",
                     "observations": [{"evidence_id": rec["evidence_id"], "field": field, "value": value}]}]
        return build

    act = lambda action_id, cause: {"action_id": action_id, "parameters": {}, "addresses_cause_id": cause, "rationale": "r"}
    llm = ScriptedLLM([
        triage,
        assess_response(hypotheses=hyp("network.dns_failure", "network.dns_resolution", "success", False),
                        next_step="propose_action", action=act("flush_dns_cache", "network.dns_failure")),
        assess_response(hypotheses=hyp("network.no_valid_address", "network.configuration", "adapters.0.addresses.0", "169.254.77.12"),
                        next_step="propose_action", action=act("renew_dhcp_lease", "network.no_valid_address")),
        assess_response(next_step="conclude"),
    ])
    _, _, report, host = run(P2, "dhcp_lease_lost", llm=llm)
    assert host.actions_applied == ["flush_dns_cache", "renew_dhcp_lease"]
    assert [a.verification.verdict.value for a in report.actions] == ["unchanged", "resolved"]
    assert report.status == SessionStatus.RESOLVED
    assert "unchanged" in llm.calls[2][1]  # the model was shown that the first fix did not work


def test_p2_attempt_limit_is_enforced():
    def stubborn(host):  # every fix "runs" but nothing changes
        host.failing_actions = set()
        host.upstream_down = True
        host.address = "169.254.1.1"
        host.gateway_ok = False
    _, _, report, host = run(P2, "dhcp_lease_lost", rules=True, tweak=lambda h: (stubborn(h), setattr(h, "apply", lambda a, p: (True, "exit code 0"))))
    assert len(report.actions) == 2
    assert report.status == SessionStatus.NOT_RESOLVED


def test_p2_refuses_high_risk_actions_and_asks_for_a_human():
    _, _, report, host = run(P2, "memory_hog")
    assert host.actions_applied == []
    assert report.status == SessionStatus.ACTION_REFUSED
    assert any("not eligible for automatic execution" in r for r in report.refused_proposals[0].decision.reasons)


def test_p2_reports_command_failure_honestly():
    _, _, report, _ = run(P2, "dns_cache_stale", tweak=lambda h: h.failing_actions.add("flush_dns_cache"))
    assert report.actions[0].execution.command_succeeded is False
    assert report.status != SessionStatus.RESOLVED


def test_p2_blocks_admin_actions_without_elevation():
    _, _, report, host = run(P2, "adapter_down", tweak=lambda h: setattr(h, "elevated", False))
    assert host.actions_applied == []
    assert any("administrator" in r for p in report.refused_proposals for r in p.decision.reasons)


# ---------------------------------------------------------------- Pipeline 3
def test_p3_executes_only_after_approval():
    _, _, report, host = run(P3, "memory_hog", approve=True)
    assert host.actions_applied == ["terminate_process"]
    assert report.actions[0].approval.approved is True
    assert report.status == SessionStatus.RESOLVED


def test_p3_denied_approval_prevents_execution():
    _, _, report, host = run(P3, "dns_cache_stale", approve=False)
    assert host.actions_applied == []
    assert report.status == SessionStatus.APPROVAL_DENIED
    assert report.actions[0].execution is None


def test_p3_missing_approval_pauses_and_resume_controls_execution():
    pipeline, session, report, host = run(P3, "dns_cache_stale")  # deferred provider
    assert report.status == SessionStatus.AWAITING_APPROVAL
    assert host.actions_applied == []
    pending = report.pending_approval
    assert pending.action_id == "flush_dns_cache" and pending.consequences

    with pytest.raises(ValueError):
        pipeline.resume(session, ApprovalResponse(decision_id="dec-forged", approved=True))
    assert host.actions_applied == []

    pipeline.resume(session, ApprovalResponse(decision_id=pending.decision_id, approved=True))
    final = pipeline.report(session)
    assert host.actions_applied == ["flush_dns_cache"]
    assert final.status == SessionStatus.RESOLVED


def test_p3_expired_approval_is_not_executed():
    from datetime import timedelta
    pipeline, session, report, host = run(P3, "dns_cache_stale")
    session.pending.request.expires_at -= timedelta(hours=1)
    pipeline.resume(session, ApprovalResponse(decision_id=report.pending_approval.decision_id, approved=True))
    assert host.actions_applied == []
    assert pipeline.report(session).status == SessionStatus.ACTION_REFUSED


def test_p3_whitelist_is_narrower_than_the_catalogue():
    from tests.fakes import ScriptedLLM, assess_response
    def stop_wuauserv(host):
        host.services["wuauserv"].update(state="Stopped", start_mode="Auto")
    def obs(p):
        rec = next(r for r in p["EVIDENCE"] if r["evidence_type"] == "windows.service_status")
        idx = next(i for i, s in enumerate(rec["data"]["services"]) if s["name"] == "wuauserv")
        return [{"cause_id": "windows_health.service_stopped", "title": "Windows Update service stopped",
                 "explanation": "x", "confidence": "high",
                 "observations": [{"evidence_id": rec["evidence_id"], "field": f"services.{idx}.state", "value": "Stopped"}]}]
    proposal = {"action_id": "restart_service", "parameters": {"service_name": "wuauserv"},
                "addresses_cause_id": "windows_health.service_stopped", "rationale": "restart it"}
    triage = {"primary_category": "windows_health", "secondary_categories": [], "evidence_types": ["windows.service_status"],
              "needs_clarification": False, "clarification_question": None, "explanation": "service"}
    script = lambda: ScriptedLLM([triage] + [assess_response(hypotheses=obs, next_step="propose_action", action=proposal)] * 6)

    _, _, p3, host3 = run(P3, "healthy", llm=script(), approve=True, tweak=stop_wuauserv, complaint="Updates fail")
    assert host3.actions_applied == []
    assert any("not on the approval whitelist" in r for p in p3.refused_proposals for r in p.decision.reasons)

    _, _, p2, host2 = run(P2, "healthy", llm=script(), tweak=stop_wuauserv, complaint="Updates fail")
    assert host2.actions_applied == ["restart_service"]
    assert p2.status == SessionStatus.RESOLVED


def test_pipelines_are_distinguishable_in_reports():
    reports = {pid: run(pid, "dns_cache_stale", approve=True)[2] for pid in (P1, P2, P3)}
    assert {r.pipeline["pipeline_id"] for r in reports.values()} == {P1, P2, P3}
    assert reports[P1].pipeline["system_changes"] == "never"
    assert reports[P2].pipeline["system_changes"] == "automatic"
    assert reports[P3].pipeline["system_changes"] == "with_approval"
    assert reports[P3].pipeline["whitelist"] is not None and reports[P2].pipeline["whitelist"] is None
